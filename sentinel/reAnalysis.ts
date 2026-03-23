/**
 * Module F.6 — Continuous Re-Analysis
 *
 * Monitors previously analyzed contracts for:
 * 1. Proxy upgrades (new implementation → re-run full pipeline)
 * 2. Significant TVL increases (>$100K → escalate priority)
 * 3. New markets/vaults that reference a known analyzed contract
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import type { Address, PublicClient } from "viem";

import { RPC_URL } from "./config.js";
import type {
  AnalyzedContract,
  BlockContext,
  NewDeployment,
  StaticAnalysisReport,
} from "./types.js";

// ─── Constants ────────────────────────────────────────────────────────────

const DB_PATH = "./data/reanalysis-db.json";
const SAVE_INTERVAL_BLOCKS = 100n;
const TVL_INCREASE_THRESHOLD_USD = 100_000;
const EIP1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;

// Conservative ETH price floor — used only to detect whether real ETH is present.
// Exact accuracy is unimportant; we just need TVL > $100K threshold to fire.
const ETH_PRICE_CONSERVATIVE_USD = 2_000;

const totalAssetsAbi = [
  { type: "function", name: "totalAssets", inputs: [], outputs: [{ name: "", type: "uint256" }], stateMutability: "view" },
] as const;

const assetAbi = [
  { type: "function", name: "asset", inputs: [], outputs: [{ name: "", type: "address" }], stateMutability: "view" },
] as const;

const decimalsAbi = [
  { type: "function", name: "decimals", inputs: [], outputs: [{ name: "", type: "uint8" }], stateMutability: "view" },
] as const;

interface SerializedDB {
  version: 1;
  savedAt: string;
  contracts: Record<string, {
    address: string;
    firstAnalyzedAt: number;
    lastAnalyzedAt: number;
    riskScore: number;
    tvlUsd: number;
    findingsCount: number;
    proxyImplementation?: string;
    scheduledForReanalysis: boolean;
    reanalysisReason?: string;
  }>;
}

// ─── Class ────────────────────────────────────────────────────────────────

export class ReAnalyzer {
  private readonly publicClient: PublicClient;
  private db = new Map<string, AnalyzedContract>();
  private lastSaveBlock = 0n;

  constructor(publicClient: PublicClient) {
    this.publicClient = publicClient;
    this.loadDb();
  }

  /**
   * Main per-block entry point. Returns addresses needing re-analysis.
   */
  async run(ctx: BlockContext, newDeployments: NewDeployment[]): Promise<Address[]> {
    const toReanalyze: Address[] = [];

    // Check proxy upgrades
    const proxyContracts = [...this.db.values()].filter(c => c.proxyImplementation !== undefined);
    for (const contract of proxyContracts) {
      try {
        const upgraded = await this.checkProxyUpgrade(contract.address, contract.proxyImplementation!);
        if (upgraded) {
          console.log(`[re-analyzer] Proxy upgrade: ${contract.address}`);
          this.db.set(contract.address.toLowerCase(), {
            ...contract,
            scheduledForReanalysis: true,
            reanalysisReason: "proxy_upgrade",
          });
          toReanalyze.push(contract.address);
        }
      } catch { /* non-fatal */ }
    }

    // Check TVL increases every 50 blocks
    if (ctx.blockNumber % 50n === 0n) {
      const candidates = [...this.db.values()].filter(c => c.riskScore >= 40 && !c.scheduledForReanalysis);
      for (const contract of candidates) {
        try {
          const currentTvl = await this.estimateTVL(contract.address);
          if (currentTvl > contract.tvlUsd + TVL_INCREASE_THRESHOLD_USD && currentTvl > TVL_INCREASE_THRESHOLD_USD) {
            console.log(`[re-analyzer] TVL increase: ${contract.address} $${contract.tvlUsd.toFixed(0)} -> $${currentTvl.toFixed(0)}`);
            this.db.set(contract.address.toLowerCase(), {
              ...contract, tvlUsd: currentTvl, scheduledForReanalysis: true,
              reanalysisReason: `tvl_increase_${currentTvl.toFixed(0)}`,
            });
            toReanalyze.push(contract.address);
          } else if (currentTvl !== contract.tvlUsd) {
            this.db.set(contract.address.toLowerCase(), { ...contract, tvlUsd: currentTvl });
          }
        } catch { /* skip */ }
      }
    }

    // Check if new deployments reference known contracts
    const knownAddresses = new Set([...this.db.keys()]);
    for (const deployment of newDeployments) {
      if (!deployment.fundHandling.isFundHandling) continue;
      try {
        const bytecode = await this.publicClient.getCode({ address: deployment.contractAddress });
        if (!bytecode) continue;
        const bytecodeStr = bytecode.toLowerCase();
        for (const knownAddr of knownAddresses) {
          const addrBytes = knownAddr.replace("0x", "");
          if (bytecodeStr.includes(addrBytes)) {
            const existing = this.db.get(knownAddr);
            if (existing && !existing.scheduledForReanalysis) {
              this.db.set(knownAddr, {
                ...existing,
                scheduledForReanalysis: true,
                reanalysisReason: `referenced_by_${deployment.contractAddress}`,
              });
              toReanalyze.push(knownAddr as Address);
            }
            break;
          }
        }
      } catch { /* skip */ }
    }

    // Persist periodically
    if (ctx.blockNumber - this.lastSaveBlock >= SAVE_INTERVAL_BLOCKS) {
      this.saveDb();
      this.lastSaveBlock = ctx.blockNumber;
    }

    return [...new Set(toReanalyze)];
  }

  /** Registers a newly analyzed contract in the database. */
  registerContract(address: Address, report: StaticAnalysisReport): void {
    const key = address.toLowerCase();
    const existing = this.db.get(key);
    this.db.set(key, {
      address,
      firstAnalyzedAt: existing?.firstAnalyzedAt ?? Date.now(),
      lastAnalyzedAt: Date.now(),
      riskScore: report.riskScore,
      tvlUsd: existing?.tvlUsd ?? 0,
      findings: report.findings,
      proxyImplementation: report.implementationAddress,
      scheduledForReanalysis: false,
    });
  }

  getDatabase(): Map<Address, AnalyzedContract> {
    return this.db as Map<Address, AnalyzedContract>;
  }

  /** Checks if a proxy contract's EIP-1967 implementation slot changed. */
  async checkProxyUpgrade(contractAddress: Address, previousImpl: Address): Promise<boolean> {
    const rawSlot = await this.publicClient.getStorageAt({
      address: contractAddress,
      slot: EIP1967_IMPL_SLOT,
    });
    if (!rawSlot || rawSlot === "0x" + "0".repeat(64)) return false;
    const currentImpl = ("0x" + rawSlot.slice(-40)) as Address;
    return currentImpl.toLowerCase() !== previousImpl.toLowerCase();
  }

  /**
   * Estimates USD TVL using two signals, in order of reliability:
   *
   * 1. Native ETH balance — unambiguous, price in USD via conservative floor.
   * 2. ERC4626 vault: totalAssets() normalised by the asset's own decimals.
   *    Requires asset() to confirm it is a vault, not a plain ERC20 token.
   *
   * totalSupply() is intentionally NOT used — it represents the number of
   * tokens minted, which bears no relation to USD value and produces
   * astronomically large fake TVL readings on meme/honeypot tokens.
   */
  async estimateTVL(contractAddress: Address): Promise<number> {
    // 1. Native ETH balance
    try {
      const ethBalance = await this.publicClient.getBalance({ address: contractAddress });
      if (ethBalance > 0n) {
        return (Number(ethBalance) / 1e18) * ETH_PRICE_CONSERVATIVE_USD;
      }
    } catch { /* skip */ }

    // 2. ERC4626 vault: must expose both totalAssets() and asset()
    try {
      const [totalAssets, assetAddress] = await Promise.all([
        this.publicClient.readContract({ address: contractAddress, abi: totalAssetsAbi, functionName: "totalAssets" }),
        this.publicClient.readContract({ address: contractAddress, abi: assetAbi, functionName: "asset" }),
      ]);
      if (totalAssets > 0n && assetAddress !== "0x0000000000000000000000000000000000000000") {
        const decimals = await this.publicClient.readContract({
          address: assetAddress as Address, abi: decimalsAbi, functionName: "decimals",
        });
        const normalized = Number(totalAssets) / 10 ** Number(decimals);
        return Math.min(normalized, 1e10); // cap at $10B
      }
    } catch { /* not ERC4626 or asset lookup failed */ }

    return 0;
  }

  private loadDb(): void {
    try {
      if (!existsSync(DB_PATH)) return;
      const parsed: SerializedDB = JSON.parse(readFileSync(DB_PATH, "utf-8"));
      if (parsed.version !== 1) return;
      for (const [addr, entry] of Object.entries(parsed.contracts)) {
        this.db.set(addr, {
          address: entry.address as Address,
          firstAnalyzedAt: entry.firstAnalyzedAt,
          lastAnalyzedAt: entry.lastAnalyzedAt,
          riskScore: entry.riskScore,
          tvlUsd: entry.tvlUsd,
          findings: [],
          proxyImplementation: entry.proxyImplementation as Address | undefined,
          scheduledForReanalysis: entry.scheduledForReanalysis,
          reanalysisReason: entry.reanalysisReason,
        });
      }
      console.log(`[re-analyzer] Loaded ${this.db.size} contracts from DB`);
    } catch (err) {
      console.warn(`[re-analyzer] DB load failed: ${(err as Error).message}`);
    }
  }

  private saveDb(): void {
    try {
      mkdirSync(dirname(DB_PATH), { recursive: true });
      const out: SerializedDB = { version: 1, savedAt: new Date().toISOString(), contracts: {} };
      for (const [addr, entry] of this.db.entries()) {
        out.contracts[addr] = {
          address: entry.address,
          firstAnalyzedAt: entry.firstAnalyzedAt,
          lastAnalyzedAt: entry.lastAnalyzedAt,
          riskScore: entry.riskScore,
          tvlUsd: entry.tvlUsd,
          findingsCount: entry.findings.length,
          proxyImplementation: entry.proxyImplementation,
          scheduledForReanalysis: entry.scheduledForReanalysis,
          reanalysisReason: entry.reanalysisReason,
        };
      }
      writeFileSync(DB_PATH, JSON.stringify(out, null, 2));
    } catch (err) {
      console.warn(`[re-analyzer] DB save failed: ${(err as Error).message}`);
    }
  }
}
