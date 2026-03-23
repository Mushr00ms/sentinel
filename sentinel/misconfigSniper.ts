import type { Address, PublicClient } from "viem";
import { getAddress, isAddress } from "viem";

import {
  EULER_EVC,
  EULER_GOVERNOR_PRIMARY,
  EULER_GOVERNOR_SECONDARY,
  AAVE_V3_POOL,
  ERC4626_TOTAL_SUPPLY_DUST_THRESHOLD,
  isConfigured,
} from "./config.js";
import type { BlockContext, MisconfigFinding, MisconfigSeverity } from "./types.js";

// ─── ABIs ─────────────────────────────────────────────────────────────────

const OWNER_ABI = [
  {
    name: "owner",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
] as const;

const ADMIN_ABI = [
  {
    name: "admin",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
] as const;

const GET_THRESHOLD_ABI = [
  {
    name: "getThreshold",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
] as const;

const GET_OWNERS_ABI = [
  {
    name: "getOwners",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address[]" }],
  },
] as const;

const TOTAL_SUPPLY_ABI = [
  {
    name: "totalSupply",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
] as const;

const TOTAL_ASSETS_ABI = [
  {
    name: "totalAssets",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
] as const;

// EIP-1967 admin storage slot
const EIP1967_ADMIN_SLOT =
  "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103" as const;

// Zero address constant
const ZERO_ADDRESS: Address = "0x0000000000000000000000000000000000000000";

// ─── Scan Targets ─────────────────────────────────────────────────────────

interface ScanTarget {
  address: Address;
  name: string;
  protocol: string;
  isERC4626?: boolean;
}

const SCAN_TARGETS: ScanTarget[] = [
  { address: EULER_EVC, name: "Euler EVC", protocol: "euler-v2" },
  { address: EULER_GOVERNOR_PRIMARY, name: "Euler Governor Primary", protocol: "euler-v2" },
  { address: EULER_GOVERNOR_SECONDARY, name: "Euler Governor Secondary", protocol: "euler-v2" },
  { address: AAVE_V3_POOL, name: "Aave V3 Pool", protocol: "aave-v3" },
].filter(t => isConfigured(t.address)); // Skip zero-address targets

// ─── MisconfigSniper ──────────────────────────────────────────────────────

export class MisconfigSniper {
  private readonly client: PublicClient;
  private lastScanBlock: bigint = 0n;
  private readonly knownFindings: Map<string, MisconfigFinding> = new Map();
  private readonly scanInterval: bigint = 1000n;

  constructor(publicClient: PublicClient) {
    this.client = publicClient;
  }

  // ─── Public API ────────────────────────────────────────────────────────

  /**
   * Run full scan every `scanInterval` blocks. Returns only new findings
   * discovered since the last scan (deduped by finding ID).
   */
  async run(ctx: BlockContext): Promise<MisconfigFinding[]> {
    const blocksSinceLast = ctx.blockNumber - this.lastScanBlock;
    if (this.lastScanBlock !== 0n && blocksSinceLast < this.scanInterval) {
      return [];
    }

    this.lastScanBlock = ctx.blockNumber;

    const newFindings: MisconfigFinding[] = [];

    const tasks: Promise<void>[] = SCAN_TARGETS.map(async (target) => {
      const results = await this.scanTarget(target, ctx.blockTimestamp);
      for (const finding of results) {
        if (!this.knownFindings.has(finding.id)) {
          this.knownFindings.set(finding.id, finding);
          newFindings.push(finding);
        }
      }
    });

    await Promise.allSettled(tasks);

    return newFindings;
  }

  /**
   * Check whether the admin or owner of a contract is an EOA or a weak
   * multisig. Returns a finding if a misconfiguration is detected.
   */
  async scanAdminEOA(
    contractAddress: Address,
    protocolName?: string,
  ): Promise<MisconfigFinding | null> {
    const adminAddress = await this.resolveAdmin(contractAddress);
    if (adminAddress === null) {
      return null;
    }

    // Admin is zero address — not a risk from this angle
    if (adminAddress.toLowerCase() === ZERO_ADDRESS.toLowerCase()) {
      return null;
    }

    const eoa = await this.isEOA(adminAddress);

    if (eoa) {
      return this.buildFinding({
        id: `admin_eoa:${contractAddress.toLowerCase()}`,
        severity: "critical",
        class: "admin_eoa",
        contractAddress,
        protocolName,
        description: `Admin/owner of ${contractAddress} is an EOA (${adminAddress}). A single private key controls this contract with no multisig protection.`,
        affectedFunction: "owner/admin",
        raw: { adminAddress },
      });
    }

    // Not an EOA — check if it might be a Gnosis Safe with a weak threshold
    const safeResult = await this.assessSafe(adminAddress);
    if (safeResult === null) {
      return null;
    }

    const { threshold, ownerCount } = safeResult;

    if (threshold === 1n) {
      return this.buildFinding({
        id: `weak_multisig:${contractAddress.toLowerCase()}`,
        severity: "critical",
        class: "weak_multisig",
        contractAddress,
        protocolName,
        description: `Admin of ${contractAddress} is a Safe at ${adminAddress} with threshold 1/${ownerCount} — effectively a single EOA.`,
        affectedFunction: "owner/admin",
        raw: { adminAddress, threshold: threshold.toString(), ownerCount: ownerCount.toString() },
      });
    }

    if (threshold === 2n && ownerCount < 5n) {
      return this.buildFinding({
        id: `weak_multisig:${contractAddress.toLowerCase()}`,
        severity: "high",
        class: "weak_multisig",
        contractAddress,
        protocolName,
        description: `Admin of ${contractAddress} is a Safe at ${adminAddress} with threshold 2/${ownerCount} — low owner count increases key-compromise risk.`,
        affectedFunction: "owner/admin",
        raw: { adminAddress, threshold: threshold.toString(), ownerCount: ownerCount.toString() },
      });
    }

    return null;
  }

  /**
   * Check whether an ERC-4626 vault is exposed to a donation (inflation)
   * attack. A vault with totalSupply below the dust threshold and non-trivial
   * totalAssets is susceptible.
   */
  async scanERC4626Inflation(
    vaultAddress: Address,
    protocolName?: string,
  ): Promise<MisconfigFinding | null> {
    let totalSupply: bigint;
    try {
      totalSupply = await this.client.readContract({
        address: vaultAddress,
        abi: TOTAL_SUPPLY_ABI,
        functionName: "totalSupply",
      });
    } catch {
      // Contract does not implement totalSupply — not an ERC-4626 vault
      return null;
    }

    if (totalSupply >= ERC4626_TOTAL_SUPPLY_DUST_THRESHOLD) {
      return null;
    }

    // Retrieve totalAssets to gauge risk magnitude
    let totalAssets: bigint = 0n;
    try {
      totalAssets = await this.client.readContract({
        address: vaultAddress,
        abi: TOTAL_ASSETS_ABI,
        functionName: "totalAssets",
      });
    } catch {
      // Not required — fall through with totalAssets = 0
    }

    const severity: MisconfigSeverity =
      totalSupply === 0n ? "critical" : totalAssets > 0n ? "high" : "medium";

    return this.buildFinding({
      id: `erc4626_inflation:${vaultAddress.toLowerCase()}`,
      severity,
      class: "erc4626_inflation",
      contractAddress: vaultAddress,
      protocolName,
      description:
        `ERC-4626 vault ${vaultAddress} has totalSupply=${totalSupply.toString()} ` +
        `(below dust threshold of ${ERC4626_TOTAL_SUPPLY_DUST_THRESHOLD.toString()}) ` +
        `and totalAssets=${totalAssets.toString()}. Vulnerable to share-inflation / donation attack.`,
      affectedFunction: "deposit/mint",
      raw: {
        totalSupply: totalSupply.toString(),
        totalAssets: totalAssets.toString(),
        dustThreshold: ERC4626_TOTAL_SUPPLY_DUST_THRESHOLD.toString(),
      },
    });
  }

  /**
   * Placeholder for approval honeypot detection. A full implementation
   * requires off-chain indexing of Approval events and cross-referencing
   * transferFrom call patterns to identify contracts that absorb approvals
   * and drain approved amounts.
   *
   * Returns null until event indexing is available.
   */
  async scanApprovalHoneypot(contractAddress: Address): Promise<MisconfigFinding | null> {
    // TODO: Index ERC-20 Approval events directed at `contractAddress`,
    // correlate with outgoing transferFrom calls, and flag contracts where
    // the approved amount is consistently drained without legitimate user
    // benefit. Requires a full event indexer (e.g., Ponder or custom).
    void contractAddress;
    return null;
  }

  // ─── Private Helpers ───────────────────────────────────────────────────

  /**
   * Returns true when the given address has no deployed bytecode, i.e. it
   * is an externally owned account.
   */
  private async isEOA(address: Address): Promise<boolean> {
    try {
      const code = await this.client.getBytecode({ address });
      return code === undefined || code === "0x" || code.length === 0;
    } catch {
      // If the RPC call fails we conservatively treat the address as a
      // contract to avoid false-positive critical findings.
      return false;
    }
  }

  /**
   * Attempt to resolve the privileged administrator address for a contract
   * by trying, in order:
   *   1. `owner()` view function
   *   2. `admin()` view function
   *   3. EIP-1967 transparent-proxy admin storage slot
   *
   * Returns null when none of the strategies yield a usable address.
   */
  private async resolveAdmin(contractAddress: Address): Promise<Address | null> {
    // Strategy 1: owner()
    try {
      const ownerAddr = await this.client.readContract({
        address: contractAddress,
        abi: OWNER_ABI,
        functionName: "owner",
      });
      if (isAddress(ownerAddr) && ownerAddr !== ZERO_ADDRESS) {
        return getAddress(ownerAddr);
      }
    } catch {
      // Function does not exist or reverted — try next strategy
    }

    // Strategy 2: admin()
    try {
      const adminAddr = await this.client.readContract({
        address: contractAddress,
        abi: ADMIN_ABI,
        functionName: "admin",
      });
      if (isAddress(adminAddr) && adminAddr !== ZERO_ADDRESS) {
        return getAddress(adminAddr);
      }
    } catch {
      // Function does not exist or reverted — try next strategy
    }

    // Strategy 3: EIP-1967 admin slot
    try {
      const raw = await this.client.getStorageAt({
        address: contractAddress,
        slot: EIP1967_ADMIN_SLOT,
      });
      if (raw && raw !== "0x" && raw.length === 66) {
        // Storage slot returns a 32-byte word; the address is in the low 20 bytes
        const slotAddr = ("0x" + raw.slice(26)) as Address;
        if (isAddress(slotAddr) && slotAddr.toLowerCase() !== ZERO_ADDRESS.toLowerCase()) {
          return getAddress(slotAddr);
        }
      }
    } catch {
      // RPC error — fall through
    }

    return null;
  }

  /**
   * Attempt to retrieve Gnosis Safe metadata (threshold + owner count) from
   * the given address. Returns null if the address does not behave like a Safe.
   */
  private async assessSafe(
    safeAddress: Address,
  ): Promise<{ threshold: bigint; ownerCount: bigint } | null> {
    let threshold: bigint;
    let owners: readonly Address[];

    try {
      threshold = await this.client.readContract({
        address: safeAddress,
        abi: GET_THRESHOLD_ABI,
        functionName: "getThreshold",
      });
    } catch {
      // getThreshold not implemented — not a Safe
      return null;
    }

    try {
      owners = await this.client.readContract({
        address: safeAddress,
        abi: GET_OWNERS_ABI,
        functionName: "getOwners",
      });
    } catch {
      // getOwners not implemented — treat ownerCount as unknown (1 is safest assumption)
      return { threshold, ownerCount: 1n };
    }

    return { threshold, ownerCount: BigInt(owners.length) };
  }

  /**
   * Run all applicable scans for a single scan target and collect findings.
   */
  private async scanTarget(
    target: ScanTarget,
    blockTimestamp: number,
  ): Promise<MisconfigFinding[]> {
    const findings: MisconfigFinding[] = [];

    // Stamp detectedAt before async work so all findings share the same
    // logical timestamp for this scan pass.
    const ts = blockTimestamp;

    // Admin / owner check
    const adminFinding = await this.scanAdminEOA(target.address, target.protocol).catch(
      () => null,
    );
    if (adminFinding !== null) {
      findings.push({ ...adminFinding, detectedAt: ts });
    }

    // ERC-4626 inflation check (only for targets flagged as vaults or by
    // opportunistically probing totalSupply)
    if (target.isERC4626 === true) {
      const inflationFinding = await this.scanERC4626Inflation(
        target.address,
        target.protocol,
      ).catch(() => null);
      if (inflationFinding !== null) {
        findings.push({ ...inflationFinding, detectedAt: ts });
      }
    }

    // Approval honeypot (placeholder — always returns null for now)
    const honeypotFinding = await this.scanApprovalHoneypot(target.address).catch(() => null);
    if (honeypotFinding !== null) {
      findings.push({ ...honeypotFinding, detectedAt: ts });
    }

    return findings;
  }

  /**
   * Construct a MisconfigFinding with detectedAt defaulting to the current
   * wall-clock time. Callers may overwrite detectedAt after the fact.
   */
  private buildFinding(
    params: Omit<MisconfigFinding, "detectedAt"> & { detectedAt?: number },
  ): MisconfigFinding {
    return {
      detectedAt: Math.floor(Date.now() / 1000),
      ...params,
    };
  }
}
