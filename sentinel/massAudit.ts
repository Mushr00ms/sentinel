/**
 * Module G — Mass Smart Contract Audit Pipeline
 *
 * Orchestrates the 7-step mass audit pipeline:
 *   1. Scrape verified contracts from block explorers (Etherscan / SonicScan)
 *   2. Decompile unverified bytecode (Heimdall — existing StaticAnalyzer)
 *   3. Classify contract type (DeFi filter: AMM, lending, vault, bridge, staking)
 *   4. Run static analysis (Heimdall + Slither on verified source)
 *   5. Layer LLM analysis (Claude CLI --print --json with OAuth)
 *   6. Flag high-confidence findings
 *   7. Prioritize by TVL / exploitability / profit potential
 *
 * Runs on a configurable timer (default 30 min), independent of the per-block loop.
 * Supports both Sonic (146) and Ethereum mainnet (1).
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import type { Address, Hex, PublicClient } from "viem";
import type {
  MassAuditTarget,
  AuditPipelineStats,
  SupportedChain,
  ExplorerContractEntry,
  StaticAnalysisReport,
  SlitherFinding,
  NewDeployment,
} from "./types.js";
import { ExplorerScraper } from "./explorerScraper.js";
import { ContractClassifier } from "./contractClassifier.js";
import { LLMAnalyzer } from "./llmAnalyzer.js";
import { StaticAnalyzer } from "./staticAnalysis.js";
import { CompositionAnalyzer } from "./compositionAnalyzer.js";
import { SelectorCollisionDetector } from "./selectorCollision.js";
import { AiFingerprinter } from "./aiFingerprint.js";
import { UpgradeMonitor } from "./upgradeMonitor.js";
import { DiffCompiler } from "./diffCompiler.js";
import { getChainClient } from "./chains.js";
import {
  FEATURES,
  MASS_AUDIT_MAX_PER_RUN,
  MASS_AUDIT_LLM_RISK_THRESHOLD,
  KNOWN_FACTORY_ADDRESSES,
  KNOWN_ETH_FACTORY_ADDRESSES,
} from "./config.js";
import { info, warn, alert, critical } from "./alerter.js";

// ─── Constants ──────────────────────────────────────────────────────────

const DB_PATH = "./data/mass-audit-db.json";
const SAVE_INTERVAL_MS = 5 * 60 * 1000; // Save DB every 5 minutes during a run
const HIGH_RISK_THRESHOLD = 70;
const MEDIUM_RISK_THRESHOLD = 40;

const totalAssetsAbi = [
  { type: "function", name: "totalAssets", inputs: [], outputs: [{ name: "", type: "uint256" }], stateMutability: "view" },
] as const;

const totalSupplyAbi = [
  { type: "function", name: "totalSupply", inputs: [], outputs: [{ name: "", type: "uint256" }], stateMutability: "view" },
] as const;

/** Known DeFi factory addresses per chain for targeted scraping. */
const DEFI_FACTORIES: Record<SupportedChain, Address[]> = {
  sonic: KNOWN_FACTORY_ADDRESSES,
  ethereum: KNOWN_ETH_FACTORY_ADDRESSES,
};

/** Seed list of known high-TVL DeFi contracts to audit on first run. */
const SEED_CONTRACTS: Record<SupportedChain, Address[]> = {
  sonic: [
    // Euler V2 vaults
    "0x4860C903f6Ad709c3eDA46D3D502943f184D4315", // EVC
    "0x3bd2B8f04C9C04c0322127ccF683C6B288bD27B8", // Vault Lens
    // Aave V3 Sonic
    "0x5362dBb1e601abF3a4c14c22ffEdA64042E5eAA3", // Pool
    // Silo V2
    "0xAd84B07082c67a1105b933c28f8c8bA5b89DFcFA", // Lens
    "0x174efb6AEBEcbCfea35a1242c5196AA5683E110B", // Liquidation Helper
    // DEXes
    "0x29f177EFF806b8A71Ff8C7259eC359312CaCE22b", // SpookySwap/factory
    // Tokens/Vaults
    "0xd3DCe716f3eF535C5Ff8d041c1A41C3bd89b97aE", // scUSD
    "0x3bcE5CB273F0F148010BbEa2470eBd4182129b6e", // scETH
    "0x039e2fB66102314Ce7b64Ce5Ce3E5183bc94aD38", // Wrapped Sonic (wS)
    "0x50c42dEAcD8Fc9773493ED674b675bE577f2634b", // WETH (Sonic)
    "0x29219dd400f2Bf60E5a23d13Be72B486D4038894", // USDC.e
    // Balancer Vault
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
  ],
  ethereum: [
    // Euler V2
    "0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383", // EVC
    // Aave V3
    "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", // Pool
    // Morpho Blue
    "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb",
    // Uniswap
    "0x1F98431c8aD98523631AE4a59f267346ea31F984", // V3 Factory
    "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", // V2 Factory
    // Core tokens
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
    "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
    "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
    // Balancer
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
  ],
};

// ─── Persistence types ──────────────────────────────────────────────────

interface SerializedAuditDB {
  version: 1;
  savedAt: string;
  stats: AuditPipelineStats;
  targets: Record<string, SerializedTarget>;
}

interface SerializedTarget {
  id: string;
  address: string;
  chain: SupportedChain;
  status: string;
  tvlUsd: number;
  priorityScore: number;
  riskScore: number;
  findingsCount: number;
  slitherCount: number;
  llmVulnCount: number;
  selectorCollisionCount: number;
  isLikelyAiGenerated: boolean;
  isVerified: boolean;
  isDeFi: boolean;
  category: string;
  deployedAt?: number;
  enqueuedAt: number;
  completedAt?: number;
  errorMessage?: string;
}

// ─── MassAuditOrchestrator ──────────────────────────────────────────────

export class MassAuditOrchestrator {
  private readonly scraper: ExplorerScraper;
  private readonly classifier: ContractClassifier;
  private readonly llmAnalyzer: LLMAnalyzer;
  private readonly compositionAnalyzer: CompositionAnalyzer;
  private readonly selectorCollision: SelectorCollisionDetector;
  private readonly aiFingerprinter: AiFingerprinter;
  readonly upgradeMonitor: UpgradeMonitor;
  private readonly diffCompiler: DiffCompiler;
  private readonly staticAnalyzers = new Map<SupportedChain, StaticAnalyzer>();
  private readonly clients = new Map<SupportedChain, PublicClient>();
  private readonly targets = new Map<string, MassAuditTarget>();

  private intervalHandle: ReturnType<typeof setInterval> | null = null;
  private isRunning = false;
  private stats: AuditPipelineStats = {
    totalQueued: 0,
    totalCompleted: 0,
    totalFailed: 0,
    highRiskCount: 0,
    mediumRiskCount: 0,
    lastRunAt: 0,
    lastRunDurationMs: 0,
  };

  constructor() {
    this.scraper = new ExplorerScraper();
    this.classifier = new ContractClassifier();
    this.llmAnalyzer = new LLMAnalyzer();
    this.compositionAnalyzer = new CompositionAnalyzer();
    this.selectorCollision = new SelectorCollisionDetector();
    this.aiFingerprinter = new AiFingerprinter();
    this.upgradeMonitor = new UpgradeMonitor();
    this.diffCompiler = new DiffCompiler();

    // Initialize chain-specific clients and analyzers
    const enabledChains = this.getEnabledChains();
    for (const chain of enabledChains) {
      const client = getChainClient(chain);
      this.clients.set(chain, client);
      this.staticAnalyzers.set(chain, new StaticAnalyzer(client));
    }

    this.loadDb();

    info("mass-audit", `Initialized for chains: ${enabledChains.join(", ")}`);
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────

  start(intervalMs: number): void {
    if (this.intervalHandle) return;

    info("mass-audit", `Starting mass audit pipeline (interval: ${(intervalMs / 1000 / 60).toFixed(1)} min)`);

    // Run immediately on start
    void this.runPipeline();

    this.intervalHandle = setInterval(() => void this.runPipeline(), intervalMs);
  }

  stop(): void {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
    }
    this.saveDb();
    info("mass-audit", "Stopped");
  }

  getStats(): AuditPipelineStats {
    return { ...this.stats };
  }

  // ── Main Pipeline ─────────────────────────────────────────────────────

  /**
   * Executes one full pass of the 7-step audit pipeline.
   */
  async runPipeline(): Promise<void> {
    if (this.isRunning) {
      warn("mass-audit", "Pipeline already running, skipping");
      return;
    }

    this.isRunning = true;
    const startMs = Date.now();

    try {
      info("mass-audit", "Pipeline run starting...");

      // ── Step 1: Scrape both chains ──────────────────────────────────
      const enabledChains = this.getEnabledChains();
      for (const chain of enabledChains) {
        await this.scrapeChain(chain);
      }

      // ── Steps 2-7: Process queue ───────────────────────────────────
      const pending = this.getPendingTargets(MASS_AUDIT_MAX_PER_RUN);
      info("mass-audit", `Processing ${pending.length} targets (${this.targets.size} total in DB)`);

      let processed = 0;
      let highRisk = 0;
      let medRisk = 0;

      for (const target of pending) {
        try {
          await this.processTarget(target);
          processed++;

          if (target.priorityScore >= HIGH_RISK_THRESHOLD) highRisk++;
          else if (target.priorityScore >= MEDIUM_RISK_THRESHOLD) medRisk++;

          // Periodic save during long runs
          if (processed % 10 === 0) this.saveDb();
        } catch (err) {
          target.status = "failed";
          target.errorMessage = (err as Error).message;
          this.stats.totalFailed++;
          warn("mass-audit", `Failed to process ${target.id}: ${(err as Error).message}`);
        }
      }

      // ── Step 8: Cross-contract composition analysis ─────────────
      const completedTargets = [...this.targets.values()].filter(
        (t) => t.status === "completed",
      );
      if (completedTargets.length >= 3) {
        for (const chain of enabledChains) {
          const chainTargets = completedTargets.filter((t) => t.chain === chain);
          if (chainTargets.length >= 2) {
            try {
              const graph = await this.compositionAnalyzer.analyze(chainTargets, chain);
              info(
                "mass-audit",
                `Composition analysis (${chain}): ${graph.nodes.size} nodes, ` +
                `${graph.edges.length} edges, ${graph.findings.length} findings`,
              );
            } catch (err) {
              warn("mass-audit", `Composition analysis failed for ${chain}: ${(err as Error).message}`);
            }
          }
        }
      }

      // Update stats
      this.stats.totalCompleted += processed;
      this.stats.highRiskCount = highRisk;
      this.stats.mediumRiskCount = medRisk;
      this.stats.lastRunAt = Date.now();
      this.stats.lastRunDurationMs = Date.now() - startMs;

      this.saveDb();

      info(
        "mass-audit",
        `Pipeline complete: ${processed} processed, ` +
        `${highRisk} high risk, ${medRisk} medium risk, ` +
        `duration ${((Date.now() - startMs) / 1000).toFixed(1)}s`,
      );
    } catch (err) {
      warn("mass-audit", `Pipeline error: ${(err as Error).message}`);
    } finally {
      this.isRunning = false;
    }
  }

  // ── Step 1: Scraping ──────────────────────────────────────────────────

  private async scrapeChain(chain: SupportedChain): Promise<void> {
    info("mass-audit", `Scraping ${chain}...`);

    let newCount = 0;

    // Strategy 0: Seed known DeFi contracts on first run
    const seeds = SEED_CONTRACTS[chain];
    for (const addr of seeds) {
      if (this.enqueueAddress(addr, chain)) newCount++;
    }

    // Strategy A: Scrape contracts from known DeFi factories
    const factories = DEFI_FACTORIES[chain];
    if (factories.length > 0) {
      try {
        const childAddresses = await this.scraper.scrapeFactoryDeployments(chain, factories);
        for (const addr of childAddresses) {
          if (this.enqueueAddress(addr, chain)) newCount++;
        }
      } catch (err) {
        warn("mass-audit", `Factory scrape failed for ${chain}: ${(err as Error).message}`);
      }
    }

    // Strategy B: Fetch verified source for all queued targets that don't have it yet
    const needsSource = [...this.targets.values()].filter(
      (t) => t.chain === chain && t.status === "queued" && !t.explorerEntry,
    );

    for (const target of needsSource.slice(0, 20)) {
      try {
        const entry = await this.scraper.getVerifiedSource(target.address, chain);
        target.explorerEntry = entry;
        target.status = "queued"; // ready for processing
      } catch (err) {
        warn("mass-audit", `Source fetch failed for ${target.address}: ${(err as Error).message}`);
      }
    }

    // Strategy C: Fetch deploy timestamps for targets missing them (recency boost)
    const needsTimestamp = [...this.targets.values()].filter(
      (t) => t.chain === chain && !t.deployedAt,
    ).slice(0, 20); // Batch max 20 per run (5 per API call = 4 calls)

    if (needsTimestamp.length > 0) {
      try {
        const addrs = needsTimestamp.map((t) => t.address);
        const creationMap = await this.scraper.getContractCreation(addrs, chain);
        for (const target of needsTimestamp) {
          const creation = creationMap.get(target.address);
          if (creation) {
            // txHash gives us the deploy block; use scrapedAt as proxy if no timestamp
            // The explorer API doesn't return timestamp directly — we use enqueuedAt as fallback
            // and mark deployedAt only when we have real data
            target.deployedAt = Math.floor(target.enqueuedAt / 1000); // placeholder until block ts
          }
        }
      } catch (err) {
        warn("mass-audit", `Deploy timestamp fetch failed for ${chain}: ${(err as Error).message}`);
      }
    }

    info("mass-audit", `${chain}: ${newCount} new contracts queued, ${needsSource.length} source fetched`);
  }

  // ── Steps 2-7: Process single target ──────────────────────────────────

  private async processTarget(target: MassAuditTarget): Promise<void> {
    const client = this.clients.get(target.chain);
    const analyzer = this.staticAnalyzers.get(target.chain);
    if (!client || !analyzer) return;

    // ── Step 1 continued: Ensure we have explorer data ────────────────
    if (!target.explorerEntry) {
      target.status = "scraping";
      target.explorerEntry = await this.scraper.getVerifiedSource(target.address, target.chain);
    }

    // ── Step 3: Classify ──────────────────────────────────────────────
    target.status = "classifying";

    if (target.explorerEntry?.isVerified) {
      target.classification = this.classifier.classify(target.explorerEntry);
    } else {
      // Bytecode-only classification
      try {
        const bytecode = await client.getBytecode({ address: target.address });
        if (bytecode && bytecode !== "0x") {
          target.classification = this.classifier.classifyFromBytecode(
            target.address,
            bytecode,
            target.chain,
          );
        }
      } catch { /* skip classification */ }
    }

    // Filter: skip non-DeFi contracts (but still track them)
    if (target.classification && !target.classification.isDeFi) {
      target.status = "completed";
      target.priorityScore = 0;
      target.completedAt = Date.now();
      info("mass-audit", `${target.id} — non-DeFi (${target.classification.category}), skipping`);
      return;
    }

    // ── Step 4: Static analysis ───────────────────────────────────────
    target.status = "static_analysis";

    if (target.explorerEntry?.isVerified && target.explorerEntry.sourceCode) {
      // Full analysis: Heimdall + Slither on verified source
      target.status = "slither_analysis";
      try {
        const { report, slitherFindings } = await analyzer.analyzeWithSource(
          target.address,
          target.chain,
          target.explorerEntry,
        );
        target.staticReport = report;
        target.slitherFindings = slitherFindings;
      } catch (err) {
        warn("mass-audit", `analyzeWithSource failed for ${target.id}: ${(err as Error).message}`);
        // Fall back to bytecode-only analysis
        await this.bytecodeOnlyAnalysis(target, client, analyzer);
      }
    } else {
      // Bytecode-only analysis
      await this.bytecodeOnlyAnalysis(target, client, analyzer);
    }

    // ── Step 4b: Selector collision detection (verified ABI) ─────────
    if (target.explorerEntry?.abi) {
      try {
        target.selectorCollisions = this.selectorCollision.detect(
          target.address,
          target.explorerEntry.abi,
        );
        // Register in global registry for cross-contract detection
        this.selectorCollision.register(target.address, target.explorerEntry.abi);
        if (target.selectorCollisions.length > 0) {
          warn(
            "mass-audit",
            `${target.id} — ${target.selectorCollisions.length} selector collision(s) detected`,
          );
        }
      } catch (err) {
        warn("mass-audit", `Selector collision check failed for ${target.id}: ${(err as Error).message}`);
      }
    }

    // ── Step 4c: AI fingerprinting (verified source) ──────────────────
    if (target.explorerEntry?.sourceCode) {
      try {
        target.aiFingerprint = this.aiFingerprinter.analyze(target.explorerEntry.sourceCode);
        if (target.aiFingerprint.isLikelyAiGenerated) {
          info(
            "mass-audit",
            `${target.id} — likely AI-generated (confidence=${target.aiFingerprint.confidence}%) ` +
            `patterns: ${target.aiFingerprint.patterns.join(", ")}`,
          );
          // Boost static risk score in-memory for downstream scoring
          if (target.staticReport) {
            target.staticReport.riskScore = Math.min(
              target.staticReport.riskScore + target.aiFingerprint.riskBoost,
              100,
            );
          }
        }
      } catch (err) {
        warn("mass-audit", `AI fingerprint failed for ${target.id}: ${(err as Error).message}`);
      }
    }

    // ── Step 4d: Differential compilation (verified source + version) ──
    if (
      FEATURES.diffCompiler &&
      target.explorerEntry?.sourceCode &&
      target.explorerEntry?.compilerVersion
    ) {
      try {
        const client = this.clients.get(target.chain);
        const deployedBytecode = client
          ? await client.getBytecode({ address: target.address }).catch(() => undefined)
          : undefined;

        const diffResult = await this.diffCompiler.analyze(
          target.address,
          target.explorerEntry.sourceCode,
          target.explorerEntry.compilerVersion,
          deployedBytecode,
        );

        if (diffResult.findings.length > 0) {
          const maxSeverity = diffResult.findings.some((f) => f.severity === "critical")
            ? "critical"
            : diffResult.findings.some((f) => f.severity === "high") ? "high" : "medium";
          warn(
            "diff-compiler",
            `${target.id} — ${diffResult.findings.length} compiler finding(s) | max: ${maxSeverity}`,
          );
          // Boost risk score for compiler-level findings
          if (target.staticReport) {
            const boost = diffResult.findings
              .filter((f) => f.isCriticalFlow)
              .length * 10;
            target.staticReport.riskScore = Math.min(
              target.staticReport.riskScore + boost,
              100,
            );
          }
        }
      } catch (err) {
        warn("diff-compiler", `Analysis failed for ${target.id}: ${(err as Error).message}`);
      }
    }

    // ── Step 4e: Register proxy in upgrade monitor ────────────────────
    if (target.explorerEntry?.implementationAddress) {
      this.upgradeMonitor.watchProxies([target.address], target.chain);
    }

    // ── Step 5: LLM analysis (if risk threshold met + feature enabled) ─
    if (
      FEATURES.llmAnalysis &&
      target.staticReport &&
      target.staticReport.riskScore >= MASS_AUDIT_LLM_RISK_THRESHOLD
    ) {
      target.status = "llm_analysis";
      const source = target.explorerEntry?.sourceCode ?? "[No source available — bytecode only analysis]";
      try {
        target.llmResult = await this.llmAnalyzer.analyze(
          target.address,
          target.chain,
          source,
          target.staticReport,
          target.slitherFindings,
        ) ?? undefined;
      } catch (err) {
        warn("mass-audit", `LLM analysis failed for ${target.id}: ${(err as Error).message}`);
      }
    }

    // ── Step 6 & 7: Flag findings + compute priority ─────────────────
    target.status = "prioritizing";

    // Estimate TVL
    target.tvlUsd = await this.estimateTVL(target.address, target.chain);

    // Compute composite priority score
    target.priorityScore = this.computePriorityScore(target);
    target.status = "completed";
    target.completedAt = Date.now();

    // ── Alert on high-risk findings ──────────────────────────────────
    const staticFindings = target.staticReport?.findings.length ?? 0;
    const slitherCount = target.slitherFindings?.length ?? 0;
    const llmVulns = target.llmResult?.vulnerabilities.length ?? 0;

    if (target.priorityScore >= HIGH_RISK_THRESHOLD) {
      critical(
        "mass-audit",
        `HIGH PRIORITY: ${target.chain}:${target.address}`,
        `Score: ${target.priorityScore} | TVL: $${target.tvlUsd.toFixed(0)} | ` +
        `Risk: ${target.staticReport?.riskScore ?? 0}/100 | ` +
        `Static: ${staticFindings} | Slither: ${slitherCount} | LLM: ${llmVulns} | ` +
        `Category: ${target.classification?.category ?? "unknown"} | ` +
        `Verified: ${target.explorerEntry?.isVerified ?? false}`,
        {
          target: {
            id: target.id,
            address: target.address,
            chain: target.chain,
            tvlUsd: target.tvlUsd,
            priorityScore: target.priorityScore,
            riskScore: target.staticReport?.riskScore,
            staticFindings: target.staticReport?.findings,
            slitherFindings: target.slitherFindings,
            llmVulnerabilities: target.llmResult?.vulnerabilities,
          },
        },
      );
    } else if (target.priorityScore >= MEDIUM_RISK_THRESHOLD) {
      alert(
        "mass-audit",
        `MEDIUM RISK: ${target.chain}:${target.address}`,
        `Score: ${target.priorityScore} | TVL: $${target.tvlUsd.toFixed(0)} | ` +
        `Findings: ${staticFindings + slitherCount + llmVulns}`,
      );
    } else {
      info(
        "mass-audit",
        `${target.id} — score=${target.priorityScore} tvl=$${target.tvlUsd.toFixed(0)} ` +
        `findings=${staticFindings + slitherCount + llmVulns}`,
      );
    }

    this.targets.set(target.id, target);
  }

  // ── Helpers ───────────────────────────────────────────────────────────

  /**
   * Fallback: bytecode-only analysis via existing StaticAnalyzer pipeline.
   */
  private async bytecodeOnlyAnalysis(
    target: MassAuditTarget,
    client: PublicClient,
    analyzer: StaticAnalyzer,
  ): Promise<void> {
    try {
      const bytecode = await client.getBytecode({ address: target.address });
      if (!bytecode || bytecode === "0x") return;

      const shimDeployment: NewDeployment = {
        contractAddress: target.address,
        deployerAddress: "0x0000000000000000000000000000000000000000" as Address,
        txHash: "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`,
        blockNumber: 0n,
        blockTimestamp: Math.floor(Date.now() / 1000),
        bytecodeSize: bytecode.length / 2,
        isProxy: !!target.explorerEntry?.implementationAddress,
        implementationAddress: target.explorerEntry?.implementationAddress,
        fundHandling: {
          isFundHandling: true,
          hasPayable: false,
          hasERC20Transfers: true,
          hasApprovals: false,
          hasDelegatecall: false,
          hasMint: false,
          hasBurn: false,
          confidence: 50,
        },
      };

      target.staticReport = await analyzer.analyze(shimDeployment);
    } catch (err) {
      warn("mass-audit", `Bytecode analysis failed for ${target.id}: ${(err as Error).message}`);
    }
  }

  /**
   * Priority score formula:
   *   base = (riskWeight * 0.4) + (tvlWeight * 0.35) + (exploitabilityWeight * 0.25)
   *   + recency boost (contracts <7d: +20, <30d: +10)
   *   + selector collision boost (critical: +15, high: +8 per finding)
   *   + AI-generated boost (from aiFingerprint.riskBoost)
   */
  private computePriorityScore(target: MassAuditTarget): number {
    // Risk weight: directly from static analysis risk score
    const riskWeight = target.staticReport?.riskScore ?? 0;

    // TVL weight: $10M+ = max score, logarithmic scale
    const tvlWeight = target.tvlUsd > 0
      ? Math.min(Math.log10(target.tvlUsd / 1000 + 1) * 30, 100)
      : 0;

    // Exploitability weight: based on finding characteristics
    let exploitWeight = 0;

    // Slither high-confidence/high-impact findings
    const criticalSlither = (target.slitherFindings ?? []).filter(
      (f) => f.impact === "High" && f.confidence === "High",
    );
    exploitWeight += Math.min(criticalSlither.length * 20, 60);

    // LLM high-severity findings
    const criticalLlm = (target.llmResult?.vulnerabilities ?? []).filter(
      (v) => (v.severity === "critical" || v.severity === "high") && v.confidence >= 70,
    );
    exploitWeight += Math.min(criticalLlm.length * 15, 40);

    // Static analysis critical findings
    const criticalStatic = (target.staticReport?.findings ?? []).filter(
      (f) => f.severity === "critical" && f.confidence >= 80,
    );
    exploitWeight += Math.min(criticalStatic.length * 10, 30);

    exploitWeight = Math.min(exploitWeight, 100);

    let score = (riskWeight * 0.4) + (tvlWeight * 0.35) + (exploitWeight * 0.25);

    // ── Recency boost: recently deployed contracts are higher priority ──
    if (target.deployedAt) {
      const ageMs = Date.now() - (target.deployedAt * 1000);
      const ageDays = ageMs / (1000 * 60 * 60 * 24);
      if (ageDays < 7) score += 20;
      else if (ageDays < 30) score += 10;
    }

    // ── Selector collision boost ────────────────────────────────────────
    for (const collision of target.selectorCollisions ?? []) {
      if (collision.severity === "critical") score += 15;
      else if (collision.severity === "high") score += 8;
      else if (collision.severity === "medium") score += 3;
    }

    // ── AI fingerprint boost ───────────────────────────────────────────
    if (target.aiFingerprint?.isLikelyAiGenerated) {
      score += target.aiFingerprint.riskBoost;
    }

    return Math.round(Math.min(score, 100));
  }

  /**
   * Estimates TVL in USD via totalAssets() or totalSupply().
   */
  private async estimateTVL(address: Address, chain: SupportedChain): Promise<number> {
    const client = this.clients.get(chain);
    if (!client) return 0;

    try {
      const totalAssets = await client.readContract({
        address,
        abi: totalAssetsAbi,
        functionName: "totalAssets",
      });
      const n = Number(totalAssets);
      if (n > 0) return totalAssets < 1_000_000_000_000n ? n / 1e6 : n / 1e18;
    } catch { /* no totalAssets */ }

    try {
      const totalSupply = await client.readContract({
        address,
        abi: totalSupplyAbi,
        functionName: "totalSupply",
      });
      const n = Number(totalSupply);
      if (n > 0) return totalSupply < 1_000_000_000_000n ? n / 1e6 : n / 1e18;
    } catch { /* no totalSupply */ }

    return 0;
  }

  /**
   * Enqueues an address for auditing if not already tracked.
   * Returns true if newly added.
   */
  private enqueueAddress(address: Address, chain: SupportedChain): boolean {
    const id = `${chain}:${address.toLowerCase()}`;
    if (this.targets.has(id)) return false;

    this.targets.set(id, {
      id,
      address: address.toLowerCase() as Address,
      chain,
      status: "queued",
      tvlUsd: 0,
      priorityScore: 0,
      enqueuedAt: Date.now(),
    });

    this.stats.totalQueued++;
    return true;
  }

  /**
   * Returns pending targets sorted by TVL (highest first) for processing.
   */
  private getPendingTargets(limit: number): MassAuditTarget[] {
    return [...this.targets.values()]
      .filter((t) => t.status === "queued")
      .sort((a, b) => b.tvlUsd - a.tvlUsd)
      .slice(0, limit);
  }

  private getEnabledChains(): SupportedChain[] {
    const chains: SupportedChain[] = [];
    if (FEATURES.massAuditSonic) chains.push("sonic");
    if (FEATURES.massAuditEthereum) chains.push("ethereum");
    return chains;
  }

  // ── Persistence ─────────────────────────────────────────────────────

  private loadDb(): void {
    try {
      if (!existsSync(DB_PATH)) return;
      const parsed: SerializedAuditDB = JSON.parse(readFileSync(DB_PATH, "utf-8"));
      if (parsed.version !== 1) return;

      this.stats = parsed.stats;

      for (const [, entry] of Object.entries(parsed.targets)) {
        // Only reload completed or queued targets (skip in-progress from crashed runs)
        const target: MassAuditTarget = {
          id: entry.id,
          address: entry.address as Address,
          chain: entry.chain,
          status: entry.status === "completed" || entry.status === "failed"
            ? entry.status
            : "queued", // Reset in-progress to queued
          tvlUsd: entry.tvlUsd,
          priorityScore: entry.priorityScore,
          deployedAt: entry.deployedAt,
          enqueuedAt: entry.enqueuedAt,
          completedAt: entry.completedAt,
          errorMessage: entry.errorMessage,
        };
        this.targets.set(entry.id, target);
      }

      info("mass-audit", `Loaded ${this.targets.size} targets from DB`);
    } catch (err) {
      warn("mass-audit", `DB load failed: ${(err as Error).message}`);
    }
  }

  private saveDb(): void {
    try {
      mkdirSync(dirname(DB_PATH), { recursive: true });

      const serialized: SerializedAuditDB = {
        version: 1,
        savedAt: new Date().toISOString(),
        stats: this.stats,
        targets: {},
      };

      for (const [id, target] of this.targets.entries()) {
        serialized.targets[id] = {
          id: target.id,
          address: target.address,
          chain: target.chain,
          status: target.status,
          tvlUsd: target.tvlUsd,
          priorityScore: target.priorityScore,
          riskScore: target.staticReport?.riskScore ?? 0,
          findingsCount: target.staticReport?.findings.length ?? 0,
          slitherCount: target.slitherFindings?.length ?? 0,
          llmVulnCount: target.llmResult?.vulnerabilities.length ?? 0,
          selectorCollisionCount: target.selectorCollisions?.length ?? 0,
          isLikelyAiGenerated: target.aiFingerprint?.isLikelyAiGenerated ?? false,
          isVerified: target.explorerEntry?.isVerified ?? false,
          isDeFi: target.classification?.isDeFi ?? false,
          category: target.classification?.category ?? "unknown",
          deployedAt: target.deployedAt,
          enqueuedAt: target.enqueuedAt,
          completedAt: target.completedAt,
          errorMessage: target.errorMessage,
        };
      }

      writeFileSync(DB_PATH, JSON.stringify(serialized, null, 2));
    } catch (err) {
      warn("mass-audit", `DB save failed: ${(err as Error).message}`);
    }
  }
}
