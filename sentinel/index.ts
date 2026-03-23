/**
 * SENTINEL — Sonic Red-Team Dominance Engine
 *
 * Main entry point. Wires all modules into a unified per-block event loop.
 * See SENTINEL_SONIC_DIRECTIVE.md for architecture documentation.
 */

import { config as dotenvConfig } from "dotenv";
// Load .env before any other imports read process.env
dotenvConfig({ path: new URL("../../.env", import.meta.url).pathname });
import { createPublicClient, http, webSocket, type PublicClient } from "viem";
import { mainnet } from "viem/chains";

import { info, warn, alert, critical } from "./alerter.js";
import {
  FEATURES,
  RPC_URL,
  WS_URL,
  PRIVATE_KEY,
  EULER_LIQUIDATOR_CONTRACT,
  SILO_LIQUIDATION_HELPER,
  MAX_GAS_PER_TX,
  ABORT_GAS_PRICE_GWEI,
  MASS_AUDIT_INTERVAL_MS,
} from "./config.js";
import { DeploymentMonitor } from "./deployMonitor.js";
import { ExploitBuilder } from "./exploitBuilder.js";
import { FuzzingOrchestrator } from "./fuzzer.js";
import { GovernanceShockDetector } from "./govShock.js";
import { KillListEngine } from "./killList.js";
import { MassAuditOrchestrator } from "./massAudit.js";
import { MisconfigSniper } from "./misconfigSniper.js";
import { OracleHunter } from "./oracleHunter.js";
import { ReAnalyzer } from "./reAnalysis.js";
import { StaticAnalyzer } from "./staticAnalysis.js";
import { SymbolicExecRunner } from "./symbolicExec.js";
import type { BlockContext, NewDeployment, StaticAnalysisReport } from "./types.js";

// dotenvConfig already called at top of file

// ─── Startup checks ───────────────────────────────────────────────────────

function validateConfig(): void {
  if (!PRIVATE_KEY) {
    throw new Error("PRIVATE_KEY not set in environment");
  }
  if (
    EULER_LIQUIDATOR_CONTRACT === "0x0000000000000000000000000000000000000000" &&
    SILO_LIQUIDATION_HELPER === "0x0000000000000000000000000000000000000000"
  ) {
    warn("index", "Both EULER_LIQUIDATOR_CONTRACT and SILO_LIQUIDATION_HELPER are zero — execution disabled");
  }
  console.log("✓ Config validated");
}

// ─── Module instantiation ─────────────────────────────────────────────────

function createModules(client: PublicClient) {
  return {
    oracleHunter: FEATURES.oracleHunter ? new OracleHunter(client) : null,
    govShock: FEATURES.govShock ? new GovernanceShockDetector(client) : null,
    killList: FEATURES.killList ? new KillListEngine(client) : null,
    misconfigSniper: FEATURES.misconfigSniper ? new MisconfigSniper(client) : null,
    deployMonitor: FEATURES.deployMonitor ? new DeploymentMonitor(client) : null,
    staticAnalyzer: FEATURES.staticAnalysis ? new StaticAnalyzer(client) : null,
    symbolicExec: FEATURES.symbolicExec ? new SymbolicExecRunner() : null,
    fuzzer: FEATURES.fuzzing ? new FuzzingOrchestrator() : null,
    exploitBuilder: new ExploitBuilder(client),
    reAnalyzer: new ReAnalyzer(client),
    massAudit: FEATURES.massAudit ? new MassAuditOrchestrator() : null,
  };
}

// ─── Per-block processing ─────────────────────────────────────────────────

let isProcessing = false;
let lastBlockNumber = 0n;

async function processBlock(
  blockNumber: bigint,
  modules: ReturnType<typeof createModules>,
): Promise<void> {
  if (isProcessing) {
    return; // skip if previous block still processing
  }
  if (blockNumber <= lastBlockNumber) {
    return; // skip duplicate
  }

  isProcessing = true;
  lastBlockNumber = blockNumber;

  const ctx: BlockContext = {
    blockNumber,
    blockTimestamp: Math.floor(Date.now() / 1000),
    baseFeePerGas: 0n, // updated below
  };

  try {
    // ── Safety: abort if gas price is extreme ─────────────────────────────
    try {
      const block = await getPublicClient().getBlock({ blockNumber });
      if (block?.baseFeePerGas) {
        ctx.baseFeePerGas = block.baseFeePerGas;
        if (ctx.baseFeePerGas > ABORT_GAS_PRICE_GWEI * 1_000_000_000n) {
          warn("index", `Gas price ${ctx.baseFeePerGas / 1_000_000_000n} gwei > abort threshold, skipping block`);
          return;
        }
      }
    } catch {
      // non-fatal
    }

    // ── Module A: Oracle Hunter (every 10 blocks) ─────────────────────────
    if (modules.oracleHunter && blockNumber % 10n === 0n) {
      try {
        const oracleAlerts = await modules.oracleHunter.run(ctx);
        for (const oa of oracleAlerts) {
          const severity = oa.severity === "critical" ? "critical" : "alert";
          const msgFn = severity === "critical" ? critical : alert;
          msgFn(
            "oracle-hunter",
            `Oracle ${oa.feedConfig.name} divergence ${oa.divergencePct.toFixed(1)}%`,
            `Staleness ratio: ${oa.stalenessRatio.toFixed(0)}x | Phantom positions: ${oa.phantomHealthyPositions.length} | Total profit: $${oa.phantomHealthyPositions.reduce((s, p) => s + p.estimatedProfitUsd, 0).toFixed(2)}`,
            oa,
          );
        }
      } catch (err) {
        warn("oracle-hunter", `Module A error: ${(err as Error).message}`);
      }
    }

    // ── Module B: Governance Shock (every block) ──────────────────────────
    if (modules.govShock) {
      try {
        const govAlerts = await modules.govShock.run(ctx);
        for (const ga of govAlerts) {
          critical(
            "gov-shock",
            `Governance event: ${ga.type} | ${ga.affectedPositions.length} positions affected`,
            `Immediate: ${ga.immediateAction} | Est profit: $${ga.estimatedTotalProfitUsd.toFixed(2)}`,
            ga,
          );
        }
      } catch (err) {
        warn("gov-shock", `Module B error: ${(err as Error).message}`);
      }
    }

    // ── Module C: Kill List (every block for tier 0) ──────────────────────
    if (modules.killList) {
      try {
        const killResult = await modules.killList.run(ctx);
        if (killResult.tier0.length > 0) {
          info(
            "kill-list",
            `Tier 0: ${killResult.tier0.length} hot positions | Top profit: $${killResult.tier0[0]?.estimatedProfitUsd?.toFixed(2) ?? "0"}`,
          );
        }
      } catch (err) {
        warn("kill-list", `Module C error: ${(err as Error).message}`);
      }
    }

    // ── Module D: Misconfig Sniper (every 1000 blocks) ────────────────────
    if (modules.misconfigSniper && blockNumber % 1000n === 0n) {
      try {
        const findings = await modules.misconfigSniper.run(ctx);
        for (const f of findings) {
          const severity = f.severity === "critical" ? "critical" : f.severity === "high" ? "alert" : "warning";
          const msgFn = severity === "critical" ? critical : severity === "alert" ? alert : warn;
          msgFn("misconfig-sniper", `${f.class.toUpperCase()} @ ${f.contractAddress}`, f.description, f);
        }
      } catch (err) {
        warn("misconfig-sniper", `Module D error: ${(err as Error).message}`);
      }
    }

    // ── Module F.1: Deploy Monitor (every block) ──────────────────────────
    let newDeployments: NewDeployment[] = [];
    if (modules.deployMonitor) {
      try {
        newDeployments = await modules.deployMonitor.run(ctx);
        if (newDeployments.length > 0) {
          info(
            "deploy-monitor",
            `Block ${blockNumber}: ${newDeployments.length} new contracts, ${newDeployments.filter((d) => d.fundHandling.isFundHandling).length} fund-handling`,
          );
        }
      } catch (err) {
        warn("deploy-monitor", `Module F.1 error: ${(err as Error).message}`);
      }
    }

    // ── Module F.2-F.5: Analysis pipeline (async, non-blocking) ──────────
    const fundHandlingDeployments = newDeployments.filter((d) => d.fundHandling.isFundHandling);
    if (fundHandlingDeployments.length > 0 && modules.staticAnalyzer) {
      void runAnalysisPipeline(fundHandlingDeployments, modules);
    }

    // ── Module H.4: Upgrade Path Monitor (every block) ───────────────────
    if (modules.massAudit) {
      try {
        const upgradeAlerts = await modules.massAudit.upgradeMonitor.run(ctx, "ethereum");
        for (const ua of upgradeAlerts) {
          critical(
            "upgrade-monitor",
            `PROXY UPGRADED: ${ua.proxyAddress.slice(0, 12)}… → ${ua.newImpl.slice(0, 12)}…`,
            `${ua.diffFindings.length} diff findings | Severity: ${ua.severity}`,
            ua,
          );
        }
      } catch (err) {
        warn("upgrade-monitor", `H.4 error: ${(err as Error).message}`);
      }
    }

    // ── Module F.6: Re-Analysis ───────────────────────────────────────────
    if (modules.reAnalyzer) {
      try {
        const toReanalyze = await modules.reAnalyzer.run(ctx, newDeployments);
        if (toReanalyze.length > 0 && modules.staticAnalyzer) {
          info("re-analyzer", `${toReanalyze.length} contracts scheduled for re-analysis`);
          // Queue for analysis (runs async)
          void (async () => {
            for (const addr of toReanalyze.slice(0, 3)) { // max 3 per block
              try {
                const bytecode = await getPublicClient().getCode({ address: addr });
                if (bytecode) {
                  const fakeDeploy: NewDeployment = {
                    contractAddress: addr,
                    deployerAddress: "0x0000000000000000000000000000000000000000",
                    txHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
                    blockNumber: ctx.blockNumber,
                    blockTimestamp: ctx.blockTimestamp,
                    bytecodeSize: bytecode.length / 2,
                    isProxy: false,
                    fundHandling: { isFundHandling: true, hasPayable: false, hasERC20Transfers: true, hasApprovals: false, hasDelegatecall: false, hasMint: false, hasBurn: false, confidence: 50 },
                  };
                  await runAnalysisPipeline([fakeDeploy], modules, true);
                }
              } catch {
                // skip
              }
            }
          })();
        }
      } catch (err) {
        warn("re-analyzer", `Module F.6 error: ${(err as Error).message}`);
      }
    }
  } finally {
    isProcessing = false;
  }
}

// ─── Analysis pipeline (runs asynchronously, non-blocking) ───────────────

async function runAnalysisPipeline(
  deployments: NewDeployment[],
  modules: ReturnType<typeof createModules>,
  isReanalysis = false,
): Promise<void> {
  if (!modules.staticAnalyzer) return;

  for (const deployment of deployments) {
    try {
      // ── Skip already-analyzed contracts unless explicitly re-queued ─────
      // The deploy monitor rescans recent blocks on every restart and will
      // re-find contracts from earlier runs. If the reAnalyzer already has
      // the address, the full pipeline (static → sym → fuzz → exploit) has
      // already run and any findings are already in analysis.jsonl.
      if (
        !isReanalysis &&
        modules.reAnalyzer?.getDatabase().has(deployment.contractAddress.toLowerCase() as `0x${string}`)
      ) {
        continue;
      }

      info("static-analysis", `Analyzing ${deployment.contractAddress} (${deployment.bytecodeSize} bytes)`);

      const report: StaticAnalysisReport = await modules.staticAnalyzer.analyze(deployment);

      if (modules.reAnalyzer) {
        modules.reAnalyzer.registerContract(deployment.contractAddress, report);
      }

      info(
        "static-analysis",
        `${deployment.contractAddress} score=${report.riskScore} findings=${report.findings.length}`,
      );

      if (report.riskScore < 40) {
        continue; // Low risk, skip deeper analysis
      }

      alert(
        "static-analysis",
        `HIGH RISK contract deployed: ${deployment.contractAddress}`,
        `Risk score: ${report.riskScore}/100 | Findings: ${report.findings.length} | Admin EOA: ${report.adminIsEOA ?? "unknown"}`,
        report,
      );

      // ── F.3: Symbolic execution for HIGH risk ─────────────────────────
      let symResult;
      if (modules.symbolicExec && report.riskScore > 70) {
        try {
          symResult = await modules.symbolicExec.run(deployment.contractAddress, report);
          if (symResult.violations.length > 0) {
            critical(
              "symbolic-exec",
              `PROPERTY VIOLATION in ${deployment.contractAddress}`,
              `${symResult.violations.length} violations found | Paths: ${symResult.pathsExplored}`,
              symResult,
            );
          }
        } catch (err) {
          warn("symbolic-exec", `F.3 error on ${deployment.contractAddress}: ${(err as Error).message}`);
        }
      }

      // ── F.4: Fuzzing for MEDIUM-HIGH risk ─────────────────────────────
      let fuzzResults;
      if (modules.fuzzer && report.riskScore >= 40) {
        try {
          fuzzResults = await modules.fuzzer.runAllCampaigns(deployment.contractAddress, report);
          const findings = fuzzResults.filter((r) => r.status === "finding");
          if (findings.length > 0) {
            critical(
              "fuzzer",
              `FUZZ FINDING in ${deployment.contractAddress}`,
              `${findings.length} campaigns found violations`,
              findings,
            );
          }
        } catch (err) {
          warn("fuzzer", `F.4 error on ${deployment.contractAddress}: ${(err as Error).message}`);
        }
      }

      // ── TVL gate: don't build exploits for empty contracts ────────────
      // Contracts with zero ETH balance and zero measured TVL can't yield
      // profit. Skip the exploit builder to prevent $0-profit CRITICAL spam.
      try {
        const bal = await getPublicClient().getBalance({
          address: deployment.contractAddress,
        });
        const tvl =
          modules.reAnalyzer
            ?.getDatabase()
            .get(deployment.contractAddress.toLowerCase() as `0x${string}`)?.tvlUsd ?? 0;
        if (bal === 0n && tvl < 1) {
          info(
            "exploit-builder",
            `${deployment.contractAddress} — zero ETH/TVL, skipping exploit build`,
          );
          continue;
        }
      } catch { /* fail open: run exploit builder if balance check errors */ }

      // ── F.5: Exploit construction (analysis only, requires human review)
      try {
        const exploitFindings = await modules.exploitBuilder.processFindings(
          report,
          symResult,
          fuzzResults,
        );

        for (const ef of exploitFindings) {
          if (ef.severity === "critical" || ef.severity === "high") {
            critical(
              "exploit-builder",
              `EXPLOIT FINDING [REQUIRES HUMAN REVIEW]: ${ef.contractAddress}`,
              `Class: ${ef.exploitClass} | Est profit: $${ef.estimatedGrossProfitUsd.toFixed(0)} | Atomic: ${ef.isAtomic} | Flash: ${ef.isFlashLoanable}`,
              ef,
            );
          }
        }
      } catch (err) {
        warn("exploit-builder", `F.5 error on ${deployment.contractAddress}: ${(err as Error).message}`);
      }
    } catch (err) {
      warn("analysis-pipeline", `Failed to analyze ${deployment.contractAddress}: ${(err as Error).message}`);
    }
  }
}

// ─── Client singleton ─────────────────────────────────────────────────────

let _publicClient: PublicClient | null = null;

function getPublicClient(): PublicClient {
  if (!_publicClient) throw new Error("Client not initialized");
  return _publicClient;
}

// ─── E2E test mode ────────────────────────────────────────────────────────

async function runE2ETest(modules: ReturnType<typeof createModules>): Promise<void> {
  console.log("\n=== SENTINEL E2E TEST MODE ===\n");

  const client = getPublicClient();
  const block = await client.getBlock({ blockTag: "latest" });

  const ctx: BlockContext = {
    blockNumber: block.number,
    blockTimestamp: Number(block.timestamp),
    baseFeePerGas: block.baseFeePerGas ?? 0n,
  };

  console.log(`Testing at block ${ctx.blockNumber}`);

  // Test each module
  const tests: Array<[string, () => Promise<unknown>]> = [];

  if (modules.oracleHunter) {
    tests.push(["Module A (Oracle Hunter)", () => modules.oracleHunter!.run(ctx)]);
  }
  if (modules.govShock) {
    tests.push(["Module B (Gov Shock)", () => modules.govShock!.run(ctx)]);
  }
  if (modules.killList) {
    tests.push(["Module C (Kill List)", () => modules.killList!.run(ctx)]);
  }
  if (modules.misconfigSniper) {
    tests.push(["Module D (Misconfig)", () => modules.misconfigSniper!.run(ctx)]);
  }
  if (modules.deployMonitor) {
    tests.push(["Module F.1 (Deploy Monitor)", () => modules.deployMonitor!.run(ctx)]);
  }

  let passed = 0;
  let failed = 0;

  for (const [name, testFn] of tests) {
    try {
      const result = await testFn();
      console.log(`  ✓ ${name} — OK (${JSON.stringify(result).length} bytes result)`);
      passed++;
    } catch (err) {
      console.log(`  ✗ ${name} — FAIL: ${(err as Error).message}`);
      failed++;
    }
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed\n`);

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log("=== E2E TEST PASSED ===\n");
    process.exit(0);
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("SENTINEL v1.0.0 — Ethereum Mainnet MEV Dominance Engine");
  console.log(`Chain: Ethereum (1) | RPC: ${RPC_URL}`);

  validateConfig();

  // Create viem client
  const transport = WS_URL
    ? webSocket(WS_URL, { reconnect: true })
    : http(RPC_URL);

  _publicClient = createPublicClient({
    chain: mainnet,
    transport,
  });

  const modules = createModules(_publicClient);

  // E2E test mode
  if (process.argv.includes("--e2e")) {
    await runE2ETest(modules);
    return;
  }

  // Startup block
  const startBlock = await _publicClient.getBlockNumber();
  info("index", `Sentinel starting at block ${startBlock}`);

  // Report enabled modules
  const enabledModules = [
    FEATURES.oracleHunter && "A:OracleHunter",
    FEATURES.govShock && "B:GovShock",
    FEATURES.killList && "C:KillList",
    FEATURES.misconfigSniper && "D:MisconfigSniper",
    FEATURES.deployMonitor && "F.1:DeployMonitor",
    FEATURES.staticAnalysis && "F.2:StaticAnalysis",
    FEATURES.symbolicExec && "F.3:SymbolicExec",
    FEATURES.fuzzing && "F.4:Fuzzing",
    "F.5:ExploitBuilder",
    "F.6:ReAnalysis",
    FEATURES.massAudit && "G:MassAudit",
    FEATURES.llmAnalysis && "G.3:LLMAnalysis",
    FEATURES.massAudit && "H:CompositionAnalysis",
    FEATURES.massAudit && "H.2:SelectorCollision",
    FEATURES.massAudit && "H.3:AIFingerprint",
    FEATURES.massAudit && "H.4:UpgradeMonitor",
    FEATURES.diffCompiler && "H.1:DiffCompiler",
    FEATURES.evmAnalysis && "EVM:BytecodeEngine",
  ].filter(Boolean);
  info("index", `Active modules: ${enabledModules.join(", ")}`);

  // Subscribe to new blocks
  if (WS_URL) {
    // WebSocket subscription (preferred)
    _publicClient.watchBlocks({
      onBlock: (block) => {
        void processBlock(block.number, modules);
      },
      onError: (err) => {
        warn("index", `Block watch error: ${err.message}`);
      },
    });
    info("index", "Block subscription active (WebSocket)");
  } else {
    // HTTP polling fallback
    let lastPolled = startBlock;
    const poll = async () => {
      try {
        const current = await _publicClient!.getBlockNumber();
        if (current > lastPolled) {
          for (let b = lastPolled + 1n; b <= current; b++) {
            await processBlock(b, modules);
          }
          lastPolled = current;
        }
      } catch (err) {
        warn("index", `Poll error: ${(err as Error).message}`);
      }
    };
    setInterval(() => { void poll(); }, 1000);
    info("index", "Block polling active (HTTP, 1s interval)");
  }

  // ── Module G: Mass Audit Pipeline (timer-based, independent of block loop)
  if (modules.massAudit) {
    modules.massAudit.start(MASS_AUDIT_INTERVAL_MS);
    // Seed upgrade monitor cache so we have a baseline before first upgrade event
    const enabledChains: Array<"sonic" | "ethereum"> = [];
    if (process.env["ENABLE_MASS_AUDIT_ETHEREUM"] !== "false") enabledChains.push("ethereum");
    if (process.env["ENABLE_MASS_AUDIT_SONIC"] === "true") enabledChains.push("sonic");
    for (const chain of enabledChains) {
      void modules.massAudit.upgradeMonitor.seedCache(chain).catch((err: Error) =>
        warn("upgrade-monitor", `Seed failed for ${chain}: ${err.message}`),
      );
    }
    info("index", `Mass audit pipeline active (interval: ${(MASS_AUDIT_INTERVAL_MS / 1000 / 60).toFixed(0)} min)`);
  }

  info("index", "Sentinel is live. Monitoring Ethereum...");
}

// ─── Graceful shutdown ────────────────────────────────────────────────────

process.on("SIGINT", () => {
  info("index", "Received SIGINT, shutting down...");
  process.exit(0);
});

process.on("SIGTERM", () => {
  info("index", "Received SIGTERM, shutting down...");
  process.exit(0);
});

process.on("uncaughtException", (err) => {
  critical("index", "Uncaught exception", err.message, { stack: err.stack });
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  warn("index", `Unhandled rejection: ${String(reason)}`);
});

// ─── Start ────────────────────────────────────────────────────────────────

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
