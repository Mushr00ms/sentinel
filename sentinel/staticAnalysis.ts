// FILE: staticAnalysis.ts

import { exec } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import type { PublicClient, Address, Hex } from "viem";
import type {
  NewDeployment,
  StaticAnalysisReport,
  StaticAnalysisFinding,
  DecompiledFunction,
  ApprovalNode,
  ExternalCall,
  MisconfigSeverity,
  RiskClass,
  SlitherFinding,
  ExplorerContractEntry,
  SupportedChain,
} from "./types.js";
import { TOOLCHAIN, VULNERABLE_SELECTORS, RPC_URL, FEATURES } from "./config.js";
import { CHAIN_CONFIGS } from "./chains.js";
import { analyzeEVMBytecode, containsOpcode } from "./evm/index.js";
import type { EVMAnalysisResult, StorageLayoutResult } from "./evm/index.js";
import { runAllDetectors } from "./detectors/index.js";
import { matchExploitPatterns, patternMatchesToFindings } from "./exploitPatterns/matcher.js";
import type { EVMAnalysisResultRef, ExploitPatternMatchRef } from "./types.js";

const execAsync = promisify(exec);

// ─── Constants ────────────────────────────────────────────────────────────

/** Base URL for 4byte.directory function signature lookup. */
const FOURBYTE_API = "https://www.4byte.directory/api/v1/signatures/";

/** Heimdall subprocess timeout in milliseconds (matches --timeout 60). */
const HEIMDALL_TIMEOUT_MS = 75_000;

/** Directory prefix used for Heimdall output. */
const HEIMDALL_OUTPUT_BASE = "/tmp/sentinel";

/** Risk score weights per severity. */
const SEVERITY_WEIGHTS: Record<MisconfigSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

// ─── Internal types ────────────────────────────────────────────────────────

/**
 * Shape of an ABI entry as produced by Heimdall's `abi.json` output.
 * We only need the fields that matter for our analysis.
 */
interface HeimdallAbiEntry {
  type: string; // "function" | "event" | "constructor" | ...
  name?: string;
  inputs?: { type: string; name?: string }[];
  outputs?: { type: string }[];
  stateMutability?: string; // "payable" | "nonpayable" | "view" | "pure"
  selector?: string; // 4-byte hex selector, may or may not carry "0x" prefix
}

/** Internal representation of Heimdall's parsed output. */
export interface HeimdallOutput {
  /** Parsed ABI entries from abi.json */
  abi: HeimdallAbiEntry[];
  /** Path to the output directory Heimdall wrote to */
  outputDir: string;
  /** Whether the run succeeded or fell back to pattern matching */
  success: boolean;
  /** Error message if the run failed */
  error?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Strips `0x` prefix and lower-cases for uniform substring matching. */
function stripHex(hex: Hex | string): string {
  return hex.startsWith("0x") ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

/**
 * Derives a 4-byte selector hex string from a function name + input types,
 * or returns the selector as-is if it already looks like one.
 */
function normaliseSelector(raw: string | undefined): Hex {
  if (!raw) return "0x00000000";
  const clean = raw.startsWith("0x") ? raw : `0x${raw}`;
  return clean.slice(0, 10) as Hex;
}

/**
 * Look up a human-readable function signature from 4byte.directory.
 * Returns undefined if the lookup fails or returns no results.
 */
async function lookupFunctionName(
  selector: string,
): Promise<string | undefined> {
  const bare = selector.startsWith("0x") ? selector.slice(2) : selector;
  try {
    const res = await fetch(`${FOURBYTE_API}?hex_signature=0x${bare}`, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) return undefined;
    const json = (await res.json()) as {
      results?: { text_signature: string }[];
    };
    return json.results?.[0]?.text_signature;
  } catch {
    return undefined;
  }
}

/**
 * Opcode-aware bytecode pattern matching. Walks bytecode respecting PUSH
 * operand boundaries to avoid false positives from matching data bytes.
 * Used as a fallback when Heimdall and the EVM engine are unavailable.
 */
function bytecodePatternFindings(bytecode: Hex): StaticAnalysisFinding[] {
  const code = stripHex(bytecode);
  const findings: StaticAnalysisFinding[] = [];

  if (containsOpcode(code, "f4")) { // DELEGATECALL
    findings.push({
      riskClass: "calldata_forwarding",
      severity: "high",
      functionSelector: "0x00000000",
      description: "Contract contains DELEGATECALL opcode – potential proxy or calldata-forwarding pattern.",
      confidence: 60,
    });
  }

  if (containsOpcode(code, "ff")) { // SELFDESTRUCT
    findings.push({
      riskClass: "drain",
      severity: "critical",
      functionSelector: "0x00000000",
      description: "Contract contains SELFDESTRUCT opcode – can destroy contract and drain ETH balance.",
      confidence: 80,
    });
  }

  if (containsOpcode(code, "32")) { // ORIGIN
    findings.push({
      riskClass: "flash_loan_attack",
      severity: "medium",
      functionSelector: "0x00000000",
      description: "ORIGIN opcode detected – possible tx-origin auth (vulnerable to phishing).",
      confidence: 50,
    });
  }

  if (
    code.includes("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef") &&
    containsOpcode(code, "f4")
  ) {
    findings.push({
      riskClass: "approval_exploit",
      severity: "high",
      functionSelector: "0x00000000",
      description: "ERC-20 Transfer topic combined with DELEGATECALL – potential token approval exploitation.",
      confidence: 55,
    });
  }

  if (code.includes("07a2d13a")) { // convertToAssets selector (in PUSH4 data, safe to check as substring)
    findings.push({
      riskClass: "erc4626_inflation",
      severity: "medium",
      functionSelector: "0x07a2d13a",
      functionName: "convertToAssets(uint256)",
      description: "ERC-4626 vault interface detected – review for share-inflation attack vectors.",
      confidence: 45,
    });
  }

  return findings;
}

// ─── StaticAnalyzer ────────────────────────────────────────────────────────

/**
 * Module F.2 – Bytecode decompilation and static analysis.
 *
 * Runs Heimdall against newly deployed contracts, parses the resulting ABI,
 * matches selectors against known-vulnerable patterns, enriches with
 * 4byte.directory labels, and produces a scored `StaticAnalysisReport`.
 *
 * Falls back to pure bytecode pattern matching when Heimdall is unavailable
 * or times out.
 */
export class StaticAnalyzer {
  private readonly publicClient: PublicClient;

  /** Completed reports keyed by contract address (lower-cased). */
  private readonly analysisCache: Map<Address, StaticAnalysisReport> =
    new Map();

  /**
   * Tracks addresses that are currently being analysed to prevent concurrent
   * duplicate work.
   */
  private readonly pendingAnalysis: Set<Address> = new Set();

  constructor(publicClient: PublicClient) {
    this.publicClient = publicClient;
  }

  // ── Public API ────────────────────────────────────────────────────────

  /**
   * Full analysis pipeline for a freshly deployed contract.
   *
   * 1. Run Heimdall (or fall back to bytecode patterns).
   * 2. Match selectors against `VULNERABLE_SELECTORS`.
   * 3. Build on-chain approval graph.
   * 4. Compute risk score.
   * 5. Cache and return the report.
   */
  async analyze(deployment: NewDeployment): Promise<StaticAnalysisReport> {
    const addr = deployment.contractAddress.toLowerCase() as Address;

    // Return cached result if available.
    const cached = this.analysisCache.get(addr);
    if (cached) return cached;

    // Guard against concurrent duplicate analysis.
    if (this.pendingAnalysis.has(addr)) {
      // Poll until the in-flight analysis resolves (simple back-off).
      return new Promise((resolve) => {
        const poll = setInterval(() => {
          const result = this.analysisCache.get(addr);
          if (result) {
            clearInterval(poll);
            resolve(result);
          }
        }, 500);
      });
    }

    this.pendingAnalysis.add(addr);

    try {
      // ── Step 1: Decompile via Heimdall ─────────────────────────────────
      const heimdallOutput = await this.runHeimdall(deployment.contractAddress);

      // ── Step 2: Build DecompiledFunction list ──────────────────────────
      const functions = await this.buildFunctionList(
        heimdallOutput,
        deployment,
      );

      // ── Step 3: Match vulnerable selectors ────────────────────────────
      const selectorFindings =
        await this.matchVulnerableSelectors(functions);

      // ── Step 4: Pattern findings (always run as supplemental check) ────
      let patternFindings: StaticAnalysisFinding[] = [];
      if (!heimdallOutput.success) {
        const bytecode = await this.safeGetBytecode(
          deployment.contractAddress,
        );
        if (bytecode) patternFindings = bytecodePatternFindings(bytecode);
      }

      // ── Step 4b: EVM engine analysis (if enabled) ─────────────────────
      let evmFindings: StaticAnalysisFinding[] = [];
      let evmAnalysisRef: EVMAnalysisResultRef | undefined;
      let exploitPatternMatchRefs: ExploitPatternMatchRef[] | undefined;

      if (FEATURES.evmAnalysis) {
        const bytecodeForEvm = await this.safeGetBytecode(deployment.contractAddress);
        if (bytecodeForEvm && bytecodeForEvm.length > 4) {
          try {
            const evmResult = analyzeEVMBytecode(bytecodeForEvm);

            // Run custom detectors
            const detectorFindings = runAllDetectors(evmResult, evmResult.storageLayout);
            evmFindings.push(...detectorFindings);

            // Run exploit pattern matcher
            const patternMatches = matchExploitPatterns(evmResult, evmResult.storageLayout);
            if (patternMatches.length > 0) {
              evmFindings.push(...patternMatchesToFindings(patternMatches));
              exploitPatternMatchRefs = patternMatches.map(m => ({
                patternId: m.pattern.id,
                patternName: m.pattern.name,
                protocol: m.pattern.protocol,
                lossAmountUsd: m.pattern.lossAmountUsd,
                matchScore: m.matchScore,
                matchedConditions: m.matchedConditions,
                description: m.pattern.description,
              }));
            }

            // Add taint-based findings
            for (const flow of evmResult.taint.flows) {
              if (flow.sink === "DELEGATECALL_TARGET" && flow.source === "CALLDATALOAD") {
                evmFindings.push({
                  riskClass: "calldata_forwarding",
                  severity: "critical",
                  functionSelector: (flow.selector ?? "0x00000000") as Hex,
                  description: `Taint flow: user calldata reaches DELEGATECALL target — arbitrary code execution risk.`,
                  confidence: flow.confidence,
                });
              }
              if (flow.sink === "SELFDESTRUCT_BENEFICIARY") {
                evmFindings.push({
                  riskClass: "selfdestruct",
                  severity: "critical",
                  functionSelector: (flow.selector ?? "0x00000000") as Hex,
                  description: `Taint flow: ${flow.source} data reaches SELFDESTRUCT beneficiary — controllable drain.`,
                  confidence: flow.confidence,
                });
              }
            }

            // Add unconditional drain findings
            for (const drain of evmResult.valueFlow.drains) {
              if (drain.severity >= 80) {
                evmFindings.push({
                  riskClass: "drain",
                  severity: "critical",
                  functionSelector: (drain.transfer.selector ?? "0x00000000") as Hex,
                  description: `Unconditional drain: ${drain.reason}`,
                  confidence: Math.min(drain.severity, 90),
                });
              }
            }

            // Store lightweight reference
            evmAnalysisRef = {
              analysisTimeMs: evmResult.analysisTimeMs,
              instructionCount: evmResult.instructionCount,
              blockCount: evmResult.blockCount,
              selectors: evmResult.selectors,
              taintFlowCount: evmResult.taint.flows.length,
              highSeverityTaintFlows: evmResult.taint.hasHighSeverityFlow,
              unconditionalDrainCount: evmResult.valueFlow.drains.length,
              storageSlotCount: evmResult.storageLayout.slots.length,
              isUpgradeableProxy: evmResult.storageLayout.isUpgradeableProxy,
              externalCallCount: evmResult.crossContractFlow.externalCallCount,
            };
          } catch {
            // EVM engine failure is non-fatal — continue with pattern findings
          }
        }
      }

      // Merge and de-duplicate findings (same selector + riskClass).
      const allFindings = this.deduplicateFindings([
        ...selectorFindings,
        ...patternFindings,
        ...evmFindings,
      ]);

      // ── Step 5: Approval graph ─────────────────────────────────────────
      const approvalGraph = await this.buildApprovalGraph(
        deployment.contractAddress,
      );

      // ── Step 6: External call graph (derived from functions) ──────────
      const externalCallGraph = this.buildExternalCallGraph(functions);

      // ── Step 7: Risk score ────────────────────────────────────────────
      const riskScore = this.computeRiskScore(allFindings);

      // ── Step 8: Proxy metadata ────────────────────────────────────────
      const proxyType = deployment.isProxy
        ? resolveProxyType(deployment)
        : undefined;

      // ── Step 9: Admin EOA check ───────────────────────────────────────
      let adminIsEOA: boolean | undefined;
      const implAddr =
        deployment.implementationAddress ?? undefined;
      if (implAddr) {
        adminIsEOA = await this.isEOA(implAddr);
      }

      const report: StaticAnalysisReport = {
        contractAddress: deployment.contractAddress,
        analysisTimestamp: Math.floor(Date.now() / 1000),
        riskScore,
        proxyType,
        implementationAddress: deployment.implementationAddress,
        adminAddress: implAddr,
        adminIsEOA,
        functions,
        findings: allFindings,
        approvalGraph,
        externalCallGraph,
        evmAnalysis: evmAnalysisRef,
        exploitPatternMatches: exploitPatternMatchRefs,
      };

      this.analysisCache.set(addr, report);
      return report;
    } finally {
      this.pendingAnalysis.delete(addr);
    }
  }

  /**
   * Runs the Heimdall decompiler against `address` and returns a parsed
   * `HeimdallOutput`.
   *
   * On failure (non-zero exit, timeout, missing output) returns a
   * `HeimdallOutput` with `success: false` so the caller can fall back to
   * bytecode pattern matching.
   */
  async runHeimdall(address: Address): Promise<HeimdallOutput> {
    const outputDir = `${HEIMDALL_OUTPUT_BASE}-${address.toLowerCase()}`;

    const cmd =
      `${TOOLCHAIN.heimdall} decompile ${address}` +
      ` --rpc-url ${RPC_URL}` +
      ` --output ${outputDir}` +
      ` --timeout 60`;

    try {
      await execAsync(cmd, { timeout: HEIMDALL_TIMEOUT_MS });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        abi: [],
        outputDir,
        success: false,
        error: `Heimdall execution failed: ${msg}`,
      };
    }

    // Attempt to read and parse abi.json.
    const abiPath = path.join(outputDir, "abi.json");
    try {
      const raw = await fs.readFile(abiPath, "utf-8");
      const abi = JSON.parse(raw) as HeimdallAbiEntry[];
      return { abi, outputDir, success: true };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        abi: [],
        outputDir,
        success: false,
        error: `Failed to read Heimdall ABI output: ${msg}`,
      };
    }
  }

  /**
   * Checks every function selector in `functions` against the known-vulnerable
   * selector registry (`VULNERABLE_SELECTORS` from config) and against a set
   * of hard-coded high-risk patterns.
   */
  async matchVulnerableSelectors(
    functions: DecompiledFunction[],
  ): Promise<StaticAnalysisFinding[]> {
    const findings: StaticAnalysisFinding[] = [];

    for (const fn of functions) {
      const bare = fn.selector.startsWith("0x")
        ? fn.selector.slice(2).toLowerCase()
        : fn.selector.toLowerCase();

      // ── Registry match ─────────────────────────────────────────────────
      const registryName = VULNERABLE_SELECTORS[`0x${bare}`];
      if (registryName) {
        const { riskClass, severity } = classifyByName(registryName);
        findings.push({
          riskClass,
          severity,
          functionSelector: fn.selector,
          functionName: fn.name ?? registryName,
          description: buildFindingDescription(registryName, fn),
          confidence: 85,
        });
      }

      // ── Structural heuristics ──────────────────────────────────────────

      // Payable + external call with user-controlled calldata → drain risk.
      if (fn.isPayable && fn.hasExternalCall) {
        findings.push({
          riskClass: "drain",
          severity: "high",
          functionSelector: fn.selector,
          functionName: fn.name,
          description:
            "Payable function with external call – potential fund drain via ETH forwarding.",
          confidence: 70,
        });
      }

      // Delegatecall without access control → calldata forwarding risk.
      if (fn.hasDelegatecall && !fn.hasAccessControl) {
        findings.push({
          riskClass: "calldata_forwarding",
          severity: "critical",
          functionSelector: fn.selector,
          functionName: fn.name,
          description:
            "DELEGATECALL without apparent access control – arbitrary storage write possible.",
          confidence: 75,
        });
      }

      // External call + storage write without access control → reentrancy.
      if (fn.hasExternalCall && fn.hasStorageWrite && !fn.hasAccessControl) {
        findings.push({
          riskClass: "reentrancy",
          severity: "high",
          functionSelector: fn.selector,
          functionName: fn.name,
          description:
            "External call followed by storage write without access control – possible reentrancy.",
          confidence: 60,
        });
      }
    }

    // Enrich findings with 4byte.directory names where missing.
    for (const finding of findings) {
      if (!finding.functionName) {
        finding.functionName = await lookupFunctionName(
          finding.functionSelector,
        );
      }
    }

    return findings;
  }

  /**
   * Queries on-chain Transfer and Approval events for `address` to construct
   * a lightweight approval graph showing which contracts have been approved to
   * spend tokens held by this contract.
   *
   * Only the most recent 10_000 blocks are scanned to keep latency manageable.
   */
  async buildApprovalGraph(address: Address): Promise<ApprovalNode[]> {
    const nodes: ApprovalNode[] = [];

    // ERC-20 Approval(address owner, address spender, uint256 value)
    const APPROVAL_TOPIC =
      "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";

    try {
      const latestBlock = await this.publicClient.getBlockNumber();
      const fromBlock = latestBlock > 10_000n ? latestBlock - 10_000n : 0n;

      // Find all Approval events where this contract is the `owner` (topic1).
      // We use a type assertion to pass raw topic filters; viem's typed getLogs
      // overload requires an `event` schema, but raw topic arrays are valid
      // JSON-RPC and work at runtime.
      const logs = await (this.publicClient.getLogs as (args: {
        fromBlock: bigint;
        toBlock: bigint;
        topics: (Hex | null)[];
      }) => Promise<{ topics: (Hex | undefined)[]; address: Address }[]>)({
        fromBlock,
        toBlock: latestBlock,
        topics: [
          APPROVAL_TOPIC as Hex,
          // Pad the 20-byte address to 32-byte topic
          `0x000000000000000000000000${address.slice(2).toLowerCase()}` as Hex,
        ],
      });

      for (const log of logs) {
        // topic[2] = spender (32 bytes, right-aligned address)
        const spenderTopic = log.topics[2];
        if (!spenderTopic) continue;
        const spenderAddr = `0x${spenderTopic.slice(-40)}` as Address;

        // Determine caller classification.
        const calledByAnyone = await this.isUnguardedApproval(
          address,
          log.address,
        );

        nodes.push({
          approvedContract: spenderAddr,
          approvedToken: log.address,
          canBeTriggeredBy: calledByAnyone ? "anyone" : "unknown",
          calldataValidated: false,
        });
      }
    } catch {
      // Network or ABI decoding errors – return empty graph rather than throw.
    }

    return nodes;
  }

  /**
   * Computes a 0–100 risk score from a list of findings.
   *
   * Weights:  CRITICAL +25 | HIGH +15 | MEDIUM +8 | LOW +3
   * Capped at 100.
   */
  computeRiskScore(findings: StaticAnalysisFinding[]): number {
    const raw = findings.reduce(
      (acc, f) => acc + (SEVERITY_WEIGHTS[f.severity] ?? 0),
      0,
    );
    return Math.min(raw, 100);
  }

  // ── Private helpers ───────────────────────────────────────────────────

  /**
   * Converts Heimdall's parsed ABI entries into `DecompiledFunction` objects.
   *
   * When Heimdall failed, falls back to pattern-matching the raw bytecode.
   */
  private async buildFunctionList(
    heimdallOutput: HeimdallOutput,
    deployment: NewDeployment,
  ): Promise<DecompiledFunction[]> {
    if (!heimdallOutput.success || heimdallOutput.abi.length === 0) {
      // Fallback: synthesise a single synthetic entry representing the full
      // contract, using the classification already performed by DeployMonitor.
      const fh = deployment.fundHandling;
      return [
        {
          selector: "0x00000000" as Hex,
          name: undefined,
          isPayable: fh.hasPayable,
          hasExternalCall: fh.hasDelegatecall,
          hasDelegatecall: fh.hasDelegatecall,
          hasStorageWrite: fh.hasERC20Transfers,
          hasAccessControl: false,
        },
      ];
    }

    const functions: DecompiledFunction[] = [];

    for (const entry of heimdallOutput.abi) {
      if (entry.type !== "function") continue;

      const selector = normaliseSelector(entry.selector);
      const isPayable = entry.stateMutability === "payable";

      // Attempt to enrich with 4byte.directory name when Heimdall did not
      // supply one.
      let name = entry.name;
      if (!name && selector !== "0x00000000") {
        name = await lookupFunctionName(selector);
      }

      // Structural inference from the ABI alone is limited; we default to
      // conservative assumptions that downstream findings can override.
      functions.push({
        selector,
        name,
        isPayable,
        hasExternalCall: false,  // enriched by pattern analysis if needed
        hasDelegatecall: false,
        hasStorageWrite: entry.stateMutability === "nonpayable",
        hasAccessControl: false, // conservative default
      });
    }

    // Overlay the coarse signals from bytecode classification.
    if (deployment.fundHandling.hasDelegatecall) {
      for (const fn of functions) {
        fn.hasDelegatecall = true;
        fn.hasExternalCall = true;
      }
    }

    return functions;
  }

  /** Builds a simplified external-call graph from a function list. */
  private buildExternalCallGraph(
    functions: DecompiledFunction[],
  ): ExternalCall[] {
    return functions
      .filter((fn) => fn.hasExternalCall || fn.hasDelegatecall)
      .map((fn) => ({
        fromFunction: fn.selector,
        targetType: fn.hasDelegatecall
          ? ("storage" as const)
          : ("user_controlled" as const),
        target: undefined,
        calldataValidated: fn.hasAccessControl,
        valueTransferred: fn.isPayable,
      }));
  }

  /**
   * Removes duplicate findings that share the same selector and riskClass,
   * keeping the one with the highest confidence.
   */
  private deduplicateFindings(
    findings: StaticAnalysisFinding[],
  ): StaticAnalysisFinding[] {
    const seen = new Map<string, StaticAnalysisFinding>();
    for (const f of findings) {
      const key = `${f.functionSelector}:${f.riskClass}`;
      const existing = seen.get(key);
      if (!existing || f.confidence > existing.confidence) {
        seen.set(key, f);
      }
    }
    return Array.from(seen.values());
  }

  /**
   * Checks whether there is an unguarded path to trigger an approval from
   * `contractAddress` for `tokenAddress`.  This is a best-effort heuristic:
   * if we cannot determine access control from the ABI alone we return false
   * (conservative – unknown).
   */
  private async isUnguardedApproval(
    _contractAddress: Address,
    _tokenAddress: Address,
  ): Promise<boolean> {
    // Without deeper symbolic execution we cannot determine this reliably.
    // Return false (conservative / unknown) rather than false-positive.
    return false;
  }

  /** Returns the deployed bytecode for `address`, or undefined on failure. */
  private async safeGetBytecode(address: Address): Promise<Hex | undefined> {
    try {
      return await this.publicClient.getBytecode({ address });
    } catch {
      return undefined;
    }
  }

  /**
   * Returns true if `address` has no deployed bytecode (i.e., is an EOA or
   * a self-destructed contract).
   */
  private async isEOA(address: Address): Promise<boolean> {
    try {
      const code = await this.publicClient.getBytecode({ address });
      return !code || code === "0x";
    } catch {
      return false;
    }
  }

  // ── Slither Integration (verified source) ─────────────────────────

  /**
   * Runs Slither on verified Solidity source code.
   * Writes source to a temp directory, invokes slither --json, parses output.
   */
  async runSlitherOnSource(
    address: Address,
    sourceCode: string,
    compilerVersion?: string,
  ): Promise<SlitherFinding[]> {
    const workDir = `${HEIMDALL_OUTPUT_BASE}-slither-${address.toLowerCase()}`;

    try {
      await fs.mkdir(workDir, { recursive: true });

      // Write source to a .sol file
      const solPath = path.join(workDir, "Contract.sol");
      await fs.writeFile(solPath, sourceCode, "utf-8");

      const outputPath = path.join(workDir, "slither-output.json");

      // Build slither command
      let cmd = `${TOOLCHAIN.slither} ${solPath} --json ${outputPath}`;

      // If compiler version is specified, try to use it
      if (compilerVersion) {
        // Clean up version string (e.g., "v0.8.20+commit.abc" -> "0.8.20")
        const cleanVer = compilerVersion
          .replace(/^v/, "")
          .replace(/\+.*$/, "");
        cmd += ` --solc-solcs-select ${cleanVer}`;
      }

      // Slither exits non-zero when it finds issues — that's normal
      try {
        await execAsync(cmd, { timeout: 120_000 });
      } catch {
        // Non-zero exit is expected when findings exist
      }

      // Parse output
      try {
        const raw = await fs.readFile(outputPath, "utf-8");
        const parsed = JSON.parse(raw) as {
          success: boolean;
          error: string | null;
          results?: {
            detectors?: Array<{
              check: string;
              impact: string;
              confidence: string;
              description: string;
              elements?: Array<{
                name?: string;
                source_mapping?: { filename_relative?: string };
              }>;
            }>;
          };
        };

        if (!parsed.results?.detectors) return [];

        return parsed.results.detectors.map((d): SlitherFinding => ({
          check: d.check,
          impact: d.impact as SlitherFinding["impact"],
          confidence: d.confidence as SlitherFinding["confidence"],
          description: d.description,
          elements: (d.elements ?? [])
            .map((e) => e.name ?? e.source_mapping?.filename_relative ?? "")
            .filter(Boolean),
        }));
      } catch {
        return [];
      }
    } catch {
      return [];
    } finally {
      // Cleanup temp directory
      try {
        await fs.rm(workDir, { recursive: true, force: true });
      } catch { /* non-fatal */ }
    }
  }

  /**
   * Full analysis for a contract with verified source from a block explorer.
   * Runs BOTH Heimdall (bytecode) and Slither (source), merges findings.
   */
  async analyzeWithSource(
    address: Address,
    chain: SupportedChain,
    explorerEntry: ExplorerContractEntry,
  ): Promise<{ report: StaticAnalysisReport; slitherFindings: SlitherFinding[] }> {
    const chainConfig = CHAIN_CONFIGS[chain];

    // Step 1: Run Heimdall on bytecode (uses chain-specific RPC)
    const heimdallOutput = await this.runHeimdallForChain(address, chainConfig.rpcUrl);

    // Step 2: Build function list from Heimdall output
    // Create a shim NewDeployment for the existing buildFunctionList
    const bytecode = await this.safeGetBytecode(address);
    const shimDeployment: NewDeployment = {
      contractAddress: address,
      deployerAddress: "0x0000000000000000000000000000000000000000" as Address,
      txHash: "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`,
      blockNumber: 0n,
      blockTimestamp: Math.floor(Date.now() / 1000),
      bytecodeSize: bytecode ? bytecode.length / 2 : 0,
      isProxy: !!explorerEntry.implementationAddress,
      implementationAddress: explorerEntry.implementationAddress,
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

    const functions = await this.buildFunctionList(heimdallOutput, shimDeployment);
    const selectorFindings = await this.matchVulnerableSelectors(functions);

    let patternFindings: StaticAnalysisFinding[] = [];
    if (!heimdallOutput.success && bytecode) {
      patternFindings = bytecodePatternFindings(bytecode);
    }

    // Step 3: Run Slither on verified source
    let slitherFindings: SlitherFinding[] = [];
    if (explorerEntry.sourceCode) {
      slitherFindings = await this.runSlitherOnSource(
        address,
        explorerEntry.sourceCode,
        explorerEntry.compilerVersion,
      );
    }

    // Step 4: Convert high-impact Slither findings to StaticAnalysisFindings
    // Generate deterministic pseudo-selectors per Slither check name to avoid
    // dedup collisions (all Slither findings previously shared "0x00000000").
    const slitherAsStatic = slitherFindings
      .filter((f) => f.impact === "High" || f.impact === "Medium")
      .map((f, idx): StaticAnalysisFinding => ({
        riskClass: mapSlitherCheckToRiskClass(f.check),
        severity: f.impact === "High" ? "critical" : "high",
        functionSelector: slitherPseudoSelector(f.check, idx),
        functionName: f.elements[0] ?? undefined,
        description: `[Slither:${f.check}] ${f.description}`,
        confidence: f.confidence === "High" ? 90 : f.confidence === "Medium" ? 70 : 50,
      }));

    // Step 4b: EVM engine analysis (if enabled)
    let evmFindings: StaticAnalysisFinding[] = [];
    let evmAnalysisRef: EVMAnalysisResultRef | undefined;
    let exploitPatternMatchRefs: ExploitPatternMatchRef[] | undefined;

    if (FEATURES.evmAnalysis && bytecode && bytecode.length > 4) {
      try {
        const evmResult = analyzeEVMBytecode(bytecode);
        const detectorFindings = runAllDetectors(evmResult, evmResult.storageLayout);
        evmFindings.push(...detectorFindings);

        const patternMatches = matchExploitPatterns(evmResult, evmResult.storageLayout);
        if (patternMatches.length > 0) {
          evmFindings.push(...patternMatchesToFindings(patternMatches));
          exploitPatternMatchRefs = patternMatches.map(m => ({
            patternId: m.pattern.id,
            patternName: m.pattern.name,
            protocol: m.pattern.protocol,
            lossAmountUsd: m.pattern.lossAmountUsd,
            matchScore: m.matchScore,
            matchedConditions: m.matchedConditions,
            description: m.pattern.description,
          }));
        }

        evmAnalysisRef = {
          analysisTimeMs: evmResult.analysisTimeMs,
          instructionCount: evmResult.instructionCount,
          blockCount: evmResult.blockCount,
          selectors: evmResult.selectors,
          taintFlowCount: evmResult.taint.flows.length,
          highSeverityTaintFlows: evmResult.taint.hasHighSeverityFlow,
          unconditionalDrainCount: evmResult.valueFlow.drains.length,
          storageSlotCount: evmResult.storageLayout.slots.length,
          isUpgradeableProxy: evmResult.storageLayout.isUpgradeableProxy,
          externalCallCount: evmResult.crossContractFlow.externalCallCount,
        };
      } catch { /* non-fatal */ }
    }

    // Step 5: Merge and deduplicate all findings
    const allFindings = this.deduplicateFindings([
      ...selectorFindings,
      ...patternFindings,
      ...slitherAsStatic,
      ...evmFindings,
    ]);

    const approvalGraph = await this.buildApprovalGraph(address);
    const externalCallGraph = this.buildExternalCallGraph(functions);
    const riskScore = this.computeRiskScore(allFindings);

    const report: StaticAnalysisReport = {
      contractAddress: address,
      analysisTimestamp: Math.floor(Date.now() / 1000),
      riskScore,
      proxyType: explorerEntry.implementationAddress ? "eip1967" : undefined,
      implementationAddress: explorerEntry.implementationAddress,
      adminAddress: undefined,
      adminIsEOA: undefined,
      functions,
      findings: allFindings,
      approvalGraph,
      externalCallGraph,
      evmAnalysis: evmAnalysisRef,
      exploitPatternMatches: exploitPatternMatchRefs,
    };

    const addr = address.toLowerCase() as Address;
    this.analysisCache.set(addr, report);

    return { report, slitherFindings };
  }

  /**
   * Runs Heimdall against a contract on a specific chain's RPC.
   */
  private async runHeimdallForChain(address: Address, rpcUrl: string): Promise<HeimdallOutput> {
    const outputDir = `${HEIMDALL_OUTPUT_BASE}-${address.toLowerCase()}`;

    const cmd =
      `${TOOLCHAIN.heimdall} decompile ${address}` +
      ` --rpc-url ${rpcUrl}` +
      ` --output ${outputDir}` +
      ` --timeout 60`;

    try {
      await execAsync(cmd, { timeout: HEIMDALL_TIMEOUT_MS });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { abi: [], outputDir, success: false, error: `Heimdall failed: ${msg}` };
    }

    const abiPath = path.join(outputDir, "abi.json");
    try {
      const raw = await fs.readFile(abiPath, "utf-8");
      const abi = JSON.parse(raw) as HeimdallAbiEntry[];
      return { abi, outputDir, success: true };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { abi: [], outputDir, success: false, error: `ABI read failed: ${msg}` };
    }
  }
}

/**
 * Generates a deterministic pseudo-selector from a Slither check name and index.
 * Avoids all Slither findings colliding on "0x00000000" in dedup.
 */
function slitherPseudoSelector(check: string, index: number): Hex {
  // Simple deterministic hash: sum char codes + index
  let hash = index;
  for (let i = 0; i < check.length; i++) {
    hash = ((hash << 5) - hash + check.charCodeAt(i)) | 0;
  }
  const hex = (hash >>> 0).toString(16).padStart(8, "0").slice(0, 8);
  return `0x${hex}` as Hex;
}

// ─── Internal helpers ──────────────────────────────────────────────────────

/**
 * Maps a known-vulnerable function name to a `RiskClass` and `MisconfigSeverity`.
 */
function classifyByName(name: string): {
  riskClass: RiskClass;
  severity: MisconfigSeverity;
} {
  const lower = name.toLowerCase();

  if (lower.includes("flash")) return { riskClass: "flash_loan_attack", severity: "high" };
  if (lower.includes("upgrade")) return { riskClass: "calldata_forwarding", severity: "critical" };
  if (lower.includes("oracle") || lower.includes("pricefeed"))
    return { riskClass: "oracle_manipulation", severity: "high" };
  if (lower.includes("multicall") || lower.includes("aggregate") || lower.includes("execute"))
    return { riskClass: "calldata_forwarding", severity: "high" };
  if (lower.includes("donate"))
    return { riskClass: "drain", severity: "high" };
  if (lower.includes("zap") || lower.includes("leverage"))
    return { riskClass: "drain", severity: "medium" };

  return { riskClass: "drain", severity: "medium" };
}

/**
 * Generates a human-readable description for a finding derived from a
 * known-vulnerable selector.
 */
function buildFindingDescription(
  selectorName: string,
  fn: DecompiledFunction,
): string {
  const parts: string[] = [
    `Function "${selectorName}" matches a known-vulnerable selector pattern.`,
  ];
  if (fn.isPayable) parts.push("Function is payable (accepts ETH).");
  if (fn.hasDelegatecall) parts.push("Function uses DELEGATECALL.");
  if (!fn.hasAccessControl) parts.push("No access control detected.");
  return parts.join(" ");
}

/**
 * Infers the proxy standard from a `NewDeployment` record.
 *
 * Since DeploymentMonitor already resolved the implementation address, we
 * use presence/type of that information to classify the proxy standard.
 */
function resolveProxyType(
  deployment: NewDeployment,
): StaticAnalysisReport["proxyType"] {
  if (!deployment.isProxy) return undefined;
  if (!deployment.implementationAddress) return "unknown";
  // EIP-1167 proxies have very small bytecode (< 50 bytes).
  if (deployment.bytecodeSize < 50) return "eip1167";
  // Larger proxies with a resolved implementation are likely EIP-1967-based.
  return "eip1967";
}

/**
 * Maps a Slither detector check name to the closest Sentinel RiskClass.
 */
function mapSlitherCheckToRiskClass(check: string): RiskClass {
  const lower = check.toLowerCase();

  if (lower.includes("reentrancy")) return "reentrancy";
  if (lower.includes("arbitrary-send") || lower.includes("suicidal")) return "drain";
  if (lower.includes("controlled-delegatecall")) return "calldata_forwarding";
  if (lower.includes("oracle") || lower.includes("price")) return "oracle_manipulation";
  if (lower.includes("unprotected-upgrade")) return "calldata_forwarding";
  if (lower.includes("unchecked") || lower.includes("overflow")) return "integer_overflow";
  if (lower.includes("approval") || lower.includes("erc20")) return "approval_exploit";
  if (lower.includes("selfdestruct")) return "selfdestruct";
  if (lower.includes("access") || lower.includes("unprotected")) return "access_control";

  return "drain"; // conservative default
}
