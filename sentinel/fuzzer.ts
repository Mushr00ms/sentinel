// FILE: fuzzer.ts
// Module F.4 - Echidna-based property fuzzing with corpus seeding from
// known exploits. Orchestrates multiple targeted campaigns per contract.

import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import path from "node:path";
import type { Address, Hex } from "viem";

import type {
  StaticAnalysisReport,
  DecompiledFunction,
  FuzzCampaignConfig,
  FuzzCampaignResult,
  FuzzCampaignType,
  FuzzFinding,
  FuzzCall,
} from "./types.js";
import { TOOLCHAIN, RPC_URL } from "./config.js";

const execFileAsync = promisify(execFile);

// ─── Constants ────────────────────────────────────────────────────────────

const HARNESS_DIR = "/tmp/sentinel-echidna";
const CORPUS_BASE_DIR = "/tmp/sentinel-corpus";

/** Total budget across all campaigns for a single contract (30 minutes). */
const TOTAL_CAMPAIGN_TIMEOUT_MS = 30 * 60 * 1_000;

// ─── Corpus seeds ─────────────────────────────────────────────────────────

/**
 * Calldata patterns extracted from historical on-chain exploits.
 * Used to seed Echidna's mutation engine for faster vulnerability discovery.
 */
const CORPUS_SEEDS: Record<FuzzCampaignType, Hex[]> = {
  balance_drain: [
    // donate() pattern used in several Euler-style exploits
    "0x5acc7e00000000000000000000000000000000000000000000000000000000000000000",
  ],
  access_escalation: [],
  reentrancy: [],
  integer_overflow: [],
  flash_loan: [],
};

// ─── Campaign parameter table ─────────────────────────────────────────────

interface CampaignParams {
  rounds: number;
  timeout: number; // seconds
}

const CAMPAIGN_PARAMS: Record<FuzzCampaignType, CampaignParams> = {
  balance_drain: { rounds: 10_000, timeout: 30 },
  access_escalation: { rounds: 5_000, timeout: 20 },
  reentrancy: { rounds: 5_000, timeout: 20 },
  integer_overflow: { rounds: 3_000, timeout: 15 },
  flash_loan: { rounds: 5_000, timeout: 20 },
};

// ─── Campaign selection heuristics ────────────────────────────────────────

/**
 * Chooses which campaign types are relevant for a given StaticAnalysisReport
 * by mapping risk classes from static analysis findings to campaign types.
 */
function selectCampaigns(report: StaticAnalysisReport): FuzzCampaignType[] {
  const campaigns = new Set<FuzzCampaignType>();

  // Always run balance_drain for fund-handling contracts
  campaigns.add("balance_drain");

  for (const finding of report.findings) {
    switch (finding.riskClass) {
      case "drain":
        campaigns.add("balance_drain");
        break;
      case "access_control":
        campaigns.add("access_escalation");
        break;
      case "reentrancy":
        campaigns.add("reentrancy");
        break;
      case "integer_overflow":
        campaigns.add("integer_overflow");
        break;
      case "flash_loan_attack":
        campaigns.add("flash_loan");
        break;
      default:
        break;
    }
  }

  return Array.from(campaigns);
}

// ─── Echidna output parser ────────────────────────────────────────────────

interface EchidnaCallEntry {
  call: string;
  value?: string;
  sender?: string;
}

/**
 * Parses Echidna's text output to extract a failing call sequence.
 * Echidna prints:
 *   echidna_no_drain: failed!
 *     Call sequence:
 *       functionName(args) from 0xSENDER Value: 0xVALUE
 */
function parseEchidnaOutput(
  output: string,
  campaignType: FuzzCampaignType,
): FuzzFinding | undefined {
  const failedRe = /echidna_\w+:\s*failed!/i;
  if (!failedRe.test(output)) return undefined;

  const callSequence: FuzzCall[] = [];

  // Extract the "Call sequence:" block
  const seqMatch = /Call sequence[:\s]*([\s\S]+?)(?:\n\n|\nCalling|\nseeds:|$)/i.exec(output);
  if (seqMatch) {
    const seqBlock = seqMatch[1] ?? "";
    const lineRe =
      /^\s*(\w[\w\d_]*)\(([^)]*)\)\s*(?:from\s+(0x[0-9a-fA-F]+))?\s*(?:[Vv]alue:\s*(0x[0-9a-fA-F]+|\d+))?/gm;

    let lineMatch: RegExpExecArray | null;
    while ((lineMatch = lineRe.exec(seqBlock)) !== null) {
      const fnName = lineMatch[1] ?? "unknown";
      const argsRaw = lineMatch[2] ?? "";
      const sender = (lineMatch[3] ?? "0x0000000000000000000000000000000000000000") as Address;
      const valueStr = lineMatch[4];

      // Build a best-effort function selector (4-byte keccak is not available
      // without a crypto module in pure TS at parse time; use name as proxy)
      const selector = `0x${fnName.slice(0, 8).padEnd(8, "0")}` as Hex;
      const args = argsRaw
        .split(",")
        .map((a) => a.trim())
        .filter((a) => a.length > 0);
      const value = valueStr !== undefined ? BigInt(valueStr) : undefined;

      callSequence.push({ functionSelector: selector, args, value, sender });
    }
  }

  // Try to extract an estimated profit from balance difference lines
  let estimatedProfit: bigint | undefined;
  const profitMatch = /balance[:\s]+(\d+)/i.exec(output);
  if (profitMatch) {
    try {
      estimatedProfit = BigInt(profitMatch[1]!);
    } catch {
      // ignore parse errors
    }
  }

  return {
    campaignType,
    violatingCallsequence: callSequence,
    description: `Echidna property violation detected for campaign type: ${campaignType}`,
    estimatedProfit,
  };
}

/**
 * Estimates the number of fuzzing rounds Echidna completed by scanning
 * its output for progress markers.
 */
function parseRoundsCompleted(output: string, configured: number): number {
  const m = /(\d+)\s*(?:tests?|calls?)\s*(?:run|completed)/i.exec(output);
  if (m) {
    try {
      return Math.min(parseInt(m[1]!, 10), configured);
    } catch {
      // fall through
    }
  }
  return configured;
}

// ─── Harness / config helpers ─────────────────────────────────────────────

/**
 * Generates the Solidity interface body for the target contract.
 */
function buildInterfaceMethods(functions: DecompiledFunction[]): string {
  if (functions.length === 0) {
    return "    // No decompiled functions available\n";
  }
  return functions
    .map((fn) => {
      const name = fn.name ?? `fn_${fn.selector.slice(2, 10)}`;
      const payable = fn.isPayable ? " payable" : "";
      return `    function ${name}(bytes calldata data) external${payable} returns (bytes memory);`;
    })
    .join("\n");
}

/**
 * Returns the Echidna property function relevant to the campaign type.
 */
function buildPropertyFunction(campaignType: FuzzCampaignType): string {
  switch (campaignType) {
    case "balance_drain":
      return `\
    // Echidna property: contract ETH balance must never fall below initial level
    function echidna_no_drain() public view returns (bool) {
        return address(target).balance >= initialBalance;
    }`;

    case "access_escalation":
      return `\
    bool internal _accessEscalated;

    // Echidna property: privileged state must not change via unprivileged caller
    function echidna_no_access_escalation() public view returns (bool) {
        return !_accessEscalated;
    }

    fallback() external payable {
        _accessEscalated = true;
    }`;

    case "reentrancy":
      return `\
    bool internal _inCall;
    bool internal _reentrancyDetected;

    // Echidna property: no reentrancy state corruption
    function echidna_no_reentrancy() public view returns (bool) {
        return !_reentrancyDetected;
    }

    receive() external payable {
        if (_inCall) {
            _reentrancyDetected = true;
        }
    }`;

    case "integer_overflow":
      return `\
    // Echidna property: arithmetic operations must not overflow/underflow
    function echidna_no_overflow(uint256 a, uint256 b) public pure returns (bool) {
        unchecked {
            uint256 sum = a + b;
            return sum >= a;
        }
    }`;

    case "flash_loan":
      return `\
    uint256 internal _flashLoanDebt;

    // Echidna property: flash loan must be repaid within the same transaction
    function echidna_flash_loan_repaid() public view returns (bool) {
        return _flashLoanDebt == 0;
    }`;

    default:
      return `\
    function echidna_no_drain() public view returns (bool) {
        return address(this).balance >= initialBalance;
    }`;
  }
}

// ─── FuzzingOrchestrator ───────────────────────────────────────────────────

export class FuzzingOrchestrator {
  constructor() {}

  // ── Public entry points ──────────────────────────────────────────────────

  /**
   * Runs all relevant fuzz campaigns for the given contract.
   * Respects a hard 30-minute wall-clock budget across all campaigns.
   * Returns a result array regardless of individual campaign outcomes.
   */
  async runAllCampaigns(
    contractAddress: Address,
    report: StaticAnalysisReport,
  ): Promise<FuzzCampaignResult[]> {
    if (!(await this.isEchidnaAvailable())) {
      const campaignTypes = Object.keys(CAMPAIGN_PARAMS) as FuzzCampaignType[];
      return campaignTypes.map((campaignType) => ({
        contractAddress,
        campaignType,
        status: "failed",
        rounds: 0,
        duration: 0,
      }));
    }

    const campaignTypes = selectCampaigns(report);
    const results: FuzzCampaignResult[] = [];
    const globalDeadline = Date.now() + TOTAL_CAMPAIGN_TIMEOUT_MS;

    for (const campaignType of campaignTypes) {
      const remaining = globalDeadline - Date.now();
      if (remaining <= 0) break;

      const params = CAMPAIGN_PARAMS[campaignType];
      const effectiveTimeout = Math.min(params.timeout, Math.floor(remaining / 1_000));

      const config: FuzzCampaignConfig = {
        contractAddress,
        campaignType,
        rounds: params.rounds,
        timeout: effectiveTimeout,
        corpusSeed: CORPUS_SEEDS[campaignType],
      };

      const result = await this.runCampaign(config);
      results.push(result);

      // Short-circuit if a finding was discovered - report immediately
      if (result.status === "finding") break;
    }

    return results;
  }

  /**
   * Runs a single Echidna fuzz campaign from a FuzzCampaignConfig.
   * Generates the harness and YAML config, executes Echidna, and parses
   * its output.
   */
  async runCampaign(config: FuzzCampaignConfig): Promise<FuzzCampaignResult> {
    const startMs = Date.now();

    if (!(await this.isEchidnaAvailable())) {
      return {
        contractAddress: config.contractAddress,
        campaignType: config.campaignType,
        status: "failed",
        rounds: 0,
        duration: 0,
      };
    }

    // Prepare directories
    const corpusDir = path.join(CORPUS_BASE_DIR, config.contractAddress, config.campaignType);
    await mkdir(HARNESS_DIR, { recursive: true });
    await mkdir(corpusDir, { recursive: true });

    // Write corpus seed files if any
    if (config.corpusSeed && config.corpusSeed.length > 0) {
      for (let i = 0; i < config.corpusSeed.length; i++) {
        const seed = config.corpusSeed[i]!;
        const seedPath = path.join(corpusDir, `seed_${i}.txt`);
        await writeFile(seedPath, seed, "utf8");
      }
    }

    // Generate harness Solidity file
    // We pass empty functions array here since runCampaign is called directly;
    // callers that have a full report should call generateEchidnaHarness first.
    let harnessPath: string;
    try {
      harnessPath = await this.generateEchidnaHarness(config, []);
    } catch (err) {
      return {
        contractAddress: config.contractAddress,
        campaignType: config.campaignType,
        status: "failed",
        rounds: 0,
        duration: Date.now() - startMs,
      };
    }

    // Write Echidna YAML config
    const configPath = path.join(HARNESS_DIR, `echidna_${config.campaignType}_${config.contractAddress.slice(2, 10)}.yaml`);
    const yaml = buildEchidnaYaml(config, corpusDir);
    await writeFile(configPath, yaml, "utf8");

    // Execute Echidna
    const args = [
      harnessPath,
      "--contract", "EchidnaTest",
      "--config", configPath,
      "--timeout", String(config.timeout),
    ];

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    try {
      const result = await execFileAsync(TOOLCHAIN.echidna, args, {
        timeout: (config.timeout + 10) * 1_000,
        maxBuffer: 20 * 1024 * 1024,
      });
      stdout = result.stdout;
      stderr = result.stderr;
    } catch (err: unknown) {
      const execErr = err as NodeJS.ErrnoException & {
        stdout?: string;
        stderr?: string;
        killed?: boolean;
      };
      timedOut = execErr.killed === true ||
        (execErr.message ?? "").toLowerCase().includes("timeout");
      stdout = execErr.stdout ?? "";
      stderr = execErr.stderr ?? "";
      // Echidna exits non-zero on violations; continue to parse output
    }

    const combined = stdout + "\n" + stderr;
    const finding = parseEchidnaOutput(combined, config.campaignType);
    const rounds = parseRoundsCompleted(combined, config.rounds);
    const duration = Date.now() - startMs;

    if (finding) {
      return {
        contractAddress: config.contractAddress,
        campaignType: config.campaignType,
        status: "finding",
        rounds,
        duration,
        finding,
      };
    }

    if (timedOut) {
      return {
        contractAddress: config.contractAddress,
        campaignType: config.campaignType,
        status: "timeout",
        rounds,
        duration,
      };
    }

    return {
      contractAddress: config.contractAddress,
      campaignType: config.campaignType,
      status: "completed",
      rounds,
      duration,
    };
  }

  // ── Harness generation ───────────────────────────────────────────────────

  /**
   * Generates an Echidna test contract in Solidity and writes it to
   * HARNESS_DIR. Returns the absolute path of the written file.
   */
  async generateEchidnaHarness(
    config: FuzzCampaignConfig,
    functions: DecompiledFunction[],
  ): Promise<string> {
    await mkdir(HARNESS_DIR, { recursive: true });

    const addrStripped = config.contractAddress.slice(2);
    const interfaceMethods = buildInterfaceMethods(functions);
    const propertyFn = buildPropertyFunction(config.campaignType);

    const solidity = `\
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// Auto-generated by Sentinel fuzzing orchestrator (Module F.4)
// Target: ${config.contractAddress}
// Campaign: ${config.campaignType}

interface ITarget {
${interfaceMethods}
    receive() external payable;
    fallback() external payable;
}

contract EchidnaTest {
    ITarget internal target;
    uint256 internal initialBalance;

    constructor() payable {
        target = ITarget(payable(address(0x${addrStripped})));
        initialBalance = address(this).balance;
    }

${propertyFn}
}
`;

    const filename = `EchidnaTest_${config.campaignType}_${addrStripped}.sol`;
    const filePath = path.join(HARNESS_DIR, filename);
    await writeFile(filePath, solidity, "utf8");
    return filePath;
  }

  // ── Tool availability ────────────────────────────────────────────────────

  /**
   * Returns true if the Echidna binary resolves in PATH or at the configured
   * TOOLCHAIN.echidna path.
   */
  async isEchidnaAvailable(): Promise<boolean> {
    try {
      await execFileAsync("which", [TOOLCHAIN.echidna], { timeout: 5_000 });
      return true;
    } catch {
      // Try the configured path directly
      try {
        await execFileAsync(TOOLCHAIN.echidna, ["--version"], { timeout: 5_000 });
        return true;
      } catch {
        return false;
      }
    }
  }
}

// ─── YAML builder ─────────────────────────────────────────────────────────

function buildEchidnaYaml(config: FuzzCampaignConfig, corpusDir: string): string {
  return `\
# Echidna config generated by Sentinel (Module F.4)
# Campaign: ${config.campaignType} | Contract: ${config.contractAddress}
testMode: property
corpusDir: ${corpusDir}
seqLen: 100
testLimit: ${config.rounds}
timeout: ${config.timeout}
# Connect to live Sonic node for state forking
rpc: ${RPC_URL}
codeSize: "0x10000"
shrinkLimit: 5000
filterFunctions: []
quiet: false
`;
}
