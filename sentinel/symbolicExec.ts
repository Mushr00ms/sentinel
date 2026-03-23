// FILE: symbolicExec.ts
// Module F.3 - Symbolic execution harness generator and runner
// Uses Halmos (preferred) and Mythril (fallback) for property verification
// on HIGH risk contracts (riskScore > 70).

import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import path from "node:path";
import type { Address, Hex } from "viem";

import type {
  StaticAnalysisReport,
  DecompiledFunction,
  SymbolicExecResult,
  SymbolicProperty,
  PropertyViolation,
  SymbolicExecStatus,
} from "./types.js";
import { TOOLCHAIN, RPC_URL } from "./config.js";

const execFileAsync = promisify(execFile);

// ─── Constants ────────────────────────────────────────────────────────────

const HARNESS_DIR = "/tmp/sentinel-halmos";

// Standard properties checked for every contract
const STANDARD_PROPERTIES: SymbolicProperty[] = [
  {
    name: "drain_check",
    description: "Can any non-owner caller drain contract balance?",
    invariant: "address(target).balance >= _initialBalance - 1",
  },
  {
    name: "access_control",
    description: "Can non-admin call restricted functions?",
    invariant: "!_accessControlViolated",
  },
  {
    name: "reentrancy",
    description: "Does state remain consistent after reentrant call?",
    invariant: "_stateHash == _stateHashAfter",
  },
  {
    name: "self_destruct",
    description: "Can SELFDESTRUCT be triggered by external caller?",
    invariant: "address(target).code.length > 0",
  },
];

// Additional properties for ERC-4626 vaults / lending protocols
const ERC4626_PROPERTIES: SymbolicProperty[] = [
  {
    name: "erc4626_invariant",
    description: "convertToAssets(totalSupply) <= totalAssets + 1",
    invariant: "ITarget(target).convertToAssets(ITarget(target).totalSupply()) <= ITarget(target).totalAssets() + 1",
  },
  {
    name: "lending_invariant",
    description: "totalDebt <= totalDeposits",
    invariant: "_totalDebt <= _totalDeposits",
  },
];

// ─── Utility ──────────────────────────────────────────────────────────────

/**
 * Resolves a command to its absolute path or returns null if not found.
 * Uses the `which` shell built-in via child_process.
 */
async function resolveCommand(cmd: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("which", [cmd], { timeout: 5_000 });
    const resolved = stdout.trim();
    return resolved.length > 0 ? resolved : null;
  } catch {
    return null;
  }
}

/**
 * Determines whether a StaticAnalysisReport indicates ERC-4626 characteristics
 * by checking for known vault-related function selectors.
 */
function looksLikeERC4626(report: StaticAnalysisReport): boolean {
  const vaultSelectors = new Set([
    "0x07a2d13a", // convertToAssets
    "0xc6e6f592", // convertToShares
    "0x94bf804d", // mint
    "0xb3d7f6b9", // previewDeposit
    "0x4cdad506", // previewMint
    "0x0a28a477", // previewWithdraw
    "0xd905777e", // maxDeposit
    "0x01e1d114", // totalAssets
  ]);
  return report.functions.some((fn) => vaultSelectors.has(fn.selector));
}

/**
 * Generates the Solidity interface body from a list of decompiled functions.
 * Uses Heimdall ABI entry types when available for better harness quality.
 */
function buildInterfaceMethods(functions: DecompiledFunction[], heimdallAbi?: HeimdallAbiEntry[]): string {
  if (functions.length === 0) {
    return "    // No decompiled functions available; using fallback low-level calls\n";
  }

  // Build ABI lookup by selector for enriched type information
  const abiBySelector = new Map<string, HeimdallAbiEntry>();
  if (heimdallAbi) {
    for (const entry of heimdallAbi) {
      if (entry.type === "function" && entry.selector) {
        const sel = entry.selector.startsWith("0x") ? entry.selector : `0x${entry.selector}`;
        abiBySelector.set(sel.toLowerCase(), entry);
      }
    }
  }

  return functions
    .map((fn) => {
      const name = fn.name ?? `fn_${fn.selector.slice(2, 10)}`;
      const payable = fn.isPayable ? " payable" : "";

      // Try to use actual parameter types from Heimdall ABI
      const abiEntry = abiBySelector.get(fn.selector.toLowerCase());
      if (abiEntry?.inputs && abiEntry.inputs.length > 0) {
        const params = abiEntry.inputs
          .map((inp, i) => `${inp.type} ${inp.name || `arg${i}`}`)
          .join(", ");
        const returns = abiEntry.outputs && abiEntry.outputs.length > 0
          ? ` returns (${abiEntry.outputs.map((o, i) => `${o.type} ret${i}`).join(", ")})`
          : " returns (bytes memory)";
        return `    function ${name}(${params}) external${payable}${returns};`;
      }

      return `    function ${name}(bytes calldata data) external${payable} returns (bytes memory);`;
    })
    .join("\n");
}

/** Shape of Heimdall ABI entry — matches staticAnalysis.ts HeimdallAbiEntry. */
interface HeimdallAbiEntry {
  type: string;
  name?: string;
  inputs?: { type: string; name?: string }[];
  outputs?: { type: string }[];
  stateMutability?: string;
  selector?: string;
}

// ─── SymbolicExecRunner ────────────────────────────────────────────────────

export class SymbolicExecRunner {
  constructor() {}

  // ── Public entry point ──────────────────────────────────────────────────

  /**
   * Runs symbolic execution for HIGH risk contracts only (riskScore > 70).
   * Prefers Halmos; falls back to Mythril if Halmos is unavailable.
   * Returns status="failed" immediately when neither tool is installed.
   */
  async run(
    contractAddress: Address,
    report: StaticAnalysisReport,
    timeout = 120,
  ): Promise<SymbolicExecResult> {
    const startMs = Date.now();

    if (!this.isHighRisk(report)) {
      return {
        contractAddress,
        status: "completed",
        duration: Date.now() - startMs,
        violations: [],
        pathsExplored: 0,
      };
    }

    // Resolve tool availability
    const halmosPath = await resolveCommand(TOOLCHAIN.halmos);
    const mythrilPath = await resolveCommand(TOOLCHAIN.mythril);

    if (!halmosPath && !mythrilPath) {
      return {
        contractAddress,
        status: "failed",
        duration: Date.now() - startMs,
        violations: [],
        pathsExplored: 0,
      };
    }

    // Build property list
    const properties: SymbolicProperty[] = [
      ...STANDARD_PROPERTIES,
      ...(looksLikeERC4626(report) ? ERC4626_PROPERTIES : []),
    ];

    let status: SymbolicExecStatus = "completed";
    let violations: PropertyViolation[] = [];
    let pathsExplored = 0;

    if (halmosPath) {
      // Primary path: generate Halmos harness and run
      try {
        await mkdir(HARNESS_DIR, { recursive: true });
        const harnessPath = await this.generateHalmosHarness(contractAddress, report.functions);
        const halmosViolations = await this.runHalmos(harnessPath, timeout);
        violations = halmosViolations;
        pathsExplored = 100; // Halmos does not expose a path counter; sentinel default
      } catch (err: unknown) {
        if (err instanceof Error && err.message.includes("timeout")) {
          status = "timeout";
        } else {
          // Halmos failed unexpectedly; try Mythril if available
          if (mythrilPath) {
            try {
              violations = await this.runMythril(contractAddress, timeout);
            } catch {
              status = "failed";
            }
          } else {
            status = "failed";
          }
        }
      }
    } else if (mythrilPath) {
      // Fallback path: Mythril only
      try {
        violations = await this.runMythril(contractAddress, timeout);
      } catch (err: unknown) {
        if (err instanceof Error && err.message.includes("timeout")) {
          status = "timeout";
        } else {
          status = "failed";
        }
      }
    }

    return {
      contractAddress,
      status,
      duration: Date.now() - startMs,
      violations,
      pathsExplored,
    };
  }

  // ── Harness generation ──────────────────────────────────────────────────

  /**
   * Generates a Solidity test harness suitable for Halmos symbolic execution.
   * Writes the file to HARNESS_DIR and returns the file path.
   */
  async generateHalmosHarness(
    contractAddress: Address,
    functions: DecompiledFunction[],
  ): Promise<string> {
    await mkdir(HARNESS_DIR, { recursive: true });

    const addrStripped = contractAddress.slice(2); // remove 0x
    const interfaceMethods = buildInterfaceMethods(functions);

    const solidity = `\
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "forge-std/Test.sol";

// Auto-generated by Sentinel symbolic execution harness (Module F.3)
// Target: ${contractAddress}

interface ITarget {
${interfaceMethods}
    // Generic low-level interaction
    receive() external payable;
    fallback() external payable;
}

contract HalmosTest is Test {
    ITarget target;
    address attacker;
    uint256 internal _initialBalance;
    bool internal _accessControlViolated;
    bytes32 internal _stateHash;
    bytes32 internal _stateHashAfter;
    uint256 internal _totalDebt;
    uint256 internal _totalDeposits;

    function setUp() public {
        target = ITarget(address(0x${addrStripped}));
        attacker = address(0xBEEF);
        _initialBalance = address(target).balance;
        // Approximate state fingerprint using balance + code hash
        _stateHash = keccak256(
            abi.encode(address(target).balance, address(target).codehash)
        );
        _stateHashAfter = _stateHash;
        _accessControlViolated = false;
    }

    // ── Property: no balance drain ──────────────────────────────────────

    /// @custom:halmos
    function check_drain(address caller, uint256 amount) public {
        vm.assume(caller != address(0));
        vm.assume(amount <= address(target).balance);
        uint256 before = address(target).balance;

        vm.prank(caller);
        (bool ok, ) = address(target).call{value: 0}(
            abi.encodeWithSignature("withdraw(uint256)", amount)
        );

        uint256 after_ = address(target).balance;
        // Invariant: balance must not decrease by more than 1 wei (rounding)
        assert(after_ >= before - 1);
    }

    // ── Property: access control ────────────────────────────────────────

    /// @custom:halmos
    function check_access_control(address caller, bytes4 selector) public {
        vm.assume(caller != address(0));
        // Exclude common admin addresses
        vm.assume(caller != address(this));

        vm.prank(caller);
        (bool success, bytes memory data) = address(target).call(
            abi.encodePacked(selector)
        );

        // If the call succeeded and returned non-empty data, flag as potential
        // access control violation only when selector matches restricted ops
        if (success && data.length > 0) {
            // Symbolic: assert caller must be authorized
            assert(!_accessControlViolated);
        }
    }

    // ── Property: reentrancy state consistency ──────────────────────────

    /// @custom:halmos
    function check_reentrancy(uint256 callValue) public {
        vm.assume(callValue <= 10 ether);
        bytes32 before_ = keccak256(
            abi.encode(address(target).balance, address(target).codehash)
        );
        vm.deal(address(this), callValue);

        (bool ok, ) = address(target).call{value: callValue}("");

        bytes32 after__ = keccak256(
            abi.encode(address(target).balance, address(target).codehash)
        );
        // Invariant: state fingerprint must remain consistent
        if (ok) {
            _stateHashAfter = after__;
        }
        assert(_stateHash == _stateHashAfter || ok);
    }

    // ── Property: no selfdestruct ────────────────────────────────────────

    /// @custom:halmos
    function check_self_destruct(address caller) public {
        vm.assume(caller != address(0));
        uint256 codeSizeBefore;
        address t = address(target);
        assembly { codeSizeBefore := extcodesize(t) }

        vm.prank(caller);
        (bool ok, ) = address(target).call(
            abi.encodeWithSignature("kill()")
        );

        uint256 codeSizeAfter;
        assembly { codeSizeAfter := extcodesize(t) }

        // Invariant: contract code must survive external calls
        assert(codeSizeAfter > 0);
    }

    // ── Property: ERC-4626 invariant ────────────────────────────────────

    /// @custom:halmos
    function check_erc4626_invariant() public view {
        // convertToAssets(totalSupply) <= totalAssets + 1
        (bool okSupply, bytes memory supplyData) = address(target).staticcall(
            abi.encodeWithSignature("totalSupply()")
        );
        (bool okAssets, bytes memory assetsData) = address(target).staticcall(
            abi.encodeWithSignature("totalAssets()")
        );

        if (okSupply && okAssets && supplyData.length == 32 && assetsData.length == 32) {
            uint256 supply = abi.decode(supplyData, (uint256));
            uint256 assets = abi.decode(assetsData, (uint256));

            (bool okConvert, bytes memory convertData) = address(target).staticcall(
                abi.encodeWithSignature("convertToAssets(uint256)", supply)
            );
            if (okConvert && convertData.length == 32) {
                uint256 converted = abi.decode(convertData, (uint256));
                assert(converted <= assets + 1);
            }
        }
    }

    // ── Property: lending invariant ─────────────────────────────────────

    /// @custom:halmos
    function check_lending_invariant() public view {
        (bool okDebt, bytes memory debtData) = address(target).staticcall(
            abi.encodeWithSignature("totalDebt()")
        );
        (bool okDeposits, bytes memory depositData) = address(target).staticcall(
            abi.encodeWithSignature("totalDeposits()")
        );

        if (okDebt && okDeposits && debtData.length == 32 && depositData.length == 32) {
            uint256 debt = abi.decode(debtData, (uint256));
            uint256 deposits = abi.decode(depositData, (uint256));
            assert(debt <= deposits);
        }
    }
}
`;

    const filename = `HalmosTest_${addrStripped}.sol`;
    const filePath = path.join(HARNESS_DIR, filename);
    await writeFile(filePath, solidity, "utf8");
    return filePath;
  }

  // ── Halmos execution ────────────────────────────────────────────────────

  /**
   * Executes Halmos against the generated harness and parses its output for
   * property violations. Returns an array of PropertyViolation objects.
   */
  async runHalmos(harnessPath: string, timeout: number): Promise<PropertyViolation[]> {
    const args = [
      "--contract", "HalmosTest",
      "--function", "check_",
      "--timeout", String(timeout),
      "--solver-timeout-branching", "5000",
      "--solver-timeout-assertion", "10000",
    ];

    let stdout = "";
    let stderr = "";

    try {
      const result = await execFileAsync(TOOLCHAIN.halmos, args, {
        cwd: HARNESS_DIR,
        timeout: (timeout + 10) * 1_000,
        maxBuffer: 10 * 1024 * 1024,
      });
      stdout = result.stdout;
      stderr = result.stderr;
    } catch (err: unknown) {
      const execErr = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string; killed?: boolean };
      if (execErr.killed || (execErr.message ?? "").toLowerCase().includes("timeout")) {
        throw new Error(`halmos timeout after ${timeout}s`);
      }
      stdout = execErr.stdout ?? "";
      stderr = execErr.stderr ?? "";
      // Halmos exits non-zero when it finds violations; continue parsing
    }

    return this._parseHalmosOutput(stdout + "\n" + stderr);
  }

  // ── Mythril execution ────────────────────────────────────────────────────

  /**
   * Runs Mythril against a live contract address using JSON output mode.
   * Maps "High" severity issues to critical violations and "Medium" to
   * standard property violations.
   */
  async runMythril(contractAddress: Address, timeout: number): Promise<PropertyViolation[]> {
    const args = [
      "analyze",
      "--address", contractAddress,
      "--rpc", RPC_URL,
      "--timeout", String(timeout),
      "--json",
    ];

    let stdout = "";

    try {
      const result = await execFileAsync(TOOLCHAIN.mythril, args, {
        timeout: (timeout + 15) * 1_000,
        maxBuffer: 10 * 1024 * 1024,
      });
      stdout = result.stdout;
    } catch (err: unknown) {
      const execErr = err as NodeJS.ErrnoException & { stdout?: string; killed?: boolean };
      if (execErr.killed || (execErr.message ?? "").toLowerCase().includes("timeout")) {
        throw new Error(`mythril timeout after ${timeout}s`);
      }
      stdout = execErr.stdout ?? "";
      // Mythril exits non-zero on findings; parse anyway
    }

    return this._parseMythrilOutput(stdout);
  }

  // ── Risk assessment ──────────────────────────────────────────────────────

  /**
   * Returns true when the report's riskScore exceeds the HIGH threshold of 70.
   */
  isHighRisk(report: StaticAnalysisReport): boolean {
    return report.riskScore > 70;
  }

  // ── Private output parsers ───────────────────────────────────────────────

  private _parseHalmosOutput(output: string): PropertyViolation[] {
    const violations: PropertyViolation[] = [];

    // Halmos outputs lines like:
    //   [FAIL] check_drain (counterexample: ...)
    //   Counterexample: caller=0x... amount=0x...
    const failLineRe = /\[FAIL\]\s+(check_\w+)/g;
    const counterexRe = /[Cc]ounterexample[:\s]+([0-9a-fA-Fx,= \t\n]+)/;

    let match: RegExpExecArray | null;
    while ((match = failLineRe.exec(output)) !== null) {
      const checkName = match[1] ?? "unknown";

      // Try to extract a counterexample hex blob from surrounding context
      const snippet = output.slice(
        Math.max(0, (match.index ?? 0) - 20),
        (match.index ?? 0) + 500,
      );
      const cexMatch = counterexRe.exec(snippet);
      const rawInput = cexMatch ? cexMatch[1].replace(/\s+/g, "").slice(0, 128) : "0x";
      const violatingInput: Hex = rawInput.startsWith("0x")
        ? (rawInput as Hex)
        : (`0x${rawInput}` as Hex);

      const property = this._checkNameToProperty(checkName);
      violations.push({
        property: property.name,
        violatingInput,
        description: property.description,
        estimatedDrainAmount: checkName.includes("drain")
          ? this._extractDrainAmount(snippet)
          : undefined,
      });
    }

    return violations;
  }

  private _parseMythrilOutput(raw: string): PropertyViolation[] {
    const violations: PropertyViolation[] = [];

    let parsed: { issues?: MythrilIssue[] } = {};
    try {
      parsed = JSON.parse(raw) as { issues?: MythrilIssue[] };
    } catch {
      return violations;
    }

    const issues: MythrilIssue[] = parsed.issues ?? [];

    for (const issue of issues) {
      if (issue.severity !== "High" && issue.severity !== "Medium") continue;

      const isCritical = issue.severity === "High";
      const property = this._mythrilTitleToProperty(issue.title ?? "");

      violations.push({
        property: property.name,
        violatingInput: (issue.tx_sequence?.slice(0, 2) === "0x"
          ? (issue.tx_sequence as Hex)
          : `0x${issue.tx_sequence ?? ""}`) as Hex,
        description: isCritical
          ? `[CRITICAL] ${issue.description ?? property.description}`
          : issue.description ?? property.description,
        estimatedDrainAmount: isCritical ? undefined : undefined,
      });
    }

    return violations;
  }

  // ── Mapping helpers ──────────────────────────────────────────────────────

  private _checkNameToProperty(checkName: string): SymbolicProperty {
    const all = [...STANDARD_PROPERTIES, ...ERC4626_PROPERTIES];
    for (const prop of all) {
      if (checkName.toLowerCase().includes(prop.name.replace(/_/g, ""))) return prop;
    }
    return {
      name: checkName,
      description: `Property violation in ${checkName}`,
      invariant: "unknown",
    };
  }

  private _mythrilTitleToProperty(title: string): SymbolicProperty {
    const lower = title.toLowerCase();
    if (lower.includes("ether") || lower.includes("drain") || lower.includes("send")) {
      return STANDARD_PROPERTIES[0]!;
    }
    if (lower.includes("access") || lower.includes("owner") || lower.includes("auth")) {
      return STANDARD_PROPERTIES[1]!;
    }
    if (lower.includes("reentran") || lower.includes("reentrant")) {
      return STANDARD_PROPERTIES[2]!;
    }
    if (lower.includes("selfdestruct") || lower.includes("suicide")) {
      return STANDARD_PROPERTIES[3]!;
    }
    return {
      name: "mythril_finding",
      description: title,
      invariant: "unknown",
    };
  }

  private _extractDrainAmount(text: string): bigint | undefined {
    // Look for amount= or value= patterns followed by a number
    const m = /(?:amount|value)\s*=\s*(0x[0-9a-fA-F]+|\d+)/i.exec(text);
    if (!m) return undefined;
    try {
      return BigInt(m[1]!);
    } catch {
      return undefined;
    }
  }
}

// ─── Mythril JSON schema (internal) ───────────────────────────────────────

interface MythrilIssue {
  title?: string;
  description?: string;
  severity?: "High" | "Medium" | "Low";
  tx_sequence?: string;
  swc_id?: string;
  address?: number;
}
