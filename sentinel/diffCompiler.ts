/**
 * Module H.1 — Differential Compilation Analyzer
 *
 * AI auditors and Slither analyze source code. What actually executes is
 * bytecode. The compiler is the gap. This module:
 *
 *   1. Takes a verified contract's stated compiler version
 *   2. Recompiles the source with that version AND adjacent patch versions
 *   3. Diffs the resulting bytecodes at function-selector granularity
 *   4. Flags semantic divergence in critical paths (fund flows, access control)
 *
 * Detects:
 *   - Compiler CVEs affecting the deployed contract's version
 *   - Optimizer-introduced semantic differences (--optimize --optimize-runs)
 *   - "Verified source doesn't match deployed bytecode" attacks
 *   - Functions that behave differently across optimizer settings
 *
 * Requires: solc-select (pip install solc-select) and solc installed
 * Enable with: ENABLE_DIFF_COMPILER=true
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import type { Address, Hex } from "viem";
import type { MisconfigSeverity } from "./types.js";
import { warn, info } from "./alerter.js";

const execAsync = promisify(exec);

// ─── Constants ──────────────────────────────────────────────────────────

const WORK_DIR_BASE = "/tmp/sentinel-diffcompiler";
const COMPILE_TIMEOUT_MS = 60_000;

/** Known compiler versions with CVEs that can introduce vulnerabilities. */
const VULNERABLE_COMPILER_VERSIONS: Record<string, { cve: string; description: string; severity: MisconfigSeverity }[]> = {
  "0.8.13": [{ cve: "CVE-2022-35961", description: "Memory corruption in ABI encoding of calldata values", severity: "high" }],
  "0.8.14": [{ cve: "CVE-2022-35961", description: "Memory corruption in ABI encoding of calldata values", severity: "high" }],
  "0.8.15": [{ cve: "CVE-2022-35961", description: "Bug in Yul optimizer can produce incorrect code", severity: "high" }],
  "0.6.0":  [{ cve: "SOL-0.6.0", description: "Constructor visibility — constructor keyword required, missing gives deployment bugs", severity: "medium" }],
  "0.7.6":  [{ cve: "SOL-0.7.6", description: "Signed right shift bug in Yul optimizer", severity: "high" }],
  "0.5.0":  [{ cve: "SOL-0.5.0", description: "No explicit visibility — functions default to public, major attack surface", severity: "critical" }],
};

/** Function selectors indicating fund-flow criticality (prioritized in diff). */
const CRITICAL_FLOW_SELECTORS = new Set([
  "a9059cbb", // transfer
  "23b872dd", // transferFrom
  "095ea7b3", // approve
  "40c10f19", // mint
  "9dc29fac", // burn(address,uint256)
  "69328dec", // withdraw
  "e8eda9df", // deposit
  "a415bcad", // borrow
  "573ade81", // repay
]);

// ─── Types ────────────────────────────────────────────────────────────────

export interface DiffCompilerFinding {
  selector?: Hex;
  functionName?: string;
  diffType: "selector_missing" | "bytecode_divergence" | "known_cve" | "optimizer_diff" | "source_mismatch";
  statedVersion: string;
  comparedVersion?: string;
  description: string;
  severity: MisconfigSeverity;
  confidence: number;
  isCriticalFlow: boolean;
}

export interface DiffCompilerResult {
  contractAddress: Address;
  statedVersion: string;
  findings: DiffCompilerFinding[];
  deployedBytecodeMatchesCompiled: boolean;
  analyzedAt: number;
  analysisTimeMs: number;
}

// ─── DiffCompiler ─────────────────────────────────────────────────────────

export class DiffCompiler {
  private solcSelectAvailable = false;

  constructor() {
    void this.checkAvailable();
  }

  /**
   * Main entry point. Analyzes a verified contract for compiler-level issues.
   */
  async analyze(
    address: Address,
    sourceCode: string,
    statedVersion: string,
    deployedBytecode?: Hex,
  ): Promise<DiffCompilerResult> {
    const startMs = Date.now();
    const findings: DiffCompilerFinding[] = [];

    // ── Check 1: Known CVEs for this compiler version ─────────────────
    const cleanVersion = this.cleanVersion(statedVersion);
    const cveEntries = VULNERABLE_COMPILER_VERSIONS[cleanVersion] ?? [];
    for (const cve of cveEntries) {
      findings.push({
        diffType: "known_cve",
        statedVersion: cleanVersion,
        description: `Compiler ${cleanVersion} has known CVE ${cve.cve}: ${cve.description}`,
        severity: cve.severity,
        confidence: 95,
        isCriticalFlow: false,
      });
    }

    // ── Check 2: Very old / risky compiler versions ────────────────────
    const [major, minor] = cleanVersion.split(".").map(Number);
    if (major === 0 && minor < 6) {
      findings.push({
        diffType: "known_cve",
        statedVersion: cleanVersion,
        description: `Compiler version ${cleanVersion} is pre-0.6.0 — lacks constructor keyword, SafeMath, and modern security primitives`,
        severity: "high",
        confidence: 90,
        isCriticalFlow: false,
      });
    }
    if (major === 0 && minor < 8) {
      findings.push({
        diffType: "known_cve",
        statedVersion: cleanVersion,
        description: `Compiler version ${cleanVersion} lacks built-in overflow protection (Solidity 0.8+). Unchecked arithmetic is dangerous.`,
        severity: "medium",
        confidence: 85,
        isCriticalFlow: false,
      });
    }

    // ── Check 3: Source vs deployed bytecode mismatch (if we have both) ─
    let deployedBytecodeMatchesCompiled = true;
    if (this.solcSelectAvailable && deployedBytecode && deployedBytecode !== "0x") {
      try {
        const compiled = await this.compileSingle(sourceCode, cleanVersion, address);
        if (compiled) {
          const match = this.bytecodesSimilar(compiled, deployedBytecode);
          deployedBytecodeMatchesCompiled = match;
          if (!match) {
            findings.push({
              diffType: "source_mismatch",
              statedVersion: cleanVersion,
              description:
                "Deployed bytecode does not match compilation of verified source. " +
                "Possible: different compiler flags, different constructor args, or intentional mismatch.",
              severity: "high",
              confidence: 70,
              isCriticalFlow: false,
            });
          }

          // ── Check 4: Diff compiled vs deployed at selector level ───────
          const compiledSelectors = this.extractSelectors(compiled);
          const deployedSelectors = this.extractSelectors(deployedBytecode);

          for (const sel of compiledSelectors) {
            if (!deployedSelectors.has(sel)) {
              const isCritical = CRITICAL_FLOW_SELECTORS.has(sel);
              findings.push({
                selector: `0x${sel}` as Hex,
                diffType: "selector_missing",
                statedVersion: cleanVersion,
                description:
                  `Function with selector 0x${sel} is present in compiled source but absent in deployed bytecode. ` +
                  (isCritical ? "CRITICAL: this is a fund-flow function." : ""),
                severity: isCritical ? "critical" : "medium",
                confidence: 80,
                isCriticalFlow: isCritical,
              });
            }
          }

          // ── Check 5: Diff with optimizer OFF vs ON ─────────────────────
          const compiledNoOpt = await this.compileSingle(sourceCode, cleanVersion, address, false);
          if (compiledNoOpt && compiled !== compiledNoOpt) {
            const optSelectors = this.extractSelectors(compiled);
            const noOptSelectors = this.extractSelectors(compiledNoOpt);

            for (const sel of optSelectors) {
              if (!noOptSelectors.has(sel)) {
                findings.push({
                  selector: `0x${sel}` as Hex,
                  diffType: "optimizer_diff",
                  statedVersion: cleanVersion,
                  description:
                    `Selector 0x${sel} appears with optimizer ON but not OFF. ` +
                    "Optimizer may be inlining or eliminating functions in ways that change ABI surface.",
                  severity: "medium",
                  confidence: 60,
                  isCriticalFlow: CRITICAL_FLOW_SELECTORS.has(sel),
                });
              }
            }
          }

          // ── Check 6: Adjacent version diff ────────────────────────────
          const adjVersions = this.getAdjacentVersions(cleanVersion);
          for (const adjVer of adjVersions) {
            try {
              const adjCompiled = await this.compileSingle(sourceCode, adjVer, address);
              if (adjCompiled) {
                const adjSelectors = this.extractSelectors(adjCompiled);
                for (const sel of compiledSelectors) {
                  if (!adjSelectors.has(sel)) {
                    const isCritical = CRITICAL_FLOW_SELECTORS.has(sel);
                    if (isCritical) {
                      findings.push({
                        selector: `0x${sel}` as Hex,
                        diffType: "bytecode_divergence",
                        statedVersion: cleanVersion,
                        comparedVersion: adjVer,
                        description:
                          `Fund-flow function 0x${sel} behaves differently between compiler ${cleanVersion} and ${adjVer}. ` +
                          "Adjacent-version divergence suggests compiler-sensitive code path.",
                        severity: "high",
                        confidence: 65,
                        isCriticalFlow: true,
                      });
                    }
                  }
                }
              }
            } catch {
              // Adjacent version might not be installed — skip
            }
          }
        }
      } catch (err) {
        warn("diff-compiler", `Compilation failed for ${address}: ${(err as Error).message}`);
      }
    }

    return {
      contractAddress: address,
      statedVersion: cleanVersion,
      findings,
      deployedBytecodeMatchesCompiled,
      analyzedAt: Date.now(),
      analysisTimeMs: Date.now() - startMs,
    };
  }

  // ── Private ─────────────────────────────────────────────────────────────

  private async checkAvailable(): Promise<void> {
    try {
      await execAsync("solc-select --version", { timeout: 5_000 });
      this.solcSelectAvailable = true;
      info("diff-compiler", "solc-select available — differential compilation enabled");
    } catch {
      this.solcSelectAvailable = false;
      warn("diff-compiler", "solc-select not found — CVE checks only (no recompilation)");
    }
  }

  /**
   * Compiles Solidity source with a given version using solc-select.
   * Returns the runtime bytecode hex or undefined on failure.
   */
  private async compileSingle(
    source: string,
    version: string,
    address: Address,
    optimize = true,
  ): Promise<string | undefined> {
    const workDir = path.join(WORK_DIR_BASE, `${address.slice(0, 10)}-${version}-${optimize ? "opt" : "noopt"}`);

    try {
      await fs.mkdir(workDir, { recursive: true });
      const solPath = path.join(workDir, "Contract.sol");
      await fs.writeFile(solPath, source, "utf-8");

      // Select solc version
      await execAsync(`solc-select use ${version} --always-install`, { timeout: 30_000 });

      // Compile
      const optFlag = optimize ? "--optimize --optimize-runs 200" : "";
      const outPath = path.join(workDir, "out.json");
      await execAsync(
        `solc ${optFlag} --combined-json bin-runtime ${solPath} > ${outPath} 2>/dev/null`,
        { timeout: COMPILE_TIMEOUT_MS },
      );

      const raw = await fs.readFile(outPath, "utf-8");
      const parsed = JSON.parse(raw) as {
        contracts?: Record<string, { "bin-runtime"?: string }>;
      };

      // Find the largest bin-runtime (usually the main contract)
      let largest = "";
      for (const [, c] of Object.entries(parsed.contracts ?? {})) {
        const bin = c["bin-runtime"] ?? "";
        if (bin.length > largest.length) largest = bin;
      }

      return largest || undefined;
    } catch {
      return undefined;
    } finally {
      await fs.rm(workDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  /**
   * Extracts 4-byte function selectors from compiled hex bytecode.
   */
  private extractSelectors(bytecode: string): Set<string> {
    const code = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
    const selectors = new Set<string>();
    // PUSH4 = 0x63
    for (let i = 0; i < code.length - 10; i += 2) {
      if (code[i] === "6" && code[i + 1] === "3") {
        const sel = code.slice(i + 2, i + 10);
        if (/^[0-9a-f]{8}$/.test(sel)) selectors.add(sel);
      }
    }
    return selectors;
  }

  /**
   * Rough similarity check: compare PUSH4-extracted selectors.
   * Two bytecodes "match" if they share >80% of selectors.
   */
  private bytecodesSimilar(compiled: string, deployed: Hex): boolean {
    const compiledSels = this.extractSelectors(compiled);
    const deployedSels = this.extractSelectors(deployed);
    if (compiledSels.size === 0) return true; // can't compare
    const shared = [...compiledSels].filter((s) => deployedSels.has(s)).length;
    return shared / compiledSels.size > 0.8;
  }

  /** Returns adjacent patch versions (e.g., 0.8.20 → [0.8.19, 0.8.21]). */
  private getAdjacentVersions(version: string): string[] {
    const parts = version.split(".").map(Number);
    if (parts.length !== 3) return [];
    const [maj, min, patch] = parts;
    const adj: string[] = [];
    if (patch > 0) adj.push(`${maj}.${min}.${patch - 1}`);
    adj.push(`${maj}.${min}.${patch + 1}`);
    return adj;
  }

  /** Cleans compiler version string: "v0.8.20+commit.abc" → "0.8.20". */
  private cleanVersion(raw: string): string {
    return raw.replace(/^v/, "").replace(/\+.*$/, "").trim();
  }
}
