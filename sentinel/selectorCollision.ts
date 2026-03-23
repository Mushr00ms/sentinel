/**
 * Module H.2 — Function Selector Collision Detector
 *
 * Solidity function selectors are 4-byte keccak256 hashes. With only 2^32
 * possible values and thousands of functions across DeFi, collisions exist
 * where a safe-looking function signature hashes to the same selector as a
 * dangerous one. Attackers can call the dangerous operation through the
 * benign-looking interface.
 *
 * Also detects when a contract's ABI contains a selector that matches a
 * historically-exploited function across any other contract in the audit DB.
 */

import { keccak256, toBytes } from "viem";
import type { Address, Hex } from "viem";
import type { SelectorCollisionFinding, MisconfigSeverity } from "./types.js";
import { VULNERABLE_SELECTORS } from "./config.js";

// ─── Known dangerous selectors ──────────────────────────────────────────

/**
 * Historical exploit selectors — functions whose presence in a contract
 * has led to real exploits. Keyed by 4-byte hex selector (no 0x prefix).
 */
const HISTORICAL_EXPLOIT_SELECTORS: Record<string, { name: string; reason: string; severity: MisconfigSeverity }> = {
  // Flash loan / reentrancy surfaces
  "5cffe9de": { name: "flashLoan(address,address,uint256,bytes)", reason: "Standard flash loan entry — reentrancy surface if callback not guarded", severity: "high" },
  "23e30c8b": { name: "onFlashLoan(address,address,uint256,uint256,bytes)", reason: "ERC-3156 flash loan callback — must validate initiator and token", severity: "high" },
  "fa461e33": { name: "uniswapV3SwapCallback(int256,int256,bytes)", reason: "Uniswap V3 callback — unguarded implementation drains pool", severity: "critical" },
  "10d1e85c": { name: "uniswapV2Call(address,uint256,uint256,bytes)", reason: "Uniswap V2 flash callback — must validate caller is a V2 pair", severity: "high" },
  "84800812": { name: "pancakeV3SwapCallback(int256,int256,bytes)", reason: "PancakeSwap V3 callback — same risk as Uniswap V3", severity: "critical" },

  // Fund drain patterns
  "42966c68": { name: "burn(uint256)", reason: "Unchecked burn can destroy token supply", severity: "medium" },
  "9dc29fac": { name: "burn(address,uint256)", reason: "Admin burn — if unprotected allows destroying any balance", severity: "critical" },
  "40c10f19": { name: "mint(address,uint256)", reason: "Admin mint — if unprotected allows unlimited inflation", severity: "critical" },
  "5acc7e05": { name: "donate()", reason: "donate() used in several exploits to manipulate reserve accounting", severity: "high" },

  // Proxy / upgrade risks
  "3659cfe6": { name: "upgradeTo(address)", reason: "UUPS/transparent proxy upgrade — compromised admin = full drain", severity: "critical" },
  "4f1ef286": { name: "upgradeToAndCall(address,bytes)", reason: "Proxy upgrade with delegate init — arbitrary delegatecall risk", severity: "critical" },
  "cf7a1d77": { name: "prepareUpgrade(address)", reason: "Staged upgrade — window between prepare and execute is exploitable", severity: "high" },

  // Oracle / price manipulation
  "76ca3a82": { name: "setOracle(address)", reason: "Unprotected oracle setter allows pointing to malicious price feed", severity: "critical" },
  "9d1b464a": { name: "setPriceFeed(address)", reason: "Unprotected price feed setter", severity: "critical" },
  "1626ba7e": { name: "isValidSignature(bytes32,bytes)", reason: "ERC-1271 signature validation — if accepts arbitrary sigs, can bypass auth", severity: "high" },

  // Access control bypass
  "8da5cb5b": { name: "owner()", reason: "If owner is EOA on production, single point of failure", severity: "low" },
  "f2fde38b": { name: "transferOwnership(address)", reason: "Unprotected ownership transfer = instant rug", severity: "critical" },
  "715018a6": { name: "renounceOwnership()", reason: "Irreversible — accidental call bricks protocol if needed", severity: "medium" },

  // Multicall / calldata forwarding
  "ac9650d8": { name: "multicall(bytes[])", reason: "Multicall without msg.value isolation — ETH theft via re-use across calls", severity: "high" },
  "82ad56cb": { name: "aggregate(Call[])", reason: "Aggregate multicall — same ETH msg.value issue as multicall", severity: "high" },

  // Emergency / admin backdoors
  "c2985578": { name: "pause()", reason: "Pause mechanism — if permissionless, griefing vector", severity: "medium" },
  "3f4ba83a": { name: "unpause()", reason: "Unpause — if unprotected, bypasses intended paused state", severity: "high" },
  "60f9bb11": { name: "emergencyWithdraw()", reason: "Emergency withdraw — classic rugpull vector if unprotected", severity: "critical" },
  "db2e21bc": { name: "emergencyExit()", reason: "Emergency exit — may bypass normal checks, drain pool", severity: "critical" },
};

// ─── SelectorCollisionDetector ───────────────────────────────────────────

export class SelectorCollisionDetector {
  /**
   * Global registry of selectors seen across all audited contracts.
   * Maps selector → list of {address, functionName} that use it.
   */
  private readonly globalRegistry = new Map<string, Array<{ address: Address; functionName: string }>>();

  /**
   * Analyzes a contract's ABI for:
   * 1. Collisions with known dangerous/exploit selectors
   * 2. Collisions with selectors seen on high-risk contracts in the audit DB
   */
  detect(address: Address, abiJson: string): SelectorCollisionFinding[] {
    const findings: SelectorCollisionFinding[] = [];

    let abi: Array<{ type?: string; name?: string; inputs?: Array<{ type: string }> }>;
    try {
      abi = JSON.parse(abiJson);
    } catch {
      return findings;
    }

    const functions = abi.filter((e) => e.type === "function" && e.name);

    for (const fn of functions) {
      const sig = this.buildSignature(fn.name!, fn.inputs ?? []);
      const selector = this.computeSelector(sig);
      const bare = selector.slice(2); // strip 0x

      // ── Check 1: Known exploit selectors ─────────────────────────────
      const exploitEntry = HISTORICAL_EXPLOIT_SELECTORS[bare];
      if (exploitEntry && fn.name !== exploitEntry.name.split("(")[0]) {
        // Same selector, different function name — collision!
        findings.push({
          selector: selector as Hex,
          contractFunction: sig,
          collidingFunction: exploitEntry.name,
          riskReason: `Selector collision with historical exploit vector: ${exploitEntry.reason}`,
          severity: exploitEntry.severity,
          confidence: 90,
        });
      }

      // ── Check 2: VULNERABLE_SELECTORS from config ────────────────────
      const vulnName = VULNERABLE_SELECTORS[`0x${bare}`];
      if (vulnName && fn.name?.toLowerCase() !== vulnName.toLowerCase()) {
        findings.push({
          selector: selector as Hex,
          contractFunction: sig,
          collidingFunction: vulnName,
          riskReason: `Selector matches known vulnerable function pattern: ${vulnName}`,
          severity: "high",
          confidence: 80,
        });
      }

      // ── Check 3: Present in both this contract AND a known dangerous context
      const knownDangerous = this.globalRegistry.get(bare);
      if (knownDangerous) {
        for (const entry of knownDangerous) {
          if (entry.address === address) continue;
          if (entry.functionName !== fn.name) {
            // Same selector, different function names across contracts
            findings.push({
              selector: selector as Hex,
              contractFunction: sig,
              collidingFunction: entry.functionName,
              collidingContract: entry.address,
              riskReason:
                `Selector collision with ${entry.functionName} on ${entry.address.slice(0, 12)}…. ` +
                `Cross-contract confusion: callers targeting one may accidentally invoke the other.`,
              severity: "medium",
              confidence: 60,
            });
          }
        }
      }

      // Register this function in the global registry
      if (!this.globalRegistry.has(bare)) this.globalRegistry.set(bare, []);
      this.globalRegistry.get(bare)!.push({ address, functionName: fn.name! });
    }

    return findings;
  }

  /**
   * Registers a contract's ABI into the global selector registry.
   * Call this for every contract processed, so cross-contract collision
   * detection accumulates over time.
   */
  register(address: Address, abiJson: string): void {
    let abi: Array<{ type?: string; name?: string; inputs?: Array<{ type: string }> }>;
    try {
      abi = JSON.parse(abiJson);
    } catch {
      return;
    }

    for (const fn of abi) {
      if (fn.type !== "function" || !fn.name) continue;
      const sig = this.buildSignature(fn.name, fn.inputs ?? []);
      const selector = this.computeSelector(sig).slice(2);
      if (!this.globalRegistry.has(selector)) this.globalRegistry.set(selector, []);
      this.globalRegistry.get(selector)!.push({ address, functionName: fn.name });
    }
  }

  // ── Private ────────────────────────────────────────────────────────────

  private buildSignature(name: string, inputs: Array<{ type: string }>): string {
    return `${name}(${inputs.map((i) => i.type).join(",")})`;
  }

  private computeSelector(signature: string): string {
    const hash = keccak256(toBytes(signature));
    return hash.slice(0, 10); // 0x + 4 bytes = 10 chars
  }
}
