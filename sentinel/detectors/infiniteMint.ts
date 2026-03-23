/**
 * Infinite Mint / Token Inflation Detector
 *
 * Logic Signature: any mint function that does not enforce
 * mintedAmount ≤ (reserveBalance − existingLiabilities) allows
 * unlimited supply inflation, regardless of token standard or mechanism.
 *
 * Covers (2026):
 *   - Saga Infinite Mint and Dump ($7M)
 *   - DGLD Infinite Mint ($0 — caught early)
 *   - TMX TRIBE Mint-Stake Loop ($1.4M)
 *   - SolvBTC Mint Reserves Logic Exploit ($2.7M)
 *   - Truebit Bonding Curve Overflow ($26.4M)
 *
 * Sub-patterns:
 *   A. Uncapped mint: mint() callable with no reserve ratio validation
 *   B. Mint-stake loop: circular dependency where minting feeds back into
 *      the reserve that authorizes further minting
 *   C. Bonding curve rounding: DIV-before-MUL in curve pricing creates
 *      a profitable arbitrage cycle per transaction
 *   D. Pending-vs-confirmed reserve confusion: mint authorized against
 *      uncommitted/expected reserves rather than settled balances
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

// Mint-related function selectors (4-byte hashes)
// The detector does NOT require these — they are used as entry-point hints
const MINT_SELECTORS = new Set([
  "0x40c10f19", // mint(address,uint256)
  "0xa0712d68", // mint(uint256)
  "0x94bf804d", // mint(uint256,address) — ERC-4626
  "0x1249c58b", // mint()
  "0x6a627842", // mint(address)
  "0x4b750334", // issue(uint256)     — stablecoin style
  "0x2e1a7d4d", // withdraw(uint256)  — sometimes used for mint in bonding curves
  "0xd96a094a", // buy(uint256)       — bonding curve buy
  "0x23b872dd", // transferFrom used in some mint gates
]);

// Buy/sell bonding curve selectors
const BONDING_CURVE_SELECTORS = new Set([
  "0xd96a094a", // buy(uint256)
  "0x7f47a0a5", // sell(uint256)
  "0x441a3e70", // withdraw(uint256,uint256)
  "0x2e1a7d4d", // withdraw(uint256)
  "0x6a8f3f6f", // buyTokens(uint256)
  "0xa6f2ae3a", // buy()
]);

// Reserve-reading selectors — if a mint function calls these AND validates,
// that's a good sign; if it doesn't call them, it's an uncapped mint
const RESERVE_CHECK_SELECTORS = new Set([
  "0x18160ddd", // totalSupply()
  "0x01e1d114", // totalAssets()
  "0x70a08231", // balanceOf(address)
  "0x47e7ef24", // deposit(address,uint256)
  "0xd0e30db0", // deposit()
]);

export function detectInfiniteMint(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];
  const detectedSelectors = new Set(evm.selectors);

  // --- A. Uncapped mint: mint function with no reserve ratio check ---
  for (const sel of detectedSelectors) {
    if (!MINT_SELECTORS.has(sel)) continue;

    const entryBlock = evm.cfg.selectorToBlock.get(sel);
    if (entryBlock === undefined) continue;

    const analysis = analyzeMintFunction(evm, entryBlock);

    if (!analysis.hasReserveCheck && !analysis.hasMaxSupplyCheck) {
      findings.push({
        riskClass: "infinite_mint",
        severity: "critical",
        functionSelector: sel as `0x${string}`,
        description:
          `Uncapped mint: function ${sel} mints tokens without validating ` +
          `mintAmount ≤ reserveBalance. No reserve ratio check (balanceOf / totalAssets) ` +
          `and no max supply cap detected in the execution path. ` +
          `An attacker can mint unbounded tokens and dump them. ` +
          `Seen in Saga ($7M, 2026-01-21) and DGLD (2026-02-23).`,
        confidence: analysis.hasMintOpcode ? 85 : 65,
      });
    } else if (!analysis.hasReserveCheck && analysis.hasMaxSupplyCheck) {
      findings.push({
        riskClass: "infinite_mint",
        severity: "medium",
        functionSelector: sel as `0x${string}`,
        description:
          `Partial mint protection: function ${sel} has a max supply cap but no per-mint ` +
          `reserve ratio validation. If the cap can be updated by governance, it is not ` +
          `a sufficient protection against economic mint abuse.`,
        confidence: 60,
      });
    }
  }

  // --- B. Circular mint-stake loop ---
  // Detect: contract has both mint AND stake functions, and the stake function
  // calls back into the mint-authorized path
  const hasMintFunction = [...MINT_SELECTORS].some(s => detectedSelectors.has(s));
  const hasStakeFunction = detectStakeFunction(evm, detectedSelectors);

  if (hasMintFunction && hasStakeFunction) {
    const { hasCircularFlow } = detectCircularMintStake(evm);
    if (hasCircularFlow) {
      findings.push({
        riskClass: "mint_loop",
        severity: "high",
        functionSelector: "0x00000000" as `0x${string}`,
        description:
          "Circular mint-stake loop detected: the contract has both mint and stake " +
          "functions, and the stake path leads back to a mint-authorizing state. " +
          "If staking token A generates token B which can be staked to generate more token A, " +
          "the protocol's reward accounting can be drained in a single transaction. " +
          "Seen in TMX TRIBE ($1.4M, 2026-01-05).",
        confidence: 70,
      });
    }
  }

  // --- C. Bonding curve rounding exploit ---
  // Pattern: buy() and sell() both use DIV in their pricing formula
  // If round-trip is buy→sell and the division always favors caller, profit per cycle
  const hasBuySell = [...BONDING_CURVE_SELECTORS].some(s => detectedSelectors.has(s));
  if (hasBuySell) {
    const bondingAnalysis = analyzeBondingCurve(evm, detectedSelectors);
    if (bondingAnalysis.hasDivInBuy && bondingAnalysis.hasDivInSell) {
      findings.push({
        riskClass: "bonding_curve_overflow",
        severity: "high",
        functionSelector: "0xd96a094a" as `0x${string}`,
        description:
          "Bonding curve rounding arbitrage: both buy and sell functions contain integer " +
          "division. If the rounding direction is inconsistent (e.g., buy rounds down price " +
          "to caller's benefit while sell rounds up), each buy→sell cycle extracts a small " +
          "amount from the pool. At scale with flashloans this drains reserves entirely. " +
          `${bondingAnalysis.hasMulAfterDiv ? "MUL-after-DIV pattern detected — likely precision loss. " : ""}` +
          "Seen in Truebit bonding curve ($26.4M, 2026-01-08).",
        confidence: bondingAnalysis.hasMulAfterDiv ? 85 : 65,
      });
    }
  }

  // --- D. Pending/expected vs confirmed reserve mint ---
  // Pattern: mint function reads from RETURNDATALOAD (external call) and
  // immediately uses the result in a comparison to authorize minting,
  // without a second confirmation step (e.g., checking settled balance)
  for (const sel of detectedSelectors) {
    if (!MINT_SELECTORS.has(sel)) continue;
    const entryBlock = evm.cfg.selectorToBlock.get(sel);
    if (entryBlock === undefined) continue;

    const { usesExternalReturnAsReserve } = detectPendingReservePattern(evm, entryBlock);
    if (usesExternalReturnAsReserve) {
      findings.push({
        riskClass: "infinite_mint",
        severity: "high",
        functionSelector: sel as `0x${string}`,
        description:
          `Function ${sel} uses the return value of an external call directly as the ` +
          `reserve authorization for minting, without cross-validating against a settled ` +
          `on-chain balance. Pending/expected amounts can be spoofed or front-run. ` +
          "Seen in SolvBTC mint reserves exploit ($2.7M, 2026-03-06).",
        confidence: 70,
      });
    }
  }

  return dedup(findings);
}

// ─── Helpers ──────────────────────────────────────────────────────────────

interface MintFunctionAnalysis {
  hasReserveCheck: boolean;
  hasMaxSupplyCheck: boolean;
  hasMintOpcode: boolean;
}

function analyzeMintFunction(evm: EVMAnalysisResult, entryBlock: number): MintFunctionAnalysis {
  let hasReserveCheck = false;
  let hasMaxSupplyCheck = false;
  let hasExternalCall = false;
  let hasMintOpcode = false;
  let callCount = 0;

  const visited = new Set<number>();
  const queue = [entryBlock];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    const insts = block.instructions;
    for (let i = 0; i < insts.length; i++) {
      const op = insts[i].opcode;

      // External calls that could read reserve state
      if (op === 0xf1 || op === 0xfa) {
        callCount++;
        hasExternalCall = true;
      }

      // PUSH4 of reserve-reading selectors → followed by CALL = reserve check
      if (op === 0x63 && insts[i].operand !== undefined) {
        const selHex = "0x" + insts[i].operand!.toString(16).padStart(8, "0");
        if (RESERVE_CHECK_SELECTORS.has(selHex)) {
          hasReserveCheck = true;
        }
      }

      // GT/LT comparison followed by JUMPI — potential max supply or ratio check
      if ((op === 0x10 || op === 0x11) && insts[i + 1]?.opcode === 0x57) {
        if (callCount > 0) {
          // Comparison happens after an external call (likely reserve check)
          hasReserveCheck = true;
        } else {
          // Comparison before external calls — may be max supply
          hasMaxSupplyCheck = true;
        }
      }

      // SSTORE after computing new supply — typical mint state update
      if (op === 0x55) hasMintOpcode = true;
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }

  return { hasReserveCheck, hasMaxSupplyCheck, hasMintOpcode };
}

function detectStakeFunction(evm: EVMAnalysisResult, detectedSelectors: Set<string>): boolean {
  const STAKE_SELECTORS = new Set([
    "0xa694fc3a", // stake(uint256)
    "0xb6b55f25", // deposit(uint256)
    "0x02c77fcf", // stake(uint256,address)
    "0x7acb7757", // stakeFor(address,uint256)
  ]);
  return [...STAKE_SELECTORS].some(s => detectedSelectors.has(s));
}

function detectCircularMintStake(
  evm: EVMAnalysisResult,
): { hasCircularFlow: boolean } {
  // Approximation: detect if the same function both mints (SSTORE after totalSupply-like read)
  // AND calls an external address that in turn could call back (re-entrancy-adjacent pattern)
  let mintSeen = false;
  let externalCallAfterMint = false;

  for (const block of evm.cfg.blocks.values()) {
    const insts = block.instructions;
    for (let i = 0; i < insts.length; i++) {
      if (insts[i].opcode === 0x55) mintSeen = true; // SSTORE = state change
      if (mintSeen && (insts[i].opcode === 0xf1 || insts[i].opcode === 0xf4)) {
        externalCallAfterMint = true;
      }
    }
  }

  return { hasCircularFlow: mintSeen && externalCallAfterMint };
}

interface BondingCurveAnalysis {
  hasDivInBuy: boolean;
  hasDivInSell: boolean;
  hasMulAfterDiv: boolean;
}

function analyzeBondingCurve(
  evm: EVMAnalysisResult,
  detectedSelectors: Set<string>,
): BondingCurveAnalysis {
  let hasDivInBuy = false;
  let hasDivInSell = false;
  let hasMulAfterDiv = false;

  const buySel = [...BONDING_CURVE_SELECTORS].find(s => detectedSelectors.has(s));
  const sellSel = "0x7f47a0a5";

  if (buySel) {
    const { hasDiv, hasMulAfterDiv: mad } = countDivMul(evm, buySel);
    hasDivInBuy = hasDiv;
    hasMulAfterDiv = hasMulAfterDiv || mad;
  }

  if (detectedSelectors.has(sellSel)) {
    const { hasDiv } = countDivMul(evm, sellSel);
    hasDivInSell = hasDiv;
  }

  return { hasDivInBuy, hasDivInSell, hasMulAfterDiv };
}

function countDivMul(
  evm: EVMAnalysisResult,
  sel: string,
): { hasDiv: boolean; hasMulAfterDiv: boolean } {
  const entryBlock = evm.cfg.selectorToBlock.get(sel);
  if (entryBlock === undefined) return { hasDiv: false, hasMulAfterDiv: false };

  let hasDiv = false;
  let hasMulAfterDiv = false;
  const visited = new Set<number>();
  const queue = [entryBlock];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    for (let i = 0; i < block.instructions.length; i++) {
      const op = block.instructions[i].opcode;
      if (op === 0x04 || op === 0x05) hasDiv = true;
      if (hasDiv && op === 0x02) hasMulAfterDiv = true; // MUL after DIV = precision loss risk
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }

  return { hasDiv, hasMulAfterDiv };
}

function detectPendingReservePattern(
  evm: EVMAnalysisResult,
  entryBlock: number,
): { usesExternalReturnAsReserve: boolean } {
  let hasExternalCall = false;
  let hasReturnDataUsedInComparison = false;
  const visited = new Set<number>();
  const queue = [entryBlock];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    for (let i = 0; i < block.instructions.length; i++) {
      const op = block.instructions[i].opcode;
      if (op === 0xf1 || op === 0xfa) hasExternalCall = true;
      // RETURNDATACOPY or subsequent MLOAD after external call used in GT/LT
      if (hasExternalCall && op === 0x3e) { // RETURNDATACOPY
        hasReturnDataUsedInComparison = true;
      }
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }

  return {
    usesExternalReturnAsReserve: hasExternalCall && hasReturnDataUsedInComparison,
  };
}

function dedup(findings: StaticAnalysisFinding[]): StaticAnalysisFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.riskClass}:${f.functionSelector}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
