/**
 * Flashloan Share Manipulation Detector
 *
 * Logic Signature: any protocol that computes share prices or exchange rates
 * from totalAssets() at the time of deposit/borrow, where totalAssets() is
 * influenced by token balances that can be temporarily inflated via flashloan,
 * without a flashloan-resistant lock (transient storage, nonReentrant on
 * the price function, or committed-price pattern).
 *
 * Covers (2026):
 *   - Cyrus Finance Flashloan Pool Shares ($5M, 2026-03-22)
 *   - Wise Lending V2 Flashloan Exploit ($66k, 2026-02-28)
 *
 * Key distinction from donation attack: here the manipulation is atomic
 * within the same transaction via flashloan callback, whereas donation
 * attacks involve a separate transaction to send tokens.
 *
 * Pattern requirements (all must be present):
 *   1. A flashloan entry point (callback) in the same contract or a function
 *      that processes flashloan proceeds
 *   2. A share/rate computation that uses live balance (SELFBALANCE/BALANCE)
 *   3. No transient-storage lock or re-entrancy guard on the rate computation
 *   4. A deposit/borrow/redeem operation callable within the flashloan callback
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

// Flashloan callback / initiator selectors
const FLASHLOAN_SELECTORS = new Map<string, string>([
  ["0x5cffe9de", "flashLoan(address,address,uint256,bytes)"],        // Aave V2
  ["0xab9c4b5d", "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)"], // Aave V3
  ["0x23e30c8b", "onFlashLoan(address,address,uint256,uint256,bytes)"],  // ERC-3156 callback
  ["0x10d1e85c", "receiveFlashLoan(address[],uint256[],uint256[],bytes)"], // Balancer callback
  ["0xfa461e33", "uniswapV3FlashCallback(uint256,uint256,bytes)"],    // Uniswap V3 flash
  ["0x84800812", "pancakeV3FlashCallback(uint256,uint256,bytes)"],    // PancakeSwap V3
  ["0xfc0c546a", "flash(address,uint256,uint256,bytes)"],             // Uniswap V3 pool
  ["0x490e6cbc", "flashSwap(bytes)"],                                 // generic
  ["0xe0ee6570", "executeOperation(address,uint256,uint256,address,bytes)"], // Aave V1
]);

// Deposit/borrow/redeem selectors — these should not be callable within flashloan context
const LENDING_ACTION_SELECTORS = new Set([
  "0x6e553f65", // deposit(uint256,address)
  "0x94bf804d", // mint(uint256,address)
  "0xba087652", // redeem(uint256,address,address)
  "0xb460af94", // withdraw(uint256,address,address)
  "0xc5ebeaec", // borrow(uint256)
  "0xa0712d68", // mint(uint256)
  "0xe8eda9df", // deposit(address,uint256,address,uint16)
]);

export function detectFlashloanShareManipulation(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];
  const detectedSelectors = new Set(evm.selectors);

  // Check 1: Does this contract have flashloan callbacks?
  const flashloanCallbacks = [...FLASHLOAN_SELECTORS.keys()]
    .filter(s => detectedSelectors.has(s));

  if (flashloanCallbacks.length === 0) {
    // Also check if any function has a known flashloan-initiator call
    const callsFlashloan = detectFlashloanInitiatorCall(evm);
    if (!callsFlashloan) return findings;
  }

  // Check 2: Does any function compute share price from live balance?
  const sharePriceFunctions = findSharePriceFromBalance(evm);
  if (sharePriceFunctions.length === 0) return findings;

  // Check 3: Are the share-price functions protected against re-entrancy?
  for (const sel of sharePriceFunctions) {
    const entryBlock = evm.cfg.selectorToBlock.get(sel);
    if (entryBlock === undefined) continue;

    const { hasReentrancyGuard, hasTransientLock } = checkReentrancyProtection(evm, entryBlock);

    if (!hasReentrancyGuard && !hasTransientLock) {
      const isLendingAction = LENDING_ACTION_SELECTORS.has(sel);

      findings.push({
        riskClass: "flashloan_share_manipulation",
        severity: isLendingAction ? "critical" : "high",
        functionSelector: sel as `0x${string}`,
        description:
          `Flashloan share manipulation: function ${sel} computes a share/exchange rate ` +
          `from a live token balance (SELFBALANCE/BALANCE) and has no re-entrancy guard. ` +
          `A flashloan can temporarily inflate the balance before this function executes, ` +
          `allowing minting of inflated shares or over-collateralized borrows. ` +
          "Fix: (1) use a committed-price pattern (read price before flashloan, commit to storage), " +
          "(2) add nonReentrant modifier to ALL functions that read balance for pricing, " +
          "(3) use transient storage (EIP-1153) for in-flight locks. " +
          "Seen in Cyrus Finance ($5M, 2026-03-22) and Wise Lending V2 ($66k, 2026-02-28).",
        confidence: 80,
      });
    }
  }

  // Check 4: Flashloan callback that calls back into lending actions
  for (const cbSel of flashloanCallbacks) {
    const entryBlock = evm.cfg.selectorToBlock.get(cbSel);
    if (entryBlock === undefined) continue;

    const callsLending = detectLendingCallsInCallback(evm, entryBlock, detectedSelectors);
    if (callsLending) {
      findings.push({
        riskClass: "flashloan_share_manipulation",
        severity: "high",
        functionSelector: cbSel as `0x${string}`,
        functionName: FLASHLOAN_SELECTORS.get(cbSel),
        description:
          `Flashloan callback ${cbSel} (${FLASHLOAN_SELECTORS.get(cbSel)}) makes calls ` +
          `that appear to reach lending action functions (deposit/borrow/redeem). ` +
          "This is the standard flashloan re-entrancy pattern — verify that share prices " +
          "are computed from a committed snapshot, not from live balances.",
        confidence: 70,
      });
    }
  }

  return dedup(findings);
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function findSharePriceFromBalance(evm: EVMAnalysisResult): string[] {
  const result: string[] = [];

  for (const [sel, entryBlock] of evm.cfg.selectorToBlock) {
    let hasBalanceRead = false;
    let hasDivision = false;

    const visited = new Set<number>();
    const queue = [entryBlock];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const block = evm.cfg.blocks.get(id);
      if (!block) continue;

      for (const inst of block.instructions) {
        if (inst.opcode === 0x31 || inst.opcode === 0x47) hasBalanceRead = true; // BALANCE / SELFBALANCE
        if (hasBalanceRead && (inst.opcode === 0x04 || inst.opcode === 0x05)) hasDivision = true;
      }

      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }

    if (hasBalanceRead && hasDivision) result.push(sel);
  }

  return result;
}

function checkReentrancyProtection(
  evm: EVMAnalysisResult,
  entryBlock: number,
): { hasReentrancyGuard: boolean; hasTransientLock: boolean } {
  // Re-entrancy guard pattern: SLOAD at entry → ISZERO → JUMPI (require(!locked))
  //                             SSTORE near entry (set lock)
  // Transient storage: TLOAD (0x5c) / TSTORE (0x5d) — EIP-1153 opcodes
  let hasSloadAtEntry = false;
  let hasSstoreAtEntry = false;
  let hasTransientLock = false;

  const firstBlock = evm.cfg.blocks.get(entryBlock);
  if (!firstBlock) return { hasReentrancyGuard: false, hasTransientLock: false };

  const insts = firstBlock.instructions.slice(0, 20); // Check first 20 instructions
  for (const inst of insts) {
    if (inst.opcode === 0x54) hasSloadAtEntry = true; // SLOAD
    if (inst.opcode === 0x55) hasSstoreAtEntry = true; // SSTORE
    if (inst.opcode === 0x5c || inst.opcode === 0x5d) hasTransientLock = true; // TLOAD/TSTORE
  }

  return {
    hasReentrancyGuard: hasSloadAtEntry && hasSstoreAtEntry,
    hasTransientLock,
  };
}

function detectFlashloanInitiatorCall(evm: EVMAnalysisResult): boolean {
  // Check if any function calls a known flashloan initiator by selector
  for (const [, entryBlock] of evm.cfg.selectorToBlock) {
    const visited = new Set<number>();
    const queue = [entryBlock];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const block = evm.cfg.blocks.get(id);
      if (!block) continue;

      for (const inst of block.instructions) {
        if (inst.opcode === 0x63 && inst.operand !== undefined) {
          const selHex = "0x" + inst.operand.toString(16).padStart(8, "0");
          if (FLASHLOAN_SELECTORS.has(selHex)) return true;
        }
      }

      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }
  }
  return false;
}

function detectLendingCallsInCallback(
  evm: EVMAnalysisResult,
  entryBlock: number,
  detectedSelectors: Set<string>,
): boolean {
  const visited = new Set<number>();
  const queue = [entryBlock];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    for (const inst of block.instructions) {
      if (inst.opcode === 0x63 && inst.operand !== undefined) {
        const selHex = "0x" + inst.operand.toString(16).padStart(8, "0");
        if (LENDING_ACTION_SELECTORS.has(selHex) && detectedSelectors.has(selHex)) {
          return true;
        }
      }
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }
  return false;
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
