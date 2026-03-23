/**
 * Oracle Misconfiguration Detector
 *
 * Logic Signature: any contract that (a) reads a price from an external
 * source and (b) uses that price for lending/collateral decisions without
 * one or more of: staleness check, TWAP, bounds validation, or circuit breaker.
 *
 * Covers (2026): Makina Flashloan Oracle ($4.2M), Blend Pools V2 ($11M),
 *                Ploutos Money ($390k), Aave V3 CAPO ($862k),
 *                YO Protocol Slippage ($3.7M), Moonwell cbETH ($1.78M)
 *
 * Key insight: the vulnerability is NOT which oracle is used — it is that
 * the price read is (1) spot/instantaneous, (2) unvalidated, or (3) used
 * in the same transaction in which it can be manipulated.
 *
 * Four sub-patterns detected:
 *   A. Spot-price-in-same-block: Uniswap getReserves / slot0 used directly
 *   B. No-staleness-check: Chainlink latestRoundData with no updatedAt validation
 *   C. Cap-without-reference-check: CAPO-style oracle where the cap reference can be stale
 *   D. LST-exchange-rate-as-price: liquid staking token priced at internal rate, not market
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

// Known DEX spot-price selectors that return instantaneous price
// (manipulable by flashloan in the same tx)
const DEX_SPOT_PRICE_SELECTORS = new Set([
  "0x0902f1ac", // getReserves() — Uniswap V2 / Sushi
  "0x3850c7bd", // slot0()       — Uniswap V3
  "0x252c09d7", // observations() — Uniswap V3 TWAP (but direct slot, not averaged)
  "0xddca3f43", // fee()          — Uniswap V3
  "0x50d25bcd", // latestAnswer() — Chainlink (deprecated, no staleness)
]);

// Chainlink-style oracle selectors — should be followed by staleness checks
const CHAINLINK_SELECTORS = new Set([
  "0xfeaf968c", // latestRoundData()
  "0x50d25bcd", // latestAnswer()    — deprecated, no roundId
  "0x8205bf6a", // latestTimestamp() — Chainlink V1
]);

// LST/LSD internal exchange rate selectors — these return backing rate, not market price
const LST_RATE_SELECTORS = new Set([
  "0x035faf82", // exchangeRate()     — generic
  "0xbd6d894d", // exchangeRateCurrent() — cToken
  "0x182df0f5", // exchangeRateStored()
  "0x035faf82", // getExchangeRate()
  "0x0a9f6b50", // pricePerShare()    — Yearn
  "0x77c7b8fc", // pricePerFullShare()
  "0xe6aa216c", // getPooledEthByShares() — Lido stETH
  "0x7a28fb88", // convertToAssets(1e18) — stETH equivalent
]);

// Selectors that represent lending/borrowing decisions — these should NEVER
// use spot oracle values computed in the same tx
const LENDING_ACTION_SELECTORS = new Set([
  "0xc5ebeaec", // borrow(uint256)
  "0x1249c58b", // mint() — borrow side
  "0xa0712d68", // mint(uint256)
  "0x69328dec", // withdraw(address,uint256,address)
  "0xe8eda9df", // deposit(address,uint256,address,uint16)
  "0xab9c4b5d", // liquidationCall(...)
  "0x415912b8", // liquidateBorrow(...)
]);

export function detectOracleMisconfiguration(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];
  const detectedSelectors = new Set(evm.selectors);

  // --- A. Spot price in same block ---
  // Detect: CALL to known DEX spot selector → result used without TWAP/averaging
  const spotPriceFunctions = findFunctionsCallingSelectors(evm, DEX_SPOT_PRICE_SELECTORS);

  for (const sel of spotPriceFunctions) {
    // Check if the return value is used in a lending action in the same tx
    const hasTwapProtection = checkForTwapPattern(evm, evm.cfg.selectorToBlock.get(sel) ?? -1);

    findings.push({
      riskClass: "oracle_manipulation",
      severity: hasTwapProtection ? "medium" : "critical",
      functionSelector: sel as `0x${string}`,
      description:
        `Spot-price oracle: function ${sel} calls a DEX spot-price getter ` +
        `(getReserves/slot0). This price is instantaneous and flashloan-manipulable ` +
        `in the same transaction. ` +
        (hasTwapProtection
          ? "A TWAP-like pattern was detected — verify the time window is sufficient (≥ 30 min)."
          : "No time-weighted averaging detected. Use a TWAP oracle or Chainlink with staleness check."),
      confidence: hasTwapProtection ? 55 : 85,
    });
  }

  // --- B. Chainlink without staleness check ---
  // Pattern: latestRoundData() called but no comparison of updatedAt with block.timestamp
  const chainlinkFunctions = findFunctionsCallingSelectors(evm, CHAINLINK_SELECTORS);

  for (const sel of chainlinkFunctions) {
    const entryBlock = evm.cfg.selectorToBlock.get(sel);
    if (entryBlock === undefined) continue;

    const { hasTimestampRead, hasTimestampComparison, hasRoundIdCheck } =
      analyzeChainlinkValidation(evm, entryBlock);

    if (!hasTimestampComparison || !hasRoundIdCheck) {
      findings.push({
        riskClass: "oracle_misconfiguration",
        severity: "high",
        functionSelector: sel as `0x${string}`,
        description:
          `Chainlink oracle missing validation in function ${sel}: ` +
          (!hasTimestampComparison ? "no 'updatedAt > block.timestamp - maxStaleness' check; " : "") +
          (!hasRoundIdCheck ? "no 'answeredInRound >= roundId' check. " : " ") +
          "A stale or unfinished round will return the last known price, which may be outdated. " +
          "Seen in Ploutos Money ($390k, 2026-02-26) and Aave CAPO ($862k, 2026-03-12).",
        confidence: 75,
      });
    }
  }

  // --- C. CAPO-style oracle: price cap without reference staleness validation ---
  // Pattern: min(price, cap) where cap is derived from an older stored value
  // without checking that the stored reference price is fresh
  const hasMinOpcode = detectMinPatternInAnyFunction(evm);
  if (hasMinOpcode && chainlinkFunctions.size > 0) {
    findings.push({
      riskClass: "oracle_misconfiguration",
      severity: "medium",
      functionSelector: "0x00000000" as `0x${string}`,
      description:
        "CAPO-style oracle pattern detected: price is capped via min() operation. " +
        "Verify that the reference price used to derive the cap is itself freshness-validated. " +
        "If the cap reference price is stale, the cap may be set incorrectly, allowing " +
        "manipulated prices to pass through. Seen in Aave V3 CAPO exploit ($862k, 2026-03-12).",
      confidence: 55,
    });
  }

  // --- D. LST/LSD internal rate used as price in lending ---
  // Pattern: pricePerShare / exchangeRate called and fed into collateral valuation
  // without cross-checking against a DEX market price
  const lstRateFunctions = findFunctionsCallingSelectors(evm, LST_RATE_SELECTORS);
  const hasLendingActions = [...LENDING_ACTION_SELECTORS].some(s => detectedSelectors.has(s));

  if (lstRateFunctions.size > 0 && hasLendingActions) {
    for (const sel of lstRateFunctions) {
      findings.push({
        riskClass: "collateral_mispricing",
        severity: "high",
        functionSelector: sel as `0x${string}`,
        description:
          `Function ${sel} reads a liquid staking token's internal exchange rate ` +
          `(pricePerShare / exchangeRateCurrent) for collateral pricing. ` +
          `Internal rates can diverge from market price (depeg, pending withdrawals, slashing). ` +
          `Use a market-price oracle (Chainlink / TWAP) for LTV calculations. ` +
          `Seen in Moonwell cbETH exploit ($1.78M, 2026-02-15).`,
        confidence: 70,
      });
    }
  }

  // --- E. No-bounds check on oracle output (generic) ---
  // Pattern: CALL to external oracle → result used in DIV without GT/LT sanity check
  const oracleReturnWithoutBounds = detectUnboundedOracleResult(evm);
  if (oracleReturnWithoutBounds.length > 0) {
    for (const sel of oracleReturnWithoutBounds) {
      findings.push({
        riskClass: "oracle_misconfiguration",
        severity: "medium",
        functionSelector: sel as `0x${string}`,
        description:
          `Function ${sel} uses the return value of an external CALL in arithmetic ` +
          `(division or multiplication) without a preceding bounds check (GT/LT comparison). ` +
          `A zero or extreme oracle value can cause division by zero or unbounded scaling. ` +
          `Always validate: require(price > MIN_PRICE && price < MAX_PRICE).`,
        confidence: 60,
      });
    }
  }

  return dedup(findings);
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function findFunctionsCallingSelectors(
  evm: EVMAnalysisResult,
  targetSelectors: Set<string>,
): Set<string> {
  const result = new Set<string>();

  // Walk all blocks and look for PUSH4 matching known selectors
  // (external calls are made by pushing the 4-byte selector onto the stack)
  for (const [funcSel, entryBlock] of evm.cfg.selectorToBlock) {
    const visited = new Set<number>();
    const queue = [entryBlock];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const block = evm.cfg.blocks.get(id);
      if (!block) continue;
      for (const inst of block.instructions) {
        if (inst.opcode === 0x63 && inst.operand !== undefined) { // PUSH4
          const selHex = "0x" + inst.operand.toString(16).padStart(8, "0");
          if (targetSelectors.has(selHex)) {
            result.add(funcSel);
          }
        }
      }
      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }
  }
  return result;
}

function checkForTwapPattern(evm: EVMAnalysisResult, entryBlock: number): boolean {
  if (entryBlock < 0) return false;
  // TWAP pattern: TIMESTAMP opcode used in same function path
  // (indicates time-based calculation)
  const visited = new Set<number>();
  const queue = [entryBlock];
  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;
    for (const inst of block.instructions) {
      if (inst.opcode === 0x42) return true; // TIMESTAMP — indicates time-awareness
    }
    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }
  return false;
}

function analyzeChainlinkValidation(
  evm: EVMAnalysisResult,
  entryBlock: number,
): { hasTimestampRead: boolean; hasTimestampComparison: boolean; hasRoundIdCheck: boolean } {
  let hasTimestampRead = false;
  let hasTimestampComparison = false;
  let hasRoundIdCheck = false;

  const visited = new Set<number>();
  const queue = [entryBlock];
  let prevWasTimestamp = false;

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    for (const inst of block.instructions) {
      if (inst.opcode === 0x42) { // TIMESTAMP
        hasTimestampRead = true;
        prevWasTimestamp = true;
      }
      // GT or LT after TIMESTAMP → staleness comparison
      if (prevWasTimestamp && (inst.opcode === 0x10 || inst.opcode === 0x11)) {
        hasTimestampComparison = true;
      }
      if (inst.opcode !== 0x42 && inst.opcode !== 0x80) { // not TIMESTAMP or DUP1
        prevWasTimestamp = false;
      }
      // RETURNDATASIZE > 1 (checking that roundId == answeredInRound pattern)
      // Approximation: if there are 2+ SUB operations after RETURNDATALOAD path, likely roundId check
      if (inst.opcode === 0x03) { // SUB — often used in roundId difference check
        hasRoundIdCheck = true;
      }
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }
  return { hasTimestampRead, hasTimestampComparison, hasRoundIdCheck };
}

function detectMinPatternInAnyFunction(evm: EVMAnalysisResult): boolean {
  // Detect min(a, b) pattern: GT + ISZERO + conditional swap, or explicit LT-based min
  for (const block of evm.cfg.blocks.values()) {
    const insts = block.instructions;
    for (let i = 0; i < insts.length - 2; i++) {
      if (
        (insts[i].opcode === 0x10 || insts[i].opcode === 0x11) && // LT or GT
        insts[i + 1].opcode === 0x57 // JUMPI — conditional branch for min/max
      ) {
        return true;
      }
    }
  }
  return false;
}

function detectUnboundedOracleResult(evm: EVMAnalysisResult): string[] {
  const vulnerable: string[] = [];

  for (const [sel, entryBlock] of evm.cfg.selectorToBlock) {
    const visited = new Set<number>();
    const queue = [entryBlock];
    let hasExternalCall = false;
    let hasArithmeticOnReturn = false;
    let hasBoundsCheck = false;

    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const block = evm.cfg.blocks.get(id);
      if (!block) continue;

      for (let i = 0; i < block.instructions.length; i++) {
        const op = block.instructions[i].opcode;
        if (op === 0xf1 || op === 0xfa) hasExternalCall = true; // CALL, STATICCALL
        if (hasExternalCall && (op === 0x04 || op === 0x02)) hasArithmeticOnReturn = true;
        if (op === 0x10 || op === 0x11) hasBoundsCheck = true; // LT or GT
      }

      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }

    if (hasExternalCall && hasArithmeticOnReturn && !hasBoundsCheck) {
      vulnerable.push(sel);
    }
  }
  return vulnerable;
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
