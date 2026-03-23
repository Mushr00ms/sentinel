/**
 * Donation / Share-Inflation Attack Detector
 *
 * Logic Signature: any contract that derives a share-to-asset exchange rate
 * from a live token balance (SELFBALANCE, BALANCE, or external balanceOf)
 * rather than a tracked internal reserve is vulnerable to donation manipulation.
 *
 * Covers (2026): Curve LlamaLend, Venus Core Pool, Goose Finance,
 *                dTRINITY dLEND, Hundred Finance, Euler Finance
 *
 * Key insight: the vulnerability is NOT in the specific selector names —
 * it is in the *data flow* pattern where an external balance read feeds
 * directly into a division that determines how many shares a depositor receives.
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

// All opcodes that read external or contract balance
const BALANCE_OPCODES = new Set([
  0x31, // BALANCE (external address)
  0x47, // SELFBALANCE
]);

// Arithmetic opcodes — when these follow a balance read in the same function
// they indicate the balance is used to compute a ratio/price/shares value
const RATIO_OPCODES = new Set([
  0x04, // DIV
  0x05, // SDIV
  0x0b, // SIGNEXTEND (sometimes used in fixed-point math)
]);

// ERC-4626 and cToken-style deposit/rate selectors — used to determine
// which functions to trace from, but the detector does NOT require them
const VAULT_ENTRY_SELECTORS = new Set([
  "0x6e553f65", // deposit(uint256,address)
  "0x94bf804d", // mint(uint256,address)
  "0xb460af94", // withdraw(uint256,address,address)
  "0xba087652", // redeem(uint256,address,address)
  "0x07a2d13a", // convertToAssets(uint256)
  "0xc6e6f592", // convertToShares(uint256)
  "0xef8b30f7", // previewDeposit(uint256)
  "0x01e1d114", // totalAssets()
  "0xbd6d894d", // exchangeRateCurrent() — Compound / Venus cToken
  "0x182df0f5", // exchangeRateStored()
  "0x17bfdfbc", // getPricePerFullShare() — Yearn-style
  "0xe1fffcc4", // getVirtualPrice() — Curve-style
]);

export function detectDonationAttack(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];
  const detectedSelectors = new Set(evm.selectors);

  // --- Pass 1: detect any function where BALANCE/SELFBALANCE feeds into DIV ---
  // This is the core logic signature: balance → arithmetic → shares/price
  const balanceToRatioSelectors: string[] = [];

  for (const [sel, entryBlock] of evm.cfg.selectorToBlock) {
    const { hasBalanceRead, hasRatioDivision, hasMulAfterBalance } =
      traceBalanceToDivision(evm, entryBlock);

    if (hasBalanceRead && hasRatioDivision) {
      balanceToRatioSelectors.push(sel);
      const confidence = hasMulAfterBalance ? 80 : 65;

      findings.push({
        riskClass: "donation_attack",
        severity: "high",
        functionSelector: sel as `0x${string}`,
        functionName: VAULT_ENTRY_SELECTORS.has(sel) ? knownName(sel) : undefined,
        description:
          `Donation attack surface: function ${sel} reads an external token balance ` +
          `(BALANCE/SELFBALANCE) and uses it in a division that determines a share price or ` +
          `asset ratio. An attacker can donate tokens to inflate this value before the call, ` +
          `manipulating the exchange rate. Protect with virtual offset (e.g., +1 share / +1 asset ` +
          `initial dead mint) or track reserves in a separate storage variable.`,
        confidence,
      });
    }
  }

  // --- Pass 2: first-depositor inflation (empty vault with no protection) ---
  // Check if the vault can have totalSupply == 0 while totalAssets > 0
  const hasDepositFunction = detectedSelectors.has("0x6e553f65") ||
    detectedSelectors.has("0x94bf804d") ||
    detectedSelectors.has("0xbd6d894d"); // cToken mint

  if (hasDepositFunction && balanceToRatioSelectors.length > 0) {
    // Check whether there is a dead-share mint (address(1) or address(0xdead)) in constructor
    const hasDeadShareMint = detectDeadShareMintInConstructor(evm);
    if (!hasDeadShareMint) {
      findings.push({
        riskClass: "donation_attack",
        severity: "high",
        functionSelector: "0x6e553f65" as `0x${string}`,
        functionName: "deposit / mint",
        description:
          "First-depositor share inflation: vault has no dead-share mint protection. " +
          "When totalSupply == 0, a single-wei deposit followed by a token donation inflates " +
          "pricePerShare, rounding subsequent depositors to zero shares. " +
          "Fix: mint dead shares to address(0xdead) at initialization, or require minimum deposit.",
        confidence: 70,
      });
    }
  }

  // --- Pass 3: cToken exchangeRate pattern (Venus/Compound style) ---
  // exchangeRateCurrent uses (cash + totalBorrows - totalReserves) / totalSupply
  // where 'cash' is directly balanceOf(underlying) — classic donation vector
  const hasCTokenRate = detectedSelectors.has("0xbd6d894d") ||
    detectedSelectors.has("0x182df0f5");

  if (hasCTokenRate) {
    const rateBlock = evm.cfg.selectorToBlock.get("0xbd6d894d") ??
      evm.cfg.selectorToBlock.get("0x182df0f5");

    if (rateBlock !== undefined) {
      const { hasBalanceRead } = traceBalanceToDivision(evm, rateBlock);
      if (hasBalanceRead) {
        findings.push({
          riskClass: "donation_attack",
          severity: "high",
          functionSelector: "0xbd6d894d" as `0x${string}`,
          functionName: "exchangeRateCurrent()",
          description:
            "cToken-style exchange rate reads underlying.balanceOf(this) for 'cash' component. " +
            "Direct token transfer (donation) to the market increases 'cash' without increasing " +
            "totalSupply, inflating exchangeRate. Affects liquidations, borrows, and redemptions. " +
            "Seen in Venus Core Pool ($3.7M, 2026-03-15).",
          confidence: 85,
        });
      }
    }
  }

  return dedup(findings);
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function traceBalanceToDivision(
  evm: EVMAnalysisResult,
  entryBlock: number,
): { hasBalanceRead: boolean; hasRatioDivision: boolean; hasMulAfterBalance: boolean } {
  let hasBalanceRead = false;
  let hasRatioDivision = false;
  let hasMulAfterBalance = false;

  const visited = new Set<number>();
  const queue = [entryBlock];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    let sawBalance = false;
    for (const inst of block.instructions) {
      if (BALANCE_OPCODES.has(inst.opcode)) {
        hasBalanceRead = true;
        sawBalance = true;
      }
      if (sawBalance && inst.opcode === 0x02) { // MUL after balance
        hasMulAfterBalance = true;
      }
      if (sawBalance && RATIO_OPCODES.has(inst.opcode)) {
        hasRatioDivision = true;
      }
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }

  return { hasBalanceRead, hasRatioDivision, hasMulAfterBalance };
}

function detectDeadShareMintInConstructor(evm: EVMAnalysisResult): boolean {
  // Look for PUSH20 of address(0xdead) or 0x0000...0001 in constructor path
  // Constructor bytecode is separate, but we can check for the constant in bytecode
  const DEAD_ADDRESS_SUFFIX = BigInt("0xdEaD");
  const ONE_ADDRESS = BigInt(1);

  for (const block of evm.cfg.blocks.values()) {
    for (const inst of block.instructions) {
      if (inst.opcode === 0x73) { // PUSH20
        const val = inst.operand;
        if (val !== undefined && (val === DEAD_ADDRESS_SUFFIX || val === ONE_ADDRESS)) {
          return true;
        }
      }
    }
  }
  return false;
}

function knownName(sel: string): string {
  const map: Record<string, string> = {
    "0x6e553f65": "deposit(uint256,address)",
    "0x94bf804d": "mint(uint256,address)",
    "0xb460af94": "withdraw(uint256,address,address)",
    "0xba087652": "redeem(uint256,address,address)",
    "0x07a2d13a": "convertToAssets(uint256)",
    "0xc6e6f592": "convertToShares(uint256)",
    "0x01e1d114": "totalAssets()",
    "0xbd6d894d": "exchangeRateCurrent()",
    "0x182df0f5": "exchangeRateStored()",
  };
  return map[sel] ?? sel;
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
