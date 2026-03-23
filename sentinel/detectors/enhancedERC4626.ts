/**
 * Enhanced ERC-4626 / First Depositor Detector
 *
 * Beyond basic share-inflation: detects donation attack surface,
 * missing min-deposit guard, missing dead-share mint, and rounding
 * direction inconsistency.
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";
import { operandToBigInt } from "../evm/disassembler.js";

// ERC-4626 selectors
const SELECTORS = {
  deposit:          0x6e553f65n, // deposit(uint256,address)
  mint:             0x94bf804dn, // mint(uint256,address)
  withdraw:         0xb460af94n, // withdraw(uint256,address,address)
  redeem:           0xba087652n, // redeem(uint256,address,address)
  totalAssets:      0x01e1d114n, // totalAssets()
  totalSupply:      0x18160dddn, // totalSupply()
  convertToShares:  0xc6e6f592n, // convertToShares(uint256)
  convertToAssets:  0x07a2d13an, // convertToAssets(uint256)
  previewDeposit:   0xef8b30f7n, // previewDeposit(uint256)
  previewMint:      0xb3d7f6b9n, // previewMint(uint256)
  previewWithdraw:  0x0a28a477n, // previewWithdraw(uint256)
  previewRedeem:    0x4cdad506n, // previewRedeem(uint256)
  maxDeposit:       0x402d267dn, // maxDeposit(address)
};

// Fix the typo in totalSupply
const TOTAL_SUPPLY_SEL = 0x18160dddn;

export function detectEnhancedERC4626(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];

  // Check if this is an ERC-4626 vault
  const detectedSelectors = new Set(evm.selectors);
  const hasConvertToAssets = detectedSelectors.has("0x07a2d13a");
  const hasDeposit = detectedSelectors.has("0x6e553f65");
  const hasTotalAssets = detectedSelectors.has("0x01e1d114");

  if (!hasConvertToAssets && !hasDeposit) return findings; // Not ERC-4626

  // Check 1: Donation attack surface
  // If totalAssets reads from SELFBALANCE/BALANCE rather than internal accounting
  if (hasTotalAssets) {
    let usesSelfBalance = false;
    const totalAssetsBlock = evm.cfg.selectorToBlock.get("0x01e1d114");
    if (totalAssetsBlock !== undefined) {
      const visited = new Set<number>();
      const queue = [totalAssetsBlock];
      while (queue.length > 0) {
        const id = queue.shift()!;
        if (visited.has(id)) continue;
        visited.add(id);
        const block = evm.cfg.blocks.get(id);
        if (!block) continue;
        for (const inst of block.instructions) {
          if (inst.opcode === 0x47 || inst.opcode === 0x31) { // SELFBALANCE or BALANCE
            usesSelfBalance = true;
          }
        }
        for (const succ of block.successors) {
          if (!visited.has(succ)) queue.push(succ);
        }
      }
    }
    if (usesSelfBalance) {
      findings.push({
        riskClass: "erc4626_inflation",
        severity: "high",
        functionSelector: "0x01e1d114" as `0x${string}`,
        functionName: "totalAssets()",
        description:
          "ERC-4626 donation attack: totalAssets() reads contract balance directly (SELFBALANCE/BALANCE). " +
          "An attacker can donate tokens/ETH to inflate totalAssets, manipulating share-to-asset ratio.",
        confidence: 75,
      });
    }
  }

  // Check 2: Missing min-deposit guard
  // Look for a minimum amount check in deposit function
  if (hasDeposit) {
    const depositBlock = evm.cfg.selectorToBlock.get("0x6e553f65");
    if (depositBlock !== undefined) {
      let hasMinCheck = false;
      const visited = new Set<number>();
      const queue = [depositBlock];
      while (queue.length > 0) {
        const id = queue.shift()!;
        if (visited.has(id)) continue;
        visited.add(id);
        const block = evm.cfg.blocks.get(id);
        if (!block) continue;
        for (let i = 0; i < block.instructions.length - 1; i++) {
          // Look for GT/LT comparison followed by JUMPI (require pattern)
          if (
            (block.instructions[i].opcode === 0x11 || block.instructions[i].opcode === 0x10) && // GT or LT
            block.instructions[i + 1]?.opcode === 0x57 // JUMPI
          ) {
            hasMinCheck = true;
          }
        }
        for (const succ of block.successors) {
          if (!visited.has(succ)) queue.push(succ);
        }
      }

      if (!hasMinCheck) {
        findings.push({
          riskClass: "erc4626_inflation",
          severity: "medium",
          functionSelector: "0x6e553f65" as `0x${string}`,
          functionName: "deposit(uint256,address)",
          description:
            "Missing minimum deposit guard: deposit() has no apparent minimum amount check. " +
            "First depositor can be attacked via share inflation if no dead shares are minted.",
          confidence: 55,
        });
      }
    }
  }

  // Check 3: Missing dead-share mint
  // In constructors/initializers, look for MINT to dead address pattern
  // This is hard to detect purely from bytecode, so we check for
  // the _mint call with address(1) or similar pattern
  // For now, flag if there's a deposit function without apparent initializer protection
  if (hasDeposit && !storage.hasInitializerGuard) {
    findings.push({
      riskClass: "erc4626_inflation",
      severity: "low",
      functionSelector: "0x6e553f65" as `0x${string}`,
      functionName: "deposit(uint256,address)",
      description:
        "No initializer guard detected in ERC-4626 vault. " +
        "Consider minting dead shares during initialization to prevent first-depositor attacks.",
      confidence: 40,
    });
  }

  // Check 4: Rounding direction inconsistency
  // Check if both deposit and withdraw use the same DIV direction
  // deposit should round DOWN (fewer shares), withdraw should round UP (more assets needed)
  const hasWithdraw = detectedSelectors.has("0xb460af94");
  if (hasDeposit && hasWithdraw) {
    const depositDivCount = countDivInFunction(evm, "0x6e553f65");
    const withdrawDivCount = countDivInFunction(evm, "0xb460af94");

    // If both have divisions, check for potential inconsistency
    if (depositDivCount > 0 && withdrawDivCount > 0) {
      // Heuristic: if deposit uses MUL before DIV and withdraw also uses MUL before DIV,
      // the rounding might be in the wrong direction for one of them
      findings.push({
        riskClass: "erc4626_inflation",
        severity: "low",
        functionSelector: "0x00000000" as `0x${string}`,
        description:
          "ERC-4626 rounding direction: both deposit and withdraw contain division operations. " +
          "Verify that deposit rounds in favor of the vault (down for shares) and withdraw " +
          "rounds in favor of the vault (up for assets).",
        confidence: 35,
      });
    }
  }

  return findings;
}

function countDivInFunction(evm: EVMAnalysisResult, selector: string): number {
  const entryBlock = evm.cfg.selectorToBlock.get(selector);
  if (entryBlock === undefined) return 0;

  let count = 0;
  const visited = new Set<number>();
  const queue = [entryBlock];
  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;
    for (const inst of block.instructions) {
      if (inst.opcode === 0x04 || inst.opcode === 0x05) count++; // DIV or SDIV
    }
    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }
  return count;
}
