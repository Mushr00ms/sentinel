/**
 * Fee-on-Transfer Detector
 *
 * Detects when transferFrom/safeTransferFrom calls assume the received
 * amount equals the sent amount, without using balanceOf before/after pattern.
 */

import type { EVMAnalysisResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";
import { operandToBigInt } from "../evm/disassembler.js";

// Known selectors
const TRANSFER_FROM_SEL = 0x23b872ddn;    // transferFrom(address,address,uint256)
const SAFE_TRANSFER_FROM_SEL = 0x42842e0en; // safeTransferFrom(address,address,uint256)
const BALANCE_OF_SEL = 0x70a08231n;         // balanceOf(address)

export function detectFeeOnTransfer(evm: EVMAnalysisResult): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];

  // Build block-to-selector map
  const blockToSelector = new Map<number, string>();
  for (const [selector, blockId] of evm.cfg.selectorToBlock) {
    const visited = new Set<number>();
    const queue = [blockId];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      if (!blockToSelector.has(id)) blockToSelector.set(id, selector);
      const block = evm.cfg.blocks.get(id);
      if (block) for (const s of block.successors) if (!visited.has(s)) queue.push(s);
    }
  }

  // Find functions with transferFrom but no balanceOf before+after pattern
  for (const [selector, entryBlock] of evm.cfg.selectorToBlock) {
    let hasTransferFrom = false;
    let balanceOfCount = 0;

    // BFS through function's blocks
    const visited = new Set<number>();
    const queue = [entryBlock];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const block = evm.cfg.blocks.get(id);
      if (!block) continue;

      for (const inst of block.instructions) {
        if (inst.opcode === 0x63 && inst.operand) { // PUSH4
          const val = operandToBigInt(inst.operand);
          if (val === TRANSFER_FROM_SEL || val === SAFE_TRANSFER_FROM_SEL) {
            hasTransferFrom = true;
          }
          if (val === BALANCE_OF_SEL) {
            balanceOfCount++;
          }
        }
      }

      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }

    // If transferFrom is used but balanceOf is not called 2+ times (before+after),
    // the function assumes amount == received
    if (hasTransferFrom && balanceOfCount < 2) {
      findings.push({
        riskClass: "fee_on_transfer" as any,
        severity: "medium",
        functionSelector: selector as `0x${string}`,
        description:
          "Fee-on-transfer vulnerability: transferFrom used without balanceOf before/after check. " +
          "If a fee-on-transfer token is used, the contract will account for more tokens than received.",
        confidence: 60,
      });
    }
  }

  return findings;
}
