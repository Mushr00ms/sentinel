/**
 * ERC-777 Hook Reentrancy Detector
 *
 * Detects token transfers without reentrancy guard + state updates after
 * transfer, which are vulnerable to ERC-777 tokensReceived hooks.
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";
import { operandToBigInt } from "../evm/disassembler.js";

// Known ERC-20 transfer selectors that can trigger ERC-777 hooks
const TRANSFER_SEL = 0xa9059cbbn;       // transfer(address,uint256)
const TRANSFER_FROM_SEL = 0x23b872ddn;  // transferFrom(address,address,uint256)

// Reentrancy guard patterns — slot commonly at a fixed low number
// OZ ReentrancyGuard uses _status at a specific slot

export function detectERC777Reentrancy(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
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

  for (const blockId of evm.cfg.reachableBlocks) {
    const block = evm.cfg.blocks.get(blockId);
    if (!block) continue;

    const insts = block.instructions;

    for (let i = 0; i < insts.length; i++) {
      // Look for CALL preceded by PUSH4(transfer/transferFrom selector)
      if (insts[i].opcode !== 0xf1) continue; // CALL only

      // Check if this call is a token transfer
      let isTokenTransfer = false;
      for (let j = Math.max(0, i - 10); j < i; j++) {
        if (insts[j].opcode === 0x63 && insts[j].operand) { // PUSH4
          const val = operandToBigInt(insts[j].operand);
          if (val === TRANSFER_SEL || val === TRANSFER_FROM_SEL) {
            isTokenTransfer = true;
          }
        }
      }

      if (!isTokenTransfer) continue;

      // Check if SSTORE follows this CALL (state update after transfer)
      let hasPostTransferStateUpdate = false;
      for (let j = i + 1; j < insts.length; j++) {
        if (insts[j].opcode === 0x55) { // SSTORE
          hasPostTransferStateUpdate = true;
          break;
        }
      }

      // Also check successor blocks
      if (!hasPostTransferStateUpdate) {
        for (const succId of block.successors) {
          const succBlock = evm.cfg.blocks.get(succId);
          if (succBlock) {
            for (const succInst of succBlock.instructions) {
              if (succInst.opcode === 0x55) {
                hasPostTransferStateUpdate = true;
                break;
              }
            }
          }
          if (hasPostTransferStateUpdate) break;
        }
      }

      if (!hasPostTransferStateUpdate) continue;

      // Check for reentrancy guard
      const hasReentrancyGuard = detectReentrancyGuard(evm, blockId);

      if (!hasReentrancyGuard) {
        const selector = blockToSelector.get(blockId);
        findings.push({
          riskClass: "reentrancy",
          severity: "high",
          functionSelector: (selector ?? "0x00000000") as `0x${string}`,
          description:
            "ERC-777 hook reentrancy: token transfer (transfer/transferFrom) followed by " +
            "state update (SSTORE) without reentrancy guard. If the token implements ERC-777 " +
            "tokensReceived hooks, an attacker can re-enter during the callback.",
          confidence: 65,
        });
      }
    }
  }

  return dedup(findings);
}

/**
 * Heuristic detection of reentrancy guard pattern:
 * SLOAD(guard_slot) → check → SSTORE(guard_slot, locked) → ... → SSTORE(guard_slot, unlocked)
 */
function detectReentrancyGuard(evm: EVMAnalysisResult, targetBlockId: number): boolean {
  // Walk backwards from the target block to find a guard pattern
  const visited = new Set<number>();
  const queue = [targetBlockId];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);

    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    const insts = block.instructions;

    // Look for SLOAD + ISZERO/EQ + JUMPI + SSTORE pattern (reentrancy guard check-and-lock)
    for (let i = 0; i < insts.length - 3; i++) {
      if (
        insts[i].opcode === 0x54 &&     // SLOAD
        (insts[i + 1]?.opcode === 0x15 || insts[i + 1]?.opcode === 0x14) && // ISZERO or EQ
        insts[i + 2]?.opcode === 0x57    // JUMPI (revert if locked)
      ) {
        // Check if there's a matching SSTORE nearby (setting the lock)
        for (let j = i + 3; j < Math.min(i + 8, insts.length); j++) {
          if (insts[j].opcode === 0x55) return true; // SSTORE — this is a reentrancy guard
        }
      }
    }

    for (const pred of block.predecessors) {
      if (!visited.has(pred)) queue.push(pred);
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
