/**
 * Read-Only Reentrancy Detector
 *
 * Finds CALL instructions followed by SSTORE in the same function, where
 * view functions SLOAD the same slots written after the CALL. This means
 * the view function returns stale data during the callback window.
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

export function detectReadOnlyReentrancy(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];

  // Find functions that have CALL followed by SSTORE
  const callThenStoreSelectors = new Map<string, Set<string>>(); // selector -> written slot keys

  for (const blockId of evm.cfg.reachableBlocks) {
    const block = evm.cfg.blocks.get(blockId);
    if (!block) continue;

    const insts = block.instructions;
    for (let i = 0; i < insts.length; i++) {
      const isCall = [0xf1, 0xf2, 0xf4, 0xfa].includes(insts[i].opcode);
      if (!isCall) continue;

      // Look for SSTORE after this CALL (in same block or successor blocks)
      for (let j = i + 1; j < insts.length; j++) {
        if (insts[j].opcode === 0x55) { // SSTORE
          // Find the selector for this block
          for (const [sel, entryBlock] of evm.cfg.selectorToBlock) {
            if (isBlockReachableFrom(evm, entryBlock, blockId)) {
              if (!callThenStoreSelectors.has(sel)) {
                callThenStoreSelectors.set(sel, new Set());
              }
              // Record the written slots
              for (const slot of storage.slots) {
                if (slot.writtenBy.includes(sel)) {
                  callThenStoreSelectors.get(sel)!.add(slotId(slot));
                }
              }
            }
          }
        }
      }
    }
  }

  // Find view functions that read the same slots
  for (const [writerSel, writtenSlots] of callThenStoreSelectors) {
    for (const slot of storage.slots) {
      const slotKey = slotId(slot);
      if (!writtenSlots.has(slotKey)) continue;

      for (const readerSel of slot.readBy) {
        if (readerSel === writerSel) continue; // same function

        findings.push({
          riskClass: "read_only_reentrancy" as any,
          severity: "high",
          functionSelector: readerSel as `0x${string}`,
          functionName: undefined,
          description:
            `Read-only reentrancy: function ${readerSel} reads a storage slot that is written ` +
            `by ${writerSel} AFTER an external call. During the callback window, ${readerSel} ` +
            `returns stale data (Curve-style read-only reentrancy).`,
          confidence: 65,
        });
      }
    }
  }

  return dedup(findings);
}

function slotId(slot: { slot: bigint | "dynamic" }): string {
  return slot.slot === "dynamic" ? "dynamic" : slot.slot.toString(16);
}

function isBlockReachableFrom(evm: EVMAnalysisResult, from: number, to: number): boolean {
  const visited = new Set<number>();
  const queue = [from];
  while (queue.length > 0) {
    const id = queue.shift()!;
    if (id === to) return true;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (block) {
      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }
  }
  return false;
}

function dedup(findings: StaticAnalysisFinding[]): StaticAnalysisFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.riskClass}:${f.functionSelector}:${f.description.slice(0, 80)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
