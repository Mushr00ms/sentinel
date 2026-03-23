/**
 * Precision Loss Detector
 *
 * Detects division-before-multiplication patterns in the abstract stack,
 * which can lead to precision loss. Higher severity when the result feeds
 * into token amounts or ETH value transfers.
 */

import type { EVMAnalysisResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

export function detectPrecisionLoss(evm: EVMAnalysisResult): StaticAnalysisFinding[] {
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
    const state = evm.abstractStates.get(blockId);
    if (!block || !state) continue;

    for (const inst of block.instructions) {
      if (inst.opcode !== 0x02) continue; // MUL

      const snapshot = state.stackSnapshots.get(inst.offset);
      if (!snapshot || snapshot.length < 2) continue;

      // Check if either operand of MUL is the result of a DIV
      const a = snapshot[snapshot.length - 1];
      const b = snapshot[snapshot.length - 2];

      const divInA = hasDivAncestor(a);
      const divInB = hasDivAncestor(b);

      if (divInA || divInB) {
        // Check if this feeds into a value transfer (higher severity)
        const feedsTransfer = evm.valueFlow.transfers.some(
          t => t.blockId === blockId,
        );

        const selector = blockToSelector.get(blockId);
        findings.push({
          riskClass: "precision_loss" as any,
          severity: feedsTransfer ? "high" : "medium",
          functionSelector: (selector ?? "0x00000000") as `0x${string}`,
          description:
            "Division-before-multiplication pattern detected. The result of a division is used " +
            "as an operand to multiplication, causing precision loss due to integer truncation." +
            (feedsTransfer ? " This value feeds into a token/ETH transfer." : ""),
          confidence: feedsTransfer ? 75 : 55,
        });
      }
    }
  }

  return dedup(findings);
}

function hasDivAncestor(val: { kind: string; opcode?: number; sources?: any[] }, depth = 0): boolean {
  if (depth > 5) return false;
  if (val.kind === "op" && val.opcode === 0x04) return true; // DIV
  if (val.kind === "op" && val.opcode === 0x05) return true; // SDIV
  if (val.kind === "op" && val.sources) {
    return val.sources.some((s: any) => hasDivAncestor(s, depth + 1));
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
