/**
 * Unchecked Return Value Detector
 *
 * After CALL/STATICCALL/DELEGATECALL, checks if the success boolean
 * is consumed by ISZERO+JUMPI or POPped/ignored. Higher severity for
 * value-transferring calls.
 */

import type { EVMAnalysisResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

const CALL_OPCODES = new Set([0xf1, 0xf2, 0xf4, 0xfa]); // CALL, CALLCODE, DELEGATECALL, STATICCALL

export function detectUncheckedReturnValues(evm: EVMAnalysisResult): StaticAnalysisFinding[] {
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
      if (!CALL_OPCODES.has(insts[i].opcode)) continue;

      const callOpcode = insts[i].opcode;
      const isValueTransfer = callOpcode === 0xf1 || callOpcode === 0xf2; // CALL or CALLCODE have value param

      // Check the instruction(s) after the CALL
      const nextInst = i + 1 < insts.length ? insts[i + 1] : null;

      let returnChecked = false;

      if (nextInst) {
        // Good patterns: ISZERO (for revert on failure) or direct JUMPI check
        if (nextInst.opcode === 0x15) { // ISZERO
          returnChecked = true;
        } else if (nextInst.opcode === 0x57) { // JUMPI — checking success directly
          returnChecked = true;
        } else if (nextInst.opcode === 0x80) { // DUP1 — likely saving for later check
          returnChecked = true;
        } else if (nextInst.opcode === 0x50) { // POP — explicitly discarding!
          returnChecked = false;
        } else if (nextInst.opcode === 0x90) { // SWAP1 — might be used later
          // Check if ISZERO follows within next 3 instructions
          for (let j = i + 2; j < Math.min(i + 5, insts.length); j++) {
            if (insts[j].opcode === 0x15 || insts[j].opcode === 0x57) {
              returnChecked = true;
              break;
            }
          }
        } else {
          // If the next instruction is something that consumes the success value
          // for a comparison, it's checked
          if ([0x14, 0x15, 0x10, 0x11].includes(nextInst.opcode)) { // EQ, ISZERO, LT, GT
            returnChecked = true;
          }
        }
      }

      // If block ends with the CALL (i.e., next instruction is in successor block)
      if (!nextInst && block.successors.length > 0) {
        // Check successor block's first instruction
        for (const succId of block.successors) {
          const succBlock = evm.cfg.blocks.get(succId);
          if (succBlock && succBlock.instructions.length > 0) {
            const firstSuccInst = succBlock.instructions[0];
            if (firstSuccInst.opcode === 0x5b) { // JUMPDEST — skip it
              const second = succBlock.instructions[1];
              if (second && (second.opcode === 0x15 || second.opcode === 0x57)) {
                returnChecked = true;
              }
            } else if (firstSuccInst.opcode === 0x15 || firstSuccInst.opcode === 0x57) {
              returnChecked = true;
            }
          }
        }
      }

      if (!returnChecked) {
        const callName = callOpcode === 0xf4 ? "DELEGATECALL" :
          callOpcode === 0xfa ? "STATICCALL" :
          callOpcode === 0xf2 ? "CALLCODE" : "CALL";
        const selector = blockToSelector.get(blockId);

        findings.push({
          riskClass: "unchecked_return_value" as any,
          severity: isValueTransfer ? "high" : "medium",
          functionSelector: (selector ?? "0x00000000") as `0x${string}`,
          description:
            `Unchecked ${callName} return value at offset ${insts[i].offset}. ` +
            `The success boolean is not checked after the external call.` +
            (isValueTransfer ? " This is a value-transferring call, increasing severity." : ""),
          confidence: 70,
        });
      }
    }
  }

  return dedup(findings);
}

function dedup(findings: StaticAnalysisFinding[]): StaticAnalysisFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.riskClass}:${f.functionSelector}:${f.description.slice(0, 60)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
