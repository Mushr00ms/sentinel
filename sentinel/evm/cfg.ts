/**
 * EVM Control Flow Graph Builder
 *
 * Splits disassembled instructions into basic blocks, resolves jump targets,
 * detects the function dispatcher pattern, and computes reachability.
 */

import type { EVMInstruction, DisassemblyResult } from "./disassembler.js";
import { operandToBigInt, pushSize } from "./disassembler.js";

// ─── Types ────────────────────────────────────────────────────────────────

export interface BasicBlock {
  id: number;
  startOffset: number;
  endOffset: number; // inclusive last byte of last instruction
  instructions: EVMInstruction[];
  /** Successor block IDs. */
  successors: number[];
  /** Predecessor block IDs. */
  predecessors: number[];
  /** If the block ends with a terminator (STOP, RETURN, REVERT, INVALID, SELFDESTRUCT). */
  isTerminal: boolean;
  /** 4-byte selector if this block is a dispatcher branch. */
  dispatchSelector?: string;
}

export interface ControlFlowGraph {
  blocks: Map<number, BasicBlock>;
  /** Map from bytecode offset to block ID containing that offset. */
  offsetToBlock: Map<number, number>;
  /** Function selectors mapped to their entry block IDs. */
  selectorToBlock: Map<string, number>;
  /** Entry block ID (offset 0). */
  entryBlockId: number;
  /** Reachable block IDs from entry via BFS. */
  reachableBlocks: Set<number>;
}

// ─── Terminators ──────────────────────────────────────────────────────────

const TERMINATORS = new Set([
  0x00, // STOP
  0xf3, // RETURN
  0xfd, // REVERT
  0xfe, // INVALID
  0xff, // SELFDESTRUCT
]);

const JUMP_OPCODES = new Set([0x56, 0x57]); // JUMP, JUMPI

// ─── CFG Builder ──────────────────────────────────────────────────────────

export function buildCFG(disasm: DisassemblyResult): ControlFlowGraph {
  const { instructions, jumpDests } = disasm;
  if (instructions.length === 0) {
    const emptyBlock: BasicBlock = {
      id: 0, startOffset: 0, endOffset: 0,
      instructions: [], successors: [], predecessors: [],
      isTerminal: true,
    };
    return {
      blocks: new Map([[0, emptyBlock]]),
      offsetToBlock: new Map(),
      selectorToBlock: new Map(),
      entryBlockId: 0,
      reachableBlocks: new Set([0]),
    };
  }

  // Step 1: Identify block boundaries
  const blockStarts = new Set<number>([0]); // offset 0 always starts a block
  for (const inst of instructions) {
    if (inst.opcode === 0x5b) { // JUMPDEST
      blockStarts.add(inst.offset);
    }
    if (TERMINATORS.has(inst.opcode) || JUMP_OPCODES.has(inst.opcode)) {
      // The instruction after a terminator/jump starts a new block
      const nextOffset = inst.offset + inst.size;
      if (nextOffset < disasm.bytecodeBytes.length) {
        blockStarts.add(nextOffset);
      }
    }
  }

  // Step 2: Build basic blocks
  const sortedStarts = [...blockStarts].sort((a, b) => a - b);
  const blocks = new Map<number, BasicBlock>();
  const offsetToBlock = new Map<number, number>();
  let blockId = 0;

  for (let si = 0; si < sortedStarts.length; si++) {
    const startOffset = sortedStarts[si];
    const nextStart = si + 1 < sortedStarts.length ? sortedStarts[si + 1] : Infinity;

    const blockInstructions = instructions.filter(
      inst => inst.offset >= startOffset && inst.offset < nextStart,
    );

    if (blockInstructions.length === 0) continue;

    const lastInst = blockInstructions[blockInstructions.length - 1];
    const endOffset = lastInst.offset + lastInst.size - 1;

    const block: BasicBlock = {
      id: blockId,
      startOffset,
      endOffset,
      instructions: blockInstructions,
      successors: [],
      predecessors: [],
      isTerminal: TERMINATORS.has(lastInst.opcode),
    };

    blocks.set(blockId, block);
    for (const inst of blockInstructions) {
      offsetToBlock.set(inst.offset, blockId);
    }

    blockId++;
  }

  // Step 3: Resolve edges
  for (const [, block] of blocks) {
    const lastInst = block.instructions[block.instructions.length - 1];

    if (TERMINATORS.has(lastInst.opcode)) {
      continue; // No successors
    }

    if (lastInst.opcode === 0x56) {
      // JUMP — target from preceding PUSH
      const target = resolvePushJumpTarget(block.instructions);
      if (target !== null && jumpDests.has(target)) {
        const targetBlockId = offsetToBlock.get(target);
        if (targetBlockId !== undefined) {
          block.successors.push(targetBlockId);
        }
      }
    } else if (lastInst.opcode === 0x57) {
      // JUMPI — conditional: fall-through + target
      const target = resolvePushJumpTarget(block.instructions);
      if (target !== null && jumpDests.has(target)) {
        const targetBlockId = offsetToBlock.get(target);
        if (targetBlockId !== undefined) {
          block.successors.push(targetBlockId);
        }
      }
      // Fall-through
      const fallThrough = lastInst.offset + lastInst.size;
      const ftBlockId = offsetToBlock.get(fallThrough);
      if (ftBlockId !== undefined) {
        block.successors.push(ftBlockId);
      }
    } else {
      // Normal fall-through
      const nextOffset = lastInst.offset + lastInst.size;
      const nextBlockId = offsetToBlock.get(nextOffset);
      if (nextBlockId !== undefined) {
        block.successors.push(nextBlockId);
      }
    }
  }

  // Set predecessors
  for (const [, block] of blocks) {
    for (const succId of block.successors) {
      const succ = blocks.get(succId);
      if (succ && !succ.predecessors.includes(block.id)) {
        succ.predecessors.push(block.id);
      }
    }
  }

  // Step 4: Detect function dispatcher
  const selectorToBlock = detectDispatcher(blocks, offsetToBlock, jumpDests);

  // Step 5: BFS reachability from entry block
  const entryBlockId = offsetToBlock.get(0) ?? 0;
  const reachableBlocks = bfsReachable(blocks, entryBlockId);

  return { blocks, offsetToBlock, selectorToBlock, entryBlockId, reachableBlocks };
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * Resolves the jump target from a PUSH+JUMP pattern at the end of a block.
 */
function resolvePushJumpTarget(instructions: EVMInstruction[]): number | null {
  if (instructions.length < 2) return null;
  const jumpInst = instructions[instructions.length - 1];
  if (jumpInst.opcode !== 0x56 && jumpInst.opcode !== 0x57) return null;

  // Walk backwards to find the PUSH that feeds the JUMP
  const pushInst = instructions[instructions.length - 2];
  if (pushInst.opcode >= 0x5f && pushInst.opcode <= 0x7f) {
    const val = operandToBigInt(pushInst.operand);
    if (val !== null && val >= 0n && val < 0x100000n) {
      return Number(val);
    }
    if (pushInst.opcode === 0x5f) return 0; // PUSH0
  }
  return null;
}

/**
 * Detects the standard function dispatcher pattern:
 *   CALLDATALOAD(0) → SHR(224) → DUP → PUSH4(selector) → EQ → PUSH → JUMPI
 *
 * Returns a map from 4-byte selector strings to block IDs.
 */
function detectDispatcher(
  blocks: Map<number, BasicBlock>,
  offsetToBlock: Map<number, number>,
  jumpDests: Set<number>,
): Map<string, number> {
  const selectorToBlock = new Map<string, number>();

  for (const [, block] of blocks) {
    const insts = block.instructions;

    // Look for EQ + PUSH + JUMPI pattern within blocks
    for (let i = 0; i < insts.length - 2; i++) {
      const inst = insts[i];

      // Pattern: PUSH4(selector) ... EQ ... PUSH(target) ... JUMPI
      if (inst.opcode === 0x63 && inst.operand) { // PUSH4
        const selector = "0x" + Array.from(inst.operand)
          .map(b => b.toString(16).padStart(2, "0"))
          .join("");

        // Look for JUMPI after this PUSH4
        for (let j = i + 1; j < Math.min(i + 6, insts.length); j++) {
          if (insts[j].opcode === 0x57) { // JUMPI
            // Target is the PUSH before EQ or before JUMPI
            const target = resolvePushJumpTarget(insts.slice(0, j + 1));
            if (target !== null && jumpDests.has(target)) {
              const targetBlockId = offsetToBlock.get(target);
              if (targetBlockId !== undefined) {
                selectorToBlock.set(selector, targetBlockId);
              }
            }
            break;
          }
        }
      }
    }
  }

  return selectorToBlock;
}

/**
 * BFS from entryBlockId. Returns all reachable block IDs.
 */
function bfsReachable(blocks: Map<number, BasicBlock>, entryBlockId: number): Set<number> {
  const visited = new Set<number>();
  const queue = [entryBlockId];
  visited.add(entryBlockId);

  while (queue.length > 0) {
    const current = queue.shift()!;
    const block = blocks.get(current);
    if (!block) continue;

    for (const succ of block.successors) {
      if (!visited.has(succ)) {
        visited.add(succ);
        queue.push(succ);
      }
    }
  }

  return visited;
}

/**
 * Topological sort of blocks (reverse post-order).
 * Falls back to block-ID order if cycles exist (limited by iteration cap).
 */
export function topologicalOrder(cfg: ControlFlowGraph): number[] {
  const visited = new Set<number>();
  const order: number[] = [];

  function dfs(id: number, depth: number): void {
    if (visited.has(id) || depth > 1000) return;
    visited.add(id);
    const block = cfg.blocks.get(id);
    if (!block) return;
    for (const succ of block.successors) {
      dfs(succ, depth + 1);
    }
    order.push(id);
  }

  dfs(cfg.entryBlockId, 0);
  // Also visit selector entry blocks
  for (const [, blockId] of cfg.selectorToBlock) {
    dfs(blockId, 0);
  }

  return order.reverse();
}
