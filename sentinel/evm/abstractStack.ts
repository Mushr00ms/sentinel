/**
 * Abstract Stack Tracker
 *
 * Tracks abstract values through EVM stack operations to determine
 * the semantic origin of values at each instruction.
 */

import type { BasicBlock, ControlFlowGraph } from "./cfg.js";
import { topologicalOrder } from "./cfg.js";
import type { EVMInstruction } from "./disassembler.js";
import { STACK_EFFECTS, operandToBigInt, pushSize } from "./disassembler.js";

// ─── Abstract Value Types ─────────────────────────────────────────────────

export type AbstractValueKind =
  | "concrete"
  | "calldataload"
  | "callvalue"
  | "caller"
  | "origin"
  | "sload"
  | "mload"
  | "returndataload"
  | "balance"
  | "timestamp"
  | "gasprice"
  | "op"
  | "unknown";

export interface AbstractValue {
  kind: AbstractValueKind;
  /** For concrete: the value. For sload: the slot. For calldataload: the offset. */
  value?: bigint;
  /** For op: the opcode that produced this value. */
  opcode?: number;
  /** Source abstract values (operands) that produced this value via an op. */
  sources?: AbstractValue[];
}

export interface AbstractState {
  /** Stack at block entry. */
  entryStack: AbstractValue[];
  /** Stack at block exit. */
  exitStack: AbstractValue[];
  /** Per-instruction snapshots: stack BEFORE executing that instruction. */
  stackSnapshots: Map<number, AbstractValue[]>; // offset -> stack
}

// ─── Constructors ─────────────────────────────────────────────────────────

function concreteVal(v: bigint): AbstractValue {
  return { kind: "concrete", value: v };
}

function unknownVal(): AbstractValue {
  return { kind: "unknown" };
}

function sourceVal(kind: AbstractValueKind, value?: bigint): AbstractValue {
  return { kind, value };
}

function opVal(opcode: number, sources: AbstractValue[]): AbstractValue {
  return { kind: "op", opcode, sources };
}

// ─── Abstract Interpretation ──────────────────────────────────────────────

/**
 * Computes abstract stack states for all reachable blocks in the CFG.
 * Uses forward dataflow in topological order with fixpoint iteration.
 */
export function computeAbstractStates(
  cfg: ControlFlowGraph,
): Map<number, AbstractState> {
  const states = new Map<number, AbstractState>();
  const order = topologicalOrder(cfg);
  const MAX_ITERATIONS = 3;
  const MAX_STACK_DEPTH = 64;

  for (let iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
    let changed = false;

    for (const blockId of order) {
      if (!cfg.reachableBlocks.has(blockId)) continue;
      const block = cfg.blocks.get(blockId);
      if (!block) continue;

      // Merge entry stacks from predecessors
      let entryStack: AbstractValue[] = [];
      if (block.predecessors.length > 0) {
        const predStates = block.predecessors
          .map(pid => states.get(pid))
          .filter((s): s is AbstractState => s !== undefined);
        if (predStates.length > 0) {
          entryStack = mergeStacks(predStates.map(s => s.exitStack));
        }
      }

      // Simulate the block
      const { exitStack, stackSnapshots } = simulateBlock(block, entryStack, MAX_STACK_DEPTH);

      const existing = states.get(blockId);
      if (!existing || !stacksEqual(existing.exitStack, exitStack)) {
        changed = true;
      }

      states.set(blockId, { entryStack, exitStack, stackSnapshots });
    }

    if (!changed) break;
  }

  return states;
}

/**
 * Simulates execution of a single basic block, starting from the given stack.
 */
function simulateBlock(
  block: BasicBlock,
  initialStack: AbstractValue[],
  maxDepth: number,
): { exitStack: AbstractValue[]; stackSnapshots: Map<number, AbstractValue[]> } {
  let stack = [...initialStack];
  const snapshots = new Map<number, AbstractValue[]>();

  for (const inst of block.instructions) {
    // Save pre-execution stack snapshot
    snapshots.set(inst.offset, [...stack]);

    stack = executeInstruction(inst, stack, maxDepth);
  }

  return { exitStack: stack, stackSnapshots: snapshots };
}

/**
 * Executes a single instruction on the abstract stack.
 */
function executeInstruction(
  inst: EVMInstruction,
  stack: AbstractValue[],
  maxDepth: number,
): AbstractValue[] {
  const result = [...stack];
  const op = inst.opcode;

  // PUSH0-PUSH32
  if (op === 0x5f) {
    result.push(concreteVal(0n));
    return trimStack(result, maxDepth);
  }
  if (op >= 0x60 && op <= 0x7f) {
    const val = operandToBigInt(inst.operand);
    result.push(val !== null ? concreteVal(val) : unknownVal());
    return trimStack(result, maxDepth);
  }

  // DUP1-DUP16
  if (op >= 0x80 && op <= 0x8f) {
    const depth = op - 0x7f; // DUP1 = depth 1
    if (result.length >= depth) {
      result.push(result[result.length - depth]);
    } else {
      result.push(unknownVal());
    }
    return trimStack(result, maxDepth);
  }

  // SWAP1-SWAP16
  if (op >= 0x90 && op <= 0x9f) {
    const depth = op - 0x8f; // SWAP1 = depth 1
    const topIdx = result.length - 1;
    const swapIdx = result.length - 1 - depth;
    if (swapIdx >= 0) {
      [result[topIdx], result[swapIdx]] = [result[swapIdx], result[topIdx]];
    }
    return result;
  }

  // Source-producing instructions (taint sources)
  switch (op) {
    case 0x33: // CALLER
      result.push(sourceVal("caller"));
      return trimStack(result, maxDepth);
    case 0x32: // ORIGIN
      result.push(sourceVal("origin"));
      return trimStack(result, maxDepth);
    case 0x34: // CALLVALUE
      result.push(sourceVal("callvalue"));
      return trimStack(result, maxDepth);
    case 0x35: { // CALLDATALOAD
      const offset = result.length > 0 ? result.pop()! : unknownVal();
      result.push(sourceVal("calldataload", offset.kind === "concrete" ? offset.value : undefined));
      return trimStack(result, maxDepth);
    }
    case 0x54: { // SLOAD
      const slot = result.length > 0 ? result.pop()! : unknownVal();
      result.push(sourceVal("sload", slot.kind === "concrete" ? slot.value : undefined));
      return trimStack(result, maxDepth);
    }
    case 0x31: { // BALANCE
      if (result.length > 0) result.pop();
      result.push(sourceVal("balance"));
      return trimStack(result, maxDepth);
    }
    case 0x42: // TIMESTAMP
      result.push(sourceVal("timestamp"));
      return trimStack(result, maxDepth);
    case 0x3a: // GASPRICE
      result.push(sourceVal("gasprice"));
      return trimStack(result, maxDepth);
    case 0x3d: // RETURNDATASIZE
      result.push(sourceVal("returndataload"));
      return trimStack(result, maxDepth);
  }

  // Generic stack effect
  const effect = STACK_EFFECTS[op];
  if (effect) {
    const [pops, pushes] = effect;
    const popped: AbstractValue[] = [];
    for (let i = 0; i < pops; i++) {
      popped.push(result.length > 0 ? result.pop()! : unknownVal());
    }

    // For arithmetic ops, propagate as "op" values with source tracking
    const isArithmetic = op <= 0x0b || (op >= 0x10 && op <= 0x1d) || op === 0x20;
    for (let i = 0; i < pushes; i++) {
      if (isArithmetic && popped.length > 0) {
        result.push(opVal(op, popped));
      } else {
        result.push(unknownVal());
      }
    }
  } else {
    // Unknown opcode — conservatively push unknown
    result.push(unknownVal());
  }

  return trimStack(result, maxDepth);
}

// ─── Utilities ────────────────────────────────────────────────────────────

function trimStack(stack: AbstractValue[], maxDepth: number): AbstractValue[] {
  if (stack.length > maxDepth) {
    return stack.slice(stack.length - maxDepth);
  }
  return stack;
}

function mergeStacks(stacks: AbstractValue[][]): AbstractValue[] {
  if (stacks.length === 0) return [];
  if (stacks.length === 1) return [...stacks[0]];

  // Use the shortest stack length
  const minLen = Math.min(...stacks.map(s => s.length));
  const merged: AbstractValue[] = [];

  for (let i = 0; i < minLen; i++) {
    const vals = stacks.map(s => s[s.length - minLen + i]);
    if (vals.every(v => v.kind === vals[0].kind && v.value === vals[0].value)) {
      merged.push(vals[0]);
    } else {
      merged.push(unknownVal());
    }
  }

  return merged;
}

function stacksEqual(a: AbstractValue[], b: AbstractValue[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((v, i) => v.kind === b[i].kind && v.value === b[i].value);
}

/**
 * Checks if an abstract value originates from user-controlled input.
 */
export function isUserControlled(val: AbstractValue): boolean {
  switch (val.kind) {
    case "calldataload":
    case "callvalue":
    case "origin":
      return true;
    case "op":
      return val.sources?.some(isUserControlled) ?? false;
    default:
      return false;
  }
}

/**
 * Checks if an abstract value involves the caller/origin identity.
 */
export function isCallerDependent(val: AbstractValue): boolean {
  switch (val.kind) {
    case "caller":
    case "origin":
      return true;
    case "op":
      return val.sources?.some(isCallerDependent) ?? false;
    default:
      return false;
  }
}
