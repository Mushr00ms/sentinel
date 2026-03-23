/**
 * EVM Taint Analysis Engine
 *
 * Tracks flow of user-controlled data from sources (CALLDATALOAD, CALLVALUE,
 * CALLER, ORIGIN, etc.) to security-sensitive sinks (CALL targets, SSTORE
 * values, SELFDESTRUCT beneficiaries, etc.).
 */

import type { ControlFlowGraph, BasicBlock } from "./cfg.js";
import type { AbstractState, AbstractValue } from "./abstractStack.js";
import { isUserControlled } from "./abstractStack.js";
import type { EVMInstruction } from "./disassembler.js";

// ─── Types ────────────────────────────────────────────────────────────────

export type TaintSource =
  | "CALLDATALOAD"
  | "CALLVALUE"
  | "CALLER"
  | "ORIGIN"
  | "RETURNDATALOAD"
  | "BALANCE"
  | "TIMESTAMP"
  | "GASPRICE";

export type TaintSink =
  | "CALL_ADDRESS"
  | "CALL_VALUE"
  | "DELEGATECALL_TARGET"
  | "SSTORE_SLOT"
  | "SSTORE_VALUE"
  | "CREATE_VALUE"
  | "CREATE2_SALT"
  | "SELFDESTRUCT_BENEFICIARY";

export interface TaintFlow {
  source: TaintSource;
  sink: TaintSink;
  /** Bytecode offset of the source instruction. */
  sourceOffset: number;
  /** Bytecode offset of the sink instruction. */
  sinkOffset: number;
  /** Block IDs on the path from source to sink. */
  pathBlockIds: number[];
  /** Confidence score 0-100. */
  confidence: number;
  /** The function selector context (if known). */
  selector?: string;
}

export interface TaintAnalysisResult {
  flows: TaintFlow[];
  /** Summary counts by sink type. */
  sinkCounts: Record<string, number>;
  /** Whether any high-severity flow was found. */
  hasHighSeverityFlow: boolean;
}

// ─── Source/Sink Mapping ──────────────────────────────────────────────────

function abstractKindToSource(kind: string): TaintSource | null {
  const map: Record<string, TaintSource> = {
    calldataload: "CALLDATALOAD",
    callvalue: "CALLVALUE",
    caller: "CALLER",
    origin: "ORIGIN",
    returndataload: "RETURNDATALOAD",
    balance: "BALANCE",
    timestamp: "TIMESTAMP",
    gasprice: "GASPRICE",
  };
  return map[kind] ?? null;
}

/**
 * Gets the taint sources from an abstract value (recursive).
 */
function getTaintSources(val: AbstractValue): TaintSource[] {
  const direct = abstractKindToSource(val.kind);
  if (direct) return [direct];
  if (val.kind === "op" && val.sources) {
    return val.sources.flatMap(getTaintSources);
  }
  return [];
}

// ─── Taint Analysis ───────────────────────────────────────────────────────

/**
 * Runs taint analysis over the CFG using pre-computed abstract states.
 */
export function runTaintAnalysis(
  cfg: ControlFlowGraph,
  abstractStates: Map<number, AbstractState>,
): TaintAnalysisResult {
  const flows: TaintFlow[] = [];
  const sinkCounts: Record<string, number> = {};

  // Build selector lookup: blockId -> selector
  const blockToSelector = new Map<number, string>();
  for (const [selector, blockId] of cfg.selectorToBlock) {
    blockToSelector.set(blockId, selector);
    // Propagate to reachable blocks from this function entry
    const visited = new Set<number>();
    const queue = [blockId];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      blockToSelector.set(id, selector);
      const block = cfg.blocks.get(id);
      if (block) {
        for (const succ of block.successors) {
          if (!visited.has(succ)) queue.push(succ);
        }
      }
    }
  }

  // Scan each reachable block for sink instructions
  for (const blockId of cfg.reachableBlocks) {
    const block = cfg.blocks.get(blockId);
    const state = abstractStates.get(blockId);
    if (!block || !state) continue;

    for (const inst of block.instructions) {
      const snapshot = state.stackSnapshots.get(inst.offset);
      if (!snapshot) continue;

      const sinkChecks = getSinkChecks(inst, snapshot);
      for (const { sink, value, confidence: baseConf } of sinkChecks) {
        if (!isUserControlled(value)) continue;

        const sources = getTaintSources(value);
        for (const source of sources) {
          const flow: TaintFlow = {
            source,
            sink,
            sourceOffset: -1, // approximate — we don't track precise source offset
            sinkOffset: inst.offset,
            pathBlockIds: [blockId],
            confidence: baseConf,
            selector: blockToSelector.get(blockId),
          };
          flows.push(flow);
          sinkCounts[sink] = (sinkCounts[sink] ?? 0) + 1;
        }
      }
    }
  }

  // Deduplicate flows with same source+sink+selector
  const deduped = deduplicateFlows(flows);

  const highSeveritySinks = new Set<TaintSink>([
    "CALL_ADDRESS", "DELEGATECALL_TARGET", "SELFDESTRUCT_BENEFICIARY",
    "CALL_VALUE", "CREATE_VALUE",
  ]);
  const hasHighSeverityFlow = deduped.some(f => highSeveritySinks.has(f.sink));

  return { flows: deduped, sinkCounts, hasHighSeverityFlow };
}

// ─── Sink Detection ───────────────────────────────────────────────────────

interface SinkCheck {
  sink: TaintSink;
  value: AbstractValue;
  confidence: number;
}

function getSinkChecks(inst: EVMInstruction, stack: AbstractValue[]): SinkCheck[] {
  const checks: SinkCheck[] = [];
  const len = stack.length;

  switch (inst.opcode) {
    case 0xf1: // CALL: gas, addr, value, inOffset, inSize, outOffset, outSize
      if (len >= 7) {
        checks.push({ sink: "CALL_ADDRESS", value: stack[len - 2], confidence: 85 });
        checks.push({ sink: "CALL_VALUE", value: stack[len - 3], confidence: 80 });
      }
      break;

    case 0xf4: // DELEGATECALL: gas, addr, inOffset, inSize, outOffset, outSize
      if (len >= 6) {
        checks.push({ sink: "DELEGATECALL_TARGET", value: stack[len - 2], confidence: 90 });
      }
      break;

    case 0xf2: // CALLCODE: gas, addr, value, inOffset, inSize, outOffset, outSize
      if (len >= 7) {
        checks.push({ sink: "CALL_ADDRESS", value: stack[len - 2], confidence: 85 });
        checks.push({ sink: "CALL_VALUE", value: stack[len - 3], confidence: 80 });
      }
      break;

    case 0xfa: // STATICCALL: gas, addr, inOffset, inSize, outOffset, outSize
      if (len >= 6) {
        checks.push({ sink: "CALL_ADDRESS", value: stack[len - 2], confidence: 60 });
      }
      break;

    case 0x55: // SSTORE: slot, value
      if (len >= 2) {
        checks.push({ sink: "SSTORE_SLOT", value: stack[len - 1], confidence: 75 });
        checks.push({ sink: "SSTORE_VALUE", value: stack[len - 2], confidence: 70 });
      }
      break;

    case 0xf0: // CREATE: value, offset, size
      if (len >= 3) {
        checks.push({ sink: "CREATE_VALUE", value: stack[len - 1], confidence: 80 });
      }
      break;

    case 0xf5: // CREATE2: value, offset, size, salt
      if (len >= 4) {
        checks.push({ sink: "CREATE_VALUE", value: stack[len - 1], confidence: 80 });
        checks.push({ sink: "CREATE2_SALT", value: stack[len - 4], confidence: 70 });
      }
      break;

    case 0xff: // SELFDESTRUCT: addr
      if (len >= 1) {
        checks.push({ sink: "SELFDESTRUCT_BENEFICIARY", value: stack[len - 1], confidence: 95 });
      }
      break;
  }

  return checks;
}

function deduplicateFlows(flows: TaintFlow[]): TaintFlow[] {
  const seen = new Map<string, TaintFlow>();
  for (const f of flows) {
    const key = `${f.source}:${f.sink}:${f.selector ?? "none"}`;
    const existing = seen.get(key);
    if (!existing || f.confidence > existing.confidence) {
      seen.set(key, f);
    }
  }
  return Array.from(seen.values());
}
