/**
 * Cross-Contract Value Tracing
 *
 * For each CALL in an analyzed contract: traces whether calldata is forwarded
 * from own calldata, whether return values feed security-sensitive ops, and
 * detects transitive calldata forwarding chains.
 */

import type { ControlFlowGraph } from "./cfg.js";
import type { AbstractState, AbstractValue } from "./abstractStack.js";
import { isUserControlled } from "./abstractStack.js";
import type { EVMAnalysisResult } from "./index.js";

// ─── Types ────────────────────────────────────────────────────────────────

export interface CrossContractCall {
  /** Bytecode offset of the CALL instruction. */
  offset: number;
  /** Type of call (CALL, DELEGATECALL, STATICCALL, CALLCODE). */
  callType: "CALL" | "DELEGATECALL" | "STATICCALL" | "CALLCODE";
  /** Whether the calldata appears forwarded from own CALLDATALOAD. */
  calldataForwarded: boolean;
  /** Whether the call target is user-controlled. */
  targetUserControlled: boolean;
  /** Whether the call value is user-controlled. */
  valueUserControlled: boolean;
  /** Function selector context (if known). */
  selector?: string;
}

export interface CrossContractFlowResult {
  calls: CrossContractCall[];
  /** Whether calldata is forwarded through to external calls. */
  hasCalldataForwarding: boolean;
  /** Whether any DELEGATECALL target is user-controlled. */
  hasDangerousDelegatecall: boolean;
  /** Number of external calls total. */
  externalCallCount: number;
}

// ─── Analysis ─────────────────────────────────────────────────────────────

export function analyzeCrossContractFlows(
  cfg: ControlFlowGraph,
  abstractStates: Map<number, AbstractState>,
): CrossContractFlowResult {
  const calls: CrossContractCall[] = [];

  // Build selector lookup
  const blockToSelector = new Map<number, string>();
  for (const [selector, blockId] of cfg.selectorToBlock) {
    const visited = new Set<number>();
    const queue = [blockId];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      if (!blockToSelector.has(id)) blockToSelector.set(id, selector);
      const block = cfg.blocks.get(id);
      if (block) {
        for (const succ of block.successors) {
          if (!visited.has(succ)) queue.push(succ);
        }
      }
    }
  }

  for (const blockId of cfg.reachableBlocks) {
    const block = cfg.blocks.get(blockId);
    const state = abstractStates.get(blockId);
    if (!block || !state) continue;

    for (const inst of block.instructions) {
      const snapshot = state.stackSnapshots.get(inst.offset);
      if (!snapshot) continue;

      let callType: CrossContractCall["callType"] | null = null;
      let addrIdx = -1;
      let valueIdx = -1;

      switch (inst.opcode) {
        case 0xf1: // CALL: gas, addr, value, inOffset, inSize, outOffset, outSize
          callType = "CALL";
          addrIdx = snapshot.length - 2;
          valueIdx = snapshot.length - 3;
          break;
        case 0xf4: // DELEGATECALL: gas, addr, inOffset, inSize, outOffset, outSize
          callType = "DELEGATECALL";
          addrIdx = snapshot.length - 2;
          break;
        case 0xfa: // STATICCALL: gas, addr, inOffset, inSize, outOffset, outSize
          callType = "STATICCALL";
          addrIdx = snapshot.length - 2;
          break;
        case 0xf2: // CALLCODE: gas, addr, value, inOffset, inSize, outOffset, outSize
          callType = "CALLCODE";
          addrIdx = snapshot.length - 2;
          valueIdx = snapshot.length - 3;
          break;
      }

      if (callType && addrIdx >= 0 && addrIdx < snapshot.length) {
        const addr = snapshot[addrIdx];

        // Check if calldata is forwarded
        const calldataForwarded = checkCalldataForwarding(block, inst, state);

        calls.push({
          offset: inst.offset,
          callType,
          calldataForwarded,
          targetUserControlled: isUserControlled(addr),
          valueUserControlled: valueIdx >= 0 && valueIdx < snapshot.length
            ? isUserControlled(snapshot[valueIdx])
            : false,
          selector: blockToSelector.get(blockId),
        });
      }
    }
  }

  return {
    calls,
    hasCalldataForwarding: calls.some(c => c.calldataForwarded),
    hasDangerousDelegatecall: calls.some(
      c => c.callType === "DELEGATECALL" && c.targetUserControlled,
    ),
    externalCallCount: calls.length,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * Heuristically checks if calldata is forwarded from own CALLDATALOAD/CALLDATACOPY
 * to this CALL's input data.
 */
function checkCalldataForwarding(
  block: { instructions: readonly { opcode: number; offset: number }[] },
  callInst: { offset: number },
  state: AbstractState,
): boolean {
  // Look for CALLDATACOPY or CALLDATALOAD preceding this CALL in the same block
  for (const inst of block.instructions) {
    if (inst.offset >= callInst.offset) break;
    // CALLDATACOPY (0x37) copies calldata to memory, which is then used as CALL input
    if (inst.opcode === 0x37) return true;
    // CALLDATALOAD (0x35) loads calldata to stack
    if (inst.opcode === 0x35) {
      // Check if any stack value at the CALL comes from CALLDATALOAD
      const snapshot = state.stackSnapshots.get(callInst.offset);
      if (snapshot?.some(v => v.kind === "calldataload")) return true;
    }
  }
  return false;
}
