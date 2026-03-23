/**
 * Value Flow Tracer
 *
 * Traces ETH and token value movements through the contract, identifies
 * unconditional drains, and maps transfers to containing functions.
 */

import type { ControlFlowGraph, BasicBlock } from "./cfg.js";
import type { AbstractState, AbstractValue } from "./abstractStack.js";
import { isUserControlled, isCallerDependent } from "./abstractStack.js";
import type { EVMInstruction } from "./disassembler.js";
import { operandToBigInt } from "./disassembler.js";

// ─── Types ────────────────────────────────────────────────────────────────

export type TransferKind = "eth_send" | "erc20_transfer" | "erc20_transferFrom" | "erc20_approve";

export interface ValueTransfer {
  kind: TransferKind;
  /** Bytecode offset of the CALL instruction. */
  offset: number;
  /** Block ID containing the transfer. */
  blockId: number;
  /** Function selector context (if known). */
  selector?: string;
  /** Whether the transfer value/amount is user-controlled. */
  amountUserControlled: boolean;
  /** Whether the transfer target is user-controlled. */
  targetUserControlled: boolean;
  /** Whether there's a CALLER/ORIGIN check on the path to this transfer. */
  hasCallerCheck: boolean;
}

export interface UnconditionalDrain {
  /** The value transfer that constitutes the drain. */
  transfer: ValueTransfer;
  /** Reason this is flagged as unconditional. */
  reason: string;
  /** Severity 0-100. */
  severity: number;
}

export interface ValueFlowGraph {
  transfers: ValueTransfer[];
  drains: UnconditionalDrain[];
  /** Number of ETH-sending calls. */
  ethSendCount: number;
  /** Number of token operations. */
  tokenOpCount: number;
}

// ─── Known ERC-20 Selectors ──────────────────────────────────────────────

const ERC20_TRANSFER = 0xa9059cbbn;     // transfer(address,uint256)
const ERC20_TRANSFER_FROM = 0x23b872ddn; // transferFrom(address,address,uint256)
const ERC20_APPROVE = 0x095ea7b3n;       // approve(address,uint256)

// Full 4-byte selectors
const TOKEN_SELECTORS: Map<bigint, TransferKind> = new Map([
  [ERC20_TRANSFER, "erc20_transfer"],
  [ERC20_TRANSFER_FROM, "erc20_transferFrom"],
  [ERC20_APPROVE, "erc20_approve"],
]);

// ─── Value Flow Tracer ───────────────────────────────────────────────────

export function traceValueFlows(
  cfg: ControlFlowGraph,
  abstractStates: Map<number, AbstractState>,
): ValueFlowGraph {
  const transfers: ValueTransfer[] = [];

  // Build selector lookup
  const blockToSelector = new Map<number, string>();
  for (const [selector, blockId] of cfg.selectorToBlock) {
    propagateSelector(cfg, blockId, selector, blockToSelector);
  }

  // Build caller-check blocks: blocks where CALLER or ORIGIN is compared (EQ opcode)
  const callerCheckBlocks = findCallerCheckBlocks(cfg, abstractStates);

  // Scan all reachable blocks for value-transferring instructions
  for (const blockId of cfg.reachableBlocks) {
    const block = cfg.blocks.get(blockId);
    const state = abstractStates.get(blockId);
    if (!block || !state) continue;

    for (const inst of block.instructions) {
      const snapshot = state.stackSnapshots.get(inst.offset);
      if (!snapshot) continue;

      // Check for CALL with non-zero value (ETH send)
      if (inst.opcode === 0xf1 && snapshot.length >= 7) { // CALL
        const value = snapshot[snapshot.length - 3]; // stack position for value
        const addr = snapshot[snapshot.length - 2];  // stack position for address
        const isNonZeroValue = value.kind !== "concrete" || (value.value !== undefined && value.value !== 0n);

        if (isNonZeroValue) {
          const hasCallerCheck = pathHasCallerCheck(cfg, blockId, callerCheckBlocks);
          transfers.push({
            kind: "eth_send",
            offset: inst.offset,
            blockId,
            selector: blockToSelector.get(blockId),
            amountUserControlled: isUserControlled(value),
            targetUserControlled: isUserControlled(addr),
            hasCallerCheck,
          });
        }

        // Check calldata for ERC-20 selector
        checkTokenCall(inst, snapshot, blockId, blockToSelector, callerCheckBlocks, cfg, transfers);
      }

      // STATICCALL doesn't transfer value but might be reading token state
      // DELEGATECALL inherits value context — skip for now
    }
  }

  // Identify unconditional drains
  const drains = findUnconditionalDrains(transfers);

  return {
    transfers,
    drains,
    ethSendCount: transfers.filter(t => t.kind === "eth_send").length,
    tokenOpCount: transfers.filter(t => t.kind !== "eth_send").length,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function propagateSelector(
  cfg: ControlFlowGraph,
  startBlock: number,
  selector: string,
  blockToSelector: Map<number, string>,
): void {
  const visited = new Set<number>();
  const queue = [startBlock];
  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    if (!blockToSelector.has(id)) {
      blockToSelector.set(id, selector);
    }
    const block = cfg.blocks.get(id);
    if (block) {
      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }
  }
}

/**
 * Finds blocks that contain a CALLER or ORIGIN followed by EQ comparison.
 */
function findCallerCheckBlocks(
  cfg: ControlFlowGraph,
  abstractStates: Map<number, AbstractState>,
): Set<number> {
  const result = new Set<number>();

  for (const blockId of cfg.reachableBlocks) {
    const block = cfg.blocks.get(blockId);
    const state = abstractStates.get(blockId);
    if (!block || !state) continue;

    for (const inst of block.instructions) {
      if (inst.opcode === 0x14) { // EQ
        const snapshot = state.stackSnapshots.get(inst.offset);
        if (snapshot && snapshot.length >= 2) {
          const a = snapshot[snapshot.length - 1];
          const b = snapshot[snapshot.length - 2];
          if (isCallerDependent(a) || isCallerDependent(b)) {
            result.add(blockId);
          }
        }
      }
    }
  }

  return result;
}

/**
 * Checks if any block on the path from entry to `targetBlock` contains
 * a caller check (CALLER/ORIGIN + EQ).
 */
function pathHasCallerCheck(
  cfg: ControlFlowGraph,
  targetBlock: number,
  callerCheckBlocks: Set<number>,
): boolean {
  // BFS backwards from target to entry
  const visited = new Set<number>();
  const queue = [targetBlock];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);

    if (callerCheckBlocks.has(id)) return true;

    const block = cfg.blocks.get(id);
    if (block) {
      for (const pred of block.predecessors) {
        if (!visited.has(pred)) queue.push(pred);
      }
    }
  }

  return false;
}

function checkTokenCall(
  inst: EVMInstruction,
  snapshot: AbstractValue[],
  blockId: number,
  blockToSelector: Map<number, string>,
  callerCheckBlocks: Set<number>,
  cfg: ControlFlowGraph,
  transfers: ValueTransfer[],
): void {
  // For CALL: check if the calldata starts with a known ERC-20 selector
  // The calldata is loaded via MSTORE before the CALL, so we check for
  // preceding PUSH4 of known selectors
  const block = cfg.blocks.get(blockId);
  if (!block) return;

  const instIdx = block.instructions.indexOf(inst);
  // Look backwards for PUSH4 that could be a selector
  for (let i = Math.max(0, instIdx - 10); i < instIdx; i++) {
    const prevInst = block.instructions[i];
    if (prevInst.opcode === 0x63 && prevInst.operand) { // PUSH4
      const selVal = operandToBigInt(prevInst.operand);
      if (selVal !== null) {
        const kind = TOKEN_SELECTORS.get(selVal);
        if (kind) {
          const hasCallerCheck = pathHasCallerCheck(cfg, blockId, callerCheckBlocks);
          transfers.push({
            kind,
            offset: inst.offset,
            blockId,
            selector: blockToSelector.get(blockId),
            amountUserControlled: true, // conservative
            targetUserControlled: kind === "erc20_transfer" || kind === "erc20_approve",
            hasCallerCheck,
          });
        }
      }
    }
  }
}

function findUnconditionalDrains(transfers: ValueTransfer[]): UnconditionalDrain[] {
  const drains: UnconditionalDrain[] = [];

  for (const t of transfers) {
    // Unconditional drain: outflow without caller/origin check
    if (!t.hasCallerCheck) {
      if (t.kind === "eth_send") {
        drains.push({
          transfer: t,
          reason: "ETH send reachable without CALLER/ORIGIN comparison on path",
          severity: t.targetUserControlled ? 90 : 70,
        });
      } else if (t.kind === "erc20_transfer" || t.kind === "erc20_transferFrom") {
        drains.push({
          transfer: t,
          reason: `Token ${t.kind} reachable without CALLER/ORIGIN comparison on path`,
          severity: t.targetUserControlled ? 85 : 65,
        });
      } else if (t.kind === "erc20_approve") {
        drains.push({
          transfer: t,
          reason: "Token approve reachable without CALLER/ORIGIN comparison on path",
          severity: 80,
        });
      }
    }
  }

  return drains;
}
