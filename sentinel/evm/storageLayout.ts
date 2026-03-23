/**
 * Storage Layout Analyzer
 *
 * Analyzes SLOAD/SSTORE patterns to determine storage slot usage,
 * semantic classification, and proxy storage collision detection.
 */

import type { ControlFlowGraph } from "./cfg.js";
import type { AbstractState, AbstractValue } from "./abstractStack.js";
import { isUserControlled } from "./abstractStack.js";
import type { TaintAnalysisResult } from "./taintAnalysis.js";

// ─── Types ────────────────────────────────────────────────────────────────

export type SlotClassification =
  | "eip1967_impl"     // 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
  | "eip1967_admin"    // 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
  | "eip1967_beacon"   // 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
  | "oz_ownable"       // slot 0 in many OZ contracts
  | "oz_initialized"   // slot typically at 0 or mapped
  | "mapping"          // keccak256(key . slot) pattern
  | "struct_member"    // slot + offset
  | "unknown";

export interface StorageSlotInfo {
  /** The slot value (concrete or symbolic description). */
  slot: bigint | "dynamic";
  /** Classification of this slot. */
  classification: SlotClassification;
  /** Function selectors that read (SLOAD) this slot. */
  readBy: string[];
  /** Function selectors that write (SSTORE) this slot. */
  writtenBy: string[];
  /** Whether the slot index is user-controlled. */
  slotUserControlled: boolean;
  /** Whether the value written is user-controlled. */
  valueUserControlled: boolean;
}

export interface StorageCollision {
  /** Description of the collision. */
  description: string;
  /** Slots involved. */
  slots: (bigint | string)[];
  /** Severity 0-100. */
  severity: number;
}

export interface StorageLayoutResult {
  slots: StorageSlotInfo[];
  collisions: StorageCollision[];
  /** Whether this looks like an upgradeable proxy. */
  isUpgradeableProxy: boolean;
  /** Whether initializer protection is detected. */
  hasInitializerGuard: boolean;
}

// ─── Known Slots ──────────────────────────────────────────────────────────

const EIP1967_IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbcn;
const EIP1967_ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103n;
const EIP1967_BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50n;
const OZ_INITIALIZED_SLOT = 0n; // Typically slot 0 for _initialized flag

const KNOWN_SLOTS: Map<bigint, SlotClassification> = new Map([
  [EIP1967_IMPL_SLOT, "eip1967_impl"],
  [EIP1967_ADMIN_SLOT, "eip1967_admin"],
  [EIP1967_BEACON_SLOT, "eip1967_beacon"],
]);

// ─── Storage Layout Analyzer ─────────────────────────────────────────────

export function analyzeStorageLayout(
  cfg: ControlFlowGraph,
  abstractStates: Map<number, AbstractState>,
  taint: TaintAnalysisResult,
): StorageLayoutResult {
  const slotMap = new Map<string, StorageSlotInfo>();

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

  // Walk all reachable blocks for SLOAD/SSTORE
  for (const blockId of cfg.reachableBlocks) {
    const block = cfg.blocks.get(blockId);
    const state = abstractStates.get(blockId);
    if (!block || !state) continue;

    const selector = blockToSelector.get(blockId) ?? "unknown";

    for (const inst of block.instructions) {
      const snapshot = state.stackSnapshots.get(inst.offset);
      if (!snapshot) continue;

      if (inst.opcode === 0x54 && snapshot.length >= 1) { // SLOAD
        const slotVal = snapshot[snapshot.length - 1];
        const key = slotKey(slotVal);
        const info = getOrCreateSlot(slotMap, key, slotVal);
        if (!info.readBy.includes(selector)) info.readBy.push(selector);
        if (isUserControlled(slotVal)) info.slotUserControlled = true;
      }

      if (inst.opcode === 0x55 && snapshot.length >= 2) { // SSTORE
        const slotVal = snapshot[snapshot.length - 1];
        const valueVal = snapshot[snapshot.length - 2];
        const key = slotKey(slotVal);
        const info = getOrCreateSlot(slotMap, key, slotVal);
        if (!info.writtenBy.includes(selector)) info.writtenBy.push(selector);
        if (isUserControlled(slotVal)) info.slotUserControlled = true;
        if (isUserControlled(valueVal)) info.valueUserControlled = true;
      }
    }
  }

  const slots = Array.from(slotMap.values());

  // Classify slots
  for (const slot of slots) {
    if (slot.slot !== "dynamic") {
      const known = KNOWN_SLOTS.get(slot.slot);
      if (known) {
        slot.classification = known;
      }
    }
  }

  // Detect proxy patterns
  const isUpgradeableProxy = slots.some(s => s.classification === "eip1967_impl");

  // Detect initializer guard (look for slot 0 read + JUMPI pattern)
  const hasInitializerGuard = detectInitializerGuard(cfg, abstractStates);

  // Detect storage collisions
  const collisions = detectCollisions(slots, isUpgradeableProxy);

  return { slots, collisions, isUpgradeableProxy, hasInitializerGuard };
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function slotKey(val: AbstractValue): string {
  if (val.kind === "concrete" && val.value !== undefined) {
    return val.value.toString(16);
  }
  if (val.kind === "op" && val.opcode === 0x20) { // SHA3 — mapping pattern
    return "mapping:" + (val.sources?.map(s => s.kind).join(",") ?? "unknown");
  }
  return "dynamic:" + val.kind;
}

function getOrCreateSlot(
  map: Map<string, StorageSlotInfo>,
  key: string,
  val: AbstractValue,
): StorageSlotInfo {
  let info = map.get(key);
  if (!info) {
    const slot = val.kind === "concrete" && val.value !== undefined ? val.value : "dynamic" as const;
    const classification = classifySlot(val);
    info = {
      slot,
      classification,
      readBy: [],
      writtenBy: [],
      slotUserControlled: false,
      valueUserControlled: false,
    };
    map.set(key, info);
  }
  return info;
}

function classifySlot(val: AbstractValue): SlotClassification {
  if (val.kind === "concrete" && val.value !== undefined) {
    const known = KNOWN_SLOTS.get(val.value);
    if (known) return known;
    if (val.value === 0n) return "oz_ownable"; // common pattern
    return "unknown";
  }
  if (val.kind === "op" && val.opcode === 0x20) { // SHA3
    return "mapping";
  }
  if (val.kind === "op" && val.opcode === 0x01) { // ADD — struct offset
    return "struct_member";
  }
  return "unknown";
}

function detectInitializerGuard(
  cfg: ControlFlowGraph,
  abstractStates: Map<number, AbstractState>,
): boolean {
  // Look for SLOAD(slot) + ISZERO + JUMPI pattern in early blocks
  for (const blockId of cfg.reachableBlocks) {
    const block = cfg.blocks.get(blockId);
    if (!block) continue;

    const insts = block.instructions;
    for (let i = 0; i < insts.length - 2; i++) {
      if (
        insts[i].opcode === 0x54 &&    // SLOAD
        insts[i + 1]?.opcode === 0x15 && // ISZERO
        insts[i + 2]?.opcode === 0x57    // JUMPI
      ) {
        return true;
      }
    }
  }
  return false;
}

function detectCollisions(
  slots: StorageSlotInfo[],
  isProxy: boolean,
): StorageCollision[] {
  const collisions: StorageCollision[] = [];

  if (!isProxy) return collisions;

  // Check for user-controlled slot writes (storage corruption risk)
  for (const slot of slots) {
    if (slot.slotUserControlled && slot.writtenBy.length > 0) {
      collisions.push({
        description: "User-controlled storage slot write detected in proxy contract — potential storage corruption",
        slots: [slot.slot === "dynamic" ? "dynamic" : slot.slot],
        severity: 90,
      });
    }
  }

  // Check for writes to low slots (0-10) in proxy without initializer guard
  const lowSlotWrites = slots.filter(
    s => s.slot !== "dynamic" && s.slot < 10n && s.writtenBy.length > 0,
  );
  if (lowSlotWrites.length > 0) {
    const hasEip1967 = slots.some(s => s.classification === "eip1967_impl");
    if (hasEip1967) {
      // Proxy writing to low slots may collide with implementation storage
      collisions.push({
        description: "Proxy contract writes to low storage slots that may collide with implementation storage",
        slots: lowSlotWrites.map(s => s.slot),
        severity: 70,
      });
    }
  }

  return collisions;
}
