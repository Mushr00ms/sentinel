/**
 * Access Control Bypass Detector
 *
 * Covers two distinct 2026 exploit logic patterns:
 *
 * 1. Mutable-storage modifier bypass (Molt EVM, $127k, 2026-03-07)
 *    Logic Signature: an access control modifier that reads its authority
 *    address/role from a STORAGE SLOT that can be written by an
 *    insufficiently protected initializer or setter. If an attacker can
 *    write that storage slot before the guarded function is called,
 *    they become the authorized caller.
 *
 * 2. EIP-7702 EOA delegation bypass (Fusion by IPOR, $336k, 2026-01-06)
 *    Logic Signature: a security gate that uses EXTCODESIZE(msg.sender) == 0
 *    to assert "caller is a safe EOA". Under EIP-7702, EOAs can delegate
 *    to contract code without changing their address — extcodesize returns
 *    non-zero. Any contract using this pattern for security is bypassed.
 *
 * Key insight: neither of these requires specific function names or contract
 * types. Any contract with these opcode-level patterns is vulnerable.
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

export function detectAccessControlBypass(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];

  findings.push(...detectMutableModifier(evm, storage));
  findings.push(...detectEIP7702Bypass(evm));

  return dedup(findings);
}

// ─── Pattern 1: Mutable access control modifier ───────────────────────────
//
// Opcode-level signature:
//   SLOAD (load authority from storage)
//   CALLER
//   EQ          ← compare msg.sender to stored authority
//   ISZERO
//   JUMPI       ← revert if not authorized
//
// Vulnerability: if the SLOAD slot is also written by a publicly reachable
// SSTORE with insufficient protection, authority can be hijacked.

function detectMutableModifier(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];

  // Find slots that are both (a) used in a CALLER comparison and (b) writeable
  // by a function reachable without strict access control

  // Step 1: identify storage slots used in CALLER equality checks
  const authSlots = new Set<bigint>();

  for (const block of evm.cfg.blocks.values()) {
    const insts = block.instructions;
    for (let i = 0; i + 3 < insts.length; i++) {
      // Pattern: SLOAD ... CALLER ... EQ
      if (
        insts[i].opcode === 0x54 &&     // SLOAD
        insts[i + 1].opcode === 0x33 && // CALLER
        insts[i + 2].opcode === 0x14    // EQ
      ) {
        // The slot being SLOADed is the auth slot
        // We can't resolve the slot value statically in all cases,
        // but we flag the pattern
        authSlots.add(BigInt(i)); // use instruction offset as proxy
        break;
      }
    }
  }

  if (authSlots.size === 0) return findings;

  // Step 2: check if any function can SSTORE without first doing a CALLER+EQ check
  // i.e., there's a public or weakly-guarded setter for the auth slot
  const { hasPublicSetter } = detectPublicStorageSetter(evm);

  if (hasPublicSetter) {
    findings.push({
      riskClass: "access_control",
      severity: "critical",
      functionSelector: "0x00000000" as `0x${string}`,
      description:
        "Mutable access control modifier: the authority address used in access checks " +
        "(SLOAD → CALLER → EQ pattern) is stored in a slot that can be updated by a " +
        "function reachable without equivalent protection. " +
        "An attacker can set themselves as the authority before calling the protected function. " +
        "Fix: store auth addresses in immutable variables, or protect the setter with " +
        "the same or stronger modifier than what it controls. " +
        "Seen in Molt EVM onlySpawnerToken bypass ($127k, 2026-03-07).",
      confidence: 75,
    });
  }

  // Step 3: look for re-initializable pattern (initialize() callable more than once)
  const { isReinitializable } = detectReinitializablePattern(evm);
  if (isReinitializable) {
    findings.push({
      riskClass: "access_control",
      severity: "high",
      functionSelector: "0x8129fc1c" as `0x${string}`, // initialize()
      functionName: "initialize()",
      description:
        "Re-initializable contract: the initialize() function can be called multiple times " +
        "because the initialized flag is not checked or can be reset. " +
        "Combined with an access control modifier that reads from storage, " +
        "re-initialization allows authority takeover. " +
        "Fix: use OpenZeppelin Initializable._initialized guard.",
      confidence: 70,
    });
  }

  return findings;
}

// ─── Pattern 2: EIP-7702 EOA code-length check bypass ─────────────────────
//
// EIP-7702 (Prague hardfork) allows EOAs to delegate execution to a contract.
// After delegation, EXTCODESIZE(eoa_address) returns the code size of the
// delegate, not zero. Any require(msg.sender.code.length == 0) guard is bypassed.
//
// Opcode-level signature:
//   CALLER
//   EXTCODESIZE  ← check code size of msg.sender
//   ISZERO       ← require it's zero (== EOA check)
//   JUMPI        ← revert if has code

function detectEIP7702Bypass(evm: EVMAnalysisResult): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];

  for (const [sel, entryBlock] of evm.cfg.selectorToBlock) {
    const result = checkForEoaCodeLengthGate(evm, entryBlock);
    if (result.hasEoaCheck) {
      findings.push({
        riskClass: "eip7702_delegation",
        severity: "high",
        functionSelector: sel as `0x${string}`,
        description:
          `Function ${sel} uses EXTCODESIZE(msg.sender) == 0 as an EOA guard. ` +
          "Under EIP-7702 (active since Prague hardfork), EOAs can delegate code without " +
          "changing their address — extcodesize returns non-zero for delegated EOAs. " +
          "This check no longer reliably distinguishes EOAs from contracts. " +
          "Replace with tx.origin == msg.sender (weaker but EIP-7702-aware), or redesign " +
          "the guard to not rely on code-length heuristics. " +
          "Seen in Fusion by IPOR EIP-7702 exploit ($336k, 2026-01-06).",
        confidence: result.isInRequire ? 90 : 65,
      });
    }
  }

  return findings;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function detectPublicStorageSetter(evm: EVMAnalysisResult): { hasPublicSetter: boolean } {
  // A "public setter" pattern: function reachable from a selector that
  // does SSTORE without a CALLER+SLOAD+EQ guard preceding it
  let hasPublicSetter = false;

  for (const [, entryBlock] of evm.cfg.selectorToBlock) {
    let hasCallerCheck = false;
    let hasUncheckedStore = false;

    const visited = new Set<number>();
    const queue = [entryBlock];

    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const block = evm.cfg.blocks.get(id);
      if (!block) continue;

      for (let i = 0; i + 2 < block.instructions.length; i++) {
        if (
          block.instructions[i].opcode === 0x33 &&    // CALLER
          block.instructions[i + 1].opcode === 0x14   // EQ
        ) {
          hasCallerCheck = true;
        }
        if (block.instructions[i].opcode === 0x55 && !hasCallerCheck) { // SSTORE without prior check
          hasUncheckedStore = true;
        }
      }

      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }

    if (hasUncheckedStore) {
      hasPublicSetter = true;
      break;
    }
  }

  return { hasPublicSetter };
}

function detectReinitializablePattern(evm: EVMAnalysisResult): { isReinitializable: boolean } {
  // initialize() selector = 0x8129fc1c
  // Re-initializable if: no SLOAD+ISZERO+JUMPI guard at the top of initialize()
  const initSel = "0x8129fc1c";
  const entryBlock = evm.cfg.selectorToBlock.get(initSel);
  if (entryBlock === undefined) return { isReinitializable: false };

  let hasInitGuard = false;
  const firstBlock = evm.cfg.blocks.get(entryBlock);
  if (!firstBlock) return { isReinitializable: false };

  // Check first 10 instructions for the initialized guard pattern
  const insts = firstBlock.instructions.slice(0, 15);
  for (let i = 0; i + 2 < insts.length; i++) {
    if (
      insts[i].opcode === 0x54 &&     // SLOAD (load initialized flag)
      insts[i + 1].opcode === 0x15 && // ISZERO (check it's false)
      insts[i + 2].opcode === 0x57    // JUMPI (revert if already initialized)
    ) {
      hasInitGuard = true;
    }
  }

  return { isReinitializable: !hasInitGuard };
}

function checkForEoaCodeLengthGate(
  evm: EVMAnalysisResult,
  entryBlock: number,
): { hasEoaCheck: boolean; isInRequire: boolean } {
  const visited = new Set<number>();
  const queue = [entryBlock];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    const insts = block.instructions;
    for (let i = 0; i + 2 < insts.length; i++) {
      // Pattern: CALLER → EXTCODESIZE → ISZERO
      if (
        insts[i].opcode === 0x33 &&     // CALLER
        insts[i + 1].opcode === 0x3b && // EXTCODESIZE
        insts[i + 2].opcode === 0x15    // ISZERO
      ) {
        const isInRequire = insts[i + 3]?.opcode === 0x57; // JUMPI
        return { hasEoaCheck: true, isInRequire };
      }
      // Also catch: EXTCODESIZE of msg.sender without CALLER first
      // (e.g., PUSH20 address or loaded from calldata)
      if (insts[i].opcode === 0x3b && insts[i + 1].opcode === 0x15) {
        const isInRequire = insts[i + 2]?.opcode === 0x57;
        return { hasEoaCheck: true, isInRequire };
      }
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }
  return { hasEoaCheck: false, isInRequire: false };
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
