/**
 * ZK Verifier Bypass Detector
 *
 * Logic Signature: any on-chain ZK proof verifier that uses BN256 pairing
 * precompiles may be misconfigured if (a) the verification key is hardcoded
 * and doesn't match the proving circuit, (b) public inputs are not
 * range-checked, or (c) the verifier contract is a deployed standard
 * (Groth16/Plonk) without proof-of-correct-setup.
 *
 * Covers (2026): Veil Cash misconfigured Groth16 verifier ($5k, 2026-02-21)
 *                FOOM Cash fake proof spam (see also crossChainSpoofing)
 *
 * Key insight: a ZK verifier written in Solidity that calls BN256 precompiles
 * is structurally identical across all implementations — Groth16 always calls
 * precompile 0x06 (EC add), 0x07 (EC mul), and 0x08 (pairing check).
 * The vulnerability is in WHAT the verifier checks, not HOW it calls precompiles.
 *
 * Three logic failures this detector identifies:
 *   A. Missing range check on public inputs (any field element > BN256 field order
 *      should fail but passes if unchecked)
 *   B. Missing nullifier/used-proof store (allows proof replay)
 *   C. Hardcoded verification key that may not match the circuit
 *      (heuristic: VK constants in bytecode with no corresponding deployment event)
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

// BN256 elliptic curve precompile addresses
const BN256_ADD      = 0x06n;
const BN256_SCALAR   = 0x07n;
const BN256_PAIRING  = 0x08n;

// BN256 field order (used to detect if range checks are present)
// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
const BN256_FIELD_ORDER =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

export function detectZkVerifierBypass(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];

  // Step 1: Determine if this is a ZK verifier at all
  const verifierInfo = detectZkVerifier(evm);
  if (!verifierInfo.isVerifier) return findings;

  const { usesAdd, usesMul, usesPairing, pairing_call_selectors } = verifierInfo;

  // Step 2: Check for public input range validation
  if (!verifierInfo.hasBn256FieldOrderCheck) {
    findings.push({
      riskClass: "zk_verifier_bypass",
      severity: "high",
      functionSelector: pairing_call_selectors[0] as `0x${string}` ?? "0x00000000" as `0x${string}`,
      description:
        "ZK verifier missing public input range check: the BN256 field order " +
        "(21888242871839275222246405745257275088696311157297823662689037894645226208583) " +
        "was not found as a constant in the bytecode, suggesting public inputs are not " +
        "validated to be less than the field prime. Supplying inputs >= field order can " +
        "cause the verifier to accept forged proofs in some Groth16 implementations. " +
        "Fix: require(input < BN256_FIELD_ORDER) for each public input before verification. " +
        "Seen in Veil Cash misconfigured Groth16 ($5k, 2026-02-21).",
      confidence: 70,
    });
  }

  // Step 3: Check for nullifier/replay protection
  if (!verifierInfo.hasNullifierStore) {
    findings.push({
      riskClass: "zk_verifier_bypass",
      severity: "critical",
      functionSelector: pairing_call_selectors[0] as `0x${string}` ?? "0x00000000" as `0x${string}`,
      description:
        "ZK verifier missing proof replay protection: no SSTORE of a proof hash/nullifier " +
        "was detected after the pairing check. A valid proof can be submitted multiple times, " +
        "triggering the associated action (mint, withdraw, claim) repeatedly. " +
        "Fix: maintain a mapping(bytes32 => bool) of used proof hashes; " +
        "require(!usedProofs[proofHash]) before processing and set it to true after. " +
        "Seen in FOOM Cash fake proof spam ($2.26M, 2026-03-02).",
      confidence: 85,
    });
  }

  // Step 4: Check if verification key is hardcoded vs loaded from storage
  if (verifierInfo.hasHardcodedVK) {
    findings.push({
      riskClass: "zk_verifier_bypass",
      severity: "medium",
      functionSelector: "0x00000000" as `0x${string}`,
      description:
        "ZK verifier uses a hardcoded verification key (large constants in bytecode). " +
        "If the proving circuit is ever updated or re-parameterized after audit, the on-chain " +
        "VK must be manually redeployed. A mismatch between the VK and the actual circuit " +
        "allows provers to generate 'valid' proofs for arbitrary statements. " +
        "Consider using an upgradeable VK with a timelock, and emit an event whenever the VK changes.",
      confidence: 60,
    });
  }

  // Step 5: pairing count heuristic for Groth16 vs Plonk
  // Groth16 requires exactly 3 pairing calls (A·B, α·β, L·γ)
  // PLONK requires more pairing calls
  // If pairing count != expected for the scheme, may be misconfigured
  if (usesPairing && verifierInfo.pairingCallCount > 0 && verifierInfo.pairingCallCount !== 3 && verifierInfo.pairingCallCount < 6) {
    findings.push({
      riskClass: "zk_verifier_bypass",
      severity: "medium",
      functionSelector: "0x00000000" as `0x${string}`,
      description:
        `Unexpected BN256 pairing call count: detected ${verifierInfo.pairingCallCount} pairing ` +
        "invocations. Standard Groth16 requires 3 paired elements; standard PLONK requires 6+. " +
        "An incorrect pairing count can indicate a misconfigured verifier that may accept " +
        "invalid proofs or reject valid ones.",
      confidence: 55,
    });
  }

  return dedup(findings);
}

// ─── Helpers ──────────────────────────────────────────────────────────────

interface VerifierInfo {
  isVerifier: boolean;
  usesAdd: boolean;
  usesMul: boolean;
  usesPairing: boolean;
  pairingCallCount: number;
  hasBn256FieldOrderCheck: boolean;
  hasNullifierStore: boolean;
  hasHardcodedVK: boolean;
  pairing_call_selectors: string[];
}

function detectZkVerifier(evm: EVMAnalysisResult): VerifierInfo {
  let usesAdd = false;
  let usesMul = false;
  let usesPairing = false;
  let pairingCallCount = 0;
  let hasBn256FieldOrderCheck = false;
  let hasNullifierStore = false;
  let hasHardcodedVK = false;
  let hashCallSeen = false;
  let storeAfterHash = false;
  const pairing_call_selectors: string[] = [];

  // Also track which function selectors contain pairing calls
  const selWithPairing = new Set<string>();

  for (const block of evm.cfg.blocks.values()) {
    const insts = block.instructions;
    for (let i = 0; i < insts.length; i++) {
      const op = insts[i].opcode;
      const operand = insts[i].operand;

      // STATICCALL or CALL to BN256 precompiles
      if ((op === 0xfa || op === 0xf1) && operand === undefined) {
        // Can't resolve target statically in all cases, but look for
        // preceding PUSH2 with value 6, 7, or 8
        for (let j = Math.max(0, i - 8); j < i; j++) {
          if (insts[j].opcode === 0x61 && insts[j].operand !== undefined) { // PUSH2
            if (insts[j].operand === BN256_ADD) usesAdd = true;
            if (insts[j].operand === BN256_SCALAR) usesMul = true;
            if (insts[j].operand === BN256_PAIRING) {
              usesPairing = true;
              pairingCallCount++;
            }
          }
          // Also check PUSH1 for small values
          if (insts[j].opcode === 0x60 && insts[j].operand !== undefined) {
            if (insts[j].operand === BN256_ADD) usesAdd = true;
            if (insts[j].operand === BN256_SCALAR) usesMul = true;
            if (insts[j].operand === BN256_PAIRING) {
              usesPairing = true;
              pairingCallCount++;
            }
          }
        }
      }

      // Check for BN256 field order as a constant (PUSH32)
      if (op === 0x7f && operand === BN256_FIELD_ORDER) {
        hasBn256FieldOrderCheck = true;
      }

      // Large constants in bytecode → hardcoded VK (256-bit curve points)
      if (op === 0x7f && operand !== undefined) {
        // VK constants are large BN256 curve points — not zero, not max uint
        if (operand > 0n && operand < (1n << 256n) - 1n && operand !== BN256_FIELD_ORDER) {
          hasHardcodedVK = true;
        }
      }

      // KECCAK256 followed by SSTORE → nullifier pattern
      if (op === 0x20) hashCallSeen = true;
      if (hashCallSeen && op === 0x55) {
        storeAfterHash = true;
        hasNullifierStore = true;
      }
    }
  }

  // Identify which selectors contain pairing calls
  for (const [sel, entryBlock] of evm.cfg.selectorToBlock) {
    const visited = new Set<number>();
    const queue = [entryBlock];
    let found = false;
    while (queue.length > 0 && !found) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const block = evm.cfg.blocks.get(id);
      if (!block) continue;
      for (const inst of block.instructions) {
        if (inst.opcode === 0x60 && inst.operand === BN256_PAIRING) {
          pairing_call_selectors.push(sel);
          found = true;
          break;
        }
      }
      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }
  }

  const isVerifier = usesAdd || usesMul || usesPairing;

  return {
    isVerifier,
    usesAdd,
    usesMul,
    usesPairing,
    pairingCallCount,
    hasBn256FieldOrderCheck,
    hasNullifierStore,
    hasHardcodedVK,
    pairing_call_selectors,
  };
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
