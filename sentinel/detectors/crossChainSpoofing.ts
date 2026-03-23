/**
 * Cross-Chain Message Spoofing Detector
 *
 * Logic Signature: any cross-chain message receiver that does not validate
 * BOTH the caller identity (msg.sender == trustedBridge) AND the source
 * chain/address (srcChainId + srcAddress from calldata) is exploitable by
 * a fake message claiming to originate from a trusted source.
 *
 * Covers (2026):
 *   - CrossCurve Spoofed Cross-Chain Messages ($3M, 2026-02-01)
 *   - FOOM Cash Fake Proof Spam ($2.26M, 2026-03-02)
 *
 * Key insight: the implementation doesn't matter — LayerZero, CCIP,
 * Axelar, Wormhole, custom bridge. Any contract that processes
 * cross-chain messages shares the same attack surface:
 *   1. Is the caller the expected bridge?
 *   2. Is the source chain/address the expected trusted peer?
 *   3. Has this message been processed before (replay protection)?
 *
 * If any of these three checks is missing, the message is spoofable.
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

// Known cross-chain receiver function selectors
// These are the canonical entry points for different messaging protocols
const XCHAIN_RECEIVER_SELECTORS = new Map<string, string>([
  ["0x1c38b58e", "lzReceive(uint16,bytes,uint64,bytes)"],             // LayerZero V1
  ["0xe9bbb273", "lzReceive(uint32,bytes32,uint64,bytes32,bytes)"],   // LayerZero V2
  ["0x85572ffb", "ccipReceive(Any2EVMMessage)"],                       // Chainlink CCIP
  ["0x7d76e7a4", "anyExecute(bytes)"],                                 // Multichain anyCall
  ["0x4ff69621", "processMessage(bytes)"],                             // generic
  ["0x9a5e4e0e", "handleMessage(bytes32,bytes)"],                      // generic bridge
  ["0x14d4cfe1", "onMessageReceived(address,uint256,bytes)"],          // Polygon bridge
  ["0x73d4a13a", "finalizeInboundTransfer(address,address,address,uint256,bytes)"],
  ["0x09c5eabe", "executeWithToken(bytes32,string,bytes,string,uint256)"], // Axelar
  ["0x54c8a4a2", "execute(bytes32,string,string,bytes)"],              // Axelar
  ["0x9d3f8ccc", "receiveMessage(bytes)"],                             // Circle CCTP
  ["0x7b3aba50", "handleDeposit(bytes)"],                              // generic
  ["0xe44d43eb", "processProof(bytes)"],                               // ZK bridge
  ["0xb77f9bfb", "verifyAndExecute(bytes,bytes)"],                     // generic ZK
]);

// Access control patterns
// CALLER pushed then compared = msg.sender check
// CALLDATALOAD at offset 4+ compared against stored address = source address check

export function detectCrossChainSpoofing(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];
  const detectedSelectors = new Set(evm.selectors);

  for (const [sel, funcName] of XCHAIN_RECEIVER_SELECTORS) {
    if (!detectedSelectors.has(sel)) continue;

    const entryBlock = evm.cfg.selectorToBlock.get(sel);
    if (entryBlock === undefined) continue;

    const analysis = analyzeCrossChainReceiver(evm, entryBlock);

    // Three required checks
    const issues: string[] = [];

    if (!analysis.hasMsgSenderCheck) {
      issues.push("no msg.sender validation (bridge identity not checked)");
    }
    if (!analysis.hasSourceChainCheck) {
      issues.push("no source chain ID validation (spoofable origin chain)");
    }
    if (!analysis.hasReplayProtection) {
      issues.push("no replay protection (message hash/nonce not stored)");
    }

    if (issues.length > 0) {
      findings.push({
        riskClass: "cross_chain_spoofing",
        severity: issues.length >= 2 ? "critical" : "high",
        functionSelector: sel as `0x${string}`,
        functionName: funcName,
        description:
          `Cross-chain receiver ${funcName} (${sel}) is missing: ${issues.join("; ")}. ` +
          "Any of these omissions allows an attacker to forge messages appearing to come " +
          "from a trusted source chain or bridge contract. " +
          "Fix: (1) require(msg.sender == trustedBridge), " +
          "(2) validate srcChainId and srcAddress from calldata against a whitelist, " +
          "(3) store processed message hashes to prevent replay. " +
          "Seen in CrossCurve ($3M, 2026-02-01).",
        confidence: 75 + (issues.length * 5),
      });
    }
  }

  // Generic detection: any function that takes large calldata (bridge message pattern)
  // and contains an external CALL without a CALLER check
  const genericReceivers = detectGenericMessageReceivers(evm);
  for (const sel of genericReceivers) {
    if (XCHAIN_RECEIVER_SELECTORS.has(sel)) continue; // already handled above
    findings.push({
      riskClass: "cross_chain_spoofing",
      severity: "medium",
      functionSelector: sel as `0x${string}`,
      description:
        `Function ${sel} processes large calldata and makes external calls without ` +
        `a detected msg.sender check. If this is a cross-chain message receiver, ` +
        `verify that the bridge identity, source chain, and replay protection are all validated.`,
      confidence: 50,
    });
  }

  // ZK bridge specific: check for missing nullifier set
  const zkReceivers = [...XCHAIN_RECEIVER_SELECTORS.keys()].filter(
    s => detectedSelectors.has(s) && (s === "0xe44d43eb" || s === "0xb77f9bfb"),
  );
  for (const sel of zkReceivers) {
    const entryBlock = evm.cfg.selectorToBlock.get(sel);
    if (entryBlock === undefined) continue;

    const hasNullifierStore = detectNullifierPattern(evm, entryBlock);
    if (!hasNullifierStore) {
      findings.push({
        riskClass: "cross_chain_spoofing",
        severity: "critical",
        functionSelector: sel as `0x${string}`,
        functionName: "ZK bridge receiver",
        description:
          `ZK proof-based bridge receiver ${sel} does not appear to store used proof hashes ` +
          `(nullifiers). Without a nullifier registry, valid proofs can be submitted multiple ` +
          `times, allowing the same proof to unlock funds repeatedly. ` +
          "Seen in FOOM Cash fake proof spam ($2.26M, 2026-03-02).",
        confidence: 80,
      });
    }
  }

  return dedup(findings);
}

// ─── Helpers ──────────────────────────────────────────────────────────────

interface ReceiverAnalysis {
  hasMsgSenderCheck: boolean;
  hasSourceChainCheck: boolean;
  hasReplayProtection: boolean;
}

function analyzeCrossChainReceiver(
  evm: EVMAnalysisResult,
  entryBlock: number,
): ReceiverAnalysis {
  let callerOnStack = false;
  let hasMsgSenderCheck = false;
  let hasCalldataComparison = false;
  let hasStorageWrite = false;

  const visited = new Set<number>();
  const queue = [entryBlock];

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    for (let i = 0; i < block.instructions.length; i++) {
      const op = block.instructions[i].opcode;

      // CALLER pushed onto stack
      if (op === 0x33) callerOnStack = true;

      // EQ after CALLER → msg.sender == someAddress check
      if (callerOnStack && op === 0x14) hasMsgSenderCheck = true;

      // CALLDATALOAD at non-zero offset compared with EQ/GT/LT → source chain/address check
      if (op === 0x35) { // CALLDATALOAD
        const nextOp = block.instructions[i + 1]?.opcode;
        if (nextOp === 0x14 || nextOp === 0x10 || nextOp === 0x11) {
          hasCalldataComparison = true;
        }
      }

      // SSTORE → could be replay protection (storing processed nonces/hashes)
      if (op === 0x55) hasStorageWrite = true;

      // Reset caller flag if other ops push values
      if (![0x80, 0x81, 0x82, 0x33, 0x14, 0x15, 0x57].includes(op)) {
        callerOnStack = false;
      }
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }

  return {
    hasMsgSenderCheck,
    // Source chain check: calldata comparison and caller check combined
    hasSourceChainCheck: hasCalldataComparison,
    // Replay protection: SSTORE (storing seen message hashes/nonces)
    hasReplayProtection: hasStorageWrite,
  };
}

function detectGenericMessageReceivers(evm: EVMAnalysisResult): string[] {
  const result: string[] = [];

  for (const [sel, entryBlock] of evm.cfg.selectorToBlock) {
    let hasLargeCalldataRead = false;
    let hasExternalCall = false;
    let hasCallerCheck = false;

    const visited = new Set<number>();
    const queue = [entryBlock];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const block = evm.cfg.blocks.get(id);
      if (!block) continue;

      for (let i = 0; i < block.instructions.length; i++) {
        const op = block.instructions[i].opcode;
        if (op === 0x36) hasLargeCalldataRead = true; // CALLDATASIZE > 0
        if (op === 0x37 || op === 0x3e) hasLargeCalldataRead = true; // CALLDATACOPY / RETURNDATACOPY
        if (op === 0xf1 || op === 0xf4) hasExternalCall = true;
        if (op === 0x33) hasCallerCheck = true; // CALLER
      }

      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }

    if (hasLargeCalldataRead && hasExternalCall && !hasCallerCheck) {
      result.push(sel);
    }
  }

  return result;
}

function detectNullifierPattern(evm: EVMAnalysisResult, entryBlock: number): boolean {
  // Nullifier pattern: KECCAK256 (hashing the proof) followed by SLOAD+SSTORE
  // (checking and setting the used-proof registry)
  let hasHash = false;
  let hasCheckAndStore = false;

  const visited = new Set<number>();
  const queue = [entryBlock];
  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const block = evm.cfg.blocks.get(id);
    if (!block) continue;

    for (let i = 0; i < block.instructions.length; i++) {
      const op = block.instructions[i].opcode;
      if (op === 0x20) hasHash = true; // KECCAK256
      if (hasHash && op === 0x54) { // SLOAD after hash → checking registry
        const next = block.instructions[i + 1]?.opcode;
        if (next === 0x57) { // JUMPI → require(!used)
          hasCheckAndStore = true;
        }
      }
    }

    for (const succ of block.successors) {
      if (!visited.has(succ)) queue.push(succ);
    }
  }

  return hasHash && hasCheckAndStore;
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
