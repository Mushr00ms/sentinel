/**
 * Unlimited Approval / Arbitrary-Call Drain Detector
 *
 * Logic Signature: any contract that (1) holds or routes token approvals
 * granted by users AND (2) passes user-controlled calldata to a
 * user-controlled target creates a vector to drain those approvals.
 *
 * Covers (2026): Matcha (0x) Unlimited Approval Exploit ($16.8M, 2026-01-26)
 *
 * The vulnerability is NOT specific to meta-aggregators or 0x protocol.
 * Any contract matching this pattern is exploitable:
 *   - DEX routers accepting arbitrary calldata
 *   - Multi-call contracts forwarding user-supplied calls
 *   - Permit2-style approval routers
 *   - Account abstraction executors with insufficient validation
 *
 * Detection requires TWO conditions together:
 *   A. The contract can call arbitrary targets (user-controlled CALL address)
 *   B. Users have granted (or the contract holds) token approvals
 *
 * Either condition alone is insufficient — the vulnerability only exists
 * when both are true simultaneously.
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";

// ERC-20 approval-related selectors
const APPROVAL_SELECTORS = new Set([
  "0x095ea7b3", // approve(address,uint256)
  "0xd505accf", // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
  "0x36c78516", // permit2 permit
  "0x2b67b570", // permit2 transferFrom
  "0x23b872dd", // transferFrom(address,address,uint256)
]);

// Selectors that transfer tokens using pre-granted approvals
const TRANSFER_WITH_APPROVAL_SELECTORS = new Set([
  "0x23b872dd", // transferFrom(address,address,uint256)
  "0xa9059cbb", // transfer(address,uint256)
  "0x2e1a7d4d", // withdraw(uint256) — WETH style
]);

export function detectUnlimitedApproval(
  evm: EVMAnalysisResult,
  storage: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];
  const detectedSelectors = new Set(evm.selectors);

  // Condition A: user-controlled CALL target
  // Pattern: CALLDATALOAD flows into CALL target address
  const { hasUserControlledCallTarget, affectedSelectors } = detectUserControlledCall(evm);

  if (!hasUserControlledCallTarget) return findings;

  // Condition B: approval context
  // Check 1: does this contract handle approvals directly?
  const hasApprovalSelector = [...APPROVAL_SELECTORS].some(s => detectedSelectors.has(s));

  // Check 2: does this contract call transferFrom (using stored approvals)?
  const hasTransferFromCall = detectTransferFromCall(evm);

  // Check 3: does any function set unlimited approvals to external targets?
  const hasUnlimitedApproveCall = detectUnlimitedApproveCall(evm);

  if (hasUserControlledCallTarget && (hasApprovalSelector || hasTransferFromCall)) {
    for (const sel of affectedSelectors) {
      findings.push({
        riskClass: "unlimited_approval",
        severity: "critical",
        functionSelector: sel as `0x${string}`,
        description:
          `Approval drain via arbitrary call: function ${sel} accepts a user-controlled ` +
          `target address in calldata and makes a CALL to it. This contract also handles ` +
          `token approvals (ERC-20 approve / transferFrom). ` +
          "An attacker can construct calldata directing the contract to call a token contract's " +
          "transferFrom using the victim's existing approval to this contract as the spender. " +
          "Fix: validate that call targets are from a whitelist of known protocols; " +
          "never forward arbitrary calldata to token contract addresses. " +
          "Seen in Matcha (0x) exploit ($16.8M, 2026-01-26).",
        confidence: 85,
      });
    }
  }

  // Check for multicall with user-supplied calls
  const hasMulticall = detectMulticallPattern(evm, detectedSelectors);
  if (hasMulticall && (hasTransferFromCall || hasUnlimitedApproveCall)) {
    findings.push({
      riskClass: "unlimited_approval",
      severity: "high",
      functionSelector: "0xac9650d8" as `0x${string}`, // multicall(bytes[])
      functionName: "multicall(bytes[])",
      description:
        "Multicall pattern with approval context: this contract implements multicall " +
        "(batch of arbitrary calls) and handles token approvals. " +
        "If users approve this contract as a spender, an attacker can construct a " +
        "multicall payload that drains those approvals by calling transferFrom to themselves. " +
        "Fix: in multicall, never allow calls to addresses that hold approval context for users; " +
        "or restrict multicall targets to a verified whitelist.",
      confidence: 70,
    });
  }

  // Check for contracts that grant infinite approvals to arbitrary addresses
  if (hasUnlimitedApproveCall) {
    findings.push({
      riskClass: "unlimited_approval",
      severity: "high",
      functionSelector: "0x00000000" as `0x${string}`,
      description:
        "Unlimited approval grant: this contract calls approve(target, type(uint256).max) " +
        "where the target address is user-controlled or set from storage that can be changed. " +
        "If the target can be set to an attacker-controlled contract, this effectively " +
        "grants unlimited spend authorization to the attacker.",
      confidence: 75,
    });
  }

  return dedup(findings);
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function detectUserControlledCall(
  evm: EVMAnalysisResult,
): { hasUserControlledCallTarget: boolean; affectedSelectors: string[] } {
  const affectedSelectors: string[] = [];

  for (const [sel, entryBlock] of evm.cfg.selectorToBlock) {
    // Check if CALLDATALOAD appears on path to CALL target
    let hasCalldataBeforeCall = false;
    let hasCall = false;

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
        if (op === 0x35 || op === 0x37) hasCalldataBeforeCall = true; // CALLDATALOAD / CALLDATACOPY
        if (hasCalldataBeforeCall && op === 0xf1) { // CALL
          hasCall = true;
        }
      }

      for (const succ of block.successors) {
        if (!visited.has(succ)) queue.push(succ);
      }
    }

    if (hasCalldataBeforeCall && hasCall) {
      affectedSelectors.push(sel);
    }
  }

  return {
    hasUserControlledCallTarget: affectedSelectors.length > 0,
    affectedSelectors,
  };
}

function detectTransferFromCall(evm: EVMAnalysisResult): boolean {
  // Look for PUSH4 of transferFrom selector in any function
  for (const block of evm.cfg.blocks.values()) {
    for (const inst of block.instructions) {
      if (inst.opcode === 0x63 && inst.operand !== undefined) {
        const selHex = "0x" + inst.operand.toString(16).padStart(8, "0");
        if (TRANSFER_WITH_APPROVAL_SELECTORS.has(selHex)) return true;
      }
    }
  }
  return false;
}

function detectUnlimitedApproveCall(evm: EVMAnalysisResult): boolean {
  // Pattern: PUSH32 of 2^256-1 (max uint256) followed eventually by CALL
  // with approve selector
  const MAX_UINT256 = (1n << 256n) - 1n;

  for (const block of evm.cfg.blocks.values()) {
    const insts = block.instructions;
    for (let i = 0; i < insts.length; i++) {
      if (insts[i].opcode === 0x7f && insts[i].operand === MAX_UINT256) {
        // Found max uint256 — check if approve is called nearby
        for (let j = i; j < Math.min(i + 10, insts.length); j++) {
          if (insts[j].opcode === 0x63 && insts[j].operand !== undefined) {
            const selHex = "0x" + insts[j].operand!.toString(16).padStart(8, "0");
            if (selHex === "0x095ea7b3") return true; // approve
          }
        }
      }
    }
  }
  return false;
}

function detectMulticallPattern(
  evm: EVMAnalysisResult,
  detectedSelectors: Set<string>,
): boolean {
  const MULTICALL_SELS = new Set([
    "0xac9650d8", // multicall(bytes[])
    "0x1f811564", // multicall(uint256,bytes[])
    "0x5ae401dc", // multicall(uint256,bytes[]) — Uniswap V3
    "0x1dde7e35", // executeMulticall(bytes[])
  ]);
  return [...MULTICALL_SELS].some(s => detectedSelectors.has(s));
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
