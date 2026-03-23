/**
 * Unified Detector Runner
 *
 * Runs all custom vulnerability detectors against an EVM analysis result
 * and returns merged findings.
 */

import type { EVMAnalysisResult, StorageLayoutResult } from "../evm/index.js";
import type { StaticAnalysisFinding } from "../types.js";
import { detectReadOnlyReentrancy } from "./readOnlyReentrancy.js";
import { detectFeeOnTransfer } from "./feeOnTransfer.js";
import { detectPrecisionLoss } from "./precisionLoss.js";
import { detectEnhancedERC4626 } from "./enhancedERC4626.js";
import { detectUncheckedReturnValues } from "./uncheckedReturnValues.js";
import { detectERC777Reentrancy } from "./erc777Reentrancy.js";
// 2026 logic-signature detectors
import { detectDonationAttack } from "./donationAttack.js";
import { detectOracleMisconfiguration } from "./oracleMisconfiguration.js";
import { detectInfiniteMint } from "./infiniteMint.js";
import { detectCrossChainSpoofing } from "./crossChainSpoofing.js";
import { detectAccessControlBypass } from "./accessControlBypass.js";
import { detectFlashloanShareManipulation } from "./flashloanShareManipulation.js";
import { detectUnlimitedApproval } from "./unlimitedApproval.js";
import { detectZkVerifierBypass } from "./zkVerifierBypass.js";

/**
 * Runs all vulnerability detectors and returns merged findings.
 */
export function runAllDetectors(
  evmAnalysis: EVMAnalysisResult,
  storageLayout: StorageLayoutResult,
): StaticAnalysisFinding[] {
  const findings: StaticAnalysisFinding[] = [];

  // Phase 3.1: Read-Only Reentrancy
  try {
    findings.push(...detectReadOnlyReentrancy(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.2: Fee-on-Transfer
  try {
    findings.push(...detectFeeOnTransfer(evmAnalysis));
  } catch { /* non-fatal */ }

  // Phase 3.3: Precision Loss
  try {
    findings.push(...detectPrecisionLoss(evmAnalysis));
  } catch { /* non-fatal */ }

  // Phase 3.4: Enhanced ERC-4626
  try {
    findings.push(...detectEnhancedERC4626(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.5: Unchecked Return Values
  try {
    findings.push(...detectUncheckedReturnValues(evmAnalysis));
  } catch { /* non-fatal */ }

  // Phase 3.6: ERC-777 Hook Reentrancy
  try {
    findings.push(...detectERC777Reentrancy(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // ── 2026 Logic-Signature Detectors ────────────────────────────────────

  // Phase 3.7: Donation / Share-Inflation Attack
  // (Curve LlamaLend, Venus, Goose Finance, dTRINITY dLEND)
  try {
    findings.push(...detectDonationAttack(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.8: Oracle Misconfiguration
  // (Makina, Blend Pools, Ploutos, Aave CAPO, YO Protocol, Moonwell)
  try {
    findings.push(...detectOracleMisconfiguration(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.9: Infinite Mint / Token Inflation
  // (Saga, DGLD, TMX TRIBE, SolvBTC, Truebit bonding curve)
  try {
    findings.push(...detectInfiniteMint(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.10: Cross-Chain Message Spoofing
  // (CrossCurve, FOOM Cash ZK bridge replay)
  try {
    findings.push(...detectCrossChainSpoofing(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.11: Access Control Bypass
  // (Molt EVM mutable modifier, Fusion by IPOR EIP-7702)
  try {
    findings.push(...detectAccessControlBypass(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.12: Flashloan Share Manipulation
  // (Cyrus Finance, Wise Lending V2)
  try {
    findings.push(...detectFlashloanShareManipulation(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.13: Unlimited Approval / Arbitrary-Call Drain
  // (Matcha / 0x)
  try {
    findings.push(...detectUnlimitedApproval(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Phase 3.14: ZK Verifier Bypass
  // (Veil Cash Groth16 misconfiguration, FOOM Cash)
  try {
    findings.push(...detectZkVerifierBypass(evmAnalysis, storageLayout));
  } catch { /* non-fatal */ }

  // Deduplicate across detectors
  return deduplicateFindings(findings);
}

function deduplicateFindings(findings: StaticAnalysisFinding[]): StaticAnalysisFinding[] {
  const seen = new Map<string, StaticAnalysisFinding>();
  for (const f of findings) {
    const key = `${f.functionSelector}:${f.riskClass}:${f.description.slice(0, 80)}`;
    const existing = seen.get(key);
    if (!existing || f.confidence > existing.confidence) {
      seen.set(key, f);
    }
  }
  return Array.from(seen.values());
}
