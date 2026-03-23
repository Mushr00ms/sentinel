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
