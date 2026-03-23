/**
 * Module H.3 — AI Code Fingerprinting
 *
 * Detects contracts likely generated with AI assistance (ChatGPT, Claude,
 * Copilot) by scoring characteristic source-code patterns. AI-generated
 * contracts have systematic blind spots inherited from training data —
 * surface-level correctness with subtle deeper vulnerabilities.
 *
 * When a contract is flagged as likely AI-generated, its risk score is
 * boosted because:
 *   - Deployers who used AI tend to skip professional audits
 *   - AI misses cross-function reentrancy, economic invariants, and
 *     composability issues that require whole-system reasoning
 *   - AI copies patterns from training data that may include patched bugs
 *     the AI doesn't know are patched
 */

import type { AiFingerprintResult, AiCodePattern } from "./types.js";

// ─── Pattern matchers ────────────────────────────────────────────────────

interface PatternDef {
  id: AiCodePattern;
  description: string;
  test: (source: string) => boolean;
  riskBoost: number; // bonus risk score points if this pattern is present
}

const PATTERNS: PatternDef[] = [
  {
    id: "flat_owner_access_control",
    description: "Flat onlyOwner access control without role-based hierarchy",
    test: (src) => {
      const hasOnlyOwner = /\bonlyOwner\b/.test(src);
      const hasRoles = /\bAccessControl\b|\bhasRole\b|\bROLE\b/.test(src);
      const hasManyFunctions = (src.match(/function\s+\w+/g) ?? []).length > 5;
      // Flag if: uses onlyOwner on many functions without any role-based system
      return hasOnlyOwner && !hasRoles && hasManyFunctions;
    },
    riskBoost: 10,
  },
  {
    id: "unchecked_arithmetic",
    description: "unchecked blocks around arithmetic that may overflow",
    test: (src) => {
      // AI often adds unchecked for gas optimization but sometimes misplaces it
      const uncheckedCount = (src.match(/\bunchecked\s*\{/g) ?? []).length;
      const hasUserInput = /\bmsg\.value\b|\bcalldata\b|\bmemory\b/.test(src);
      // More than 2 unchecked blocks with user-controlled input = suspicious
      return uncheckedCount > 2 && hasUserInput;
    },
    riskBoost: 8,
  },
  {
    id: "missing_cross_function_reentrancy_guard",
    description: "ReentrancyGuard on some functions but not interacting pairs",
    test: (src) => {
      const hasGuard = /\bReentrancyGuard\b|\bnonReentrant\b/.test(src);
      if (!hasGuard) return false;

      // Has external calls in non-guarded functions
      const functionBlocks = src.split(/\bfunction\b/);
      let unguardedWithExternalCall = 0;
      for (const block of functionBlocks.slice(1)) {
        const isGuarded = /\bnonReentrant\b/.test(block.split("{")[0] ?? "");
        const hasExternalCall = /\.\bcall\b\s*\{|\.\bsend\b\s*\(|\btransfer\s*\(/.test(block.slice(0, 500));
        if (!isGuarded && hasExternalCall) unguardedWithExternalCall++;
      }
      return unguardedWithExternalCall > 0;
    },
    riskBoost: 15,
  },
  {
    id: "uninitialised_initializer",
    description: "Upgradeable contract missing _disableInitializers() in constructor",
    test: (src) => {
      const isUpgradeable =
        /\bUUPSUpgradeable\b|\bTransparentUpgradeableProxy\b|\bInitializable\b/.test(src);
      const hasConstructor = /\bconstructor\s*\(/.test(src);
      const hasDisableInitializers = /_disableInitializers\s*\(\)/.test(src);
      return isUpgradeable && hasConstructor && !hasDisableInitializers;
    },
    riskBoost: 20,
  },
  {
    id: "predictable_variable_naming",
    description: "AI-typical variable names: _owner, _balances, _totalSupply without custom logic",
    test: (src) => {
      let aiNameScore = 0;
      if (/\b_owner\b/.test(src)) aiNameScore++;
      if (/\b_balances\b/.test(src)) aiNameScore++;
      if (/\b_totalSupply\b/.test(src)) aiNameScore++;
      if (/\b_allowances\b/.test(src)) aiNameScore++;
      if (/\b_name\b/.test(src) && /\b_symbol\b/.test(src)) aiNameScore++;
      // Combined with OZ imports = high confidence AI-generated
      const hasOz = /openzeppelin/.test(src.toLowerCase());
      return aiNameScore >= 3 && hasOz;
    },
    riskBoost: 5,
  },
  {
    id: "copy_paste_oz_pattern",
    description: "Verbatim OpenZeppelin pattern with minimal customization",
    test: (src) => {
      // OZ imports with no modifications to core functions = likely template
      const ozImports = (src.match(/import.*openzeppelin/gi) ?? []).length;
      const customModifiers = (src.match(/\bmodifier\b/g) ?? []).length;
      const overrideCount = (src.match(/\boverride\b/g) ?? []).length;
      // Many OZ imports, few custom modifiers, few overrides = template code
      return ozImports >= 3 && customModifiers <= 1 && overrideCount <= 2;
    },
    riskBoost: 5,
  },
  {
    id: "missing_zero_address_check",
    description: "Address parameters without zero-address validation",
    test: (src) => {
      // Count address parameters in external/public functions
      const addressParams = (src.match(/\baddress\s+\w+\b/g) ?? []).length;
      // Count zero-address checks
      const zeroChecks = (
        src.match(/require\s*\(.*!=\s*address\(0\)|!= address\(0x0\)/g) ?? []
      ).length;
      // If many address params but few zero checks, likely AI-generated
      return addressParams > 4 && zeroChecks === 0;
    },
    riskBoost: 8,
  },
  {
    id: "no_event_on_state_change",
    description: "State-changing functions without corresponding events",
    test: (src) => {
      const eventDefs = (src.match(/\bevent\s+\w+/g) ?? []).length;
      const emitCalls = (src.match(/\bemit\s+\w+/g) ?? []).length;
      const stateChangeFns = (src.match(/\b(set|update|change|transfer|mint|burn)\w*\s*\(/gi) ?? []).length;
      // AI often adds events as afterthought; if many state-change functions but few emits
      return stateChangeFns > 3 && emitCalls < stateChangeFns / 2 && eventDefs < 3;
    },
    riskBoost: 3,
  },
];

// ─── AiFingerprinter ─────────────────────────────────────────────────────

export class AiFingerprinter {
  /**
   * Analyzes Solidity source code for AI-generation fingerprints.
   * Returns a result with confidence score and pattern breakdown.
   */
  analyze(sourceCode: string): AiFingerprintResult {
    const matchedPatterns: AiCodePattern[] = [];
    let totalRiskBoost = 0;
    let patternScore = 0;

    for (const pattern of PATTERNS) {
      try {
        if (pattern.test(sourceCode)) {
          matchedPatterns.push(pattern.id);
          totalRiskBoost += pattern.riskBoost;
          patternScore += pattern.riskBoost;
        }
      } catch {
        // Pattern test failure is non-fatal
      }
    }

    // Normalise confidence: 0 patterns = 0%, all patterns = 90%
    const maxPossibleScore = PATTERNS.reduce((s, p) => s + p.riskBoost, 0);
    const confidence = Math.min(
      Math.round((patternScore / maxPossibleScore) * 100),
      90, // cap at 90% — we can never be 100% certain
    );

    // Heuristic threshold: 3+ patterns or confidence >= 30% = likely AI-generated
    const isLikelyAiGenerated = matchedPatterns.length >= 2 || confidence >= 25;

    return {
      isLikelyAiGenerated,
      confidence,
      patterns: matchedPatterns,
      riskBoost: isLikelyAiGenerated ? Math.min(totalRiskBoost, 30) : 0,
      detectedAt: Date.now(),
    };
  }
}
