/**
 * Module G.3 — LLM Semantic Vulnerability Analyzer
 *
 * Shells out to `claude --print --json` (Claude Code CLI with OAuth) for
 * semantic vulnerability analysis of smart contract source code.
 * Zero npm dependencies — uses the locally installed Claude CLI.
 *
 * Only triggers on contracts with riskScore >= configurable threshold.
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";
import type { Address } from "viem";
import type {
  LLMAnalysisResult,
  LLMVulnerability,
  MisconfigSeverity,
  RiskClass,
  SupportedChain,
  StaticAnalysisReport,
  SlitherFinding,
} from "./types.js";
import { CLAUDE_CLI_PATH, MASS_AUDIT_LLM_RISK_THRESHOLD } from "./config.js";
import { warn, info } from "./alerter.js";

const execAsync = promisify(exec);

// ─── Constants ──────────────────────────────────────────────────────────

/** Maximum source characters to send to Claude (cost control). */
const MAX_SOURCE_CHARS = 80_000;

/** Claude CLI subprocess timeout (3 minutes). */
const CLAUDE_TIMEOUT_MS = 180_000;

/** Temp directory for prompt files. */
const PROMPT_DIR = "/tmp/sentinel-llm";

// ─── System Prompt ──────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are an expert smart contract security auditor specializing in DeFi protocols on EVM chains.
Analyze the provided smart contract code for exploitable vulnerabilities.

You MUST respond with ONLY valid JSON matching this exact schema — no markdown, no explanation outside the JSON:
{
  "vulnerabilities": [
    {
      "title": "Short vulnerability title",
      "severity": "critical" | "high" | "medium" | "low",
      "category": "drain" | "access_control" | "reentrancy" | "oracle_manipulation" | "erc4626_inflation" | "calldata_forwarding" | "approval_exploit" | "flash_loan_attack" | "integer_overflow" | "selfdestruct",
      "description": "Detailed description of the vulnerability",
      "affectedFunction": "functionName or null",
      "exploitScenario": "Step-by-step exploitation scenario",
      "confidence": 0-100
    }
  ],
  "overallRiskAssessment": "Summary of the contract's security posture",
  "confidenceScore": 0-100
}

Focus on EXPLOITABLE vulnerabilities only:
1. Fund drain vectors (unauthorized withdrawals, flash loan attacks, share inflation)
2. Access control bypasses (missing modifiers, unprotected admin functions)
3. Reentrancy (cross-function, read-only, cross-contract via callbacks)
4. Oracle manipulation (spot price, TWAP manipulation, stale data exploitation)
5. ERC-4626 inflation/donation attacks
6. Flash loan attack surfaces (price manipulation, governance attacks)
7. Integer overflow/underflow in unchecked blocks
8. Proxy upgrade risks (uninitialized, storage collisions, UUPS)
9. MEV extraction vectors (sandwich, frontrun, backrun)

Do NOT report:
- Gas optimizations or style issues
- Intentional centralization (admin keys, multisigs)
- Theoretical issues with no practical exploit path
- Known standard patterns that are not vulnerable (e.g., OpenZeppelin ReentrancyGuard)

If no vulnerabilities are found, return empty vulnerabilities array with appropriate confidenceScore.`;

// ─── LLMAnalyzer ────────────────────────────────────────────────────────

export class LLMAnalyzer {
  private enabled = false;

  constructor() {
    // Check if claude CLI is available
    void this.checkCliAvailable();
  }

  /**
   * Runs semantic vulnerability analysis via Claude CLI.
   * Only triggers if riskScore >= threshold.
   *
   * Uses: claude --print --json --model sonnet -p "<prompt>"
   */
  async analyze(
    address: Address,
    chain: SupportedChain,
    sourceOrDecompiled: string,
    staticReport: StaticAnalysisReport,
    slitherFindings?: SlitherFinding[],
  ): Promise<LLMAnalysisResult | null> {
    if (!this.enabled) {
      warn("llm-analyzer", "Claude CLI not available, skipping LLM analysis");
      return null;
    }

    if (staticReport.riskScore < MASS_AUDIT_LLM_RISK_THRESHOLD) {
      return null;
    }

    const startMs = Date.now();

    try {
      // Build the user prompt
      const userPrompt = this.buildUserPrompt(
        address,
        chain,
        sourceOrDecompiled,
        staticReport,
        slitherFindings,
      );

      // Write prompt to a temp file (avoids shell escaping issues with large source)
      await fs.mkdir(PROMPT_DIR, { recursive: true });
      const promptPath = path.join(PROMPT_DIR, `${address.toLowerCase()}.txt`);
      await fs.writeFile(promptPath, userPrompt, "utf-8");

      // Shell out to Claude CLI with OAuth
      // --print: output response only (no interactive UI)
      // --output-format json: structured JSON output
      // --model: use sonnet for cost efficiency
      // --max-turns 1: single-shot, no tool use
      const cmd = [
        CLAUDE_CLI_PATH,
        "--print",
        "--output-format", "json",
        "--model", "sonnet",
        "--max-turns", "1",
        "--system-prompt", JSON.stringify(SYSTEM_PROMPT),
        "-p", `"$(cat ${promptPath})"`,
      ].join(" ");

      const { stdout } = await execAsync(cmd, {
        timeout: CLAUDE_TIMEOUT_MS,
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
        env: { ...process.env, NO_COLOR: "1" },
      });

      // Parse the Claude CLI JSON output
      const parsed = this.parseCliOutput(stdout);
      if (!parsed) {
        warn("llm-analyzer", `Failed to parse Claude response for ${address}`);
        return null;
      }

      const result: LLMAnalysisResult = {
        contractAddress: address,
        chain,
        vulnerabilities: parsed.vulnerabilities,
        overallRiskAssessment: parsed.overallRiskAssessment,
        confidenceScore: parsed.confidenceScore,
        analyzedAt: Date.now(),
        analysisTimeMs: Date.now() - startMs,
      };

      info(
        "llm-analyzer",
        `${chain}:${address} — ${result.vulnerabilities.length} vulns found, ` +
        `confidence=${result.confidenceScore}, ${result.analysisTimeMs}ms`,
      );

      // Cleanup prompt file
      await fs.unlink(promptPath).catch(() => {});

      return result;
    } catch (err) {
      const msg = (err as Error).message;
      // Don't warn on timeout — just means model took too long
      if (msg.includes("TIMEOUT") || msg.includes("timeout")) {
        warn("llm-analyzer", `Claude CLI timeout for ${address} (${CLAUDE_TIMEOUT_MS}ms)`);
      } else {
        warn("llm-analyzer", `Claude CLI error for ${address}: ${msg}`);
      }
      return null;
    }
  }

  // ── Private ─────────────────────────────────────────────────────────

  private async checkCliAvailable(): Promise<void> {
    try {
      await execAsync(`${CLAUDE_CLI_PATH} --version`, { timeout: 10_000 });
      this.enabled = true;
      info("llm-analyzer", "Claude CLI detected — LLM analysis enabled");
    } catch {
      this.enabled = false;
      warn("llm-analyzer", `Claude CLI not found at '${CLAUDE_CLI_PATH}' — LLM analysis disabled`);
    }
  }

  /**
   * Runs a focused second-pass analysis for high-risk contracts with pattern matches.
   * Returns additional vulnerabilities from targeted analysis.
   */
  async analyzeSecondPass(
    address: Address,
    chain: SupportedChain,
    sourceOrDecompiled: string,
    staticReport: StaticAnalysisReport,
  ): Promise<LLMVulnerability[]> {
    if (!this.enabled) return [];
    if (!staticReport.exploitPatternMatches || staticReport.exploitPatternMatches.length === 0) return [];
    if (staticReport.riskScore < 70) return [];

    const topMatch = staticReport.exploitPatternMatches[0];
    const truncatedSource = sourceOrDecompiled.length > MAX_SOURCE_CHARS
      ? sourceOrDecompiled.slice(0, MAX_SOURCE_CHARS) + "\n\n// ... [TRUNCATED] ..."
      : sourceOrDecompiled;

    const prompt = [
      `## Targeted Vulnerability Analysis`,
      `## Contract: ${address} on ${chain}`,
      `## Risk Score: ${staticReport.riskScore}/100`,
      ``,
      `This contract matches the "${topMatch.patternName}" exploit pattern ` +
      `(${topMatch.protocol}, $${(topMatch.lossAmountUsd / 1e6).toFixed(1)}M loss).`,
      `Match score: ${topMatch.matchScore}/100`,
      `Matched conditions: ${topMatch.matchedConditions.join(", ")}`,
      `Pattern description: ${topMatch.description}`,
      ``,
      `## Contract Source Code:`,
      `\`\`\`solidity`,
      truncatedSource,
      `\`\`\``,
      ``,
      `Analyze whether this contract is ACTUALLY vulnerable to the "${topMatch.patternName}" ` +
      `attack pattern. Consider:`,
      `1. Are the matched conditions sufficient for exploitation?`,
      `2. Are there mitigations that prevent the attack?`,
      `3. What is the realistic impact if exploitable?`,
      ``,
      `Return JSON only.`,
    ].join("\n");

    try {
      await fs.mkdir(PROMPT_DIR, { recursive: true });
      const promptPath = path.join(PROMPT_DIR, `${address.toLowerCase()}-pass2.txt`);
      await fs.writeFile(promptPath, prompt, "utf-8");

      const cmd = [
        CLAUDE_CLI_PATH,
        "--print",
        "--output-format", "json",
        "--model", "sonnet",
        "--max-turns", "1",
        "--system-prompt", JSON.stringify(SYSTEM_PROMPT),
        "-p", `"$(cat ${promptPath})"`,
      ].join(" ");

      const { stdout } = await execAsync(cmd, {
        timeout: CLAUDE_TIMEOUT_MS,
        maxBuffer: 10 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: "1" },
      });

      const parsed = this.parseCliOutput(stdout);
      await fs.unlink(promptPath).catch(() => {});

      if (parsed) {
        info("llm-analyzer", `Second-pass for ${address}: ${parsed.vulnerabilities.length} additional vulns`);
        return parsed.vulnerabilities;
      }
    } catch {
      // Non-fatal
    }

    return [];
  }

  /**
   * Builds the user prompt with contract source and context from static analysis.
   * Enriched with EVM analysis context (taint flows, value flows, storage layout,
   * exploit pattern matches) when available.
   */
  private buildUserPrompt(
    address: Address,
    chain: SupportedChain,
    source: string,
    staticReport: StaticAnalysisReport,
    slitherFindings?: SlitherFinding[],
  ): string {
    const truncatedSource = source.length > MAX_SOURCE_CHARS
      ? source.slice(0, MAX_SOURCE_CHARS) + "\n\n// ... [TRUNCATED] ..."
      : source;

    const parts: string[] = [
      `## Contract: ${address} on ${chain}`,
      `## Static Analysis Risk Score: ${staticReport.riskScore}/100`,
      "",
    ];

    // Include static analysis findings as context
    if (staticReport.findings.length > 0) {
      parts.push("## Prior Static Analysis Findings:");
      for (const f of staticReport.findings.slice(0, 10)) {
        parts.push(`- [${f.severity.toUpperCase()}] ${f.riskClass}: ${f.description} (confidence: ${f.confidence}%)`);
      }
      parts.push("");
    }

    // Include Slither findings as context
    if (slitherFindings && slitherFindings.length > 0) {
      parts.push("## Slither Findings:");
      for (const f of slitherFindings.slice(0, 10)) {
        parts.push(`- [${f.impact}/${f.confidence}] ${f.check}: ${f.description.slice(0, 200)}`);
      }
      parts.push("");
    }

    // EVM analysis enrichment (Phase 6)
    if (staticReport.evmAnalysis) {
      const evm = staticReport.evmAnalysis;
      parts.push("## EVM Bytecode Analysis:");
      parts.push(`- Instructions: ${evm.instructionCount} | Blocks: ${evm.blockCount}`);
      parts.push(`- Detected selectors: ${evm.selectors.slice(0, 10).join(", ")}`);
      parts.push(`- Taint flows: ${evm.taintFlowCount} (high-severity: ${evm.highSeverityTaintFlows})`);
      parts.push(`- Unconditional drains: ${evm.unconditionalDrainCount}`);
      parts.push(`- Storage slots: ${evm.storageSlotCount} | Upgradeable proxy: ${evm.isUpgradeableProxy}`);
      parts.push(`- External calls: ${evm.externalCallCount}`);
      parts.push("");
    }

    // Exploit pattern matches enrichment
    if (staticReport.exploitPatternMatches && staticReport.exploitPatternMatches.length > 0) {
      parts.push("## Exploit Pattern Matches:");
      for (const m of staticReport.exploitPatternMatches.slice(0, 5)) {
        parts.push(
          `- [Score: ${m.matchScore}] ${m.patternName} (${m.protocol}, ` +
          `$${(m.lossAmountUsd / 1e6).toFixed(1)}M): ${m.description}`,
        );
        parts.push(`  Matched: ${m.matchedConditions.join(", ")}`);
      }
      parts.push("");
    }

    parts.push("## Contract Source Code:");
    parts.push("```solidity");
    parts.push(truncatedSource);
    parts.push("```");
    parts.push("");
    parts.push("Analyze this contract for exploitable vulnerabilities. Return JSON only.");

    return parts.join("\n");
  }

  /**
   * Parses the Claude CLI --output-format json response.
   *
   * The CLI with --output-format json returns:
   * { "type": "result", "subtype": "success", "cost_usd": ..., "result": "..." }
   * where result contains the model's text output (our JSON).
   */
  private parseCliOutput(
    stdout: string,
  ): {
    vulnerabilities: LLMVulnerability[];
    overallRiskAssessment: string;
    confidenceScore: number;
  } | null {
    try {
      // First try to parse the outer CLI JSON envelope
      const cliOutput = JSON.parse(stdout.trim()) as {
        type?: string;
        result?: string;
        subtype?: string;
      };

      // Extract the model's response text
      let responseText = cliOutput.result ?? stdout;

      // The model's response should be our vulnerability JSON
      // Try to extract JSON from the response if it's wrapped in markdown
      if (typeof responseText === "string") {
        // Strip markdown code fences if present
        const jsonMatch = responseText.match(/```(?:json)?\s*([\s\S]*?)```/);
        if (jsonMatch) {
          responseText = jsonMatch[1].trim();
        }
      }

      return this.parseVulnerabilityJson(responseText);
    } catch {
      // If the outer parse fails, try parsing stdout directly as our JSON
      // (in case --print mode outputs the raw response)
      try {
        // Try to find JSON in the raw output
        const jsonStart = stdout.indexOf("{");
        const jsonEnd = stdout.lastIndexOf("}");
        if (jsonStart >= 0 && jsonEnd > jsonStart) {
          const jsonStr = stdout.slice(jsonStart, jsonEnd + 1);
          return this.parseVulnerabilityJson(jsonStr);
        }
      } catch { /* fall through */ }

      return null;
    }
  }

  /**
   * Parses and validates the vulnerability JSON response from Claude.
   */
  private parseVulnerabilityJson(
    text: string,
  ): {
    vulnerabilities: LLMVulnerability[];
    overallRiskAssessment: string;
    confidenceScore: number;
  } | null {
    try {
      const data = JSON.parse(text) as {
        vulnerabilities?: Array<{
          title?: string;
          severity?: string;
          category?: string;
          description?: string;
          affectedFunction?: string;
          exploitScenario?: string;
          confidence?: number;
        }>;
        overallRiskAssessment?: string;
        confidenceScore?: number;
      };

      const validSeverities = new Set(["critical", "high", "medium", "low"]);
      const validCategories = new Set([
        "drain", "access_control", "reentrancy", "oracle_manipulation",
        "erc4626_inflation", "calldata_forwarding", "approval_exploit",
        "flash_loan_attack", "integer_overflow", "selfdestruct",
        "read_only_reentrancy", "fee_on_transfer", "precision_loss",
        "storage_collision", "unchecked_return_value",
      ]);

      const vulnerabilities: LLMVulnerability[] = (data.vulnerabilities ?? [])
        .filter((v) => v.title && v.description)
        .map((v) => ({
          title: v.title!,
          severity: (validSeverities.has(v.severity ?? "") ? v.severity : "medium") as MisconfigSeverity,
          category: (validCategories.has(v.category ?? "") ? v.category : "drain") as RiskClass,
          description: v.description!,
          affectedFunction: v.affectedFunction ?? undefined,
          exploitScenario: v.exploitScenario ?? undefined,
          confidence: typeof v.confidence === "number" ? Math.min(100, Math.max(0, v.confidence)) : 50,
        }));

      return {
        vulnerabilities,
        overallRiskAssessment: data.overallRiskAssessment ?? "No assessment provided",
        confidenceScore: typeof data.confidenceScore === "number"
          ? Math.min(100, Math.max(0, data.confidenceScore))
          : 50,
      };
    } catch {
      return null;
    }
  }
}
