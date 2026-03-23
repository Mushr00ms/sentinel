/**
 * Unified EVM Bytecode Analysis Engine
 *
 * Orchestrates: disassemble → CFG → abstract states → taint → value flow
 *               → storage layout → cross-contract flow
 *
 * Single entry point for the entire custom EVM analysis pipeline.
 */

import type { Hex } from "viem";
import { disassemble, containsOpcode } from "./disassembler.js";
import type { DisassemblyResult, EVMInstruction } from "./disassembler.js";
import { buildCFG } from "./cfg.js";
import type { ControlFlowGraph, BasicBlock } from "./cfg.js";
import { computeAbstractStates } from "./abstractStack.js";
import type { AbstractState, AbstractValue } from "./abstractStack.js";
import { runTaintAnalysis } from "./taintAnalysis.js";
import type { TaintAnalysisResult, TaintFlow, TaintSource, TaintSink } from "./taintAnalysis.js";
import { traceValueFlows } from "./valueFlow.js";
import type { ValueFlowGraph, ValueTransfer, UnconditionalDrain } from "./valueFlow.js";
import { analyzeStorageLayout } from "./storageLayout.js";
import type { StorageLayoutResult, StorageSlotInfo, StorageCollision } from "./storageLayout.js";
import { analyzeCrossContractFlows } from "./crossContractFlow.js";
import type { CrossContractFlowResult, CrossContractCall } from "./crossContractFlow.js";

// ─── Re-exports ───────────────────────────────────────────────────────────

export type {
  EVMInstruction, DisassemblyResult,
  BasicBlock, ControlFlowGraph,
  AbstractValue, AbstractState,
  TaintSource, TaintSink, TaintFlow, TaintAnalysisResult,
  ValueTransfer, UnconditionalDrain, ValueFlowGraph,
  StorageSlotInfo, StorageCollision, StorageLayoutResult,
  CrossContractCall, CrossContractFlowResult,
};

export { disassemble, containsOpcode, buildCFG, computeAbstractStates, runTaintAnalysis, traceValueFlows, analyzeStorageLayout, analyzeCrossContractFlows };

// ─── Unified Result ───────────────────────────────────────────────────────

export interface EVMAnalysisResult {
  /** Raw disassembly. */
  disassembly: DisassemblyResult;
  /** Control flow graph with function dispatcher detection. */
  cfg: ControlFlowGraph;
  /** Abstract stack states per block. */
  abstractStates: Map<number, AbstractState>;
  /** Taint flow analysis: user-input to sinks. */
  taint: TaintAnalysisResult;
  /** Value (ETH/token) flow tracing. */
  valueFlow: ValueFlowGraph;
  /** Storage slot analysis. */
  storageLayout: StorageLayoutResult;
  /** Cross-contract call analysis. */
  crossContractFlow: CrossContractFlowResult;
  /** Analysis timing in ms. */
  analysisTimeMs: number;
  /** Number of instructions analyzed. */
  instructionCount: number;
  /** Number of basic blocks. */
  blockCount: number;
  /** Detected function selectors. */
  selectors: string[];
}

// ─── Main Pipeline ────────────────────────────────────────────────────────

/**
 * Runs the full EVM bytecode analysis pipeline.
 *
 * Pipeline: disassemble → CFG → abstract stack → taint → value flow
 *           → storage layout → cross-contract flow
 */
export function analyzeEVMBytecode(bytecode: Hex | string): EVMAnalysisResult {
  const startMs = Date.now();

  // Step 1: Disassemble
  const disassembly = disassemble(bytecode);

  // Step 2: Build CFG
  const cfg = buildCFG(disassembly);

  // Step 3: Abstract stack interpretation
  const abstractStates = computeAbstractStates(cfg);

  // Step 4: Taint analysis
  const taint = runTaintAnalysis(cfg, abstractStates);

  // Step 5: Value flow tracing
  const valueFlow = traceValueFlows(cfg, abstractStates);

  // Step 6: Storage layout analysis
  const storageLayout = analyzeStorageLayout(cfg, abstractStates, taint);

  // Step 7: Cross-contract flow analysis
  const crossContractFlow = analyzeCrossContractFlows(cfg, abstractStates);

  return {
    disassembly,
    cfg,
    abstractStates,
    taint,
    valueFlow,
    storageLayout,
    crossContractFlow,
    analysisTimeMs: Date.now() - startMs,
    instructionCount: disassembly.instructions.length,
    blockCount: cfg.blocks.size,
    selectors: Array.from(cfg.selectorToBlock.keys()),
  };
}
