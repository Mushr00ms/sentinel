import type { Address, Hash, Hex } from "viem";

// ─── Core ─────────────────────────────────────────────────────────────────

export type ChainId = 146 | 1; // Sonic + Ethereum mainnet

export type SupportedChain = "sonic" | "ethereum";

export interface BlockContext {
  blockNumber: bigint;
  blockTimestamp: number;
  baseFeePerGas: bigint;
}

// ─── Oracle ───────────────────────────────────────────────────────────────

export type OracleFeedType = "chainlink" | "redstone" | "pyth" | "crossadapter";

export interface OracleFeedConfig {
  name: string;
  feedAddress: Address;
  type: OracleFeedType;
  maxStalenessSeconds: number;
  heartbeatSeconds: number;
  baseToken: Address;
  quoteToken: Address;
  vault?: Address; // Euler vault using this oracle
}

export interface OracleFeedState {
  config: OracleFeedConfig;
  onChainPrice: bigint; // 18-decimal normalized
  lastUpdatedAt: number; // unix timestamp
  roundId: bigint;
  stalenessSeconds: number;
  stalenessRatio: number; // staleness / heartbeat
}

export interface DexQuote {
  inputToken: Address;
  outputToken: Address;
  inputAmount: bigint;
  outputAmount: bigint;
  pricePerUnit: number; // output/input in USD
  source: "openocean" | "kyberswap" | "1inch";
  timestamp: number;
}

export interface OracleDivergenceAlert {
  severity: "alert" | "critical";
  feedConfig: OracleFeedConfig;
  oraclePrice: number; // USD
  dexPrice: number; // USD
  divergencePct: number;
  stalenessRatio: number;
  affectedVault: Address;
  phantomHealthyPositions: PhantomHealthyPosition[];
  detectedAt: number;
}

export interface PhantomHealthyPosition {
  account: Address;
  borrowVault: Address;
  collateralVault: Address;
  healthFactorAtOracle: number;
  healthFactorAtDex: number;
  estimatedProfitUsd: number;
}

// ─── Governance ───────────────────────────────────────────────────────────

export interface GovSetLTVEvent {
  vault: Address;
  collateral: Address;
  borrowLTV: number; // basis points / 1e4
  liquidationLTV: number;
  initialLTV: number;
  targetLTV: number;
  rampDuration: number; // seconds
  txHash: Hash;
  blockNumber: bigint;
  blockTimestamp: number;
}

export interface GovSetHookConfigEvent {
  vault: Address;
  hookTarget: Address;
  hookedOps: number;
  txHash: Hash;
  blockNumber: bigint;
}

export interface GovernanceAlert {
  type: "ltv_reduction" | "hook_change" | "oracle_change" | "unpause";
  event: GovSetLTVEvent | GovSetHookConfigEvent;
  affectedPositions: GovernanceAffectedPosition[];
  immediateAction: boolean; // true if rampDuration == 0
  estimatedTotalProfitUsd: number;
  detectedAt: number;
}

export interface GovernanceAffectedPosition {
  account: Address;
  borrowVault: Address;
  collateralVault: Address;
  currentHF: number;
  hfAtNewLTV: number;
  becomesLiquidatableAtBlock: bigint;
  estimatedProfitUsd: number;
}

// ─── Position Kill List ────────────────────────────────────────────────────

export type PositionTier = 0 | 1 | 2 | 3;
export type ProtocolId = "euler-v2" | "silo-v2" | "aave-v3" | "morpho-blue";

export interface TrackedPosition {
  id: string; // "${account}:${protocol}:${market}"
  account: Address;
  protocol: ProtocolId;
  borrowVault: Address;
  collateralVault: Address;
  borrowAsset: Address;
  collateralAsset: Address;
  tier: PositionTier;
  healthFactor: number;
  estimatedProfitUsd: number;
  profitDensityScore: number;
  toxicityScore: number;
  collateralExitValidated: boolean;
  lastUpdatedAt: number;
  lastUpdatedBlock: bigint;
  blockers: PositionBlocker[];
}

export type PositionBlockerType =
  | "hook_pause"
  | "oracle_block"
  | "toxic_collateral"
  | "insufficient_liquidity"
  | "blacklisted";

export interface PositionBlocker {
  type: PositionBlockerType;
  detail: string;
}

export interface ToxicityResult {
  score: number;
  verdict: "full" | "reduced" | "blocked";
  reasons: string[];
  reducedSizePct?: number;
}

// ─── Collateral Exit Validation ────────────────────────────────────────────

export interface CollateralExitValidation {
  ok: boolean;
  failReason?: string;
  dexQuoteAvailable: boolean;
  oracleDexDivergencePct: number;
  priceImpactPct: number;
  availableCash: bigint;
  recommendedSize: "full" | "half" | "skip";
}

// ─── Misconfig Sniper ─────────────────────────────────────────────────────

export type MisconfigSeverity = "critical" | "high" | "medium" | "low";
export type MisconfigClass =
  | "admin_eoa"
  | "weak_multisig"
  | "calldata_forwarding"
  | "erc4626_inflation"
  | "approval_honeypot"
  | "unvalidated_calldata";

export interface MisconfigFinding {
  id: string;
  severity: MisconfigSeverity;
  class: MisconfigClass;
  contractAddress: Address;
  protocolName?: string;
  description: string;
  affectedFunction?: string;
  estimatedRiskUsd?: number;
  detectedAt: number;
  raw?: Record<string, unknown>;
}

// ─── New Deployment Monitor ────────────────────────────────────────────────

export interface NewDeployment {
  contractAddress: Address;
  deployerAddress: Address;
  txHash: Hash;
  blockNumber: bigint;
  blockTimestamp: number;
  bytecodeSize: number;
  isProxy: boolean;
  implementationAddress?: Address;
  fundHandling: FundHandlingClassification;
}

export interface FundHandlingClassification {
  isFundHandling: boolean;
  hasPayable: boolean;
  hasERC20Transfers: boolean;
  hasApprovals: boolean;
  hasDelegatecall: boolean;
  hasMint: boolean;
  hasBurn: boolean;
  confidence: number; // 0-100
}

// ─── Static Analysis ──────────────────────────────────────────────────────

export type RiskClass =
  | "drain"
  | "access_control"
  | "reentrancy"
  | "oracle_manipulation"
  | "erc4626_inflation"
  | "calldata_forwarding"
  | "approval_exploit"
  | "flash_loan_attack"
  | "integer_overflow"
  | "selfdestruct"
  | "read_only_reentrancy"
  | "fee_on_transfer"
  | "precision_loss"
  | "storage_collision"
  | "unchecked_return_value";

export interface StaticAnalysisFinding {
  riskClass: RiskClass;
  severity: MisconfigSeverity;
  functionSelector: Hex;
  functionName?: string;
  description: string;
  callPath?: string[];
  confidence: number; // 0-100
}

export interface StaticAnalysisReport {
  contractAddress: Address;
  analysisTimestamp: number;
  riskScore: number; // 0-100
  proxyType?: "eip1967" | "eip1167" | "diamond" | "transparent" | "uups" | "unknown";
  implementationAddress?: Address;
  adminAddress?: Address;
  adminIsEOA?: boolean;
  functions: DecompiledFunction[];
  findings: StaticAnalysisFinding[];
  approvalGraph: ApprovalNode[];
  externalCallGraph: ExternalCall[];
  /** EVM bytecode analysis result (when EVM engine is enabled). */
  evmAnalysis?: EVMAnalysisResultRef;
  /** Exploit pattern matches from historical corpus. */
  exploitPatternMatches?: ExploitPatternMatchRef[];
}

/** Lightweight reference to EVM analysis result (avoids circular import). */
export interface EVMAnalysisResultRef {
  analysisTimeMs: number;
  instructionCount: number;
  blockCount: number;
  selectors: string[];
  taintFlowCount: number;
  highSeverityTaintFlows: boolean;
  unconditionalDrainCount: number;
  storageSlotCount: number;
  isUpgradeableProxy: boolean;
  externalCallCount: number;
}

export interface ExploitPatternMatchRef {
  patternId: string;
  patternName: string;
  protocol: string;
  lossAmountUsd: number;
  matchScore: number;
  matchedConditions: string[];
  description: string;
}

export interface DecompiledFunction {
  selector: Hex;
  name?: string;
  isPayable: boolean;
  hasExternalCall: boolean;
  hasDelegatecall: boolean;
  hasStorageWrite: boolean;
  hasAccessControl: boolean;
}

export interface ApprovalNode {
  approvedContract: Address;
  approvedToken: Address;
  canBeTriggeredBy: "anyone" | "owner" | "unknown";
  calldataValidated: boolean;
}

export interface ExternalCall {
  fromFunction: Hex;
  targetType: "fixed" | "storage" | "user_controlled";
  target?: Address;
  calldataValidated: boolean;
  valueTransferred: boolean;
}

// ─── Symbolic Execution ───────────────────────────────────────────────────

export interface SymbolicExecConfig {
  contractAddress: Address;
  timeout: number; // seconds
  properties: SymbolicProperty[];
}

export interface SymbolicProperty {
  name: string;
  description: string;
  invariant: string; // Solidity expression
}

export type SymbolicExecStatus = "running" | "completed" | "timeout" | "failed";

export interface SymbolicExecResult {
  contractAddress: Address;
  status: SymbolicExecStatus;
  duration: number;
  violations: PropertyViolation[];
  pathsExplored: number;
}

export interface PropertyViolation {
  property: string;
  violatingInput: Hex;
  description: string;
  estimatedDrainAmount?: bigint;
}

// ─── Fuzzing ──────────────────────────────────────────────────────────────

export type FuzzCampaignType =
  | "balance_drain"
  | "access_escalation"
  | "reentrancy"
  | "integer_overflow"
  | "flash_loan";

export interface FuzzCampaignConfig {
  contractAddress: Address;
  campaignType: FuzzCampaignType;
  rounds: number;
  timeout: number; // seconds
  corpusSeed?: Hex[]; // known exploit calldata
}

export interface FuzzCampaignResult {
  contractAddress: Address;
  campaignType: FuzzCampaignType;
  status: "completed" | "timeout" | "finding" | "failed";
  rounds: number;
  duration: number;
  finding?: FuzzFinding;
}

export interface FuzzFinding {
  campaignType: FuzzCampaignType;
  violatingCallsequence: FuzzCall[];
  description: string;
  estimatedProfit?: bigint;
}

export interface FuzzCall {
  functionSelector: Hex;
  args: unknown[];
  value?: bigint;
  sender: Address;
}

// ─── Exploit Builder (Analysis / PoC) ─────────────────────────────────────

export type ExploitClass =
  | "fund_drain"
  | "price_manipulation"
  | "access_control_bypass"
  | "griefing_dos";

export interface ExploitFinding {
  id: string;
  contractAddress: Address;
  exploitClass: ExploitClass;
  severity: "critical" | "high" | "medium" | "low";
  origin: "static_analysis" | "symbolic_exec" | "fuzzing";
  estimatedGrossProfitUsd: number;
  capitalRequiredUsd: number;
  isAtomic: boolean;
  isFlashLoanable: boolean;
  forkValidated: boolean;
  forkNetProfitUsd?: number;
  pocCalldata?: Hex;
  description: string;
  detectedAt: number;
  requiresManualReview: boolean; // always true for new contract exploits
}

// ─── Re-Analysis ──────────────────────────────────────────────────────────

export interface AnalyzedContract {
  address: Address;
  firstAnalyzedAt: number;
  lastAnalyzedAt: number;
  riskScore: number;
  tvlUsd: number;
  findings: StaticAnalysisFinding[];
  proxyImplementation?: Address;
  scheduledForReanalysis: boolean;
  reanalysisReason?: string;
}

// ─── Execution ────────────────────────────────────────────────────────────

export interface PreStagedLiquidation {
  id: string;
  account: Address;
  protocol: ProtocolId;
  borrowVault: Address;
  collateralVault: Address;
  repayAmount: bigint;
  minYield: bigint;
  estimatedProfitUsd: number;
  calldata: Hex;
  validUntilBlock: bigint;
  builtAt: number;
}

export interface ExecutionResult {
  status: "success" | "reverted" | "failed";
  txHash?: Hash;
  netProfitUsd?: number;
  gasUsed?: bigint;
  gasUsd?: number;
  errorClass?: "nonce" | "rpc" | "revert" | "config" | "unknown";
  reason?: string;
}

// ─── Alerts / Logging ─────────────────────────────────────────────────────

export type AlertSeverity = "info" | "warning" | "alert" | "critical";

export interface SentinelAlert {
  severity: AlertSeverity;
  module: string;
  title: string;
  body: string;
  timestamp: number;
  data?: unknown;
}

// ─── Block Explorer Scraping ─────────────────────────────────────────────

export interface ExplorerContractEntry {
  address: Address;
  chain: SupportedChain;
  name?: string;
  compilerVersion?: string;
  optimizationUsed?: boolean;
  sourceCode?: string;
  abi?: string;
  isVerified: boolean;
  implementationAddress?: Address;
  deployTxHash?: Hash;
  deployBlockNumber?: bigint;
  scrapedAt: number;
}

// ─── Contract Classification ─────────────────────────────────────────────

export type ContractCategory =
  | "erc20"
  | "amm_dex"
  | "lending"
  | "vault_yield"
  | "bridge"
  | "staking"
  | "governance"
  | "nft"
  | "unknown";

export interface ContractClassification {
  address: Address;
  chain: SupportedChain;
  category: ContractCategory;
  confidence: number;
  isDeFi: boolean;
  detectedInterfaces: string[];
  classifiedAt: number;
}

// ─── LLM Analysis ────────────────────────────────────────────────────────

export interface LLMAnalysisResult {
  contractAddress: Address;
  chain: SupportedChain;
  vulnerabilities: LLMVulnerability[];
  overallRiskAssessment: string;
  confidenceScore: number;
  analyzedAt: number;
  analysisTimeMs: number;
}

export interface LLMVulnerability {
  title: string;
  severity: MisconfigSeverity;
  category: RiskClass;
  description: string;
  affectedFunction?: string;
  exploitScenario?: string;
  confidence: number;
}

// ─── Slither Findings ────────────────────────────────────────────────────

export interface SlitherFinding {
  check: string;
  impact: "High" | "Medium" | "Low" | "Informational";
  confidence: "High" | "Medium" | "Low";
  description: string;
  elements: string[];
}

// ─── Mass Audit Pipeline ─────────────────────────────────────────────────

export type AuditStatus =
  | "queued"
  | "scraping"
  | "classifying"
  | "static_analysis"
  | "slither_analysis"
  | "llm_analysis"
  | "prioritizing"
  | "completed"
  | "failed";

export interface MassAuditTarget {
  id: string;
  address: Address;
  chain: SupportedChain;
  status: AuditStatus;
  explorerEntry?: ExplorerContractEntry;
  classification?: ContractClassification;
  staticReport?: StaticAnalysisReport;
  slitherFindings?: SlitherFinding[];
  llmResult?: LLMAnalysisResult;
  selectorCollisions?: SelectorCollisionFinding[];
  aiFingerprint?: AiFingerprintResult;
  tvlUsd: number;
  deployedAt?: number; // unix timestamp from explorer
  priorityScore: number;
  enqueuedAt: number;
  completedAt?: number;
  errorMessage?: string;
}

export interface AuditPipelineStats {
  totalQueued: number;
  totalCompleted: number;
  totalFailed: number;
  highRiskCount: number;
  mediumRiskCount: number;
  lastRunAt: number;
  lastRunDurationMs: number;
}

// ─── Cross-Contract Composition Analysis ────────────────────────────────

export type InteractionType =
  | "external_call"
  | "delegatecall"
  | "oracle_read"
  | "approval_grant"
  | "callback"
  | "flash_loan"
  | "price_feed"
  | "token_transfer";

export interface ContractEdge {
  from: Address;
  to: Address;
  interaction: InteractionType;
  functionSelector?: Hex;
  functionName?: string;
  confidence: number;
  bidirectional: boolean;
}

export interface ContractNode {
  address: Address;
  chain: SupportedChain;
  category?: ContractCategory;
  tvlUsd: number;
  riskScore: number;
  inDegree: number;
  outDegree: number;
  dependencyDepth: number;
}

export type ComposabilityRiskClass =
  | "cross_contract_reentrancy"
  | "shared_oracle_manipulation"
  | "approval_chain_exploit"
  | "flash_loan_cascade"
  | "callback_hijack"
  | "dependency_rug"
  | "price_feed_cascade"
  | "shared_state_corruption"
  | "transitive_calldata_forwarding"
  | "delegatecall_storage_corruption";

export interface ComposabilityFinding {
  id: string;
  riskClass: ComposabilityRiskClass;
  severity: MisconfigSeverity;
  description: string;
  involvedContracts: Address[];
  attackPath: Address[];
  estimatedImpactUsd: number;
  confidence: number;
  detectedAt: number;
}

export interface CompositionGraph {
  nodes: Map<Address, ContractNode>;
  edges: ContractEdge[];
  findings: ComposabilityFinding[];
  analyzedAt: number;
  analysisTimeMs: number;
}

// ─── Selector Collision Detection ────────────────────────────────────────

export interface SelectorCollisionFinding {
  selector: Hex;
  contractFunction: string;
  collidingFunction: string;
  collidingContract?: Address;
  riskReason: string;
  severity: MisconfigSeverity;
  confidence: number;
}

// ─── AI Code Fingerprinting ───────────────────────────────────────────────

export type AiCodePattern =
  | "flat_owner_access_control"
  | "unchecked_arithmetic"
  | "missing_cross_function_reentrancy_guard"
  | "uninitialised_initializer"
  | "predictable_variable_naming"
  | "copy_paste_oz_pattern"
  | "missing_zero_address_check"
  | "no_event_on_state_change";

export interface AiFingerprintResult {
  isLikelyAiGenerated: boolean;
  confidence: number;
  patterns: AiCodePattern[];
  riskBoost: number; // additional points added to riskScore
  detectedAt: number;
}

// ─── Upgrade Path Monitor ─────────────────────────────────────────────────

export interface UpgradeAlert {
  proxyAddress: Address;
  chain: SupportedChain;
  previousImpl?: Address;
  newImpl: Address;
  txHash: Hash;
  blockNumber: bigint;
  diffFindings: UpgradeDiffFinding[];
  severity: MisconfigSeverity;
  detectedAt: number;
}

export type UpgradeDiffClass =
  | "new_selfdestruct"
  | "new_delegatecall"
  | "removed_access_control"
  | "new_external_call_target"
  | "removed_function"
  | "added_function"
  | "storage_layout_change";

export interface UpgradeDiffFinding {
  diffClass: UpgradeDiffClass;
  selector?: Hex;
  functionName?: string;
  description: string;
  severity: MisconfigSeverity;
}
