// Load .env before reading process.env — config.ts is the first evaluated module
import { config as _dotenv } from "dotenv";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";
_dotenv({ path: resolve(dirname(fileURLToPath(import.meta.url)), "../.env"), override: false });

import type { Address } from "viem";
import type { OracleFeedConfig } from "./types.js";

// ─── Thresholds ───────────────────────────────────────────────────────────

export const MIN_NET_PROFIT_USD = Number(process.env["MIN_NET_PROFIT_USD"] ?? "1");
export const MIN_NET_PROFIT_FUNDED_USD = Number(process.env["MIN_NET_PROFIT_FUNDED_USD"] ?? "50");
export const MIN_NET_PROFIT_NEW_CONTRACT_USD = 100;
export const MAX_CAPITAL_PER_EXECUTION_USD = Number(
  process.env["MAX_CAPITAL_PER_EXECUTION_USD"] ?? "5000",
);
export const MAX_CAPITAL_NEW_CONTRACT_USD = 1000;
export const MAX_CAPITAL_TOTAL_DEPLOYED_USD = 10_000;
export const GOVERNANCE_WAR_CHEST_USD = Number(
  process.env["GOVERNANCE_WAR_CHEST_USD"] ?? "500",
);
export const MAX_GAS_BUDGET_PER_DAY_USD = 5;
export const MAX_ANALYSIS_COMPUTE_PER_DAY_CPU_HOURS = 4;

// Oracle thresholds
export const ORACLE_DIVERGENCE_ALERT_PCT = Number(
  process.env["ORACLE_DIVERGENCE_ALERT_PCT"] ?? "2",
);
export const ORACLE_DIVERGENCE_CRITICAL_PCT = Number(
  process.env["ORACLE_DIVERGENCE_CRITICAL_PCT"] ?? "5",
);
export const ORACLE_STALENESS_RATIO_THRESHOLD = Number(
  process.env["ORACLE_STALENESS_RATIO_THRESHOLD"] ?? "5",
);

// Toxicity thresholds
export const TOXICITY_SCORE_BLOCK = Number(process.env["TOXICITY_SCORE_BLOCK"] ?? "50");
export const TOXICITY_SCORE_REDUCE = Number(process.env["TOXICITY_SCORE_REDUCE"] ?? "30");

// Gas abort
export const ABORT_GAS_PRICE_GWEI = 500n;

// Execution
export const MAX_GAS_PER_TX = 3_000_000n;

// ─── Chain ────────────────────────────────────────────────────────────────

export const CHAIN_ID = 1;
/** @deprecated use CHAIN_ID */
export const SONIC_CHAIN_ID = CHAIN_ID;

export const RPC_URL = process.env["RPC_URL_1"] ?? "http://127.0.0.1:8545";
export const WS_URL = process.env["WS_URL_1"];
export const PRIVATE_KEY = process.env["PRIVATE_KEY"] as `0x${string}` | undefined;

// ─── Protocol Contracts ───────────────────────────────────────────────────

/** Euler V2 Ethereum Vault Connector */
export const EULER_EVC: Address = "0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383";

/** Euler V2 Account Lens */
export const EULER_ACCOUNT_LENS: Address = "0x3EA8Ea4237344C9931214796d9417Af1A1180770";

/** Euler V2 Vault Lens (not yet deployed on ETH mainnet — zero address) */
export const EULER_VAULT_LENS: Address = "0x0000000000000000000000000000000000000000";

/** Euler V2 EulerRouter (not yet deployed on ETH mainnet — zero address) */
export const EULER_ROUTER: Address = "0x0000000000000000000000000000000000000000";

/** Euler V2 Governor primary (ETH mainnet — update when known) */
export const EULER_GOVERNOR_PRIMARY: Address = "0x0000000000000000000000000000000000000000";

/** Euler V2 Governor secondary (ETH mainnet — update when known) */
export const EULER_GOVERNOR_SECONDARY: Address = "0x0000000000000000000000000000000000000000";

/** Silo V2 Lens (not deployed on ETH mainnet — zero address) */
export const SILO_LENS: Address = "0x0000000000000000000000000000000000000000";

/** Aave V3 Sonic Pool */
export const AAVE_V3_POOL: Address =
  (process.env["AAVE_V3_POOL"] as Address | undefined) ??
  "0x5362dBb1e601abF3a4c14c22ffEdA64042E5eAA3";

/** Balancer Vault (flash loan source) */
export const BALANCER_VAULT: Address = "0xBA12222222228d8Ba445958a75a0704d566BF2C8";

/** Our liquidator contracts */
export const EULER_LIQUIDATOR_CONTRACT: Address =
  (process.env["EULER_LIQUIDATOR_CONTRACT"] as Address | undefined) ??
  "0x0000000000000000000000000000000000000000";

export const SILO_LIQUIDATION_HELPER: Address =
  (process.env["SILO_LIQUIDATION_HELPER"] as Address | undefined) ??
  "0x0000000000000000000000000000000000000000";

// ─── Token Addresses ─────────────────────────────────────────────────────

export const WETH: Address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
/** @deprecated Sonic-only — kept for reference, not used on Ethereum */
export const WRAPPED_SONIC: Address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
export const USDC: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
export const USDC_E: Address = USDC; // alias — on ETH native USDC is used
export const DAI: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F";
export const USDT: Address = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
export const MORPHO_BLUE: Address = "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb";

// ─── Oracle Feed Configurations ───────────────────────────────────────────

export const ORACLE_FEEDS: OracleFeedConfig[] = [
  {
    name: "ETH/USD",
    feedAddress: "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
    type: "chainlink",
    maxStalenessSeconds: 3_600,
    heartbeatSeconds: 3600,
    baseToken: WETH,
    quoteToken: USDC,
  },
  {
    name: "DAI/USD",
    feedAddress: "0xAed0c38402a5d19df6E4c03F4E2DceD6e29c1ee9",
    type: "chainlink",
    maxStalenessSeconds: 3_600,
    heartbeatSeconds: 3600,
    baseToken: DAI,
    quoteToken: USDC,
  },
  {
    name: "USDT/USD",
    feedAddress: "0x3E7d1eAB13ad0104d2750B8863b489D65364e32D",
    type: "chainlink",
    maxStalenessSeconds: 90_000,
    heartbeatSeconds: 86400,
    baseToken: USDT,
    quoteToken: USDC,
  },
];

// ─── Toxic Collateral Blacklist ────────────────────────────────────────────

// Ethereum mainnet: no known toxic collateral to blacklist by default.
// Add addresses here as new risk vectors are identified.
export const TOXIC_COLLATERAL_BLACKLIST: Set<Address> = new Set<Address>();

// ─── Known Governance Event Topics ───────────────────────────────────────

export const TOPIC_GOV_SET_LTV =
  "0xc69392046c26324e9eee913208811542aabcbde6a41ce9ee3b45473b18eb3c76" as const;

export const TOPIC_GOV_SET_HOOK_CONFIG =
  "0xabadffb695acdb6863cd1324a91e5c359712b9110a55f9103774e2fb67dedb6a" as const;

export const TOPIC_EULER_ROUTER_CONFIG_SET =
  "0x4ac83f39568b63f952374c82351889b07aff4f7e261232a20ba5a2a6d82b9ce0" as const;

// ─── Toolchain Paths ──────────────────────────────────────────────────────

export const TOOLCHAIN = {
  heimdall: process.env["HEIMDALL_PATH"] ?? "/home/cr0wn/.cargo/bin/heimdall",
  anvil: process.env["ANVIL_PATH"] ?? "/home/cr0wn/.local/bin/anvil",
  cast: process.env["CAST_PATH"] ?? "/home/cr0wn/.local/bin/cast",
  halmos: process.env["HALMOS_PATH"] ?? "halmos",
  echidna: process.env["ECHIDNA_PATH"] ?? "echidna",
  mythril: process.env["MYTHRIL_PATH"] ?? "myth",
  slither: process.env["SLITHER_PATH"] ?? "slither",
} as const;

// ─── Utility ────────────────────────────────────────────────────────────

/** Returns true if the address is set to a non-zero value. */
export function isConfigured(address: Address): boolean {
  return address !== "0x0000000000000000000000000000000000000000";
}

// ─── Feature Flags ────────────────────────────────────────────────────────

export const FEATURES = {
  oracleHunter: process.env["ENABLE_ORACLE_HUNTER"] !== "false",
  govShock: process.env["ENABLE_GOV_SHOCK"] !== "false",
  killList: process.env["ENABLE_KILL_LIST"] !== "false",
  misconfigSniper: process.env["ENABLE_MISCONFIG_SNIPER"] !== "false",
  deployMonitor: process.env["ENABLE_DEPLOY_MONITOR"] !== "false",
  staticAnalysis: process.env["ENABLE_STATIC_ANALYSIS"] !== "false",
  symbolicExec: process.env["ENABLE_SYMBOLIC_EXEC"] === "true",
  fuzzing: process.env["ENABLE_FUZZING"] === "true",
  massAudit: process.env["ENABLE_MASS_AUDIT"] === "true",
  massAuditEthereum: process.env["ENABLE_MASS_AUDIT_ETHEREUM"] === "true",
  massAuditSonic: process.env["ENABLE_MASS_AUDIT_SONIC"] !== "false",
  llmAnalysis: process.env["ENABLE_LLM_ANALYSIS"] === "true",
  diffCompiler: process.env["ENABLE_DIFF_COMPILER"] === "true",
  evmAnalysis: process.env["ENABLE_EVM_ANALYSIS"] !== "false",
} as const;

// ─── Discord Webhook ──────────────────────────────────────────────────────

export const DISCORD_WEBHOOK_URL = process.env["DISCORD_WEBHOOK_URL"];

// ─── Log Paths ────────────────────────────────────────────────────────────

export const LOG_DIR = process.env["LOG_DIR"] ?? "./logs";
export const LIQUIDATION_LOG_PATH = `${LOG_DIR}/liquidations.jsonl`;
export const ANALYSIS_LOG_PATH = `${LOG_DIR}/analysis.jsonl`;
export const ALERT_LOG_PATH = `${LOG_DIR}/alerts.jsonl`;

// ─── Multicall3 ───────────────────────────────────────────────────────────

export const MULTICALL3: Address = "0xcA11bde05977b3631167028862bE2a173976CA11";

// ─── Known Vulnerable Function Selectors ─────────────────────────────────

export const VULNERABLE_SELECTORS: Record<string, string> = {
  "0x5acc7e": "donate",
  "0x3af9e": "donateToReserves",
  "0x3d18b9": "leverage",
  "0x28b8ae1": "openLeverage",
  "0x2d2da80c": "zap",
  "0x5cffe9de": "flashLoan",
  "0x5c3d14": "flashBorrow",
  "0xac9650d8": "multicall",
  "0x82ad56cb": "aggregate",
  "0x24d7806c": "execute",
  "0x3659cfe6": "upgradeTo",
  "0x4f1ef286": "upgradeToAndCall",
  "0x76ca3a82": "setOracle",
  "0x9d1b464a": "setPriceFeed",
};

// ─── OpenOcean Quote API ──────────────────────────────────────────────────

export const OPENOCEAN_API_BASE = "https://open-api.openocean.finance/v3/eth";

// ─── Known Sonic Factory Addresses ────────────────────────────────────────

export const KNOWN_FACTORY_ADDRESSES: Address[] = [
  "0x1F98431c8aD98523631AE4a59f267346ea31F984", // Uniswap V3 Factory
  "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", // Uniswap V2 Factory
  "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", // Aave V3 Pool
  "0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb", // Morpho Blue
];

// ─── ERC-4626 Inflation Attack Thresholds ────────────────────────────────

export const ERC4626_TOTAL_SUPPLY_DUST_THRESHOLD = 1000n;

// ─── Mass Audit Pipeline ─────────────────────────────────────────────

export const MASS_AUDIT_INTERVAL_MS = Number(
  process.env["MASS_AUDIT_INTERVAL_MS"] ?? String(30 * 60 * 1000),
);

export const MASS_AUDIT_MAX_PER_RUN = Number(
  process.env["MASS_AUDIT_MAX_PER_RUN"] ?? "50",
);

export const MASS_AUDIT_LLM_RISK_THRESHOLD = Number(
  process.env["MASS_AUDIT_LLM_RISK_THRESHOLD"] ?? "40",
);

// ─── Block Explorer API Keys ────────────────────────────────────────

export const ETHERSCAN_API_KEY = process.env["ETHERSCAN_API_KEY"];
export const SONICSCAN_API_KEY = process.env["SONICSCAN_API_KEY"];

// ─── Claude CLI Path ────────────────────────────────────────────────

export const CLAUDE_CLI_PATH = process.env["CLAUDE_CLI_PATH"] ?? "claude";

// ─── Known DeFi Factories (Ethereum) ────────────────────────────────

export const KNOWN_ETH_FACTORY_ADDRESSES: Address[] = [
  "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", // Uniswap V2 Factory
  "0x1F98431c8aD98523631AE4a59f267346ea31F984", // Uniswap V3 Factory
  "0xBBa1e1291Cf0c20fCA0850Eb8C44835DfC27AD2a", // Morpho Blue
  "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", // Aave V3 Pool (ETH)
];
