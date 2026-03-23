/**
 * Shared ABI fragments for Sentinel modules
 */

// ─── Chainlink AggregatorV3 ───────────────────────────────────────────────

export const chainlinkAggregatorAbi = [
  {
    type: "function",
    name: "latestRoundData",
    inputs: [],
    outputs: [
      { name: "roundId", type: "uint80" },
      { name: "answer", type: "int256" },
      { name: "startedAt", type: "uint256" },
      { name: "updatedAt", type: "uint256" },
      { name: "answeredInRound", type: "uint80" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "decimals",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
    stateMutability: "view",
  },
] as const;

// ─── ERC-20 ───────────────────────────────────────────────────────────────

export const erc20Abi = [
  {
    type: "function",
    name: "decimals",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "balanceOf",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "totalSupply",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
] as const;

// ─── ERC-4626 ─────────────────────────────────────────────────────────────

export const erc4626Abi = [
  {
    type: "function",
    name: "totalAssets",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "totalSupply",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "convertToAssets",
    inputs: [{ name: "shares", type: "uint256" }],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "convertToShares",
    inputs: [{ name: "assets", type: "uint256" }],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
] as const;

// ─── Euler V2 EVC ─────────────────────────────────────────────────────────

export const evcAbi = [
  {
    type: "function",
    name: "getCollaterals",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "address[]" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getControllers",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "address[]" }],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "AccountStatusCheck",
    inputs: [
      { name: "account", type: "address", indexed: true },
      { name: "controller", type: "address", indexed: true },
    ],
  },
] as const;

// ─── Euler V2 eVault ──────────────────────────────────────────────────────

export const eVaultAbi = [
  {
    type: "function",
    name: "checkLiquidation",
    inputs: [
      { name: "liquidator", type: "address" },
      { name: "violator", type: "address" },
      { name: "collateral", type: "address" },
    ],
    outputs: [
      { name: "maxRepay", type: "uint256" },
      { name: "maxYield", type: "uint256" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "accountLiquidity",
    inputs: [
      { name: "account", type: "address" },
      { name: "liquidation", type: "bool" },
    ],
    outputs: [
      { name: "collateralValue", type: "uint256" },
      { name: "liabilityValue", type: "uint256" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "asset",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "cash",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "hookConfig",
    inputs: [],
    outputs: [
      { name: "hookTarget", type: "address" },
      { name: "hookedOps", type: "uint32" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "LTVFull",
    inputs: [{ name: "collateral", type: "address" }],
    outputs: [
      { name: "borrowLTV", type: "uint16" },
      { name: "liquidationLTV", type: "uint16" },
      { name: "initialLTV", type: "uint16" },
      { name: "targetLTV", type: "uint16" },
      { name: "rampDuration", type: "uint48" },
      { name: "targetTimestamp", type: "uint48" },
    ],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "GovSetLTV",
    inputs: [
      { name: "vault", type: "address", indexed: true },
      { name: "collateral", type: "address", indexed: true },
      { name: "borrowLTV", type: "uint16" },
      { name: "liquidationLTV", type: "uint16" },
      { name: "initialLTV", type: "uint16" },
      { name: "targetLTV", type: "uint16" },
      { name: "rampDuration", type: "uint48" },
    ],
  },
  {
    type: "event",
    name: "GovSetHookConfig",
    inputs: [
      { name: "hookTarget", type: "address" },
      { name: "hookedOps", type: "uint32" },
    ],
  },
] as const;

// ─── Euler V2 AccountLens ─────────────────────────────────────────────────

export const accountLensAbi = [
  {
    type: "function",
    name: "getAccountLiquidity",
    inputs: [
      { name: "account", type: "address" },
      { name: "vault", type: "address" },
    ],
    outputs: [
      { name: "collateralValue", type: "uint256" },
      { name: "liabilityValue", type: "uint256" },
    ],
    stateMutability: "view",
  },
] as const;

// ─── Aave V3 Pool ─────────────────────────────────────────────────────────

export const aaveV3PoolAbi = [
  {
    type: "function",
    name: "getUserAccountData",
    inputs: [{ name: "user", type: "address" }],
    outputs: [
      { name: "totalCollateralBase", type: "uint256" },
      { name: "totalDebtBase", type: "uint256" },
      { name: "availableBorrowsBase", type: "uint256" },
      { name: "currentLiquidationThreshold", type: "uint256" },
      { name: "ltv", type: "uint256" },
      { name: "healthFactor", type: "uint256" },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "liquidationCall",
    inputs: [
      { name: "collateralAsset", type: "address" },
      { name: "debtAsset", type: "address" },
      { name: "user", type: "address" },
      { name: "debtToCover", type: "uint256" },
      { name: "receiveAToken", type: "bool" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

// ─── Owner / Admin detection ──────────────────────────────────────────────

export const ownerAbi = [
  {
    type: "function",
    name: "owner",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
] as const;

export const adminAbi = [
  {
    type: "function",
    name: "admin",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
] as const;

// ─── Gnosis Safe ─────────────────────────────────────────────────────────

export const gnosisSafeAbi = [
  {
    type: "function",
    name: "getThreshold",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getOwners",
    inputs: [],
    outputs: [{ name: "", type: "address[]" }],
    stateMutability: "view",
  },
] as const;
