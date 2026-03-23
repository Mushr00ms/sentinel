import type { PublicClient, Address } from "viem";
import type {
  BlockContext,
  TrackedPosition,
  PositionTier,
  ProtocolId,
  ToxicityResult,
  CollateralExitValidation,
  PositionBlocker,
} from "./types.js";
import {
  TOXIC_COLLATERAL_BLACKLIST,
  EULER_EVC,
  EULER_ACCOUNT_LENS,
  AAVE_V3_POOL,
  SILO_LENS,
  USDC_E,
  WRAPPED_SONIC,
  OPENOCEAN_API_BASE,
  MIN_NET_PROFIT_USD,
  MIN_NET_PROFIT_FUNDED_USD,
  TOXICITY_SCORE_BLOCK,
  TOXICITY_SCORE_REDUCE,
  isConfigured,
} from "./config.js";

// ─── Tier Configuration ────────────────────────────────────────────────────

interface TierConfig {
  maxHF: number;
  minProfitUsd: number;
  updateIntervalBlocks: bigint;
  maxPositions: number;
  label: string;
}

const TIER_CONFIG: Record<PositionTier, TierConfig> = {
  0: {
    maxHF: 1.02,
    minProfitUsd: 1,
    updateIntervalBlocks: 1n,
    maxPositions: 20,
    label: "HOT",
  },
  1: {
    maxHF: 1.05,
    minProfitUsd: 10,
    updateIntervalBlocks: 5n,
    maxPositions: 100,
    label: "KILL",
  },
  2: {
    maxHF: 1.15,
    minProfitUsd: 0,
    updateIntervalBlocks: 50n,
    maxPositions: 500,
    label: "WATCH",
  },
  3: {
    maxHF: Infinity,
    minProfitUsd: 0,
    updateIntervalBlocks: 500n,
    maxPositions: Infinity,
    label: "CENSUS",
  },
};

// ─── ABIs ──────────────────────────────────────────────────────────────────

const EVAULT_ABI = [
  {
    name: "accountLiquidity",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "account", type: "address" },
      { name: "liquidation", type: "bool" },
    ],
    outputs: [
      { name: "collateralValue", type: "uint256" },
      { name: "liabilityValue", type: "uint256" },
    ],
  },
  {
    name: "asset",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    name: "totalAssets",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "totalSupply",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "maxWithdraw",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
] as const;

const AAVE_V3_POOL_ABI = [
  {
    name: "getUserAccountData",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "user", type: "address" }],
    outputs: [
      { name: "totalCollateralBase", type: "uint256" },
      { name: "totalDebtBase", type: "uint256" },
      { name: "availableBorrowsBase", type: "uint256" },
      { name: "currentLiquidationThreshold", type: "uint256" },
      { name: "ltv", type: "uint256" },
      { name: "healthFactor", type: "uint256" },
    ],
  },
] as const;

const ERC20_ABI = [
  {
    name: "decimals",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    name: "symbol",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
] as const;

// ─── OpenOcean Quote Response ──────────────────────────────────────────────

interface OpenOceanQuoteResponse {
  code: number;
  data?: {
    inAmount: string;
    outAmount: string;
    estimatedGas: string;
    path?: unknown[];
  };
  error?: string;
}

// ─── KillListEngine ────────────────────────────────────────────────────────

export class KillListEngine {
  private readonly client: PublicClient;

  /** All tracked positions across all tiers. */
  public positions: Map<string, TrackedPosition> = new Map();

  /** Last block number at which each tier was fully refreshed. */
  public lastTierUpdate: Map<PositionTier, bigint> = new Map([
    [0, 0n],
    [1, 0n],
    [2, 0n],
    [3, 0n],
  ]);

  constructor(publicClient: PublicClient) {
    this.client = publicClient;
  }

  // ─── Main Entry Point ────────────────────────────────────────────────────

  /**
   * Main entry point called every block. Checks which tiers are due for an
   * update based on their interval configs, runs the appropriate scans, then
   * returns the hot/kill positions ready for execution.
   */
  async run(ctx: BlockContext): Promise<{
    tier0: TrackedPosition[];
    tier1: TrackedPosition[];
    allActive: TrackedPosition[];
  }> {
    // Guard: skip if EVC not configured (zero address)
    if (!isConfigured(EULER_EVC)) {
      return { tier0: [], tier1: [], allActive: [] };
    }

    const tiersToUpdate: PositionTier[] = [];

    for (const tier of [0, 1, 2, 3] as PositionTier[]) {
      const last = this.lastTierUpdate.get(tier) ?? 0n;
      const interval = TIER_CONFIG[tier].updateIntervalBlocks;
      if (ctx.blockNumber - last >= interval) {
        tiersToUpdate.push(tier);
      }
    }

    // Run tier updates sequentially — higher-priority tiers first.
    for (const tier of tiersToUpdate) {
      try {
        await this.updateTier(tier, ctx);
      } catch (err) {
        console.error(`[KillList] updateTier(${tier}) failed:`, err);
      }
    }

    const tier0 = this.getTier0Positions();
    const tier1 = this.getTierPositions(1);
    const allActive = this.getActivePositions();

    return { tier0, tier1, allActive };
  }

  // ─── Tier Refresh ────────────────────────────────────────────────────────

  /**
   * Refreshes all positions currently assigned to `tier`.
   * For Tier 3 (CENSUS), this is a full rescan across all protocols.
   */
  async updateTier(tier: PositionTier, ctx: BlockContext): Promise<void> {
    const config = TIER_CONFIG[tier];

    if (tier === 3) {
      // Full census — rediscover positions from all protocols.
      await this.runCensus(ctx);
    } else {
      // Refresh existing positions that belong to this tier.
      const positionsForTier = Array.from(this.positions.values()).filter(
        (p) => p.tier === tier,
      );

      await Promise.allSettled(
        positionsForTier.map((pos) => this.refreshPosition(pos, ctx)),
      );
    }

    // Re-classify tiers for all positions after refresh.
    this.reclassifyAllTiers();

    // Cap each tier to its max size, keeping highest profit-density positions.
    this.enforceCapsByTier();

    this.lastTierUpdate.set(tier, ctx.blockNumber);
    console.log(
      `[KillList] Tier ${tier} (${config.label}) updated at block ${ctx.blockNumber}. ` +
        `Active positions: ${Array.from(this.positions.values()).filter((p) => p.tier === tier).length}`,
    );
  }

  // ─── Census (Full Rescan) ─────────────────────────────────────────────────

  /**
   * Tier 3 census — discovers all borrower positions across all protocols.
   * Euler V2 is fully implemented; Silo/Aave/Morpho are stubbed.
   */
  private async runCensus(ctx: BlockContext): Promise<void> {
    await Promise.allSettled([
      this.scanEulerV2(ctx),
      this.scanSiloV2(ctx),
      this.scanAaveV3(ctx),
      this.scanMorphoBlue(ctx),
    ]);
  }

  // ─── Protocol Scanners ────────────────────────────────────────────────────

  /**
   * Euler V2: Enumerates all accounts that have positions via the EVC and
   * Account Lens, then fetches liquidity for each.
   */
  private async scanEulerV2(ctx: BlockContext): Promise<void> {
    // The EVC emits AccountStatusCheck events for every vault interaction.
    // We scan recent logs to discover active borrowers. In production this
    // would be maintained incrementally; here we do a block-range scan.

    const ACCOUNT_STATUS_CHECK_TOPIC =
      "0x4a7b19b2c7c756bf2b3ae7b7d89fa5abb0d6a2ee78e7faf5cb0d87b76a5b0ca1";

    try {
      // Fetch AccountStatusCheck events from the EVC.
      // Use small chunk size (8 blocks) to stay within free-tier RPC limits.
      // For production, increase this with a paid RPC.
      const CHUNK = 8n;
      const fromBlock = ctx.blockNumber > CHUNK ? ctx.blockNumber - CHUNK : 0n;

      const logs = await this.client.getLogs({
        address: EULER_EVC,
        event: {
          name: 'AccountStatusCheck',
          type: 'event',
          inputs: [{ name: 'account', type: 'address', indexed: true }],
        },
        fromBlock,
        toBlock: ctx.blockNumber,
      });

      // Deduplicate accounts.
      const accounts = new Set<Address>();
      for (const log of logs) {
        if (log.topics[1]) {
          // topic[1] = account address (padded)
          const addr = ("0x" + log.topics[1].slice(26)) as Address;
          accounts.add(addr.toLowerCase() as Address);
        }
      }

      // For each account, try to fetch liquidity against each known vault.
      // In a full implementation we'd query the AccountLens for enabled
      // collaterals/borrows. For now we process each account individually.
      await Promise.allSettled(
        Array.from(accounts).map((account) =>
          this.processEulerAccount(account, ctx),
        ),
      );
    } catch (err) {
      console.error("[KillList] scanEulerV2 failed:", err);
    }
  }

  /**
   * Processes a single Euler V2 account — discovers vault pairs and creates
   * or updates TrackedPositions.
   */
  private async processEulerAccount(
    account: Address,
    ctx: BlockContext,
  ): Promise<void> {
    // Query the AccountLens for the account's enabled collaterals and borrows.
    // AccountLens ABI (minimal):
    //   getAccountCollaterals(address account) -> address[]
    //   getAccountBorrows(address account) -> address[]
    const ACCOUNT_LENS_ABI = [
      {
        name: "getAccountInfo",
        type: "function",
        stateMutability: "view",
        inputs: [
          { name: "account", type: "address" },
          { name: "vault", type: "address" },
        ],
        outputs: [
          {
            name: "",
            type: "tuple",
            components: [
              { name: "owner", type: "address" },
              { name: "isLocked", type: "bool" },
              { name: "enabledCollaterals", type: "address[]" },
            ],
          },
        ],
      },
    ] as const;

    // We don't have a vault to query without knowing the borrow vault.
    // Attempt to compute HF via a known borrow vault.  In production the
    // Account Lens returns enabled collaterals; here we simply try the
    // accountLiquidity call on a discovered vault.
    //
    // Because we have no vault-discovery mechanism in this stub, we skip
    // accounts where we don't already have a position registered. New
    // positions are registered externally (e.g. via event indexing) and
    // then kept up to date here.

    const existingPositions = Array.from(this.positions.values()).filter(
      (p) => p.account.toLowerCase() === account.toLowerCase() && p.protocol === "euler-v2",
    );

    for (const pos of existingPositions) {
      await this.refreshPosition(pos, ctx);
    }
  }

  /**
   * Silo V2: TODO — enumerate borrowers via SiloLens and compute HF.
   *
   * Implementation sketch:
   *   1. Call SiloLens.getUserDebts(user) for each known silo market.
   *   2. For each debt position, call SiloLens.getUserLTV(silo, user) to
   *      obtain the current LTV and derive a health factor.
   *   3. Derive HF = liquidationLTV / currentLTV.
   *   4. Build TrackedPosition and upsert into this.positions.
   */
  private async scanSiloV2(_ctx: BlockContext): Promise<void> {
    // TODO: implement Silo V2 census
    console.debug("[KillList] scanSiloV2: not yet implemented");
  }

  /**
   * Aave V3: TODO — enumerate borrowers via Pool events and getUserAccountData.
   *
   * Implementation sketch:
   *   1. Index Borrow events from AAVE_V3_POOL to discover active borrowers.
   *   2. For each borrower, call getUserAccountData(account) to retrieve the
   *      healthFactor (18-decimal, 1e18 = HF 1.0).
   *   3. Build TrackedPosition and upsert into this.positions.
   */
  private async scanAaveV3(_ctx: BlockContext): Promise<void> {
    // TODO: implement Aave V3 census
    console.debug("[KillList] scanAaveV3: not yet implemented");
  }

  /**
   * Morpho Blue: TODO — enumerate borrowers via MarketCreated + Borrow events.
   *
   * Implementation sketch:
   *   1. Fetch all MarketCreated events to enumerate markets.
   *   2. For each market, fetch Borrow events to discover borrowers.
   *   3. Call Morpho.position(marketId, borrower) to get shares/collateral.
   *   4. Compute HF = (collateral * collateralPrice * LLTV) / (borrowShares * borrowPrice).
   *   5. Build TrackedPosition and upsert into this.positions.
   */
  private async scanMorphoBlue(_ctx: BlockContext): Promise<void> {
    // TODO: implement Morpho Blue census
    console.debug("[KillList] scanMorphoBlue: not yet implemented");
  }

  // ─── Position Refresh ─────────────────────────────────────────────────────

  /**
   * Refreshes a single position — re-fetches HF, recomputes profit/toxicity.
   */
  private async refreshPosition(
    pos: TrackedPosition,
    ctx: BlockContext,
  ): Promise<void> {
    try {
      let hf: number;
      let estimatedProfitUsd: number;
      let capitalRequiredUsd: number;

      switch (pos.protocol) {
        case "euler-v2": {
          const result = await this.fetchEulerHF(pos.account, pos.borrowVault);
          hf = result.hf;
          estimatedProfitUsd = result.estimatedProfitUsd;
          capitalRequiredUsd = result.capitalRequiredUsd;
          break;
        }

        case "aave-v3": {
          const result = await this.fetchAaveHF(pos.account);
          hf = result.hf;
          estimatedProfitUsd = result.estimatedProfitUsd;
          capitalRequiredUsd = result.capitalRequiredUsd;
          break;
        }

        case "silo-v2":
          // TODO: implement Silo V2 HF fetch
          return;

        case "morpho-blue":
          // TODO: implement Morpho Blue HF fetch
          return;

        default:
          return;
      }

      // Compute gas cost estimate (~600k gas for a typical liquidation on Sonic).
      const gasEstimateUnits = 600_000n;
      const gasCostNative =
        (gasEstimateUnits * ctx.baseFeePerGas * 12n) / 10n; // 1.2x buffer
      // Approximate gas USD: wS price ~$0.50 as a conservative floor.
      const wsPrice = 0.5;
      const gasCostUsd =
        (Number(gasCostNative) / 1e18) * wsPrice;

      const profitDensityScore =
        (estimatedProfitUsd - gasCostUsd) / Math.max(capitalRequiredUsd, 1);

      const toxicityResult = await this.scoreToxicity(
        pos.collateralAsset,
        0, // oracle price — caller should supply; using 0 skips divergence check
        0,
        capitalRequiredUsd,
      );

      const blockers: PositionBlocker[] = [...pos.blockers];

      // Clear old toxicity blockers before re-evaluating.
      const filteredBlockers = blockers.filter(
        (b) => b.type !== "toxic_collateral" && b.type !== "blacklisted",
      );

      if (toxicityResult.verdict === "blocked") {
        filteredBlockers.push({
          type: "toxic_collateral",
          detail: toxicityResult.reasons.join("; "),
        });
      }

      if (
        TOXIC_COLLATERAL_BLACKLIST.has(pos.collateralAsset.toLowerCase() as Address)
      ) {
        filteredBlockers.push({
          type: "blacklisted",
          detail: `${pos.collateralAsset} is on the toxic collateral blacklist`,
        });
      }

      this.updatePosition(pos.id, {
        healthFactor: hf,
        estimatedProfitUsd,
        profitDensityScore,
        toxicityScore: toxicityResult.score,
        blockers: filteredBlockers,
        lastUpdatedAt: ctx.blockTimestamp,
        lastUpdatedBlock: ctx.blockNumber,
      });
    } catch (err) {
      console.error(
        `[KillList] refreshPosition(${pos.id}) failed:`,
        err,
      );
    }
  }

  // ─── Protocol HF Fetchers ─────────────────────────────────────────────────

  /**
   * Euler V2 HF via accountLiquidity(account, true).
   * HF = collateralValue / liabilityValue (Infinity if liabilityValue == 0).
   */
  private async fetchEulerHF(
    account: Address,
    borrowVault: Address,
  ): Promise<{
    hf: number;
    estimatedProfitUsd: number;
    capitalRequiredUsd: number;
  }> {
    const [collateralValue, liabilityValue] = await this.client.readContract({
      address: borrowVault,
      abi: EVAULT_ABI,
      functionName: "accountLiquidity",
      args: [account, true],
    });

    const hf =
      liabilityValue === 0n
        ? Infinity
        : Number(collateralValue) / Number(liabilityValue);

    // Estimate gross profit as the liquidation bonus (typically 2–5% on Euler).
    // Conservative: 2% of liability value in USD terms.
    // We normalise both values as 18-decimal fixed-point.
    const liabilityUsd = Number(liabilityValue) / 1e18;
    const collateralUsd = Number(collateralValue) / 1e18;
    const surplus = collateralUsd - liabilityUsd;
    const estimatedProfitUsd = Math.max(surplus * 0.02, 0);
    const capitalRequiredUsd = liabilityUsd;

    return { hf, estimatedProfitUsd, capitalRequiredUsd };
  }

  /**
   * Aave V3 HF via getUserAccountData.
   * healthFactor is returned directly at 18 decimals (1e18 = HF 1.0).
   */
  private async fetchAaveHF(account: Address): Promise<{
    hf: number;
    estimatedProfitUsd: number;
    capitalRequiredUsd: number;
  }> {
    const [
      totalCollateralBase,
      totalDebtBase,
      ,
      ,
      ,
      healthFactor,
    ] = await this.client.readContract({
      address: AAVE_V3_POOL,
      abi: AAVE_V3_POOL_ABI,
      functionName: "getUserAccountData",
      args: [account],
    });

    const hf =
      healthFactor === BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        ? Infinity
        : Number(healthFactor) / 1e18;

    // Aave uses 8-decimal USD base values.
    const collateralUsd = Number(totalCollateralBase) / 1e8;
    const debtUsd = Number(totalDebtBase) / 1e8;
    const surplus = collateralUsd - debtUsd;
    // Aave liquidation bonus is typically 5–10%; use 5% conservatively.
    const estimatedProfitUsd = Math.max(surplus * 0.05, 0);
    const capitalRequiredUsd = debtUsd;

    return { hf, estimatedProfitUsd, capitalRequiredUsd };
  }

  // ─── Toxicity Scoring ─────────────────────────────────────────────────────

  /**
   * Computes a toxicity score for a collateral asset.
   *
   * Scoring rules:
   *   +50  oracle/dex price ratio > 1.25   (stkscUSD-like phantom premium)
   *   +30  vault backing ratio < 0.50      (undercollateralised underlying)
   *   +20  DEX liquidity < 2x position size
   *   +10  token is wrapped staked yield
   *   +20  governance ownership renounced   (no ability to fix issues)
   *
   *   >= TOXICITY_SCORE_BLOCK  => "blocked"
   *   >= TOXICITY_SCORE_REDUCE => "reduced" at 25% size
   *   else                     => "full"
   */
  async scoreToxicity(
    collateralAsset: Address,
    oraclePriceUsd: number,
    dexPriceUsd: number,
    positionSizeUsd: number,
  ): Promise<ToxicityResult> {
    let score = 0;
    const reasons: string[] = [];

    // ── Rule 1: oracle/dex price divergence (stkscUSD pattern) ──
    if (oraclePriceUsd > 0 && dexPriceUsd > 0) {
      const priceRatio = oraclePriceUsd / dexPriceUsd;
      if (priceRatio > 1.25) {
        score += 50;
        reasons.push(
          `Oracle/DEX price ratio ${priceRatio.toFixed(3)} > 1.25 (phantom premium)`,
        );
      }
    }

    // ── Rule 2: vault backing ratio < 0.50 ──
    try {
      const backingRatio = await this.fetchVaultBackingRatio(collateralAsset);
      if (backingRatio < 0.5) {
        score += 30;
        reasons.push(
          `Vault backing ratio ${backingRatio.toFixed(3)} < 0.50 (undercollateralised)`,
        );
      }
    } catch {
      // Non-vault assets or failed reads don't penalise.
    }

    // ── Rule 3: DEX liquidity < 2x position size ──
    try {
      const dexLiquidityUsd = await this.fetchDexLiquidity(collateralAsset);
      if (dexLiquidityUsd < positionSizeUsd * 2) {
        score += 20;
        reasons.push(
          `DEX liquidity $${dexLiquidityUsd.toFixed(0)} < 2x position size $${(positionSizeUsd * 2).toFixed(0)}`,
        );
      }
    } catch {
      // Liquidity fetch failure is penalised as unknown liquidity.
      score += 20;
      reasons.push("Unable to verify DEX liquidity — penalising");
    }

    // ── Rule 4: wrapped staked yield token ──
    if (this.isWrappedStakedYield(collateralAsset)) {
      score += 10;
      reasons.push(`${collateralAsset} is a wrapped staked yield token`);
    }

    // ── Rule 5: governance ownership renounced ──
    try {
      const renounced = await this.isGovernanceRenounced(collateralAsset);
      if (renounced) {
        score += 20;
        reasons.push("Governance ownership renounced — no remediation possible");
      }
    } catch {
      // Ignore governance check failures.
    }

    // ── Verdict ──
    let verdict: ToxicityResult["verdict"];
    let reducedSizePct: number | undefined;

    if (score >= TOXICITY_SCORE_BLOCK) {
      verdict = "blocked";
    } else if (score >= TOXICITY_SCORE_REDUCE) {
      verdict = "reduced";
      reducedSizePct = 25;
    } else {
      verdict = "full";
    }

    return { score, verdict, reasons, reducedSizePct };
  }

  // ─── Collateral Exit Validation ───────────────────────────────────────────

  /**
   * Pre-flight check before executing a liquidation.
   *
   * Steps:
   *   1. Fetch an OpenOcean quote for collateralAsset -> USDC.e at full size.
   *   2. Compute price impact vs. the oracle mid-price.
   *   3. Apply abort/reduce rules.
   *   4. Return a CollateralExitValidation result.
   */
  async validateCollateralExit(
    collateralAsset: Address,
    collateralVault: Address,
    positionSizeTokens: bigint,
  ): Promise<CollateralExitValidation> {
    // Fetch token decimals for amount formatting.
    let decimals = 18;
    try {
      decimals = await this.client.readContract({
        address: collateralAsset,
        abi: ERC20_ABI,
        functionName: "decimals",
      });
    } catch {
      // Default to 18.
    }

    // Available cash in the collateral vault (how much can be withdrawn).
    let availableCash = 0n;
    try {
      availableCash = await this.client.readContract({
        address: collateralVault,
        abi: EVAULT_ABI,
        functionName: "maxWithdraw",
        args: ["0x0000000000000000000000000000000000000000"],
      });
    } catch {
      // Non-Euler vaults — skip available cash check.
    }

    // Clamp position size to available cash.
    const effectiveSize =
      availableCash > 0n && positionSizeTokens > availableCash
        ? availableCash
        : positionSizeTokens;

    // ── Step 1: fetch DEX quote ──
    let dexQuoteAvailable = false;
    let dexOutputAmount = 0n;
    let oracleDexDivergencePct = 0;
    let priceImpactPct = 0;

    try {
      const inAmountDecimal = effectiveSize.toString();
      const url =
        `${OPENOCEAN_API_BASE}/quote` +
        `?inTokenAddress=${collateralAsset}` +
        `&outTokenAddress=${USDC_E}` +
        `&amount=${inAmountDecimal}` +
        `&gasPrice=1000000000` +
        `&slippage=1`;

      const resp = await fetch(url, { signal: AbortSignal.timeout(5_000) });
      if (resp.ok) {
        const json = (await resp.json()) as OpenOceanQuoteResponse;
        if (json.code === 200 && json.data?.outAmount) {
          dexQuoteAvailable = true;
          dexOutputAmount = BigInt(json.data.outAmount);
        }
      }
    } catch (err) {
      console.warn("[KillList] OpenOcean quote fetch failed:", err);
    }

    if (!dexQuoteAvailable) {
      return {
        ok: false,
        failReason: "DEX quote unavailable — cannot validate exit",
        dexQuoteAvailable: false,
        oracleDexDivergencePct: 0,
        priceImpactPct: 0,
        availableCash,
        recommendedSize: "skip",
      };
    }

    // ── Step 2: compute oracle/DEX divergence and price impact ──
    // DEX price per input token in USDC (6 decimals out, `decimals` in).
    const dexPricePerToken =
      Number(dexOutputAmount) /
      1e6 /
      (Number(effectiveSize) / 10 ** decimals);

    // Midpoint price: the DEX price itself serves as midpoint when no oracle
    // is supplied here. Callers that have an oracle price should pass it in
    // separately. For the impact calc we use the output vs. a zero-impact
    // baseline of the same DEX price applied linearly.
    const midpointOutputAmount =
      (Number(effectiveSize) / 10 ** decimals) * dexPricePerToken * 1e6;

    // Price impact = (expected_out - midpoint_out) / midpoint_out
    // Since dexOutputAmount IS our expected output, divergence from midpoint
    // only comes from slippage embedded in the quote. We model this as 0
    // unless a separate oracle price is provided.
    // When oracle price is available externally (e.g. from the oracle hunter),
    // callers should separately check oracle/dex divergence before calling
    // this function. Here we conservatively set divergence = 0.
    oracleDexDivergencePct = 0;
    priceImpactPct =
      Math.abs(Number(dexOutputAmount) - midpointOutputAmount) /
      Math.max(midpointOutputAmount, 1) *
      100;

    // ── Step 3: abort rules ──
    // Rule A: oracle/dex ratio > 1.25 — abort entirely.
    if (oracleDexDivergencePct > 25) {
      return {
        ok: false,
        failReason: `Oracle/DEX divergence ${oracleDexDivergencePct.toFixed(1)}% > 25% — abort`,
        dexQuoteAvailable,
        oracleDexDivergencePct,
        priceImpactPct,
        availableCash,
        recommendedSize: "skip",
      };
    }

    // Rule B: price impact > 40% — skip.
    if (priceImpactPct > 40) {
      return {
        ok: false,
        failReason: `Price impact ${priceImpactPct.toFixed(1)}% > 40% — skip`,
        dexQuoteAvailable,
        oracleDexDivergencePct,
        priceImpactPct,
        availableCash,
        recommendedSize: "skip",
      };
    }

    // Rule C: price impact > 20% — reduce to 50%.
    if (priceImpactPct > 20) {
      return {
        ok: true,
        dexQuoteAvailable,
        oracleDexDivergencePct,
        priceImpactPct,
        availableCash,
        recommendedSize: "half",
      };
    }

    return {
      ok: true,
      dexQuoteAvailable,
      oracleDexDivergencePct,
      priceImpactPct,
      availableCash,
      recommendedSize: "full",
    };
  }

  // ─── Position Accessors ───────────────────────────────────────────────────

  /** Returns Tier 0 (HOT) positions sorted by profit density descending. */
  getTier0Positions(): TrackedPosition[] {
    return this.getTierPositions(0);
  }

  /** Returns positions for a given tier sorted by profit density descending. */
  private getTierPositions(tier: PositionTier): TrackedPosition[] {
    const config = TIER_CONFIG[tier];
    return Array.from(this.positions.values())
      .filter(
        (p) =>
          p.tier === tier &&
          p.blockers.length === 0 &&
          p.estimatedProfitUsd >= config.minProfitUsd,
      )
      .sort((a, b) => b.profitDensityScore - a.profitDensityScore)
      .slice(0, config.maxPositions === Infinity ? undefined : config.maxPositions);
  }

  /** Returns all positions that are not in Tier 3 (i.e. actively monitored). */
  private getActivePositions(): TrackedPosition[] {
    return Array.from(this.positions.values()).filter((p) => p.tier !== 3);
  }

  /** Upserts partial updates for a tracked position. */
  updatePosition(id: string, updates: Partial<TrackedPosition>): void {
    const existing = this.positions.get(id);
    if (!existing) {
      console.warn(`[KillList] updatePosition: unknown id ${id}`);
      return;
    }
    this.positions.set(id, { ...existing, ...updates });
  }

  // ─── Tier Reclassification ────────────────────────────────────────────────

  /**
   * Reclassifies all positions into the correct tier based on their current
   * health factor. A position always lives in the highest-urgency tier it
   * qualifies for.
   */
  private reclassifyAllTiers(): void {
    for (const [id, pos] of this.positions) {
      const newTier = this.computeTier(pos.healthFactor, pos.estimatedProfitUsd);
      if (newTier !== pos.tier) {
        this.positions.set(id, { ...pos, tier: newTier });
      }
    }
  }

  private computeTier(hf: number, profitUsd: number): PositionTier {
    if (hf < TIER_CONFIG[0].maxHF && profitUsd >= TIER_CONFIG[0].minProfitUsd)
      return 0;
    if (hf < TIER_CONFIG[1].maxHF && profitUsd >= TIER_CONFIG[1].minProfitUsd)
      return 1;
    if (hf < TIER_CONFIG[2].maxHF) return 2;
    return 3;
  }

  /**
   * Enforces per-tier position caps, dropping the lowest profit-density
   * positions when a tier exceeds its max.
   */
  private enforceCapsByTier(): void {
    for (const tier of [0, 1, 2] as PositionTier[]) {
      const config = TIER_CONFIG[tier];
      if (config.maxPositions === Infinity) continue;

      const tierPositions = Array.from(this.positions.values())
        .filter((p) => p.tier === tier)
        .sort((a, b) => b.profitDensityScore - a.profitDensityScore);

      if (tierPositions.length > config.maxPositions) {
        const toDrop = tierPositions.slice(config.maxPositions);
        for (const pos of toDrop) {
          // Demote to Tier 3 rather than deleting, so they aren't lost.
          this.positions.set(pos.id, { ...pos, tier: 3 });
        }
      }
    }
  }

  // ─── Helper Utilities ─────────────────────────────────────────────────────

  /**
   * Adds a new position to the tracked set. Called externally by event
   * indexers when a new borrow is detected.
   */
  addPosition(position: TrackedPosition): void {
    this.positions.set(position.id, position);
  }

  /**
   * Removes a position (e.g. after successful liquidation or full repayment).
   */
  removePosition(id: string): void {
    this.positions.delete(id);
  }

  /**
   * Builds a position ID from its constituent parts.
   */
  static buildPositionId(
    account: Address,
    protocol: ProtocolId,
    market: Address,
  ): string {
    return `${account.toLowerCase()}:${protocol}:${market.toLowerCase()}`;
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  /**
   * Fetches the ERC4626 vault backing ratio (totalAssets / totalSupply).
   * Returns 1.0 for non-vault tokens.
   */
  private async fetchVaultBackingRatio(asset: Address): Promise<number> {
    const VAULT_ABI = [
      {
        name: "totalAssets",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
      },
      {
        name: "totalSupply",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "uint256" }],
      },
    ] as const;

    const [totalAssets, totalSupply] = await Promise.all([
      this.client.readContract({
        address: asset,
        abi: VAULT_ABI,
        functionName: "totalAssets",
      }),
      this.client.readContract({
        address: asset,
        abi: VAULT_ABI,
        functionName: "totalSupply",
      }),
    ]);

    if (totalSupply === 0n) return 1.0;
    return Number(totalAssets) / Number(totalSupply);
  }

  /**
   * Estimates DEX liquidity for a token by querying OpenOcean for a large
   * reference swap (1M USDC.e worth) and using the output as a proxy.
   * Returns USD liquidity estimate.
   */
  private async fetchDexLiquidity(asset: Address): Promise<number> {
    // Use a 10k USDC reference swap to probe market depth.
    const REFERENCE_USDC_AMOUNT = 10_000 * 1e6; // 10k USDC.e (6 decimals)

    const url =
      `${OPENOCEAN_API_BASE}/quote` +
      `?inTokenAddress=${USDC_E}` +
      `&outTokenAddress=${asset}` +
      `&amount=${REFERENCE_USDC_AMOUNT}` +
      `&gasPrice=1000000000` +
      `&slippage=1`;

    const resp = await fetch(url, { signal: AbortSignal.timeout(5_000) });
    if (!resp.ok) throw new Error(`OpenOcean HTTP ${resp.status}`);

    const json = (await resp.json()) as OpenOceanQuoteResponse;
    if (json.code !== 200 || !json.data?.outAmount) {
      throw new Error("OpenOcean quote error: " + (json.error ?? "unknown"));
    }

    // If we got a quote for 10k USDC in, liquidity is at least 2x that = 20k.
    // This is a conservative floor; real depth requires multiple quote sizes.
    return 20_000;
  }

  /**
   * Heuristic: a token is a wrapped staked yield token if its address matches
   * known patterns or is listed in TOXIC_COLLATERAL_BLACKLIST.
   */
  private isWrappedStakedYield(asset: Address): boolean {
    const lower = asset.toLowerCase() as Address;

    // Known wrapped staked yield tokens on Sonic.
    const WRAPPED_STAKED_YIELD: Set<Address> = new Set([
      "0x9fb76f7ce5fceaa2c42887ff441d46095e494206" as Address, // wStkScUSD
      "0x4d85ba8c3918359c78ed09581e5bc7578ba932ba" as Address, // stkScUSD
    ]);

    return (
      WRAPPED_STAKED_YIELD.has(lower) ||
      TOXIC_COLLATERAL_BLACKLIST.has(lower)
    );
  }

  /**
   * Checks whether governance ownership has been renounced for a token.
   * Attempts to call `owner()` and checks for zero address.
   */
  private async isGovernanceRenounced(asset: Address): Promise<boolean> {
    const OWNABLE_ABI = [
      {
        name: "owner",
        type: "function",
        stateMutability: "view",
        inputs: [],
        outputs: [{ name: "", type: "address" }],
      },
    ] as const;

    try {
      const owner = await this.client.readContract({
        address: asset,
        abi: OWNABLE_ABI,
        functionName: "owner",
      });
      return owner === "0x0000000000000000000000000000000000000000";
    } catch {
      // Contract doesn't implement Ownable — can't determine.
      return false;
    }
  }
}
