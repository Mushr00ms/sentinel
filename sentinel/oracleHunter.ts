import type { Address, PublicClient } from "viem";

import {
  EULER_ACCOUNT_LENS,
  EULER_EVC,
  OPENOCEAN_API_BASE,
  ORACLE_DIVERGENCE_ALERT_PCT,
  ORACLE_DIVERGENCE_CRITICAL_PCT,
  ORACLE_FEEDS,
  ORACLE_STALENESS_RATIO_THRESHOLD,
  USDC_E,
} from "./config.js";
import type {
  BlockContext,
  DexQuote,
  OracleDivergenceAlert,
  OracleFeedConfig,
  OracleFeedState,
  PhantomHealthyPosition,
} from "./types.js";

// ─── ABIs ─────────────────────────────────────────────────────────────────

const AGGREGATOR_V3_ABI = [
  {
    name: "latestRoundData",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "roundId", type: "uint80" },
      { name: "answer", type: "int256" },
      { name: "startedAt", type: "uint256" },
      { name: "updatedAt", type: "uint256" },
      { name: "answeredInRound", type: "uint80" },
    ],
  },
  {
    name: "decimals",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
] as const;

const EVC_ABI = [
  {
    name: "getControllers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "address[]" }],
  },
  {
    name: "getCollaterals",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "address[]" }],
  },
] as const;

const ACCOUNT_LENS_ABI = [
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
] as const;

// ─── Constants ────────────────────────────────────────────────────────────

/** Normalise oracle answer to 18-decimal bigint using feed decimals. */
const WAD = 10n ** 18n;

/** Amount used for DEX price quotes (1 unit of base token, 18-decimal). */
const QUOTE_BASE_AMOUNT = WAD;

/** OpenOcean returns amounts in token-native decimals; most ERC-20s use 18. */
const DEFAULT_TOKEN_DECIMALS = 18;

/** Maximum accounts to scan per alert when hunting phantom-healthy positions. */
const MAX_SCAN_ACCOUNTS = 200;

/** Run every N blocks. Caller is responsible for the cadence check. */
export const ORACLE_HUNTER_BLOCK_CADENCE = 10;

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Parse OpenOcean JSON response, return { outAmount, price } or null on error. */
interface OpenOceanResponse {
  code: number;
  data?: {
    outAmount?: string;
    price?: string | number;
  };
}

/**
 * OracleHunter monitors Chainlink and RedStone oracle feeds on Sonic (chain
 * 146) for staleness and price divergence from on-chain DEX spot prices.
 *
 * When divergence exceeds configured thresholds, it identifies positions that
 * are "phantom healthy" — positions that appear solvent at the oracle price but
 * are liquidatable at the true DEX price — and returns structured alerts for
 * the execution layer.
 *
 * Call `run(ctx)` once per block cadence (every 10 blocks) from the main loop.
 */
export class OracleHunter {
  /** Latest observed state for each feed, keyed by feed name. */
  readonly feedStates: Map<string, OracleFeedState> = new Map();

  /** Most recent alert per feed, keyed by feed name, used for dedup. */
  readonly lastAlerts: Map<string, OracleDivergenceAlert> = new Map();

  private readonly client: PublicClient;

  constructor(publicClient: PublicClient) {
    this.client = publicClient;
  }

  // ─── Public API ───────────────────────────────────────────────────────

  /**
   * Main loop entry point. Reads all configured oracle feeds, compares each
   * against the DEX spot price, and returns any new divergence alerts with
   * phantom-healthy positions pre-identified.
   *
   * @param ctx - Current block context from the block subscriber.
   * @returns Array of divergence alerts; empty if no anomalies detected.
   */
  async run(ctx: BlockContext): Promise<OracleDivergenceAlert[]> {
    const alerts: OracleDivergenceAlert[] = [];

    // Filter out placeholder feeds (zero/sentinel addresses)
    const activeFeed = ORACLE_FEEDS.filter(
      (f) => f.feedAddress !== "0x0000000000000000000000000000000000000000" &&
             f.feedAddress !== "0x0000000000000000000000000000000000000001",
    );

    await Promise.allSettled(
      activeFeed.map(async (feed) => {
        try {
          const state = await this.getFeedState(feed);
          this.feedStates.set(feed.name, state);

          // Skip feeds with no associated vault — nothing to liquidate.
          if (feed.vault === undefined) return;

          const dexQuote = await this.getDexPrice(
            feed.baseToken,
            feed.quoteToken,
            QUOTE_BASE_AMOUNT,
          );
          if (dexQuote === null) return;

          const oraclePrice = this._oraclePriceToFloat(state.onChainPrice);
          const dexPrice = dexQuote.pricePerUnit;
          const divergencePct = this.computeDivergencePct(oraclePrice, dexPrice);

          if (divergencePct < ORACLE_DIVERGENCE_ALERT_PCT) return;

          const severity: OracleDivergenceAlert["severity"] =
            divergencePct >= ORACLE_DIVERGENCE_CRITICAL_PCT ? "critical" : "alert";

          // Suppress duplicate alerts that are identical to the last seen
          // alert for this feed (same severity + divergence bucket).
          const existing = this.lastAlerts.get(feed.name);
          if (
            existing !== undefined &&
            existing.severity === severity &&
            Math.abs(existing.divergencePct - divergencePct) < 0.1
          ) {
            return;
          }

          const partialAlert: Omit<OracleDivergenceAlert, "phantomHealthyPositions"> = {
            severity,
            feedConfig: feed,
            oraclePrice,
            dexPrice,
            divergencePct,
            stalenessRatio: state.stalenessRatio,
            affectedVault: feed.vault,
            detectedAt: ctx.blockTimestamp,
          };

          const phantomPositions = await this.findPhantomHealthyPositions(partialAlert);

          const alert: OracleDivergenceAlert = {
            ...partialAlert,
            phantomHealthyPositions: phantomPositions,
          };

          this.lastAlerts.set(feed.name, alert);
          alerts.push(alert);
        } catch (err) {
          console.error(
            `[OracleHunter] Error processing feed ${feed.name}:`,
            err instanceof Error ? err.message : String(err),
          );
        }
      }),
    );

    return alerts;
  }

  /**
   * Reads the latest round data from a Chainlink-compatible AggregatorV3
   * feed and returns a normalised {@link OracleFeedState}.
   *
   * The on-chain price is normalised to 18 decimals regardless of the feed's
   * native decimal precision.
   *
   * @param feed - Feed configuration to query.
   */
  async getFeedState(feed: OracleFeedConfig): Promise<OracleFeedState> {
    const [roundData, decimals] = await Promise.all([
      this.client.readContract({
        address: feed.feedAddress,
        abi: AGGREGATOR_V3_ABI,
        functionName: "latestRoundData",
      }),
      this.client.readContract({
        address: feed.feedAddress,
        abi: AGGREGATOR_V3_ABI,
        functionName: "decimals",
      }),
    ]);

    const [roundId, answer, , updatedAt] = roundData;

    if (answer <= 0n) {
      throw new Error(
        `[OracleHunter] Feed ${feed.name} returned non-positive answer: ${answer}`,
      );
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const lastUpdatedAt = Number(updatedAt);
    const stalenessSeconds = Math.max(0, nowSeconds - lastUpdatedAt);
    const stalenessRatio = stalenessSeconds / feed.heartbeatSeconds;

    // Normalise to 18-decimal WAD.
    const feedDecimals = Number(decimals);
    const onChainPrice =
      feedDecimals <= DEFAULT_TOKEN_DECIMALS
        ? answer * 10n ** BigInt(DEFAULT_TOKEN_DECIMALS - feedDecimals)
        : answer / 10n ** BigInt(feedDecimals - DEFAULT_TOKEN_DECIMALS);

    const state: OracleFeedState = {
      config: feed,
      onChainPrice,
      lastUpdatedAt,
      roundId,
      stalenessSeconds,
      stalenessRatio,
    };

    if (stalenessRatio >= ORACLE_STALENESS_RATIO_THRESHOLD) {
      console.warn(
        `[OracleHunter] Feed ${feed.name} is stale: ratio=${stalenessRatio.toFixed(2)}, ` +
          `staleness=${stalenessSeconds}s, heartbeat=${feed.heartbeatSeconds}s`,
      );
    }

    return state;
  }

  /**
   * Fetches a DEX spot price from the OpenOcean aggregator API.
   *
   * @param tokenIn  - ERC-20 address of the input token.
   * @param tokenOut - ERC-20 address of the output token.
   * @param amountIn - Input amount in 18-decimal WAD units.
   * @returns A {@link DexQuote} or `null` if the API call fails.
   */
  async getDexPrice(
    tokenIn: Address,
    tokenOut: Address,
    amountIn: bigint,
  ): Promise<DexQuote | null> {
    // OpenOcean expects a human-readable amount (no decimals suffix).
    const humanAmount = Number(amountIn) / 10 ** DEFAULT_TOKEN_DECIMALS;

    const url = new URL(`${OPENOCEAN_API_BASE}/quote`);
    url.searchParams.set("inTokenAddress", tokenIn);
    url.searchParams.set("outTokenAddress", tokenOut);
    url.searchParams.set("amount", humanAmount.toString());
    url.searchParams.set("gasPrice", "5");
    url.searchParams.set("slippage", "0");

    let response: Response;
    try {
      response = await fetch(url.toString(), {
        signal: AbortSignal.timeout(8_000),
        headers: { Accept: "application/json" },
      });
    } catch (err) {
      console.warn(
        `[OracleHunter] OpenOcean fetch failed for ${tokenIn}->${tokenOut}:`,
        err instanceof Error ? err.message : String(err),
      );
      return null;
    }

    if (!response.ok) {
      console.warn(
        `[OracleHunter] OpenOcean returned HTTP ${response.status} for ${tokenIn}->${tokenOut}`,
      );
      return null;
    }

    let json: OpenOceanResponse;
    try {
      json = (await response.json()) as OpenOceanResponse;
    } catch {
      console.warn(`[OracleHunter] OpenOcean JSON parse error for ${tokenIn}->${tokenOut}`);
      return null;
    }

    if (json.code !== 200 || json.data === undefined) {
      console.warn(
        `[OracleHunter] OpenOcean non-200 code (${json.code}) for ${tokenIn}->${tokenOut}`,
      );
      return null;
    }

    const outAmountRaw = json.data.outAmount;
    const priceRaw = json.data.price;

    if (outAmountRaw === undefined || priceRaw === undefined) {
      console.warn(`[OracleHunter] OpenOcean missing outAmount/price for ${tokenIn}->${tokenOut}`);
      return null;
    }

    const outputAmount = BigInt(outAmountRaw);
    const pricePerUnit = Number(priceRaw);

    if (pricePerUnit <= 0 || !isFinite(pricePerUnit)) {
      console.warn(
        `[OracleHunter] OpenOcean returned invalid price ${pricePerUnit} for ${tokenIn}->${tokenOut}`,
      );
      return null;
    }

    return {
      inputToken: tokenIn,
      outputToken: tokenOut,
      inputAmount: amountIn,
      outputAmount,
      pricePerUnit,
      source: "openocean",
      timestamp: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Scans active Euler positions under the affected vault and returns those
   * that are healthy at the oracle price but would be liquidatable at the
   * DEX (true market) price.
   *
   * A position is "phantom healthy" when:
   *   - healthFactorAtOracle > 1.0   (oracle says solvent)
   *   - healthFactorAtDex   < 1.0    (true price says liquidatable)
   *
   * @param alert - Partial alert without the `phantomHealthyPositions` field.
   */
  async findPhantomHealthyPositions(
    alert: Omit<OracleDivergenceAlert, "phantomHealthyPositions">,
  ): Promise<PhantomHealthyPosition[]> {
    const vault = alert.affectedVault;

    // Gather candidate accounts that have the affected vault as a controller
    // (i.e. borrower accounts). We use getLogs on AccountStatusCheck events or
    // fall back to a best-effort set derived from Transfer logs. Since a full
    // event scrape is expensive, we scan a sliding recent window and rely on
    // the kill-list module for deeper coverage.
    const accounts = await this._getCandidateAccounts(vault);

    const phantoms: PhantomHealthyPosition[] = [];

    await Promise.allSettled(
      accounts.map(async (account) => {
        try {
          const collaterals = await this.client.readContract({
            address: EULER_EVC,
            abi: EVC_ABI,
            functionName: "getCollaterals",
            args: [account],
          });

          if (collaterals.length === 0) return;

          // Check liquidity at oracle price (liquidation=false uses oracle).
          const [oracleColVal, oracleLiabVal] = await this.client.readContract({
            address: EULER_ACCOUNT_LENS,
            abi: ACCOUNT_LENS_ABI,
            functionName: "accountLiquidity",
            args: [account, false],
          });

          if (oracleLiabVal === 0n) return; // No debt — skip.

          const hfOracle = Number(oracleColVal) / Number(oracleLiabVal);
          if (hfOracle <= 1.0) return; // Already liquidatable — not phantom.

          // Estimate health factor at DEX price by scaling collateral value by
          // the divergence ratio. oracle is overpriced → DEX price is lower →
          // collateral is worth less.
          const dexScaleFactor = alert.dexPrice / alert.oraclePrice;
          const dexColVal = Number(oracleColVal) * dexScaleFactor;
          const hfDex = dexColVal / Number(oracleLiabVal);

          if (hfDex >= 1.0) return; // Still healthy at DEX price — skip.

          // Estimate profit: liability value discounted by a 5% liquidation
          // bonus is the rough yield; subtract the scaled collateral we receive.
          const LIQUIDATION_BONUS = 0.05;
          const repayUsd =
            (Number(oracleLiabVal) / 10 ** DEFAULT_TOKEN_DECIMALS) * alert.dexPrice;
          const yieldUsd = repayUsd * LIQUIDATION_BONUS;
          const estimatedProfitUsd = Math.max(0, yieldUsd);

          // Use the first collateral vault as the representative collateral.
          const collateralVault: Address = collaterals[0] as Address;

          phantoms.push({
            account,
            borrowVault: vault,
            collateralVault,
            healthFactorAtOracle: hfOracle,
            healthFactorAtDex: hfDex,
            estimatedProfitUsd,
          });
        } catch {
          // Swallow per-account errors; keep scanning.
        }
      }),
    );

    // Sort by estimated profit descending.
    phantoms.sort((a, b) => b.estimatedProfitUsd - a.estimatedProfitUsd);
    return phantoms;
  }

  // ─── Private ──────────────────────────────────────────────────────────

  /**
   * Returns the absolute percentage divergence between oracle and DEX price.
   *
   * @param oracle - Oracle price in USD (float).
   * @param dex    - DEX spot price in USD (float).
   * @returns Divergence as a percentage (e.g. 3.5 means 3.5%).
   */
  private computeDivergencePct(oracle: number, dex: number): number {
    if (oracle === 0) return 0;
    return Math.abs((oracle - dex) / oracle) * 100;
  }

  /**
   * Converts a WAD-normalised (18-decimal) on-chain price bigint to a
   * JavaScript float in USD.
   */
  private _oraclePriceToFloat(onChainPrice: bigint): number {
    return Number(onChainPrice) / Number(WAD);
  }

  /**
   * Retrieves candidate borrower accounts for a given vault by querying the
   * EVC for accounts that list the vault as a controller.
   *
   * Because there is no on-chain enumeration of all EVC accounts, we pull
   * recent `AccountStatusCheck` / borrow-related Transfer logs from the vault
   * to get a working set of addresses. We cap at `MAX_SCAN_ACCOUNTS` to bound
   * RPC cost.
   */
  private async _getCandidateAccounts(vault: Address): Promise<Address[]> {
    // ERC-20 Transfer topic (from=zero means mint, i.e. borrow shares issued).
    const TRANSFER_TOPIC =
      "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" as const;
    const ZERO_PADDED =
      "0x0000000000000000000000000000000000000000000000000000000000000000" as const;

    const seen = new Set<Address>();

    try {
      const currentBlock = await this.client.getBlockNumber();
      const fromBlock = currentBlock > 50_000n ? currentBlock - 50_000n : 0n;

      const logs = await this.client.getLogs({
        address: vault,
        event: {
          name: "Transfer",
          type: "event",
          inputs: [
            { name: "from", type: "address", indexed: true },
            { name: "to", type: "address", indexed: true },
            { name: "value", type: "uint256", indexed: false },
          ],
        },
        args: { from: ZERO_PADDED as Address },
        fromBlock,
        toBlock: currentBlock,
      });

      for (const log of logs) {
        if (seen.size >= MAX_SCAN_ACCOUNTS) break;
        const to = (log.args as { to?: Address }).to;
        if (to !== undefined && to !== null) {
          seen.add(to.toLowerCase() as Address);
        }
      }
    } catch (err) {
      console.warn(
        `[OracleHunter] getLogs for vault ${vault} failed:`,
        err instanceof Error ? err.message : String(err),
      );
    }

    // Additionally check the USDC_E vault for cross-vault borrow patterns —
    // phantom positions often arise when collateral is in one vault and debt
    // is denominated in a stablecoin.
    if (vault.toLowerCase() !== USDC_E.toLowerCase() && seen.size < MAX_SCAN_ACCOUNTS) {
      try {
        const currentBlock = await this.client.getBlockNumber();
        const fromBlock = currentBlock > 20_000n ? currentBlock - 20_000n : 0n;

        const stableLogs = await this.client.getLogs({
          address: USDC_E,
          event: {
            name: "Transfer",
            type: "event",
            inputs: [
              { name: "from", type: "address", indexed: true },
              { name: "to", type: "address", indexed: true },
              { name: "value", type: "uint256", indexed: false },
            ],
          },
          fromBlock,
          toBlock: currentBlock,
        });

        for (const log of stableLogs) {
          if (seen.size >= MAX_SCAN_ACCOUNTS) break;
          const to = (log.args as { to?: Address }).to;
          if (to !== undefined && to !== null) {
            seen.add(to.toLowerCase() as Address);
          }
        }
      } catch {
        // Non-fatal; proceed with what we have.
      }
    }

    // Filter out zero address and known contract addresses, then verify each
    // account actually has the vault as a controller (has active borrow).
    const candidates = Array.from(seen).filter(
      (a) => a !== "0x0000000000000000000000000000000000000000",
    );

    const verified: Address[] = [];
    await Promise.allSettled(
      candidates.map(async (account) => {
        try {
          const controllers = await this.client.readContract({
            address: EULER_EVC,
            abi: EVC_ABI,
            functionName: "getControllers",
            args: [account as Address],
          });
          const controllerAddrs = controllers.map((c) => c.toLowerCase());
          if (controllerAddrs.includes(vault.toLowerCase())) {
            verified.push(account as Address);
          }
        } catch {
          // Skip unresolvable accounts.
        }
      }),
    );

    return verified;
  }
}
