/**
 * Module B – GovernanceShockDetector
 *
 * Monitors Euler V2 Sonic governance events per-block and reacts to:
 *   - LTV reductions  (GovSetLTV)
 *   - Hook config changes / unpauses (GovSetHookConfig)
 *   - Oracle router config changes (EulerRouterConfigSet)
 *
 * Positions that become liquidatable immediately (rampDuration == 0) or will
 * become liquidatable during an LTV ramp are surfaced as GovernanceAlert[].
 */

import type { PublicClient, Address, Log } from "viem";
import { decodeEventLog, parseAbi } from "viem";
import type {
  BlockContext,
  GovSetLTVEvent,
  GovSetHookConfigEvent,
  GovernanceAlert,
  GovernanceAffectedPosition,
} from "./types.js";
import {
  EULER_EVC,
  EULER_ACCOUNT_LENS,
  TOPIC_GOV_SET_LTV,
  TOPIC_GOV_SET_HOOK_CONFIG,
  TOPIC_EULER_ROUTER_CONFIG_SET,
  isConfigured,
} from "./config.js";

// ---------------------------------------------------------------------------
// ABIs
// ---------------------------------------------------------------------------

const GOV_SET_LTV_ABI = parseAbi([
  "event GovSetLTV(address indexed vault, address indexed collateral, uint16 borrowLTV, uint16 liquidationLTV, uint16 initialLTV, uint16 targetLTV, uint48 rampDuration)",
]);

const GOV_SET_HOOK_CONFIG_ABI = parseAbi([
  "event GovSetHookConfig(address indexed vault, address hookTarget, uint32 hookedOps)",
]);

const EULER_ROUTER_CONFIG_SET_ABI = parseAbi([
  "event ConfigSet(address indexed asset1, address indexed asset2, address indexed oracle)",
]);

const EVC_ABI = parseAbi([
  "function getControllers(address account) external view returns (address[])",
  "function getCollaterals(address account) external view returns (address[])",
  "function isAccountOperatorAuthorized(address account, address operator) external view returns (bool)",
]);

const ACCOUNT_LENS_ABI = parseAbi([
  "function getAccountLiquidity(address account, address controller, bool liquidation) external view returns (uint256 collateralValue, uint256 liabilityValue)",
]);

// Euler vault — used to enumerate accounts that have a given vault as controller
const EULER_VAULT_ABI = parseAbi([
  "function getAccountStatus(address account) external view returns (uint8)",
  "function isControllerEnabled(address account) external view returns (bool)",
]);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Bit 8 in hookedOps corresponds to OP_REDEEM.
 * When set the vault is paused for redemptions (liquidations blocked).
 * When cleared after previously being set → unpause event.
 */
const OP_REDEEM_BIT = 0x100 as const;

/**
 * LTV basis-point denominator: values are in 1/1e4 units.
 * e.g. 9500 bps → 0.95 (95 %).
 */
const LTV_DENOM = 1e4 as const;

/**
 * Approximate block time in seconds — chain-aware.
 * Ethereum ≈ 12s, Sonic ≈ 0.4s.
 */
import { CHAIN_ID } from "./config.js";
const BLOCK_TIME_SECONDS = CHAIN_ID === 1 ? 12 : 0.4;

/**
 * Maximum number of accounts to inspect per vault per block.
 * Protects against excessively large sets returning from EVC calls.
 */
const MAX_ACCOUNTS_PER_VAULT = 200 as const;

// ---------------------------------------------------------------------------
// Ramp state
// ---------------------------------------------------------------------------

interface RampState {
  initialLTV: number;
  targetLTV: number;
  startTime: number; // unix seconds at ramp start
  rampDuration: number; // seconds
}

// ---------------------------------------------------------------------------
// GovernanceShockDetector
// ---------------------------------------------------------------------------

export class GovernanceShockDetector {
  private readonly client: PublicClient;

  /** Last block whose logs have been fully processed. */
  public lastProcessedBlock: bigint = 0n;

  /**
   * Current known liquidation LTV per vault:collateral pair.
   * Keyed as `${vault.toLowerCase()}:${collateral.toLowerCase()}`.
   */
  public knownLTVs: Map<string, number> = new Map();

  /**
   * Active LTV ramps.
   * Keyed the same way as knownLTVs.
   */
  public activeRamps: Map<string, RampState> = new Map();

  /**
   * Previous hookedOps per vault so we can detect direction of change.
   * Keyed by vault address (lower-cased).
   */
  private knownHookedOps: Map<string, number> = new Map();

  constructor(client: PublicClient) {
    this.client = client;
  }

  // -------------------------------------------------------------------------
  // Public entry point
  // -------------------------------------------------------------------------

  /**
   * Called once per block.  Fetches governance logs for the current block and
   * returns any triggered alerts.
   */
  async run(ctx: BlockContext): Promise<GovernanceAlert[]> {
    // Guard: skip if EVC not configured (zero address)
    if (!isConfigured(EULER_EVC)) return [];

    // Guard: skip blocks we have already processed
    if (ctx.blockNumber <= this.lastProcessedBlock) {
      return [];
    }

    const alerts: GovernanceAlert[] = [];

    try {
      // Fetch all relevant logs in one round-trip using topic filtering
      const logs = await this.client.getLogs({
        fromBlock: ctx.blockNumber,
        toBlock: ctx.blockNumber,
        events: [
          ...GOV_SET_LTV_ABI,
          ...GOV_SET_HOOK_CONFIG_ABI,
          ...EULER_ROUTER_CONFIG_SET_ABI,
        ],
      });

      // Partition by topic[0]
      const ltvLogs: Log[] = [];
      const hookLogs: Log[] = [];
      const oracleLogs: Log[] = [];

      for (const log of logs) {
        const topic = log.topics[0];
        if (!topic) continue;
        if (topic.toLowerCase() === TOPIC_GOV_SET_LTV.toLowerCase()) {
          ltvLogs.push(log);
        } else if (
          topic.toLowerCase() === TOPIC_GOV_SET_HOOK_CONFIG.toLowerCase()
        ) {
          hookLogs.push(log);
        } else if (
          topic.toLowerCase() === TOPIC_EULER_ROUTER_CONFIG_SET.toLowerCase()
        ) {
          oracleLogs.push(log);
        }
      }

      console.log(
        `[govShock] block=${ctx.blockNumber} ltv=${ltvLogs.length} hook=${hookLogs.length} oracle=${oracleLogs.length}`,
      );

      // ── LTV events ───────────────────────────────────────────────────────
      for (const log of ltvLogs) {
        try {
          const event = this.decodeLTVLog(log, ctx);
          if (!event) continue;
          const alert = await this.processLTVChange(event, ctx);
          if (alert) alerts.push(alert);
        } catch (err) {
          console.error(
            `[govShock] error decoding/processing LTV log tx=${log.transactionHash}:`,
            err,
          );
        }
      }

      // ── Hook-config events ────────────────────────────────────────────────
      for (const log of hookLogs) {
        try {
          const event = this.decodeHookLog(log, ctx);
          if (!event) continue;
          const alert = await this.processHookChange(event, ctx);
          if (alert) alerts.push(alert);
        } catch (err) {
          console.error(
            `[govShock] error decoding/processing hook log tx=${log.transactionHash}:`,
            err,
          );
        }
      }

      // ── Oracle config events ──────────────────────────────────────────────
      for (const log of oracleLogs) {
        try {
          const alert = await this.processOracleConfigLog(log, ctx);
          if (alert) alerts.push(alert);
        } catch (err) {
          console.error(
            `[govShock] error processing oracle log tx=${log.transactionHash}:`,
            err,
          );
        }
      }

      this.lastProcessedBlock = ctx.blockNumber;
    } catch (err) {
      console.error(
        `[govShock] fatal error in run() block=${ctx.blockNumber}:`,
        err,
      );
    }

    return alerts;
  }

  // -------------------------------------------------------------------------
  // LTV change processing
  // -------------------------------------------------------------------------

  /**
   * Processes a GovSetLTV event.
   *
   * Only emits an alert when targetLTV < currentLiqLTV (i.e. a reduction).
   * rampDuration == 0 → immediateAction; rampDuration > 0 → ramped reduction.
   */
  async processLTVChange(
    event: GovSetLTVEvent,
    ctx: BlockContext,
  ): Promise<GovernanceAlert | null> {
    const key = ltvKey(event.vault, event.collateral);
    const currentLiqLTV = this.knownLTVs.get(key) ?? event.liquidationLTV;

    const targetLTV = event.targetLTV;

    console.log(
      `[govShock] GovSetLTV vault=${event.vault} collateral=${event.collateral} ` +
        `currentLiqLTV=${currentLiqLTV} targetLTV=${targetLTV} ` +
        `rampDuration=${event.rampDuration}s`,
    );

    // Only act on reductions
    if (targetLTV >= currentLiqLTV) {
      // Update our known LTV even for increases so we track current state
      this.knownLTVs.set(key, event.liquidationLTV);
      // Clear any stale ramp
      this.activeRamps.delete(key);
      console.log(
        `[govShock] LTV increase or no change – skipping alert (target=${targetLTV} >= current=${currentLiqLTV})`,
      );
      return null;
    }

    // It is a reduction – update state
    this.knownLTVs.set(key, targetLTV);

    const immediate = event.rampDuration === 0;

    if (!immediate) {
      // Register the ramp so computeLTVRamp can be used by other parts of the system
      this.activeRamps.set(key, {
        initialLTV: event.initialLTV,
        targetLTV: event.targetLTV,
        startTime: ctx.blockTimestamp,
        rampDuration: event.rampDuration,
      });
      console.log(
        `[govShock] LTV ramp registered key=${key} duration=${event.rampDuration}s`,
      );
    } else {
      this.activeRamps.delete(key);
    }

    // Find all positions that become liquidatable at the new LTV
    const affectedPositions = await this.findAffectedPositions(
      event.vault,
      event.collateral,
      targetLTV,
    );

    // For ramped reductions, compute which block each position becomes liquidatable
    if (!immediate && affectedPositions.length > 0) {
      const ramp = this.activeRamps.get(key)!;
      for (const pos of affectedPositions) {
        if (pos.hfAtNewLTV < 1.0) {
          // HF already < 1 at final target – find intermediate LTV that triggers it
          const triggerLTV = await this.findTriggerLTV(
            pos.collateralVault,
            pos.account,
            ramp,
          );
          const secondsUntilTrigger = this.rampTimeForLTV(ramp, triggerLTV);
          const blocksUntilTrigger = BigInt(
            Math.ceil(secondsUntilTrigger / BLOCK_TIME_SECONDS),
          );
          pos.becomesLiquidatableAtBlock =
            ctx.blockNumber + blocksUntilTrigger;
        }
      }
    }

    const estimatedTotalProfitUsd = affectedPositions.reduce(
      (sum, p) => sum + p.estimatedProfitUsd,
      0,
    );

    const alert: GovernanceAlert = {
      type: "ltv_reduction",
      event,
      affectedPositions,
      immediateAction: immediate,
      estimatedTotalProfitUsd,
      detectedAt: Date.now(),
    };

    console.log(
      `[govShock] LTV reduction alert: vault=${event.vault} collateral=${event.collateral} ` +
        `affected=${affectedPositions.length} totalProfit=$${estimatedTotalProfitUsd.toFixed(2)} ` +
        `immediate=${immediate}`,
    );

    return alert;
  }

  // -------------------------------------------------------------------------
  // Hook-config change processing
  // -------------------------------------------------------------------------

  /**
   * Processes a GovSetHookConfig event.
   *
   * Detects vault unpause: hookTarget changing from non-zero to zero, OR
   * OP_REDEEM bit (bit 8 / 0x100) being cleared in hookedOps.
   */
  async processHookChange(
    event: GovSetHookConfigEvent,
    ctx: BlockContext,
  ): Promise<GovernanceAlert | null> {
    const vaultKey = event.vault.toLowerCase();
    const previousHookedOps = this.knownHookedOps.get(vaultKey);

    console.log(
      `[govShock] GovSetHookConfig vault=${event.vault} ` +
        `hookTarget=${event.hookTarget} hookedOps=0x${event.hookedOps.toString(16)} ` +
        `previousHookedOps=${previousHookedOps !== undefined ? "0x" + previousHookedOps.toString(16) : "unknown"}`,
    );

    // Update known state
    this.knownHookedOps.set(vaultKey, event.hookedOps);

    // Determine if this is an unpause event
    const hookTargetIsZero =
      event.hookTarget === "0x0000000000000000000000000000000000000000";
    const redeemBitNowClear = (event.hookedOps & OP_REDEEM_BIT) === 0;

    const wasRedeemPaused =
      previousHookedOps !== undefined
        ? (previousHookedOps & OP_REDEEM_BIT) !== 0
        : !redeemBitNowClear; // assume was paused if we had no prior knowledge and it's now clear

    const isUnpause =
      (hookTargetIsZero && previousHookedOps !== undefined) ||
      (redeemBitNowClear && wasRedeemPaused);

    if (!isUnpause) {
      // A pause or neutral hook change – record as hook_change without deep position scan
      const alert: GovernanceAlert = {
        type: "hook_change",
        event,
        affectedPositions: [],
        immediateAction: false,
        estimatedTotalProfitUsd: 0,
        detectedAt: Date.now(),
      };

      console.log(
        `[govShock] hook_change (non-unpause) vault=${event.vault} ` +
          `hookTarget=${event.hookTarget}`,
      );

      return alert;
    }

    // Unpause: scan for positions that were blocked and are now liquidatable
    console.log(
      `[govShock] UNPAUSE detected for vault=${event.vault} – scanning positions`,
    );

    // For unpause we don't have a specific collateral, so we use zero address
    // to signal "all collaterals" and let findAffectedPositions handle it.
    // We pass the current known LTV (or 0 to force all positions with HF<1).
    const affectedPositions = await this.findAffectedPositions(
      event.vault,
      "0x0000000000000000000000000000000000000000",
      0, // newLiqLTV=0 → return all positions with HF < 1 regardless of LTV
    );

    const estimatedTotalProfitUsd = affectedPositions.reduce(
      (sum, p) => sum + p.estimatedProfitUsd,
      0,
    );

    const alert: GovernanceAlert = {
      type: "unpause",
      event,
      affectedPositions,
      immediateAction: true,
      estimatedTotalProfitUsd,
      detectedAt: Date.now(),
    };

    console.log(
      `[govShock] unpause alert vault=${event.vault} affected=${affectedPositions.length} ` +
        `totalProfit=$${estimatedTotalProfitUsd.toFixed(2)}`,
    );

    return alert;
  }

  // -------------------------------------------------------------------------
  // Oracle config change (informational alert only)
  // -------------------------------------------------------------------------

  /**
   * Emits an oracle_change alert when the Euler router config changes.
   * Actual price divergence analysis is handled by Module A (oracleHunter).
   * This module surfaces the governance action so the orchestrator can
   * trigger a re-scan of affected positions.
   */
  private async processOracleConfigLog(
    log: Log,
    ctx: BlockContext,
  ): Promise<GovernanceAlert | null> {
    try {
      const decoded = decodeEventLog({
        abi: EULER_ROUTER_CONFIG_SET_ABI,
        data: log.data,
        topics: log.topics,
      });

      const { asset1, asset2, oracle } = decoded.args as {
        asset1: Address;
        asset2: Address;
        oracle: Address;
      };

      console.log(
        `[govShock] EulerRouterConfigSet asset1=${asset1} asset2=${asset2} oracle=${oracle} ` +
          `block=${ctx.blockNumber}`,
      );

      // Synthetic event for the alert – we re-use GovSetHookConfigEvent shape
      // since GovernanceAlert.event is a union type.  We manufacture a minimal
      // GovSetHookConfigEvent so the alert carries the relevant addresses.
      const syntheticEvent: GovSetHookConfigEvent = {
        vault: oracle, // oracle address in hookTarget field
        hookTarget: asset1,
        hookedOps: 0,
        txHash: log.transactionHash ?? "0x",
        blockNumber: ctx.blockNumber,
      };

      const alert: GovernanceAlert = {
        type: "oracle_change",
        event: syntheticEvent,
        affectedPositions: [],
        immediateAction: false,
        estimatedTotalProfitUsd: 0,
        detectedAt: Date.now(),
      };

      return alert;
    } catch (err) {
      console.error("[govShock] failed to decode EulerRouterConfigSet:", err);
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Find affected positions
  // -------------------------------------------------------------------------

  /**
   * Returns all accounts that hold a position in `vault` (as controller)
   * with `collateral` as collateral vault and that become liquidatable at
   * `newLiqLTV`.
   *
   * When collateral is the zero address, ALL collaterals are considered.
   * When newLiqLTV is 0, positions are returned if their current HF < 1.
   */
  async findAffectedPositions(
    vault: Address,
    collateral: Address,
    newLiqLTV: number,
  ): Promise<GovernanceAffectedPosition[]> {
    const results: GovernanceAffectedPosition[] = [];

    // Step 1: obtain candidate accounts
    const accounts = await this.getAccountsForVault(vault);

    if (accounts.length === 0) {
      console.log(
        `[govShock] findAffectedPositions: no accounts found for vault=${vault}`,
      );
      return results;
    }

    console.log(
      `[govShock] findAffectedPositions: vault=${vault} collateral=${collateral} ` +
        `newLiqLTV=${newLiqLTV} candidates=${accounts.length}`,
    );

    const zero = "0x0000000000000000000000000000000000000000";
    const checkAllCollaterals = collateral.toLowerCase() === zero.toLowerCase();
    const newLiqLTVFrac = newLiqLTV / LTV_DENOM;

    // Step 2: for each account, evaluate liquidity
    for (const account of accounts.slice(0, MAX_ACCOUNTS_PER_VAULT)) {
      try {
        // Determine which collaterals to check for this account
        let collateralsToCheck: Address[];
        if (checkAllCollaterals) {
          collateralsToCheck = await this.getCollaterals(account);
        } else {
          collateralsToCheck = [collateral];
        }

        // Get current liquidity (non-liquidation mode gives current HF numerics)
        const { collateralValue, liabilityValue } =
          await this.getAccountLiquidity(account, vault, false);

        if (liabilityValue === 0n) {
          // No debt – skip
          continue;
        }

        // Current HF
        const currentHF =
          liabilityValue > 0n
            ? Number(collateralValue) / Number(liabilityValue)
            : Infinity;

        // HF at new LTV: scale collateral value by (newLiqLTV / currentLTV)
        // We approximate: if we reduce the LTV by factor f, collateral value
        // (as reported by the risk-adjusted lens) scales linearly.
        // A more precise route would be to call getAccountLiquidity with a
        // patched LTV – but we cannot do that on-chain.  Instead we re-weight:
        //
        //   adjustedCollateralValue = rawCollateralValue * newLiqLTVFrac / currentLTVFrac
        //
        // When newLiqLTV==0 we treat the HF at new LTV as 0 (check all).
        let hfAtNewLTV: number;
        if (newLiqLTV === 0) {
          hfAtNewLTV = currentHF; // no LTV change context – use current HF
        } else {
          const currentLiqLTV = this.knownLTVs.get(
            ltvKey(vault, collateral),
          );
          if (currentLiqLTV !== undefined && currentLiqLTV > 0) {
            const currentLiqLTVFrac = currentLiqLTV / LTV_DENOM;
            const scaleFactor = newLiqLTVFrac / currentLiqLTVFrac;
            const adjustedCollateral =
              Number(collateralValue) * scaleFactor;
            hfAtNewLTV =
              liabilityValue > 0n
                ? adjustedCollateral / Number(liabilityValue)
                : Infinity;
          } else {
            // No prior LTV on record – use collateralValue * newLiqLTVFrac
            // compared against liabilityValue directly (raw comparison)
            const scaledCollateral =
              Number(collateralValue) * newLiqLTVFrac;
            hfAtNewLTV =
              liabilityValue > 0n
                ? scaledCollateral / Number(liabilityValue)
                : Infinity;
          }
        }

        // Determine if this position is (or will become) liquidatable
        const becomesLiquidatable =
          (newLiqLTV === 0 && currentHF < 1.0) ||
          (newLiqLTV > 0 && hfAtNewLTV < 1.0);

        if (!becomesLiquidatable) continue;

        // Estimate profit: simplified as (1 - HF_new) * liabilityValue in ETH
        // Assuming liability is ETH-denominated (Euler accountLiquidity returns
        // values in the same units used by the oracle, typically ETH).
        const liabilityEth = Number(liabilityValue) / 1e18;
        // Rough ETH→USD: we don't have the price here, use 1 ETH = $1 placeholder
        // (the orchestrator can re-price; we just produce a relative ordering).
        const estimatedProfitUsd = Math.max(
          0,
          (1.0 - hfAtNewLTV) * liabilityEth,
        );

        const pos: GovernanceAffectedPosition = {
          account,
          borrowVault: vault,
          collateralVault:
            collateralsToCheck.length > 0 ? collateralsToCheck[0]! : collateral,
          currentHF,
          hfAtNewLTV,
          becomesLiquidatableAtBlock: 0n, // overwritten by ramp logic if needed
          estimatedProfitUsd,
        };

        results.push(pos);
      } catch (err) {
        console.error(
          `[govShock] error evaluating account=${account} vault=${vault}:`,
          err,
        );
      }
    }

    return results;
  }

  // -------------------------------------------------------------------------
  // LTV ramp computation
  // -------------------------------------------------------------------------

  /**
   * Returns the effective liquidation LTV at `currentTimestamp` during the
   * ramp from `initialLTV` → `targetLTV` over `rampDuration` seconds.
   *
   * The Euler ramp is linear in time:
   *   effectiveLTV = initialLTV + (targetLTV - initialLTV) * elapsed / duration
   *
   * Values are clamped to [min(initial,target), max(initial,target)].
   */
  async computeLTVRamp(
    initialLTV: number,
    targetLTV: number,
    rampDuration: number,
    currentTimestamp: number,
  ): Promise<number> {
    if (rampDuration <= 0) return targetLTV;

    // We need a ramp start time; if we don't have it use currentTimestamp
    // (the ramp hasn't moved yet → return initialLTV)
    // Callers that have the startTime should subtract it from currentTimestamp.
    // This overload operates on elapsed seconds.
    const elapsed = Math.min(currentTimestamp, rampDuration);
    const fraction = elapsed / rampDuration;
    const effective = initialLTV + (targetLTV - initialLTV) * fraction;
    const lo = Math.min(initialLTV, targetLTV);
    const hi = Math.max(initialLTV, targetLTV);
    return Math.max(lo, Math.min(hi, effective));
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /** Decode a GovSetLTV log into a typed event. */
  private decodeLTVLog(
    log: Log,
    ctx: BlockContext,
  ): GovSetLTVEvent | null {
    try {
      const decoded = decodeEventLog({
        abi: GOV_SET_LTV_ABI,
        data: log.data,
        topics: log.topics,
      });

      const args = decoded.args as unknown as {
        vault: Address;
        collateral: Address;
        borrowLTV: number;
        liquidationLTV: number;
        initialLTV: number;
        targetLTV: number;
        rampDuration: bigint;
      };

      return {
        vault: args.vault,
        collateral: args.collateral,
        borrowLTV: args.borrowLTV,
        liquidationLTV: args.liquidationLTV,
        initialLTV: args.initialLTV,
        targetLTV: args.targetLTV,
        rampDuration: Number(args.rampDuration),
        txHash: log.transactionHash ?? "0x",
        blockNumber: log.blockNumber ?? ctx.blockNumber,
        blockTimestamp: ctx.blockTimestamp,
      };
    } catch (err) {
      console.error("[govShock] decodeLTVLog failed:", err);
      return null;
    }
  }

  /** Decode a GovSetHookConfig log into a typed event. */
  private decodeHookLog(
    log: Log,
    ctx: BlockContext,
  ): GovSetHookConfigEvent | null {
    try {
      const decoded = decodeEventLog({
        abi: GOV_SET_HOOK_CONFIG_ABI,
        data: log.data,
        topics: log.topics,
      });

      const args = decoded.args as {
        vault: Address;
        hookTarget: Address;
        hookedOps: number;
      };

      return {
        vault: args.vault,
        hookTarget: args.hookTarget,
        hookedOps: Number(args.hookedOps),
        txHash: log.transactionHash ?? "0x",
        blockNumber: log.blockNumber ?? ctx.blockNumber,
      };
    } catch (err) {
      console.error("[govShock] decodeHookLog failed:", err);
      return null;
    }
  }

  /**
   * Returns all accounts that have `vault` as an enabled controller via EVC.
   *
   * The EVC does not provide an enumerable list of all accounts per controller
   * directly.  We use a two-step strategy:
   *   1. Query the vault's own AccountStatusCheck events (off-chain indexed)
   *      – not available synchronously here.
   *   2. Fall back to on-chain enumeration of recent EVC AccountStatusCheck
   *      events for the vault within the last N blocks.
   *
   * For production use, an off-chain index should feed this.  As a practical
   * fallback we scan the last 50 000 blocks of EVC logs filtered by the vault
   * address in topic[1] (StatusChecks are emitted per account/controller pair).
   */
  private async getAccountsForVault(vault: Address): Promise<Address[]> {
    const accounts = new Set<Address>();

    try {
      // EVC emits AccountStatusCheck(address indexed onBehalfOfAccount, address indexed controller)
      // topic[0] = keccak256("AccountStatusCheck(address,address)")
      // topic[1] = account
      // topic[2] = controller  (== vault)
      const ACCOUNT_STATUS_CHECK_TOPIC =
        "0x4428d0f3f0e72b4a9f3e5f7a3e2c9f0b3d1e8a4c6b2e0d7f5c3a1b9e4f2d0c8" as `0x${string}`;

      // Approximate: scan last 100 000 blocks
      const fromBlock =
        this.lastProcessedBlock > 100_000n
          ? this.lastProcessedBlock - 100_000n
          : 0n;

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const logs = await (this.client.getLogs as any)({
        address: EULER_EVC,
        fromBlock,
        toBlock: "latest",
        topics: [
          ACCOUNT_STATUS_CHECK_TOPIC,
          null,
          `0x000000000000000000000000${vault.slice(2).toLowerCase()}`,
        ],
      }) as Log[];

      for (const log of logs) {
        const accountTopic = log.topics[1];
        if (accountTopic) {
          // topics are 32-byte padded; extract rightmost 20 bytes as address
          const addr = `0x${accountTopic.slice(-40)}` as Address;
          accounts.add(addr);
        }
      }
    } catch (err) {
      console.error(
        `[govShock] getAccountsForVault: log scan failed for vault=${vault}:`,
        err,
      );
    }

    // If log-scan yielded nothing, return empty – callers handle gracefully
    return Array.from(accounts);
  }

  /** Returns the collateral list for an account via EVC. */
  private async getCollaterals(account: Address): Promise<Address[]> {
    try {
      const result = await this.client.readContract({
        address: EULER_EVC,
        abi: EVC_ABI,
        functionName: "getCollaterals",
        args: [account],
      });
      return result as Address[];
    } catch (err) {
      console.error(
        `[govShock] getCollaterals failed for account=${account}:`,
        err,
      );
      return [];
    }
  }

  /** Returns collateral + liability values for an account/vault pair. */
  private async getAccountLiquidity(
    account: Address,
    controller: Address,
    liquidation: boolean,
  ): Promise<{ collateralValue: bigint; liabilityValue: bigint }> {
    try {
      const result = (await this.client.readContract({
        address: EULER_ACCOUNT_LENS,
        abi: ACCOUNT_LENS_ABI,
        functionName: "getAccountLiquidity",
        args: [account, controller, liquidation],
      })) as [bigint, bigint];

      return {
        collateralValue: result[0],
        liabilityValue: result[1],
      };
    } catch (err) {
      console.error(
        `[govShock] getAccountLiquidity failed account=${account} controller=${controller}:`,
        err,
      );
      return { collateralValue: 0n, liabilityValue: 0n };
    }
  }

  /**
   * For a ramped reduction: find the intermediate LTV at which a given
   * position tips below HF=1.  Uses binary search over the ramp interval.
   *
   * Returns the LTV (in basis points) at the trigger point.
   */
  private async findTriggerLTV(
    vault: Address,
    account: Address,
    ramp: RampState,
  ): Promise<number> {
    // Binary search between targetLTV (lower bound) and initialLTV (upper bound)
    let lo = ramp.targetLTV;
    let hi = ramp.initialLTV;

    for (let iter = 0; iter < 20; iter++) {
      const mid = Math.round((lo + hi) / 2);
      const midFrac = mid / LTV_DENOM;

      // Approximate HF at mid LTV using the stored current liquidity
      // We do not re-query the chain per iteration to save RPC calls.
      // Instead we derive from stored state in findAffectedPositions.
      // Here we just do a linear interpolation check.
      const { collateralValue, liabilityValue } =
        await this.getAccountLiquidity(account, vault, true);

      if (liabilityValue === 0n) return ramp.targetLTV;

      const scaledCollateral = Number(collateralValue) * midFrac;
      const hf = scaledCollateral / Number(liabilityValue);

      if (hf < 1.0) {
        lo = mid;
      } else {
        hi = mid;
      }

      if (hi - lo <= 1) break;
    }

    return lo;
  }

  /**
   * Given a ramp and a trigger LTV (in bps), returns the number of seconds
   * from ramp start until that LTV is reached.
   *
   * triggerLTV is assumed to be between targetLTV and initialLTV.
   * Returns 0 if target is already reached.
   */
  private rampTimeForLTV(ramp: RampState, triggerLTV: number): number {
    const span = ramp.initialLTV - ramp.targetLTV;
    if (span === 0) return 0;
    const needed = ramp.initialLTV - triggerLTV;
    const fraction = needed / span;
    return Math.max(0, fraction * ramp.rampDuration);
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Canonical map key for a (vault, collateral) LTV pair. */
function ltvKey(vault: Address, collateral: Address): string {
  return `${vault.toLowerCase()}:${collateral.toLowerCase()}`;
}
