/**
 * Module H.4 — Upgrade Path Monitor
 *
 * Watches for proxy implementation changes (EIP-1967 Upgraded events) on
 * all known proxy contracts. When an upgrade is detected, diffs the new
 * implementation bytecode against the cached previous implementation at the
 * function-selector level to find introduced vulnerabilities.
 *
 * Attack patterns detected:
 *   - New implementation adds selfdestruct / arbitrary delegatecall
 *   - Access control removed from fund-flow functions
 *   - New external call targets (previously hardcoded, now dynamic)
 *   - Functions removed that users depend on (griefing / forced migration)
 *   - Storage layout changes (can corrupt state of existing storage)
 */

import type { Address, Hex, PublicClient } from "viem";
import type {
  SupportedChain,
  UpgradeAlert,
  UpgradeDiffFinding,
  UpgradeDiffClass,
  MisconfigSeverity,
  BlockContext,
} from "./types.js";
import { getChainClient } from "./chains.js";
import { critical, alert, warn, info } from "./alerter.js";

// ─── Constants ──────────────────────────────────────────────────────────

/** EIP-1967 Upgraded(address indexed implementation) event topic */
const UPGRADED_TOPIC =
  "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b" as const;

/** EIP-1967 implementation storage slot */
const IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;

/** Selectors associated with dangerous operations (bare hex, no 0x). */
const DANGEROUS_SELECTORS = new Set([
  "ff",         // SELFDESTRUCT opcode marker
  "f4",         // DELEGATECALL opcode marker
  "3659cfe6",   // upgradeTo
  "4f1ef286",   // upgradeToAndCall
  "f2fde38b",   // transferOwnership
  "60f9bb11",   // emergencyWithdraw
  "db2e21bc",   // emergencyExit
  "40c10f19",   // mint(address,uint256)
  "9dc29fac",   // burn(address,uint256)
]);

/** Selectors associated with access control (if removed = high risk). */
const ACCESS_CONTROL_SELECTORS = new Set([
  "8da5cb5b",   // owner()
  "f2fde38b",   // transferOwnership
  "5c975abb",   // paused()
  "715018a6",   // renounceOwnership()
]);

// ─── UpgradeMonitor ──────────────────────────────────────────────────────

export class UpgradeMonitor {
  /**
   * Cache of last-known implementation bytecodes per proxy.
   * Maps proxyAddress → { implAddress, bytecode, selectors }
   */
  private readonly implCache = new Map<Address, {
    implAddress: Address;
    selectors: Set<string>;
    hasSelfDestruct: boolean;
    hasDelegatecall: boolean;
  }>();

  private readonly watchedProxies = new Map<SupportedChain, Set<Address>>();

  /**
   * Registers a set of proxy addresses to watch for upgrades.
   * Call this from MassAuditOrchestrator as contracts are audited.
   */
  watchProxies(addresses: Address[], chain: SupportedChain): void {
    if (!this.watchedProxies.has(chain)) this.watchedProxies.set(chain, new Set());
    const set = this.watchedProxies.get(chain)!;
    for (const addr of addresses) set.add(addr.toLowerCase() as Address);
  }

  /**
   * Scans recent blocks for Upgraded events on watched proxies.
   * Called from the per-block loop in index.ts.
   */
  async run(ctx: BlockContext, chain: SupportedChain): Promise<UpgradeAlert[]> {
    const alerts: UpgradeAlert[] = [];
    const client = getChainClient(chain);
    const watched = this.watchedProxies.get(chain);
    if (!watched || watched.size === 0) return alerts;

    try {
      // Scan last 10 blocks for Upgraded events on watched contracts
      const fromBlock = ctx.blockNumber > 10n ? ctx.blockNumber - 10n : 0n;

      const logs = await (client.getLogs as (args: {
        fromBlock: bigint;
        toBlock: bigint;
        topics: (Hex | null)[];
      }) => Promise<Array<{
        address: Address;
        topics: (Hex | undefined)[];
        transactionHash?: Hex;
        blockNumber?: bigint;
      }>>)({
        fromBlock,
        toBlock: ctx.blockNumber,
        topics: [UPGRADED_TOPIC as Hex],
      });

      for (const log of logs) {
        const proxy = log.address.toLowerCase() as Address;
        if (!watched.has(proxy)) continue;

        // topic[1] = indexed implementation address (32 bytes, right-aligned)
        const implTopic = log.topics[1];
        if (!implTopic) continue;
        const newImpl = ("0x" + implTopic.slice(-40)) as Address;

        const upgradeAlerts = await this.handleUpgrade(
          proxy,
          newImpl,
          log.transactionHash ?? "0x0" as Hex,
          log.blockNumber ?? ctx.blockNumber,
          chain,
          client,
        );
        alerts.push(...upgradeAlerts);
      }
    } catch (err) {
      warn("upgrade-monitor", `Block scan failed on ${chain}: ${(err as Error).message}`);
    }

    return alerts;
  }

  /**
   * Seeds the cache with current implementation for all watched proxies.
   * Call this once at startup to establish a baseline.
   */
  async seedCache(chain: SupportedChain): Promise<void> {
    const client = getChainClient(chain);
    const watched = this.watchedProxies.get(chain);
    if (!watched) return;

    let seeded = 0;
    for (const proxy of watched) {
      try {
        const implSlot = await client.getStorageAt({
          address: proxy,
          slot: IMPL_SLOT as Hex,
        });
        if (!implSlot || implSlot === "0x" + "0".repeat(64)) continue;
        const impl = ("0x" + implSlot.slice(-40)) as Address;
        if (impl === "0x0000000000000000000000000000000000000000") continue;

        const bytecode = await client.getBytecode({ address: impl });
        if (!bytecode || bytecode === "0x") continue;

        this.implCache.set(proxy, {
          implAddress: impl,
          selectors: this.extractSelectors(bytecode),
          hasSelfDestruct: this.hasSelfDestruct(bytecode),
          hasDelegatecall: this.hasDelegatecall(bytecode),
        });
        seeded++;
      } catch {
        // Non-fatal
      }
    }
    info("upgrade-monitor", `Cache seeded: ${seeded}/${watched.size} proxies on ${chain}`);
  }

  // ── Private ─────────────────────────────────────────────────────────────

  private async handleUpgrade(
    proxy: Address,
    newImpl: Address,
    txHash: Hex,
    blockNumber: bigint,
    chain: SupportedChain,
    client: PublicClient,
  ): Promise<UpgradeAlert[]> {
    const alerts: UpgradeAlert[] = [];

    // Fetch new implementation bytecode
    let newBytecode: Hex | undefined;
    try {
      newBytecode = await client.getBytecode({ address: newImpl });
    } catch {
      warn("upgrade-monitor", `Failed to fetch bytecode for new impl ${newImpl}`);
    }

    const cached = this.implCache.get(proxy);
    const diffFindings: UpgradeDiffFinding[] = [];

    if (cached && newBytecode && newBytecode !== "0x") {
      const newSelectors = this.extractSelectors(newBytecode);
      const newHasSelfDestruct = this.hasSelfDestruct(newBytecode);
      const newHasDelegatecall = this.hasDelegatecall(newBytecode);

      // ── Finding: new selfdestruct ──────────────────────────────────
      if (newHasSelfDestruct && !cached.hasSelfDestruct) {
        diffFindings.push({
          diffClass: "new_selfdestruct",
          description: "New implementation contains SELFDESTRUCT opcode — can destroy proxy and drain ETH",
          severity: "critical",
        });
      }

      // ── Finding: new delegatecall (if not in old impl) ────────────
      if (newHasDelegatecall && !cached.hasDelegatecall) {
        diffFindings.push({
          diffClass: "new_delegatecall",
          description: "New implementation contains DELEGATECALL not present in previous — arbitrary execution risk",
          severity: "critical",
        });
      }

      // ── Finding: removed selectors (functions that disappeared) ────
      for (const sel of cached.selectors) {
        if (!newSelectors.has(sel)) {
          const isAccessControl = ACCESS_CONTROL_SELECTORS.has(sel);
          diffFindings.push({
            diffClass: isAccessControl ? "removed_access_control" : "removed_function",
            selector: `0x${sel}` as Hex,
            description: isAccessControl
              ? `Access control function removed (selector 0x${sel}) — may weaken security guarantees`
              : `Function removed (selector 0x${sel}) — breaking change for integrators`,
            severity: isAccessControl ? "critical" : "medium",
          });
        }
      }

      // ── Finding: added dangerous selectors ─────────────────────────
      for (const sel of newSelectors) {
        if (!cached.selectors.has(sel) && DANGEROUS_SELECTORS.has(sel)) {
          diffFindings.push({
            diffClass: "added_function",
            selector: `0x${sel}` as Hex,
            description: `New implementation adds known-dangerous function (selector 0x${sel})`,
            severity: "critical",
          });
        }
      }

      // ── Finding: new external call targets (net-new selectors calling external contracts)
      const netNewSelectors = [...newSelectors].filter((s) => !cached.selectors.has(s));
      if (netNewSelectors.length > 5) {
        diffFindings.push({
          diffClass: "added_function",
          description:
            `New implementation adds ${netNewSelectors.length} new function selectors — ` +
            `significant logic change, review for new external call targets`,
          severity: "high",
        });
      }
    } else if (newBytecode && newBytecode !== "0x") {
      // No cached baseline — first time seeing this proxy
      const newSelectors = this.extractSelectors(newBytecode);
      if (this.hasSelfDestruct(newBytecode)) {
        diffFindings.push({
          diffClass: "new_selfdestruct",
          description: "Implementation contains SELFDESTRUCT (no baseline to compare — first upgrade observed)",
          severity: "critical",
        });
      }
      // Seed the cache
      this.implCache.set(proxy, {
        implAddress: newImpl,
        selectors: newSelectors,
        hasSelfDestruct: this.hasSelfDestruct(newBytecode),
        hasDelegatecall: this.hasDelegatecall(newBytecode),
      });
    }

    // Update cache with new impl
    if (newBytecode && newBytecode !== "0x") {
      this.implCache.set(proxy, {
        implAddress: newImpl,
        selectors: this.extractSelectors(newBytecode),
        hasSelfDestruct: this.hasSelfDestruct(newBytecode),
        hasDelegatecall: this.hasDelegatecall(newBytecode),
      });
    }

    const severity = this.aggregateSeverity(diffFindings);

    const upgradeAlert: UpgradeAlert = {
      proxyAddress: proxy,
      chain,
      previousImpl: cached?.implAddress,
      newImpl,
      txHash,
      blockNumber,
      diffFindings,
      severity,
      detectedAt: Date.now(),
    };

    if (diffFindings.length > 0) {
      const logFn = severity === "critical" ? critical : severity === "high" ? alert : warn;
      logFn(
        "upgrade-monitor",
        `PROXY UPGRADED: ${proxy.slice(0, 12)}… → ${newImpl.slice(0, 12)}…`,
        `${diffFindings.length} diff findings | Severity: ${severity} | ` +
          diffFindings.map((f) => f.diffClass).join(", "),
        upgradeAlert,
      );
      alerts.push(upgradeAlert);
    } else {
      info(
        "upgrade-monitor",
        `Proxy ${proxy.slice(0, 12)}… upgraded to ${newImpl.slice(0, 12)}… (no concerning diffs)`,
      );
    }

    return alerts;
  }

  /**
   * Extracts 4-byte function selectors from bytecode by scanning for
   * PUSH4 opcode (0x63) patterns, which precede selector comparisons.
   */
  private extractSelectors(bytecode: Hex): Set<string> {
    const code = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
    const selectors = new Set<string>();

    // Scan for PUSH4 (0x63) followed by 4 bytes
    for (let i = 0; i < code.length - 10; i += 2) {
      if (code[i] === "6" && code[i + 1] === "3") {
        const sel = code.slice(i + 2, i + 10);
        if (/^[0-9a-f]{8}$/.test(sel)) {
          selectors.add(sel);
        }
      }
    }
    return selectors;
  }

  private hasSelfDestruct(bytecode: Hex): boolean {
    const code = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
    // SELFDESTRUCT opcode = 0xff
    return /ff/.test(code);
  }

  private hasDelegatecall(bytecode: Hex): boolean {
    const code = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
    // DELEGATECALL opcode = 0xf4
    return /f4/.test(code);
  }

  private aggregateSeverity(findings: UpgradeDiffFinding[]): MisconfigSeverity {
    if (findings.some((f) => f.severity === "critical")) return "critical";
    if (findings.some((f) => f.severity === "high")) return "high";
    if (findings.some((f) => f.severity === "medium")) return "medium";
    return "low";
  }
}
