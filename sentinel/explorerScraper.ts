/**
 * Module G.1 — Block Explorer Scraper
 *
 * Rate-limited client for Etherscan / SonicScan APIs (identical format).
 * Fetches verified source code, recently verified contracts, and contracts
 * deployed by known DeFi factory addresses.
 */

import type { Address, Hash } from "viem";
import type { ExplorerContractEntry, SupportedChain } from "./types.js";
import { CHAIN_CONFIGS } from "./chains.js";
import { warn, info } from "./alerter.js";

// ─── Constants ──────────────────────────────────────────────────────────

const MAX_REQUESTS_PER_SECOND = 4;
const REQUEST_INTERVAL_MS = Math.ceil(1000 / MAX_REQUESTS_PER_SECOND);
const FETCH_TIMEOUT_MS = 15_000;
const MAX_RETRIES = 2;

// ─── Rate Limiter ───────────────────────────────────────────────────────

class RateLimiter {
  private lastRequestMs = 0;

  async wait(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastRequestMs;
    if (elapsed < REQUEST_INTERVAL_MS) {
      await new Promise((r) => setTimeout(r, REQUEST_INTERVAL_MS - elapsed));
    }
    this.lastRequestMs = Date.now();
  }
}

// ─── Explorer API response shapes ───────────────────────────────────────

interface ExplorerApiResponse {
  status: string;
  message: string;
  result: unknown;
}

interface SourceCodeResult {
  SourceCode: string;
  ABI: string;
  ContractName: string;
  CompilerVersion: string;
  OptimizationUsed: string;
  Runs: string;
  ConstructorArguments: string;
  EVMVersion: string;
  Library: string;
  LicenseType: string;
  Proxy: string;
  Implementation: string;
  SwarmSource: string;
}

interface ContractCreationResult {
  contractAddress: string;
  contractCreator: string;
  txHash: string;
}

interface InternalTxResult {
  from: string;
  to: string;
  contractAddress: string;
  hash: string;
  blockNumber: string;
  type: string;
}

// ─── ExplorerScraper ────────────────────────────────────────────────────

export class ExplorerScraper {
  private readonly rateLimiters = new Map<SupportedChain, RateLimiter>();

  constructor() {
    this.rateLimiters.set("sonic", new RateLimiter());
    this.rateLimiters.set("ethereum", new RateLimiter());
  }

  // ── Public API ──────────────────────────────────────────────────────

  /**
   * Fetches verified source code from block explorer for a given address.
   * Returns an ExplorerContractEntry with sourceCode + abi populated if verified.
   */
  async getVerifiedSource(
    address: Address,
    chain: SupportedChain,
  ): Promise<ExplorerContractEntry> {
    const result = await this.explorerFetch(chain, {
      module: "contract",
      action: "getsourcecode",
      address,
    });

    const entries = result as SourceCodeResult[];
    if (!entries || entries.length === 0) {
      return this.unverifiedEntry(address, chain);
    }

    const entry = entries[0];
    const isVerified = entry.ABI !== "Contract source code not verified";

    // Handle Etherscan multi-file source format (starts with {{ )
    let sourceCode = entry.SourceCode;
    if (sourceCode.startsWith("{{")) {
      try {
        // Etherscan wraps multi-file in double-braces JSON
        const parsed = JSON.parse(sourceCode.slice(1, -1)) as {
          sources: Record<string, { content: string }>;
        };
        sourceCode = Object.values(parsed.sources)
          .map((s) => s.content)
          .join("\n\n// ─── FILE BOUNDARY ───\n\n");
      } catch {
        // keep raw if parsing fails
      }
    }

    return {
      address,
      chain,
      name: entry.ContractName || undefined,
      compilerVersion: entry.CompilerVersion || undefined,
      optimizationUsed: entry.OptimizationUsed === "1",
      sourceCode: isVerified ? sourceCode : undefined,
      abi: isVerified && entry.ABI !== "Contract source code not verified"
        ? entry.ABI
        : undefined,
      isVerified,
      implementationAddress:
        entry.Implementation && entry.Implementation !== ""
          ? (entry.Implementation as Address)
          : undefined,
      scrapedAt: Date.now(),
    };
  }

  /**
   * Fetches creation info for a batch of contract addresses.
   * Etherscan supports up to 5 addresses per call.
   */
  async getContractCreation(
    addresses: Address[],
    chain: SupportedChain,
  ): Promise<Map<Address, { deployer: Address; txHash: Hash }>> {
    const results = new Map<Address, { deployer: Address; txHash: Hash }>();

    // Process in batches of 5 (Etherscan limit)
    for (let i = 0; i < addresses.length; i += 5) {
      const batch = addresses.slice(i, i + 5);
      try {
        const data = await this.explorerFetch(chain, {
          module: "contract",
          action: "getcontractcreation",
          contractaddresses: batch.join(","),
        });

        const entries = data as ContractCreationResult[];
        if (Array.isArray(entries)) {
          for (const entry of entries) {
            results.set(entry.contractAddress.toLowerCase() as Address, {
              deployer: entry.contractCreator as Address,
              txHash: entry.txHash as Hash,
            });
          }
        }
      } catch (err) {
        warn("explorer-scraper", `getContractCreation batch failed: ${(err as Error).message}`);
      }
    }

    return results;
  }

  /**
   * Given known DeFi protocol factory addresses, scrapes all contracts
   * created by those factories via internal transactions.
   * Returns addresses of child contracts for further analysis.
   */
  async scrapeFactoryDeployments(
    chain: SupportedChain,
    factoryAddresses: Address[],
    startBlock = 0,
  ): Promise<Address[]> {
    const childAddresses: Address[] = [];

    for (const factory of factoryAddresses) {
      try {
        const data = await this.explorerFetch(chain, {
          module: "account",
          action: "txlistinternal",
          address: factory,
          startblock: String(startBlock),
          endblock: "99999999",
          page: "1",
          offset: "100",
          sort: "desc",
        });

        const txs = data as InternalTxResult[];
        if (!Array.isArray(txs)) continue;

        for (const tx of txs) {
          // Internal txs with type "create" or "create2" produce child contracts
          if (
            tx.contractAddress &&
            tx.contractAddress !== "" &&
            tx.contractAddress !== "0x"
          ) {
            childAddresses.push(tx.contractAddress.toLowerCase() as Address);
          }
        }

        info(
          "explorer-scraper",
          `Factory ${factory.slice(0, 10)}... on ${chain}: ${txs.length} internal txs, ${childAddresses.length} child contracts`,
        );
      } catch (err) {
        warn(
          "explorer-scraper",
          `Factory scrape failed for ${factory} on ${chain}: ${(err as Error).message}`,
        );
      }
    }

    return [...new Set(childAddresses)];
  }

  /**
   * Scrapes a list of ERC-20 token addresses from the explorer's token tracker.
   * Falls back to fetching the most recently verified contracts.
   */
  async scrapeTokenList(
    chain: SupportedChain,
    page = 1,
    offset = 50,
  ): Promise<Address[]> {
    try {
      // Etherscan tokentx API — get recent token transfers to discover active tokens
      const data = await this.explorerFetch(chain, {
        module: "account",
        action: "tokentx",
        address: "0x0000000000000000000000000000000000000000",
        page: String(page),
        offset: String(offset),
        sort: "desc",
      });

      const txs = data as Array<{ contractAddress: string }>;
      if (!Array.isArray(txs)) return [];

      const uniqueTokens = [...new Set(txs.map((t) => t.contractAddress.toLowerCase() as Address))];
      return uniqueTokens;
    } catch {
      return [];
    }
  }

  /**
   * Batch-fetches verified source for multiple addresses.
   * Respects rate limits between each request.
   */
  async batchGetVerifiedSource(
    addresses: Address[],
    chain: SupportedChain,
  ): Promise<ExplorerContractEntry[]> {
    const results: ExplorerContractEntry[] = [];

    for (const addr of addresses) {
      try {
        const entry = await this.getVerifiedSource(addr, chain);
        results.push(entry);
      } catch (err) {
        warn("explorer-scraper", `Failed to fetch ${addr} on ${chain}: ${(err as Error).message}`);
        results.push(this.unverifiedEntry(addr, chain));
      }
    }

    return results;
  }

  // ── Private ─────────────────────────────────────────────────────────

  /**
   * Core fetch wrapper with rate limiting, timeout, retries, and error handling.
   */
  private async explorerFetch(
    chain: SupportedChain,
    params: Record<string, string>,
  ): Promise<unknown> {
    const config = CHAIN_CONFIGS[chain];
    const limiter = this.rateLimiters.get(chain)!;

    const url = new URL(config.explorerApiUrl);
    // Etherscan V2: chainid selects the target network
    url.searchParams.set("chainid", String(config.chainId));
    for (const [key, val] of Object.entries(params)) {
      url.searchParams.set(key, val);
    }
    if (config.explorerApiKey) {
      url.searchParams.set("apikey", config.explorerApiKey);
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      await limiter.wait();

      try {
        const res = await fetch(url.toString(), {
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          headers: { "Accept": "application/json" },
        });

        if (res.status === 429) {
          // Rate limited — back off exponentially
          const backoff = REQUEST_INTERVAL_MS * Math.pow(2, attempt + 1);
          warn("explorer-scraper", `Rate limited on ${chain}, backing off ${backoff}ms`);
          await new Promise((r) => setTimeout(r, backoff));
          continue;
        }

        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }

        const json = (await res.json()) as ExplorerApiResponse;

        if (json.status === "0" && json.message === "NOTOK") {
          throw new Error(`Explorer API error: ${JSON.stringify(json.result)}`);
        }

        return json.result;
      } catch (err) {
        lastError = err as Error;
        if (attempt < MAX_RETRIES) {
          await new Promise((r) => setTimeout(r, REQUEST_INTERVAL_MS * (attempt + 1)));
        }
      }
    }

    throw lastError ?? new Error("explorerFetch failed after retries");
  }

  private unverifiedEntry(address: Address, chain: SupportedChain): ExplorerContractEntry {
    return {
      address,
      chain,
      isVerified: false,
      scrapedAt: Date.now(),
    };
  }
}
