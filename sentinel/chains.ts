/**
 * Multi-chain client factory — supports Sonic (146) and Ethereum mainnet (1).
 *
 * The existing Sentinel modules continue using the Sonic-only client from
 * index.ts.  This module is used by the mass audit pipeline to create
 * chain-specific PublicClient instances.
 */

import {
  createPublicClient,
  http,
  webSocket,
  type PublicClient,
  type Chain,
} from "viem";
import { sonic, mainnet } from "viem/chains";
import type { SupportedChain } from "./types.js";

// ─── Chain Configuration ────────────────────────────────────────────────

export interface ChainConfig {
  id: SupportedChain;
  chainId: number;
  viemChain: Chain;
  rpcUrl: string;
  wsUrl?: string;
  explorerApiUrl: string;
  explorerApiKey?: string;
  explorerName: string;
  blockTimeMs: number;
}

// Etherscan V2 unified API — single endpoint, chainid parameter selects network
const ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api";

export const CHAIN_CONFIGS: Record<SupportedChain, ChainConfig> = {
  sonic: {
    id: "sonic",
    chainId: 146,
    viemChain: sonic,
    rpcUrl: process.env["RPC_URL_146"] ?? "https://rpc.soniclabs.com",
    wsUrl: process.env["WS_URL_146"],
    explorerApiUrl: ETHERSCAN_V2_BASE,
    explorerApiKey: process.env["SONICSCAN_API_KEY"],
    explorerName: "SonicScan",
    blockTimeMs: 400,
  },
  ethereum: {
    id: "ethereum",
    chainId: 1,
    viemChain: mainnet,
    rpcUrl: process.env["RPC_URL_1"] ?? "https://eth.llamarpc.com",
    wsUrl: process.env["WS_URL_1"],
    explorerApiUrl: ETHERSCAN_V2_BASE,
    explorerApiKey: process.env["ETHERSCAN_API_KEY"],
    explorerName: "Etherscan",
    blockTimeMs: 12_000,
  },
};

// ─── Client Factory (cached) ────────────────────────────────────────────

const clientCache = new Map<SupportedChain, PublicClient>();

export function getChainClient(chain: SupportedChain): PublicClient {
  const cached = clientCache.get(chain);
  if (cached) return cached;

  const config = CHAIN_CONFIGS[chain];
  const transport = config.wsUrl
    ? webSocket(config.wsUrl, { reconnect: true })
    : http(config.rpcUrl);

  const client = createPublicClient({
    chain: config.viemChain,
    transport,
  });

  clientCache.set(chain, client);
  return client;
}
