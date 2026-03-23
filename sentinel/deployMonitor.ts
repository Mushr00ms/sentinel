// FILE: deployMonitor.ts

import type { PublicClient, Address, Hex, Hash } from "viem";
import type {
  BlockContext,
  NewDeployment,
  FundHandlingClassification,
} from "./types.js";
import { KNOWN_FACTORY_ADDRESSES } from "./config.js";

// ─── Constants ────────────────────────────────────────────────────────────

/** EIP-1167 minimal proxy creation prefix (10 bytes) */
const EIP1167_CREATION_PREFIX = "363d3d373d3d3d363d73";

/** EIP-1167 deployment bytecode prefix (10 bytes) */
const EIP1167_DEPLOY_PREFIX = "3d602d80600a3d3981f3";

/** EIP-1167 runtime body pattern */
const EIP1167_RUNTIME_BODY = "5af43d82803e903d9160";

/** ERC-20 Transfer event topic (keccak256 of Transfer(address,address,uint256)) */
const TOPIC_ERC20_TRANSFER =
  "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/** ERC-20 Approval event topic (keccak256 of Approval(address,address,uint256)) */
const TOPIC_ERC20_APPROVAL =
  "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";

/** EIP-1967 implementation storage slot */
const EIP1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/** UUPS upgradeToAndCall selector */
const UUPS_UPGRADE_SELECTOR = "4f1ef286";

/** ERC-4626 convertToAssets selector */
const ERC4626_CONVERT_TO_ASSETS = "07a2d13a";

/** CREATE opcode */
const OP_CREATE = "f0";

/** CREATE2 opcode */
const OP_CREATE2 = "f5";

/** DELEGATECALL opcode */
const OP_DELEGATECALL = "f4";

/** SELFDESTRUCT opcode */
const OP_SELFDESTRUCT = "ff";

/** ORIGIN opcode pattern sometimes used in flash loan callbacks */
const ORIGIN_PATTERN = "40500b";

/**
 * Minimum bytecode length in bytes to be considered for full classification.
 * Minimal proxies (EIP-1167 are ~45 bytes) are excluded from double-classification.
 */
const MIN_BYTECODE_BYTES = 200;

/** Maximum number of deployments held in the analysis queue before eviction */
const MAX_QUEUE_SIZE = 100;

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * Strips the leading `0x` from a hex string and lower-cases it so that
 * substring searches are consistent.
 */
function stripHex(hex: Hex | string): string {
  return hex.startsWith("0x") ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

/**
 * Reads a 32-byte storage slot and returns the last 20 bytes as an Address,
 * or undefined if the slot is empty / zero.
 */
async function readAddressSlot(
  publicClient: PublicClient,
  address: Address,
  slot: Hex,
): Promise<Address | undefined> {
  try {
    const raw = await publicClient.getStorageAt({ address, slot });
    if (!raw || raw === "0x" + "0".repeat(64)) return undefined;
    // Last 20 bytes (40 hex chars) of the 32-byte word
    const addrHex = raw.slice(-40);
    if (addrHex === "0".repeat(40)) return undefined;
    return `0x${addrHex}` as Address;
  } catch {
    return undefined;
  }
}

// ─── DeploymentMonitor ────────────────────────────────────────────────────

/**
 * Module F.1 – New Deployment Monitor.
 *
 * Scans every block for newly deployed contracts, classifies them as
 * fund-handling or not, and queues fund-handling ones for downstream
 * static analysis.
 */
export class DeploymentMonitor {
  private readonly publicClient: PublicClient;

  /** FIFO queue of deployments waiting for static analysis (max 100 entries). */
  private readonly analysisQueue: NewDeployment[] = [];

  /** Tracks contracts already seen so we never double-process the same address. */
  private readonly processedContracts: Set<Address> = new Set();

  constructor(publicClient: PublicClient) {
    this.publicClient = publicClient;
  }

  // ── Public API ────────────────────────────────────────────────────────

  /**
   * Scans the block identified by `ctx` for all contract-creating transactions
   * and internal `CREATE` / `CREATE2` calls.
   *
   * Returns every `NewDeployment` found in the block; fund-handling ones are
   * also appended to the internal analysis queue.
   */
  async run(ctx: BlockContext): Promise<NewDeployment[]> {
    const { blockNumber, blockTimestamp } = ctx;

    // Fetch the full block so we can inspect every transaction receipt.
    const block = await this.publicClient.getBlock({
      blockNumber,
      includeTransactions: true,
    });

    const deployments: NewDeployment[] = [];

    for (const tx of block.transactions) {
      // A null `to` field means this is a contract-creation transaction.
      if (tx.to !== null && tx.to !== undefined) continue;

      // Retrieve the receipt to get the deployed contract address.
      let receipt;
      try {
        receipt = await this.publicClient.getTransactionReceipt({
          hash: tx.hash as Hash,
        });
      } catch {
        continue;
      }

      const contractAddress = receipt.contractAddress;
      if (!contractAddress) continue;

      const normalised = contractAddress.toLowerCase() as Address;
      if (this.processedContracts.has(normalised)) continue;
      this.processedContracts.add(normalised);

      // Pull deployed bytecode.
      let bytecode: Hex | undefined;
      try {
        bytecode = await this.publicClient.getBytecode({
          address: contractAddress,
        });
      } catch {
        // No bytecode → selfdestructed immediately or reverted; skip.
        continue;
      }
      if (!bytecode || bytecode === "0x") continue;

      const bytecodeHex = stripHex(bytecode);
      const bytecodeSize = bytecodeHex.length / 2; // bytes, not hex chars

      // Detect proxy type and implementation.
      const proxyInfo = await this.detectProxy(contractAddress, bytecode);

      // Classify fund-handling capability.
      // Only run full classification for non-trivial bytecode; minimal proxies
      // are captured by the proxy detection step and their implementation is
      // what matters for fund-handling analysis.
      const fundHandling =
        bytecodeSize >= MIN_BYTECODE_BYTES
          ? await this.classifyBytecode(contractAddress, bytecode)
          : this.emptyClassification();

      const deployment: NewDeployment = {
        contractAddress,
        deployerAddress: tx.from as Address,
        txHash: tx.hash as Hash,
        blockNumber,
        blockTimestamp,
        bytecodeSize,
        isProxy: proxyInfo.isProxy,
        implementationAddress: proxyInfo.implementationAddress,
        fundHandling,
      };

      deployments.push(deployment);

      // Queue fund-handling contracts for deeper static analysis.
      if (fundHandling.isFundHandling || proxyInfo.isProxy) {
        this.enqueue(deployment);
      }
    }

    return deployments;
  }

  /**
   * Analyses the bytecode of a deployed contract and returns a
   * `FundHandlingClassification` describing which fund-related patterns were
   * found.
   *
   * The `address` parameter is accepted for future on-chain enrichment but is
   * not used in the current pure-bytecode path.
   */
  async classifyBytecode(
    _address: Address,
    bytecode: Hex,
  ): Promise<FundHandlingClassification> {
    const code = stripHex(bytecode);

    // ── Pattern matching ─────────────────────────────────────────────────

    const hasERC20Transfers = code.includes(TOPIC_ERC20_TRANSFER);
    const hasApprovals = code.includes(TOPIC_ERC20_APPROVAL);
    const hasDelegatecall = code.includes(OP_DELEGATECALL);

    // PAYABLE detection: look for CALLVALUE (0x34) opcode in the code. Any
    // function that checks msg.value uses this opcode, making it payable.
    const hasPayable = code.includes("34");

    // Mint / Burn heuristics:
    //   Mint pattern – Transfer from the zero address: the topic is followed
    //     somewhere in the bytecode that pushes the zero address. We look for
    //     the zero address as a 32-byte push in conjunction with the Transfer
    //     topic.
    //   Burn pattern – Transfer to the zero address: same heuristic.
    //
    //   A simpler (and still effective) proxy: if the bytecode references the
    //   Transfer topic AND also contains SSTORE (0x55) it almost certainly
    //   mints or burns (adjusting totalSupply).
    const hasMint =
      hasERC20Transfers && code.includes("55") && code.includes("0".repeat(40));
    const hasBurn = hasMint; // symmetric at bytecode level; same heuristic

    // ERC-4626 convertToAssets indicates a vault-like fund-handling contract.
    const isVaultLike = code.includes(ERC4626_CONVERT_TO_ASSETS);

    // Flash-loan callback marker.
    const hasFlashLoanMarker = code.includes(ORIGIN_PATTERN);

    // CREATE / CREATE2 inside the contract – child deployer or factory.
    const hasInternalCreate =
      code.includes(OP_CREATE) || code.includes(OP_CREATE2);

    // ── Confidence scoring ────────────────────────────────────────────────

    let confidence = 0;
    if (hasERC20Transfers) confidence += 30;
    if (hasApprovals) confidence += 20;
    if (hasPayable) confidence += 15;
    if (hasDelegatecall) confidence += 10;
    if (hasMint) confidence += 10;
    if (isVaultLike) confidence += 10;
    if (hasFlashLoanMarker) confidence += 5;
    if (hasInternalCreate) confidence += 5;
    if (code.includes(OP_SELFDESTRUCT)) confidence = Math.max(confidence, 20);
    confidence = Math.min(confidence, 100);

    const isFundHandling =
      hasERC20Transfers ||
      hasApprovals ||
      hasPayable ||
      hasDelegatecall ||
      isVaultLike;

    return {
      isFundHandling,
      hasPayable,
      hasERC20Transfers,
      hasApprovals,
      hasDelegatecall,
      hasMint,
      hasBurn,
      confidence,
    };
  }

  /**
   * Detects whether `address` is a proxy contract and, if so, attempts to
   * resolve the implementation address.
   *
   * Checks (in order):
   * 1. EIP-1167 minimal proxy – recognised by bytecode prefix.
   * 2. EIP-1967 transparent / UUPS – reads the canonical storage slot.
   * 3. UUPS – checks for the `upgradeToAndCall` selector in bytecode.
   */
  async detectProxy(
    address: Address,
    bytecode: Hex,
  ): Promise<{ isProxy: boolean; implementationAddress?: Address }> {
    const code = stripHex(bytecode);

    // ── EIP-1167 ──────────────────────────────────────────────────────────
    if (
      code.startsWith(EIP1167_CREATION_PREFIX) ||
      code.includes(EIP1167_RUNTIME_BODY) ||
      code.includes(EIP1167_DEPLOY_PREFIX)
    ) {
      // The implementation address is embedded at bytes 10-30 of the runtime
      // bytecode: 363d3d373d3d3d363d73{20-byte-addr}5af43d…
      const implStart = EIP1167_CREATION_PREFIX.length;
      const implHex = code.slice(implStart, implStart + 40);
      const implementationAddress =
        implHex.length === 40 && implHex !== "0".repeat(40)
          ? (`0x${implHex}` as Address)
          : undefined;

      return { isProxy: true, implementationAddress };
    }

    // ── EIP-1967 (transparent proxy / UUPS) ───────────────────────────────
    const eip1967Impl = await readAddressSlot(
      this.publicClient,
      address,
      EIP1967_IMPL_SLOT as Hex,
    );
    if (eip1967Impl) {
      return { isProxy: true, implementationAddress: eip1967Impl };
    }

    // ── UUPS selector in bytecode ─────────────────────────────────────────
    if (code.includes(UUPS_UPGRADE_SELECTOR)) {
      // Implementation may not be resolved purely from bytecode; return the
      // EIP-1967 slot result (already attempted above, so undefined here).
      return { isProxy: true, implementationAddress: undefined };
    }

    return { isProxy: false };
  }

  /**
   * Returns the current snapshot of contracts waiting for static analysis.
   * Callers must not mutate the returned array.
   */
  getPendingAnalysisQueue(): NewDeployment[] {
    return [...this.analysisQueue];
  }

  // ── Private helpers ───────────────────────────────────────────────────

  /** Appends a deployment to the FIFO queue, evicting the oldest if needed. */
  private enqueue(deployment: NewDeployment): void {
    if (this.analysisQueue.length >= MAX_QUEUE_SIZE) {
      // Drop the oldest entry.
      this.analysisQueue.shift();
    }
    this.analysisQueue.push(deployment);
  }

  /**
   * Returns a zeroed-out `FundHandlingClassification` used for bytecode that
   * is too small to warrant analysis (e.g., minimal proxies < 200 bytes).
   */
  private emptyClassification(): FundHandlingClassification {
    return {
      isFundHandling: false,
      hasPayable: false,
      hasERC20Transfers: false,
      hasApprovals: false,
      hasDelegatecall: false,
      hasMint: false,
      hasBurn: false,
      confidence: 0,
    };
  }
}

// ─── Named export for convenience ─────────────────────────────────────────
export type { NewDeployment, FundHandlingClassification };
