/**
 * Module G.2 — Contract Classifier
 *
 * Classifies contracts into DeFi categories (AMM, lending, vault, bridge, etc.)
 * using ABI signatures, bytecode selector matching, and source code analysis.
 * Non-DeFi contracts are deprioritized in the mass audit pipeline.
 */

import type { Address, Hex } from "viem";
import type {
  ContractClassification,
  ContractCategory,
  ExplorerContractEntry,
  SupportedChain,
} from "./types.js";

// ─── Interface Selector Signatures ──────────────────────────────────────

interface InterfaceSpec {
  selectors: string[];
  category: ContractCategory;
  minMatches: number; // How many selectors must match to classify
}

/**
 * Known DeFi interface signatures.
 * 4-byte selectors for key functions that uniquely identify contract types.
 */
const INTERFACE_SIGNATURES: Record<string, InterfaceSpec> = {
  // ── AMM / DEX ─────────────────────────────────────────────────────
  IUniswapV2Pair: {
    selectors: [
      "0902f1ac", // getReserves()
      "022c0d9f", // swap(uint256,uint256,address,bytes)
      "6a627842", // mint(address)
      "89afcb44", // burn(address)
    ],
    category: "amm_dex",
    minMatches: 2,
  },
  IUniswapV2Router: {
    selectors: [
      "38ed1739", // swapExactTokensForTokens
      "7ff36ab5", // swapExactETHForTokens
      "e8e33700", // addLiquidity
      "02751cec", // removeLiquidity
    ],
    category: "amm_dex",
    minMatches: 2,
  },
  IUniswapV3Pool: {
    selectors: [
      "3850c7bd", // slot0()
      "128acb08", // swap(address,bool,int256,uint160,bytes)
      "a34123a7", // mint(address,int24,int24,uint128,bytes)
    ],
    category: "amm_dex",
    minMatches: 2,
  },
  ICurvePool: {
    selectors: [
      "3df02124", // exchange(int128,int128,uint256,uint256)
      "a9059cbb", // (shared) but with get_dy
      "5e0d443f", // get_dy(int128,int128,uint256)
    ],
    category: "amm_dex",
    minMatches: 2,
  },
  IBalancerVault: {
    selectors: [
      "52bbbe29", // swap(SingleSwap,FundManagement,uint256,uint256)
      "945bcec9", // batchSwap
      "f94d4668", // joinPool
    ],
    category: "amm_dex",
    minMatches: 2,
  },

  // ── Lending ───────────────────────────────────────────────────────
  IAavePool: {
    selectors: [
      "69328dec", // withdraw(address,uint256,address)
      "e8eda9df", // deposit(address,uint256,address,uint16)
      "a415bcad", // borrow(address,uint256,uint256,uint16,address)
      "573ade81", // repay(address,uint256,uint256,address)
      "e6c2e0a7", // liquidationCall
    ],
    category: "lending",
    minMatches: 2,
  },
  ICompoundCToken: {
    selectors: [
      "a6afed95", // accrueInterest()
      "852a12e3", // redeemUnderlying(uint256)
      "c5ebeaec", // borrow(uint256)
      "0e752702", // repayBorrow(uint256)
    ],
    category: "lending",
    minMatches: 2,
  },
  IMorphoBlue: {
    selectors: [
      "a99aad89", // supply(MarketParams,uint256,uint256,address,bytes)
      "5c2bea49", // borrow(MarketParams,uint256,uint256,address,address)
      "20b76e81", // repay(MarketParams,uint256,uint256,address,bytes)
    ],
    category: "lending",
    minMatches: 2,
  },
  IEulerEVault: {
    selectors: [
      "e8eda9df", // deposit
      "b460af94", // withdraw
      "d905777e", // maxRedeem
      "4cdad506", // checkAccountStatus
    ],
    category: "lending",
    minMatches: 2,
  },

  // ── Vault / Yield ─────────────────────────────────────────────────
  IERC4626: {
    selectors: [
      "07a2d13a", // convertToAssets(uint256)
      "b3d7f6b9", // convertToShares(uint256)
      "6e553f65", // deposit(uint256,address)
      "b460af94", // withdraw(uint256,address,address)
      "01e1d114", // totalAssets()
    ],
    category: "vault_yield",
    minMatches: 3,
  },
  IYearnVault: {
    selectors: [
      "d0e30db0", // deposit()
      "2e1a7d4d", // withdraw(uint256)
      "99530b06", // pricePerShare()
    ],
    category: "vault_yield",
    minMatches: 2,
  },

  // ── Bridge ────────────────────────────────────────────────────────
  IBridge: {
    selectors: [
      "0166a07a", // bridge(address,uint256,uint256)
      "c7c7f5b3", // relayMessage
      "8b3e7995", // depositFor
    ],
    category: "bridge",
    minMatches: 1,
  },

  // ── Staking ───────────────────────────────────────────────────────
  IStaking: {
    selectors: [
      "a694fc3a", // stake(uint256)
      "2e17de78", // unstake(uint256)
      "3d18b912", // getReward()
      "c8f33c91", // rewardPerToken()
      "70a08231", // balanceOf (shared, but combined with stake = staking)
    ],
    category: "staking",
    minMatches: 2,
  },

  // ── ERC-20 (basic token, not DeFi by itself) ──────────────────────
  IERC20: {
    selectors: [
      "a9059cbb", // transfer(address,uint256)
      "095ea7b3", // approve(address,uint256)
      "23b872dd", // transferFrom(address,address,uint256)
      "18160ddd", // totalSupply()
      "70a08231", // balanceOf(address)
    ],
    category: "erc20",
    minMatches: 4,
  },

  // ── NFT ───────────────────────────────────────────────────────────
  IERC721: {
    selectors: [
      "42842e0e", // safeTransferFrom(address,address,uint256)
      "b88d4fde", // safeTransferFrom(address,address,uint256,bytes)
      "6352211e", // ownerOf(uint256)
      "e985e9c5", // isApprovedForAll(address,address)
    ],
    category: "nft",
    minMatches: 3,
  },
};

/** Source code keywords that indicate DeFi contract types. */
const SOURCE_KEYWORDS: Record<ContractCategory, string[]> = {
  amm_dex: [
    "getReserves", "swap(", "addLiquidity", "removeLiquidity",
    "IUniswapV2", "IUniswapV3", "ICurvePool", "IBalancerVault",
    "sqrtPriceX96", "tickSpacing",
  ],
  lending: [
    "borrow(", "repay(", "liquidat", "accrueInterest",
    "healthFactor", "collateralFactor", "ILendingPool", "ICToken",
    "IPool", "IEVault", "IMorpho",
  ],
  vault_yield: [
    "convertToAssets", "convertToShares", "totalAssets",
    "ERC4626", "pricePerShare", "harvest(", "strategy",
  ],
  bridge: [
    "bridge(", "relayMessage", "crossChain", "layerZero",
    "ILayerZero", "IBridge", "depositFor",
  ],
  staking: [
    "stake(", "unstake(", "getReward", "rewardPerToken",
    "rewardRate", "IStaking", "earned(",
  ],
  governance: [
    "propose(", "castVote", "execute(", "queue(",
    "IGovernor", "votingDelay", "quorum",
  ],
  erc20: [],
  nft: [],
  unknown: [],
};

/** Categories considered DeFi (eligible for full audit pipeline). */
const DEFI_CATEGORIES: Set<ContractCategory> = new Set([
  "amm_dex",
  "lending",
  "vault_yield",
  "bridge",
  "staking",
]);

// ─── ContractClassifier ─────────────────────────────────────────────────

export class ContractClassifier {

  /**
   * Classify a contract using all available information.
   * Priority: ABI (highest confidence) > bytecode > source keywords.
   */
  classify(entry: ExplorerContractEntry): ContractClassification {
    const scores = new Map<ContractCategory, number>();

    // Method 1: ABI analysis (highest confidence)
    if (entry.abi && entry.isVerified) {
      const abiScores = this.classifyFromAbi(entry.abi);
      for (const [cat, score] of abiScores) {
        scores.set(cat, (scores.get(cat) ?? 0) + score * 1.0);
      }
    }

    // Method 2: Source code analysis (medium confidence)
    if (entry.sourceCode) {
      const srcScores = this.classifyFromSource(entry.sourceCode);
      for (const [cat, score] of srcScores) {
        scores.set(cat, (scores.get(cat) ?? 0) + score * 0.6);
      }
    }

    // Find the best category
    let bestCategory: ContractCategory = "unknown";
    let bestScore = 0;
    const detectedInterfaces: string[] = [];

    for (const [cat, score] of scores) {
      if (score > bestScore) {
        bestScore = score;
        bestCategory = cat;
      }
      if (score > 20) {
        detectedInterfaces.push(cat);
      }
    }

    const confidence = Math.min(Math.round(bestScore), 100);

    return {
      address: entry.address,
      chain: entry.chain,
      category: bestCategory,
      confidence,
      isDeFi: DEFI_CATEGORIES.has(bestCategory),
      detectedInterfaces,
      classifiedAt: Date.now(),
    };
  }

  /**
   * Classify from bytecode only (for unverified contracts).
   * Checks for 4-byte selectors in deployed code.
   */
  classifyFromBytecode(
    address: Address,
    bytecode: Hex,
    chain: SupportedChain,
  ): ContractClassification {
    const code = bytecode.startsWith("0x")
      ? bytecode.slice(2).toLowerCase()
      : bytecode.toLowerCase();

    const scores = new Map<ContractCategory, number>();

    for (const [ifaceName, spec] of Object.entries(INTERFACE_SIGNATURES)) {
      let matches = 0;
      for (const sel of spec.selectors) {
        if (code.includes(sel)) matches++;
      }
      if (matches >= spec.minMatches) {
        const matchRatio = matches / spec.selectors.length;
        const score = matchRatio * 80; // max 80 confidence from bytecode alone
        scores.set(spec.category, Math.max(scores.get(spec.category) ?? 0, score));
      }
    }

    let bestCategory: ContractCategory = "unknown";
    let bestScore = 0;
    const detectedInterfaces: string[] = [];

    for (const [cat, score] of scores) {
      if (score > bestScore) {
        bestScore = score;
        bestCategory = cat;
      }
      if (score > 20) detectedInterfaces.push(cat);
    }

    return {
      address,
      chain,
      category: bestCategory,
      confidence: Math.min(Math.round(bestScore), 100),
      isDeFi: DEFI_CATEGORIES.has(bestCategory),
      detectedInterfaces,
      classifiedAt: Date.now(),
    };
  }

  // ── Private ─────────────────────────────────────────────────────────

  /**
   * Analyzes verified ABI JSON for known function selectors.
   * Returns score per category.
   */
  private classifyFromAbi(abiJson: string): Map<ContractCategory, number> {
    const scores = new Map<ContractCategory, number>();

    let abi: Array<{ type?: string; name?: string }>;
    try {
      abi = JSON.parse(abiJson);
    } catch {
      return scores;
    }

    const functionNames = new Set(
      abi
        .filter((e) => e.type === "function")
        .map((e) => e.name?.toLowerCase())
        .filter(Boolean) as string[],
    );

    // Check each interface spec against the ABI function names
    for (const [, spec] of Object.entries(INTERFACE_SIGNATURES)) {
      // Also match by function name similarity (not just selectors)
      let nameMatches = 0;
      for (const sel of spec.selectors) {
        // Try matching common function names
        for (const fname of functionNames) {
          if (this.selectorMatchesName(sel, fname)) {
            nameMatches++;
            break;
          }
        }
      }
      if (nameMatches >= spec.minMatches) {
        const score = (nameMatches / spec.selectors.length) * 90;
        scores.set(spec.category, Math.max(scores.get(spec.category) ?? 0, score));
      }
    }

    // Direct function name matching for high-confidence classification
    const abiNames = [...functionNames];

    if (abiNames.some((n) => n.includes("swap")) && abiNames.some((n) => n.includes("liquidity") || n.includes("reserve"))) {
      scores.set("amm_dex", Math.max(scores.get("amm_dex") ?? 0, 85));
    }
    if (abiNames.some((n) => n.includes("borrow")) && abiNames.some((n) => n.includes("repay") || n.includes("liquidat"))) {
      scores.set("lending", Math.max(scores.get("lending") ?? 0, 85));
    }
    if (abiNames.some((n) => n.includes("converttoassets")) && abiNames.some((n) => n.includes("converttoshares"))) {
      scores.set("vault_yield", Math.max(scores.get("vault_yield") ?? 0, 90));
    }
    if (abiNames.some((n) => n.includes("stake")) && abiNames.some((n) => n.includes("reward") || n.includes("unstake"))) {
      scores.set("staking", Math.max(scores.get("staking") ?? 0, 80));
    }

    return scores;
  }

  /**
   * Scans Solidity source code for import paths and characteristic keywords.
   * Returns score per category.
   */
  private classifyFromSource(sourceCode: string): Map<ContractCategory, number> {
    const scores = new Map<ContractCategory, number>();
    const lower = sourceCode.toLowerCase();

    for (const [category, keywords] of Object.entries(SOURCE_KEYWORDS)) {
      const cat = category as ContractCategory;
      let matches = 0;
      for (const kw of keywords) {
        if (lower.includes(kw.toLowerCase())) matches++;
      }
      if (keywords.length > 0 && matches > 0) {
        const score = (matches / keywords.length) * 70;
        scores.set(cat, Math.max(scores.get(cat) ?? 0, score));
      }
    }

    return scores;
  }

  /**
   * Heuristic: check if a known selector maps to a common function name.
   */
  private selectorMatchesName(selector: string, funcName: string): boolean {
    const SELECTOR_NAME_MAP: Record<string, string[]> = {
      "0902f1ac": ["getreserves"],
      "022c0d9f": ["swap"],
      "128acb08": ["swap"],
      "69328dec": ["withdraw"],
      "e8eda9df": ["deposit"],
      "a415bcad": ["borrow"],
      "573ade81": ["repay"],
      "07a2d13a": ["converttoassets"],
      "b3d7f6b9": ["converttoshares"],
      "01e1d114": ["totalassets"],
      "a694fc3a": ["stake"],
      "2e17de78": ["unstake"],
      "3d18b912": ["getreward"],
      "a6afed95": ["accrueinterest"],
      "852a12e3": ["redeemunderlying"],
    };

    const names = SELECTOR_NAME_MAP[selector];
    if (!names) return false;
    return names.some((n) => funcName.includes(n));
  }
}
