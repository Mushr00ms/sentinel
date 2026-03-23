/**
 * Module H — Cross-Contract Composition Analyzer
 *
 * Analyzes interactions between contracts rather than auditing them in
 * isolation.  Maps call graphs across protocol boundaries, detects
 * composability bugs invisible to single-contract auditors, and identifies
 * systemic risk from shared dependencies (oracles, tokens, flash loan pools).
 *
 * Key attack surfaces detected:
 *   1. Cross-contract reentrancy (callbacks flowing through multiple contracts)
 *   2. Shared oracle manipulation (multiple protocols trusting one price source)
 *   3. Approval chain exploits (token approval → delegatecall → drain)
 *   4. Flash loan cascade attacks (borrow → manipulate → profit across protocols)
 *   5. Dependency rug risk (high-TVL protocol depending on unaudited contract)
 *   6. Price feed cascading failures (one stale oracle corrupts downstream)
 */

import type { Address, Hex, PublicClient } from "viem";
import type {
  SupportedChain,
  ContractEdge,
  ContractNode,
  ComposabilityFinding,
  ComposabilityRiskClass,
  CompositionGraph,
  InteractionType,
  MisconfigSeverity,
  MassAuditTarget,
  ExternalCall,
  ApprovalNode,
  StaticAnalysisReport,
  EVMAnalysisResultRef,
} from "./types.js";
import { getChainClient } from "./chains.js";
import { info, warn, alert, critical } from "./alerter.js";

// ─── Constants ──────────────────────────────────────────────────────────

/** Minimum TVL (USD) to consider a node "high value". */
const HIGH_VALUE_TVL_THRESHOLD = 100_000;

/** Score threshold for emitting a composability finding. */
const FINDING_CONFIDENCE_THRESHOLD = 40;

// ─── Known infrastructure addresses ────────────────────────────────────

/** Known oracle feed contract patterns (Chainlink, RedStone, Pyth). */
const ORACLE_SELECTORS = new Set([
  "50d25bcd", // latestAnswer()
  "feaf968c", // latestRoundData()
  "9a6fc8f5", // getRoundData(uint80)
  "668a0f02", // latestRound()
  "8205bf6a", // latestTimestamp()
  "b5ab58dc", // getAnswer(uint256)
  "b633620c", // getTimestamp(uint256)
]);

/** Flash loan provider selectors. */
const FLASH_LOAN_SELECTORS = new Set([
  "5cffe9de", // flashLoan(IERC3156FlashBorrower,address,uint256,bytes)
  "5c38449e", // flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)
  "490e6cbc", // flash(address,address,uint256,bytes) — Balancer
]);

/** Callback / receiver selectors that indicate re-entrant patterns. */
const CALLBACK_SELECTORS = new Set([
  "23e30c8b", // onFlashLoan(address,address,uint256,uint256,bytes)
  "fa461e33", // uniswapV3SwapCallback
  "84800812", // pancakeV3SwapCallback
  "10d1e85c", // uniswapV2Call
  "ee872558", // onERC721Received... not exactly but related
]);

/** ERC-20 approval/transfer selectors indicating token interaction. */
const TOKEN_INTERACTION_SELECTORS = new Set([
  "095ea7b3", // approve(address,uint256)
  "a9059cbb", // transfer(address,uint256)
  "23b872dd", // transferFrom(address,address,uint256)
]);

// ─── CompositionAnalyzer ────────────────────────────────────────────────

export class CompositionAnalyzer {
  private readonly graphs = new Map<SupportedChain, CompositionGraph>();

  /**
   * Builds a cross-contract interaction graph from previously audited targets
   * and runs composability analysis to find systemic vulnerabilities.
   */
  async analyze(
    targets: MassAuditTarget[],
    chain: SupportedChain,
  ): Promise<CompositionGraph> {
    const startMs = Date.now();
    const client = getChainClient(chain);

    info("composition", `Building interaction graph for ${targets.length} contracts on ${chain}`);

    // ── Step 1: Build nodes from audit targets ────────────────────────
    const nodes = new Map<Address, ContractNode>();
    for (const target of targets) {
      if (target.status !== "completed") continue;
      const addr = target.address.toLowerCase() as Address;
      nodes.set(addr, {
        address: addr,
        chain,
        category: target.classification?.category,
        tvlUsd: target.tvlUsd,
        riskScore: target.staticReport?.riskScore ?? 0,
        inDegree: 0,
        outDegree: 0,
        dependencyDepth: 0,
      });
    }

    // ── Step 2: Extract edges from static analysis reports ────────────
    const edges: ContractEdge[] = [];

    for (const target of targets) {
      if (!target.staticReport) continue;
      const fromAddr = target.address.toLowerCase() as Address;

      // Edges from external call graph
      const callEdges = this.extractCallEdges(fromAddr, target.staticReport);
      edges.push(...callEdges);

      // Edges from approval graph
      const approvalEdges = this.extractApprovalEdges(fromAddr, target.staticReport);
      edges.push(...approvalEdges);

      // Edges from ABI / source code analysis
      if (target.explorerEntry?.abi) {
        const abiEdges = this.extractAbiEdges(fromAddr, target.explorerEntry.abi);
        edges.push(...abiEdges);
      }

      // Edges from on-chain storage reads (oracle addresses, token addresses)
      if (target.explorerEntry?.sourceCode) {
        const sourceEdges = this.extractSourceEdges(fromAddr, target.explorerEntry.sourceCode);
        edges.push(...sourceEdges);
      }
    }

    // On-chain probing: read storage slots for oracle/token references
    const storageEdges = await this.probeStorageEdges(targets, chain, client);
    edges.push(...storageEdges);

    // ── Step 3: Compute graph metrics ─────────────────────────────────
    this.computeGraphMetrics(nodes, edges);

    // ── Step 4: Run composability detectors ───────────────────────────
    const findings: ComposabilityFinding[] = [];

    findings.push(...this.detectSharedOracleRisk(nodes, edges, targets));
    findings.push(...this.detectApprovalChainExploits(nodes, edges));
    findings.push(...this.detectFlashLoanCascades(nodes, edges));
    findings.push(...this.detectCrossContractReentrancy(nodes, edges));
    findings.push(...this.detectDependencyRugRisk(nodes, edges));
    findings.push(...this.detectPriceFeedCascade(nodes, edges, targets));

    // Filter low-confidence findings
    const filtered = findings.filter((f) => f.confidence >= FINDING_CONFIDENCE_THRESHOLD);

    const graph: CompositionGraph = {
      nodes,
      edges,
      findings: filtered,
      analyzedAt: Date.now(),
      analysisTimeMs: Date.now() - startMs,
    };

    this.graphs.set(chain, graph);

    // ── Step 5: Alert on findings ─────────────────────────────────────
    for (const finding of filtered) {
      const severityFn = finding.severity === "critical" ? critical
        : finding.severity === "high" ? alert
        : warn;

      severityFn(
        "composition",
        `[${finding.riskClass}] ${finding.description.slice(0, 120)}`,
        `Contracts: ${finding.involvedContracts.map((a) => a.slice(0, 10)).join(" → ")} | ` +
        `Impact: $${finding.estimatedImpactUsd.toFixed(0)} | Confidence: ${finding.confidence}%`,
        finding,
      );
    }

    info(
      "composition",
      `Graph complete: ${nodes.size} nodes, ${edges.length} edges, ` +
      `${filtered.length} findings (${Date.now() - startMs}ms)`,
    );

    return graph;
  }

  getGraph(chain: SupportedChain): CompositionGraph | undefined {
    return this.graphs.get(chain);
  }

  // ── Edge Extraction ─────────────────────────────────────────────────

  /**
   * Extracts edges from StaticAnalysisReport's externalCallGraph.
   */
  private extractCallEdges(from: Address, report: StaticAnalysisReport): ContractEdge[] {
    const edges: ContractEdge[] = [];

    for (const call of report.externalCallGraph) {
      if (!call.target) continue;
      const to = call.target.toLowerCase() as Address;
      if (to === from) continue;

      const interaction: InteractionType = call.targetType === "storage"
        ? "delegatecall"
        : "external_call";

      edges.push({
        from,
        to,
        interaction,
        functionSelector: call.fromFunction,
        confidence: call.calldataValidated ? 90 : 70,
        bidirectional: false,
      });
    }

    return edges;
  }

  /**
   * Extracts approval-grant edges from the approval graph.
   */
  private extractApprovalEdges(from: Address, report: StaticAnalysisReport): ContractEdge[] {
    const edges: ContractEdge[] = [];

    for (const node of report.approvalGraph) {
      const to = node.approvedContract.toLowerCase() as Address;
      if (to === from) continue;

      edges.push({
        from,
        to,
        interaction: "approval_grant",
        functionName: `approve(${node.approvedToken.slice(0, 10)}...)`,
        confidence: node.canBeTriggeredBy === "anyone" ? 95 : 60,
        bidirectional: false,
      });
    }

    return edges;
  }

  /**
   * Extracts edges by analyzing ABI for oracle reads, flash loans, and callbacks.
   */
  private extractAbiEdges(from: Address, abiJson: string): ContractEdge[] {
    const edges: ContractEdge[] = [];

    let abi: Array<{ type?: string; name?: string; inputs?: Array<{ type: string; name?: string }> }>;
    try {
      abi = JSON.parse(abiJson);
    } catch {
      return edges;
    }

    for (const entry of abi) {
      if (entry.type !== "function") continue;
      const name = entry.name?.toLowerCase() ?? "";

      // Flash loan callbacks indicate bidirectional interaction
      if (
        name.includes("callback") ||
        name.includes("onflasloan") ||
        name.includes("uniswapv3swapcallback") ||
        name.includes("oncall")
      ) {
        edges.push({
          from,
          to: from, // self-referencing — actual target resolved via graph traversal
          interaction: "callback",
          functionName: entry.name,
          confidence: 75,
          bidirectional: true,
        });
      }

      // Oracle read patterns
      if (
        name.includes("oracle") ||
        name.includes("pricefeed") ||
        name.includes("getprice") ||
        name.includes("latestanswer") ||
        name.includes("latestrounddata")
      ) {
        edges.push({
          from,
          to: from, // placeholder — actual oracle resolved via source/storage
          interaction: "oracle_read",
          functionName: entry.name,
          confidence: 65,
          bidirectional: false,
        });
      }
    }

    return edges;
  }

  /**
   * Extracts edges by scanning source code for hardcoded addresses and patterns.
   */
  private extractSourceEdges(from: Address, source: string): ContractEdge[] {
    const edges: ContractEdge[] = [];

    // Find hardcoded addresses in source (0x followed by 40 hex chars)
    const addressPattern = /0x[0-9a-fA-F]{40}/g;
    const matches = source.match(addressPattern) ?? [];
    const uniqueAddrs = [...new Set(matches.map((a) => a.toLowerCase() as Address))];

    for (const addr of uniqueAddrs) {
      if (addr === from) continue;
      // Skip zero address and common precompiles
      if (addr === "0x0000000000000000000000000000000000000000") continue;
      if (addr.startsWith("0x00000000000000000000000000000000000000")) continue;

      // Determine interaction type from surrounding context
      const addrIndex = source.toLowerCase().indexOf(addr);
      const surroundingCode = source.toLowerCase().slice(
        Math.max(0, addrIndex - 200),
        addrIndex + 200,
      );

      let interaction: InteractionType = "external_call";
      if (surroundingCode.includes("oracle") || surroundingCode.includes("pricefeed") || surroundingCode.includes("chainlink")) {
        interaction = "oracle_read";
      } else if (surroundingCode.includes("approve") || surroundingCode.includes("allowance")) {
        interaction = "approval_grant";
      } else if (surroundingCode.includes("flash") || surroundingCode.includes("borrow")) {
        interaction = "flash_loan";
      } else if (surroundingCode.includes("transfer") || surroundingCode.includes("balanceof")) {
        interaction = "token_transfer";
      }

      edges.push({
        from,
        to: addr,
        interaction,
        confidence: 50,
        bidirectional: false,
      });
    }

    return edges;
  }

  /**
   * Probes on-chain storage for common slot patterns to discover oracle/token
   * dependencies not visible in source code (e.g., proxies, storage-based config).
   */
  private async probeStorageEdges(
    targets: MassAuditTarget[],
    chain: SupportedChain,
    client: PublicClient,
  ): Promise<ContractEdge[]> {
    const edges: ContractEdge[] = [];

    // Well-known storage slots for common patterns
    const ORACLE_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000006"; // common oracle slot
    const ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"; // EIP-1967 admin
    const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"; // EIP-1967 impl

    for (const target of targets.slice(0, 30)) { // Limit RPC calls
      const addr = target.address.toLowerCase() as Address;

      try {
        // Check EIP-1967 implementation slot
        const implSlot = await client.getStorageAt({
          address: addr,
          slot: IMPL_SLOT as Hex,
        });

        if (implSlot && implSlot !== "0x" + "0".repeat(64)) {
          const implAddr = ("0x" + implSlot.slice(-40)) as Address;
          if (implAddr !== "0x0000000000000000000000000000000000000000") {
            edges.push({
              from: addr,
              to: implAddr.toLowerCase() as Address,
              interaction: "delegatecall",
              functionName: "EIP-1967 implementation",
              confidence: 95,
              bidirectional: false,
            });
          }
        }

        // Check admin slot
        const adminSlot = await client.getStorageAt({
          address: addr,
          slot: ADMIN_SLOT as Hex,
        });

        if (adminSlot && adminSlot !== "0x" + "0".repeat(64)) {
          const adminAddr = ("0x" + adminSlot.slice(-40)) as Address;
          if (adminAddr !== "0x0000000000000000000000000000000000000000") {
            edges.push({
              from: addr,
              to: adminAddr.toLowerCase() as Address,
              interaction: "external_call",
              functionName: "EIP-1967 admin",
              confidence: 90,
              bidirectional: false,
            });
          }
        }
      } catch {
        // Non-fatal — some contracts don't have these slots
      }
    }

    return edges;
  }

  // ── Graph Metrics ───────────────────────────────────────────────────

  /**
   * Computes in-degree, out-degree, and dependency depth for each node.
   */
  private computeGraphMetrics(
    nodes: Map<Address, ContractNode>,
    edges: ContractEdge[],
  ): void {
    // Count degrees
    for (const edge of edges) {
      const fromNode = nodes.get(edge.from);
      const toNode = nodes.get(edge.to);
      if (fromNode) fromNode.outDegree++;
      if (toNode) toNode.inDegree++;
    }

    // Compute dependency depth (max distance from a root node)
    // Root = node with inDegree 0
    const adjacency = new Map<Address, Address[]>();
    for (const edge of edges) {
      if (!adjacency.has(edge.from)) adjacency.set(edge.from, []);
      adjacency.get(edge.from)!.push(edge.to);
    }

    const visited = new Set<Address>();
    const depthOf = (addr: Address, depth: number): void => {
      if (visited.has(addr)) return;
      visited.add(addr);

      const node = nodes.get(addr);
      if (node) node.dependencyDepth = Math.max(node.dependencyDepth, depth);

      for (const neighbor of adjacency.get(addr) ?? []) {
        depthOf(neighbor, depth + 1);
      }

      visited.delete(addr);
    };

    // Start BFS from all root nodes
    for (const [addr, node] of nodes) {
      if (node.inDegree === 0) {
        depthOf(addr, 0);
      }
    }
  }

  // ── Composability Detectors ─────────────────────────────────────────

  /**
   * Detector 1: Shared Oracle Manipulation
   *
   * If multiple high-TVL protocols read from the same oracle feed, an attacker
   * who can manipulate that feed can cascade the exploit across all consumers.
   */
  private detectSharedOracleRisk(
    nodes: Map<Address, ContractNode>,
    edges: ContractEdge[],
    targets: MassAuditTarget[],
  ): ComposabilityFinding[] {
    const findings: ComposabilityFinding[] = [];

    // Group oracle reads by target (oracle address)
    const oracleConsumers = new Map<Address, Address[]>();
    for (const edge of edges) {
      if (edge.interaction === "oracle_read" || edge.interaction === "price_feed") {
        if (!oracleConsumers.has(edge.to)) oracleConsumers.set(edge.to, []);
        oracleConsumers.get(edge.to)!.push(edge.from);
      }
    }

    for (const [oracle, consumers] of oracleConsumers) {
      if (consumers.length < 2) continue;

      // Calculate aggregate TVL at risk
      const consumerNodes = consumers
        .map((c) => nodes.get(c))
        .filter((n): n is ContractNode => !!n);

      const totalTvl = consumerNodes.reduce((sum, n) => sum + n.tvlUsd, 0);
      if (totalTvl < HIGH_VALUE_TVL_THRESHOLD) continue;

      // Check if oracle itself has known vulnerabilities
      const oracleTarget = targets.find(
        (t) => t.address.toLowerCase() === oracle.toLowerCase(),
      );
      const oracleRisk = oracleTarget?.staticReport?.riskScore ?? 0;

      const confidence = Math.min(
        40 + consumers.length * 10 + (oracleRisk > 30 ? 20 : 0),
        95,
      );

      findings.push({
        id: `shared-oracle-${oracle.slice(0, 10)}-${Date.now()}`,
        riskClass: "shared_oracle_manipulation",
        severity: totalTvl > 1_000_000 ? "critical" : "high",
        description:
          `Oracle ${oracle.slice(0, 12)}... feeds ${consumers.length} DeFi protocols ` +
          `with aggregate $${(totalTvl / 1_000_000).toFixed(1)}M TVL. ` +
          `Single oracle manipulation cascades across: ` +
          consumers.map((c) => c.slice(0, 10)).join(", "),
        involvedContracts: [oracle, ...consumers],
        attackPath: [oracle, ...consumers],
        estimatedImpactUsd: totalTvl * 0.1, // conservative 10% of TVL
        confidence,
        detectedAt: Date.now(),
      });
    }

    return findings;
  }

  /**
   * Detector 2: Approval Chain Exploits
   *
   * contract A approves contract B → contract B has delegatecall → attacker
   * can use delegatecall to call transferFrom on A's approved tokens.
   */
  private detectApprovalChainExploits(
    nodes: Map<Address, ContractNode>,
    edges: ContractEdge[],
  ): ComposabilityFinding[] {
    const findings: ComposabilityFinding[] = [];

    // Find approval edges
    const approvalEdges = edges.filter((e) => e.interaction === "approval_grant");
    const delegatecallContracts = new Set(
      edges.filter((e) => e.interaction === "delegatecall").map((e) => e.from),
    );

    for (const approvalEdge of approvalEdges) {
      const approvedContract = approvalEdge.to;

      // Check if the approved contract has delegatecall or user-controlled calls
      if (delegatecallContracts.has(approvedContract)) {
        const approverNode = nodes.get(approvalEdge.from);
        const tvl = approverNode?.tvlUsd ?? 0;

        findings.push({
          id: `approval-chain-${approvalEdge.from.slice(0, 10)}-${approvedContract.slice(0, 10)}`,
          riskClass: "approval_chain_exploit",
          severity: tvl > HIGH_VALUE_TVL_THRESHOLD ? "critical" : "high",
          description:
            `Contract ${approvalEdge.from.slice(0, 12)}... grants approval to ` +
            `${approvedContract.slice(0, 12)}... which contains DELEGATECALL. ` +
            `Attacker can potentially drain approved tokens via delegated context.`,
          involvedContracts: [approvalEdge.from, approvedContract],
          attackPath: [approvedContract, approvalEdge.from],
          estimatedImpactUsd: tvl,
          confidence: approvalEdge.confidence >= 90 ? 80 : 55,
          detectedAt: Date.now(),
        });
      }

      // Check for chained approvals: A approves B, B approves C
      // (deeper approval chains = higher risk)
      const secondHop = edges.filter(
        (e) => e.from === approvedContract && e.interaction === "approval_grant",
      );

      for (const hop2 of secondHop) {
        const endNode = nodes.get(hop2.to);
        const startNode = nodes.get(approvalEdge.from);
        const tvl = Math.max(startNode?.tvlUsd ?? 0, endNode?.tvlUsd ?? 0);

        findings.push({
          id: `approval-chain-deep-${approvalEdge.from.slice(0, 8)}-${hop2.to.slice(0, 8)}`,
          riskClass: "approval_chain_exploit",
          severity: "high",
          description:
            `Multi-hop approval chain: ${approvalEdge.from.slice(0, 10)} → ` +
            `${approvedContract.slice(0, 10)} → ${hop2.to.slice(0, 10)}. ` +
            `Compromise of any intermediate contract drains upstream approvals.`,
          involvedContracts: [approvalEdge.from, approvedContract, hop2.to],
          attackPath: [hop2.to, approvedContract, approvalEdge.from],
          estimatedImpactUsd: tvl,
          confidence: 50,
          detectedAt: Date.now(),
        });
      }
    }

    return findings;
  }

  /**
   * Detector 3: Flash Loan Cascade Attacks
   *
   * Identifies contracts that interact with flash loan providers AND have
   * price-sensitive operations that can be manipulated within a single tx.
   */
  private detectFlashLoanCascades(
    nodes: Map<Address, ContractNode>,
    edges: ContractEdge[],
  ): ComposabilityFinding[] {
    const findings: ComposabilityFinding[] = [];

    // Find flash loan edges
    const flashEdges = edges.filter((e) => e.interaction === "flash_loan");
    const flashProviders = new Set(flashEdges.map((e) => e.to));
    const flashBorrowers = new Set(flashEdges.map((e) => e.from));

    // Find contracts that both borrow flash loans AND interact with price feeds
    const oracleEdges = edges.filter(
      (e) => e.interaction === "oracle_read" || e.interaction === "price_feed",
    );

    for (const borrower of flashBorrowers) {
      // Does this borrower also read oracles or interact with price-sensitive contracts?
      const borrowerOracleEdges = oracleEdges.filter((e) => e.from === borrower);
      if (borrowerOracleEdges.length === 0) continue;

      // Find other contracts sharing the same oracle
      for (const oracleEdge of borrowerOracleEdges) {
        const oracleAddr = oracleEdge.to;
        const coConsumers = oracleEdges
          .filter((e) => e.to === oracleAddr && e.from !== borrower)
          .map((e) => e.from);

        if (coConsumers.length === 0) continue;

        const totalTvl = [borrower, ...coConsumers]
          .map((a) => nodes.get(a)?.tvlUsd ?? 0)
          .reduce((s, v) => s + v, 0);

        findings.push({
          id: `flash-cascade-${borrower.slice(0, 10)}-${oracleAddr.slice(0, 10)}`,
          riskClass: "flash_loan_cascade",
          severity: totalTvl > 500_000 ? "critical" : "high",
          description:
            `Flash loan borrower ${borrower.slice(0, 12)}... shares oracle ` +
            `${oracleAddr.slice(0, 12)}... with ${coConsumers.length} other protocol(s). ` +
            `Attacker can flash-borrow → manipulate oracle → exploit co-consumers in one tx.`,
          involvedContracts: [borrower, oracleAddr, ...coConsumers],
          attackPath: [borrower, oracleAddr, ...coConsumers.slice(0, 3)],
          estimatedImpactUsd: totalTvl * 0.15,
          confidence: 55 + coConsumers.length * 5,
          detectedAt: Date.now(),
        });
      }
    }

    return findings;
  }

  /**
   * Detector 4: Cross-Contract Reentrancy
   *
   * Finds callback patterns where contract A calls B, B calls back to A (or C),
   * and state is modified after the callback returns — classic cross-contract
   * reentrancy invisible to single-contract Slither analysis.
   */
  private detectCrossContractReentrancy(
    nodes: Map<Address, ContractNode>,
    edges: ContractEdge[],
  ): ComposabilityFinding[] {
    const findings: ComposabilityFinding[] = [];

    // Build adjacency lists
    const outgoing = new Map<Address, ContractEdge[]>();
    for (const edge of edges) {
      if (!outgoing.has(edge.from)) outgoing.set(edge.from, []);
      outgoing.get(edge.from)!.push(edge);
    }

    // Find callback edges and external call edges
    const callbackEdges = edges.filter((e) => e.interaction === "callback");

    // For each contract with a callback, check if it also makes external calls
    // that could lead back to the caller
    for (const cbEdge of callbackEdges) {
      const callbackContract = cbEdge.from;
      const outEdges = outgoing.get(callbackContract) ?? [];

      // Find external calls from this contract
      const externalCalls = outEdges.filter(
        (e) => e.interaction === "external_call" || e.interaction === "token_transfer",
      );

      for (const extCall of externalCalls) {
        // Check if the external call target can call back
        const targetOutEdges = outgoing.get(extCall.to) ?? [];
        const canCallBack = targetOutEdges.some(
          (e) => e.to === callbackContract ||
                 e.interaction === "callback" ||
                 e.interaction === "external_call",
        );

        if (canCallBack) {
          const tvl = Math.max(
            nodes.get(callbackContract)?.tvlUsd ?? 0,
            nodes.get(extCall.to)?.tvlUsd ?? 0,
          );

          findings.push({
            id: `cross-reentrancy-${callbackContract.slice(0, 10)}-${extCall.to.slice(0, 10)}`,
            riskClass: "cross_contract_reentrancy",
            severity: tvl > HIGH_VALUE_TVL_THRESHOLD ? "critical" : "high",
            description:
              `Cross-contract reentrancy path: ${callbackContract.slice(0, 12)}... ` +
              `calls ${extCall.to.slice(0, 12)}... which can call back. ` +
              `State changes after callback may be exploitable.`,
            involvedContracts: [callbackContract, extCall.to],
            attackPath: [callbackContract, extCall.to, callbackContract],
            estimatedImpactUsd: tvl * 0.5,
            confidence: 45 + (canCallBack ? 20 : 0),
            detectedAt: Date.now(),
          });
        }
      }
    }

    // Also detect cycles in the call graph (A→B→C→A)
    const visited = new Set<Address>();
    const inStack = new Set<Address>();
    const cyclePaths: Address[][] = [];

    const dfs = (node: Address, path: Address[]): void => {
      if (inStack.has(node)) {
        // Found a cycle
        const cycleStart = path.indexOf(node);
        if (cycleStart >= 0) {
          cyclePaths.push(path.slice(cycleStart).concat(node));
        }
        return;
      }
      if (visited.has(node)) return;

      visited.add(node);
      inStack.add(node);

      for (const edge of outgoing.get(node) ?? []) {
        if (
          edge.interaction === "external_call" ||
          edge.interaction === "callback" ||
          edge.interaction === "delegatecall"
        ) {
          dfs(edge.to, [...path, node]);
        }
      }

      inStack.delete(node);
    };

    for (const addr of nodes.keys()) {
      visited.clear();
      inStack.clear();
      dfs(addr, []);
    }

    // Report cycles of length 3+ (A→B→C→A style)
    for (const cycle of cyclePaths) {
      if (cycle.length < 4) continue; // Need at least 3 distinct nodes + return
      const uniqueNodes = [...new Set(cycle.slice(0, -1))]; // Remove duplicate at end
      if (uniqueNodes.length < 3) continue;

      const totalTvl = uniqueNodes
        .map((a) => nodes.get(a)?.tvlUsd ?? 0)
        .reduce((s, v) => s + v, 0);

      findings.push({
        id: `call-cycle-${uniqueNodes.map((a) => a.slice(0, 6)).join("-")}`,
        riskClass: "cross_contract_reentrancy",
        severity: totalTvl > HIGH_VALUE_TVL_THRESHOLD ? "critical" : "high",
        description:
          `Call graph cycle detected: ${uniqueNodes.map((a) => a.slice(0, 10)).join(" → ")} → loop. ` +
          `${uniqueNodes.length}-hop reentrancy path bypasses single-contract guards.`,
        involvedContracts: uniqueNodes,
        attackPath: cycle,
        estimatedImpactUsd: totalTvl * 0.3,
        confidence: 40 + uniqueNodes.length * 5,
        detectedAt: Date.now(),
      });
    }

    return findings;
  }

  /**
   * Detector 5: Dependency Rug Risk
   *
   * High-TVL protocols depending on low-quality or unaudited contracts.
   * If contract A has $10M TVL and depends on contract B which has a
   * riskScore of 60+, that's a systemic risk.
   */
  private detectDependencyRugRisk(
    nodes: Map<Address, ContractNode>,
    edges: ContractEdge[],
  ): ComposabilityFinding[] {
    const findings: ComposabilityFinding[] = [];

    for (const edge of edges) {
      const fromNode = nodes.get(edge.from);
      const toNode = nodes.get(edge.to);
      if (!fromNode || !toNode) continue;

      // High-value contract depending on risky contract
      if (fromNode.tvlUsd >= HIGH_VALUE_TVL_THRESHOLD && toNode.riskScore >= 50) {
        findings.push({
          id: `dep-rug-${edge.from.slice(0, 10)}-${edge.to.slice(0, 10)}`,
          riskClass: "dependency_rug",
          severity: toNode.riskScore >= 70 ? "critical" : "high",
          description:
            `High-value contract ${edge.from.slice(0, 12)}... ($${(fromNode.tvlUsd / 1000).toFixed(0)}K TVL) ` +
            `depends on ${edge.to.slice(0, 12)}... (risk score: ${toNode.riskScore}/100) ` +
            `via ${edge.interaction}. Compromise of dependency drains upstream TVL.`,
          involvedContracts: [edge.from, edge.to],
          attackPath: [edge.to, edge.from],
          estimatedImpactUsd: fromNode.tvlUsd * 0.5,
          confidence: 50 + Math.min(toNode.riskScore / 2, 30),
          detectedAt: Date.now(),
        });
      }

      // Any contract depending on an unknown (not in our audit DB) contract
      if (fromNode.tvlUsd >= HIGH_VALUE_TVL_THRESHOLD && !toNode.category) {
        findings.push({
          id: `dep-unknown-${edge.from.slice(0, 10)}-${edge.to.slice(0, 10)}`,
          riskClass: "dependency_rug",
          severity: "medium",
          description:
            `High-value contract ${edge.from.slice(0, 12)}... ($${(fromNode.tvlUsd / 1000).toFixed(0)}K TVL) ` +
            `depends on unaudited contract ${edge.to.slice(0, 12)}... ` +
            `Category unknown — should be added to audit pipeline.`,
          involvedContracts: [edge.from, edge.to],
          attackPath: [edge.to, edge.from],
          estimatedImpactUsd: fromNode.tvlUsd * 0.2,
          confidence: 40,
          detectedAt: Date.now(),
        });
      }
    }

    return findings;
  }

  /**
   * Detector 6: Price Feed Cascade Failure
   *
   * Detects when a stale or manipulable price feed is used as input to
   * another price computation, creating cascading corruption.
   * E.g., Chainlink ETH/USD → custom adapter → lending protocol
   */
  private detectPriceFeedCascade(
    nodes: Map<Address, ContractNode>,
    edges: ContractEdge[],
    targets: MassAuditTarget[],
  ): ComposabilityFinding[] {
    const findings: ComposabilityFinding[] = [];

    // Find all oracle-reading contracts
    const oracleEdges = edges.filter(
      (e) => e.interaction === "oracle_read" || e.interaction === "price_feed",
    );

    // Find contracts that are BOTH oracle consumers AND oracle providers
    // (i.e., adapters/routers that read one feed and expose another)
    const oracleReaders = new Set(oracleEdges.map((e) => e.from));
    const oracleTargets = new Set(oracleEdges.map((e) => e.to));
    const adapters = [...oracleReaders].filter((a) => oracleTargets.has(a));

    for (const adapter of adapters) {
      // What does the adapter read from?
      const upstream = oracleEdges
        .filter((e) => e.from === adapter)
        .map((e) => e.to);

      // Who reads from the adapter?
      const downstream = oracleEdges
        .filter((e) => e.to === adapter)
        .map((e) => e.from);

      if (upstream.length === 0 || downstream.length === 0) continue;

      const downstreamTvl = downstream
        .map((a) => nodes.get(a)?.tvlUsd ?? 0)
        .reduce((s, v) => s + v, 0);

      if (downstreamTvl < HIGH_VALUE_TVL_THRESHOLD) continue;

      // Check adapter's own risk score
      const adapterNode = nodes.get(adapter);
      const adapterRisk = adapterNode?.riskScore ?? 0;

      findings.push({
        id: `price-cascade-${adapter.slice(0, 10)}`,
        riskClass: "price_feed_cascade",
        severity: downstreamTvl > 1_000_000 ? "critical" : "high",
        description:
          `Price feed adapter ${adapter.slice(0, 12)}... (risk: ${adapterRisk}/100) ` +
          `reads from ${upstream.length} upstream feed(s) and serves ` +
          `${downstream.length} downstream protocol(s) with ` +
          `$${(downstreamTvl / 1_000_000).toFixed(1)}M aggregate TVL. ` +
          `Adapter compromise or upstream staleness cascades to all consumers.`,
        involvedContracts: [...upstream, adapter, ...downstream],
        attackPath: [...upstream.slice(0, 1), adapter, ...downstream.slice(0, 2)],
        estimatedImpactUsd: downstreamTvl * 0.2,
        confidence: 45 + downstream.length * 5 + (adapterRisk > 30 ? 15 : 0),
        detectedAt: Date.now(),
      });
    }

    return findings;
  }

  // ── Phase 5: Cross-Contract Dataflow Analysis ────────────────────────

  /**
   * Analyzes dataflow between contracts using cached EVM analysis results.
   * Detects transitive calldata forwarding and delegatecall storage corruption.
   */
  analyzeDataFlows(
    targets: Map<Address, { evmAnalysis?: EVMAnalysisResultRef }>,
  ): ComposabilityFinding[] {
    const findings: ComposabilityFinding[] = [];

    for (const [address, target] of targets) {
      const evm = target.evmAnalysis;
      if (!evm) continue;

      // Detect contracts that forward calldata and have high external call counts
      if (evm.externalCallCount > 5 && evm.taintFlowCount > 3) {
        findings.push({
          id: `transitive-fwd-${address.slice(0, 10)}`,
          riskClass: "transitive_calldata_forwarding",
          severity: evm.highSeverityTaintFlows ? "high" : "medium",
          description:
            `Contract ${address.slice(0, 12)}... has ${evm.externalCallCount} external calls ` +
            `and ${evm.taintFlowCount} taint flows — potential transitive calldata forwarding chain.`,
          involvedContracts: [address],
          attackPath: [address],
          estimatedImpactUsd: 0,
          confidence: Math.min(evm.taintFlowCount * 10, 70),
          detectedAt: Date.now(),
        });
      }

      // Detect delegatecall with proxy storage patterns
      if (evm.isUpgradeableProxy && evm.externalCallCount > 0) {
        findings.push({
          id: `delegatecall-storage-${address.slice(0, 10)}`,
          riskClass: "delegatecall_storage_corruption",
          severity: "high",
          description:
            `Upgradeable proxy ${address.slice(0, 12)}... with ${evm.externalCallCount} external calls. ` +
            `Verify storage layouts match between proxy and implementation to prevent corruption.`,
          involvedContracts: [address],
          attackPath: [address],
          estimatedImpactUsd: 0,
          confidence: 50,
          detectedAt: Date.now(),
        });
      }
    }

    return findings;
  }
}
