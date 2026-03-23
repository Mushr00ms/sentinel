# SENTINEL — Sonic Red-Team Dominance Directive

## Preamble

This document is a war plan. It is derived from 86+ research sessions, $3,800 in live losses, $342 in confirmed profits, and months of on-chain reconnaissance across 14 chains and 30+ protocols. Every recommendation below is grounded in empirical Sonic data, not theory.

## Execution Model

**Operator:** Claude Code (AI) with parallel sub-agents.

This is not a 6-week human roadmap. All modules are built in a single day through parallel sub-agent execution. Claude Code spawns specialized agents for each module simultaneously — one agent writes the governance detector while another builds the bytecode analysis pipeline while another wires the oracle hunter. No sequential dependencies between modules means no idle time.

**Sub-agent allocation:**
- Agent 1: Module A (Oracle Degradation Hunter) — TypeScript, viem, DEX quoter integration
- Agent 2: Module B (Governance Shock Detector) — event polling, LTV ramp simulator, pre-staged tx builder
- Agent 3: Module C (Position Kill List) — tiered monitoring, toxicity scoring, profit density ranking
- Agent 4: Module D (Misconfiguration Sniper) — admin mapping, approval graph, ERC-4626 checks
- Agent 5: Module E (Execution Core) — collateral exit validation hardening, sweeper optimization
- Agent 6: Module F.1-F.2 (Deployment Monitor + Static Analysis) — bytecode scanner, decompiler integration, signature matching
- Agent 7: Module F.3-F.4 (Symbolic Execution + Fuzzing) — Halmos/Mythril harness generation, Echidna campaign templates, corpus seeding
- Agent 8: Module F.5-F.6 (Exploit Construction + Re-Analysis) — fork PoC framework, proxy upgrade watcher, TVL-triggered re-scan
- Agent 9: Toolchain setup — install Heimdall, Halmos, Echidna, Mythril, Slither; verify all dependencies
- Agent 10: Integration + testing — wire all modules into unified pipeline, end-to-end test on synthetic vulnerable contract

**Timeline:** All agents launch in parallel. Total wall-clock time: one session. Goes live same day.

---

## 1. Adversarial Sonic Landscape

### Competitor Assessment

**Professional searcher presence: LOW-MEDIUM.**

Evidence:
- Aave V3 Sonic has only 10 active liquidators across 257 recent events. Compare Ethereum (hundreds of competing bots per opportunity).
- Euler V2 Sonic: 80-119 liquidatable positions detected, all currently failing profit checks — meaning competitors are not aggressively pursuing sub-threshold positions either, OR positions genuinely aren't profitable yet.
- First Euler V2 liquidation profit (~$342) was captured without competition.
- No Flashbots/MEV Boost infrastructure on Sonic. Mempool is open. This is simultaneously an advantage (no builder relationships needed) and a risk (anyone can frontrun).

**Known competitor signatures:**
- 10 Aave V3 liquidator addresses (can be fingerprinted from on-chain events)
- Unknown number of Euler V2/Silo V2 bots (likely <5 based on tx patterns)

**Conclusion: Sonic is a frontier chain with amateur-to-intermediate competition. The window is open but closing.**

### Governance Hygiene: POOR

- **Euler V2 Sonic governor**: `0xB672Ea44A1EC692A9Baf851dC90a1Ee3DB25F1C4` — 2/4 Gnosis Safe. **ZERO TIMELOCK.** LTV changes execute instantly. This is the single most dangerous governance configuration in the entire Euler V2 deployment.
- 358 historical `GovSetLTV` events on Sonic — highest of any chain. Governance is actively used and fast-moving.
- Secondary governor (`0x3BA1...8B65`): 2/5 Safe, also no timelock.
- Silo V2: Governance structure unknown, requires mapping.
- Aave V3 Sonic: Standard Aave governance (slower, more predictable).

### Audit Maturity: MIXED

- Euler V2 core: Audited by multiple firms. But Sonic deployment uses CrossAdapter oracles, RedStone feeds, and custom vault configurations that may not have been specifically audited.
- Silo V2 core: Audited, but the June 2025 exploit ($550K on Sonic+Arb) was in a peripheral leverage contract, not core. Our `SiloLiquidationHelper` is custom — only we control the calldata.
- Many Sonic DeFi protocols are forks with thin modification layers. Fork density is HIGH.
- **New deployments are the primary attack surface** — unaudited contracts deploying daily, often handling significant funds before any review.

### TVL Concentration

| Protocol | Borrows | Markets | Competition |
|----------|---------|---------|-------------|
| Euler V2 | ~$14.4M | 5 vaults | Low |
| Aave V3 | ~$3.78M | Multiple | 10 liquidators |
| Silo V2 | Unknown | 11 curated | Very low |
| Morpho Blue | Active | Non-standard addr | Low |

**Total addressable: ~$20M+ in borrows.** Not massive, but competition is thin enough that dominance is achievable.

### Oracle Architecture: FRAGILE

| Feed | Type | Max Staleness | Real Heartbeat | Buffer |
|------|------|--------------|----------------|--------|
| wS/USD | Chainlink | 90,000s (25h) | ~600s | **150x** |
| WETH/USD | Chainlink | 90,000s (25h) | ~600s | **150x** |
| USDC.e/USD | Chainlink | 90,000s (25h) | ~600s | **150x** |
| scUSD/USD | RedStone | 25,200s (7h) | Variable | Large |
| scETH/WETH | CrossAdapter | 25,200s (7h) | Variable | Large |
| wstkscUSD/scUSD | Pyth | 60s | Observed 2,746s lag | **46x** |

**No Pyth push-to-liquidate vector** (Pyth not broadly deployed on Sonic). But the staleness buffers on Chainlink feeds are absurdly generous — 150x the actual heartbeat. Oracle prices can lag DEX reality by hours before the protocol considers them "stale."

**Zero hooked vaults on Sonic** — all 16 Euler V2 vaults have clean hookConfig. No bypass engineering needed.

### Where Sonic Is Structurally Weak

1. **Governance speed with no guardrails.** Zero-timelock 2/4 multisig can instantly crash LTVs and create liquidation cascades. No advance warning.
2. **Oracle staleness tolerance.** 25-hour max staleness on 600-second heartbeat feeds. Price can diverge from reality for extended periods.
3. **Thin DEX liquidity.** stS liquidity cliffs at 3M+ tokens (13%+ impact). Large liquidations will face slippage walls.
4. **No MEV protection infrastructure.** Open mempool, no Flashbots. First-to-submit wins, but also first-to-be-frontrun.
5. **Collateral toxicity risk.** stkscUSD demonstrated: oracle says $1, reality says $0.085. Stream Finance collapse permanently impaired the backing. This pattern can repeat with other wrapped/staked assets.
6. **Rapid new contract deployment with no audit culture.** Sonic attracts fork-and-deploy projects. New contracts handling funds appear weekly, often with unvalidated calldata paths, missing access controls, or ERC-4626 inflation surfaces.

---

## 2. Attack Surface Prioritization

Ranked by solo-operator exploitability on Sonic specifically:

| Rank | Class | Vector | Freq Prob | Detection Edge | Complexity | Capital | Competitor Blindspot | Score |
|------|-------|--------|-----------|---------------|------------|---------|---------------------|-------|
| **1** | **E** | **Governance LTV ramp-down** | HIGH | HIGH (no timelock = instant) | LOW | LOW | HIGH (most bots don't simulate governance) | **9.2** |
| **2** | **A** | **Oracle staleness divergence** | HIGH | MEDIUM (150x buffers = long windows) | LOW | LOW-MED | MEDIUM (basic bots check HF, not oracle freshness) | **8.5** |
| **3** | **H** | **New contract exploit (bytecode vuln)** | MEDIUM | **VERY HIGH** (nobody else is fuzzing Sonic deploys) | HIGH | VARIES | **VERY HIGH** | **8.3** |
| **4** | **G** | **Collateral exit failure** | MEDIUM | HIGH (we lost $3,800 learning this) | LOW | LOW | **VERY HIGH** (nobody else checks this) | **8.0** |
| **5** | **F** | **Liquidation denial/pause recovery** | MEDIUM | HIGH (we monitor hook/pause state) | LOW | LOW | HIGH (most bots skip paused vaults forever) | **7.5** |
| **6** | **C** | **Unvalidated calldata (periphery)** | MEDIUM | HIGH (Silo leverage exploit pattern) | MEDIUM | LOW | HIGH | **7.0** |
| **7** | **B** | **Missing health check after state change** | LOW-MED | HIGH (symbolic exec catches this) | MEDIUM | LOW | HIGH (requires tooling most searchers lack) | **6.5** |
| **8** | **D** | **ERC-4626 donation/inflation** | LOW | MEDIUM | HIGH | HIGH | MEDIUM | **4.0** |

**Primary focus: Classes E, A, H, G, F, C, B.** Class H (new contract exploits) is elevated because Sonic's frontier status means unaudited contracts are the norm, and zero competitors are running automated analysis on new Sonic deployments.

---

## 3. Scope Definition

### BUILT — Core Capabilities

- **Governance shock detection** — per-block monitoring of LTV, hook, oracle parameter changes
- **Oracle degradation hunting** — staleness tracking, DEX divergence, pre-staged liquidation
- **Position kill list** — tiered monitoring of all borrower positions across 4 protocols
- **Collateral exit validation** — learned from $3,800 loss, mandatory pre-flight checks
- **New contract exploit analysis** — bytecode decompilation, symbolic execution, targeted fuzzing of every new Sonic contract that handles funds
- **Misconfiguration sniping** — admin EOA detection, calldata forwarding, ERC-4626 surface checks

### NOT BUILT — Intentional Exclusions

- **Multi-chain orchestration** — Sentinel is Sonic-native. Other chains are handled separately.
- **DEX arbitrage** — Sub-2% spreads on Sonic. Not our edge.
- **Mempool monitoring for generic MEV** — No private pools on Sonic, and we're not competing on latency for sandwich/backrun.
- **Universal protocol auto-discovery** — We curate targets manually. Four known protocols + new deployment scanning.

---

## 4. Sonic Red-Team Architecture

### Module A — Oracle Degradation Hunter

**Target:** Class A opportunities.

**Design:**

```
Every 10 blocks (~10s on Sonic):
  For each Euler V2 vault oracle:
    1. Read on-chain oracle price (EulerRouter.getQuote())
    2. Read DEX spot price (OpenOcean quote, 0 slippage)
    3. Compute divergence = |oracle - dex| / dex
    4. Read Chainlink roundData: (roundId, answer, startedAt, updatedAt, answeredInRound)
    5. Compute staleness = now - updatedAt
    6. Compute staleness_ratio = staleness / heartbeat_interval

  IF divergence > 2% AND staleness_ratio > 5x:
    -> ALERT: Oracle degradation detected
    -> Immediately re-scan ALL positions in affected vault
    -> Compute kill list: positions where HF < 1.0 at DEX price but HF > 1.0 at oracle price
    -> These are "phantom healthy" positions -- they WILL become liquidatable when oracle updates

  IF divergence > 5%:
    -> CRITICAL: Likely price event
    -> Pre-compute liquidation transactions for top-10 profit-density positions
    -> Stage in memory, ready for instant submission when oracle catches up
```

**Detection speed edge:** We don't wait for `checkLiquidation()` to return true. We compute what WILL be liquidatable when the oracle next updates, and pre-stage execution transactions.

**False positive avoidance:**
- Require BOTH staleness AND divergence. Divergence alone could be DEX manipulation. Staleness alone could be low-volatility period.
- Cross-reference scUSD/RedStone vs USDC.e/Chainlink. If both stale in same direction, it's a real price event. If only one, it's feed-specific.

**Front-running liquidation waves:** When oracle updates, there's a ~1 block window before competitors react. Our pre-staged transactions submit in that block.

### Module B — Governance Shock Detector

**Target:** Class E + F opportunities.

**Design:**

```
Every block:
  Poll EVC logs for:
    - GovSetLTV (topic 0xc69392046c26324e9eee913208811542aabcbde6a41ce9ee3b45473b18eb3c76)
    - GovSetHookConfig (topic 0xabadffb695acdb6863cd1324a91e5c359712b9110a55f9103774e2fb67dedb6a)

  Poll EulerRouter for:
    - ConfigSet (topic 0x4ac83f39568b63f952374c82351889b07aff4f7e261232a20ba5a2a6d82b9ce0)

  Poll Silo V2 governance for:
    - Parameter changes (TBD -- requires governance mapping)

  Poll Aave V3 Pool for:
    - ReserveConfigurationChanged
```

**On GovSetLTV detection:**

```
1. Decode: (collateral, borrowLTV, liquidationLTV, initialLTV, targetLTV, rampDuration)

2. IF targetLiqLTV < currentLiqLTV (LTV REDUCTION):
   a. IF rampDuration == 0: IMMEDIATE liquidation wave possible
   b. IF rampDuration > 0: Compute effectiveLTV at each future block

3. For each position in affected (collateral, borrow) pair:
   a. Compute: at what effective LTV does this position become liquidatable?
   b. Compute: what block number does that correspond to?
   c. Rank by profit density (profit / capital required)

4. IF rampDuration == 0 (Sonic's pattern):
   -> INSTANT: Submit liquidation in SAME BLOCK as governance tx
   -> Race condition: our tx must land in the same block or next block

5. Pre-build execution transactions for top candidates
6. Set block-trigger: when effectiveLTV crosses position threshold, auto-submit
```

**On GovSetHookConfig detection:**

```
IF hookTarget changes from address(0) to non-zero:
  -> Vault is being UNPAUSED
  -> Check: were there positions blocked by this pause?
  -> If yes: immediate liquidation opportunity
  -> Submit pre-built transactions

IF hookedOps bit 8 (OP_REDEEM) cleared:
  -> Collateral redemption unpaused
  -> Same logic: check blocked positions, execute
```

**Capital pre-allocation:**
- Maintain a "governance war chest" — minimum 500 USDC.e on Sonic at all times
- When governance event detected with >$500 profit potential: allocate full war chest
- If war chest insufficient: use flash loan (Balancer vault holds ~317K wS, ~5.75 WETH)

### Module C — Position Kill List Engine

**Target:** Classes A, E, F — the execution layer.

**Design:**

```
Tier 0 -- HOT LIST (every block):
  Positions where:
    - HF < 1.02 AND
    - Estimated profit > MIN_NET_PROFIT_USD ($1) AND
    - Collateral exit validated AND
    - No blockers (no hook pause, no oracle block, no toxic collateral)

  Max size: 20 positions
  Action: Pre-built transactions in memory, ready to submit

Tier 1 -- KILL LIST (every 5 blocks):
  Positions where:
    - HF < 1.05 AND
    - Estimated profit > $10 AND
    - Collateral exit partially validated (DEX quote cached <5 min)

  Max size: 100 positions
  Action: Cached simulation results, 1-block execution delay

Tier 2 -- WATCH LIST (every 50 blocks):
  Positions where:
    - HF < 1.15
    - Any profit potential

  Max size: 500 positions
  Action: HF tracking, trend analysis (approaching Tier 1?)

Tier 3 -- CENSUS (every 500 blocks):
  All known borrowers across Euler V2, Silo V2, Aave V3, Morpho Blue
  Action: Full rescan, discover new positions, prune closed positions
```

**Profit density prioritization:**

```
score = (gross_profit_usd - gas_usd) / max(capital_required_usd, 1)

Where:
  gross_profit = (collateral_seized * dex_price) - (debt_repaid * debt_price)
  gas_usd = estimated_gas * base_fee * wS_price
  capital_required = debt_repaid (if funded) or 0 (if flash loan)
```

**Collateral toxicity scoring:**

```
toxicity_score = 0

IF oracle_price / dex_price > 1.25:  toxicity += 50  (stkscUSD pattern)
IF vault_backing_ratio < 0.50:       toxicity += 30
IF withdrawal_queue_paused:          toxicity += 40
IF dex_liquidity < 2x_position_size: toxicity += 20
IF token_is_wrapped_staked_yield:    toxicity += 10  (inherent risk class)
IF governance_ownership_renounced:   toxicity += 20  (can't be fixed)

IF toxicity >= 50: BLOCK execution
IF toxicity >= 30: REDUCE position size to 25%
IF toxicity < 30:  FULL execution
```

**Toxic collateral blacklist (permanent):**
- `stkscUSD` (`0x4d85ba8c3918359c78ed09581e5bc7578ba932ba`) — 6.23% backing, permanently bricked
- `wstkscUSD` (`0x9fb76f7ce5FCeAA2C42887ff441D46095E494206`) — wrapper of above
- Any token where `oracle_price / dex_price > 3x` for >24 hours

### Module D — Misconfiguration Sniper

**Target:** Classes B, C, D — lightweight, opportunistic.

**Design:**

```
Every 1000 blocks (~17 min) scan:

1. Admin EOA detection:
   For each protocol contract with admin/owner role:
     - Is admin an EOA? -> FLAG (single point of failure)
     - Is admin a multisig? -> Check threshold
       - 1-of-N -> FLAG (equivalent to EOA)
       - 2-of-N where N < 5 -> WARNING

2. Periphery calldata audit:
   For Silo V2: scan all contracts with Approval events > 10
     - Does the approved contract accept arbitrary bytes calldata?
     - Does it forward to .call() with user-controlled target?
     - IF YES -> CRITICAL: Silo leverage exploit pattern

3. ERC-4626 surface check (Euler V2 collateral vaults):
   For each ERC-4626 vault used as collateral:
     - totalSupply < 1000 units? -> Donation attack surface
     - No virtual shares? -> Higher risk
     - convertToAssets() manipulable by direct transfer? -> CRITICAL
```

### Module E — Sonic Execution Core

**Atomic execution path (Euler V2):**
```
1. Flash loan wS/USDC.e from Balancer vault (~317K wS, ~5.75 WETH available)
2. Repay debt via EVC.batch() -> liquidateViaBatch()
3. Receive eTokens -> redeem to underlying collateral
4. Swap collateral -> debt token via OpenOcean (primary) or KyberSwap (fallback)
5. Repay flash loan
6. Profit remains in liquidator contract
7. Auto-withdraw sweeper claims profits every 30s
```

**Atomic execution path (Silo V2):**
```
1. SiloLiquidationHelper.executeLiquidation(debtSilo, debtAsset, repayAmount, hookData, swaps[])
2. Built-in flash mechanism (Silo native)
3. Swap via same aggregator stack (OpenOcean -> KyberSwap -> LiFi -> Odos -> 1inch)
```

**Atomic execution path (Aave V3):**
```
1. Flash loan debt token from Aave V3 pool itself (cheapest)
2. Pool.liquidationCall(collateral, debt, user, maxUint256, false)
3. Swap received collateral -> debt token
4. Repay flash loan + premium
```

**Pre-flight collateral exit validation (MANDATORY — learned from $3,800 loss):**
```
BEFORE any execution:
  1. GET dex_price = OpenOcean quote for collateral -> USDC.e
  2. GET oracle_price = EulerRouter.getQuote() or equivalent
  3. IF oracle_price / dex_price > 1.25 -> ABORT (toxic collateral)
  4. CHECK withdrawal queue isPaused() for wrapped/vault tokens -> ABORT if paused
  5. CHECK dex liquidity: quote for full position size
     IF price_impact > 20% -> REDUCE to 50% of position
     IF price_impact > 40% -> ABORT
  6. CHECK vault cash: balanceOf(underlying, vault) >= position_size
     IF insufficient -> REDUCE to available cash
```

**Sonic mempool behavior:**
- Open mempool. No private transaction pools. No Flashbots.
- Transactions visible to all nodes immediately.
- Block time: ~1 second.
- Mitigation: Speed. Submit within 1 block of detection. No simulation-then-execute gap — simulate off-chain, submit directly. If it reverts, gas cost is minimal on Sonic (<$0.01).

**Failure containment:**
```
MAX_CAPITAL_PER_EXECUTION   = $5,000 (funded) or unlimited (flash loan, zero risk)
MAX_GAS_PER_TX              = 3,000,000
ABORT_IF_GAS_PRICE          > 500 gwei (Sonic norm is <10 gwei)
ABORT_IF_NONCE_MISMATCH     (indicates pending tx collision)
REVERT_COST_BUDGET          = $5/day (max gas wasted on reverts)
```

### Module F — New Contract Exploit Engine

**Target:** Class H — bytecode-level vulnerability discovery on newly deployed Sonic contracts.

This is the structural edge no other Sonic searcher is running. New contracts deploying on Sonic that handle funds are analyzed automatically using decompilation, symbolic execution, and targeted fuzzing.

#### F.1 — New Deployment Monitor

```
Every block:
  Scan for contract creation transactions (tx.to == null)
  For each new contract:
    1. Fetch bytecode via eth_getCode()
    2. Classify: does this contract handle funds?
       - Has payable functions?
       - Has ERC-20 transfer/transferFrom calls?
       - Has approval patterns?
       - Has delegatecall?
       - Bytecode size > 200 bytes? (filter out minimal proxies)
    3. IF fund-handling: queue for full analysis pipeline

  Also monitor:
    - Factory contract Create2 deployments (known factory addresses)
    - Proxy upgrades (implementation changes on existing proxies)
    - New markets/vaults added to known protocols (Euler V2, Silo V2, Aave V3)
```

**Throughput target:** Sonic deploys ~50-200 contracts/day. After fund-handling filter, expect ~10-30 candidates/day for deep analysis.

#### F.2 — Bytecode Decompilation & Static Analysis

```
For each candidate contract:

  1. DECOMPILE (Heimdall / Panoramix / ethervm.io):
     - Extract function signatures
     - Reconstruct control flow graph
     - Identify storage layout
     - Map external calls (CALL, DELEGATECALL, STATICCALL targets)

  2. SIGNATURE MATCHING:
     - Match function selectors against known vulnerable patterns:
       - donate/donateToReserves -> Missing health check (Class B, Euler V1 pattern)
       - leverage/openLeverage/zap -> Unvalidated calldata (Class C, Silo V2 pattern)
       - flashLoan/flashBorrow -> Callback reentrancy surface
       - multicall/batch/execute -> Generic calldata forwarding
       - upgrade/upgradeProxy -> Admin takeover surface
       - setOracle/setPriceFeed -> Oracle manipulation surface
     - Check 4byte.directory for selector collisions

  3. CALL GRAPH ANALYSIS:
     - Map: which functions can call which external contracts?
     - Flag: any function that forwards user-supplied bytes to .call()
     - Flag: any function that performs delegatecall to user-controlled address
     - Flag: any function that sends ETH/tokens based on user-controlled parameters
     - Flag: missing msg.sender/onlyOwner checks on privileged functions

  4. APPROVAL GRAPH:
     - Enumerate all Approval events for the contract address
     - If contract holds approvals to token contracts:
       - Can any external caller trigger transfers using those approvals?
       - Is calldata to the approved contract validated?
       - This is the "Approval Honeypot" pattern from Silo V2 exploit

  5. PROXY DETECTION:
     - EIP-1967 proxy? -> Monitor for upgrades
     - EIP-1167 minimal proxy? -> Analyze implementation, not proxy
     - Diamond proxy (EIP-2535)? -> Map all facets
     - Transparent proxy? -> Check admin slot
     - UUPS? -> Check upgradeToAndCall access control

  6. STORAGE ANALYSIS:
     - Read admin/owner slots (slot 0, EIP-1967 admin slot 0xb53...)
     - Is admin an EOA? -> Higher risk
     - Is admin address(0)? -> Immutable (good or permanently broken)
     - Is admin a known multisig factory pattern? -> Check threshold
```

**Output:** Structured report per contract — risk score, flagged functions, call graph, admin analysis, proxy type.

#### F.3 — Symbolic Execution

**Tool:** Halmos (preferred — Solidity-native, foundry-integrated) or Mythril as fallback.

```
For HIGH-RISK candidates (risk score > 70 from F.2):

  1. PROPERTY CHECKS (automated):
     - Can any non-admin caller drain contract balance?
       Property: forall msg.sender != admin: balance_after >= balance_before
     - Can any caller extract more tokens than they deposited?
       Property: forall user: withdrawn[user] <= deposited[user] + earned[user]
     - Can any caller bypass access control on privileged functions?
       Property: forall restricted_func: msg.sender in allowed_set
     - Can reentrancy change state between external calls?
       Property: no state change between CALL and post-CALL logic
     - Can self-destruct be triggered?
       Property: SELFDESTRUCT not reachable from external caller

  2. PATH EXPLORATION:
     - Enumerate all reachable states from public/external functions
     - Flag: paths that lead to token transfers without corresponding balance reduction
     - Flag: paths that modify storage slots controlling access (admin, owner, operator)
     - Flag: paths where return value of external call is not checked

  3. INVARIANT FUZZING (Halmos-specific):
     - For ERC-4626 vaults: assert(convertToAssets(totalSupply) <= totalAssets + 1)
     - For lending pools: assert(totalDebt <= totalDeposits)
     - For price oracles: assert(getPrice() > 0 && getPrice() < MAX_SANE_PRICE)
     - For access control: assert(!hasRole(attacker, ADMIN_ROLE))

  Timeout: 5 minutes per contract. If no violation found, move on.
  If violation found: escalate to F.5 (Exploit Construction).
```

#### F.4 — Targeted Fuzzing

**Tool:** Echidna (property-based) + custom harness generation.

```
For MEDIUM-RISK candidates (risk score 40-70 from F.2)
  OR when symbolic execution times out:

  1. HARNESS GENERATION (automated):
     - Extract ABI from bytecode
     - Generate Echidna test contract that:
       a. Deploys the target (or forks Sonic state at current block)
       b. Calls each public function with random/edge-case inputs
       c. Checks invariants after each call sequence

  2. FUZZING CAMPAIGNS:
     Campaign A — Balance drain:
       - Invariant: attacker ETH/token balance should not increase
       - Duration: 10,000 rounds

     Campaign B — Access escalation:
       - Invariant: non-admin should not gain admin role
       - Invariant: non-admin should not be able to call restricted functions
       - Duration: 5,000 rounds

     Campaign C — Reentrancy:
       - Deploy attacker contract with fallback that re-enters
       - Invariant: state should be consistent after reentrant call
       - Duration: 5,000 rounds

     Campaign D — Integer overflow/underflow:
       - Feed boundary values (0, 1, 2^255, 2^256-1, type(int256).min)
       - Invariant: no unexpected revert patterns
       - Duration: 3,000 rounds

     Campaign E — Flash loan attack simulation:
       - Borrow max from Balancer/Aave -> interact with target -> repay
       - Invariant: attacker profit should be 0 or negative
       - Duration: 5,000 rounds

  3. CORPUS SEEDING:
     - Seed fuzzer with known exploit transaction calldata:
       - Silo V2 exploit tx calldata (borrow-as-swap pattern)
       - Euler V1 exploit tx calldata (donate + self-liquidate)
       - Sonne Finance exploit tx calldata (empty market donation)
     - This biases the fuzzer toward known-vulnerable patterns

  Timeout: 30 minutes per contract total across all campaigns.
```

#### F.5 — Exploit Construction & Validation

```
When F.2, F.3, or F.4 produces a finding:

  1. CLASSIFY:
     - Fund drain (direct theft)? -> CRITICAL, immediate action
     - Price manipulation (oracle/vault share)? -> HIGH, construct liquidation play
     - Access control bypass? -> HIGH if admin can drain, MEDIUM otherwise
     - Griefing/DoS only? -> LOW, log and move on

  2. CONSTRUCT PROOF-OF-CONCEPT:
     - Fork Sonic at current block (anvil --fork-url)
     - Replay the violating input sequence
     - Measure: how much value can be extracted?
     - Measure: what capital is required (flash loan? funded?)
     - Measure: is the exploit atomic (single tx) or multi-step?

  3. VALIDATE ON FORK:
     - Full simulation including gas costs
     - Verify collateral/token exit path (same validation as Module E)
     - Compute net profit after all costs

  4. EXECUTE OR REPORT:
     - IF net profit > $100 AND atomic AND flash-loanable:
       -> Build production transaction
       -> Submit immediately (open mempool — speed is everything)

     - IF net profit > $1000 AND requires funded capital:
       -> Pre-flight collateral exit validation
       -> Capital allocation check
       -> Execute with MAX_CAPITAL_PER_EXECUTION cap

     - IF exploitable but unprofitable for us:
       -> Log finding
       -> Consider: does this create a liquidation opportunity on a protocol we monitor?
         (e.g., oracle manipulation on a new protocol could cascade to Euler V2 positions)
```

#### F.6 — Continuous Re-Analysis

```
For all previously analyzed contracts:

  On proxy upgrade (implementation change):
    -> Re-run full pipeline (F.2 through F.4) on new implementation
    -> Compare: did the upgrade introduce new attack surface?
    -> Compare: did the upgrade fix a previously flagged issue?

  On significant TVL increase (>$100K deposited):
    -> Re-prioritize: higher TVL = higher reward for same vulnerability
    -> Re-run F.3 symbolic execution if previously timed out (worth more compute now)

  On new market/vault referencing analyzed contract:
    -> Check: is the contract used as oracle? collateral? debt token?
    -> Assess cascade risk to our monitored protocols
```

#### F.7 — Toolchain

| Tool | Purpose | Installation | Notes |
|------|---------|-------------|-------|
| **Heimdall** | Bytecode decompilation, signature extraction | `cargo install heimdall-rs` | Fast, Rust-native |
| **Halmos** | Symbolic execution (Solidity) | `pip install halmos` | Foundry-integrated, best for Solidity |
| **Mythril** | Symbolic execution (bytecode) | `pip install mythril` | Fallback, works on raw bytecode |
| **Echidna** | Property-based fuzzing | `brew install echidna` or binary | Fastest fuzzer for EVM |
| **Slither** | Static analysis | `pip install slither-analyzer` | Only useful when source available |
| **4byte.directory** | Selector lookup | API: `https://www.4byte.directory/api/v1/signatures/` | Function name resolution |
| **anvil** | Local fork | Part of Foundry | Already installed |
| **cast** | RPC interaction | Part of Foundry | Already installed |

**Resource budget:** Max 2 CPU cores + 4GB RAM dedicated to analysis pipeline at runtime. Analysis should not degrade the execution bot's performance. During build phase, all available CPU/RAM is used by parallel sub-agents — the bot is not yet running.

### Module G — Reserved

*Module E covers execution. Module G reserved for future expansion (e.g., cross-protocol cascade detection).*

---

## 5. Single-Day Parallel Build Plan

All modules built simultaneously by Claude Code sub-agents. No sequential phases. Everything goes live at end of session.

### Phase 1 — Parallel Build (All Agents Simultaneous)

| Agent | Module | Deliverable | Dependencies |
|-------|--------|-------------|-------------|
| **Agent 1** | A: Oracle Degradation Hunter | `sentinel/oracleHunter.ts` — staleness tracker, DEX divergence comparator, phantom-healthy position detector, pre-staged tx builder | None (reads existing oracle configs) |
| **Agent 2** | B: Governance Shock Detector | `sentinel/govShock.ts` — per-block event poller for GovSetLTV/GovSetHookConfig/ConfigSet, LTV ramp simulator, same-block liquidation trigger | None (reads existing vault configs) |
| **Agent 3** | C: Position Kill List | `sentinel/killList.ts` — 4-tier position manager (Tier 0 every block through Tier 3 every 500 blocks), profit density ranking, collateral toxicity scoring | None (wraps existing adapters) |
| **Agent 4** | D: Misconfiguration Sniper | `sentinel/misconfigSniper.ts` — admin EOA/multisig scanner, approval honeypot graph, ERC-4626 donation surface checker | None (RPC reads only) |
| **Agent 5** | E: Execution Core Hardening | Enhance existing `collateralExitValidator.ts` + `swapRouteChecker.ts`, add toxicity blacklist enforcement, reduce sweeper to 30s | Existing codebase |
| **Agent 6** | F.1-F.2: Deploy Monitor + Static Analysis | `sentinel/deployMonitor.ts` — block scanner for contract creations, fund-handling classifier. `sentinel/staticAnalysis.ts` — bytecode decompiler integration (Heimdall), signature matching, call graph, approval graph, proxy detection, storage analysis | Agent 9 (toolchain) |
| **Agent 7** | F.3-F.4: Symbolic Exec + Fuzzing | `sentinel/symbolicExec.ts` — Halmos harness generator, property check templates, invariant suite. `sentinel/fuzzer.ts` — Echidna campaign orchestrator, corpus seeder (Silo V2/Euler V1/Sonne exploit calldata) | Agent 9 (toolchain) |
| **Agent 8** | F.5-F.6: Exploit Construction + Re-Analysis | `sentinel/exploitBuilder.ts` — fork PoC framework (anvil), profit calculator, execution decision engine. `sentinel/reAnalysis.ts` — proxy upgrade watcher, TVL-triggered re-scan, finding database | None |
| **Agent 9** | Toolchain Setup | Install Heimdall, Halmos, Echidna, Mythril, Slither. Verify all binaries. Configure PATH. Test each tool on a known contract. | None (runs first, fast) |
| **Agent 10** | Integration + E2E Test | `sentinel/index.ts` — unified entry point wiring all modules into single event loop. Deploy synthetic vulnerable contract on anvil fork, verify full pipeline: detection -> decompilation -> analysis -> PoC -> execution decision | All agents |

### Phase 2 — Integration (After All Agents Complete)

Agent 10 wires everything:

```
sentinel/
  index.ts              <- Main loop: block subscription, module dispatch
  oracleHunter.ts       <- Module A
  govShock.ts           <- Module B
  killList.ts           <- Module C
  misconfigSniper.ts    <- Module D
  deployMonitor.ts      <- Module F.1
  staticAnalysis.ts     <- Module F.2
  symbolicExec.ts       <- Module F.3
  fuzzer.ts             <- Module F.4
  exploitBuilder.ts     <- Module F.5
  reAnalysis.ts         <- Module F.6
  types.ts              <- Shared types
  config.ts             <- Sentinel-specific config (thresholds, blacklists, tool paths)
```

Execution core (Module E) is not a new file — it's enhancements to the existing adapter pipeline.

### Phase 3 — Activation

```
1. Run full E2E test on anvil fork with synthetic vulnerable contract
2. Verify: deployment detected -> classified as fund-handling -> decompiled ->
   flagged as vulnerable -> symbolic exec confirms -> PoC built -> profit calculated
3. Verify: governance event simulated -> positions identified -> tx pre-staged
4. Verify: oracle staleness simulated -> phantom-healthy detected -> tx ready
5. Add sentinel to PM2 ecosystem config
6. Start sentinel process
7. Verify first real block processed, first real contract scanned
```

**Goes live: same day. All modules operational.**

### Backfill (Runs After Go-Live)

Once live pipeline is running, backfill existing Sonic state:
- Scan ALL existing high-TVL Sonic contracts through F.2-F.4 pipeline (batch job)
- Build initial contract database (~500-1000 existing contracts)
- Run misconfiguration sniper on all known protocol admin addresses
- Populate kill list with current positions from all 4 protocols

### Dominance Metrics (Measured After 24h Live)

- Modules operational: 10/10
- New contracts classified per block: target 100% of fund-handling deploys
- Oracle divergence detection latency: <10 blocks behind tip
- Governance event detection latency: <1 block
- Kill list population: all Tier 0-3 positions across Euler V2, Silo V2, Aave V3, Morpho Blue
- First bytecode analysis finding: within 24h of go-live
- Zero toxic collateral losses: enforced by blacklist + toxicity scoring
- Execution pipeline tested end-to-end: synthetic contract on fork

---

## 6. Asymmetric Edge Design

### Chosen axes: **Structural awareness + Risk filtering + Bytecode intelligence.**

We will NOT compete on:
- **Latency** — no co-located nodes, no builder relationships. We accept 1-block disadvantage against infrastructure-heavy competitors.
- **Capital** — limited capital means we can't brute-force large funded liquidations.

We WILL compete on:

**1. Governance awareness (unique edge)**

No competitor we've observed monitors `GovSetLTV` on Sonic. Standard liquidation bots check `healthFactor < 1.0` every block. They don't check "what happens if LTV drops 5% in the next block due to governance action." We do. On a chain with zero timelock, this is a structural advantage.

**How we beat reactive liquidators:** They see HF < 1.0 after governance executes. We see the governance tx in the same block and submit liquidation atomically. 1-block advantage.

**2. Collateral toxicity filtering (learned edge)**

We lost $3,800 to learn that oracle price != exit price. No basic health-factor bot checks DEX liquidity before executing. They will make the same mistake we made — and we won't make it again.

**How we beat basic HF bots:** They execute every HF < 1.0 position. We skip the traps. Over time, they lose money on toxic collateral; we don't.

**3. Oracle pre-staging (speed edge)**

Standard bots: oracle updates -> HF recalculates -> detect HF < 1.0 -> simulate -> execute. That's 3-5 blocks.

Sentinel: oracle divergence detected -> phantom-healthy positions identified -> transactions pre-built -> oracle updates -> submit immediately. That's 1 block.

**How we beat oracle monitors without DEX comparison:** They wait for `checkLiquidation()` to return true. We predict it will return true before it does, and have the transaction ready.

**4. Bytecode intelligence (frontier edge)**

No Sonic searcher is running automated vulnerability analysis on new contract deployments. This is a zero-competition activity. Every new lending protocol, vault, or DeFi primitive deployed on Sonic gets decompiled, analyzed for known exploit patterns, and fuzzed within hours. If a vulnerability exists, we find it before anyone else knows the contract exists.

**How we beat everyone:** They discover vulnerabilities through Twitter, audit reports, or manual review. We discover them through automated analysis before the protocol even announces its launch. Detection-to-exploitation window: hours, not days.

**5. Pause/unpause monitoring (timing edge)**

Avalanche Euler V2 has 25 liquidatable positions blocked by vault pause. When that pause lifts, there's a stampede. We're already watching. Most bots gave up on paused vaults.

Same applies to Sonic: any future pause -> we track -> unpause -> we're first.

---

## 7. Failure Scenarios

| # | Failure Mode | Probability | Impact | Mitigation |
|---|-------------|-------------|--------|------------|
| 1 | **Faster bot appears** | HIGH | Revenue drops 50%+ | Accept partial loss. Our edge is structural awareness, not speed. If they're faster AND smarter, we lose. If they're only faster, we win on toxic avoidance and governance timing. |
| 2 | **Liquidity illusion** | MEDIUM | Capital locked in worthless collateral | Pre-flight collateral exit validation. DEX quote required before every execution. >25% oracle/DEX divergence = hard block. stkscUSD blacklist permanent. |
| 3 | **Oracle snapback** | MEDIUM | Pre-staged transactions become unprofitable | All pre-staged txs include profit check in the execution path. If position is no longer liquidatable at execution time, the on-chain call reverts harmlessly. Cost: gas only (<$0.01 on Sonic). |
| 4 | **Governance revert** | LOW | LTV reduction reversed before we execute | Target same-block execution. If governance reverts in next block, our tx already landed. If governance includes a ramp (rampDuration > 0), we have time to react. |
| 5 | **RPC desync** | MEDIUM | Stale state leads to failed txs or missed opportunities | Dual RPC: primary `RPC_URL_146` + fallback `rpc.soniclabs.com`. WebSocket for real-time events. Block number comparison between RPCs — if >2 blocks apart, switch to fresher. |
| 6 | **Flash loan unavailable** | LOW | Cannot execute atomic liquidations | Balancer vault is primary (317K wS). Fallback: funded liquidation with capital cap ($5K max). Morpho flash loan NOT viable on Sonic (~2 wS only). |
| 7 | **Toxic collateral lock** | MEDIUM (proven) | Capital trapped in unredeemable tokens | Permanent blacklist. Toxicity scoring. Never execute on tokens with >25% oracle/DEX divergence. Check `isPaused()` on all vault/queue contracts. Check `hookConfig()` for redeem pause. |
| 8 | **Gas spike / DoS** | LOW | Execution cost exceeds profit | Hard abort at 500 gwei. Sonic baseline is <10 gwei. If sustained spike, something systemic is happening — back off and observe. |
| 9 | **Contract upgrade breaks our executor** | LOW | Liquidator contract incompatible | Monitor `Upgraded` events on all protocol proxy contracts. If upgrade detected, halt execution on that protocol until manual review. |
| 10 | **Nonce collision between adapters** | LOW | Tx fails, opportunity missed | Already mitigated: `NonceManager` via `WalletManager` coordinates across Euler/Silo/Aave/Morpho adapters. |
| 11 | **False positive from analysis pipeline** | MEDIUM | Waste compute / pursue non-exploitable finding | 5-minute timeout on symbolic execution. Fork validation required before any execution. Net profit check mandatory. |
| 12 | **Analyzed contract is a honeypot** | LOW | Attacker deploys bait contract to trap exploit bots | Never send funded capital to unverified contracts. Flash-loan-only execution for new contract exploits. Simulate on fork FIRST. |

---

## 8. Extraction Discipline Framework

### Thresholds

```
MIN_NET_PROFIT_USD            = $1    (flash loan, zero capital risk)
MIN_NET_PROFIT_FUNDED_USD     = $50   (funded, capital at risk)
MIN_NET_PROFIT_NEW_CONTRACT   = $100  (new contract exploit, higher uncertainty)
MAX_CAPITAL_PER_EXECUTION     = $5,000 (funded liquidations)
MAX_CAPITAL_NEW_CONTRACT      = $1,000 (new contract exploits -- higher risk)
MAX_CAPITAL_TOTAL_DEPLOYED    = $10,000 (across all active positions)
GOVERNANCE_WAR_CHEST          = $500 USDC.e (always maintained)
MAX_GAS_BUDGET_PER_DAY        = $5 (failed tx gas)
MAX_ANALYSIS_COMPUTE_PER_DAY  = 4 CPU-hours (analysis pipeline budget)
```

### Toxic Collateral Blacklist Criteria

Add to permanent blacklist if ANY of:
- `oracle_price / dex_price > 3.0` sustained for >24 hours
- Withdrawal queue paused AND governance bricked (no way to unpause)
- Token backing ratio < 10% (stkscUSD pattern)
- Zero DEX liquidity (savUSD on Berachain pattern)
- Manually flagged after loss event

### Governance Action Confirmation

```
IF governance event detected:
  Wait 0 blocks (Sonic has no timelock -- instant execution)

  BUT: verify governance tx succeeded (check receipt status)
  AND: verify new parameters are as expected (re-read on-chain state)
  AND: verify position is actually liquidatable at new parameters

  ONLY THEN: submit liquidation
```

### New Contract Exploit Execution Rules

```
1. NEVER send funded capital to an unanalyzed contract
2. ALWAYS simulate on anvil fork before live execution
3. Flash-loan-only for first execution against any new contract
4. If exploit requires multi-step (non-atomic): MANUAL REVIEW REQUIRED
5. If exploit target has < $10K TVL: skip (not worth the risk/compute)
6. If exploit requires deploying a new contract: use CREATE2 with salt derived from block hash (unpredictable address)
7. Log ALL analysis findings regardless of exploitability -- builds pattern library
```

### Abort Conditions Mid-Block

```
ABORT if:
  - Gas price > 500 gwei
  - Nonce mismatch detected
  - RPC returns error or timeout (>5s)
  - Collateral token is on blacklist
  - DEX quote unavailable for collateral
  - Pre-flight simulation reverts
  - Profit estimate < MIN_NET_PROFIT after gas
  - Another liquidation tx for same position detected in mempool
  - Target contract bytecode changed since analysis (proxy upgraded mid-execution)
```

### Profit Extraction Cadence

```
- Auto-withdraw: every 30s (reduced from 120s)
- Auto-swap to USDC.e: enabled, 0.5% slippage max
- War chest maintenance: after each swap, ensure $500 USDC.e remains
- Manual skim: weekly, all accumulated profits to cold wallet
- Profit logging: every execution -> logs/liquidations.jsonl
- Daily summary: automated P&L report via Discord
```

### Emotional Execution Prevention

These rules are inviolable:
1. **Never increase MAX_CAPITAL_PER_EXECUTION after a win.** Winning creates overconfidence.
2. **Never execute on a blacklisted token "just this once."** The blacklist exists because of a $3,800 lesson.
3. **Never skip pre-flight validation for speed.** The 1-block delay is worth more than the $3,800 it saves.
4. **Never manually override the toxicity score.** If the score says BLOCK, it's BLOCKED.
5. **Never trust analysis output without fork validation.** Symbolic execution and fuzzing produce false positives.
6. **Never deploy exploit contracts without CREATE2 salt randomization.** Predictable addresses = frontrun targets.
7. **Review every failed execution within 24 hours.** Failures contain information. Extract it.

---

## Summary

Sentinel is five capabilities connected by one kill chain:

```
[New Contract Analysis] ----\
                              \
Governance/Oracle Event Detection --> Position Impact Simulation
                              /            |
[Bytecode Exploit Detection] /             v
                              Collateral Exit Validation
                                           |
                                           v
                                    Atomic Execution
```

The edge is not speed. The edge is knowing which positions to hit, which contracts are vulnerable, which collateral to avoid, and being ready before the trigger event occurs.

Sonic is structurally weak in governance hygiene (zero timelock), oracle tolerance (150x staleness buffers), DEX depth (liquidity cliffs), and audit culture (unverified contracts deploying daily). Sentinel exploits all four.

**Execution:** 10 parallel Claude Code sub-agents build all modules simultaneously. No phased rollout. No sequential dependencies between modules. Toolchain installed, code written, integration tested, and deployed in a single session. The 6-week human roadmap is compressed to one day because AI agents don't sleep, don't context-switch, and can write 10 modules in parallel.

**Go-live criteria:** All 10 modules operational. E2E test passes on synthetic vulnerable contract. First real Sonic block processed. First real contract bytecode analyzed. Kill list populated. Governance poller running. Oracle hunter active.

Target: >50% of Sonic Euler V2 + Silo V2 liquidation volume captured within first week of operation. Zero toxic collateral losses. First governance-triggered liquidation capture. First automated vulnerability discovery on a new Sonic contract. These four milestones define dominance.
