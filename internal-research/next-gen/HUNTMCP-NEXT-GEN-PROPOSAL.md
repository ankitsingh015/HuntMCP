# HUNTMCP-NEXT-GEN-PROPOSAL.md — Deep Research & Architecture Discovery

> Status: **research/design artifact only.** No implementation, no production-code changes, no
> benchmark/ground-truth changes, no commits. This document proposes a long-term roadmap; it does **not**
> authorize starting any of it. Sequencing here is by *dependency, leverage, and scientific measurability*,
> not by speed (there is no delivery deadline).
>
> Canonical spec chain this extends: [XYZ.md](XYZ.md) → [PHASE1-PLAN.md](PHASE1-PLAN.md) →
> [PHASE1-EXECUTION-PLAN.md](PHASE1-EXECUTION-PLAN.md) → [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md).
> The fixed thesis is **unchanged**: HuntMCP is a *proof / causal-validation engine (CEM)*, not a
> discovery-throughput engine. Discovery breadth is table stakes we match; CEM is the axis we win on.

---

## 1. Executive Summary

HuntMCP is already an unusually mature autonomous-hunting system: a Level-1 orchestrator (HuntBrain) driving
Level-2 specialists over 131 MCP tools, with strong safety substrate (scope/budget/dedupe/work-registry/audit/
redact/content-scanner), a structured case store with evidence-gated confirmation, and a Phase-1
Counterfactual-Evidence-Minimization (CEM) engine in progress that is the genuine research differentiator.

The highest-leverage next-generation improvements are **not** more optimizations of the kind already done
(per-agent MCP scoping, static model routing). They fall into six themes, in dependency order:

1. **Substrate / measurement (P0):** HuntMCP cannot currently answer "did this tool call earn its cost?"
   because it records `duration_ms` but no token/HTTP/cost figure and never links spend to finding yield.
   A cost/yield/information telemetry layer plus a standing ground-truth benchmark range are the prerequisites
   for *every* later capability or efficiency claim to be provable. This is exactly the "measure early, decide
   late" posture [INTELLIGENCE-ALLOCATION-MEMO.md §11–12](INTELLIGENCE-ALLOCATION-MEMO.md) already demands.

2. **Architecture / context (Pareto):** Agents currently hand results back to HuntBrain as prose, forcing
   manual summarization and re-derivation. Promoting the case store to the inter-agent *state bus* (structured
   records + IDs, raw persisted to disk and recoverable) is a Pareto move — context ↓, tokens ↓, duplicate
   work ↓ — with neutral-to-positive capability.

3. **Validation moat (the CEM axis, where humans still beat agents):** the literature is consistent that
   autonomous agents win on breadth but humans still win on **business-logic / authorization** and
   **audit-grade attestation**. A stateful, workflow-aware access-control differential engine and autonomous
   CEM-condition extraction deepen precisely that moat.

4. **Discovery / chaining gap (table stakes):** chaining today is 15 hardcoded templates matched by vuln
   class — not a search over attack state. An attack-state graph with a best-first/MCTS planner, spec-driven
   surface expansion, and CEM-byproduct variant discovery close the gap to XBOW-class breadth.

5. **Learning / knowledge:** three disjoint stores (ChromaDB RAG, SQLite memory, freeform-markdown lessons)
   that are never fed back into experiment prioritization. A unified, structured, poison-resistant knowledge
   layer plus a CEM causal-signature store is the substrate for continuous learning.

6. **Efficiency (measurement-gated, last):** information-gain experiment scheduling, directed scan
   prioritization, and adaptive intelligence allocation — all admissible **only** on the Pareto frontier that
   satisfies a hard security-quality floor, and all gated on the P0 telemetry + benchmark substrate.

**Guiding constraint (hard):** an optimization is a *failed* optimization if it causes any regression in
high/critical discovery, coverage, validation depth, exploitability reasoning, attack-chain discovery,
evidence quality, or false-positive resistance — regardless of token/cost savings.

---

## 2. Current HuntMCP Capability Baseline

### 2.1 Orchestration
- **HuntBrain (L1, `mode: primary`)** runs a fixed phase loop: init/scope → recon → scan → chain-planning →
  exploit/validate → report → learn. It cannot itself use bash (OpenCode strips it from primary orchestrators)
  and delegates all target-touching work.
- **Permanent L2 specialists:** recon-agent, scan-agent, exploit-agent, chain-planner, report-agent — one
  markdown file each with a locked-down `tools:` MCP allowlist and permission block.
- **Dynamic specialists** are spawned on demand as new `.opencode/agents/*.md` with required tool scoping.
- **Handoff is prose:** specialists return structured *markdown* to HuntBrain; HuntBrain is instructed to
  manually summarize large recon/scan output and to persist state to `memory-mcp`/`case-mcp` because a context
  compaction can drop conversation history mid-hunt.

### 2.2 Tooling (131 MCP tools; global-off + per-agent allowlist)
- Recon: subfinder, httpx, katana, nmap, secrets (gitleaks), osint (Shodan/VT/Censys/SecurityTrails),
  github-security, burp-import, browser.
- Scan: nuclei, sqlmap, dalfox, ffuf, waf-bypass, playwright.
- Exploit/validate: chainer, oob (interactsh), second-opinion (cross-model), browser/obscura (headless-Chromium
  execution proof), idor (two-account sweep), aws/azure/gcp-postexploit, local-privesc, ad-recon, optional burp.
- Knowledge: writeup (ChromaDB RAG + CVE fetch + disclosed-report citation), memory (SQLite per-target), lessons
  (markdown per-vuln-class).
- Meta/state: case-mcp (+ CEM tools), hackerone, target-discovery, watch.
- Shared modules: tool_resolver, scope_guard, budget_guard, engagement_paths, audit_log, work_registry,
  dedupe_check, job_runtime, content_scanner, tool_gaps, model_gateway, redact, http_probe, session_context,
  stuck_detector, cem_engine, case_store.

### 2.3 State & validation
- **`case_store.py`:** hypotheses → evidence → findings → experiments → root_causes, one SQLite DB per
  engagement. **Content-addressed evidence** (SHA-256), **evidence-gated confirmation**
  (`update_finding_status` refuses CONFIRMED/IMPACT_PROVEN with zero evidence rows), signal-based confidence
  scoring, and `check_experiment_exists` to stop repeated tests.
- **`suggest_next_action` is a deliberately trivial heuristic** ("finish what's in flight"). Its own docstring
  states it is *not* the expected-value/information-gain formula because there is *no instrumentation for
  request cost, novelty, or measured information gain* — upgrading it is explicitly deferred until real
  cost/gain data exists.

### 2.4 CEM (Phase 1, in progress in this worktree — ~1115 lines)
`cem_engine.py` implements: `SuccessSignature` + `evaluate_signature`, a **determinism/stability gate**,
one-variable-at-a-time counterfactual `classify` (necessary / apparently_not_necessary / interacting /
inconclusive) + `classify_race` (probabilistic), `minimal_condition_sets` (delta-debugging), alternate-set and
AND-necessity discovery, `minimize_poc`, recursive redaction, and `assemble_bundle` (the Triager-Proof Bundle).
Conditions are **supplied explicitly** in Phase 1; autonomous extraction is deferred.

### 2.5 Chaining
`chainer-mcp` = **15 static `CHAIN_TEMPLATES`** (`idor_xss_ato`, `ssrf_cloud_creds`, `fileupload_lfi_rce`, …)
matched to detected vuln classes via `analyze_chains`. This is rule-based template matching — there is no
representation of the actual reachable attack surface as a searchable state space.

### 2.6 Learning / memory
Three **disjoint** stores: writeup RAG (cross-target technique knowledge), memory-mcp (per-target hunt
history), lessons-mcp (freeform markdown, keyword-searchable, ~400-line cap). None feed back into
prioritization; lessons are prose, not structured signals. `tool_gaps.py` captures global tool gaps but does
not author anything.

### 2.7 Safety & efficiency substrate
scope_guard (per-target isolation + one-target-per-chat), budget_guard (500-call circuit breaker, 70/85/95%
bands), dedupe_check, work_registry (duplicate-spawn), audit_log (per-call JSON: tool, redacted args,
returncode, `duration_ms`, block), redact, content_scanner (OWASP Skill/MCP Top-10 scan), stuck_detector
(repeated-tool-call detection), model_gateway (static per-role provider selection via env).

---

## 3. Existing Context / Token / Cost Architecture

Measured baseline (recorded, reproducible from the earlier study):

- OpenCode 1.18.29; provider opencode-go/deepseek-v4-flash.
- No-MCP baseline ≈ 8,616 tokens; full HuntMCP controlled baseline ≈ 46,129 tokens.
- 131 MCP tools; MCP schema contribution ≈ 25,600 tokens; ≈ 195 tokens/tool.
- Real HuntBrain unscoped ≈ 47,016; scoped ≈ 29,192; final scoped ≈ 29.5K.
- Reduction ≈ 36–38% from **global MCP-off + per-agent MCP allowlists** (already shipped).
- Continued-turn cache-read ≈ 99.6%.

**Interpretation.** The tool-schema lever has largely been pulled. The remaining context/token opportunities
are in the **conversational hot path**, not the schema: raw recon/scan dumps carried as prose, re-derivation of
state after compaction, and prose hand-offs between agents. Crucially, **token count is the wrong sole
objective** — the memo's constrained-optimization frame (`max yield/cost s.t. quality ≥ floor`, where cost
includes tokens + HTTP + wall-clock) is adopted here. We cannot even compute that objective today because HTTP/
wall-clock/cost-per-finding is not instrumented. Hence P0 telemetry is the true first move.

---

## 4. Research Findings (three loops)

### Loop 1 — Security capability
- **The durable human advantage is business-logic / authorization and audit-grade attestation**, per the
  [LLM-pentest survey](https://arxiv.org/html/2607.02605v1) and [CyberScoop on XBOW](https://cyberscoop.com/is-xbows-success-the-beginning-of-the-end-of-human-led-bug-hunting-not-yet/).
  HuntMCP's CEM thesis targets exactly the attestation half; the authz half is under-served by the current
  single-request IDOR sweep.
- **Automated BOLA/IDOR is now spec-driven, multi-identity, and stateful-workflow-aware** with a
  ground-truth-fetch oracle: [AuthProbe](https://arxiv.org/html/2607.20574v1), [BACFuzz](https://arxiv.org/pdf/2507.15984),
  and stateful REST fuzzers (RESTler, fuzz-lightyear). The key insight HuntMCP's sweep misses: *authorization
  decided in step 1, state carried into step 2 by an unrevalidated identifier.*
- **XBOW = coordinator → parallel solvers → independent multi-stage validators** ([XBOW writeup](https://xbow.com/blog/top-1-how-xbow-did-it)):
  breadth from parallelism, trust from independent execution proof. HuntBrain is sequential/phase-driven.

### Loop 2 — System / architecture
- **2026 agent memory is a first-class subsystem**: dual store (vector + knowledge graph), a write/manage/read
  loop, layered working/episodic/semantic memory ([memory survey](https://arxiv.org/html/2603.07670v1),
  [structured belief state](https://arxiv.org/pdf/2605.11325)).
- **Context principle: "raw > compaction > summarization"** — strip only what is recoverable from the
  environment; operate on whole tool-call/response units ([context engineering](https://tianpan.co/blog/2026/02/26/context-engineering-memory-compaction-tool-clearing),
  [ACON](https://arxiv.org/pdf/2510.00615)). Directly supports "persist raw to disk, carry the distilled view."
- **[Decision-Aware Memory Cards](https://arxiv.org/pdf/2606.08151)** — counterfactual-inspired context
  selection for tool-using agents — is a striking parallel to CEM: select context by what changes the decision.

### Loop 3 — Cross-domain
- **Attack-path planning is a solved pattern to adopt, not invent**: MDP + MCTS attack-path generation
  ([ShotFlex](https://sands.edpsciences.org/articles/sands/full_html/2025/01/sands20250003/sands20250003.html)),
  LLM + classical planning ([2512.11143](https://arxiv.org/pdf/2512.11143)), MITRE-ATT&CK-constrained task
  trees (VulnBot). Best-first/MCTS over an explicit attack-state graph is a clean fit for chaining.
- **Bayesian experimental design / information gain** ([BED](https://arxiv.org/pdf/2302.14545)) and
  **Bayesian-guided directed fuzzing** ([PLDI/OOPSLA 2025](https://dl.acm.org/doi/10.1145/3776659)) map directly
  onto "which experiment / which endpoint next" — the exact gap `suggest_next_action` acknowledges.
- **Adaptive reasoning-effort / test-time compute** ([Ares](https://arxiv.org/pdf/2603.07915),
  [Learning When to Think](https://arxiv.org/abs/2608.20256)) is maturing and complements model routing — but
  overlaps the memo's Phase-5 analysis and must be measurement-gated.
- ⚠️ **Cross-domain risk:** any knowledge graph fed target-derived text is a **GraphRAG-poisoning** surface
  ([GragPoison ~98% success](https://arxiv.org/html/2508.04276)); existing defenses are shown inadequate. This
  constrains all graph/knowledge candidates (see §13, §15).

---

## 5. Candidate Innovations

Sixteen candidates, grouped by theme. IDs are stable references for the scorecard (§10) and roadmap (§16).
Each names the existing component it extends and an honest novelty classification.

### Substrate / measurement (P0)
- **P0-TEL — Cost/yield/information telemetry.** Extend `audit_log.py` + `budget_guard.py` to record tokens,
  HTTP request count, wall-clock, and a link from each experiment/tool call to the finding it advanced; derive
  yield-per-cost metrics. *Established; the memo's own prerequisite.*
- **P0-BENCH — Standing ground-truth benchmark range.** Extend the CEM constructed testbed (Juice Shop / crAPI /
  VAmPI / PortSwigger-style planted vulns) into a multi-class range with a *frontier-heavy reference arm*, so
  every later change is A/B-measurable against a quality floor. *Established practice; the measurability
  backbone the user prioritized.*

### Architecture / context (Pareto)
- **ARCH-STATE — Case store as the inter-agent state bus.** Specialists write structured records to `case-mcp`
  and return IDs + a compact digest; HuntBrain reads case.db views instead of re-reading prose. Raw output
  persists to disk (recoverable), not the context window. *Uncommon adaptation of memory-card / structured-
  belief-state ideas.*
- **ARCH-DISTILL — Tool-result distillation at the MCP boundary.** recon/scan servers return schema'd findings;
  full raw output goes to the engagement's disk dir (already the pattern for downloads/jobs), referenced by
  path. *Established context-compression; new application at the MCP seam.*
- **ARCH-PAR — Parallel-solver orchestration option.** An opt-in HuntBrain mode that fans out independent
  per-endpoint/per-class solvers under existing work_registry + budget guards, mirroring XBOW's coordinator/
  solver split. *Established (XBOW/VulnBot); roadmap Phase 2.*

### Validation moat (CEM axis)
- **VAL-AUTHZ — Stateful, workflow-aware authorization differential engine.** Extend `idor-mcp` from single-
  request two-account replay to: an identity × role × object matrix, *multi-step workflow* replay (authz in
  step 1, state in step 2), and an AuthProbe-style ground-truth-fetch oracle; emit findings straight into
  case-mcp with candidate CEM conditions. *Existing technique, materially stronger application; targets the
  human-advantage class.*
- **VAL-COND — Autonomous CEM condition extraction.** Derive candidate perturbable conditions from the
  `audit_log`/case experiment trace instead of requiring them supplied by hand (XYZ.md §2.1 defers this).
  Preserves the Phase-1 human-supplied default as fallback. *Differentiated combination; the autonomy step for
  the moat.*
- **VAL-DIFF — Structural differentiation evidence.** Compare a finding's minimal condition set(s) to
  `disclosed_reports.py` documented conditions and emit a bounded, labeled differentiation argument
  (XYZ.md §2.6, Phase 3+). *Already specified; included for completeness.*

### Discovery / chaining gap
- **DISC-GRAPH — Attack-state graph + best-first/MCTS planner.** Replace static templates with an explicit
  graph of capabilities/state/edges (each edge citing a real `audit_log` id — the anti-hallucination invariant
  from XYZ.md §3), searched by best-first/MCTS for chains and multi-step paths; CEM minimal-set signatures act
  as search heuristics. Extend `chainer-mcp` (XYZ.md Phase 5 says extend, not new server). *Differentiated
  combination (planner + CEM-signature heuristics).*
- **DISC-SPEC — Spec-driven surface expansion.** Parse OpenAPI/GraphQL schemas and JS-mined route literals into
  a stateful endpoint/parameter model (RESTler analogy) feeding scan + VAL-AUTHZ. Extend recon/scan +
  `endpoint_template.py`. *Established; new integration.*
- **DISC-VARIANT — Counterfactual variant discovery.** Turn CEM's incidental "capability survives under a
  different value/state" observation (XYZ.md §2.7, Phase 4) into active neighboring-param/endpoint probing.
  Extend `cem_engine` + a variant-probe executor. *Genuinely underexplored per XYZ.md §1.3.*

### Learning / knowledge
- **LEARN-KG — Unified, poison-resistant knowledge layer.** A structured write/manage/read layer over the
  three stores (optionally a knowledge graph) with a hard invariant: **target-derived text can never write an
  authoritative edge** (mirrors XYZ.md §3's audit_log-citation rule; directly answers the GraphRAG-poisoning
  risk). Feeds EFF-SCHED/EFF-SCAN/DISC-GRAPH. *Established substrate; the safety framing is the differentiator.*
- **LEARN-SIG — CEM causal-signature store & reuse.** Persist CEM signatures (minimal condition families,
  apparently-not-necessary conditions, determinism status) and reuse them as *re-confirmed hints* on
  structurally similar future findings (never as skips; never reuse nondeterministic signatures). This is the
  memo's defensible research bet (question C). *Domain instantiation of skill-reuse/amortization; research-
  worthy, not clean novelty.*

### Efficiency (measurement-gated, last)
- **EFF-SCHED — Information-gain / value-of-computation experiment scheduler.** Upgrade
  `case_store.suggest_next_action` from heuristic to a VOC/BED scorer once P0-TEL supplies real cost/gain data.
  *Established theory (Russell–Wefald VOC, BED); the exact upgrade the docstring anticipates.*
- **EFF-SCAN — Directed scan prioritization.** Prioritize endpoints/parameters by likelihood-of-bug (directed-
  greybox-fuzzing analogy) instead of exhaustive per-phase scanning — under a **hard per-class coverage floor**.
  *Established; coverage-risk gated.*
- **EFF-ALLOC — Adaptive intelligence allocation.** Model routing + reasoning-effort selection + the CEM
  aleatoric/epistemic determinism signal, exactly as analyzed in
  [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md). *Largely prior art; included so the
  roadmap is complete, credited to the existing memo, gated on P0-TEL + LEARN-SIG.*

---

## 6. Prior-Art Analysis

| Candidate | Closest known work | Honest classification |
|---|---|---|
| P0-TEL | FrugalGPT cost accounting; standard agent observability | **Already established** — engineering, not novelty |
| P0-BENCH | CyberGym / ExploitGym / crAPI / VAmPI; the memo's A/B/C/D design | **Already established** methodology |
| ARCH-STATE | Structured belief state; Decision-Aware Memory Cards; blackboard architectures | **Uncommon adaptation** for a security agent |
| ARCH-DISTILL | ACON, semantic context compression | **Established technique, new application** at the MCP seam |
| ARCH-PAR | XBOW coordinator/solver; VulnBot task-graph; HPTSA | **Already established** in the field (we'd be matching, not leading) |
| VAL-AUTHZ | AuthProbe, BACFuzz, RESTler, fuzz-lightyear | **Existing technique, stronger application** (multi-step + CEM feed) |
| VAL-COND | Delta-debugging condition spaces; program-slicing feature extraction | **Differentiated combination** (trace → CEM conditions) |
| VAL-DIFF | Disclosed-report diffing (no formal prior art for the exact bounded claim) | **Uncommon; explicitly bounded** (XYZ.md §2.6) |
| DISC-GRAPH | ShotFlex (MCTS), LLM+classical planning, attack graphs | **Differentiated combination** (planner + CEM-signature heuristics + evidence-cited edges) |
| DISC-SPEC | RESTler, restler-fuzzer, Schemathesis | **Already established**; integration value only |
| DISC-VARIANT | Metamorphic testing; CEM byproduct (XYZ.md §1.3) | **Genuinely underexplored** as a necessity-testing byproduct |
| LEARN-KG | Cognee/mem0/GraphRAG; GragPoison (the threat) | Store is established; **poison-resistant, evidence-cited edges are the differentiated part** |
| LEARN-SIG | Skill-reuse-as-compression; computation amortization | **Research-worthy, unclear** — the memo's question C; do not overclaim |
| EFF-SCHED | Russell–Wefald VOC; Bayesian experimental design | **Established theory**, new domain fit |
| EFF-SCAN | Directed greybox fuzzing; Bayesian program analysis | **Established** |
| EFF-ALLOC | RouteLLM, FrugalGPT, Ares, Learning-When-to-Think | **Largely prior art** (per the memo) |

**Verdict.** The defensible research contributions are the *combinations*, not the components:
CEM + variant discovery (DISC-VARIANT), CEM-signature-guided planning (DISC-GRAPH), CEM-signature amortization
(LEARN-SIG), and evidence-cited/poison-resistant knowledge (LEARN-KG). Everything else is competent
engineering of established techniques — valuable, but not to be sold as novel.

---

## 7. Library / Dependency Opportunities

Posture chosen: **selective best-of-breed** — add a dependency only where it genuinely unlocks capability, each
justified, `content_scanner`-checked, and preferably prototyped hand-rolled first to confirm the stdlib version
is the bottleneck.

| Library | Unlocks | For | Cost / risk | Verdict |
|---|---|---|---|---|
| **networkx** (pure-Python) | Graph storage + pathfinding/centrality | DISC-GRAPH, LEARN-KG | Low (pure Python, mature); XYZ.md already names it as the deferred graph lib | **Strong candidate** when DISC-GRAPH is pursued; start with SQLite adjacency + hand-rolled best-first, promote to networkx if algorithms get complex |
| **pydantic** (already implied for CEM) | Typed condition/verdict/finding schemas | ARCH-STATE, VAL-*, P0-TEL | Minimal; XYZ.md already budgets it | **Adopt** |
| **A PDDL planner** (e.g. `pyperplan`/`unified-planning`) | Classical-planning attack paths | DISC-GRAPH | Medium; encoding attack state as PDDL is real work; may be overkill vs best-first/MCTS | **Prototype-gate**: only if best-first/MCTS proves insufficient |
| **scikit-learn / small Bayesian libs** | Surrogate models for likelihood-of-bug, info-gain | EFF-SCHED, EFF-SCAN | Medium footprint; risk of "confidence theater" without real data | **Defer** until P0-TEL yields enough labeled data; start with simple closed-form info-gain |
| **A schema parser** (`openapi-core`, `graphql-core`) | Spec-driven surface | DISC-SPEC | Low-medium | **Adopt** when DISC-SPEC is pursued |
| Heavy ML / embeddings-for-graph / RL frameworks | — | — | High maintenance, opaque, poisoning-prone | **Reject** — the memo's "no heavy ML" line holds; RL attack-path work (ShotFlex) needs training infra HuntMCP shouldn't own |

**Principle:** no dependency is added to Phase-1 CEM (stdlib + pydantic only, per XYZ.md §4). Dependencies enter
only in the later, separately-gated phases and never on the CEM hot path.

---

## 8. Context / Token / Cost Opportunities

Ranked by leverage, all subordinate to the quality floor:

1. **ARCH-STATE + ARCH-DISTILL** — the biggest hot-path win. Prose hand-offs and raw dumps are the dominant
   remaining context cost (schema cost is already minimized). Persist raw to disk; carry structured digests +
   IDs. Expected: material context/token reduction with neutral-or-positive capability (less re-derivation
   after compaction). *Pareto.*
2. **EFF-SCHED** — fewer wasted experiments → fewer tool calls and tokens per validated finding. *Gated on
   P0-TEL; must respect coverage floor.*
3. **EFF-SCAN** — fewer scan calls for equal coverage. *Highest coverage risk; hard per-class floor required.*
4. **EFF-ALLOC** — token/cost routing. *Lowest priority, most prior-art, most measurement-gated; per the memo.*

**Anti-goal reminder:** token count alone is never the objective. P0-TEL exists precisely so we optimize
`yield/total-cost` (tokens + HTTP + wall-clock) subject to the floor, not tokens in isolation.

---

## 9. Security-Capability Opportunities

Ranked by expected capability gain, cost ignored (Loop-1 posture):

1. **VAL-AUTHZ** — directly attacks the class where humans still beat agents (authorization / business logic).
   Highest expected *new* finding capability.
2. **DISC-GRAPH** — real multi-step chain/path discovery vs 15 static templates; turns individually-low bugs
   into critical chains a template never encoded.
3. **DISC-VARIANT** — free higher-severity variants as a byproduct of necessity testing; unique to the CEM
   design.
4. **VAL-COND** — autonomy for the moat (conditions discovered, not hand-fed) without weakening the Phase-1
   trust gates.
5. **DISC-SPEC** — surfaces shadow/zombie endpoints and parameters the crawl misses.
6. **ARCH-PAR** — breadth via parallel solvers (table stakes).
7. **LEARN-SIG / LEARN-KG** — compounding capability over time (learning across engagements).

---

## 10. Multi-Dimensional Scorecard

Qualitative HIGH / MED / LOW. "Cap" = finding capability, "Cov" = coverage, "Val" = validation quality,
"Chain" = attack-chain capability, "FP-res" = false-positive resistance, "Ev" = evidence quality,
"Ctx" = context efficiency gain, "Tok" = token efficiency gain, "Tool" = tool-call efficiency gain,
"Cmplx" = implementation complexity (HIGH = harder), "Safety" = safety risk (HIGH = riskier),
"Novel" = novelty/differentiation.

| ID | Cap | Cov | Val | Chain | FP-res | Ev | Ctx | Tok | Tool | Latency | Reliab | Cmplx | Safety | Novel |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P0-TEL | — | — | MED | — | MED | MED | LOW | LOW | LOW | — | HIGH | LOW | LOW | LOW |
| P0-BENCH | — | HIGH | HIGH | MED | HIGH | MED | — | — | — | — | HIGH | MED | LOW | LOW |
| ARCH-STATE | LOW | LOW | MED | LOW | MED | MED | HIGH | HIGH | MED | MED | HIGH | MED | LOW | MED |
| ARCH-DISTILL | — | — | LOW | — | LOW | MED | HIGH | HIGH | LOW | MED | MED | MED | MED | LOW |
| ARCH-PAR | MED | HIGH | — | MED | — | — | LOW | LOW | LOW | HIGH | MED | HIGH | MED | LOW |
| VAL-AUTHZ | HIGH | HIGH | HIGH | MED | MED | HIGH | — | — | LOW | MED | MED | MED-HIGH | MED | MED |
| VAL-COND | MED | MED | HIGH | MED | MED | HIGH | LOW | LOW | MED | — | MED | MED | MED | MED |
| VAL-DIFF | LOW | — | MED | — | HIGH | HIGH | — | — | — | — | MED | LOW | LOW | MED |
| DISC-GRAPH | HIGH | MED | MED | HIGH | MED | MED | MED | LOW | MED | MED | MED | HIGH | MED | HIGH |
| DISC-SPEC | MED | HIGH | LOW | MED | LOW | LOW | LOW | LOW | MED | LOW | MED | MED | MED | LOW |
| DISC-VARIANT | HIGH | MED | MED | MED | MED | MED | — | — | LOW | — | MED | MED | MED | HIGH |
| LEARN-KG | MED | MED | MED | MED | MED | MED | MED | MED | MED | — | MED | HIGH | HIGH | MED |
| LEARN-SIG | MED | MED | HIGH | MED | HIGH | MED | MED | MED | HIGH | MED | MED | HIGH | MED | HIGH |
| EFF-SCHED | LOW | MED | MED | MED | MED | — | MED | MED | HIGH | MED | MED | MED | MED | MED |
| EFF-SCAN | — | risk↓ | — | — | LOW | — | MED | MED | HIGH | HIGH | MED | HIGH | HIGH | LOW |
| EFF-ALLOC | — | — | — | — | — | — | MED | HIGH | MED | HIGH | MED | HIGH | MED | LOW |

**Reading the scorecard.**
- **Best safety-value-per-risk:** P0-TEL, P0-BENCH, ARCH-STATE — low risk, high enabling leverage.
- **Best capability-per-risk:** VAL-AUTHZ, DISC-VARIANT — high capability at moderate complexity/risk.
- **Highest capability but highest complexity:** DISC-GRAPH, LEARN-SIG — the research bets; sequence after the
  substrate proves them measurable.
- **Highest safety risk:** EFF-SCAN (coverage floor) and LEARN-KG (poisoning) — hard-gated, never merged
  without the corresponding guard proven.

`SECURITY VALUE / RESOURCE COST` favors, in order: P0-TEL → ARCH-STATE → VAL-AUTHZ → DISC-VARIANT → the rest.

---

## 11. Selected Innovations

Because the chosen direction is "all four, sequenced by dependency/leverage/measurability," none are cut — but
they are **tiered by readiness and dependency**, not merged. The measurement substrate and Pareto architecture
lead; the capability bets follow once measurable; efficiency is gated last.

- **Tier A (enabling, low-risk):** P0-TEL, P0-BENCH, ARCH-STATE, ARCH-DISTILL.
- **Tier B (moat capability):** VAL-AUTHZ, VAL-COND, VAL-DIFF, DISC-VARIANT.
- **Tier C (breadth / chaining):** DISC-SPEC, DISC-GRAPH, ARCH-PAR.
- **Tier D (learning):** LEARN-KG, LEARN-SIG.
- **Tier E (efficiency, gated on A + floors):** EFF-SCHED, EFF-SCAN, EFF-ALLOC.

**Explicitly excluded (this proposal will not pursue):** heavy ML / RL attack-path training; any new MCP server
where an extension suffices; any change to Phase-1 CEM methodology; any efficiency change not gated on P0-TEL +
a proven quality floor.

---

## 12. Proposed Architecture

Layered, extension-first (mirrors XYZ.md §4 "extend, don't multiply"):

```
                         ┌───────────────────────────────────────────────┐
   HuntBrain (L1)  ──────│  reads STRUCTURED case/graph views, not prose  │
        │                └───────────────────────────────────────────────┘
        │ spawns (sequential today; ARCH-PAR adds opt-in parallel solvers)
        ▼
   L2 specialists (recon / scan / exploit / chain-planner / report / dynamic)
        │  write structured records + IDs  ▲  read prioritized next-action
        ▼                                  │
   ┌──────────────────────── case-mcp (state bus) ─────────────────────────┐
   │  case_store  ·  cem_engine  ·  [NEW] attack-state graph (DISC-GRAPH)   │
   │  [NEW] experiment scheduler (EFF-SCHED)  ·  [NEW] signature store      │
   └───────────────────────────────────────────────────────────────────────┘
        │ every edge/record cites a real audit_log id  (anti-hallucination invariant)
        ▼
   Shared substrate:  audit_log(+cost/yield P0-TEL) · budget/scope/dedupe/work guards
                      · tool_resolver · redact · content_scanner
        ▼
   Executors: existing MCP tool servers (recon/scan/exploit) + VAL-AUTHZ (extends idor-mcp)
              + DISC-SPEC surface model
        ▼
   Knowledge:  writeup RAG + memory + lessons  ──unify──▶  [NEW] LEARN-KG (poison-resistant)
                                                           + LEARN-SIG (CEM signatures)
        ▼
   [NEW, last] EFF-ALLOC policy  ──abstract tier──▶  model_gateway (unchanged plumbing)
```

**Invariants preserved everywhere:** scope gate on every target-touching call; budget circuit-breaker;
evidence-gated confirmation; audit-cited edges (no edge/observation without a real `audit_log` id — extends
XYZ.md §3 to the whole graph/knowledge layer); redact on all persisted args; CEM stays post-validation and off
the hot path; policy/plumbing separation for EFF-ALLOC (abstract tier in, model id out — per the memo §8).

**Key structural change:** the **case store becomes the shared state bus and the graph substrate**, so
capability (planner, scheduler, signatures) and context-efficiency (structured handoff) are the *same*
architectural move viewed from two angles — this is the leverage point.

---

## 13. Capability-Preservation Strategy

The non-negotiable: **no security-capability regression.** Mechanisms:

1. **Frontier-heavy reference arm (P0-BENCH).** Every candidate is A/B'd against a fixed baseline arm on the
   ground-truth range. The comparison is the memo's quality vector: valid/unique/high-critical findings,
   exploit success, independent-validation success, false-positive rate, coverage, attack-path depth,
   chain discovery, variant discovery.
2. **Hard-fail policy (from the memo §7).** Missing any high/critical finding the baseline found, or exceeding
   baseline FP rate, **rejects** the change regardless of cost savings. Medium/low/coverage/depth deltas are
   scored on the Pareto frontier, reported explicitly, never hidden in an aggregate.
3. **Per-class coverage floor.** EFF-SCAN and EFF-SCHED must not bias toward easy classes; coverage is a hard
   constraint per vuln class, reported per-class.
4. **Hints, never skips.** LEARN-SIG signatures and EFF-SCHED priorities lower/raise ordering but never
   hard-block a not-yet-confirmed novel angle; suppressed experiments are audited.
5. **Determinism gate stays authoritative.** Nondeterministic CEM signatures are non-cacheable (never reused as
   shortcuts); the aleatoric/epistemic split (EFF-ALLOC) uses the determinism signal, never overrides it.
6. **Poison resistance (LEARN-KG).** Target-derived text can never write an authoritative edge; authoritative
   edges require an `audit_log`-cited executed observation. Knowledge-graph reads are treated as untrusted data,
   consistent with the repo's prompt-injection rules.
7. **Human-in-loop on state-changing perturbations** (VAL-AUTHZ multi-step, DISC-VARIANT) — default to
   idempotent/read-shaped tests; non-idempotent perturbation requires per-finding human exception (UD-4 ruling).

---

## 14. Benchmark Design

- **Track 1 — Constructed ground-truth range (P0-BENCH).** Planted vulns with known structure across classes:
  authz/IDOR (single- and multi-step), SSRF, injection, chains (≥2 independent paths), interaction-only
  conditions, and nondeterminism red herrings (cache/throttle + a genuine race). Blind manifest + evaluator-
  only answer key (the Phase-1 CEM harness already established this split — reuse it, do not weaken it).
- **Track 2 — Real-world held-out.** HuntMCP's own past confirmed findings for PoC-minimization and verdict-
  agreement (XYZ.md §6.2) — never used to tune policies (train/test split).
- **Per-candidate metrics:**
  - VAL-AUTHZ: authz-finding recall/precision vs planted labels; multi-step-only findings recovered.
  - DISC-GRAPH: chains/paths recovered vs planted; chain-recall vs the 15-template baseline.
  - DISC-VARIANT: planted variants surfaced per finding.
  - EFF-SCHED/EFF-SCAN: findings-per-tool-call and per-1K-tokens **at equal or higher recall/coverage**;
    reject on any high/critical miss.
  - ARCH-STATE/DISTILL: context/token per engagement at **equal** finding set (capability held constant).
  - LEARN-SIG: signature transfer rate; frontier-call reduction **with quality floor held** (the memo's
    C-vs-D ablation).
- **Reproducibility record (per benchmarks.md):** benchmark version, config, seeds, target mode, request
  counts, verdicts, failures, verification results.

---

## 15. Risks and Failure Modes

| Risk | Affected | Mitigation |
|---|---|---|
| Efficiency change silently drops a high/critical | EFF-* | Hard-fail policy + frontier reference arm (§13.1–2) |
| Coverage bias toward easy classes | EFF-SCAN/SCHED | Per-class coverage floor, per-class reporting (§13.3) |
| Stale signature → missed bug on drifted target | LEARN-SIG | Signatures are re-confirmed hints, TTL + watch-mcp revalidation, never skips (§13.4) |
| Knowledge-graph poisoning by target text | LEARN-KG, DISC-GRAPH | Audit-cited authoritative edges only; target text is untrusted data (§13.6) |
| Hallucinated graph edges | DISC-GRAPH | Evidence-required write invariant (XYZ.md §3) extended to all edges |
| State-changing authz/variant probes cause harm | VAL-AUTHZ, DISC-VARIANT | Idempotent default; human exception for non-idempotent (§13.7); scope_guard every trial |
| Planner burns budget on deep search | DISC-GRAPH | budget_guard caps depth/branching; report search completeness, not feign exhaustiveness |
| Structured handoff loses signal vs prose | ARCH-STATE/DISTILL | Raw persisted to disk + recoverable; A/B holds capability constant (§14) |
| Parallel solvers race guards / duplicate work | ARCH-PAR | Existing work_registry + budget guards; per-solver scope isolation |
| "Confidence theater" from invented cost/gain numbers | EFF-SCHED | Gated on real P0-TEL data; simple closed-form first, ML only when justified |
| Scope creep destabilizes Phase-1 CEM | all | Everything here is post-Phase-1 or measurement-only; no change to CEM methodology (§11 exclusions) |
| Novelty overclaim | LEARN-SIG, DISC-GRAPH | §6 honest classification; combinations claimed, components credited |

---

## 16. Phased Implementation Roadmap

Each phase = objective · components · benefit · risks · benchmark · rollback · exit. **Sequenced by dependency,
leverage, and measurability — not speed.** All phases are *proposals*; none is authorized to start here, and
all are subordinate to Phase-1 CEM completing first (per the user's "proposal only, decide later").

### Phase 0 — Baseline / telemetry (enabling)
- **Objective:** make `yield/total-cost s.t. quality floor` computable and every later change A/B-measurable.
- **Components:** P0-TEL, P0-BENCH.
- **Benefit:** unlocks all measurement; zero capability risk (measurement-only).
- **Risks:** low; only that telemetry adds negligible overhead.
- **Benchmark:** self-check that recorded cost/yield reconciles with audit_log; frontier reference arm runs.
- **Rollback:** telemetry is additive; disable the writer. **Exit:** cost/yield + frontier baseline recorded
  and reproducible.

### Phase 1 — (unchanged) Scientifically-trustworthy CEM
- Owned by the existing spec chain; **this proposal changes nothing about it.** All later phases assume it has
  shipped and passed its gates (false-causal-conclusion-rate == 0).

### Phase 2 — Architecture Pareto (safe, high-leverage)
- **Objective:** cut hot-path context/tokens with capability held constant.
- **Components:** ARCH-STATE, ARCH-DISTILL.
- **Benefit:** context ↓ tokens ↓ duplicate-work ↓; better post-compaction reliability.
- **Risks:** signal loss in distillation. **Benchmark:** equal finding set at lower context (§14). **Rollback:**
  revert to prose handoff. **Exit:** ≥ target context reduction with zero finding-set change on the range.

### Phase 3 — Validation moat (capability)
- **Objective:** win harder on authorization/business-logic and autonomous condition discovery.
- **Components:** VAL-AUTHZ → VAL-COND → VAL-DIFF.
- **Benefit:** new authz/multi-step findings; autonomy for CEM conditions; stronger dedupe evidence.
- **Risks:** state-changing probes (gated). **Benchmark:** authz recall vs planted multi-step labels; verdict
  agreement. **Rollback:** feature-flag the engine; fall back to idor-mcp sweep. **Exit:** multi-step authz
  findings recovered that the single-request sweep misses, zero new FPs.

### Phase 4 — Discovery / chaining (breadth)
- **Objective:** real attack-state search + surface expansion + variant discovery.
- **Components:** DISC-SPEC → DISC-GRAPH → ARCH-PAR → DISC-VARIANT.
- **Benefit:** chains/paths beyond the 15 templates; shadow endpoints; free variants.
- **Risks:** planner budget, graph poisoning, parallel-solver races (all §15-mitigated).
- **Benchmark:** chain recall vs template baseline; variant yield. **Rollback:** planner falls back to template
  matcher. **Exit:** chain recall > template baseline with no FP regression; variants surfaced per finding.

### Phase 5 — Learning (compounding)
- **Objective:** unify knowledge, reuse causal signatures safely.
- **Components:** LEARN-KG → LEARN-SIG.
- **Benefit:** cross-engagement learning; the memo's amortization bet (question C).
- **Risks:** poisoning, staleness (§15). **Benchmark:** signature transfer rate; C-vs-D ablation with quality
  floor. **Rollback:** signatures are hints; disable reuse. **Exit:** measured transfer with no quality-floor
  breach.

### Phase 6 — Efficiency (gated last)
- **Objective:** yield-per-cost gains that provably respect the floor.
- **Components:** EFF-SCHED → EFF-SCAN → EFF-ALLOC (the last is the memo's Phase-5 work, credited there).
- **Benefit:** fewer wasted experiments/scans/frontier calls per validated finding.
- **Risks:** coverage regression, premature-close (§15). **Benchmark:** the memo's A/B/C/D on the range with the
  hard-fail policy. **Rollback:** revert to exhaustive/heuristic behavior. **Exit:** Pareto improvement with the
  quality vector ≥ baseline floor.

---

## 17. Success Metrics

- **Primary (constrained):** `Σ(severity_weight × validated_unique_finding) / total_cost` with
  `total_cost = tokens + HTTP + wall-clock`, **subject to** high/critical recall ≥ baseline − ε, FP ≤ baseline,
  per-class coverage ≥ baseline, independent-validation success ≥ baseline (verbatim from the memo §5).
- **Capability:** new authz/multi-step findings (VAL-AUTHZ); chain recall vs template baseline (DISC-GRAPH);
  variant yield (DISC-VARIANT); PoC-step reduction and verdict agreement (CEM).
- **Efficiency (only if floor holds):** frontier-calls / validated finding; cost / high-critical finding;
  context & tokens / engagement at equal finding set; tool-calls / validated finding.
- **Trust (business):** triager acceptance, time-to-triage, duplicate/needs-info rate on real submissions
  (A/B with vs without the Triager-Proof Bundle).
- **Learning:** signature transfer rate; fraction of frontier reasoning shown redundant (the memo's open
  question 1).

---

## 18. Explicit Non-Goals

- Not making HuntMCP "smaller" as an end in itself; token reduction is never the objective.
- Not optimizing cost/latency at any cost to security capability (hard constraint).
- Not adding heavy ML / RL training infrastructure.
- Not adding new MCP servers where an extension suffices.
- Not building an adaptive model router now (measurement-gated; the memo's standing conclusion).
- Not claiming novelty for established techniques (routing, cascades, RAG, planning, BED).
- Not auto-submitting reports; every output remains a human-reviewed draft.

## 19. Things We Should NOT Change Yet

- **Phase-1 CEM methodology** — determinism gate, replicated arms, verdict labels, zero-false-causal-conclusion
  gate. Frozen until it ships and passes its gates.
- **The protected benchmark** — blind manifest / evaluator-only key split, ground-truth labels, oracle logic
  (per `benchmarks.md`; changes require explicit human approval).
- **Safety substrate** — scope/budget/dedupe/work/redact/content-scanner and the `rm`-hard-block. Extend, never
  weaken.
- **model_gateway plumbing** — stays config-driven; EFF-ALLOC sits *beside* it as policy, never couples into it.
- **The one-target-per-chat + per-engagement isolation** model.
- **Evidence-gated confirmation** — no confirmed finding without linked evidence; extend the invariant, don't
  relax it.

## 20. Future Research Directions

- **CEM-signature transfer across targets** (the memo's crux question 2) — does a minimal-condition-set family
  generalize, or is it target-specific?
- **Aleatoric-vs-epistemic uncertainty as the primary efficiency lever** (memo question 3) — if target-side
  nondeterminism dominates, the determinism signal beats model routing.
- **Decision-aware context selection** — apply the memo's/CEM's counterfactual logic to context itself: keep
  only what would change the next decision ([Decision-Aware Memory Cards](https://arxiv.org/pdf/2606.08151)).
- **Metamorphic security relations** for variant generation beyond single-condition perturbation.
- **Poison-resistant knowledge graphs** as a defensive research contribution in their own right (given
  GragPoison-class attacks defeat current defenses).
- **Verifier-guided reasoning-effort** (PRM-style) using CEM's oracle as the verifier signal.

---

## Appendix A — Novelty honesty ledger

- **Clearly novel / underexplored:** DISC-VARIANT (variant as necessity-testing byproduct); the specific
  CEM-signature-guided-planning combination (DISC-GRAPH); evidence-cited poison-resistant knowledge (LEARN-KG
  framing).
- **Research-worthy but unclear:** LEARN-SIG (CEM amortization — the memo's question C; do not overclaim).
- **Differentiated combination:** ARCH-STATE (structured belief state for a security agent); VAL-COND.
- **Existing technique, stronger application:** VAL-AUTHZ, ARCH-DISTILL, DISC-SPEC, EFF-SCHED, EFF-SCAN.
- **Already established (we match, not lead):** P0-TEL, P0-BENCH, ARCH-PAR, EFF-ALLOC.

## Appendix B — Source map (research grounding)

Autonomous-pentest survey (arxiv 2607.02605) · XBOW methodology (xbow.com/blog/top-1-how-xbow-did-it) ·
CyberScoop human-vs-agent · LLM+classical planning (2512.11143) · ShotFlex MCTS attack-path
(sands.edpsciences.org) · AuthProbe (2607.20574) · BACFuzz (2507.15984) · agent-memory survey (2603.07670) ·
Decision-Aware Memory Cards (2606.08151) · ACON (2510.00615) · context-engineering (tianpan.co 2026-02-26) ·
Bayesian experimental design (2302.14545) · Bayesian-guided fuzzing (dl.acm.org/10.1145/3776659) · Ares
(2603.07915) · Learning-When-to-Think (2608.20256) · GragPoison / GraphRAG poisoning (2508.04276). Internal:
XYZ.md, PHASE1-PLAN.md, PHASE1-EXECUTION-PLAN.md, INTELLIGENCE-ALLOCATION-MEMO.md, ROADMAP.md.
