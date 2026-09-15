# UNKNOWN-UNKNOWN-RESEARCH.md — Final Gap-Discovery Pass

> **What this is:** a research / gap-discovery artifact, not a roadmap. It asks one question —
> *"what have we still missed?"* — and answers it against the **actual current worktree** as ground truth
> (`main` @ `15435a8`, CEM Phase 1 ACCEPTED AND FROZEN), with existing planning docs
> ([XYZ.md](XYZ.md), [ROADMAP.md](ROADMAP.md), [PHASE1-PLAN.md](PHASE1-PLAN.md),
> [PHASE1-EXECUTION-PLAN.md](PHASE1-EXECUTION-PLAN.md), [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md),
> [ARCHITECTURE.md](ARCHITECTURE.md)) treated as **baseline**.
>
> **What this is NOT:** a rewrite of any plan, another generic roadmap, a competitor summary, or a request for
> more agents / more MCPs / more scanners / bigger RAG. Every candidate here is judged by *what underlying
> capability it unlocks*, not by feature parity.
>
> **Prime directive honored:** nothing below is reported as a "new discovery" if the worktree already implements,
> wires, plans, researches, or explicitly rejects it. Each item is classified. Be skeptical of everything marked
> **NEW** or **UNKNOWN UNKNOWN** — the bar was: *not in the plans, not in the code, not a prompt, measurable,
> buildable, and ideally synergistic with CEM.*

---

## PART I — WHAT WE ALREADY HAD (the baseline, so nothing here double-counts)

### I.1 Implementation ground truth (verified against code, not filenames)

| Layer | Reality in the worktree |
|---|---|
| **Orchestration** | 6 static agents (`huntbrain`, `recon`, `scan`, `exploit`, `chain-planner`, `report`). "Dynamic specialists" = HuntBrain is *instructed in prose* to author a new `.opencode/agents/<name>.md` at runtime with a scoped `tools:` allowlist. Not a mechanized spawner; an LLM writing a markdown file. Orchestration is largely **sequential** (recon → scan → chain → exploit → report), with a duplicate-spawn guard (`work_registry.py`), not a parallel solver swarm. |
| **CEM (the differentiator)** | `cem_engine.py` + `case-mcp` + `case_store.py`: determinism gate, one-var-at-a-time replicated counterfactual interventions, confounder pinning, verdicts (`necessary`/`apparently_not_necessary`/`interacting`/`inconclusive`/`probabilistic`), multiple minimal condition sets, DD PoC minimization, Triager-Proof Bundle. **Post-validation only.** FROZEN with a zero-false-causal-conclusion benchmark gate. |
| **Knowledge** | Writeup RAG (ChromaDB), `memory-mcp` (per-target SQLite hunt blobs + `search_by_tech`), `lessons-mcp` (per-`vuln_class` registry of CONFIRMED / CLOSED-FP), `disclosed_reports.py`, `writeup-mcp` CVE fetch. 51 vuln-class skills. |
| **State / case layer** | `case_store.py`: hypotheses, evidence (content-addressed), finding lifecycle, `suggest_next_action` / `suggest_root_cause` (**deliberately simple heuristics — no info-gain/EV formula**, by design, because "this repo has no real cost/gain instrumentation yet"). Per-engagement SQLite. |
| **Guards / plumbing** | `scope_guard`, `budget_guard` (500-call breaker + per-finding ceiling), `audit_log` (per-call JSON trail), `dedupe_check`, `work_registry`, `engagement_paths` (per-target isolation + pointer), `stuck_detector` (cross-call repeat-loop → ok/nudge/abort), `tool_gaps` (missing-capability capture with recurrence counting), `model_gateway` (tier→provider plumbing), `redact`, `content_scanner`, `job_runtime` (background jobs). |
| **Tooling breadth** | ~25 tool MCPs incl. recon (subfinder/httpx/katana/nmap), scan (nuclei/sqlmap/dalfox/ffuf/waf-bypass), validation (oob/browser/playwright/second-opinion/burp bridge), cloud post-exploit (aws/azure/gcp), `ad-recon`, `local-privesc`, `idor`, `osint`, `github-security`, `secrets`, `obscura`, `case`, `chainer` (15 static DAG templates), `watch` (recon-diff snapshots). |
| **Backend** | Go/Gin + pgvector service + embedder microservice. **Not wired to the OpenCode agents** (ARCHITECTURE.md §883: "two independent, unconnected implementations"). |

### I.2 What the plans already own (do not re-propose these)

- **CEM as proof engine** — the entire XYZ thesis. Fixed.
- **Phase 2 XBOW-class discovery breadth**, **parallel fan-out rework** (design-only backlog, worker_pool.py-informed), **model routing / intelligence allocation** (INTELLIGENCE-ALLOCATION-MEMO, Phase 5, "measure early decide late").
- **Self-expanding toolkit** — full autonomous version explicitly *deferred as too risky*; bounded first step (`tool_gaps.py`) shipped.
- **Explicitly OPEN, already-named "Batch 8" items** (ARCHITECTURE.md §1155): **Asset Graph, Coverage Engine, Skill Router, tool-output-injection sanitization.** These are *known* gaps, so they are **not** unknown-unknowns — but their *framing* is narrow, and Part III argues several should be re-scoped.
- **Digital twin** — considered and **demoted/rejected** in XYZ.md in favor of CEM. Do not resurrect as-is.
- **CEM→amortization reuse loop** — researched in the memo; gated on Phases 2–4.

---

## PART II — BASELINE CAPABILITY MATRIX

Categories: `IMPLEMENTED` · `IMPL-UNDERUSED` · `IMPL-NOT-WIRED` · `PARTIAL` · `PLANNED` · `RESEARCHED` ·
`REJECTED` · `SMALL GAP` · `IMPORTANT GAP` · `NEW DIRECTION` · `UNKNOWN UNKNOWN`.

| # | Capability | Status | Runtime path? | Notes / evidence |
|---|---|---|---|---|
| 1 | Recon → scan → exploit → report pipeline | IMPLEMENTED | Yes (huntbrain spawns agents) | Sequential; real. |
| 2 | CEM causal validation (post-finding) | IMPLEMENTED | Yes (`case-mcp` CEM tools) | FROZEN, benchmark-gated. |
| 3 | Per-target memory + tech-keyed recall | PARTIAL | Yes (`memory-mcp`) | Raw blobs; **no generalized technique induction**. |
| 4 | Lessons registry (confirmed + closed-FP) | PARTIAL | Yes (`lessons-mcp`) | Positive + *thin* negative (CLOSED-FP only). No ineffective-tool/condition/payload negatives. |
| 5 | Hypothesis / evidence / finding lifecycle | IMPLEMENTED | Yes (`case_store`) | **Per-engagement, ephemeral. No cross-session persistence or resurrection.** |
| 6 | Next-best-action selection | PARTIAL | Yes (heuristic) | "Finish what's in flight" — **not** info-gain/EV. Deferred pending instrumentation. |
| 7 | Repeat-loop / stuck detection | IMPLEMENTED | Yes (`stuck_detector`) | Mechanical (identical tool+args). Not semantic ("we keep circling this idea"). |
| 8 | Missing-capability capture | IMPLEMENTED | Yes (`tool_gaps`) | Captures **gaps**. Does **not** detect **underuse/misuse/overuse** of *existing* capability. |
| 9 | Duplicate-work / duplicate-finding guard | IMPLEMENTED | Yes | Fingerprint-based. |
| 10 | Continuous watch (recon diff) | PARTIAL | Yes (`watch-mcp`) | Diffs subdomains/snapshots, logs `watch_events`. **Change → investigation routing is absent.** |
| 11 | Dynamic specialist spawning | PARTIAL | Prose-instructed | LLM authors an `.md`; no validation/benchmark of the spawned specialist. |
| 12 | Chaining | PARTIAL | Yes (`chainer-mcp`) | 15 **static** DAG templates over **findings**. No search; no capability+invariant chaining pre-finding. |
| 13 | Asset graph (hosts/endpoints) | PLANNED (open) | No | Batch 8. **Not a semantic application model.** |
| 14 | Coverage engine | PLANNED (open) | No | Batch 8. Framed as attack-surface coverage. |
| 15 | Skill/capability router | PLANNED (open) | No | Batch 8. |
| 16 | Tool-output injection sanitization | PLANNED (open) | No | Batch 8. **Security gap** — target text flows into agent reasoning today. |
| 17 | Parallel solver fan-out | PLANNED (design-only) | No | XBOW/worker_pool-informed backlog. |
| 18 | Model/intelligence-allocation routing | RESEARCHED (Phase 5) | No | Memo. Passive measurement not yet instrumented. |
| 19 | **Application state-machine / invariant inference** | **NEW DIRECTION** | No | Zero mentions across all docs. See Opp-1. |
| 20 | **Cross-session hypothesis ledger + resurrection** | **IMPORTANT GAP / NEW** | No | `resurrect` = 0 hits anywhere. See Opp-2. |
| 21 | **Information-gain / VOC experiment selection** | **IMPORTANT GAP** | No | Distinct from model routing (§18). See Opp-3. |
| 22 | **Structured, actionable negative knowledge** | **IMPORTANT GAP** | No | Beyond CLOSED-FP. See Opp-4. |
| 23 | **Capability-utilization observability** | **NEW / UNKNOWN UNKNOWN** | No | Mine `audit_log` for underused capability. See Opp-5. |
| 24 | **Hunt postmortem / self-evaluation** | **IMPORTANT GAP** | No | `postmortem`/`self-eval`/`hunt review` = 0 hits. Coverage Engine (planned) is a *partial* substrate. |
| 25 | Deterministic hunt replay / experiment lineage | SMALL→IMPORTANT GAP | Partial | `audit_log` + content-addressed evidence exist, but a hunt is not replayable end-to-end. |
| 26 | Long-horizon hunting benchmark | IMPORTANT GAP | No | Only the CEM causal-conclusion benchmark exists. See Part VII. |
| 27 | Human escalation as *information-value* trigger | SMALL GAP | Partial | Human-in-loop exists for permission/non-idempotent ops; not for "human judgment is high-value here." |

---

## PART III — WHAT THIS RESEARCH FOUND BEYOND THE BASELINE

Five candidates survived the anti-hype and novelty filters. Each is a **mechanism** unlocking a **capability**, not
a feature. They are deliberately few — one genuinely important unknown beats twenty ordinary features.

The organizing insight tying them together: **HuntMCP today reasons in the space of *vulnerability classes* and
*confirmed findings*. Expert hunters reason in the space of the *application's own rules* (who may do what to which
object, and what must always hold) and *live hypotheses* (competing explanations they update as evidence
arrives).** The gaps below are all facets of that missing layer — and CEM, the frozen differentiator, is exactly
the engine that layer would feed.

---

### OPPORTUNITY 1 — Application-property inference: an *invariant/state model*, not an asset graph  ⟶ Class **D/E**

**Problem.** Every skill and MCP is organized by vuln *class*. The system asks "is this endpoint vulnerable to
XSS/SQLi/IDOR?" It never builds a model of *what the application is supposed to guarantee* — the security
invariants (e.g. "a user can only read objects they own," "price is server-authoritative," "a consumed one-time
token cannot be replayed," "step 3 requires step 2"). The highest-value bugs (business logic, auth chains,
broken workflows) are *invariant violations that belong to no predefined class* — precisely what a class-driven
scanner cannot see, and what human hunters find by building a mental model of the app.

**Current industry approach.** RedAmon's Neo4j graph (19 node / 20+ edge types) and ars0n's ROI scoring model
*assets and findings*, not *behavioral properties*. XBOW-class systems confirm "the exploit fired." None infer
the application's own rules and then try to break them.

**What we could do differently.** Passively mine the HTTP corpus a hunt already produces into a small
**actor → action → object → state-transition → invariant** model, then hand the *candidate broken invariants* to
CEM as hypotheses. This is **model-based / property-based security testing** and **active automata learning**
(AALpy, symbolic Mealy machines) applied to a live black-box app — mature techniques in protocol security,
essentially unused in bug-bounty automation. It reframes hunting as *"which application property can I falsify?"*

**Why HuntMCP can build it.** (a) CEM already reasons about *conditions* and *broken invariants* — an invariant
model is the natural *source* of the conditions CEM currently receives by hand (XYZ §2.1: conditions "supplied
explicitly … Autonomous extraction … is a later phase"). This is that later phase, reframed. (b) `audit_log`
already records every request/response. (c) It directly answers **Q6 (CEM as discovery)**: CEM stops being only a
validator and becomes an *invariant discovery* engine — falsify a candidate invariant = find a bug.

**Required architecture.** A read-only `app_model` builder over `audit_log` + a small typed schema in `case_store`
(reuse, don't add a graph server — same discipline XYZ applied). Feed candidate invariant-violations into the
existing `case-mcp` hypothesis flow, then CEM.
**Required data.** The hunt's own request/response corpus; multi-identity sessions (2 accounts) to learn authz
boundaries — the two-account IDOR procedure already exists as a skill.
**Required libraries.** `AALpy` (active automata learning) *if* full state-machine inference is pursued; otherwise
stdlib + `pydantic` for the invariant schema. Keep the "moderate dependency budget" posture.
**Difficulty.** High (the inference quality is the hard part; a shallow heuristic version is medium).
**Failure modes.** Over-fitting a noisy corpus into false invariants → false hypotheses → wasted budget (mitigate:
invariants are *hypotheses to falsify*, never asserted facts; every one must pass CEM's determinism gate).
Combinatorial blow-up (mitigate: `budget_guard`, bound the alphabet).
**Benchmark.** Plant apps with known invariant violations (business-logic price tampering, workflow step-skip,
replay) that map to *no single vuln class*; measure how many the model surfaces that class-driven scanning misses.
**Expected impact.** Access to the bug category the whole market is worst at (business logic / chains), and it
makes CEM a discovery engine, not just a proof engine.
**Why genuinely different.** Nobody in this space models the *application's rules* as the primitive; everyone
models *assets* and *vuln classes*. This is the counter-hypothesis (§V.1) made constructive.

---

### OPPORTUNITY 2 — A persistent, evidence-linked hypothesis ledger with *conditional resurrection*  ⟶ Class **D**

**Problem.** `case_store` hypotheses die with the engagement (per-engagement SQLite). A hypothesis abandoned
because "identity B was unavailable" or "the /admin endpoint 404'd today" is **gone** — even when the blocking
condition later disappears (B becomes available; the endpoint appears on the next `watch` diff). Human hunters
keep a running mental backlog of "come back to this if X changes." HuntMCP cannot. **`resurrect` appears zero
times across the entire codebase and all docs.**

**Current industry approach.** RedAmon's **EvoGraph** ("evolutionary attack chain graph … cross-session memory …
agents avoid redundant work") is the closest analog — it persists decisions *and failures* across sessions. That
is the capability HuntMCP is missing; we can build it *differently* (evidence-linked, CEM-signature-keyed, with
explicit resurrection triggers rather than a monolithic graph).

**What we could do differently.** A durable **hypothesis ledger** where each dormant hypothesis records its
*blocking condition* as a machine-checkable predicate (`identity_B_available`, `endpoint:/admin exists`,
`param X reflected`). A cheap watcher (fed by `watch-mcp` diffs, new recon, new credentials) re-queues a
hypothesis **only** when its predicate flips — **conditional resurrection (Q3)**. Keyed to CEM signatures so a
resurrected hypothesis reuses the prior evidence.

**Why HuntMCP can build it.** `case_store` already models hypotheses + evidence; `watch-mcp` already produces
change events; `engagement_paths` already isolates per-target state. This is a *promotion* of existing pieces to a
durable, cross-session store + a predicate evaluator — not a new subsystem.

**Required architecture.** A `dormant_hypotheses` table (predicate + last-evidence pointer) + a resurrection hook
on watch/recon/credential events. **Required data.** Blocking predicates (must be captured at abandonment time —
a small discipline change in exploit-agent). **Libraries.** stdlib. **Difficulty.** Medium.
**Failure modes.** Predicate rot / stale resurrection re-testing dead ideas (mitigate: TTL + cap + the same
quality-floor discipline the memo defines); ledger bloat (mitigate: bound + decay).
**Benchmark.** A two-phase target where a resource appears only in phase 2; measure whether the phase-1 hypothesis
resurrects and converts. **Expected impact.** Turns HuntMCP from single-shot into genuinely *continuous* hunting —
the thing "continuous" is supposed to mean beyond "cron + scanner."
**Why different.** Not "store more memory" — it's *conditional, predicate-triggered* re-activation, which memory
blobs and the lessons registry cannot do.

---

### OPPORTUNITY 3 — Experiment selection by expected information gain (VOC), distinct from model routing  ⟶ Class **C→D**

**Problem.** `suggest_next_action` is "finish what's in flight." There is no mechanism that, given several open
hypotheses, picks the **next experiment that best distinguishes between them** — the single most characteristic
behavior of an expert hunter deciding *where not to spend time*. The INTELLIGENCE-ALLOCATION-MEMO deeply covers
*which model* to use (routing); it does **not** cover *which experiment* to run — a different question.

**Current industry approach.** Value-of-Computation / rational metareasoning (Russell & Wefald) and active
learning formalize "act to maximize expected information gain." EGATS (Evidence-Guided Attack Tree Search) already
adapts MCTS to pentest with **evidence-based branch pruning**. LATS unifies reasoning/acting with tree search +
value functions. These are the transferable frames; none are in HuntMCP (`information gain`, `MCTS`, `tree search`
= 0 relevant hits).

**What we could do differently.** A lightweight **experiment planner** that scores candidate experiments by
`P(distinguishes competing hypotheses) × severity_potential ÷ cost`, and — crucially — *designs an experiment
specifically to falsify* one hypothesis vs another (counterfactual by construction). This is the natural home for
CEM's determinism signal: **aleatoric vs epistemic** uncertainty tells the planner when more compute *cannot*
help (memo §9), a genuinely CEM-sharpened lever the memo already identified but placed in Phase 5 routing.

**Why HuntMCP can build it.** The case store already holds competing hypotheses + evidence; CEM already runs
controlled interventions. This is a *selection policy over experiments*, reusing both.
**Required architecture.** A scorer over `case_store` open hypotheses + a cheap cost model (needs the passive
cost/quality instrumentation the memo already recommends starting early). **Libraries.** stdlib.
**Difficulty.** Medium-High (calibrating P(distinguish) and severity-potential *before* spending reasoning is the
hard, honest open question — memo Q5). **Failure modes.** Miscalibrated scores suppress a real test (mitigate:
conservative policy — a score never *hard-blocks*, only *orders*, mirroring the memo's dedupe rule; severity-gated
minimum-effort floor). **Benchmark.** Fixed budget, target with several plausible-but-only-one-real hypotheses;
measure findings-per-experiment vs the "finish-in-flight" baseline. **Expected impact.** More findings per unit
cost *without* the model-routing complexity — and it's the missing "observe→hypothesize→**design experiment**→
falsify" step the testing rules (`.claude/rules/testing.md`) already demand.
**Why different.** It selects *experiments*, not *models*; it's the untouched half of the allocation problem.

---

### OPPORTUNITY 4 — Structured, actionable *negative knowledge*  ⟶ Class **C** (cheap, high-yield)

**Problem.** `lessons-mcp` records CONFIRMED findings and CLOSED-FPs by vuln class. It does **not** record the far
larger, more actionable body of negatives: *"tool T is ineffective against stack S," "payload family F repeatedly
fails behind WAF W," "specialist X is not worth spawning when signal Y is absent," "experiment E is redundant
given evidence Z."* This is the knowledge that most improves **long-horizon efficiency**, and it's nearly free to
capture because the audit trail already contains every failed attempt (Q1).

**Current industry approach.** EGATS prunes intractable branches on evidence; RedAmon's EvoGraph tracks failures
to avoid redundant work. HuntMCP tracks *successes and false-positives*, but discards *ineffectiveness*.

**What we could do differently.** A `negative_knowledge` store keyed on `(technique/tool, context-signature)` with
an outcome tally, mined semi-automatically from `audit_log` + `stuck_detector` aborts. It feeds two consumers:
the Skill Router (planned) as a *deprioritization* input, and the experiment planner (Opp-3) as a *redundancy*
filter. **Explicitly a hint, never a hard skip** — the exact discipline the memo already established for stale CEM
signatures (staleness = missed-finding risk).

**Why HuntMCP can build it.** `audit_log`, `lessons_store`, and `stuck_detector` already produce the raw signal;
this is an aggregation + a retrieval surface. **Libraries.** stdlib. **Difficulty.** Low-Medium.
**Failure modes.** Over-trusting negatives → skipping a test that *would* now succeed on a changed target
(mitigate: context-signature includes target-version/stack; TTL; hints-not-skips; quality floor catches
regressions). **Benchmark.** Measure wasted-effort reduction (redundant failing calls avoided) with **zero**
high/critical recall loss — a hard constraint, not a tradeoff. **Expected impact.** Direct long-horizon cost
reduction on the cheapest possible substrate, and it makes the planned Skill Router actually *smart* instead of
static. **Why different.** It's the inverse of everything the knowledge layer does today; and it's the one item
here that is *cheap now* rather than research-grade.

---

### OPPORTUNITY 5 — Capability-utilization observability (not gap capture, not coverage)  ⟶ Class **E (unknown unknown)**

**Problem.** `tool_gaps.py` detects *missing* capabilities. The Coverage Engine (planned) will measure *attack
surface* covered. **Nothing measures whether the ~25 MCPs and 51 skills that already exist are actually being
selected, selected correctly, or over-selected** (Q2). This is a true blind spot: a capability can exist, be
tested, pass CI, and *never be invoked by the autonomous planner on an eligible target* — and no one would know.
The prompt's own observation applies literally here: "a feature existing in code does NOT mean the autonomous
system invokes it."

**Current industry approach.** None found — competitors report *coverage* and *cost*, not *capability
utilization*. This is the item most likely to be a genuine unknown-unknown.

**What we could do differently.** Mine `audit_log` across engagements to produce a **utilization report** per
capability: `eligible-engagements / times-selected / outcome-quality-when-selected`, classifying each as
`UNDERUSED` (exists, rarely chosen when relevant), `MISUSED` (chosen but low yield), `OVERUSED` (chosen far beyond
its payoff), or `GAP` (from `tool_gaps`). "A capability exists, but the planner almost never selects it" becomes a
first-class, queryable signal — feeding both the Skill Router and the human's build/prune decisions.

**Why HuntMCP can build it.** `audit_log` already logs every Tier-2 call per engagement; the MCP/skill inventory
is enumerable. This is pure offline analysis over data that already exists — **zero new runtime risk.**
**Libraries.** stdlib (optionally `pandas` for the report — weigh against dependency budget). **Difficulty.** Low.
**Failure modes.** "Eligible" is fuzzy — needs an eligibility signature per capability (mitigate: start with the
recon-signal each specialist already keys on, e.g. graphql-agent eligible iff `/graphql` seen). **Benchmark.**
Not a security benchmark — an *operational* one: does the report correctly flag a deliberately-disabled tool as
underused? **Expected impact.** Closes the runtime-vs-code blind spot the prompt is most worried about; makes the
whole toolkit *auditable for actual use*, and is a prerequisite for trusting any efficiency claim later.
**Why different.** Everyone measures what they *found*; nobody measures whether their *own capabilities are being
used*. It's introspection on the agent, not on the target.

---

### OPPORTUNITY 6 — Schema-driven *stateful property testing* as an autonomous falsifier for CEM  ⟶ Class **D**  *(added by Expansion Pass, 2026-09-11)*

> *This is the "small library → disproportionate unlock" instance the first pass gestured at (Part IV named
> "model-/property-based testing" and `AALpy` abstractly) but never surfaced as a concrete opportunity. It is the
> most immediately buildable of the six and the sharpest "match discovery, win on proof" case at the API layer.*

**Problem.** Recon routinely recovers an **OpenAPI/Swagger spec or a GraphQL introspection schema** (both are
heavily referenced across the skills — `introspection` alone appears in 21 files), yet **nothing consumes that
schema as a test *engine***. scan-agent points GraphQL at a static payload wordlist; there is no mechanism that
turns the schema into *stateful, dependency-aware property tests*. This is exactly where **business-logic and
broken-authorization bugs live** — the category class-driven scanners miss and the one the market is worst at.
The research consensus is explicit: *"traditional stateless fuzzing fails to detect business-logic
vulnerabilities, motivating stateful approaches."*

**Current industry approach.** `schemathesis` (4.x, 2026; Rust core; OpenAPI + GraphQL; built on the `hypothesis`
property-based-testing engine; stateful — it threads response values into later requests via OpenAPI links) and
Microsoft's `RESTler` (dependency-aware stateful REST fuzzing that found real Azure/O365 bugs) *find* spec
violations, crashes, validation bypasses, and multi-step stateful bugs. 2026 work extends this to LLM-driven
(`RESTing-LLAMA`) and GraphQL (`SGAFuzzer`) fuzzing, and to access-policy-violation checks. **But every one of
these stops at "a violation was observed."** None derive *which conditions are necessary*, minimize the
reproducer, or gate the conclusion against nondeterminism — the precise trust dimension CEM owns.

**What we could do differently.** Wrap a property-testing engine as a thin, scope/budget/audit-gated falsifier
that (a) consumes the schema recon already found, (b) runs **stateful** operation sequences under a real
identity, (c) checks *properties* rather than payload signatures — schema-conformance, authorization
monotonicity ("user A must not read B's object"), workflow order ("step 3 requires step 2"), idempotency — and
(d) emits each **violated property as a candidate finding + its condition set straight into the `case-mcp`
hypothesis flow, where CEM proves necessity, minimizes, and gates determinism.** The discovery half is
off-the-shelf; the *differentiator* (proof) is HuntMCP's. This is XYZ's "match discovery, win on proof" thesis
made concrete at the API layer — and a concrete on-ramp to Opp-1's abstract invariant model for the API subset
(a schema *is* a partial, machine-readable invariant specification you get for free).

**Why HuntMCP can build it.** Recon already recovers schemas; `case-mcp`/CEM already ingest conditions and prove
them; `scope_guard`/`budget_guard`/`audit_log`/`job_runtime` already gate long black-box runs. The new surface is
one MCP wrapper around an existing engine + a property-to-hypothesis adapter — not a new reasoning subsystem.
**Required architecture.** A `schema-fuzz` MCP wrapper (FastMCP, `resolve_tool`/`run_tool` discipline, background
job) + an adapter mapping violated properties → `case_store` hypotheses. Reuse everything else.
**Required data / libraries.** A discovered OpenAPI/GraphQL schema; `schemathesis` (+ its `hypothesis` core) — a
real dependency add, so it must clear XYZ's dependency-budget bar; `RESTler` is heavier and optional. Both are
external binaries/libs, not homegrown fuzzers.
**Difficulty.** Medium (the engine is off-the-shelf; the authorization/workflow *properties* and the CEM adapter
are the real work). **Failure modes.** State-changing sequences against a live target (mitigate: the existing
non-idempotent-refused-by-default + human-exception policy already covers this exact risk); schema drift/lies
(mitigate: violations are hypotheses CEM must still confirm); noise/false 500s (mitigate: CEM's determinism gate
filters flaky violations — the same gate that protects the frozen slice).
**Benchmark.** The **WFC/WFD web-fuzzing-commons dataset** (2026) is a ready, independent REST-API-fuzzing
benchmark; measure business-logic/authz violations surfaced-and-CEM-confirmed vs the current class-driven scan,
at zero high/critical recall loss. **Expected impact.** Direct access to stateful/business-logic API bugs the
current pipeline structurally cannot reach, with a small dependency add — and it feeds the differentiator rather
than competing with it. **Why genuinely different.** The novelty is **not** the fuzzer (prior art, honestly
labeled) — it is the *composition*: an off-the-shelf stateful property falsifier whose every hit is
necessity-proven, minimized, and determinism-gated by CEM, and whose violated properties seed the invariant model
(Opp-1). No compared system (RedAmon, ars0n, RESTler, schemathesis) couples discovery to a causal-proof engine
this way; and this specific composition is hard to reproduce with ordinary prompting, because stateful sequence
generation, dependency inference, and shrinking are exactly what the engine does deterministically that an LLM
does unreliably.

---

## PART IV — CROSS-DOMAIN IMPORTS (only those with a real security-hunting payoff)

| Field | Idea | Where it lands | Verdict |
|---|---|---|---|
| Active automata learning (AALpy) | Infer a black-box state machine by testing | Opp-1 invariant model | **Import** (bounded) |
| Model-/property-based testing | Define properties, generate falsifying inputs | Opp-1 | **Import** (framing) |
| VOC / rational metareasoning | Spend compute only when it changes the decision | Opp-3 | **Import** |
| Active learning / experimental design | Pick the max-information experiment | Opp-3 | **Import** |
| MCTS / LATS / EGATS | Bounded branching search with evidence pruning | Chainer *could* evolve from static DAGs → evidence-pruned search | **Watch** — only if chaining becomes a bottleneck; don't add search for its own sake |
| Process/workflow mining | Reconstruct the real process from event logs | Opp-1 (workflow invariants) | **Import** (lightweight) |
| Anomaly detection / clustering | Flag unexplained response clusters | Q4 unknown-unknown detection (below) | **Watch** — cheap heuristic first |
| Software test-suite reduction | Delta debugging | **Already in CEM** | (baseline) |
| Property-based / stateful API testing (schemathesis, Hypothesis, RESTler) | Generate stateful, dependency-aware tests from a schema; check *properties* | **Opp-6** (added by expansion pass) | **Import** (off-the-shelf falsifier → CEM) |

**Deliberately rejected imports (Class F distractions):** heavy ML/RL policy training (no data, no payoff vs the
dependency cost); a full SCM / do-calculus engine (XYZ already rejected this); a graph database (SQLite tables are
sufficient at this scale — XYZ's own discipline); "agent swarm for its own sake."

---

## PART V — THREE SERIOUS COUNTER-HYPOTHESES (trying to prove our direction wrong)

**V.1 — The vuln-class *skill* may be the wrong primitive; the application *invariant* is.**
The spine of HuntMCP is 51 class-organized skills + class-organized scanners. But the bugs with the highest payout
and the lowest automation rate — business logic, chains, workflow abuse — are invariant violations that fit *no*
class. If the primitive were "application property," the 51 skills demote to *payload libraries* serving a
property-falsification loop, and the architecture reorganizes around Opp-1. **This is the strongest challenge and
it is constructive, not destructive** — it doesn't discard the skills, it re-subordinates them.

**V.2 — CEM-as-post-validation may be the right engine pointed at the wrong end of the funnel (for now).**
XYZ declares proof the scarce good and discovery table-stakes — but **Phase 2 discovery has not been built.** A
proof engine is only as valuable as the flow of findings it proves. There is a real risk of a superbly
trustworthy validator with a thin discovery pipeline feeding it. The counter-argument (which the docs make
deliberately) is that proof is the *durable* moat while discovery commoditizes — but the *sequencing* deserves an
explicit, evidence-based re-check, and Opp-1/Opp-3 are attractive precisely because they make CEM a *discovery*
engine, hedging this risk. **Surface it; the docs chose this ordering knowingly — but "knowingly" isn't
"validated."**

**V.3 — Persistent per-target memory may induce confirmation bias / anchoring.**
`memory-mcp` + `lessons-mcp` condition future hunts on past ones. On an *evolving* target this biases toward
previously-found classes and *away* from genuinely new surface — the exact staleness/missed-finding risk the memo
flags for CEM signatures, generalized to all memory. There is currently **no anti-anchoring counter-force**: nothing
deliberately tests what memory says is dead (which is also why Opp-4 must be *hints-not-skips*). More memory is not
strictly better; it may need a paired "challenge the memory" mechanism.

*(Bonus, the anti-hype one: more autonomy / more agents ≠ more finding quality. The sequential 6-agent pipeline
with strong guards may already be near the quality ceiling for its discovery breadth; the leverage is in the
reasoning layer (Opp 1–5), not in agent count.)*

### V.4 — Adversarial stress of the opportunities themselves  *(added by Expansion Pass, 2026-09-11)*

The first pass challenged the *architecture* (V.1–V.3) but did not turn the same skepticism on the six
opportunities. Doing so honestly:

- **Opp-1 (invariant model)** — *strongest idea, weakest tractability.* Inferring a faithful application model from
  a noisy black-box corpus is the hardest problem here; a shallow heuristic version risks emitting confident
  false invariants (garbage-in for CEM). **Survives only if gated behind a measured shallow prototype** before any
  `AALpy`-grade investment. This is why Opp-6 matters: it delivers the *API subset* of the same value with an
  off-the-shelf engine, de-risking Opp-1.
- **Opp-2 (resurrection)** — real, but its value is bounded by how often blocking conditions actually flip on live
  bounty targets. If they rarely do, it is a small win. **Cheap enough that the downside is low; upside unproven.**
- **Opp-3 (info-gain selection)** — the honest open question (memo Q5) is whether severity/P(distinguish) can be
  estimated *before* spending reasoning. If they can only be estimated *after*, the policy is partly circular.
  **Do not build before the passive instrumentation exists to calibrate it.**
- **Opp-4 (negative knowledge)** — the safest bet, but its one real hazard (stale negatives → missed bug on a
  changed target) is a *security* failure, not just an efficiency one. **Hints-not-skips is non-negotiable.**
- **Opp-5 (utilization observability)** — near-free and low-risk; its only failure is a fuzzy "eligibility"
  signal producing noisy verdicts. **Lowest-risk item; worst case it's merely uninformative, never harmful.**
- **Opp-6 (schema property testing → CEM)** — the discovery half is prior art (correctly labeled), so the whole
  value rests on the *composition* and on schemas actually being present/accurate on real targets. If a target
  exposes no schema, it contributes nothing. **Highest immediate payoff *conditional on* schema availability;
  verify that condition on real scopes before committing.**

Net: **Opp-4, Opp-5, and Opp-6 are the low-risk near-term trio; Opp-1 and Opp-3 are research-grade and must be
instrumented/prototyped before commitment; Opp-2 is a cheap opportunistic add.**

---

## PART VI — UNKNOWN-UNKNOWN REGISTER

| ID | Title | Category | Discovery | Why we missed it | Why it matters | Relationship to HuntMCP | Status | Deps | Difficulty | Confidence | How to validate | Benchmark? | Recommendation |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| UU-1 | Application invariant/state model as the reasoning primitive | E/D | Nothing models app *rules*; all class-driven | We organized around vuln classes (the natural unit for skills/scanners) | Unlocks business-logic/chain bugs; makes CEM a discovery engine (Q6) | Feeds conditions to CEM (XYZ §2.1 "later phase") | NEW | Opp-3 helps | High | Med-High | Plant no-class invariant violations; measure surfacing vs class scan | Yes (new) | **Prototype the shallow heuristic version; gate the AALpy version on it** |
| UU-2 | Conditional hypothesis resurrection | E | Case store is per-engagement; "single-shot" felt complete | Continuous hunting was scoped as watch-diff, not hypothesis lifecycle | Makes "continuous" mean something; recovers abandoned high-value leads | Promotes `case_store`+`watch-mcp` | NEW | watch-mcp | Med | High | Two-phase target; measure resurrection→conversion | Yes (long-horizon) | **Build after Opp-4; small, high-leverage** |
| UU-3 | Info-gain experiment selection (VOC) | D | Memo covered model routing, not experiment choice | "Which model" and "which experiment" look similar, are not | More findings/cost without routing complexity | Selection policy over `case_store`+CEM | GAP | passive cost instr. | Med-High | Med | Fixed-budget multi-hypothesis target | Yes | **Start passive instrumentation now (memo already advises); build policy later** |
| UU-4 | Structured negative knowledge | C | We stored wins + FPs, not ineffectiveness | Negatives feel like "nothing happened"; easy to discard | Cheapest long-horizon efficiency win | Aggregates `audit_log`/`stuck_detector`; feeds Skill Router | GAP | audit_log | Low-Med | High | Redundant-call reduction @ zero recall loss | Yes (efficiency+floor) | **Build first — cheap, unlocks Skill Router** |
| UU-5 | Capability-utilization observability | E | We measured target coverage, never our own tool usage | Introspection on the agent isn't a habit; CI-green felt sufficient | Closes the code-exists≠invoked blind spot (the prompt's core worry) | Offline mine of `audit_log` + inventory | NEW | audit_log | Low | High | Flag a disabled tool as underused | Operational | **Build early — near-free, high diagnostic value** |
| UU-6 | Anti-anchoring counter-force to memory | E | Memory was assumed net-positive | Confirmation bias is invisible from inside the loop | Prevents memory-induced misses on evolving targets | Paired mechanism for memory/lessons | NEW (hypothesis) | Opp-4 | Med | Low-Med | A/B: memory-conditioned vs memory-challenged hunts | Yes | **Investigate; do not build blind** |
| UU-7 | Tool-output prompt-injection sanitization | C | Known-open (Batch 8) but under-prioritized | Framed as a "batch item," not a live risk | Target text flows into agent reasoning *now* | Security boundary | PLANNED (open) | none | Med | High | Injected-payload corpus in tool output | Yes (security) | **Prioritize — it's a standing security gap, not a nicety** |
| UU-8 | Deterministic hunt replay / experiment lineage | B→C | Per-call audit ≠ replayable hunt | "We have an audit log" felt like reproducibility | Debugging failed runs; benchmark determinism; trust | Extends `audit_log`+evidence store | GAP | none | Med | Med | Replay a recorded hunt to identical verdicts | Yes | **Fold into the long-horizon benchmark work** |
| UU-9 | Human escalation as information-value trigger | B | Human-in-loop was framed as *permission*, not *intelligence* | Escalation = safety, not a value signal | Spends the scarcest resource (human judgment) where it pays most | Extends existing HITL gates | SMALL GAP | Opp-3 | Low | Med | Measure finding-value on escalated vs non | Optional | **Cheap add-on to Opp-3** |
| UU-10 | Schema-driven stateful property testing → CEM *(expansion pass)* | D | Recon finds schemas; nothing consumes them as a test *engine* | We treated OpenAPI/GraphQL as discovery artifacts, not falsifiers; "fuzz" meant value-fuzz (ffuf/dalfox), not stateful property-fuzz | Reaches stateful/business-logic API bugs the class-driven pipeline structurally misses; off-the-shelf discovery feeding CEM's proof | Thin engine wrapper + property→hypothesis adapter over `case-mcp`/CEM | NEW | `schemathesis` dep; a discovered schema | Med | Med-High | WFC/WFD dataset; violations surfaced-and-CEM-confirmed vs class scan | Yes (WFC/WFD ready) | **Strongest low-risk near-term item *when a schema exists*; verify schema availability on real scopes first** |

---

## PART VII — BENCHMARK IMPLICATIONS

The frozen CEM benchmark measures **one confirmed finding's causal conclusion**. It says nothing about the
capabilities above, because none of them are single-finding, single-shot. The honest gap:

- **A long-horizon hunting benchmark (Q11) does not exist.** It would measure: sustained multi-step investigation,
  multi-identity workflows, business-logic/invariant violations, target *change* between phases, hypothesis
  *persistence and resurrection*, failure recovery, learning *between* hunts, and — uniquely — **the quality of a
  correct *no-finding* conclusion** (knowing when to stop is a skill; current benchmarks reward only finding).
- It must stay **blind and independent** (per `.claude/rules/benchmarks.md`): planted invariant violations and
  resurrection triggers are *evaluator-only ground truth*; the implementation must not derive them.
- Reference point: *"What Makes a Good LLM Agent for Real-world Penetration Testing?"* (arXiv 2602.17622) — worth
  reading before designing this, to avoid re-inventing a weaker eval.
- **(Expansion pass)** For the **API subset**, a benchmark substrate already exists: the **WFC/WFD web-fuzzing
  commons dataset** (arXiv 2509.01612, 2026) — a ready, independent REST-API-fuzzing corpus for measuring Opp-6
  (schema property testing → CEM) without hand-building targets. Use it for the API slice; the broader
  long-horizon benchmark above is still needed for UU-1/2/3.
- **Do not** let a new benchmark weaken the CEM zero-false-causal-conclusion gate; it is additive.

---

## PART VIII — SYNTHESIS (the 15-point answer)

1. **What HuntMCP already covers:** full recon→report pipeline, a frozen best-in-class CEM proof engine, broad
   tooling (~25 MCPs, 51 skills), strong guards/isolation, per-target memory + lessons, static chaining, recon-diff
   watch.
2. **What current *plans* cover:** XBOW-class discovery breadth (P2), model/intelligence routing (P5, measure-first),
   Asset Graph / Coverage Engine / Skill Router / injection-sanitization (Batch 8, open), self-expanding toolkit
   (bounded step done, full version safety-gated), parallel fan-out (design-only).
3. **What current *implementation* covers:** everything in Part I.1 — verified in code, not filenames. CEM
   post-validation, not discovery. Orchestration sequential, not swarm.
4. **Implemented but underused:** `audit_log` (a rich substrate mined for almost nothing — Opp-4/Opp-5 change
   that); `second-opinion-mcp` and the many post-exploit MCPs (utilization unknown — literally Opp-5's point);
   `case_store` hypotheses (created then discarded per engagement — Opp-2).
5. **Still missing:** an application-property model (UU-1); cross-session hypothesis lifecycle (UU-2); info-gain
   experiment selection (UU-3); structured negative knowledge (UU-4); capability-utilization introspection (UU-5);
   hunt self-evaluation; a long-horizon benchmark.
6. **What we completely failed to consider:** capability-*utilization* observability (UU-5) and an
   *anti-anchoring* counter-force to memory (UU-6) — neither appears anywhere; both are cheap and both are blind
   spots by construction (you can't see them from inside the loop).
7. **Cross-domain discoveries:** automata learning / model-based testing (→ UU-1), VOC/active learning (→ UU-3),
   process mining (→ UU-1), EGATS-style evidence-pruned search (watch-list for chaining).
8. **Most interesting research directions:** UU-1 (invariant model, because it converts CEM into a discovery
   engine and attacks the market's weakest category) and UU-3 (experiment selection, the untouched half of
   allocation).
9. **Genuinely new opportunities:** Opp-1…Opp-5 (first pass) + **Opp-6 schema-property-testing→CEM** (expansion
   pass) — six total; Part III.
10. **3 architectural counter-hypotheses:** V.1 (invariant > vuln-class primitive), V.2 (proof-before-discovery
    sequencing), V.3 (memory as bias) — Part V.
11. **Features we should NOT build:** a graph DB, an SCM/do-calculus engine, RL policy training, a bigger RAG, more
    static agents, autonomous unreviewed code execution (self-expanding toolkit's full form), any "swarm" without a
    measured bottleneck. (Class F.)
12. **Libraries worth investigating:** `AALpy` (only if UU-1's shallow version proves out); `pydantic` (already in
    use, for the invariant/negative-knowledge schemas); `pandas` *maybe* for offline reports (weigh vs budget).
    Everything else stays stdlib, honoring XYZ's dependency discipline.
13. **Benchmark implications:** a new, blind, independent **long-horizon** benchmark is needed for UU-1/2/3; the
    CEM gate stays untouched (Part VII).
14. **Recommended experiments (research, not commitments):** (a) shallow invariant-inference prototype on a
    2-account fixture, measured against class-scanning; (b) UU-5 utilization report over existing audit logs — near
    zero cost, immediate signal; (c) UU-4 negative-knowledge aggregation + redundant-call-reduction measurement;
    (d) the memo's already-recommended passive cost/quality instrumentation, which UU-3 also needs.
15. **Questions requiring human decisions:** see Part IX.

---

## PART IX — QUESTIONS REQUIRING A HUMAN DECISION

1. **Primitive question (the big one):** should the next research investment target the *reasoning layer*
   (invariant model + hypothesis lifecycle + experiment selection, UU-1/2/3) rather than the planned *breadth*
   layer (Phase 2 discovery)? This reorders the roadmap's implicit priority and is explicitly out of scope for me
   to decide.
2. **Sequencing vs the freeze:** every opportunity here is post-Phase-1 and none touches the frozen CEM slice —
   but UU-1 and UU-3 *reinterpret* XYZ's "autonomous condition discovery" (a later-phase item) as nearer-term.
   Confirm that's a re-scope you want, not scope creep.
3. **Cheap-wins-first?** UU-4 (negative knowledge) and UU-5 (utilization) are low-cost, low-risk, and buildable on
   existing data now. Do you want a small, self-contained "reasoning-substrate hygiene" effort before any of the
   research-grade items?
4. **Benchmark commitment:** a long-horizon benchmark is a real build with protected-asset discipline. Approve in
   principle before any UU-1/2/3 work, since those items are unfalsifiable without it.
5. **UU-7 priority:** tool-output injection sanitization is an *open security gap that exists in the running
   system today* — should it jump the Batch-8 queue independent of everything else here?

---

*Ground truth: current worktree `main` @ `15435a8`, CEM Phase 1 FROZEN. No planning file was modified; no code was
changed. This document is a gap register, not a roadmap — building anything here requires the human decisions in
Part IX first.*

### Sources (external anchors)
- RedAmon — [github.com/samugit83/redamon](https://github.com/samugit83/redamon) (EvoGraph, Fireteam/Scatter-Gather, TrafficMind, proxy_brain, Neo4j knowledge graph)
- ars0n-framework-v2 — [github.com/R-s0n/ars0n-framework-v2](https://github.com/R-s0n/ars0n-framework-v2) (ROI scoring, workflow-enforced methodology)
- Language Agent Tree Search (LATS) — [arXiv 2310.04406](https://arxiv.org/abs/2310.04406); EGATS / SWE-Search MCTS — [arXiv 2410.20285](https://arxiv.org/pdf/2410.20285)
- Active automata learning research agenda — [Springer, 2026](https://link.springer.com/article/10.1007/s10009-026-00839-z); AALpy; State Machine Inference for Security Protocols — [cs.ru.nl](http://www.cs.ru.nl/~joeri/StateMachineInference.html)
- What Makes a Good LLM Agent for Real-world Penetration Testing? — [arXiv 2602.17622](https://arxiv.org/pdf/2602.17622)
- Rational Metareasoning for LLMs (VOC) — [arXiv 2410.05563](https://arxiv.org/pdf/2410.05563) (also cited in INTELLIGENCE-ALLOCATION-MEMO.md)
- *(Expansion pass)* Schemathesis — [schemathesis.io](https://schemathesis.io/) (property-based, stateful, OpenAPI+GraphQL, built on Hypothesis); RESTler stateful REST fuzzing — [ICSE 2019](https://dl.acm.org/doi/10.1109/ICSE.2019.00083) / [Microsoft Research](https://www.microsoft.com/en-us/research/blog/restler-finds-security-and-reliability-bugs-through-automated-fuzzing/); WFC/WFD web-fuzzing benchmark — [arXiv 2509.01612](https://arxiv.org/pdf/2509.01612); coverage-level guided blackbox REST fuzzing — [arXiv 2112.15485](https://arxiv.org/pdf/2112.15485)

---

## EXPANSION-PASS VERIFICATION NOTE (2026-09-11)

A final targeted pass re-read this document, XYZ.md, INTELLIGENCE-ALLOCATION-MEMO.md, ARCHITECTURE.md, ROADMAP.md,
and the relevant code, then audited the existing research against the "golden research pattern" (2–3 differentiated
innovations unseen elsewhere · reason from baseline · small architecture/library changes that unlock
disproportionate value · fresh directions across loops · adversarial challenge · new-vs-planned discipline).

**Criteria review:**

| # | Golden criterion | Verdict before pass | Action |
|---|---|---|---|
| 1 | Searched for differentiated innovations, not just gaps | Partially — Opp-5 was the clearest "unseen elsewhere"; doc leaned gap-flavored | **Added Opp-6** (a differentiated composition) |
| 2 | Reasoned from baseline | ✅ Strong (Part I + per-item "why HuntMCP can build it") | none |
| 3 | Small architecture/library change → disproportionate unlock | **Under-developed** — named `AALpy`/"property-based" only abstractly | **Closed via Opp-6** (schemathesis, a real small-dep unlock) |
| 4 | Sufficiently different directions | ✅ Six directions: app-model / lifecycle / selection / knowledge / introspection / (now) schema-property-testing | none |
| 5 | Challenged strongest ideas adversarially | Partially — challenged the *architecture* (V.1–V.3), not the *opportunities* | **Added V.4** (adversarial stress of Opp-1…6) |
| 6 | Distinguished new from planned/implemented | ✅ Rigorous (Part I.2, matrix, Batch 8) | Opp-6 verified new (`schemathesis`/`grammar`/`coverage-guided` = 0 hits; metamorphic cited-and-set-aside in XYZ) |
| 7 | Any important innovation the doc missed | **Yes — one:** schema-driven stateful property testing as a CEM falsifier | **Added Opp-6 / UU-10** |

**Materially added by this pass:** Opportunity 6 (Part III), a cross-domain row (Part IV), an adversarial-stress
subsection V.4 (Part V), register entry UU-10 (Part VI), a WFC/WFD benchmark note (Part VII), and these sources.
All first-pass findings and terminology were preserved unchanged.

**Explicitly rejected during this pass (did not meet the anti-hype bar):** a differential-response oracle as a
*standalone* item (folded into Opp-1/Opp-6 rather than duplicated); heavier stateful fuzzers (`RESTler`) as a
*required* dependency (noted as optional — too heavy for the dependency budget vs `schemathesis`); a generic
"add a fuzzing MCP" (rejected — the value is the CEM composition, not another scanner); metamorphic testing as a
new mechanism (XYZ already cites and sets it aside). No other innovation was forced.

**Sufficiency for the final 3-research synthesis:** with Opp-6 and V.4 added, the document now satisfies the
golden pattern — it carries differentiated innovations (not only gaps), an explicit library-unlock lens, six
distinct directions, adversarial challenge of both architecture and opportunities, clean new-vs-planned
separation, and human-decision framing. **It is sufficient as the research input for a subsequent synthesis
pass.** No further research gap was found; nothing was invented beyond the single evidenced addition.
