# HUNTMCP-NEXT-GEN-PROPOSAL-v3.md — Capability-First Next-Generation Roadmap

> Status: **research / architecture only.** No implementation, no production-code changes, no benchmark/
> ground-truth changes, no commits, no phase started.
>
> Lineage: [v1](HUNTMCP-NEXT-GEN-PROPOSAL.md) → [audit](HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT.md) →
> [v2](HUNTMCP-NEXT-GEN-PROPOSAL-v2.md) → **v3 (this file)**. All prior files remain unchanged and are kept as
> the record. v3 is the controlling roadmap.
>
> **Corrected direction (the reason v3 exists):** the roadmap is **capability-first and benchmark-driven**.
> `audit_log.py` is **completely out of the dependency graph** — unchanged, not a prerequisite, not a
> foundation, not the telemetry mechanism for anything. **There is no telemetry subsystem and no token/cost
> telemetry phase.** Metrics are **feature-local and optional**; unavailable metrics are marked **UNVERIFIED**
> and never block the roadmap. **P0-BENCH is the only foundational layer**, and it is self-contained.
>
> Evidence tags: **OBSERVED** (verified in repo) · **SUPPORTED** (external literature) · **INFERRED** ·
> **SPECULATIVE** · **UNVERIFIED** (benefit not yet measured). No "unseen anywhere" claims without strong
> evidence. The fixed thesis is unchanged: HuntMCP is a **proof / causal-validation engine (CEM)**; Phase-1 CEM
> is the current focus and is untouched by everything here.

---

## 0. Corrected principles (binding on the whole document)

1. `audit_log.py` is out of the roadmap dependency graph; it stays exactly as implemented. **(OBSERVED baseline
   preserved.)**
2. No telemetry subsystem is required or proposed.
3. No token/cost telemetry phase exists.
4. Metrics are feature-local and optional — a number is added only when one feature needs it and can obtain it
   with a small isolated mechanism *local to that feature*, using existing state where available.
5. Any metric not cleanly available is **UNVERIFIED** and is never a gate.
6. **P0-BENCH is the only foundational validation layer**, and it does not read `audit_log` — it inspects the
   findings and case-store state produced by running the range.
7. Capability-first development is the primary strategy.
8. **VAL-AUTHZ** and **DISC-VARIANT** are the high-value capability bets.
9. **DISC-SPEC** supports discovery, authz, and scanning.
10. **ARCH-STATE** is reliability / provenance / resumability work — **not** a token-saving project.
11. case.db concurrency fixes are prerequisites **only** for multi-writer state work.
12. **EFF-SCHED-v0** uses **only existing case.db signals** (no telemetry dependency).
13. EFF-SCHED-v1 / VOC / BED is **optional future** work, never a gate.
14. **EFF-ALLOC** stays owned by [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md) and is not
    duplicated.
15. **DISC-GRAPH** is experimental: a minimal best-first over a SQLite adjacency table must first beat the
    current 15-template chainer on P0-BENCH before any richer planner is considered.
16. Knowledge-graph infrastructure is optional and not assumed necessary.
17. Any target-derived knowledge/state must preserve provenance and poisoning resistance.
18. Token/context/cost efficiency remains desirable but is **never a hard constraint when it conflicts with
    security capability.** Security capability is the only hard floor.

---

## 1. Executive Summary

HuntMCP already has a strong safety substrate, an evidence-gated structured case store, and a Phase-1 CEM engine
in progress. The next-generation leverage is **capability**, validated by a single self-contained benchmark
foundation:

- **P0-BENCH** — the only foundation. A standing ground-truth range that proves capability/coverage/validation/
  FP by inspecting findings + case state. No dependency on `audit_log` or telemetry.
- **VAL-AUTHZ** — the top capability bet: stateful, multi-step authorization testing with a ground-truth-fetch
  oracle, extending the existing `idor-mcp` sweep. Targets the class the literature says humans still win
  (business logic / authorization).
- **DISC-VARIANT** — the differentiated moat-widener that rides CEM's own machinery to find nearby variants.
- **DISC-SPEC** — surface expansion (OpenAPI/GraphQL) feeding both authz and scanning.
- **ARCH-STATE + EFF-SCHED-v0** — a reliability/resumability substrate and a better experiment-ordering
  heuristic using only existing case.db state. Efficiency is welcome but **UNVERIFIED**, never a constraint.

Everything else (attack-state graph planning, unified/graph knowledge, VOC scheduling, adaptive allocation) is
**experimental, optional, or already-owned**, deferred until P0-BENCH can justify it.

**Only hard constraint:** no regression in high/critical discovery, coverage, validation depth, exploitability
reasoning, attack-chain discovery, evidence quality, or false-positive resistance. Efficiency never overrides
this.

---

## 2. Baseline classification (corrected, verified)

Legend: **[IMPLEMENTED]** works today · **[WEAK]** exists but limited · **[PROPOSED]** new capability ·
**[EXPERIMENTAL]** prototype-gated · **[OPTIONAL]** only if a feature needs it · **[OWNED-ELSEWHERE]**.

| Component | Class | Reality (OBSERVED unless noted) |
|---|---|---|
| Per-agent MCP scoping | **[IMPLEMENTED]** | Global `tools:false` + per-agent allowlists; ~36–38% context cut; ~99.6% cache-read. **This is the current context-reduction baseline and must not be re-proposed** (see §3). |
| `audit_log.py` | **[IMPLEMENTED, frozen]** | Per Tier-2 call: tool, redacted args, returncode, `duration_ms`, block. **Out of the roadmap; unchanged; not a dependency.** |
| `budget_guard` | **[IMPLEMENTED]** | Call counts by tool; 500-call breaker; 70/85/95 bands. Usable as an *existing* signal, not extended. |
| `case_store` | **[IMPLEMENTED]** | hypotheses→evidence→findings→experiments→root_causes; content-addressed evidence; evidence-gated confirm; confidence scoring; `experiments` has `cost` + `finding_id`. **WAL + foreign_keys, no `busy_timeout`.** |
| `file_lock` | **[IMPLEMENTED]** | flock on budget/work/findings JSON; **does not cover case.db.** |
| `job_runtime` | **[IMPLEMENTED]** | background subprocess; returns full stdout/stderr on done-poll; **unlinks temp files** (no durable raw store). |
| CEM (`cem_engine`) | **[IMPLEMENTED, Phase-1 in progress]** | determinism gate, classify, minimal/alternate/AND sets, poc minimization, bundle; conditions human-supplied in Phase 1. |
| Chaining (`chainer-mcp`) | **[WEAK]** | 15 static templates matched by `required_findings`; not a search. |
| Authz/IDOR (`idor-mcp`) | **[WEAK]** | single-request, two-account replay with pair classification. |
| Memory (`memory.db`) | **[IMPLEMENTED]** | global, structured, `search_by_tech`; **not cross-referenced or fed into prioritization.** |
| Writeup RAG / lessons | **[IMPLEMENTED / WEAK]** | ChromaDB technique RAG; lessons is freeform markdown, not queryable signals. |
| `model_gateway` | **[IMPLEMENTED, static]** | per-role env selection. Adaptive routing is **[OWNED-ELSEWHERE]** (the memo). |
| Next-action (`suggest_next_action`) | **[WEAK]** | trivial "finish what's in flight" heuristic. |
| Safety substrate | **[IMPLEMENTED]** | scope/budget/dedupe/work-registry/redact/content_scanner/stuck_detector + `rm` hard-block. Keep intact. |

---

## 3. Efficiency & the context baseline (no re-proposal, no telemetry subsystem)

**The context-reduction win already exists.** OpenCode per-agent MCP scoping (global `tools:false` + per-agent
allowlists) already delivers the ~36–38% reduction (~47K → ~29.5K real scoped HuntBrain) with ~99.6%
continued-turn cache-read — **OBSERVED**. v3 **does not re-propose** this and does not build on top of it as a
"further optimization" phase.

**No telemetry subsystem.** There is no P0-TEL phase, no audit_log extension, no OpenCode token/cost spike on
any path. If a specific future feature needs a specific number, it may read what **already exists**
(`budget_guard` call counts, `case_store.experiments.cost`/`finding_id`, `duration_ms` already recorded by
audit_log without modifying it, findings/status in case.db) via a small mechanism **local to that feature**.
Anything not cleanly available is **UNVERIFIED** and does not block anything.

**Efficiency posture (priority order, §0.18):** capability first; validation quality; useful work per resource;
reduce waste; reduce tokens/cost only where capability is not harmed. Any efficiency figure in this document is
tagged UNVERIFIED unless it can be shown on P0-BENCH without new instrumentation. **We do not invent token/cost
improvements.**

---

## 4. Dependency graph (rebuilt from scratch, capability-first)

Two parallel tracks. `audit_log` and telemetry appear **nowhere**. P0-BENCH is the only shared foundation, and
it is self-contained.

```
                 ┌────────────────────────────────────────────┐
                 │  Phase-1 CEM (existing) ships first          │
                 │  (only DISC-VARIANT / VAL-COND / LEARN-SIG   │
                 │   depend on it)                              │
                 └────────────────────────────────────────────┘
                                    │
                 ┌──────────────────┴───────────────────┐
                 ▼                                        ▼
        CAPABILITY TRACK                        RELIABILITY / EFFICIENCY-SUPPORT TRACK
   ────────────────────────────            ──────────────────────────────────────────
   P0-BENCH  (foundation; self-contained; gates all A/B claims on BOTH tracks)
        │                                        │
        ├── VAL-AUTHZ (min) ◄── DISC-SPEC        ├── EFF-SCHED-v0  (existing case.db signals only)
        │                                        │
        ├── DISC-VARIANT (post-CEM)              └── case.db concurrency fix
        │                                              └── enables ► ARCH-STATE (multi-writer),
        └── VAL-COND (later)                                          ARCH-PAR (experimental)
        │
        └── DISC-GRAPH (experimental; best-first; must beat 15-template chainer on P0-BENCH)

   OPTIONAL / OWNED-ELSEWHERE (no position on the critical path):
     LEARN-XREF (SQLite cross-ref)  ·  LEARN-SIG (experimental, post-CEM)
     EFF-SCHED-v1 / VOC / BED (optional future)  ·  EFF-ALLOC (memo)  ·  knowledge graph (only if XREF fails)
```

Key properties:
- **No serial chain.** Capability work (VAL-AUTHZ) does not wait behind any measurement work.
- **P0-BENCH is the only foundation**, needed to *validate* both tracks, not to *run* them.
- **case.db concurrency fix gates only multi-writer state work** (ARCH-STATE multi-writer, ARCH-PAR) — nothing
  else.
- **EFF-SCHED-v0 depends on nothing new** (reads existing case.db).
- **No circular dependencies.** No dependency on `audit_log` or telemetry anywhere.

---

## 5. Major proposals (full template each)

Template fields: current baseline · exact gap · proposed mechanism · security-capability impact · efficiency
impact · dependencies · complexity · risks · benchmark · rollback · exit · confidence.

### 5.1 P0-BENCH — self-contained validation foundation  · **[PROPOSED, foundational]**
- **Current baseline (OBSERVED):** CEM constructed testbed + blind-manifest / evaluator-only-key split exist
  (`test_cem_scenarios_blind.py`).
- **Exact gap:** no standing *multi-class* range with a frontier reference arm for A/B-ing capability changes
  outside CEM.
- **Proposed mechanism:** extend the testbed **additively** (no edits to existing ground truth; benchmarks.md
  approval) into a multi-class range (authz single/multi-step, SSRF, injection, chains with ≥2 paths,
  interaction-only, nondeterminism red herrings) + a frontier-heavy reference arm. Measurement is by
  **inspecting findings + case-store state after a run** — **not** by reading `audit_log` or any telemetry.
- **Security-capability impact:** HIGH (indirect) — makes non-regression provable; enforces the hard floor.
- **Efficiency impact:** none directly; enables honest, UNVERIFIED-until-measured efficiency comparison.
- **Dependencies:** none.
- **Complexity:** MED. **Risks:** LOW (benchmark integrity — additive only, human-approved).
- **Benchmark:** self-consistency of planted labels; frontier arm reproducible.
- **Rollback:** additive/removable scenarios. **Exit:** frontier baseline + planted labels reproducible per
  benchmarks.md; a capability change can be scored against it without new instrumentation.
- **Confidence:** HIGH.

### 5.2 VAL-AUTHZ — stateful authorization differential engine  · **[PROPOSED, top capability bet]**
- **Current baseline (OBSERVED):** `idor-mcp sweep_idor` = single-request, single-endpoint, two-account replay
  with pair classification.
- **Exact gap (SUPPORTED — AuthProbe/BACFuzz/RESTler):** (1) multi-step workflows (authz at step 1, an
  unrevalidated id carried into step 2); (2) a ground-truth-fetch oracle (compare cross-account response to the
  true owner's fetch, not status/length); (3) an identity/role matrix (unauth, low-priv, admin, tenant-B).
- **Proposed mechanism (smallest useful first):** strengthen the sweep's oracle to **owner-fetch-and-compare**;
  add a **two-step replay primitive** (capture a short workflow as A, replay step N under B while holding
  earlier steps, classify the same way); emit confirmed findings into `case_store.create_finding` with candidate
  CEM conditions (identity, step-order, carried id).
- **Security-capability impact:** HIGH — the human-advantage class; new multi-step authz findings the sweep
  misses.
- **Efficiency impact:** neutral (UNVERIFIED); not the point.
- **Dependencies:** benefits from DISC-SPEC; validated on P0-BENCH. **Not** dependent on telemetry.
- **Complexity:** MED. **Risks:** state-changing mutations (idempotent default; UD-4 human gate); oracle FPs
  (mitigated by owner-fetch compare). `scope_guard` on every request; reuse `http_probe.py`.
- **Benchmark:** planted multi-step authz labels on P0-BENCH.
- **Rollback:** flag off → existing sweep. **Exit:** recovers multi-step authz findings the sweep misses, **zero
  new false positives**, verdicts agree with ground truth.
- **Confidence:** HIGH.

### 5.3 DISC-SPEC — spec-driven surface expansion  · **[PROPOSED, supporting]**
- **Current baseline (OBSERVED):** `endpoint_template.py` + secrets-mcp `extract_endpoints` pull route literals
  from JS; recon mines JS/crawls.
- **Exact gap:** OpenAPI/GraphQL schemas and their stateful operation shapes aren't parsed into the endpoint/
  parameter model.
- **Proposed mechanism:** parse OpenAPI/GraphQL (hand-rolled first; a parser lib only if proven necessary) into
  a stateful endpoint/parameter model feeding scan targeting and VAL-AUTHZ workflow capture.
- **Security-capability impact:** MED — shadow/zombie endpoints + richer authz inputs; improves coverage.
- **Efficiency impact:** neutral/positive (fewer blind fuzz calls; UNVERIFIED).
- **Dependencies:** none (feeds VAL-AUTHZ/scan). **Complexity:** MED. **Risks:** parser edge cases; treat spec
  as untrusted data.
- **Benchmark:** endpoints recovered beyond crawl on P0-BENCH.
- **Rollback:** disable spec ingestion. **Exit:** measurable surface gain feeding authz/scan.
- **Confidence:** MED.

### 5.4 DISC-VARIANT — counterfactual variant discovery  · **[PROPOSED, differentiated; post-CEM]**
- **Current baseline (OBSERVED):** CEM records an incidental "capability survives under a different value/state"
  observation if it falls out of a necessity trial (XYZ.md §2.7 — Phase-1 records, Phase-4 acts);
  `dedupe_check` avoids double-reporting.
- **Exact gap:** no **active** neighboring probing; variants are only noticed if they happen to fall out.
- **Proposed mechanism (rides CEM, no new engine):** perturb a confirmed condition to an adjacent value/
  identity/endpoint and re-test; reuse CEM's minimal-set machinery to extract signatures; prioritize variants
  by signature similarity + severity potential; validate through the same CEM oracle + evidence gate.
- **Security-capability impact:** HIGH — often higher-severity adjacent findings; unique to the CEM design.
- **Efficiency impact:** neutral (UNVERIFIED).
- **Dependencies:** CEM Phase 1; validated on P0-BENCH. **Complexity:** MED (low marginal — reuses CEM).
- **Risks:** state-changing perturbation (human gate); mislabeling a known finding as a variant (dedupe).
- **Benchmark:** planted variants surfaced per finding on P0-BENCH.
- **Rollback:** disable active probing (fall back to incidental recording). **Exit:** variants recovered that
  the incidental path misses, zero double-reports.
- **Confidence:** MED (novelty is a *combination* claim — "to our knowledge," not "unseen").

### 5.5 VAL-COND — autonomous CEM condition extraction  · **[PROPOSED, later]**
- **Current baseline (OBSERVED):** CEM conditions are human-supplied in Phase 1 (deliberate, for trust).
- **Exact gap:** conditions aren't derived from the case/experiment trace.
- **Proposed mechanism:** derive candidate perturbable conditions from case-store experiment records; keep the
  human-supplied default as fallback.
- **Security-capability impact:** MED — autonomy for the moat without weakening trust gates.
- **Efficiency impact:** neutral. **Dependencies:** CEM Phase 1 shipped; P0-BENCH.
- **Complexity:** MED. **Risks:** low-quality auto-conditions inflating false-necessity (mitigated by CEM's own
  determinism/replication gates + benchmark).
- **Benchmark:** auto-extracted vs human-supplied conditions produce the same verdicts, no new false necessity.
- **Rollback:** revert to human-supplied. **Exit:** parity with human conditions on the red-herring benchmark.
- **Confidence:** MED. **Defer** until CEM Phase 1 is done.

### 5.6 ARCH-STATE — durable inter-agent state (reliability, not tokens)  · **[PROPOSED, supporting]**
- **Current baseline (OBSERVED):** case-mcp used by huntbrain/exploit-agent/chain-planner; recon/scan agents
  **lack** case-mcp; subagents already isolate context (HuntBrain gets summaries, not raw dumps).
- **Exact gap:** state/provenance not durable across the whole pipeline; resume-after-compaction re-derives from
  summarized-away history; recon/scan work isn't in the shared experiment ledger.
- **Proposed mechanism:** specialists write structured records + IDs to case-mcp; HuntBrain resumes from case
  views; every state fact cites a real observation (extends XYZ.md §3 anti-hallucination invariant to the state
  layer). Wiring recon/scan into case-mcp is done **only if** it demonstrably reduces duplication more than it
  costs those agents in schema tokens — a measured decision, not assumed.
- **Security-capability impact:** MED (indirect — less duplication, better resume, provenance).
- **Efficiency impact:** **UNVERIFIED** — explicitly **not** a token-saving project. Any context effect is
  within a subagent's loop and must be measured, never claimed.
- **Dependencies:** **case.db concurrency fix (§5.7) is a prerequisite for multi-writer use.**
- **Complexity:** MED. **Risks:** concurrency (see §5.7); indirection if agents round-trip for data they already
  hold (mitigation: write-through, read-on-resume).
- **Benchmark:** equal finding set with improved resume/dedup on P0-BENCH; **no capability change**.
- **Rollback:** revert to prose handoff. **Exit:** measured reliability/dedup improvement, zero finding-set
  change; recon/scan wiring adopted only if net-positive.
- **Confidence:** MED (reliability value HIGH-INFERRED; token value UNVERIFIED).

### 5.7 case.db concurrency fix  · **[PROPOSED, prerequisite for multi-writer only]**
- **Current baseline (OBSERVED):** `_get_conn` sets WAL + `foreign_keys`, **no `busy_timeout`**; `file_lock`
  does not cover case.db. Serial single-agent use is safe today.
- **Exact gap:** concurrent writers get immediate `SQLITE_BUSY`.
- **Proposed mechanism:** add `PRAGMA busy_timeout` (watch-mcp already does this); optionally route case.db
  read-modify-write through `file_lock.locked()`; bounded retry on residual busy; keep atomic finding-status/
  evidence transactions.
- **Security-capability impact:** none directly (correctness enabler).
- **Efficiency impact:** none. **Dependencies:** none. **Complexity:** LOW-MED.
- **Risks:** subtle transaction semantics (covered by a concurrency test).
- **Benchmark:** N-writer test — no lost updates, no `SQLITE_BUSY` surfaced to agents, FK/evidence invariants
  preserved.
- **Rollback:** revert PRAGMA/lock. **Exit:** concurrent writers safe. **Confidence:** HIGH.
- **Scope note:** required **only** before ARCH-STATE multi-writer / ARCH-PAR — not a global gate.

### 5.8 EFF-SCHED-v0 — better next-action from existing case.db signals  · **[PROPOSED, supporting]**
- **Current baseline (OBSERVED):** `suggest_next_action` = trivial "finish what's in flight."
- **Exact gap:** no use of novelty/severity signals already present in case.db.
- **Proposed mechanism:** upgrade the heuristic using **only existing case.db state** — novelty (untested
  vuln_class/endpoint), severity potential, finish-in-flight, avoid `check_experiment_exists` repeats.
  **No ML, no new deps, no telemetry.**
- **Security-capability impact:** neutral-to-positive (better ordering; never hard-blocks a novel angle).
- **Efficiency impact:** fewer wasted round-trips — **UNVERIFIED magnitude**; validated on P0-BENCH.
- **Dependencies:** none. **Complexity:** LOW. **Risks:** premature close (severity-gated min-effort floor;
  audit suppressed experiments); easy-class bias (per-class coverage floor on P0-BENCH).
- **Benchmark:** fewer experiments-per-finding at equal recall/coverage on P0-BENCH.
- **Rollback:** revert to trivial heuristic. **Exit:** measured waste reduction with no coverage/validation
  regression. **Confidence:** MED.

### 5.9 DISC-GRAPH — attack-state graph (experimental, minimal-first)  · **[EXPERIMENTAL]**
- **Current baseline (OBSERVED):** `chainer-mcp` = 15 static templates.
- **Exact gap:** no search over reachable attack state; multi-step/composed chains not expressible.
- **Proposed mechanism (staged):** (1) minimal SQLite adjacency — nodes = capabilities/states/findings, edges =
  enables/depends-on **each citing a real observation** (poisoning/hallucination defense); (2) **best-first
  search only** (severity×confidence), budget-capped, dominated-path pruning; (3) **benchmark gate on
  P0-BENCH — must recover chains the 15-template matcher cannot, at no FP cost**; (4) only if best-first
  tunnel-visions: beam, then MCTS/planner + networkx (SUPPORTED for unknown-topology, INFERRED overkill here).
- **Security-capability impact:** HIGH (potential) — real chains beyond templates; UNPROVEN until the gate.
- **Efficiency impact:** neutral/negative during search (budget-capped).
- **Dependencies:** P0-BENCH (to justify itself); CEM signatures (as heuristics) later.
- **Complexity:** HIGH. **Risks:** complexity-as-innovation, poisoning, branching blowup (all gated).
- **Benchmark:** chain recall vs template baseline on P0-BENCH, no FP regression.
- **Rollback:** fall back to template matcher. **Exit:** best-first beats templates on the range, or the idea is
  dropped. **Confidence:** LOW (correctly experimental).

---

## 6. Optional / owned-elsewhere (lighter treatment)

- **LEARN-XREF — SQLite cross-reference + provenance  · [OPTIONAL].** Gap (OBSERVED): `memory.db` /`case.db`/
  RAG/lessons exist but aren't cross-referenced or fed into prioritization. Mechanism: a minimal cross-reference
  over existing stores via a shared vocabulary (vuln_class/endpoint/tech/cwe) + provenance, feeding a
  prioritization signal to EFF-SCHED. **Invariant:** target-derived text never writes an authoritative fact;
  only observed facts can. Isolation note: `memory.db` is global, `case.db` per-engagement — a per-engagement
  fact is not a global fact. Confidence MED; build only if a feature needs it.
- **LEARN-SIG — CEM causal-signature reuse  · [EXPERIMENTAL, post-CEM].** The memo's research bet (question C).
  Signatures are **re-confirmed hints, never skips**; nondeterministic signatures non-cacheable; oracle must
  still fire. Gated on Phase-4 signatures + measured transfer without floor breach. Confidence LOW.
- **Knowledge graph  · [OPTIONAL, not assumed necessary].** Only if SQLite cross-referencing provably hits a
  wall. Adds a **GraphRAG-poisoning** surface (GragPoison ~98%, defenses inadequate — SUPPORTED) for marginal
  early benefit. Default: **do not build.**
- **EFF-SCHED-v1 / VOC / BED  · [OPTIONAL future].** Value-of-computation / Bayesian experimental design
  (SUPPORTED). Needs cost/gain data obtained *feature-locally* only if a concrete decision requires it. Not a
  phase, not a gate. Confidence LOW.
- **ARCH-PAR — parallel solvers  · [EXPERIMENTAL].** XBOW-style breadth (SUPPORTED); requires the concurrency
  fix; table stakes, not a moat move. Defer.
- **EFF-SCAN — directed scan prioritization  · [EXPERIMENTAL].** Highest coverage risk; requires a hard
  per-class coverage floor on P0-BENCH before consideration. Defer.
- **EFF-ALLOC — adaptive intelligence allocation  · [OWNED-ELSEWHERE].** Fully specified in
  [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md); **not duplicated.** v3 does not create its
  inputs as a dependency; if the memo's Phase-5 work ever proceeds, it sources data feature-locally per its own
  plan.
- **VAL-DIFF — structural differentiation evidence  · [OWNED by XYZ.md §2.6].** Existing roadmap; not a v3
  candidate.

---

## 7. Roadmap (parallel tracks; capability-first)

All subordinate to CEM Phase 1; all research-only until authorized; no assumption every idea ships.

### Phase 0 — Foundation
- **Objective:** make capability non-regression provable. **Scope:** P0-BENCH (additive, self-contained, no
  audit_log). **Prereqs:** none. **Capability gain:** enabler. **Efficiency:** none. **Risk:** LOW (additive).
  **Benchmark:** label self-consistency + frontier arm. **Rollback:** removable scenarios. **Exit:** frontier
  baseline reproducible; any capability change scorable without new instrumentation.

### Phase 1 — Capability track (primary)
- **Objective:** widen the moat on authz + differentiated variants. **Scope:** VAL-AUTHZ(min) → DISC-SPEC (feeds
  it) → DISC-VARIANT (post-CEM) → VAL-COND (later). **Prereqs:** P0-BENCH; CEM Phase 1 for DISC-VARIANT/VAL-COND.
  **Capability gain:** HIGH. **Efficiency:** neutral (UNVERIFIED). **Risks:** mutation safety (gated), oracle FP
  (owner-fetch). **Benchmark:** planted authz/variant labels. **Rollback:** flags → existing sweep/CEM. **Exit:**
  recovers findings the baselines miss, zero new FP.

### Phase 1 (parallel) — Reliability / efficiency-support track
- **Objective:** durable state + less waste, no telemetry. **Scope:** case.db concurrency fix →
  ARCH-STATE (reliability-framed) ; EFF-SCHED-v0 (existing signals). **Prereqs:** concurrency fix before
  multi-writer ARCH-STATE. **Capability gain:** indirect. **Efficiency:** UNVERIFIED (measure, don't claim).
  **Risks:** concurrency (fixed first), premature close (floors). **Benchmark:** equal finding set at ≤
  resources; N-writer safety. **Rollback:** revert to prose/trivial heuristic. **Exit:** measured reliability/
  waste improvement, zero finding-set change.

### Phase 2 — Experimental capability
- **Objective:** prove or drop attack-state search. **Scope:** DISC-GRAPH (best-first, benchmark-gated).
  **Prereqs:** P0-BENCH. **Capability gain:** HIGH-if-proven. **Efficiency:** neutral/negative during search.
  **Risks:** complexity, poisoning. **Benchmark:** beats 15-template chainer on P0-BENCH, no FP regression.
  **Rollback:** template matcher. **Exit:** demonstrated chain-recall gain, else dropped.

### Phase 3 — Optional learning / advanced efficiency
- **Objective:** compounding learning + optional VOC efficiency + interface to the memo. **Scope:** LEARN-XREF
  (if a feature needs it) ; LEARN-SIG (experimental, post-CEM) ; EFF-SCHED-v1 (optional, feature-local data).
  **Prereqs:** CEM signatures (LEARN-SIG); a concrete decision (EFF-SCHED-v1). **Risks:** stale signatures
  (hints-not-skips), confidence theater (no invented numbers). **Benchmark:** transfer rate / experiments-per-
  finding on P0-BENCH. **Rollback:** disable. **Exit:** measured gain, no floor breach.

### Phase 4 — Optional / gated experiments
- ARCH-PAR (after concurrency fix), EFF-SCAN (per-class floor), knowledge graph (only if XREF fails). Each must
  beat its incumbent on P0-BENCH at no capability cost, or be dropped.

---

## 8. Novelty audit (honest model retained)

- **Genuinely novel:** none claimed outright.
- **Novel combination (to our knowledge underexplored):** DISC-VARIANT; CEM-signature-guided DISC-GRAPH;
  LEARN-SIG (research-worthy, unproven).
- **Novel application:** VAL-AUTHZ; ARCH-STATE (structured belief state for a security agent).
- **Established technique:** P0-BENCH, DISC-SPEC, EFF-SCHED, best-first search, LEARN-XREF.
- **Prior art (owned elsewhere):** EFF-ALLOC, model routing, cascades, RAG, MCTS/PDDL planning.

No "unseen anywhere" claims. GraphRAG-poisoning risk (SUPPORTED) preserved as a hard constraint on any
graph/knowledge candidate; provenance-of-observation invariant applies to all target-derived state.

---

## 9. What changed from V2

- **`audit_log` removed from the dependency graph entirely.** All prior references to extending it, or to it
  being a telemetry foundation, are gone. It stays frozen.
- **Telemetry subsystem eliminated.** v2's P0-TEL-TOOL / P0-TEL-LLM (spike) / two-surface telemetry design is
  **removed**. No telemetry phase exists.
- **Token/cost measurement demoted to feature-local + optional.** Metrics use existing state where available;
  anything else is UNVERIFIED and non-blocking. No token/cost improvement is asserted.
- **P0-BENCH re-specified as self-contained** — measures by inspecting findings/case state, explicitly **not**
  by reading audit_log. It remains the *only* foundation.
- **Ordering is now capability-first**: the capability track (VAL-AUTHZ/DISC-SPEC/DISC-VARIANT) leads;
  reliability/efficiency support runs in parallel and depends on nothing new except (for multi-writer) the
  concurrency fix.
- **EFF-SCHED-v0 confirmed to need no telemetry** (existing case.db signals only); EFF-SCHED-v1/VOC/BED made
  explicitly optional-future.
- **ARCH-STATE token benefit downgraded to UNVERIFIED**, reframed purely as reliability/provenance/resumability
  (already the v2 direction; v3 hardens the "not a token project" framing).
- **EFF-ALLOC's inputs are no longer created as a v3 dependency** — it stays fully owned by the memo.
- **Context-reduction baseline explicitly fenced off**: OpenCode per-agent MCP scoping is the existing baseline
  and is not re-proposed or built upon as an optimization phase.

---

## 10. Top 3–5 long-term bets

1. **P0-BENCH** — the only foundation; converts every capability claim into evidence and enforces the floor.
   Self-contained, no telemetry. *Highest confidence.*
2. **VAL-AUTHZ (minimal multi-step + owner-fetch oracle)** — clearest capability gap, cleanest existing
   baseline (`idor-mcp`), targets the human-advantage class, feeds CEM.
3. **DISC-VARIANT** — most differentiated, cheap because it rides CEM's own machinery.
4. **DISC-SPEC** — force-multiplier for both authz and scanning coverage.
5. **ARCH-STATE (reliability-framed, with the concurrency fix)** — durable/provenance substrate the later
   capability and experimental phases rely on; bet on correctness, not tokens.

Deliberately **not** top bets: DISC-GRAPH (prototype-gate it), knowledge graph (don't build), adaptive routing
(the memo owns it), any telemetry subsystem (eliminated), token-reduction-as-a-goal (fenced baseline; never a
constraint).

---

## 11. What we should NOT build yet

- **No telemetry subsystem** and **no token/cost telemetry phase.** Metrics are feature-local and optional.
- **Do not extend, replace, or depend on `audit_log.py`.**
- **Do not re-propose or build atop OpenCode MCP-scoping** — that context reduction already exists.
- **No knowledge graph** — SQLite cross-reference first; a graph only if that provably fails (and it carries a
  poisoning surface).
- **No MCTS / A\* / PDDL / networkx / RL** — best-first over SQLite first, benchmark-gated.
- **No ML/Bayesian scheduling (EFF-SCHED-v1/VOC/BED) until a concrete decision needs it** with feature-local
  data.
- **No parallel solvers (ARCH-PAR) before the concurrency fix.**
- **No directed scan prioritization (EFF-SCAN) before a proven per-class coverage floor.**
- **Do not duplicate EFF-ALLOC** — it is the memo's.
- **Do not change Phase-1 CEM methodology or the protected benchmark ground truth.**
- **Do not treat any token/cost/latency figure as a hard constraint** — capability is the only floor.

---

## 12. Confidence

- **Strategy & floor discipline:** HIGH — capability-first, CEM-untouched, audit_log-independent, extend-don't-
  multiply.
- **Capability bets (VAL-AUTHZ, DISC-VARIANT, DISC-SPEC):** MED-HIGH — existing baselines + literature;
  measurable success criteria.
- **Reliability (ARCH-STATE, concurrency fix):** MED-HIGH for correctness value; token/context value UNVERIFIED.
- **Efficiency:** intentionally UNVERIFIED — no token/cost gain asserted; only a measurement path via P0-BENCH,
  never a dependency.
- **Experimental (DISC-GRAPH, LEARN-SIG, knowledge graph):** LOW — correctly gated as prototypes.

**Overall:** v3 is capability-first, benchmark-driven, internally consistent, reconciled with the code, and free
of any `audit_log`/telemetry dependency. It commits to a validation foundation and concrete capability bets,
keeps efficiency welcome-but-optional-and-unverified, and defers all speculative infrastructure. Research-only;
no phase authorized to start.
