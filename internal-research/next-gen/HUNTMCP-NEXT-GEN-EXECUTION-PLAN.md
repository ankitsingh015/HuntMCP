# HUNTMCP-NEXT-GEN-EXECUTION-PLAN.md — Living Execution Tracker (V3 roadmap)

> Purpose: the resumable execution tracker for the capability-first V3 roadmap. A future session should read
> this file + the controlling proposal and know exactly what to do next, without conversation memory.
>
> **Controlling documents (read in this order at the start of every implementation session):**
> 1. [HUNTMCP-NEXT-GEN-PROPOSAL-v3.md](HUNTMCP-NEXT-GEN-PROPOSAL-v3.md) — the controlling roadmap (capability-first, benchmark-driven, `audit_log`/telemetry-independent).
> 2. **this file** — task status + next unfinished task.
> 3. `git status` / `git diff` — actual working-tree state.
> Then: identify the single next unfinished task and work **only** on that task.
>
> Supporting research history (finalized, do not re-litigate): [v1](HUNTMCP-NEXT-GEN-PROPOSAL.md) ·
> [audit](HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT.md) · [v2](HUNTMCP-NEXT-GEN-PROPOSAL-v2.md) ·
> [universal-capability research](UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH.md). Product spec chain:
> [XYZ.md](XYZ.md) · [PHASE1-PLAN.md](PHASE1-PLAN.md) · [PHASE1-EXECUTION-PLAN.md](PHASE1-EXECUTION-PLAN.md) ·
> [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md) · [ROADMAP.md](ROADMAP.md).

---

## Status legend
- `[ ]` NOT STARTED
- `[~]` IN PROGRESS
- `[x]` DONE (implementation + required tests + required validation all complete)
- `[!]` BLOCKED (needs a human decision or an unmet external dependency)
- `[>]` DEFERRED (intentionally not now)
- `[-]` REJECTED (decided against)

**DONE discipline:** never mark `[x]` unless implementation, required tests, and required
benchmark/validation are all complete and recorded below. Static inspection is not validation.

## Git policy (for this roadmap's artifacts)
- **Tracked & committed (permanent project knowledge):** this file, `HUNTMCP-NEXT-GEN-PROPOSAL-v3.md`, and the
  finalized research/audit docs (v1, audit, v2, universal-capability research) — intentional research history.
  **Do not** add these to `.gitignore`; **do not** broadly ignore `*.md`.
- **Gitignored (generated/local-only):** temp experiment output, raw result dumps, scratch dirs, local db
  files, lock files, runtime WAL/SHM/journal sidecars, temp measurement files, machine-specific artifacts.
- **Per-task rule:** when a task introduces a concrete generated-output path (e.g. a benchmark results dir or a
  local benchmark db), that task adds the **specific** path to `.gitignore` — never a broad wildcard — and the
  benchmark **definition / ground truth** stays tracked (per `.claude/rules/benchmarks.md`).
- **Do not commit or push** unless the workflow explicitly calls for it and the user has approved.

## Global guardrails (apply to every task)
- **Security capability is the only hard floor.** No change may regress high/critical discovery, coverage,
  validation depth, exploitability reasoning, attack-chain discovery, evidence quality, or FP resistance —
  regardless of token/cost savings.
- `audit_log.py` stays **frozen and out of the dependency graph**. No telemetry subsystem. Metrics are
  feature-local and optional; unavailable metrics are **UNVERIFIED**, never a blocker.
- **Phase-1 CEM methodology and protected benchmark ground truth are untouched** (benchmark changes are
  additive + human-approved only).
- The **OpenCode MCP-scoping baseline** and the **shared `scope_gate_hook`** are untouched.
- One coherent task per session: read state → implement → test → validate → checkpoint → update this file → stop.

---

## CURRENT STATE (update after each task — this is the resume point)

```
CONTROLLING ROADMAP:  HUNTMCP-NEXT-GEN-PROPOSAL-v3.md (capability-first)
CURRENT PHASE:        Phase 0 — Foundation (P0-BENCH)
NEXT TASK:            T-P0-BENCH  (status [ ] NOT STARTED — NOT authorized to begin yet)
BLOCKED ON:           Human approval to begin P0-BENCH implementation
LAST ACTION:          Created this tracker; added SQLite WAL/SHM/journal sidecars to .gitignore
                      (smallest safe change; no *.lock rule — tracked benchmark .lock files must not be hidden)
DO NOT:               start P0-BENCH; commit; push; touch audit_log.py / CEM methodology / benchmark ground truth
```

---

## Prerequisite (external to this roadmap, tracked for visibility)

### T-CEM1 — Phase-1 CEM vertical slice ships & passes its gates
- **Objective:** the existing trustworthy-CEM Phase 1 (owned by the product spec chain) completes.
- **Dependencies:** none here. **Status:** `[!]` BLOCKED (owned elsewhere; awaiting its own G0 approval per
  ROADMAP.md). Tracked because **DISC-VARIANT / VAL-COND / LEARN-SIG depend on it.**
- **Files/tests/validation:** per PHASE1-EXECUTION-PLAN.md G1–G9. **Notes:** not this roadmap's work; a
  dependency only.

---

## PHASE 0 — Foundation (self-contained validation)

### T-P0-BENCH — Standing multi-class ground-truth benchmark range
- **Objective:** the only foundational validation layer. Extend the CEM constructed testbed **additively** into
  a multi-class range (authz single/multi-step, SSRF, injection, chains ≥2 paths, interaction-only,
  nondeterminism red herrings) + a frontier-heavy reference arm. Measures by **inspecting findings + case-store
  state after a run** — **not** by reading `audit_log` or any telemetry.
- **Dependencies:** none to begin scaffolding; some scenarios reference CEM (T-CEM1) but the range itself is
  independent.
- **Status:** `[ ]` NOT STARTED — **do not begin until human approval.**
- **Files changed:** _(none yet)_. Planned area: `tests/fixtures/…` / a new benchmark harness dir (exact path
  TBD at design; that path's raw-output subdir gets a **specific** `.gitignore` entry as part of this task;
  ground-truth/scenario files stay tracked + integrity-locked per benchmarks.md).
- **Tests:** _(TBD)_ label self-consistency; scenario/answer-key integrity locks preserved.
- **Benchmark/validation:** frontier reference arm reproducible; a capability change can be scored without new
  instrumentation.
- **Audit/review:** _(pending)_. **Commit/PR:** _(none)_.
- **Notes/blockers:** Must be additive to existing protected CEM ground truth (no edits); benchmark methodology
  changes require human approval (benchmarks.md). Scope the design before coding.

---

## PHASE 1 — Capability track (primary) + reliability/efficiency support (parallel)

### Capability track
- `[ ]` **T-VAL-AUTHZ** — Stateful authorization differential engine (minimal). *Objective:* owner-fetch-compare
  oracle + two-step replay primitive extending `idor-mcp`; emit findings + candidate CEM conditions into
  case-mcp. *Dependencies:* T-P0-BENCH (validation); benefits from T-DISC-SPEC. *Status:* NOT STARTED.
  *Success:* recovers multi-step authz the sweep misses, **zero new FP**, verdicts match ground truth.
  *Files/tests/validation/audit/commit/notes:* _(pending)_. **Top capability bet.**
- `[ ]` **T-DISC-SPEC** — OpenAPI/GraphQL surface into the endpoint model (hand-rolled parse first). *Deps:*
  none; feeds T-VAL-AUTHZ + scan. *Status:* NOT STARTED.
- `[ ]` **T-DISC-VARIANT** — Active counterfactual variant probing (rides CEM machinery). *Deps:* T-CEM1,
  T-P0-BENCH. *Status:* NOT STARTED (blocked on T-CEM1). **Differentiator.**
- `[ ]` **T-VAL-COND** — Autonomous CEM condition extraction (human-supplied default retained). *Deps:* T-CEM1,
  T-P0-BENCH. *Status:* NOT STARTED (later).

### Reliability / efficiency-support track (parallel; no telemetry dependency)
- `[ ]` **T-CONCURRENCY** — case.db concurrency fix: add `PRAGMA busy_timeout` (+ optional `file_lock` on
  case.db read-modify-write), bounded retry, atomic finding-status/evidence transactions + an N-writer test.
  *Deps:* none. *Status:* NOT STARTED. **Prerequisite for any multi-writer state work only.**
- `[ ]` **T-ARCH-STATE** — Durable inter-agent state (reliability/provenance/resumability — **not** a token
  project; token benefit UNVERIFIED). Recon/scan wiring into case-mcp only if measured net-positive. *Deps:*
  T-CONCURRENCY (for multi-writer), T-P0-BENCH. *Status:* NOT STARTED.
- `[ ]` **T-EFF-SCHED-v0** — Better `suggest_next_action` from **existing case.db signals only** (novelty +
  severity + in-flight; avoid `check_experiment_exists` repeats). No ML, no new deps, no telemetry. *Deps:*
  none (validate on T-P0-BENCH). *Status:* NOT STARTED. *Guardrail:* never hard-block a novel angle; per-class
  coverage floor.

---

## PHASE 2 — Experimental capability

- `[>]` **T-DISC-GRAPH** — Attack-state graph, **minimal-first**: SQLite adjacency + **best-first only**, each
  edge citing a real observation. **Benchmark gate:** must recover chains the 15-template chainer cannot on
  T-P0-BENCH at no FP cost **before** any beam/MCTS/A*/PDDL/networkx. *Deps:* T-P0-BENCH. *Status:* DEFERRED
  (experimental; gate not yet met). *Notes:* do not adopt a complex planner because it sounds advanced.

---

## PHASE 3 — Optional learning / advanced efficiency

- `[>]` **T-LEARN-XREF** — SQLite cross-reference + provenance over existing stores (memory.db/case.db/RAG/
  lessons); target-derived text never writes an authoritative fact. Build only if a feature needs it. *Status:*
  DEFERRED.
- `[>]` **T-LEARN-SIG** — CEM causal-signature reuse (hints-not-skips; nondeterministic signatures
  non-cacheable). *Deps:* T-CEM1 (+ later signatures). *Status:* DEFERRED (experimental).
- `[>]` **T-EFF-SCHED-v1** — VOC/BED scheduling using feature-local cost/gain data, only if a concrete decision
  needs it. *Status:* DEFERRED (optional future).
- `[>]` **T-EFF-ALLOC** — Adaptive intelligence allocation. *Status:* DEFERRED — **OWNED by
  INTELLIGENCE-ALLOCATION-MEMO.md; not duplicated here.**

---

## PHASE 4 — Optional / gated experiments

- `[>]` **T-ARCH-PAR** — Parallel solvers. *Deps:* T-CONCURRENCY. *Status:* DEFERRED (table stakes, not moat).
- `[>]` **T-EFF-SCAN** — Directed scan prioritization. *Status:* DEFERRED — requires a proven per-class coverage
  floor first (highest coverage-regression risk).
- `[>]` **T-KNOWLEDGE-GRAPH** — Only if T-LEARN-XREF provably hits a wall (carries GraphRAG-poisoning risk).
  *Status:* DEFERRED / default do-not-build.

---

## V4 — Conditional architecture item

- `[>]` **T-UNIV-CAP** — Universal capability/tool-policy layer (registry → resolver → runtime config
  generator; optional proxy only for a non-filtering runtime). Per
  [UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH.md](UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH.md): **conditional** —
  build only when a genuine third runtime appears **or** dynamic-specialist scale makes hand-scoping a measured
  drift/error source. Interim cheap mitigation option: a cross-runtime allowlist **drift-check test**. Delivers
  maintainability/portability/least-privilege consistency — **not** new context reduction. *Status:* DEFERRED
  (conditional).

---

## Completed research/architecture artifacts (history)

- `[x]` V1 next-gen proposal — `HUNTMCP-NEXT-GEN-PROPOSAL.md`.
- `[x]` Skeptical audit — `HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT.md`.
- `[x]` V2 (audit-corrected) — `HUNTMCP-NEXT-GEN-PROPOSAL-v2.md`.
- `[x]` V3 (capability-first; controlling) — `HUNTMCP-NEXT-GEN-PROPOSAL-v3.md`.
- `[x]` Universal-capability research note — `UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH.md`.
- `[x]` This execution tracker created.
- `[x]` `.gitignore`: SQLite WAL/SHM/journal sidecar ignore added (smallest safe change; no `*.lock` rule —
  tracked benchmark `.lock` integrity files preserved).

---

## Change log
- **(this session)** Tracker created; `.gitignore` gained `*.db-wal` / `*.db-shm` / `*.db-journal`. No code,
  no commit, no push. P0-BENCH not started (awaiting approval).
