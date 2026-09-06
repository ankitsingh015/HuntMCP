# ROADMAP.md — HuntMCP Persistent Project Roadmap

> Purpose: make the project **resumable across future Claude Code sessions**. A new session should be able to
> read this file (plus [PHASE1-PLAN.md](PHASE1-PLAN.md) and [PHASE1-EXECUTION-PLAN.md](PHASE1-EXECUTION-PLAN.md))
> and know exactly where things stand, what to do next, and what must NOT be touched yet — without any
> conversation memory.

**Canonical spec chain:** [XYZ.md](XYZ.md) (thesis + architecture) → [PHASE1-PLAN.md](PHASE1-PLAN.md) (Phase-1
spec) → [PHASE1-EXECUTION-PLAN.md](PHASE1-EXECUTION-PLAN.md) (implementation-ready Phase-1 plan) →
[INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md) (future-work research memo, NOT Phase 1).

The central thesis is fixed and NOT to be re-litigated without a concrete correctness problem: **HuntMCP is a
proof / causal-validation engine (CEM), not a discovery-throughput engine.**

---

## Phase sequence (high-level; only Phase 1 is detailed elsewhere)

### Phase 0 — Substrate / read-model cleanup
- **Objective:** ensure the substrate CEM builds on is coherent — the case store, evidence store, audit log,
  scope/budget guards, and the `idor_sweep` HTTP primitive — and that an observed evidence model can be built
  from data HuntMCP already produces, with no new probing.
- **Major capabilities:** verified reuse map of existing primitives; any behavior-preserving refactor needed to
  share the HTTP fetch primitive cleanly (see PHASE1-EXECUTION-PLAN Unresolved Decision UD-1).
- **Dependencies:** none beyond the current repo.
- **Expected outcome:** a confirmed, documented foundation; deviations between plan assumptions and repo reality
  recorded.
- **Exit/acceptance concept:** the reuse map is validated against the repo; the existing test suite is green;
  no new behavior introduced.
- **Current status:** **effectively COMPLETE as analysis** (the repo-exact reuse map is captured in
  PHASE1-EXECUTION-PLAN §5). Any shared-primitive refactor is folded into Phase 1 Group A.

### Phase 1 — Scientifically-trustworthy CEM vertical slice  ← **CURRENT IMPLEMENTATION FOCUS**
- **Objective:** prove *"Given a confirmed vulnerability and candidate conditions, HuntMCP can experimentally
  determine which tested conditions are necessary, which appear unnecessary, and which remain inconclusive,
  while detecting uncontrolled nondeterminism and producing reproducible evidence."*
- **Major capabilities:** condition model + machine-checkable success oracle; determinism/stability gate;
  one-variable-at-a-time replicated counterfactual interventions; confounder pinning where feasible; verdicts
  `necessary / apparently_not_necessary / inconclusive` (+ `interacting`, + `probabilistic` for races);
  multiple minimal condition sets where feasible; delta-debugging PoC minimization after causal evidence;
  Triager-Proof Bundle; full scope/rate/budget/audit preservation; constructed ground-truth benchmark;
  false-causal-conclusion-rate release gate.
- **Dependencies:** existing `case_store.py`, `case-mcp`, `idor_sweep.py` primitives, guards, audit/evidence
  stores. Zero new MCP servers, zero new runtime dependencies.
- **Expected outcome:** CEM runs post-validation on confirmed findings, emits trustworthy structured output,
  and never emits a false necessity claim on the benchmark.
- **Exit/acceptance concept:** all acceptance gates G1–G9 pass (see PHASE1-EXECUTION-PLAN §13), headline gate =
  **false-causal-conclusion-rate == 0** on the constructed benchmark.
- **Current status:** **PLANNING COMPLETE, implementation NOT started.**

### Phase 2 — Autonomous hunting capability expansion  *(FUTURE — high-level only)*
- **Objective:** expand discovery breadth toward the publicly-disclosed capability baseline of XBOW-class
  systems (parallel-solver breadth, provider selection via existing `model_gateway`, headless-browser/OOB
  harness already partly present).
- **Major capabilities:** broader autonomous surface coverage; treated as table-stakes, not the differentiator.
- **Dependencies:** stable Phase-1 baseline; existing recon/scan/exploit agents.
- **Expected outcome:** competitive discovery throughput without regressing finding quality.
- **Exit/acceptance concept:** measured coverage/throughput gain with no quality-floor regression.
- **Current status:** **FUTURE — not to be detailed or started.**

### Phase 3 — CEM + autonomous hunting integration  *(FUTURE — high-level only)*
- **Objective:** wire CEM to run automatically after each independently-validated finding; add structural
  differentiation evidence vs disclosed reports.
- **Dependencies:** Phase 1 (CEM) + Phase 2 (autonomous baseline).
- **Expected outcome:** every validated finding flows into CEM as part of the hunt.
- **Exit/acceptance concept:** CEM-in-hunt with no material hot-path slowdown.
- **Current status:** **FUTURE.**

### Phase 4 — Causal-signature-driven variant discovery / experimentation  *(FUTURE — high-level only)*
- **Objective:** use CEM minimal-condition-set signatures to generate/prioritize variants and adjacent findings.
- **Dependencies:** Phase 3.
- **Expected outcome:** reusable causal signatures drive variant hunting.
- **Exit/acceptance concept:** measurable variant yield with preserved false-positive discipline.
- **Current status:** **FUTURE.**

### Phase 5 — Advanced uncertainty, coverage-gap experimentation, adaptive intelligence allocation, continuous learning  *(FUTURE — high-level only)*
- **Objective:** uncertainty/coverage-gap-driven experiment selection; continuous learning; and the
  **intelligence-allocation** research direction (reduce unnecessary expensive reasoning while preserving
  security outcomes) — **only where experimentally justified**.
- **Dependencies:** Phases 2–4; the research memo's A/B/C/D experiment (see INTELLIGENCE-ALLOCATION-MEMO.md).
- **Expected outcome:** efficiency gains that provably respect a security-quality floor.
- **Exit/acceptance concept:** constrained-optimization result — cost reduced subject to no high/critical
  regression.
- **Current status:** **FUTURE / HYPOTHESIS.** Model routing / adaptive model selection is **explicitly NOT
  Phase 1** and remains a hypothesis until experimentally validated. Signatures are **not assumed to transfer**
  across targets.

---

## Standing rules (apply to every phase)
1. **Phase 1 is the current focus.** Phases 2–5 are future work and must not be prematurely detailed or locked.
2. **Intelligence allocation / model routing is NOT part of Phase 1.**
3. **Future research directions remain hypotheses** until experimentally justified.
4. **Do not weaken CEM methodology** (determinism gate, replicated arms, verdict labels) to hit a metric.
5. **Never delete or weaken an acceptance test** to obtain a pass.
6. **CEM stays post-validation** and must not materially slow normal hunting when inactive.
7. Preserve existing HuntMCP behavior and finding quality (regression gate G1).

---

## PROJECT STATE  (update this block after each milestone — this is the resume point)

```
CURRENT PHASE:        Phase 1 — scientifically-trustworthy CEM vertical slice
CURRENT MILESTONE:    Phase 1a testing-architecture hardening COMPLETE & verified; CEM engine NOT started (awaiting G0)
STATUS:               PLANNING (no implementation code written)
COMPLETED:            - XYZ.md thesis + architecture (approved)
                      - PHASE1-PLAN.md spec (approved)
                      - INTELLIGENCE-ALLOCATION-MEMO.md future-work review (delivered)
                      - Repo-exact reuse map verified (PHASE1-EXECUTION-PLAN §5)
                      - ROADMAP.md + PHASE1-EXECUTION-PLAN.md authored
                      - UD-1..UD-4 resolved & recorded (PHASE1-EXECUTION-PLAN §2; task A1 [x])
                      - Phase-1 TEST-ENVIRONMENT SUBSTRATE built & verified (A3/H1/H2)
                      - Phase-1a TESTING-ARCHITECTURE HARDENING complete & verified (A1-A4, B1-B3):
                        blind scenario manifest + evaluator-only answer key (split, both integrity-locked),
                        independent evaluator (FCCR/coverage/missed/FP/reproducibility), evidence trail,
                        vulnerable/patched mutation target, loopback-only, no-CEM-production guard;
                        full suite 661 green (37 CEM-env/hardening tests), no regression
IN PROGRESS:          (none — implementation not started)
BLOCKED:              Awaiting human G0 implementation approval (all design decisions now resolved)
NEXT STEP:            Human G0 approval → begin CEM engine (A2 worktree, A4 http_probe extract, then B..P) under TDD
                      (test-environment substrate already in place: bash scripts/verify-phase1.sh)
KNOWN DEVIATIONS:     RESOLVED via rulings —
                      - UD-1=B: extract shared mcp-servers/http_probe.py; idor_sweep imports it (regression-guarded)
                      - UD-2=A: CEM shares the 500-call cap + per-finding CEM request ceiling
                      - UD-3=explicit caller-supplied oracle (auto-derivation disallowed)
                      - UD-4=refuse non-idempotent perturbations by default (per-finding human exception only)
                      (Design note, not a decision) CEM HTTP path bypasses tool_resolver → rate handling is
                      executor-local (spacing + 429→inconclusive), same bypass idor-mcp already accepts.
LAST VERIFIED:        Repo read + reuse map + UD rulings recorded (this session). No code executed/changed.
NEXT ACCEPTANCE GATE: G0 — implementation approval (design decisions already resolved); then G1..G9
```

*Do not depend on conversation memory. If this block and the conversation disagree, this block (once updated by
the implementer) is authoritative for project state; the spec chain is authoritative for design.*
