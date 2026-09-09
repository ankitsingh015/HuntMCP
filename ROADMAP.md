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
CURRENT MILESTONE:    G0 implementation approval GRANTED. Pure CEM engine (Group C, C1-C8) COMPLETE and
                      MERGED to main (PR #93); Group A and Group H MERGED (PRs #92/#93). Group B fully
                      RECOVERED & VERIFIED on the completion branch 2026-09-07: B1 (4-table CEM schema in
                      case_store._init_schema() + 19 schema-contract tests), B2 (CEM_TRIAL_ARMS/CEM_VERDICTS
                      constants + the 4 CRUD helpers cem_define/cem_record_trial/cem_record_verdict/
                      cem_load_state), B3 (6 cascade-delete/deep-isolation tests + helpers; test file now 25
                      tests). Full suite 917 green; case_store.py byte-identical to the
                      phase1-cem-implementation-6e1693 copy modulo two disclosed doc-comment lines,
                      test_cem_case_store.py byte-identical modulo its module docstring.
                      Group D (intervention executor) COMPLETE 2026-09-07 in cem_engine.py — D1 (Controls +
                      apply_control_gate), D2 (run_intervention + Trial), D3 (throttled_in + apply_throttle_gate
                      + run_intervention 429-abort). Group E (MCP tool integration) COMPLETE 2026-09-07 in
                      case-mcp/server.py — E1 (6 CEM @app.tool() wrappers delegating to cem_engine +
                      case_store; senders send via http_probe.fetch, persist cem_trials/cem_verdicts), E2
                      (budget_guard.enforce per request + audit_log.log_call once per call, idor-mcp pattern;
                      + B-1 _make_budget_cb/_sender_run de-dup + T-2), E3 (CONFIRMED/IMPACT_PROVEN guard on
                      define_conditions + both senders; SuccessSignature.from_dict validation, UD-3; new
                      case_store.get_finding()). New tests/test_cem_mcp.py (18) + tests/test_cem_safety.py
                      (26). Full suite 1037 green; every design decision human-approved via AskUserQuestion.
                      E3 awaiting review. Nothing from Group B, D or E is on main yet (uncommitted working-tree
                      state). Groups F-P not started. Phase-1 acceptance gate (G1-G9 via
                      scripts/verify-phase1.sh) still PENDING.
STATUS:               IMPLEMENTATION IN PROGRESS — CEM Phase-1 completion effort (runtime / MCP integration /
                      safety / evidence persistence / end-to-end benchmark + FCCR). One task at a time.
COMPLETED:            - XYZ.md thesis + architecture (approved)
                      - PHASE1-PLAN.md spec (approved)
                      - INTELLIGENCE-ALLOCATION-MEMO.md future-work review (delivered)
                      - Repo-exact reuse map verified (PHASE1-EXECUTION-PLAN §5)
                      - ROADMAP.md + PHASE1-EXECUTION-PLAN.md authored
                      - UD-1..UD-4 resolved & recorded (PHASE1-EXECUTION-PLAN §2; task A1 [x])
                      - Phase-1 TEST-ENVIRONMENT SUBSTRATE built & verified (A3/H1/H2)
                      - MERGED to main via PR #92 (3cb25bb): Group H benchmark environment
                        (tests/fixtures/cem_target/*, tests/test_cem_environment.py) + Phase-1a
                        TESTING-ARCHITECTURE HARDENING (blind scenario manifest + evaluator-only answer key,
                        both integrity-locked; independent evaluator for FCCR/coverage/missed/FP/repro;
                        evidence trail; vulnerable/patched mutation target; loopback-only guard) + A3 baseline
                        (docs/cem-phase1-baseline.txt). (661 green at that milestone, no regression.)
                      - MERGED to main via PR #93 (796831a): Group A/A4 (mcp-servers/http_probe.py extract +
                        idor_sweep.py re-export refactor); Group C C1-C8 pure CEM engine
                        (mcp-servers/cem_engine.py + tests/test_cem_engine.py), incl. 2 retrospective C1-C8
                        audit-fix rounds + the C6 AND-necessity addendum; planning docs (ROADMAP.md,
                        PHASE1-PLAN.md, PHASE1-EXECUTION-PLAN.md, XYZ.md, INTELLIGENCE-ALLOCATION-MEMO.md).
                        This-branch full suite: 892 green (2026-09-07).
NOT ON MAIN:          - Group B (B1+B2+B3) + Group D (D1+D2+D3) + Group E (E1+E2+E3): uncommitted working-tree
                        changes on the completion branch (claude/cem-phase-1-completion-1a5cd5) —
                        mcp-servers/case_store.py (B1 4 CEM tables + B2 CEM_TRIAL_ARMS/CEM_VERDICTS + 4 CRUD
                        helpers + E3 get_finding() accessor); tests/test_cem_case_store.py untracked (25);
                        tests/test_case_store.py (+1 E3 get_finding test); mcp-servers/cem_engine.py (D1-D3 —
                        C1-C8 committed bodies untouched); tests/test_cem_engine.py (+85 D1-D3 tests, purely
                        additive); mcp-servers/case-mcp/server.py (E1 6 wrappers + E2 budget/audit + B-1
                        _make_budget_cb/_sender_run + E3 _confirmed_or_error guards; existing 15 tools
                        byte-untouched); tests/test_cem_mcp.py untracked (18 E1) + tests/test_cem_safety.py
                        untracked (26 = 8 E2 + 1 B-1 + 7 E3, T-2 strengthened in place). Nothing committed to
                        main. B1-B3 recovery source of truth: the phase1-cem-implementation-6e1693 worktree
                        (branch claude/phase1-cem-implementation-6e1693, HEAD e1b9644).
IN PROGRESS:          (none) — Group B recovered & verified (917 green); Group D done & verified (1002 green);
                      Group E done & verified (1037 green; E1 18 + E2 9 + E3 8 tests). E2 audited (SAFE WITH
                      IMPROVEMENTS) → B-1 (de-dup senders via _make_budget_cb factory + _sender_run
                      contextmanager) + T-2 (strengthened partial-persistence regression) implemented +
                      re-reviewed; B-2/B-3 deferred to G1. Paused for E3 review. N2 doc-reconciliation pass
                      also done (final post-P1 read-back still pending).
BLOCKED:              (none)
NEXT STEP:            E3 review/audit (separate session). Then F1 (add "case-mcp" to
                      scope_gate_hook.TIER2_MCP_SERVERS so the two senders' url arg is scope-gated) .. P1
                      under TDD, one task at a time. Test-environment substrate already in place: bash
                      scripts/verify-phase1.sh.
KNOWN DEVIATIONS:     RESOLVED via rulings —
                      - UD-1=B: extract shared mcp-servers/http_probe.py; idor_sweep imports it (regression-guarded)
                      - UD-2=A: CEM shares the 500-call cap + per-finding CEM request ceiling
                      - UD-3=explicit caller-supplied oracle (auto-derivation disallowed)
                      - UD-4=refuse non-idempotent perturbations by default (per-finding human exception only)
                      (Design note, not a decision) CEM HTTP path bypasses tool_resolver → rate handling is
                      executor-local (spacing + 429→inconclusive), same bypass idor-mcp already accepts.
LAST VERIFIED:        2026-09-07 (E3): guards in case-mcp/server.py — define_conditions + determinism_gate +
                      run_counterfactual refuse a finding not in {CONFIRMED, IMPACT_PROVEN} (senders
                      re-check, so a post-define demotion can't send real requests; fetch spy proves 0
                      requests); define_conditions also rejects a missing/invalid success_signature via
                      cem_engine.SuccessSignature.from_dict (UD-3, no derivation). New public
                      case_store.get_finding() accessor (0 removed lines; B1/B2 CEM schema/CRUD untouched;
                      case_store.py touch was part of the human-approved guard-scope option). The 3 local
                      assemblers are NOT gated (they read vetted state, send nothing). TDD: 7 tests in
                      test_cem_safety.py + 1 in test_case_store.py, RED (AttributeError on get_finding + the
                      guard behaviours) → GREEN. cem_engine.py / test_cem_engine.py NOT touched by E3. Full
                      suite `.venv/bin/python -m pytest tests/ -q` → 1037 passed, 0 failed; test_cem_mcp.py
                      18/18, test_cem_engine.py 296/296, test_case_store.py 36→37, test_idor_mcp_server.py 3/3
                      unmodified; ruff (CI-exact) + py_compile clean, zero fixes. No commit.
                      Earlier same day: E2 + B-1/T-2 (senders de-duped via _make_budget_cb/_sender_run;
                      partial-persistence tests strengthened; B-2/B-3 deferred to G1; 1029 green).
                      Earlier same day: E1 (6 CEM @app.tool() wrappers, 18 smoke tests, 1020 green). D3
                      (THROTTLE_STATUS/throttled_in/apply_throttle_gate + run_intervention
                      429-abort, 19 tests, 1002 green). D2 (Trial + run_intervention, 25 tests, 983 green); D1 (Controls +
                      apply_control_gate, 41 tests, 958 green, one TRY004 ruff round, C1 precedent).
                      Earlier same day: B3 recovery (6 cascade tests + 3 helpers byte-for-byte; 25/25;
                      917 green; foreign_keys=OFF non-vacuity spike). B2 recovery (CEM constants + 4 CRUD
                      helpers byte-for-byte; case_store.py 723 lines; 911 green; 18-check CRUD smoke).
                      Earlier same day (B1 recovery): `tests/test_cem_case_store.py` written first → RED on
                      this branch (no such table); 4 CREATE TABLE statements added to
                      case_store._init_schema() byte-for-byte from that worktree → GREEN. Focused (B1):
                      test_cem_case_store.py 19/19, test_case_store.py 36/36 (unmodified), test_cem_engine.py
                      211/211 (unmodified). Full suite `.venv/bin/python -m pytest tests/ -q` → 911 passed,
                      0 failed. ruff clean on both changed files. No commit.
NEXT ACCEPTANCE GATE: G0 GRANTED. Next: Phase-1 acceptance gates G1..G9 via scripts/verify-phase1.sh
                      (run only after D-P prerequisites are implemented and reviewed) — still PENDING.
```

*Do not depend on conversation memory. If this block and the conversation disagree, this block (once updated by
the implementer) is authoritative for project state; the spec chain is authoritative for design.*
