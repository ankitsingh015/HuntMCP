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
CURRENT MILESTONE:    G0 implementation approval GRANTED. main HEAD = 517dc1c.
                      MERGED to main: Group A + Group H + Phase-1a hardening (PR #92, 3cb25bb);
                      A4 + Group C C1-C8 pure engine + planning docs (PR #93, 796831a);
                      Group B (B1-B3 case_store CEM persistence) + Group D (D1-D3 intervention executor) +
                      Group E (E1-E3 MCP tool integration) + Group F (F1 scope gate / F2 shared 500-call cap
                      + per-finding ceiling default 200 / F3 per-trial post-perturbation scope_check /
                      F3b-UD-4 non-idempotent-refused-by-default) + G1 (adversarial stack review + the
                      determinism_gate budget-denied => "INCOMPLETE" fix) — all in PR #99 (517dc1c).
                      NOTE: the plan's original G1 content-addressed evidence hashing
                      (cem_trials.*_evidence_hash, assemble_bundle audit_trail) is UNBUILT — tracked
                      capability limitation, not a defect (docs/cem-phase1-limitations.md).
                      UNCOMMITTED on this branch (claude/cem-phase1-j1-benchmark, cut fresh from
                      origin/main@517dc1c): J1 (end-to-end six-tool pipeline vs the real loopback benchmark,
                      network not mocked), K1 CLOSED (real-CEM vs protected answer_key via
                      evaluator.evaluate(); one human-approved case_03 ruling, lock 87e0f55b=>5546f890;
                      5 strict xfails = documented Phase-2 boundaries), K2 (aggregate FCCR == 0, gate fails
                      otherwise), L1 (full suite green >= A3 baseline; test_case_store.py/test_idor_sweep.py
                      byte-identical to main; + docs/cem-phase1-limitations.md), M1 (within-process A->B->A
                      wall-clock sandwich applying §12's literal <= 1.02 to a bootstrap CI + deterministic
                      sys.setprofile CEM-isolation gate; config B: 0 cem_engine calls on the normal path,
                      0 extra HTTP), N1 (docs/cem-phase1.md), N2 (this block + PHASE1-EXECUTION-PLAN.md §19),
                      P1 (scripts/verify-phase1.sh rewritten to run the real §14 pipeline + G1-G9 verdict;
                      + phase1-report.json in .gitignore),
                      O1 (final §15 security audit -- adversarial code inspection + 3 fixes: CEM outbound
                      scheme allowlist + cloud-metadata/link-local deny [O1-1 MED / O1-2 LOW] and no-redirect
                      CEM fetch [O1-3 MED], in case-mcp/server.py + http_probe.py; tests/test_cem_o1_ssrf.py
                      NEW 20; O1-4 k>=3 floor + an RFC1918-reachability residual documented as LOW
                      non-blocking follow-ups). O1 is the first production change on this branch since PR #99
                      (2 files); J1..P1 add none.
                      P1 RAN GREEN 2026-09-11 (re-run post-O1): verify-phase1.sh exit 0, phase1-report.json
                      overall PASS -- G1 1328>=637, G2 339, G3 12, G4 20+5-approved-xfails, G5 fccr==0.0,
                      G6 247 (incl. 20 O1 tests), G7 5, G9 harness 36 + integrity 5546f890.../31862b91...
                      unchanged; G8 review-by-record.
                      Still open: I1 only (engine-branch coverage-audit formality -- G2's unit suite is green,
                      the explicit tally is unrecorded; NOT an acceptance gate).
                      HUMAN REVIEW 2026-09-11: the O1 production diff (case-mcp/server.py + http_probe.py)
                      is APPROVED. Final completion-checkpoint re-run (post-approval) of
                      scripts/verify-phase1.sh: exit 0, overall PASS, identical gate result.
                      >>> CEM PHASE 1: ACCEPTED AND FROZEN (2026-09-11). <<< G1-G9 GREEN, O1 signed off,
                      no unresolved High/Med. No further Phase-1 code/test/benchmark change is authorized
                      absent a genuine regression found later. Phase 2 NOT started.
STATUS:               CEM PHASE 1 ACCEPTED AND FROZEN -- G1-G9 GREEN via scripts/verify-phase1.sh, O1
                      security audit COMPLETE + human-approved (no unresolved High/Med). B/D/E/F/G1 on main
                      (PR #99); J1/K1/K2/L1/M1/N1/N2/P1/O1 done, uncommitted on this branch, awaiting a
                      human integration decision (finishing-a-development-branch). Only the I1 coverage-audit
                      formality is unrecorded (not a gate, not a blocker). Nothing committed/pushed/merged.
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
                      - MERGED to main via PR #99 (517dc1c) — "CEM Phase-1: intervention executor, MCP
                        integration, safety controls, evidence integrity (D-G1)":
                        Group B (case_store.py 4 CEM tables + enums + CRUD helpers; tests/test_cem_case_store.py),
                        Group D (cem_engine.py D1 Controls/apply_control_gate, D2 run_intervention/Trial,
                        D3 throttled_in/apply_throttle_gate/429-abort; C1-C8 bodies untouched),
                        Group E (case-mcp/server.py 6 CEM @app.tool() wrappers + budget/audit wiring +
                        CONFIRMED/UD-3 guards + case_store.get_finding(); existing 15 tools untouched),
                        Group F (scope_gate_hook.py TIER2_MCP_TOOLS + case-mcp _scope_or_error [F1];
                        budget_guard.enforce_cem_finding + per-finding ceiling default 200 [F2];
                        cem_engine.run_intervention scope_check [F3]; cem_engine method policy +
                        cem_meta.nonidempotent_approval [F3b/UD-4]),
                        G1 (adversarial stack review + the determinism_gate budget-denied => "INCOMPLETE"
                        fix). Original G1 content-addressed evidence hashing UNBUILT (tracked limitation).
                      - ON-BRANCH, NOT MERGED (claude/cem-phase1-j1-benchmark, uncommitted working-tree):
                        J1 — tests/test_cem_benchmark.py (end-to-end six-tool pipeline, real loopback).
                        K1 — CLOSED; K1 section in tests/test_cem_benchmark.py; tests/fixtures/cem_target/
                        answer_key.py case_03 label corrected (interacting=>necessary) + regenerated
                        answer_key.py.sha256.lock (87e0f55b=>5546f890 via integrity.update()); consequential
                        tests/test_cem_evaluator.py _correct_vulnerable() case_03 sync;
                        docs/cem-phase1-k1-decisions.md. K2 — K2 section in tests/test_cem_benchmark.py
                        (aggregate FCCR == 0). L1 — docs/cem-phase1-limitations.md (regression gate is
                        verification-only). M1 — tests/test_cem_performance.py. N1 — docs/cem-phase1.md.
                        N2 — this block + PHASE1-EXECUTION-PLAN.md §19 reconciliation update + J1..P1 task
                        notes in PHASE1-EXECUTION-PLAN.md §6.
                        P1 — scripts/verify-phase1.sh rewritten (was stubbing CEM gates as PENDING) to run
                        the §14 pipeline + emit a real G1-G9 verdict; phase1-report.json added to .gitignore.
NOT ON MAIN:          - J1 + K1 + K2 + L1 + M1 + N1 + N2 + P1 + O1 — uncommitted working-tree state on
                        claude/cem-phase1-j1-benchmark (branch cut fresh from origin/main@517dc1c, which
                        already carries B/D/E/F/G1 via PR #99). git diff --name-only HEAD:
                        PHASE1-EXECUTION-PLAN.md, ROADMAP.md, scripts/verify-phase1.sh, .gitignore,
                        mcp-servers/case-mcp/server.py (O1: _cem_outbound_policy_error + _cem_fetch + wiring),
                        mcp-servers/http_probe.py (O1: allow_redirects kw, default True),
                        tests/fixtures/cem_target/answer_key.py,
                        tests/fixtures/cem_target/answer_key.py.sha256.lock, tests/test_cem_evaluator.py,
                        tests/test_cem_g1_integration.py (O1: _cem_fetch invariant update).
                        Untracked: tests/test_cem_benchmark.py, tests/test_cem_performance.py,
                        tests/test_cem_o1_ssrf.py, docs/cem-phase1.md, docs/cem-phase1-limitations.md,
                        docs/cem-phase1-k1-decisions.md.
                        cem_engine.py / case_store.py / scope_gate_hook.py / budget_guard.py remain
                        byte-identical to HEAD (O1 touched only case-mcp/server.py + http_probe.py).
                        Nothing committed.
IN PROGRESS:          (none) — B/D/E/F/G1 on main (PR #99). J1/K1/K2/L1/M1/N1/N2/P1/O1 done and uncommitted
                      on this branch; verify-phase1.sh G1-G9 GREEN (exit 0) and O1 COMPLETE (no unresolved
                      High/Med). Every design decision human-approved via AskUserQuestion where the plan
                      named a behaviour not a signature.
BLOCKED:              (none)
NEXT STEP:            Phase 1 is ACCEPTED AND FROZEN — human review of the O1 diff is approved
                      (2026-09-11). Remaining step is a human integration decision via
                      finishing-a-development-branch — present integration options for the uncommitted
                      J1..O1 work (2 O1 production files + benchmark/perf/doc test files + state prose);
                      do NOT auto-merge. Do NOT start Phase 2. Optional non-blocking hardening follow-ups
                      recorded under §6 O1 (not required for acceptance):
                      (a) k>=3 floor in define_conditions + senders (O1-4, LOW); (b) scope_guard
                      is_safe_test_host should not pre-empt an explicit out_of_scope entry (O1-1 RFC1918
                      residual, LOW); (c) I1's formal engine-branch coverage tally (G2's unit suite is green).
KNOWN DEVIATIONS:     RESOLVED via rulings —
                      - UD-1=B: extract shared mcp-servers/http_probe.py; idor_sweep imports it (regression-guarded)
                      - UD-2=A: CEM shares the 500-call cap + per-finding CEM request ceiling
                      - UD-3=explicit caller-supplied oracle (auto-derivation disallowed)
                      - UD-4=refuse non-idempotent perturbations by default (per-finding human exception only)
                      (Design note, not a decision) CEM HTTP path bypasses tool_resolver → rate handling is
                      executor-local (spacing + 429→inconclusive), same bypass idor-mcp already accepts.
LAST VERIFIED:        2026-09-11 (FINAL PHASE-1 COMPLETION CHECKPOINT, post human O1 approval):
                      re-read `git status`/`git diff` — J1..O1 are the only Phase-1 deltas, no unrelated
                      change present (untracked `budget.json.lock`/`data/watch.db-*` are pre-existing,
                      unrelated runtime files, left untouched). Re-ran `PYTHON=.venv/bin/python bash
                      scripts/verify-phase1.sh` → exit 0, phase1-report.json overall PASS, identical to
                      the pre-approval run. CEM PHASE 1 DECLARED ACCEPTED AND FROZEN.
                      2026-09-11 (O1 final security audit + fixes; verifier re-run post-O1):
                      `PYTHON=.venv/bin/python bash scripts/verify-phase1.sh` → exit 0, phase1-report.json
                      overall PASS. Automated gates: G7 performance_non_regression 5 passed (quiet host,
                      wall-clock CI <= §12's 1.02; config B 0 cem_engine calls / 0 extra HTTP);
                      G1 regression_full_suite 1328 passed / 5 xfailed (>= 637; +20 new O1 SSRF tests);
                      G2 cem_unit_tests 339; G3 cem_integration (J1) 12; G4 cem_causal_benchmark (K1)
                      20 passed / 5 xfailed (0 XPASS); G5 fccr==0.0, 2 passed; G6 scope_rate_budget_audit
                      247 passed (incl. tests/test_cem_o1_ssrf.py 20); G9 benchmark_harness_isolation 36 +
                      integrity_start == integrity_end (answer_key.py 5546f890…, scenarios.py 31862b91…
                      unchanged). G8 review-by-record (deviations incl. the verifier rewrite + the O1 fixes
                      documented in PHASE1-EXECUTION-PLAN.md §6; pending human sign-off).
                      O1 fixes (production, 2 files): case-mcp/server.py — _cem_outbound_policy_error (scheme
                      allowlist http/https only + cloud-metadata/link-local/v4-mapped deny, on the fail-fast
                      and per-trial scope paths) + _cem_fetch (http_probe.fetch with redirects disabled);
                      http_probe.py — allow_redirects kw-only param, default True (idor_sweep unchanged).
                      All 3 reproduced exploits (file:// LFI, 169.254.169.254 IMDS, 302→internal) now
                      refused before any HTTP, nothing persisted; benchmark loopback path unchanged.
                      CI-exact ruff mcp-servers/ 136 (unchanged). O1-4 (k>=3 floor) + RFC1918 residual =
                      LOW, documented non-blocking follow-ups. K1/K2/L1/M1/N1/N2/P1 regression: none.
                      2026-09-10 (M1): within-process A→B→A wall-clock sandwich (bootstrap CI vs §12's literal
                      1.02) + deterministic sys.setprofile CEM-isolation gate; config B 0 cem_engine calls /
                      0 extra HTTP; full suite 1308 passed / 5 xfailed at capture.
                      2026-09-10 (L1): full suite green ≥ A3 baseline; test_case_store.py / test_idor_sweep.py
                      byte-identical to main; docs/cem-phase1-limitations.md added.
                      2026-09-09 (K2): aggregate FCCR == 0/4 through the protected evaluator; gate fails if
                      fccr_numerator != 0. (K1): real-CEM vs answer_key via evaluator.evaluate(); case_03
                      label ruling (lock 87e0f55b→5546f890); 5 strict xfails, 0 XPASS.
                      2026-09-09 (G1): adversarial review of the full stack; determinism_gate budget-denied
                      → "INCOMPLETE" fix; original evidence-hashing scope UNBUILT (tracked). (J1): six-tool
                      pipeline end-to-end vs the real loopback benchmark, network not mocked.
                      2026-09-07..09 (F1–F3b): case-mcp scope-gated (TIER2_MCP_TOOLS + sender _scope_or_error,
                      SEC-1/SEC-2 remediation); shared 500 cap + per-finding ceiling (default 200) with
                      partial-arm → incomplete=1; per-trial post-perturbation scope_check; non-idempotent
                      methods refused by default.
                      2026-09-07 (E3): guards in case-mcp/server.py — define_conditions + determinism_gate +
                      run_counterfactual refuse a finding not in {CONFIRMED, IMPACT_PROVEN}; define_conditions
                      also rejects a missing/invalid success_signature via SuccessSignature.from_dict (UD-3).
                      New case_store.get_finding(). 1037 green at capture.
                      Earlier: E2 + B-1/T-2 (senders de-duped via _make_budget_cb/_sender_run;
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
NEXT ACCEPTANCE GATE: G0 GRANTED. Phase-1 acceptance gates G1..G9 — GREEN (scripts/verify-phase1.sh
                      exit 0, phase1-report.json overall PASS, re-confirmed at the final completion
                      checkpoint 2026-09-11; G8 confirmed, O1 diff human-approved). O1 final §15 security
                      audit — COMPLETE 2026-09-11 (no unresolved High/Med; O1-1/O1-2/O1-3 fixed, O1-4 +
                      documented residuals = LOW non-blocking). **CEM PHASE 1: ACCEPTED AND FROZEN.**
                      No further Phase-1 code/test/benchmark change is authorized absent a genuine
                      regression found later; Phase 2 has NOT started and must not be prematurely
                      detailed. Next (human decision, not code): finishing-a-development-branch for the
                      uncommitted J1..O1 work (no auto-merge performed).
```

*Do not depend on conversation memory. If this block and the conversation disagree, this block (once updated by
the implementer) is authoritative for project state; the spec chain is authoritative for design.*
