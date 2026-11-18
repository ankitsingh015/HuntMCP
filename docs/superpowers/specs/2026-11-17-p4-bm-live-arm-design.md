# P4-BM live arm + omitted-scenario scoring (design)

**Date:** 2026-11-17
**Status:** DRAFT — awaiting human approval
**Tracker row:** P4-BM (`IMPLEMENTATION-TASK-TRACKER.md` §6), `[~]` → `[x]` on completion.
**Context:** P5-A0 (allocation STOP/GO) is **deferred** pending this P4 measurement (human decision 2026-11-17).

---

## 1. Intent & why

P4-BM's blind long-horizon benchmark substrate is built (`tests/fixtures/lh_target/`): a hermetic
7-dimension simulator, a blind scenario index, an evaluator-only answer key (SHA-256 locked), an
arm-agnostic trajectory scorer (`lh_evaluator.evaluate`), and a GOLDEN reference arm
(`lh_harness.golden_trajectory`). Two things remain, and P5-A0 is gated on them:

1. a **live arm** that drives HuntMCP's *real* pipeline (not a hand-written golden script) to emit
   the same trajectory contract, and a **measured uplift** over a naive baseline;
2. the **omitted-scenario scoring policy** — `evaluate` currently iterates `conclusions.items()`, so
   a scenario an arm never concludes on is silently unscored (an arm could dodge misses by staying
   silent). Flagged by `/code-review` on the P4-BM build; deferred as a methodology decision.

## 2. Goals

1. **`lh_live_arm.py` (new, test-only):** `real_pipeline_trajectory(target)` drives the REAL,
   deterministic HuntMCP modules across all 7 dimensions and returns `(steps, conclusions)` in the
   `lh_evaluator` contract. Real consumers, one per dimension where one exists:
   - **bravo** (cross-identity IDOR): real `invariant_probe` ownership mining → `to_cem_hypothesis`
     → real `run_cem_pipeline` (simulator-backed `http_probe.fetch`, same wiring as
     `test_invariant_probe_pipeline`) → `identity` necessary verdict. (Exercises P4-M1 end-to-end.)
   - **charlie** (business-logic replay): real `invariant_probe` one-time-use → CEM `replays`
     necessary.
   - **echo** (resurrection): real `case_store.log_hypothesis` at epoch 0 (INCONCLUSIVE, OOB not
     fired) → add deferred evidence at epoch 1 → real `case_store.find_resurrectable_hypotheses`
     resurrects it (the consumer the tracker names).
   - **alpha / delta / foxtrot** (sustained / target-change / recovery): drive the real multi-step
     sequence against the simulator and record the real event-backed conclusion via `case_store`.
   - **golf** (secured decoy): correctly conclude `no_finding`.
2. **Baseline arm** `baseline_trajectory(target)`: a naive arm with NO cross-run memory /
   resurrection and NO invariant mining (class-scanner-style single-pass). It legitimately MISSES
   the dimensions that need those (echo resurrection; the class-less charlie one-time-use), so
   `evaluate(real) vs evaluate(baseline)` shows a concrete, measured uplift.
2b. **Agent wiring for real hunting (the point of this expansion, human-steered 2026-11-17):** the
   built P4 capabilities are mostly not yet referenced by the agents, so a live hunt never uses them.
   Wire the two highest-leverage consumers into BOTH agent variants (`.opencode/agents/` +
   `.claude/agents/`), the same light, read-only, confirm-each-candidate pattern as the invariant-
   mining step 3.6 already added:
   - **Hypothesis resurrection** (`find_resurrectable_hypotheses`, P4-RESURRECT): after new evidence
     or a later epoch/recheck, the agent revisits dormant INCONCLUSIVE/REFUTED leads instead of
     dropping them — catches deferred-evidence (OOB/async) bugs a single pass misses. Advisory only;
     re-opening a hypothesis is the agent's judgment via `update_hypothesis`.
   - **Info-gain ordering** (`order_experiments` / `info_gain`, P4-INFOGAIN): when the agent has
     several candidate experiments, order them by expected info-gain-per-cost so the highest-yield
     tests run first — explicitly **never dropping or skipping a novel/low-history test** (§11-A:
     hints, never skips; a novel class gets the optimistic prior).
   These are agent-instruction edits (prompt wiring), not new runtime code; `info_gain.py` /
   `find_resurrectable_hypotheses` already exist and are tested. Coverage-matrix + escalation-value
   wiring is explicitly OUT (a later step) to keep the change surface small.
3. **Omitted-scenario scoring:** `evaluate` scores the full `AK.EXPECTED` set; a scenario with no
   conclusion counts as `inconclusive` (honest: not a hit, not a silent drop). `inconclusive`
   remains its own bucket and NEVER an FCCR hit (unchanged).
4. **Measurement test** (`tests/test_lh_live_arm.py`): real arm vs baseline through `evaluate`;
   assert the real arm scores strictly better on the uplift dimensions, **FCCR==0** for the real
   arm, determinism + reproducibility, and that an omitted scenario now scores `inconclusive`.

## 3. Non-goals / honest limits

- **No LLM agents in the loop.** The live arm drives the real *deterministic* modules, not
  huntbrain/exploit-agent (an LLM run is non-deterministic and un-hermetic). Whether a live LLM run
  reproduces this trajectory is observed in the first real engagement — same honesty bar as P3-
  CEMHUNT / P4-M1's own adoption caveat. This is stated in the tracker, not hidden.
- **No new simulator scenarios / no new planted ground truth.** The arm consumes the existing blind
  scenarios; `lh_answer_key.py` / `lh_target.py` / `lh_scenarios.py` are untouched (and stay
  integrity-locked). Only `lh_evaluator.py` changes (goal 3).
- **Frozen CEM untouched** (`cem_engine.py` etc. byte-identical; `verify-phase1.sh` G1–G9 PASS).
- No new dependency; no new runtime module. The only non-test edits are the two agent-prompt
  wirings (goal 2b) + the tracker; `info_gain.py` / `find_resurrectable_hypotheses` are reused as-is.
- The irreducible honest limit stands and is NOT claimed fixed: an LLM agent run is non-deterministic
  and un-hermetic, so it can't be a CI benchmark arm. Wiring (2b) + the deterministic live-arm proof
  (goal 1) maximize the chance a real engagement benefits, but whether a live LLM run actually calls
  these tools well is observed in the first real engagement, not asserted here.

## 4. Constraints

- **C1 — benchmark integrity / blindness:** `lh_live_arm.py` is an ARM — it must reach its
  conclusions from the simulator's observable behaviour + the blind index only, and MUST NOT import
  `lh_answer_key.py` (asserted by a blindness test, same bar as `lh_harness`).
- **C2 — protected-benchmark change = human approval (`.claude/rules/benchmarks.md`):** the
  `evaluate` omitted-scenario change is a scoring-methodology change. Approving this doc authorizes
  it. `lh_evaluator.py` is not currently integrity-locked; if review finds it should be, lock it and
  record it. The change only makes scoring *stricter* (an omission can no longer be hidden), never
  looser — it cannot flatter an arm.
- **C3 — FCCR==0 stays the headline invariant;** `inconclusive` never counts toward FCCR.
- **C4 — determinism:** the arm is hermetic (simulator is in-process, no network/fs/randomness);
  CEM fetch is wired to the simulator exactly as the existing invariant pipeline test does.

## 5. Approaches considered

- **A — deterministic real-pipeline arm + naive baseline (CHOSEN):** drives the real modules; gives
  a real, reproducible, measurable uplift now, with the LLM-agent arm as a documented deferred
  observation. Faithful to "measure-first" and hermetic.
- **B — LLM-agent live arm:** drive huntbrain/exploit-agent for real. Non-deterministic, un-hermetic,
  can't be a CI-gated benchmark arm; belongs in a real engagement, not the benchmark. Rejected as the
  benchmark arm (kept as the documented real-engagement observation).
- **C — leave P4-BM `[~]`, only fix scoring:** closes the anti-gaming gap but delivers no live arm /
  uplift, so P5-A0 stays un-measurable. Rejected — it doesn't unblock the decision P5-A0 waits on.

## 6. Acceptance (tracker §10 "P4-BM")
- Real arm vs baseline scored by the REAL `evaluate`; real arm strictly better on uplift dimensions,
  **FCCR==0**, reproducible ×3; omitted-scenario now `inconclusive` (anti-gaming closed).
- Blindness held (arm never imports the key); frozen CEM untouched (`verify-phase1.sh` PASS); full
  regression green.
- `/code-review` + `/security-review` clean or fixed; **prove-it-runs:** the real live arm executed
  end-to-end (real invariant_probe → real run_cem_pipeline → real find_resurrectable_hypotheses)
  with the scored report shown.
- Resurrection + info-gain wired into both agent variants; `tests/test_agent_tool_scoping.py`
  invariants still green (no orphan/unreal server; only real, enabled tools referenced).
- Tracker P4-BM → `[x]` with the LLM-agent-uplift caveat explicitly recorded; P4-RESURRECT /
  P4-INFOGAIN rows updated to note they are now agent-wired; P5-A0 note updated ("P4 measurement
  now available; decision still pending").

## 7. What's left to the builder
- The exact per-dimension step sequence for alpha/delta/foxtrot (follow `golden_trajectory`'s shape,
  but reach each conclusion through a real `case_store` record, not a hand-set `ScenarioConclusion`).
- Whether the baseline arm omits a dimension entirely (→ now `inconclusive` under goal 3) or
  concludes `no_finding` (→ `miss`) — builder's call per dimension, chosen to make the uplift honest
  (a baseline that can't resurrect echo should MISS it, not stay silent, so the uplift is real).
