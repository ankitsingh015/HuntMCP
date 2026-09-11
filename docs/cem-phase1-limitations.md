# CEM Phase-1 — limitations & honest-reading guide

Status: **current as of L1 (2026-09-10).** Consolidation only — every statement
here is sourced from an existing repository artifact (cited inline). No new
finding, no production-behaviour claim, no benchmark change originates in this
document.

Read this alongside:

- `docs/cem-phase1-k1-decisions.md` — the per-case K1 decision record (root
  causes, evidence, rulings). This document summarises it and adds the
  real-world FCCR caveat that `PHASE1-EXECUTION-PLAN.md` §9 requires to appear
  in the docs.
- `PHASE1-EXECUTION-PLAN.md` §9 (FCCR definition + honesty caveat), §11
  (regression coverage gaps), §6 J1/K1/K2 entries (verification records).

The purpose of this file is narrow: make sure a future reader **cannot mistake
an honest Phase-1 capability limitation for a false negative, a hidden test
failure, or a false security conclusion.**

---

## 1. What the FCCR = 0 result does and does not claim

**Result (K2, `PHASE1-EXECUTION-PLAN.md` §6 K2 entry):** the aggregate
false-causal-conclusion rate over the real CEM `CaseConclusion`s, computed
through the protected independent `evaluator.evaluate()` across both target
modes, is **0 / 4 = 0.0**. Release gate G5 (§13) is met.

- **Numerator = 0** — no condition whose benchmark ground truth is
  *not-necessary* received the `necessary` verdict; no flaky / cached / race
  case was labelled `necessary`.
- **Denominator = 4** — the conditions at risk of a false necessity claim:
  `answer_key.MUST_NOT_BE_NECESSARY_CASES` = {case_04, case_05, case_06} plus
  `answer_key.APPARENTLY_NOT_NECESSARY_CONDITIONS` = {(case_01, trace_param)}.

**Honesty caveat (`PHASE1-EXECUTION-PLAN.md` §9, reproduced here because §9
requires it to appear in the docs):**

> FCCR == 0 is asserted **only** on the constructed benchmark with known planted
> ground truth. **No zero-false-conclusion claim is made for real-world
> targets**, where ground truth is unknown. On a real target, CEM's honesty
> mechanisms (determinism gate, control gate, throttle gate, `inconclusive` on
> any uncontrolled confounder) reduce — but cannot be proven to eliminate —
> false necessity claims.

`inconclusive` is **never** counted as a false conclusion (§9): it is the
correct, honest output when controls fail, and is tracked separately as an
honesty metric. `probabilistic` (race) is never counted as a necessity claim.

---

## 2. The three Phase-2 capability boundaries

These are the three benchmark expectations that real Phase-1 CEM does **not**
reproduce. Each is a **capability that is not built**, not an engine defect and
not a mis-classification that produces a false causal conclusion. Full evidence:
`docs/cem-phase1-k1-decisions.md`. In `tests/test_cem_benchmark.py` each is a
`pytest.mark.xfail(strict=True)` with a source-backed reason — so the case is
neither skipped nor silently passed, and the suite turns **RED (XPASS)** the
moment the capability lands and the boundary should be retired. There are
**5 strict xfails** total (case_02 label + minimal-set, case_06 label, case_07
label + minimal-set).

| Benchmark case | Answer-key expectation (correct for a full CEM) | Real Phase-1 CEM output | Why it is a boundary, not a defect |
|---|---|---|---|
| **case_02** — `/svc/bravo`, success via `X-Access: grant` **OR** session cookie (two independent paths) | both conditions `interacting`; two 1-element minimal sets | both `apparently_not_necessary`; `minimal_condition_sets` has nothing to minimise | One-variable-at-a-time `run_counterfactual` correctly sees each single condition as individually droppable. Recovering the OR structure needs **live combined-condition subset re-trials** (budget-gated), an input fix (feed the full present set, not only `necessary`-verdict conditions), and a verdict-promotion step. The pure engine fn `find_alternate_condition_sets` *is* capable given a live predicate; the MCP wrapper defers it (server docstring: "live subset re-trials need the budget guard (E2) and are deferred"). `apparently_not_necessary` is **not** in the FCCR denominator — not a false conclusion. |
| **case_06** — `/svc/foxtrot`, returns 200 only under real concurrency (`race_in_flight >= 2`) | `probe_header` = `probabilistic` | `probe_header` = `inconclusive`; determinism `NONDETERMINISTIC` | `run_intervention` executes trials **sequentially** (`Controls` rejects `concurrency != 1`; the race path is a separate flagged path, not a `Controls` value). Every trial → 409 → all-MISS → honest `inconclusive`. An honest `probabilistic` verdict requires **observed intermittent success** under a bounded concurrent burst — a Phase-2 subsystem (`XYZ.md` §2.5.5 / `job_runtime.py`). `classify_race([F,F,F,F,F])` would be a probability label with zero observed successes = fabricated evidence, which Phase-1 refuses to emit. `inconclusive` is **never** an FCCR hit (§9); the determinism gate still catches the nondeterminism and blocks any necessity claim. |
| **case_07 `target_object_id`** — `/svc/golf/99`, path-segment substitution `99 → 42` | `target_object_id` = `necessary` | clean per-condition **error** — no verdict, no trial, no phantom result | `_perturbation_for` supports only the `{"drop": true}` shape; a path-segment **substitution** has no representation. The engine returns a clean error rather than silently no-op-ing, so the causal record stays honest and `target_object_id` is never treated as tested. case_07's other condition, `session_cookie`, still classifies `necessary` (passes K1). Substitution is core to IDOR, so this is a **high-priority Phase-2 task** (perturbation vocabulary v2: `{"set": …}` for query/body params + a `base_request` path template + F3 scope re-verification), not a K1 bolt-on. |

**Reversibility.** All three are explicitly reversible: if the project
prioritises the capability, the boundary is retired by building it (with its own
TDD'd task) and deleting the corresponding `xfail`. The `answer_key` labels are
already correct and are **not** to be changed for these three.

---

## 3. What is NOT a limitation — the case_03 benchmark correction

`docs/cem-phase1-k1-decisions.md` and `PHASE1-EXECUTION-PLAN.md` §6 K1 closure
record this in full. Summary so it is not misread as an engine change:

- The protected `answer_key.py` case_03 verdicts were changed from
  `interacting` / `interacting` to `necessary` / `necessary` (minimal set and
  the AND / intersection-group semantics preserved) by **explicit human
  ruling**, because the original labels were internally inconsistent with the
  human-approved 2026-09-05 C6 addendum, with the structurally-identical
  case_07-vulnerable label, with the live engine output, and with `XYZ.md`
  §2.2's `necessary` definition.
- `answer_key.py.sha256.lock` was regenerated via the repo's own
  `integrity.update()`; `integrity.verify()` passes for `answer_key.py`
  (`5546f890…`) and `scenarios.py` (`31862b91…`).
- **No production CEM code changed.** The existing engine behaviour
  (`necessary` + `necessary` + size-2 minimal set + `AndNecessityGroup`) is the
  accepted behaviour and was already correct.
- One consequential test-fixture sync: `tests/test_cem_evaluator.py`
  `_correct_vulnerable()` — a synthetic "perfectly-correct CEM output" double
  that by construction mirrors `answer_key.EXPECTED` — had its case_03 entry
  updated to match. Assertions unchanged (`coverage == 1.0`).

---

## 4. Honest-outcome vocabulary vs. a false causal conclusion

From `PHASE1-EXECUTION-PLAN.md` §9. A reader auditing a bundle should hold these
distinct:

| CEM output | Meaning | Counts as a false causal conclusion? |
|---|---|---|
| `necessary` | but-for necessity held across replicated arms under the pinned controls | **Only if** the ground truth is not-necessary |
| `apparently_not_necessary` | the condition was individually droppable without losing the capability | No |
| `interacting` | matters only jointly with another condition | No |
| `inconclusive` | controls failed / confounder uncontrolled / arm aborted / determinism unstable | **No — never.** Honest non-answer. Tracked as a separate honesty metric. |
| `probabilistic` | genuine race; success observed intermittently under concurrency | No — never a necessity claim |
| clean error / no verdict | the perturbation shape is not expressible in Phase-1 | No — nothing is asserted |

A false causal conclusion = emitting `necessary` for a condition whose ground
truth is not-necessary, **or** labelling a flaky / cached / race case
`necessary` instead of `inconclusive` / `probabilistic`.

---

## 5. Regression-suite coverage gaps carried forward

From `PHASE1-EXECUTION-PLAN.md` §11 — stated so they are not papered over:

- There is **no automated end-to-end test of full multi-agent hunting**
  (agents are markdown + live tools). Phase-1 mitigates by not changing agent
  logic.
- MCP-server **process** startup is not exercised in CI beyond import / smoke.
  Phase-1 mitigates by smoke-importing `case-mcp/server.py`.
- Memory / reporting subsystems have unit tests but **no integration harness**.
  Phase-1 does not touch them, so regression risk is low but coverage is
  partial.

---

## 6. Deferred items from earlier CEM phases (pointers only — not L1's to fix)

Tracked in `PHASE1-EXECUTION-PLAN.md` §6 / §19; listed here for a single
overview:

- **C8 / G1 content-addressed request/response evidence hashing** is **unbuilt**
  (`cem_trials.request_evidence_hash` / `response_evidence_hash`,
  `assemble_bundle`'s `audit_trail`). The G1 entry classifies this as a
  *capability limitation, not a correctness or security defect*: trials persist
  `arm` / `k_index` / `http_status` / `oracle_hit`, verdicts are honest, and the
  bundle honestly signals `incomplete`. The exact request/response bytes cannot
  be rebuilt from the bundle.
- **`SuccessSignature` `body_regex=""` vacuous-oracle vector** (C1) — left open,
  tracked under §6 C1.
- **Secret-header redaction for names outside the 4 canonical ones**
  (e.g. `X-Auth-Token`, `X-Session-Id`) — left open, tracked under §6 C8.

---

## 7. How to read the test suite

- `tests/test_cem_benchmark.py` (J1 + K1 + K2): drives the **real** merged CEM
  MCP tools against the real loopback benchmark target — the network path is not
  monkeypatched.
- **5 `xfail(strict=True)`** = the three Phase-2 boundaries in §2. Expected.
- **Any `XPASS`** on those = a real alarm: a capability landed and its boundary
  entry (here and in `docs/cem-phase1-k1-decisions.md`) must be retired in the
  same change.
- `test_k1_no_case_emits_a_false_necessary`, `test_k2_*` = the scientific-
  integrity gates. A failure there is a hard quality failure, never something to
  xfail around.
- `test_k1_blindness_production_has_no_answer_key_path` = proves no production
  module under `mcp-servers/` can import the answer key.
- `test_k1_benchmark_integrity_locks_unchanged` = proves the protected
  benchmark artifacts are byte-identical to their `.sha256.lock`s.
