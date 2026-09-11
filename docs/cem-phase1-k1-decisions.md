# CEM Phase-1 — K1 benchmark-comparison decision record

Status: **K1 CLOSED (2026-09-09).**
- **case_03** — protected `answer_key.py` corrected (`interacting`→`necessary` for
  both conditions) by **explicit human ruling** because it was internally
  inconsistent with the C6 addendum, the structurally-identical case_07-vulnerable
  label, the live CEM engine output, and XYZ.md §2.2's `necessary` definition.
  Now a hard-pass; **no production CEM change**.
- **case_02 / case_06 / case_07 (`target_object_id`)** — DEFERRED Phase-2
  capability boundaries (strict xfail). The `answer_key` labels are correct; the
  Phase-2 capabilities are **not built**. Phase-1's honest outcome
  (`inconclusive` / `apparently_not_necessary` / clean per-condition error) is
  not a false causal conclusion.

K1 (`tests/test_cem_benchmark.py`, the K1 section) compares the **real** CEM
verdict/label for every `scenarios.py` case against the protected `answer_key.py`,
joined by the independent `evaluator.py`. This document records the source-backed
root cause for each non-match and the decision taken.

Only `answer_key.py` case_03 verdicts + its `.sha256.lock` (regenerated via the
repo's own `integrity.update()`) changed in `tests/fixtures/cem_target/`.
Integrity of `scenarios.py` and `answer_key.py` verifies after the change.

---

## Matching today (hard K1 PASS)

| case / mode | expectation | real CEM |
|---|---|---|
| case_01 / vulnerable | `session_cookie`=necessary, `trace_param`=apparently_not_necessary; minimal set `{session_cookie}` | exact match |
| case_03 / vulnerable | `role_admin`=necessary, `flag_on`=necessary; minimal set `{role_admin, flag_on}` (AND group) | exact match — after the 2026-09-09 human-ruled `answer_key` correction; CEM behaviour unchanged |
| case_04 / vulnerable | `probe_header`=inconclusive; determinism `NONDETERMINISTIC` | exact match |
| case_05 / vulnerable | `probe_header`=inconclusive | exact match |
| case_07 / patched | `capability_absent` (no `necessary` emitted) | exact match — all-MISS baseline → determinism gate → no necessity |

---

## case_03 — CLOSED: protected benchmark corrected by explicit human ruling (2026-09-09)

**Ruling:** `answer_key.py` case_03 changed `role_admin`/`flag_on` from
`interacting` to `necessary` (minimal set + AND/intersection group semantics
preserved); `.sha256.lock` regenerated via `integrity.update()`; integrity
verifies. **No production CEM change.** `test_k1_answer_key_labels[case_03-vulnerable]`
is now a hard pass. The rest of this section is the evidence that justified the
ruling — retained as the record.

**Answer key was:** `role_admin`=`interacting`, `flag_on`=`interacting` (now
`necessary`/`necessary`).
**Real CEM (unchanged):** `role_admin`=`necessary`, `flag_on`=`necessary`;
minimal set `{role_admin, flag_on}`.

`/svc/charlie` requires `X-Role: admin` **AND** `flag=on`. Each single removal
flips the oracle (403); joint removal also flips.

### Proof the answer key is internally inconsistent

1. **C6 addendum** (`cem_engine.find_and_necessity_groups` docstring —
   *"human-approved Option 2 of 3 presented, 2026-09-05"*): a pure
   AND-both-required pattern (*"PHASE1-PLAN.md's own `/merge` example"*) yields
   `classify()`'s `necessary` verdict per condition **plus** an
   `AndNecessityGroup` over the minimal set — explicitly **not** `interacting`.
   Rule 1 / Rule 2 of `find_alternate_condition_sets` *"can [not] fire on a pure
   AND-both-required pattern … by design, not by bug"*, and the group annotation
   *"is not a replacement for classify()'s own per-condition `necessary` verdict …
   correctly still says `necessary` for role_admin and flag_on individually"*.

2. **Counterfactually-identical benchmark case labelled differently.**
   `case_07`-vulnerable (`/svc/golf/99` with cookie) also needs
   `session_cookie` **AND** the victim `target_object_id` — each single
   removal/substitution flips the oracle; joint removal flips. Under
   counterfactual intervention (the only thing CEM observes) this is the *same
   structure* as case_03: a pure 2-way AND where each condition singly flips the
   oracle. The answer key labels case_07-vulnerable `necessary` + `necessary` +
   size-2 set — not `interacting`. A benchmark that grades CEM's counterfactual
   output cannot consistently grade two counterfactually-identical cases with
   different labels.

3. **Observed runtime evidence — the engine with a real live subset-re-trial
   predicate (k=5 real HTTP trials per subset):**

   | | `minimal_sets` | `interacting` | `and_necessity_groups` |
   |---|---|---|---|
   | case_03 (`/svc/charlie`, drop predicate) | `[{X-Role, flag}]` | `[]` | `[{X-Role, flag}]` |
   | case_07-vuln (`/svc/golf`, substitution predicate) | `[{session_cookie, target_object_id}]` | `[]` | `[{session_cookie, target_object_id}]` |

   `find_alternate_condition_sets` never flags case_03 as `interacting`, even
   given a perfect predicate. It flags a mutual-AND-necessity group — matching
   CEM's current output and the C6 addendum.

4. **XYZ.md §2.2** defines `necessary` as *"perturbing C reliably kills the
   capability across replicated arms (but-for necessity holds **under the
   held-fixed controls**)"*. With `flag` held fixed, dropping `role` → 403 →
   but-for necessity holds. `necessary` is satisfied. (§2.2 also lists
   `interacting` = "matters only jointly", which case_03 also satisfies
   literally — §2.2 alone is dual; the **C6 addendum is the project's explicit
   2026-09-05 ruling** that resolved the ambiguity toward `necessary` + group
   for pure AND. The answer key was not updated to that ruling.)

### Correction applied (2026-09-09, explicit human ruling)

```python
# answer_key.py  --  ONLY the two verdict strings changed
"case_03": MappingProxyType({
    "verdicts": MappingProxyType({"role_admin": "necessary", "flag_on": "necessary"}),
    "minimal_sets": (("role_admin", "flag_on"),),   # unchanged -- AND/intersection group preserved
}),
```
`answer_key.py.sha256.lock` regenerated via the repo's own
`integrity.update("…/answer_key.py")`; `integrity.verify()` passes.
`MEANING["case_03"]` ("interaction (both needed)") is unused by any assertion and
still accurately describes the preserved AND-necessity group — left untouched.
`scenarios.py` untouched. No unrelated `answer_key` case changed.

This aligns the benchmark with (1) the human-approved C6 addendum, (2) the
case_07-vulnerable label, (3) observed engine behaviour, and (4) XYZ.md §2.2's
`necessary` definition. **Zero CEM code change.** No security or
scientific-capability regression: `necessary` for a genuinely but-for-necessary
condition is a *stronger, more actionable* claim than `interacting`, fully backed
by 5/5 perturbed-MISS evidence.

Rejected alternatives: (a) defer — dishonest, this is not a capability gap;
(b) make CEM emit `interacting` for pure AND — reverses the 2026-09-05 ruling
and weakens a true claim; (c) a K1-test-layer "these labels are equivalent"
translation — indistinguishable from benchmark gaming.

`test_k1_answer_key_labels[case_03-vulnerable]` is a hard pass; case_03 moved
from `_K1_KNOWN_GAPS` to `_K1_MATCHING`. `test_k1_benchmark_integrity_locks_unchanged`
now verifies against the regenerated lock.

---

## case_06 — RESOLVED: Phase-2 capability boundary (controlled parallel race replication)

**Answer key expects:** `probe_header`=`probabilistic`.
**Real CEM:** `probe_header`=`inconclusive`; determinism `NONDETERMINISTIC`.

`/svc/foxtrot` returns 200 only under real concurrency (`race_in_flight >= 2`).
`run_intervention` executes trials **sequentially** (blocking `urllib`;
`Controls` rejects `concurrency != 1` — *"the race path is a separate flagged
path, not a Controls value"*). Every trial → 409 → all MISS → `classify()`
"baseline not all-HIT → `inconclusive`". `run_counterfactual` calls only
`classify()`, never `classify_race()`; `define_conditions` has no race flag.

**An honest `probabilistic` verdict requires observed intermittent success.**
`classify_race([F,F,F,F,F], k=5)` → `hit_rate = 0.0` — a probability label with
zero observed successes = fabricated evidence. A real `probabilistic` verdict
needs controlled parallel replication (a bounded concurrent burst, real
hit-rate under concurrency) + a race flag/route — a Phase-2 subsystem
(XYZ.md §2.5.5 ties it to the race-conditions skill / single-packet technique +
`job_runtime.py`; PHASE1-PLAN §D says "finding **flagged** race/TOCTOU").

**Decision:** `inconclusive` is the honest Phase-1 outcome. The `probabilistic`
expectation is correct for a full CEM and is classified as a **Phase-2
capability boundary** (analysis 2026-09-09; reversible if prioritised).
No `answer_key` change. `inconclusive` is never an FCCR hit (§9),
and deferral loses no capability — CEM still catches the nondeterminism via the
determinism gate and refuses a false necessity claim.

`test_k1_answer_key_labels[case_06-vulnerable]` stays `xfail(strict=True)`.

---

## case_07 — RESOLVED (`target_object_id`): Phase-2 capability boundary (substitution perturbation vocabulary)

**Answer key expects:** `session_cookie`=`necessary` (PASS today),
`target_object_id`=`necessary`.
**Real CEM (`target_object_id`):** clean error — `_perturbation_for` supports
only `{"drop": true}`; a path-segment *substitution* (`/svc/golf/99` →
`/svc/golf/42`) has no representation. No verdict, no trial, no phantom result.

**The causal analysis is ready** — Experiment 2 (live substitution predicate)
produces `minimal_sets=[{session_cookie, target_object_id}]` + AND-group,
matching the answer key. The only missing piece is the **substitution
perturbation primitive**. Substitution is core to IDOR (CEM's headline use
case: "is targeting the victim's object rather than your own necessary?"), so
this is a **high-priority Phase-2 task**, not a low-value nice-to-have:

> Phase-2: perturbation vocabulary v2 — `{"set": {<key>: <value>}}` for
> query/body params + path-segment substitution via a `base_request` path
> template; F3 scope-recheck verification for each new shape; dedicated test
> matrix. TDD'd as its own task, not a K1 bolt-on.

**Decision:** classified as a **Phase-2 capability boundary** (analysis
2026-09-09; reversible if prioritised — substitution is high-value for IDOR).
case_07's Phase-1-expressible parts already pass K1. No `answer_key` change (the
`necessary` label is correct, just not Phase-1-testable). `target_object_id` is
never silently treated as tested.

`test_k1_answer_key_labels[case_07-vulnerable]` and
`test_k1_minimal_condition_sets_match_answer_key[case_07]` stay
`xfail(strict=True)`.

---

## case_02 — RESOLVED: Phase-2 capability boundary (live combined-condition subset re-trials)

**Answer key expects:** `x_access_header`=`interacting`,
`session_cookie`=`interacting`; two minimal sets.
**Real CEM:** both `apparently_not_necessary`; `minimal_condition_sets` returns
"no `necessary` verdict" (nothing to minimise).

`/svc/bravo` succeeds via `X-Access: grant` **OR** session cookie (independent
paths). One-variable-at-a-time `run_counterfactual` correctly sees each as
individually droppable → `apparently_not_necessary`.

**The pure engine function reproduces the benchmark's answer STRUCTURE — given
a live predicate.** Experiment 1 (`/svc/bravo`, k=5 real trials per subset):

```
minimal_sets      = [['Cookie'], ['X-Access']]
interacting       = ['Cookie', 'X-Access']        (Rule 2: joint removal flips,
interacting_pairs = [['Cookie', 'X-Access']]        neither single removal does)
```

Three Phase-1 limitations block this on the MCP path, all deferred:

1. The MCP `minimal_condition_sets` tool feeds only `necessary`-verdict
   conditions to `find_alternate_condition_sets`; an OR-redundancy case has
   none, so the analysis never runs. (Per PHASE1-PLAN §11 the input should be
   the full present/triggering set S.)
2. It uses a **stored-verdict predicate** (infer "drop both → MISS" from two
   single-drop verdicts) instead of **live subset re-trials**. That inference
   is unsound in general — e.g. ANY-TWO-OF-THREE redundancy: each of a,b,c is
   individually droppable, so the predicate says "keep only c → HIT", but
   reality is MISS. Honest validation requires actually re-running the
   intervention with multiple conditions dropped (budget-gated). The server
   docstring already marks this deferred: *"live subset re-trials need the
   budget guard (E2) and are deferred"*.
3. Even with (1)+(2), `run_counterfactual` has already written
   `apparently_not_necessary` to `cem_verdicts` for each condition; nothing
   promotes those to `interacting`. A promotion step (from the Rule-1/Rule-2
   flags) is needed for the per-condition verdict / bundle to read `interacting`.

**Decision:** classified as a **Phase-2 capability boundary** (analysis
2026-09-09; reversible if the project prioritises it) — live combined-condition
subset re-trials + the input fix + verdict promotion. The pure
`find_alternate_condition_sets` function is *capable* (Rule 2 fires on the OR
pattern given a live predicate); the MCP wrapper is not. No `answer_key` change
(the `interacting` label is correct). `apparently_not_necessary` here is not in
the FCCR denominator.

`test_k1_answer_key_labels[case_02-vulnerable]` and
`test_k1_minimal_condition_sets_match_answer_key[case_02]` stay
`xfail(strict=True)`.

---

## K1 status — CLOSED (2026-09-09)

| | outcome |
|---|---|
| case_01, case_03, case_04, case_05, case_07-patched | **PASS** — real CEM matches the answer key. (case_03 after the human-ruled `answer_key` correction; CEM behaviour unchanged.) |
| case_02, case_06, case_07-`target_object_id` | **DEFERRED Phase-2 capability boundary** — strict-xfail with a source-backed reason; the `answer_key` label is correct, the capability is **not built**, Phase-1's honest outcome is not a false causal conclusion |

Every Phase-1-expressible benchmark expectation is now correctly reproduced by
real CEM. The three remaining strict-xfails are legitimate Phase-2 capability
boundaries, not engine defects and not hidden mismatches — the suite reports
them as XFAIL and goes RED (XPASS) if the capability lands without the boundary
being retired.

**K1 is CLOSED** (independently audited 2026-09-09).

**K2 (2026-09-09):** the aggregate false-causal-conclusion rate over the SAME
real `k1_results` CaseConclusions, computed through the protected
`evaluator.evaluate()` across both target modes, is **0/4 = 0.0** — release gate
G5 met. `test_cem_benchmark.py::test_k2_false_causal_conclusion_rate_is_zero`
(asserts `fccr_numerator == 0`, `fccr == 0`, `fccr_denominator == 4`) +
`test_k2_fccr_gate_detects_a_false_necessary` (mutation proof). No production CEM
change, no benchmark-artifact change. The three deferred Phase-2 boundaries do
not contribute a false conclusion: case_02 → `apparently_not_necessary`;
case_06 → honest `inconclusive` (§9: never a false conclusion); case_07-vuln
`target_object_id` → no verdict emitted.
