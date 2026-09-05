"""Unit tests for mcp-servers/cem_engine.py, tasks C1 and C2. Pure logic only -- no
network, no case_store, no MCP.

C1 (SuccessSignature contract / evaluate_signature): written before cem_engine.py
existed (TDD RED), per PHASE1-EXECUTION-PLAN.md task C1.

Contract resolved with the human (2026-09-05, an explicit stop-and-ask rather than a
guess): PHASE1-PLAN.md D5's `similarity_to_baseline >= t` shorthand cannot work as a
bare threshold given evaluate_signature's documented 2-arg shape (FetchResult, sig) --
a similarity check needs two bodies to compare. Resolved as: similarity_to_baseline is
a nested {body, threshold} object embedded in the signature itself, so the reference
body travels inside sig and evaluate_signature stays strictly 2-arg and self-contained.

C2 (determinism_gate): written before determinism_gate/DeterminismResult existed in
cem_engine.py (TDD RED), per PHASE1-EXECUTION-PLAN.md task C2. Uses only fake/injected
fetch_fn callables -- no real network call anywhere in this file.

C3 (classify): written before classify existed in cem_engine.py (TDD RED), per
PHASE1-EXECUTION-PLAN.md task C3. Pure classification over already-observed
baseline/perturbed hit sequences -- no fetch_fn, no HTTP, no perturbation.

Scope boundary resolved with the human (2026-09-05, stopped and asked rather than
guessed): 429/throttle detection is NOT classify()'s job. PHASE1-PLAN.md's verdict-
rules table lists "any arm sees 429/throttle -> inconclusive" as its own bullet, and
classify()'s literal signature (baseline_hits, perturbed_hits, k) has no distinguishable
throttle channel -- a plain bool can't tell "oracle didn't match" apart from "got
rate-limited". Resolved: throttle detection belongs to the executor (task D3, which
inspects real HTTP status as trials happen, and either short-circuits to inconclusive
itself or never calls classify() for a throttled run). classify() only ever sees plain
hit/miss bools, matching DeterminismResult.hits' type exactly (C2). See
test_classify_signature_has_no_throttle_parameter_by_design below, which pins this
boundary down.

C4 (classify_race): written before classify_race/RaceResult existed in cem_engine.py
(TDD RED), per PHASE1-EXECUTION-PLAN.md task C4 ("race/TOCTOU path -> probabilistic
(report perturbed HIT-rate; never necessary)"). PHASE1-PLAN.md's C4 line names no
function/signature (unlike C1/C2/C3, each of which named its exact function in the
plan), so the API was a genuine ambiguity -- stopped and asked rather than guessed
(2026-09-05). Resolved with the human: a new, separate pure function rather than
widening classify()'s C3-pinned 3-arg signature (which has its own dedicated
signature-lock test above). classify_race(perturbed_hits, k) -> RaceResult takes no
baseline_hits (the plan's own wording only ever says "report perturbed HIT-rate") and
no boolean race flag -- being routed to this dedicated function at all IS the race
flag, mirroring how determinism_gate/classify are already separate pure functions per
concern rather than one function branching on a mode parameter. RaceResult.verdict is
hardcoded to VERDICT_PROBABILISTIC so the function can structurally never return
"necessary" regardless of the observed hit pattern -- that is the whole point of C4
(a race must never produce a false deterministic causal conclusion). hit_rate is the
raw perturbed-arm HIT fraction (count(True)/k), preserving uncertainty explicitly
instead of collapsing it into a boolean.

C5 (minimal_condition_sets): written before minimal_condition_sets/MinimalSetResult
existed in cem_engine.py (TDD RED), per PHASE1-EXECUTION-PLAN.md task C5
("minimal_condition_sets(): ddmin for one 1-minimal set"). PHASE1-PLAN.md names the
defining property precisely ("a subset is interesting iff, with all conditions
outside it perturbed to non-triggering, the oracle is unanimously HIT over k") but,
unlike C1/C2/C3, gives no concrete pure-function signature for the engine layer --
only the DB-backed orchestration-level `minimal_condition_sets(finding_id)` (a later
E1 task, out of scope here since C5 must stay pure/DB-free, same as C1-C4). This was
a genuine API ambiguity -- stopped and asked rather than guessed (2026-09-05).
Resolved with the human (of 3 options presented): an injected pure predicate
`is_interesting: Callable[[frozenset[str]], bool]`, matching classic
ddmin(test, circumstances) exactly and mirroring C2's fetch_fn-injection precedent.
Strictly bool -- PHASE1-PLAN.md's own definition of "interesting" is already binary
(unanimous HIT over k, nothing else), so no new inconclusive/tri-state channel is
invented at this layer; a predicate returning anything other than a real bool is a
hard TypeError (see test_minimal_condition_sets_rejects_predicate_returning_non_bool),
never silently coerced or treated as "inconclusive". C5 finds exactly ONE 1-minimal
set -- alternates and interaction detection are task C6, not this function.

C6 (find_alternate_condition_sets): written before find_alternate_condition_sets/
AlternateSetsResult/InteractionEvidence existed in cem_engine.py (TDD RED), per
PHASE1-EXECUTION-PLAN.md task C6 ("alternates + interaction detection (bounded;
report completeness)"). Built strictly on top of C5's minimal_condition_sets()
(called directly, never reimplemented) per PHASE1-PLAN.md sec 11's literal
procedure and its 2 explicit interaction rules.

Two ambiguities were stopped-and-asked rather than guessed (2026-09-05, both
human-approved):

(1) Rule 1 ("c singly apparently_not_necessary but present in every recovered
minimal set") -- checked against every recovered set EXCEPT c's own force-excluded
alternate (structurally can never contain c) and EXCEPT M1 itself when c is one of
M1's own members ("c is in M1" restates the premise, proves nothing new). Including
either would make Rule 1 vacuously impossible or tautological. See
test_c6_rule1_does_not_fire_on_a_two_member_family_lacking_independent_evidence and
test_c6_rule1_fires_with_genuinely_independent_corroborating_alternates below.

(2) The candidate pool for individual droppability testing (is_interesting(S-{c}),
feeding both rules) is every condition in the original S, not just M1's members --
the Alternates SET-FINDING procedure itself stays M1-scoped exactly as literally
written ("for each c in M1"), but interaction-candidate testing is broadened,
because ddmin's greedy sweep can drop one half of a real interacting pair before it
ever reaches M1. See test_c6_rule2_detects_interaction_even_when_one_member_never_
reaches_m1 below (the a/b/d example from the module docstring).
C7 (minimize_poc): written before minimize_poc/PocMinimizationResult existed in
cem_engine.py (TDD RED), per PHASE1-EXECUTION-PLAN.md task C7 ("ddmin over
conditions/steps, runs AFTER verdicts, re-validated by determinism gate").
PHASE1-PLAN.md sec 12 says "PoC minimization reuses the SAME ddmin with the oracle
as interestingness" -- so minimize_poc() calls minimal_condition_sets() (C5)
directly, never reimplementing ddmin a second time. "steps" is not a separate
concept anywhere in the plan (checked: it only ever appears as loose synonym for
"conditions/fields", no dedicated dataclass) -- minimize_poc() operates over the
exact same `conditions: list[str]` abstraction as C5/C6.

Re-validation ("output re-validated through determinism_gate ... guards a DD local
optimum dropping a real step") is implemented as an injected `revalidate:
Callable[[frozenset[str]], DeterminismResult]` callable -- kept abstract so this
function stays pure/no-network, exactly how `is_interesting` already stands in for
a real oracle check, and reusing C2's own `DeterminismResult` type unmodified
rather than inventing new determinism vocabulary. Resolved directly from the
plan's own text, not guessed: "ddmin local optimum drops a needed step. Mitigation:
re-validate minimal set/PoC via determinism gate; optional DDMIN* re-iterate" --
the re-iteration is explicitly marked OPTIONAL, i.e. NOT part of Phase 1's minimum
bar. So on a NONDETERMINISTIC revalidation, minimize_poc() does NOT retry/backtrack
-- it reports `accepted=False` honestly (poc still returned for evidence/
inspection, but flagged as not validated), matching the file's established
"no majority vote, no silent retry" principle (C2's determinism_gate already does
exactly k trials, no more).

C8 (assemble_bundle): written before assemble_bundle existed in cem_engine.py (TDD
RED), per PHASE1-EXECUTION-PLAN.md task C8 / task-C8-brief.md. C8's only declared
deps are C3..C7, not the not-yet-built intervention executor (D1-D3) or case_store
(E1) -- so assemble_bundle is a pure aggregator over already-computed C1-C7 result
types (DeterminismResult, AlternateSetsResult, PocMinimizationResult) plus raw
caller-supplied context (original_baseline, intervention_matrix, controls,
observed_confounders, verdict_labels, inconclusive_experiments, audit_trail, k);
it never calls determinism_gate/classify/classify_race/minimal_condition_sets/
find_alternate_condition_sets/minimize_poc/http_probe.fetch itself, mirroring C2's
injected fetch_fn / C7's injected revalidate precedent (tested below the same way
C2/C6/C7 already prove they never touch the real http_probe.fetch, via
monkeypatch-raises-if-called on cem_engine's own module attributes).

Field 9 (`minimal_condition_sets`, the MSC family + interactions) and field 15
(`completeness_bound`, the sets_found/trials_used/bounded triple) are deliberately
split per the brief -- both unpack the same AlternateSetsResult but are kept as two
distinct top-level bundle keys rather than nested one inside the other, so the
same three completeness counts are never duplicated across two shapes. Field 5
(`controlled_pinned_conditions`) and field 13 (`controls`) are, by contrast,
*intentionally* the same value under two different key names (PHASE1-PLAN.md's own
separate naming of "controlled/pinned conditions" (sec 2.8) vs. "controls" (Phase-1
addendum)) -- likewise field 4 (`replication_counts`) and field 14 (`k`) are the
same int under two names. Neither of these is a bug to "fix" by collapsing the
keys; tested explicitly below as intentional duplication.

Redaction: `redact_text` (mcp-servers/redact.py, reused as-is, unmodified) only
ever operates on one string at a time -- the recursive dict/list walk that applies
it to every string leaf of the assembled bundle is assemble_bundle's own bundle-
assembly logic (a private `_redact_recursive` helper in cem_engine.py), not
redact.py's job. The redaction tests below plant an obviously-secret-shaped
fixture (a fake-but-real-shaped JWT, the exact trigger shape test_redact.py's own
tests already use) inside original_baseline/intervention_matrix/audit_trail, and
first prove the fixture is non-vacuous (redact_text really does change it on its
own) before relying on it disappearing from the assembled bundle -- otherwise a
totally broken redaction pass could pass the bundle-level tests by accident.
"""
import inspect
import json

import pytest
from cem_engine import (
    AlternateSetsResult,
    DeterminismResult,
    InteractionEvidence,
    MinimalSetResult,
    PocMinimizationResult,
    RaceResult,
    SimilarityToBaseline,
    SuccessSignature,
    assemble_bundle,
    classify,
    classify_race,
    determinism_gate,
    evaluate_signature,
    find_alternate_condition_sets,
    minimal_condition_sets,
    minimize_poc,
)
from http_probe import FetchResult
from redact import redact_text

# ---------------------------------------------------------------------------
# status_in
# ---------------------------------------------------------------------------

def test_status_in_matches():
    sig = SuccessSignature(status_in=[200, 201])
    assert evaluate_signature(FetchResult(status=200, body="ok"), sig) is True


def test_status_in_does_not_match():
    sig = SuccessSignature(status_in=[200])
    assert evaluate_signature(FetchResult(status=403, body="forbidden"), sig) is False


# ---------------------------------------------------------------------------
# body_contains
# ---------------------------------------------------------------------------

def test_body_contains_matches():
    sig = SuccessSignature(body_contains="order total: $500")
    assert evaluate_signature(FetchResult(status=200, body="your order total: $500 today"), sig) is True


def test_body_contains_does_not_match():
    sig = SuccessSignature(body_contains="order total: $500")
    assert evaluate_signature(FetchResult(status=200, body="access denied"), sig) is False


# ---------------------------------------------------------------------------
# body_regex
# ---------------------------------------------------------------------------

def test_body_regex_matches():
    sig = SuccessSignature(body_regex=r"order #\d{4,}")
    assert evaluate_signature(FetchResult(status=200, body="see order #4521 for details"), sig) is True


def test_body_regex_does_not_match():
    sig = SuccessSignature(body_regex=r"order #\d{4,}")
    assert evaluate_signature(FetchResult(status=200, body="no such order"), sig) is False


# ---------------------------------------------------------------------------
# similarity_to_baseline
# ---------------------------------------------------------------------------

def test_similarity_to_baseline_matches_when_above_threshold():
    sig = SuccessSignature(similarity_to_baseline=SimilarityToBaseline(
        body="order #4521 total $89.97 shipping to 123 Main Street", threshold=0.9,
    ))
    result = FetchResult(status=200, body="order #4521 total $89.97 shipping to 123 Main Street")
    assert evaluate_signature(result, sig) is True


def test_similarity_to_baseline_fails_when_below_threshold():
    sig = SuccessSignature(similarity_to_baseline=SimilarityToBaseline(
        body="order #4521 total $89.97 shipping to 123 Main Street", threshold=0.9,
    ))
    result = FetchResult(status=200, body="access denied")
    assert evaluate_signature(result, sig) is False


def test_similarity_to_baseline_boundary_is_inclusive():
    # spec is ">= t" -- a ratio exactly equal to the threshold must pass, not fail.
    sig = SuccessSignature(similarity_to_baseline=SimilarityToBaseline(body="abc", threshold=1.0))
    result = FetchResult(status=200, body="abc")
    assert evaluate_signature(result, sig) is True


# ---------------------------------------------------------------------------
# AND semantics across multiple fields set on one signature
# ---------------------------------------------------------------------------

def test_multiple_matchers_all_must_pass():
    sig = SuccessSignature(status_in=[200], body_contains="total")
    assert evaluate_signature(FetchResult(status=200, body="order total: $500"), sig) is True


def test_multiple_matchers_one_failing_fails_the_whole_signature():
    sig = SuccessSignature(status_in=[200], body_contains="total")
    # status matches but body doesn't -- AND semantics means overall False
    assert evaluate_signature(FetchResult(status=200, body="access denied"), sig) is False
    # body matches but status doesn't
    assert evaluate_signature(FetchResult(status=403, body="order total: $500"), sig) is False


# ---------------------------------------------------------------------------
# A failed/errored request never satisfies any signature
# ---------------------------------------------------------------------------

def test_fetch_error_never_satisfies_any_signature():
    sig = SuccessSignature(status_in=[200, 403, 404, 500])  # deliberately permissive
    result = FetchResult(status=None, body="", error="Connection refused")
    assert evaluate_signature(result, sig) is False


# ---------------------------------------------------------------------------
# UD-3: explicit oracle is mandatory -- no field defaults to "always true", no
# construction path yields an empty/auto signature, no dict is accepted loosely.
# ---------------------------------------------------------------------------

def test_signature_with_no_matchers_set_is_rejected_at_construction():
    with pytest.raises(ValueError, match="at least one matcher"):
        SuccessSignature()


def test_from_dict_rejects_empty_dict():
    with pytest.raises(ValueError):
        SuccessSignature.from_dict({})


def test_from_dict_rejects_non_dict():
    with pytest.raises(TypeError):
        SuccessSignature.from_dict(None)
    with pytest.raises(TypeError):
        SuccessSignature.from_dict("status_in=200")


def test_from_dict_rejects_unknown_key():
    with pytest.raises(ValueError, match="unknown"):
        SuccessSignature.from_dict({"stauts_in": [200]})  # typo'd key


def test_evaluate_signature_rejects_a_raw_dict_instead_of_a_signature():
    with pytest.raises(TypeError):
        evaluate_signature(FetchResult(status=200, body="ok"), {"status_in": [200]})


def test_evaluate_signature_rejects_none_signature():
    with pytest.raises(TypeError):
        evaluate_signature(FetchResult(status=200, body="ok"), None)


# ---------------------------------------------------------------------------
# Malformed signature handling -- safe, deterministic rejection, never a
# silently-wrong verdict.
# ---------------------------------------------------------------------------

def test_status_in_rejects_non_list():
    with pytest.raises(TypeError):
        SuccessSignature(status_in=200)


def test_status_in_rejects_empty_list():
    with pytest.raises(ValueError):
        SuccessSignature(status_in=[])


def test_status_in_rejects_non_int_elements():
    with pytest.raises(TypeError):
        SuccessSignature(status_in=["200"])


def test_body_contains_rejects_non_string():
    with pytest.raises(TypeError):
        SuccessSignature(body_contains=12345)


def test_body_regex_rejects_invalid_pattern():
    with pytest.raises(ValueError, match="regular expression"):
        SuccessSignature(body_regex="(unclosed[")


def test_similarity_to_baseline_rejects_non_string_body():
    with pytest.raises(TypeError):
        SimilarityToBaseline(body=12345, threshold=0.9)


def test_similarity_to_baseline_rejects_threshold_out_of_range():
    with pytest.raises(ValueError):
        SimilarityToBaseline(body="x", threshold=1.5)
    with pytest.raises(ValueError):
        SimilarityToBaseline(body="x", threshold=-0.1)


def test_similarity_to_baseline_rejects_non_numeric_threshold():
    with pytest.raises(TypeError):
        SimilarityToBaseline(body="x", threshold="high")


def test_from_dict_similarity_to_baseline_requires_body_and_threshold():
    with pytest.raises(ValueError):
        SuccessSignature.from_dict({"similarity_to_baseline": {"body": "x"}})
    with pytest.raises(ValueError):
        SuccessSignature.from_dict({"similarity_to_baseline": {"threshold": 0.9}})


# ---------------------------------------------------------------------------
# from_dict round-trips the exact shape case_store.cem_define/cem_load_state use
# ---------------------------------------------------------------------------

def test_from_dict_builds_a_working_signature():
    sig = SuccessSignature.from_dict({"status_in": [200], "body_contains": "total"})
    assert evaluate_signature(FetchResult(status=200, body="order total: $9"), sig) is True


def test_from_dict_similarity_to_baseline_builds_a_working_signature():
    sig = SuccessSignature.from_dict({
        "similarity_to_baseline": {"body": "order #4521 total $89.97", "threshold": 0.9},
    })
    assert evaluate_signature(FetchResult(status=200, body="order #4521 total $89.97"), sig) is True
    assert evaluate_signature(FetchResult(status=200, body="access denied"), sig) is False


# ---------------------------------------------------------------------------
# Determinism: identical inputs always produce identical results, repeatedly.
# ---------------------------------------------------------------------------

def test_evaluation_is_deterministic_across_repeated_calls():
    sig = SuccessSignature(status_in=[200], body_regex=r"order #\d+")
    result = FetchResult(status=200, body="order #4521 total $9")
    outcomes = {evaluate_signature(result, sig) for _ in range(50)}
    assert outcomes == {True}


def test_non_matching_evaluation_is_deterministic_across_repeated_calls():
    sig = SuccessSignature(status_in=[200], body_regex=r"order #\d+")
    result = FetchResult(status=403, body="forbidden")
    outcomes = {evaluate_signature(result, sig) for _ in range(50)}
    assert outcomes == {False}


# ===========================================================================
# C2: determinism_gate
#
# fetch_fn is injected with http_probe.fetch's exact signature
# (url, method, headers, body, timeout_s) -> FetchResult, so a real production
# caller (a later task) can pass http_probe.fetch itself with zero adapter code --
# reusing the existing primitive's contract rather than inventing a new one. Every
# fake fetch here is a plain Python function/closure; none of them touch a socket.
# ===========================================================================

_BASE_REQUEST = {"method": "GET", "url": "https://t/doc/1", "headers": {"Cookie": "s=1"}, "body": None}
_HIT_SIG = SuccessSignature(status_in=[200])


def _fetch_sequence(statuses):
    """fetch_fn that returns FetchResult(status=s, body="ok") for each status in
    `statuses`, one per call, in order. Records every call's args on .calls for
    inspection. Raises if called more times than len(statuses) -- a determinism_gate
    that calls fetch_fn more than k times must fail loudly, not silently reuse/repeat
    a response."""
    calls = []
    remaining = list(statuses)

    def fetch_fn(url, method, headers, body, timeout_s):
        calls.append((url, method, headers, body, timeout_s))
        if not remaining:
            raise AssertionError("fetch_fn called more times than expected")
        status = remaining.pop(0)
        return FetchResult(status=status, body="ok")

    fetch_fn.calls = calls
    return fetch_fn


def _fetch_constant(status):
    """fetch_fn that always returns the same status -- reusable across multiple
    determinism_gate calls, for the determinism-of-the-gate-itself test."""
    def fetch_fn(url, method, headers, body, timeout_s):
        return FetchResult(status=status, body="ok")
    return fetch_fn


def test_all_k_hit_is_stable():
    fetch_fn = _fetch_sequence([200, 200, 200, 200, 200])
    result = determinism_gate(_BASE_REQUEST, 5, _HIT_SIG, fetch_fn)
    assert isinstance(result, DeterminismResult)
    assert result.status == "STABLE"
    assert result.hits == [True, True, True, True, True]
    assert result.k == 5


def test_one_miss_among_k_is_nondeterministic():
    fetch_fn = _fetch_sequence([200, 200, 200, 200, 403])
    result = determinism_gate(_BASE_REQUEST, 5, _HIT_SIG, fetch_fn)
    assert result.status == "NONDETERMINISTIC"
    assert result.hits == [True, True, True, True, False]


def test_alternating_hit_miss_is_nondeterministic():
    fetch_fn = _fetch_sequence([200, 403, 200, 403])
    result = determinism_gate(_BASE_REQUEST, 4, _HIT_SIG, fetch_fn)
    assert result.status == "NONDETERMINISTIC"
    assert result.hits == [True, False, True, False]


def test_all_k_miss_is_nondeterministic_not_a_third_bucket():
    # the plan's contract is a strict binary -- consistently MISSing is still
    # NONDETERMINISTIC, never a separate "STABLE_MISS"/"CONFIRMED_ABSENT" status.
    fetch_fn = _fetch_sequence([403, 403, 403])
    result = determinism_gate(_BASE_REQUEST, 3, _HIT_SIG, fetch_fn)
    assert result.status == "NONDETERMINISTIC"
    assert result.hits == [False, False, False]


def test_k_equals_one_hit_is_stable():
    fetch_fn = _fetch_sequence([200])
    result = determinism_gate(_BASE_REQUEST, 1, _HIT_SIG, fetch_fn)
    assert result.status == "STABLE"
    assert result.hits == [True]


def test_k_equals_one_miss_is_nondeterministic():
    fetch_fn = _fetch_sequence([403])
    result = determinism_gate(_BASE_REQUEST, 1, _HIT_SIG, fetch_fn)
    assert result.status == "NONDETERMINISTIC"
    assert result.hits == [False]


def test_invalid_k_zero_rejected():
    with pytest.raises(ValueError):
        determinism_gate(_BASE_REQUEST, 0, _HIT_SIG, _fetch_constant(200))


def test_invalid_k_negative_rejected():
    with pytest.raises(ValueError):
        determinism_gate(_BASE_REQUEST, -1, _HIT_SIG, _fetch_constant(200))


def test_invalid_k_non_int_rejected():
    with pytest.raises(TypeError):
        determinism_gate(_BASE_REQUEST, "5", _HIT_SIG, _fetch_constant(200))
    with pytest.raises(TypeError):
        determinism_gate(_BASE_REQUEST, 5.0, _HIT_SIG, _fetch_constant(200))


def test_invalid_k_bool_rejected():
    # bool is a subclass of int in Python -- must not silently be accepted as k.
    with pytest.raises(TypeError):
        determinism_gate(_BASE_REQUEST, True, _HIT_SIG, _fetch_constant(200))


def test_fetch_fn_called_exactly_k_times():
    for k in (1, 3, 7):
        fetch_fn = _fetch_sequence([200] * k)
        determinism_gate(_BASE_REQUEST, k, _HIT_SIG, fetch_fn)
        assert len(fetch_fn.calls) == k


def test_fetch_fn_called_with_base_request_fields():
    fetch_fn = _fetch_sequence([200, 200])
    determinism_gate(_BASE_REQUEST, 2, _HIT_SIG, fetch_fn)
    for call in fetch_fn.calls:
        url, method, headers, body, _timeout_s = call
        assert url == "https://t/doc/1"
        assert method == "GET"
        assert headers == {"Cookie": "s=1"}
        assert body is None


def test_gate_execution_is_deterministic_across_repeated_calls():
    fetch_fn = _fetch_constant(200)
    outcomes = {determinism_gate(_BASE_REQUEST, 5, _HIT_SIG, fetch_fn).status for _ in range(20)}
    assert outcomes == {"STABLE"}


def test_gate_execution_is_deterministic_for_the_nondeterministic_case_too():
    # "deterministic repeated execution of the gate" means the GATE's classification
    # logic is deterministic given the same fetch behavior -- not that the underlying
    # target is stable. A fetch_fn that always returns a MISS must always yield
    # NONDETERMINISTIC, every time the gate itself is invoked.
    fetch_fn = _fetch_constant(403)
    outcomes = {determinism_gate(_BASE_REQUEST, 5, _HIT_SIG, fetch_fn).status for _ in range(20)}
    assert outcomes == {"NONDETERMINISTIC"}


def test_fetch_error_trial_counts_as_a_miss_not_a_third_status():
    # existing Phase-1 contract (C1): a FetchResult with .error set never satisfies
    # any signature. One connection-level failure among otherwise-HIT trials is
    # exactly one MISS, handled by the same binary rule -- no special-cased status.
    call_count = [0]

    def fetch_fn(url, method, headers, body, timeout_s):
        call_count[0] += 1
        if call_count[0] == 3:
            return FetchResult(status=None, body="", error="Connection refused")
        return FetchResult(status=200, body="ok")

    result = determinism_gate(_BASE_REQUEST, 5, _HIT_SIG, fetch_fn)
    assert result.status == "NONDETERMINISTIC"
    assert result.hits.count(False) == 1
    assert call_count[0] == 5


def test_all_trials_fetch_error_is_nondeterministic():
    def fetch_fn(url, method, headers, body, timeout_s):
        return FetchResult(status=None, body="", error="Connection refused")
    result = determinism_gate(_BASE_REQUEST, 3, _HIT_SIG, fetch_fn)
    assert result.status == "NONDETERMINISTIC"
    assert result.hits == [False, False, False]


def test_determinism_gate_rejects_non_signature():
    with pytest.raises(TypeError):
        determinism_gate(_BASE_REQUEST, 3, {"status_in": [200]}, _fetch_constant(200))


def test_determinism_gate_never_calls_the_real_http_probe_fetch(monkeypatch):
    import http_probe

    def _forbidden(*args, **kwargs):
        raise AssertionError("determinism_gate must never call the real http_probe.fetch")

    monkeypatch.setattr(http_probe, "fetch", _forbidden)
    result = determinism_gate(_BASE_REQUEST, 3, _HIT_SIG, _fetch_constant(200))
    assert result.status == "STABLE"


# ===========================================================================
# C3: classify -- pure verdict classification over already-observed hit
# sequences. Exactly 3 verdicts: necessary / apparently_not_necessary /
# inconclusive. No fetch_fn, no HTTP, no perturbation, no throttle parameter
# (see module docstring's C3 scope-boundary note).
# ===========================================================================

def test_stable_baseline_hit_stable_perturbed_miss_is_necessary():
    assert classify([True] * 5, [False] * 5, 5) == "necessary"


def test_stable_baseline_hit_stable_perturbed_hit_is_apparently_not_necessary():
    assert classify([True] * 5, [True] * 5, 5) == "apparently_not_necessary"


def test_mixed_baseline_is_inconclusive():
    # baseline itself isn't trustworthy this run -- no comparison against it can be
    # trusted either, regardless of what the perturbed arm looks like.
    assert classify([True, True, False, True, True], [False] * 5, 5) == "inconclusive"
    assert classify([True, True, False, True, True], [True] * 5, 5) == "inconclusive"


def test_mixed_perturbed_with_stable_baseline_is_inconclusive():
    assert classify([True] * 5, [True, False, True, False, True], 5) == "inconclusive"


def test_baseline_all_miss_is_inconclusive():
    # baseline failure -- not just "mixed", but consistently NOT establishing the
    # expected successful behavior at all -- is still "baseline not all-HIT", so
    # still inconclusive, never necessary/apparently_not_necessary.
    assert classify([False] * 5, [False] * 5, 5) == "inconclusive"
    assert classify([False] * 5, [True] * 5, 5) == "inconclusive"


def test_all_miss_perturbed_arm_with_valid_stable_baseline_is_necessary():
    # same rule as test_stable_baseline_hit_stable_perturbed_miss_is_necessary,
    # phrased to match PHASE1-EXECUTION-PLAN.md's own wording ("all-miss perturbed
    # arm ... correct necessary behavior when the baseline is valid and stable").
    baseline_hits = [True, True, True]
    perturbed_hits = [False, False, False]
    assert classify(baseline_hits, perturbed_hits, 3) == "necessary"


def test_classify_signature_has_no_throttle_parameter_by_design():
    # 2026-09-05 human-approved scope decision: throttle/rate-limit detection is the
    # executor's job (task D3, which inspects real HTTP status as trials happen), not
    # classify()'s. classify() only ever sees plain hit/miss bools. This test pins the
    # boundary down so a future task doesn't silently widen classify()'s signature to
    # smuggle a throttle flag back in without an equally explicit decision.
    sig = inspect.signature(classify)
    assert list(sig.parameters) == ["baseline_hits", "perturbed_hits", "k"]


def test_classify_rejects_baseline_length_mismatched_with_k():
    with pytest.raises(ValueError):
        classify([True, True], [False] * 5, 5)


def test_classify_rejects_perturbed_length_mismatched_with_k():
    with pytest.raises(ValueError):
        classify([True] * 5, [False, False], 5)


def test_classify_rejects_non_list_baseline_hits():
    with pytest.raises(TypeError):
        classify("HIT,HIT,HIT", [False] * 3, 3)


def test_classify_rejects_non_bool_elements():
    with pytest.raises(TypeError):
        classify([1, 1, 1], [False] * 3, 3)
    with pytest.raises(TypeError):
        classify([True] * 3, [0, 0, 0], 3)


def test_classify_rejects_invalid_k_zero():
    with pytest.raises(ValueError):
        classify([], [], 0)


def test_classify_rejects_invalid_k_negative():
    with pytest.raises(ValueError):
        classify([True], [False], -1)


def test_classify_rejects_invalid_k_non_int():
    with pytest.raises(TypeError):
        classify([True], [False], "1")


def test_classify_rejects_invalid_k_bool():
    with pytest.raises(TypeError):
        classify([True], [False], True)


def test_classify_is_deterministic_across_repeated_calls():
    outcomes = {classify([True] * 5, [False] * 5, 5) for _ in range(50)}
    assert outcomes == {"necessary"}

    outcomes2 = {classify([True] * 5, [True, False, True, False, True], 5) for _ in range(50)}
    assert outcomes2 == {"inconclusive"}


def test_classify_never_touches_the_real_http_probe_fetch(monkeypatch):
    import http_probe

    def _forbidden(*args, **kwargs):
        raise AssertionError("classify must never call the real http_probe.fetch")

    monkeypatch.setattr(http_probe, "fetch", _forbidden)
    assert classify([True] * 3, [False] * 3, 3) == "necessary"


def test_classify_returns_only_the_three_documented_verdicts():
    # never a 4th verdict (interacting/probabilistic are separate later tasks C4/C6),
    # never anything other than these exact 3 strings.
    cases = [
        ([True] * 3, [True] * 3, 3),
        ([True] * 3, [False] * 3, 3),
        ([True] * 3, [True, False, True], 3),
        ([False] * 3, [True] * 3, 3),
    ]
    for baseline, perturbed, k in cases:
        assert classify(baseline, perturbed, k) in {"necessary", "apparently_not_necessary", "inconclusive"}


# ===========================================================================
# C4: classify_race -- race/TOCTOU path. Always "probabilistic", reporting the
# perturbed-arm HIT-rate; structurally can never return "necessary" no matter
# what hit pattern is observed. No baseline_hits, no fetch_fn, no HTTP, no
# perturbation execution, no boolean race flag (see module docstring's C4
# API-resolution note).
# ===========================================================================

def test_race_all_perturbed_hit_is_probabilistic_with_hit_rate_one():
    result = classify_race([True] * 5, 5)
    assert result.verdict == "probabilistic"
    assert result.hit_rate == 1.0
    assert result.k == 5


def test_race_all_perturbed_miss_is_probabilistic_never_necessary():
    # the critical C4 invariant: a flagged-race input whose perturbed arm is
    # all-MISS -- the exact pattern that makes classify() return "necessary" --
    # must still come out "probabilistic", never "necessary".
    result = classify_race([False] * 5, 5)
    assert result.verdict == "probabilistic"
    assert result.hit_rate == 0.0
    assert result.k == 5


def test_race_mixed_perturbed_hit_rate_is_the_observed_fraction():
    result = classify_race([True, True, True, False, False], 5)
    assert result.verdict == "probabilistic"
    assert result.hit_rate == pytest.approx(0.6)
    assert result.k == 5


def test_race_never_returns_necessary_across_every_hit_pattern():
    # exhaustive over every hit pattern for small k -- no combination of
    # perturbed-arm outcomes can ever flip classify_race's verdict away from
    # "probabilistic". This is what makes race handling probabilistic rather
    # than a false deterministic causal conclusion.
    import itertools

    for k in (1, 2, 3, 4):
        for combo in itertools.product([True, False], repeat=k):
            result = classify_race(list(combo), k)
            assert result.verdict == "probabilistic"


def test_classify_race_returns_a_raceresult_instance():
    result = classify_race([True, False], 2)
    assert isinstance(result, RaceResult)


def test_classify_race_signature_takes_no_baseline_hits_and_no_race_flag():
    # pins the C4 API-resolution decision down so a future task can't silently
    # widen classify_race's signature (e.g. sneaking baseline_hits or a
    # boolean race flag back in) without an equally explicit decision.
    sig = inspect.signature(classify_race)
    assert list(sig.parameters) == ["perturbed_hits", "k"]


def test_classify_race_rejects_length_mismatched_with_k():
    with pytest.raises(ValueError):
        classify_race([True, True], 5)


def test_classify_race_rejects_non_list_perturbed_hits():
    with pytest.raises(TypeError):
        classify_race("HIT,HIT,HIT", 3)


def test_classify_race_rejects_non_bool_elements():
    with pytest.raises(TypeError):
        classify_race([1, 0, 1], 3)


def test_classify_race_rejects_invalid_k_zero():
    with pytest.raises(ValueError):
        classify_race([], 0)


def test_classify_race_rejects_invalid_k_negative():
    with pytest.raises(ValueError):
        classify_race([True], -1)


def test_classify_race_rejects_invalid_k_non_int():
    with pytest.raises(TypeError):
        classify_race([True], "1")


def test_classify_race_rejects_invalid_k_bool():
    with pytest.raises(TypeError):
        classify_race([True], True)


def test_classify_race_is_deterministic_across_repeated_calls():
    results = [classify_race([True, False, True], 3) for _ in range(50)]
    assert all(r.verdict == "probabilistic" for r in results)
    assert all(r.hit_rate == pytest.approx(2 / 3) for r in results)


def test_classify_race_never_touches_the_real_http_probe_fetch(monkeypatch):
    import http_probe

    def _forbidden(*args, **kwargs):
        raise AssertionError("classify_race must never call the real http_probe.fetch")

    monkeypatch.setattr(http_probe, "fetch", _forbidden)
    result = classify_race([False] * 3, 3)
    assert result.verdict == "probabilistic"


# ---------------------------------------------------------------------------
# minimal_condition_sets (C5)
# ---------------------------------------------------------------------------

def test_minimal_condition_sets_returns_minimalsetresult_instance():
    result = minimal_condition_sets(["a"], lambda s: True)
    assert isinstance(result, MinimalSetResult)


def test_minimal_condition_sets_removes_the_one_unnecessary_condition():
    # only "a" matters; "b" can always be dropped.
    is_interesting = lambda s: "a" in s
    result = minimal_condition_sets(["a", "b"], is_interesting)
    assert result.minimal_set == frozenset({"a"})


def test_minimal_condition_sets_recovers_planted_minimal_set_doc_scenario():
    # mirrors the ground-truth benchmark's /doc/{id} shape: auth_cookie is
    # planted-necessary, trace_param is planted-irrelevant (H/§8, read-only
    # reference here -- no import of the protected benchmark fixtures).
    is_interesting = lambda s: "auth_cookie" in s
    result = minimal_condition_sets(["auth_cookie", "trace_param"], is_interesting)
    assert result.minimal_set == frozenset({"auth_cookie"})


def test_minimal_condition_sets_repeated_removal_converges_on_larger_set():
    # 4 candidate conditions, only "a" is ever needed -- ddmin must keep
    # sweeping/restarting until every removable condition is gone, not stop
    # after the first successful removal.
    is_interesting = lambda s: "a" in s
    result = minimal_condition_sets(["a", "b", "c", "d"], is_interesting)
    assert result.minimal_set == frozenset({"a"})


def test_minimal_condition_sets_both_conditions_required_neither_removable():
    # AND-interaction shape (mirrors /merge needing role=admin AND flag=on):
    # neither condition alone reproduces the effect, so ddmin cannot remove
    # either -- both must remain in the 1-minimal set.
    is_interesting = lambda s: "role_admin" in s and "flag_on" in s
    result = minimal_condition_sets(["role_admin", "flag_on"], is_interesting)
    assert result.minimal_set == frozenset({"role_admin", "flag_on"})


def test_minimal_condition_sets_recovers_a_valid_minimal_set_when_multiple_exist():
    # OR-shape (mirrors /report reachable via header OR cookie): both {"a"}
    # and {"b"} are independently valid 1-minimal sets. C5 only needs to
    # recover ONE of them (alternates are C6's job) -- verify genericially
    # that whichever one it returns is truly 1-minimal (interesting itself,
    # and removing its one remaining element breaks interestingness), plus
    # pin the specific deterministic outcome for this exact algorithm/order.
    is_interesting = lambda s: ("a" in s) or ("b" in s)
    result = minimal_condition_sets(["a", "b"], is_interesting)
    assert result.minimal_set in (frozenset({"a"}), frozenset({"b"}))
    assert is_interesting(result.minimal_set) is True
    for element in result.minimal_set:
        assert is_interesting(result.minimal_set - {element}) is False
    # deterministic for this algorithm/order: earliest-in-input-order is
    # attempted for removal first, so "a" is dropped and "b" survives.
    assert result.minimal_set == frozenset({"b"})


def test_minimal_condition_sets_predicate_is_always_called_with_a_frozenset():
    seen_types = []

    def spy(subset):
        seen_types.append(type(subset))
        return "a" in subset

    minimal_condition_sets(["a", "b", "c"], spy)
    assert seen_types  # at least one call happened
    assert all(t is frozenset for t in seen_types)


def test_minimal_condition_sets_empty_conditions_returns_empty_set_with_zero_calls():
    calls = []

    def spy(subset):
        calls.append(subset)
        return True

    result = minimal_condition_sets([], spy)
    assert result.minimal_set == frozenset()
    assert result.predicate_calls == 0
    assert calls == []  # predicate never consulted for a trivially-empty input


def test_minimal_condition_sets_single_condition_that_is_necessary():
    is_interesting = lambda s: "auth_cookie" in s
    result = minimal_condition_sets(["auth_cookie"], is_interesting)
    assert result.minimal_set == frozenset({"auth_cookie"})


def test_minimal_condition_sets_single_condition_that_is_not_necessary_reduces_to_empty():
    # ddmin must still try reducing a singleton down to the empty set --
    # "only one candidate condition" does not mean "assume it's necessary".
    result = minimal_condition_sets(["trace_param"], lambda s: True)
    assert result.minimal_set == frozenset()


def test_minimal_condition_sets_returned_set_is_a_subset_of_input_conditions():
    is_interesting = lambda s: "b" in s
    result = minimal_condition_sets(["a", "b", "c"], is_interesting)
    assert result.minimal_set <= frozenset({"a", "b", "c"})


def test_minimal_condition_sets_rejects_non_list_conditions():
    with pytest.raises(TypeError):
        minimal_condition_sets(frozenset({"a"}), lambda s: True)


def test_minimal_condition_sets_rejects_non_string_condition_elements():
    with pytest.raises(TypeError):
        minimal_condition_sets(["a", 2], lambda s: True)


def test_minimal_condition_sets_rejects_duplicate_conditions():
    with pytest.raises(ValueError):
        minimal_condition_sets(["a", "a"], lambda s: True)


def test_minimal_condition_sets_rejects_non_callable_predicate():
    with pytest.raises(TypeError):
        minimal_condition_sets(["a"], "not-callable")


def test_minimal_condition_sets_rejects_full_set_not_interesting():
    # ddmin's own precondition: you cannot minimize a set that doesn't
    # reproduce the effect in the first place.
    with pytest.raises(ValueError):
        minimal_condition_sets(["a", "b"], lambda s: False)


def test_minimal_condition_sets_rejects_predicate_returning_non_bool():
    # pins the C5 scope boundary: the ddmin predicate contract is strictly
    # bool (PHASE1-PLAN.md's own binary definition of "interesting"); a
    # predicate that returns None (e.g. "not yet observed") is a hard error,
    # never silently treated as falsy/truthy or as a 3rd "inconclusive" state.
    with pytest.raises(TypeError):
        minimal_condition_sets(["a"], lambda s: None)


def test_minimal_condition_sets_is_deterministic_across_repeated_calls():
    is_interesting = lambda s: "a" in s
    results = [minimal_condition_sets(["a", "b", "c"], is_interesting) for _ in range(20)]
    assert all(r.minimal_set == frozenset({"a"}) for r in results)
    assert all(r.predicate_calls == results[0].predicate_calls for r in results)


def test_minimal_condition_sets_exact_predicate_call_count_for_known_scenario():
    # hand-traced against the documented single-element-removal-sweep
    # algorithm: conditions=["a","b"], only "a" matters.
    #   call 1: test({a,b})            -> True  (precondition check)
    #   call 2: test({b})   (drop a)   -> False
    #   call 3: test({a})   (drop b)   -> True  -> current = ["a"]
    #   call 4: test({})    (drop a)   -> False -> no further change
    is_interesting = lambda s: "a" in s
    result = minimal_condition_sets(["a", "b"], is_interesting)
    assert result.minimal_set == frozenset({"a"})
    assert result.predicate_calls == 4


def test_minimal_condition_sets_never_touches_the_real_http_probe_fetch(monkeypatch):
    import http_probe

    def _forbidden(*args, **kwargs):
        raise AssertionError("minimal_condition_sets must never call the real http_probe.fetch")

    monkeypatch.setattr(http_probe, "fetch", _forbidden)
    result = minimal_condition_sets(["a", "b"], lambda s: "a" in s)
    assert result.minimal_set == frozenset({"a"})


def test_minimal_condition_sets_signature_has_no_finding_id_no_db_no_network_params():
    # pins the C5 API-resolution decision down: this is the pure engine-layer
    # function (conditions, injected predicate) -- NOT the DB-backed
    # orchestration-level minimal_condition_sets(finding_id) from
    # PHASE1-PLAN.md sec B item 4, which is a later (E1) task.
    sig = inspect.signature(minimal_condition_sets)
    assert list(sig.parameters) == ["conditions", "is_interesting"]


# ---------------------------------------------------------------------------
# find_alternate_condition_sets (C6)
# ---------------------------------------------------------------------------
# Scenario predicates used below (hand-traced against the documented algorithm
# before writing assertions -- exact call counts and outcomes are not guesses):
#
#   OR_HEADER_COOKIE: mirrors the benchmark's /report (header OR cookie).
#   AND_NO_REDUNDANCY: mirrors /merge (role=admin AND flag=on) with NO other
#     redundancy anywhere -- both conditions are genuinely, individually
#     necessary, so neither rule's precondition (individually droppable) is
#     even met; this is the "never infer interaction from mere co-occurrence"
#     negative case.
#   OR_THEN_GATE (a, b, d): d is always required; a and b are mutually
#     substitutable but jointly required -- ddmin (list order ["a","b","d"])
#     drops "a" immediately, so "a" never becomes an M1 member, yet a
#     genuine Rule-2 interaction exists between a and b.
#   ANY_TWO_OF_THREE (gate, p, q, r): gate always required; any 2 of {p,q,r}
#     suffice. Rich enough to give 3 distinct minimal sets and a genuine,
#     non-vacuous Rule-1 firing (for p and r, which survive in M1) alongside
#     Rule 2 (which independently catches all 3 pairs, including q).

def _or_header_cookie(s):
    return ("header" in s) or ("cookie" in s)


def _and_no_redundancy(s):
    return ("role_admin" in s) and ("flag_on" in s)


def _or_then_gate(s):
    return ("d" in s) and (("a" in s) or ("b" in s))


def _any_two_of_three(s):
    return ("gate" in s) and (
        ("p" in s and "q" in s) or ("q" in s and "r" in s) or ("p" in s and "r" in s)
    )


def test_c6_returns_alternatesetsresult_instance():
    result = find_alternate_condition_sets(["header", "cookie"], _or_header_cookie, 100)
    assert isinstance(result, AlternateSetsResult)


def test_c6_finds_at_least_two_sets_when_planted_or_redundancy():
    # the literal C6 accept criterion: "≥2 sets when planted".
    result = find_alternate_condition_sets(["header", "cookie"], _or_header_cookie, 100)
    assert result.sets_found >= 2
    assert set(result.minimal_sets) == {frozenset({"cookie"}), frozenset({"header"})}


def test_c6_rule2_flags_the_only_two_independent_paths_as_interacting():
    # Rule 2 taken literally: removing BOTH of the only two sufficient paths
    # together flips the oracle, while neither alone does -- true, even
    # though it's a direct corollary of "these are the only 2 minimal sets"
    # rather than a surprising hidden dependency. Documented honestly rather
    # than silently suppressed (the plan states no exclusion for this case).
    result = find_alternate_condition_sets(["header", "cookie"], _or_header_cookie, 100)
    assert result.interacting == frozenset({"header", "cookie"})
    assert result.interacting_pairs == [InteractionEvidence(pair=frozenset({"cookie", "header"}))]


def test_c6_exact_call_accounting_for_or_header_cookie_scenario():
    # hand-traced: base=3, alternates-loop(1 attempt, success)=+2=5,
    # droppability-scan(2 conditions)=+2=7, pairwise(1 pair)=+1=8.
    result = find_alternate_condition_sets(["header", "cookie"], _or_header_cookie, 100)
    assert result.trials_used == 8
    assert result.bounded is False


def test_c6_never_infers_interaction_from_pure_necessity_with_no_redundancy():
    # neither role_admin nor flag_on is individually droppable at all (each
    # is genuinely, straightforwardly necessary) -- so neither rule's
    # precondition is met, and C6 must NOT flag anything "interacting" just
    # because the minimal set happens to have 2 members.
    result = find_alternate_condition_sets(["role_admin", "flag_on"], _and_no_redundancy, 100)
    assert result.sets_found == 1
    assert result.minimal_sets == [frozenset({"role_admin", "flag_on"})]
    assert result.interacting == frozenset()
    assert result.interacting_pairs == []


def test_c6_exact_call_accounting_for_and_no_redundancy_scenario():
    # hand-traced: base=3, alternates-loop(2 attempts, both ValueError)=+2=5,
    # droppability-scan(2 conditions, both False)=+2=7.
    result = find_alternate_condition_sets(["role_admin", "flag_on"], _and_no_redundancy, 100)
    assert result.trials_used == 7


def test_c6_rule2_detects_interaction_even_when_one_member_never_reaches_m1():
    # the a/b/d example from the module docstring: ddmin drops "a" before it
    # ever reaches M1 (M1 = {b, d}), yet a and b genuinely interact
    # (mutually substitutable, jointly required alongside d). This is only
    # detectable because interaction-candidate testing was broadened to ALL
    # of the original conditions, not just M1's own members.
    result = find_alternate_condition_sets(["a", "b", "d"], _or_then_gate, 100)
    assert result.sets_found == 2
    assert set(result.minimal_sets) == {frozenset({"b", "d"}), frozenset({"a", "d"})}
    assert result.interacting == frozenset({"a", "b"})
    assert result.interacting_pairs == [InteractionEvidence(pair=frozenset({"a", "b"}))]
    assert result.trials_used == 12


def test_c6_rule1_does_not_fire_on_a_two_member_family_lacking_independent_evidence():
    # In the a/b/d scenario, "b" (an M1 member) has exactly one recovered
    # alternate (its own self-exclusion), which is excluded from Rule 1's
    # comparison by design -- leaving zero independent evidence, so Rule 1
    # must NOT fire for "b" here (Rule 2 alone correctly catches the a/b
    # interaction; Rule 1 correctly stays silent for lack of evidence).
    result = find_alternate_condition_sets(["a", "b", "d"], _or_then_gate, 100)
    # interacting is still {a, b} (via Rule 2), but interacting_pairs has
    # exactly one entry -- proof Rule 1 contributed nothing additional here.
    assert len(result.interacting_pairs) == 1


def test_c6_rule1_fires_with_genuinely_independent_corroborating_alternates():
    # any-2-of-3: M1 = {gate, p, r} (ddmin order ["gate","q","r","p"]).
    # Excluding p yields {gate,q,r}; excluding r yields {gate,q,p} -- two
    # genuinely independent alternates. "p" persists in the r-exclusion
    # alternate and "r" persists in the p-exclusion alternate: real,
    # non-vacuous Rule 1 evidence for both.
    result = find_alternate_condition_sets(["gate", "q", "r", "p"], _any_two_of_three, 100)
    assert result.sets_found == 3
    assert set(result.minimal_sets) == {
        frozenset({"gate", "p", "r"}),
        frozenset({"gate", "q", "r"}),
        frozenset({"gate", "q", "p"}),
    }
    # all three of p, q, r are flagged interacting (q via Rule 2 only; p and
    # r via both Rule 1 and Rule 2) -- gate is never flagged (never
    # individually droppable, so never even a rule candidate).
    assert result.interacting == frozenset({"p", "q", "r"})
    assert "gate" not in result.interacting


def test_c6_rule2_flags_all_three_pairs_in_any_two_of_three_scenario():
    result = find_alternate_condition_sets(["gate", "q", "r", "p"], _any_two_of_three, 100)
    pairs = {ev.pair for ev in result.interacting_pairs}
    assert pairs == {
        frozenset({"p", "q"}),
        frozenset({"p", "r"}),
        frozenset({"q", "r"}),
    }


def test_c6_exact_call_accounting_for_any_two_of_three_scenario():
    # hand-traced: base=6; alternates-loop (gate fails=+1=7, p succeeds=+4=11,
    # r succeeds=+4=15); droppability-scan (4 conditions)=+4=19; pairwise
    # (3 pairs)=+3=22.
    result = find_alternate_condition_sets(["gate", "q", "r", "p"], _any_two_of_three, 100)
    assert result.trials_used == 22
    assert result.bounded is False


def test_c6_bounded_true_and_graceful_partial_result_when_budget_is_tight():
    # max_trials=5 is less than the base computation's own 6 calls -- every
    # subsequent step must be skipped, not crash, and bounded must be
    # reported True rather than silently claiming a complete search.
    result = find_alternate_condition_sets(["gate", "q", "r", "p"], _any_two_of_three, 5)
    assert result.bounded is True
    assert result.minimal_sets == [frozenset({"gate", "p", "r"})]
    assert result.sets_found == 1
    assert result.interacting == frozenset()
    assert result.trials_used == 6


def test_c6_empty_conditions_returns_trivial_result_with_zero_trials():
    result = find_alternate_condition_sets([], lambda s: True, 10)
    assert result.minimal_sets == [frozenset()]
    assert result.sets_found == 1
    assert result.interacting == frozenset()
    assert result.interacting_pairs == []
    assert result.trials_used == 0
    assert result.bounded is False


def test_c6_is_deterministic_across_repeated_calls():
    results = [
        find_alternate_condition_sets(["gate", "q", "r", "p"], _any_two_of_three, 100)
        for _ in range(10)
    ]
    first = results[0]
    for r in results[1:]:
        assert r.minimal_sets == first.minimal_sets
        assert r.interacting == first.interacting
        assert r.trials_used == first.trials_used
        assert r.bounded == first.bounded


def test_c6_rejects_non_list_conditions():
    with pytest.raises(TypeError):
        find_alternate_condition_sets(frozenset({"a"}), lambda s: True, 10)


def test_c6_rejects_non_string_condition_elements():
    with pytest.raises(TypeError):
        find_alternate_condition_sets(["a", 2], lambda s: True, 10)


def test_c6_rejects_duplicate_conditions():
    with pytest.raises(ValueError):
        find_alternate_condition_sets(["a", "a"], lambda s: True, 10)


def test_c6_rejects_non_callable_predicate():
    with pytest.raises(TypeError):
        find_alternate_condition_sets(["a"], "not-callable", 10)


def test_c6_rejects_non_int_max_trials():
    with pytest.raises(TypeError):
        find_alternate_condition_sets(["a"], lambda s: True, "10")


def test_c6_rejects_bool_max_trials():
    with pytest.raises(TypeError):
        find_alternate_condition_sets(["a"], lambda s: True, True)


def test_c6_rejects_zero_max_trials():
    with pytest.raises(ValueError):
        find_alternate_condition_sets(["a"], lambda s: True, 0)


def test_c6_rejects_negative_max_trials():
    with pytest.raises(ValueError):
        find_alternate_condition_sets(["a"], lambda s: True, -1)


def test_c6_reuses_minimal_condition_sets_directly_not_reimplemented(monkeypatch):
    # proves C6 extends C5 by calling it, rather than re-deriving 1-minimal
    # sets via separate/duplicated logic: exactly 1 base call + 1 attempt
    # per M1 member (M1 has exactly 1 member here: "cookie").
    import cem_engine

    real = cem_engine.minimal_condition_sets
    calls = []

    def spy(conditions, is_interesting):
        calls.append(list(conditions))
        return real(conditions, is_interesting)

    monkeypatch.setattr(cem_engine, "minimal_condition_sets", spy)
    find_alternate_condition_sets(["header", "cookie"], _or_header_cookie, 100)
    assert len(calls) == 2
    assert calls[0] == ["header", "cookie"]


def test_c6_never_touches_classify_or_classify_race(monkeypatch):
    # interacting is a separate flag/result (like classify_race's
    # probabilistic), never a 4th classify() verdict and never routed
    # through classify_race -- C6 must not call either.
    import cem_engine

    def _forbidden(*args, **kwargs):
        raise AssertionError("find_alternate_condition_sets must never call classify/classify_race")

    monkeypatch.setattr(cem_engine, "classify", _forbidden)
    monkeypatch.setattr(cem_engine, "classify_race", _forbidden)
    result = find_alternate_condition_sets(["header", "cookie"], _or_header_cookie, 100)
    assert result.sets_found == 2


def test_c6_never_touches_the_real_http_probe_fetch(monkeypatch):
    import http_probe

    def _forbidden(*args, **kwargs):
        raise AssertionError("find_alternate_condition_sets must never call the real http_probe.fetch")

    monkeypatch.setattr(http_probe, "fetch", _forbidden)
    result = find_alternate_condition_sets(["header", "cookie"], _or_header_cookie, 100)
    assert result.sets_found == 2


def test_c6_result_has_no_verdict_field_mimicking_classify():
    # structural guard: AlternateSetsResult carries no field that could be
    # mistaken for a necessary/apparently_not_necessary/inconclusive/
    # probabilistic verdict -- interacting is an orthogonal set of names,
    # not a verdict string.
    import dataclasses

    field_names = {f.name for f in dataclasses.fields(AlternateSetsResult)}
    assert field_names == {
        "minimal_sets", "interacting", "interacting_pairs",
        "sets_found", "trials_used", "bounded",
    }


def test_c6_signature_is_conditions_is_interesting_max_trials():
    sig = inspect.signature(find_alternate_condition_sets)
    assert list(sig.parameters) == ["conditions", "is_interesting", "max_trials"]


# ---------------------------------------------------------------------------
# minimize_poc (C7)
# ---------------------------------------------------------------------------

def _stable(hits_k=3):
    return DeterminismResult(status="STABLE", hits=[True] * hits_k, k=hits_k)


def _nondeterministic(hits_k=3):
    hits = [True, False, True][:hits_k] + [True] * max(0, hits_k - 3)
    return DeterminismResult(status="NONDETERMINISTIC", hits=hits, k=hits_k)


def test_minimize_poc_returns_pocminimizationresult_instance():
    result = minimize_poc(["a"], lambda s: True, lambda poc: _stable())
    assert isinstance(result, PocMinimizationResult)


def test_minimize_poc_drops_the_unnecessary_condition_and_is_accepted():
    # the literal C7 accept criterion: "unnecessary condition dropped;
    # minimal PoC re-passes gate" -- mirrors the benchmark's /doc/{id}
    # scenario (auth_cookie necessary, trace_param irrelevant).
    is_interesting = lambda s: "auth_cookie" in s
    result = minimize_poc(["auth_cookie", "trace_param"], is_interesting, lambda poc: _stable())
    assert result.poc == frozenset({"auth_cookie"})
    assert result.accepted is True
    assert result.determinism.status == "STABLE"


def test_minimize_poc_exact_predicate_call_count_matches_underlying_ddmin():
    # hand-traced against minimal_condition_sets' own documented algorithm:
    # same 4-call trace as C5's auth_cookie/trace_param scenario.
    is_interesting = lambda s: "auth_cookie" in s
    result = minimize_poc(["auth_cookie", "trace_param"], is_interesting, lambda poc: _stable())
    assert result.predicate_calls == 4


def test_minimize_poc_reports_rejection_honestly_on_nondeterministic_revalidation():
    # ddmin local-optimum risk (PHASE1-PLAN.md sec 15): revalidation fails
    # -> minimize_poc must NOT silently accept the candidate, NOT crash,
    # and NOT retry -- it reports accepted=False with the poc still
    # present as evidence.
    is_interesting = lambda s: "a" in s
    result = minimize_poc(["a", "b"], is_interesting, lambda poc: _nondeterministic())
    assert result.accepted is False
    assert result.poc == frozenset({"a"})
    assert result.determinism.status == "NONDETERMINISTIC"


def test_minimize_poc_calls_revalidate_exactly_once_with_the_minimal_set():
    calls = []

    def spy(poc):
        calls.append(poc)
        return _stable()

    is_interesting = lambda s: "auth_cookie" in s
    minimize_poc(["auth_cookie", "trace_param"], is_interesting, spy)
    assert calls == [frozenset({"auth_cookie"})]


def test_minimize_poc_does_not_retry_or_reiterate_after_a_failed_revalidation():
    # proof there is no automatic "DDMIN* re-iterate" -- PHASE1-PLAN.md
    # marks that explicitly optional/out of Phase-1 scope. revalidate is
    # called exactly once even when it reports NONDETERMINISTIC.
    calls = []

    def spy(poc):
        calls.append(poc)
        return _nondeterministic()

    is_interesting = lambda s: "a" in s
    minimize_poc(["a", "b"], is_interesting, spy)
    assert len(calls) == 1


def test_minimize_poc_rejects_non_callable_revalidate():
    with pytest.raises(TypeError):
        minimize_poc(["a"], lambda s: True, "not-callable")


def test_minimize_poc_rejects_revalidate_returning_non_determinismresult():
    with pytest.raises(TypeError):
        minimize_poc(["a"], lambda s: True, lambda poc: "STABLE")


def test_minimize_poc_propagates_minimal_condition_sets_validation_errors():
    # conditions/is_interesting validation is not duplicated -- it's
    # inherited for free by delegating directly to minimal_condition_sets,
    # exactly the same errors C5 already raises.
    with pytest.raises(TypeError):
        minimize_poc(frozenset({"a"}), lambda s: True, lambda poc: _stable())
    with pytest.raises(ValueError):
        minimize_poc(["a", "a"], lambda s: True, lambda poc: _stable())
    with pytest.raises(ValueError):
        minimize_poc(["a"], lambda s: False, lambda poc: _stable())


def test_minimize_poc_reuses_minimal_condition_sets_directly_not_reimplemented(monkeypatch):
    import cem_engine

    real = cem_engine.minimal_condition_sets
    calls = []

    def spy(conditions, is_interesting):
        calls.append(list(conditions))
        return real(conditions, is_interesting)

    monkeypatch.setattr(cem_engine, "minimal_condition_sets", spy)
    minimize_poc(["auth_cookie", "trace_param"], lambda s: "auth_cookie" in s, lambda poc: _stable())
    assert calls == [["auth_cookie", "trace_param"]]


def test_minimize_poc_never_touches_classify_classify_race_or_alternates(monkeypatch):
    import cem_engine

    def _forbidden(*args, **kwargs):
        raise AssertionError("minimize_poc must never call classify/classify_race/find_alternate_condition_sets")

    monkeypatch.setattr(cem_engine, "classify", _forbidden)
    monkeypatch.setattr(cem_engine, "classify_race", _forbidden)
    monkeypatch.setattr(cem_engine, "find_alternate_condition_sets", _forbidden)
    result = minimize_poc(["auth_cookie", "trace_param"], lambda s: "auth_cookie" in s, lambda poc: _stable())
    assert result.accepted is True


def test_minimize_poc_never_touches_the_real_http_probe_fetch(monkeypatch):
    import http_probe

    def _forbidden(*args, **kwargs):
        raise AssertionError("minimize_poc must never call the real http_probe.fetch")

    monkeypatch.setattr(http_probe, "fetch", _forbidden)
    result = minimize_poc(["auth_cookie", "trace_param"], lambda s: "auth_cookie" in s, lambda poc: _stable())
    assert result.accepted is True


def test_minimize_poc_never_calls_the_real_determinism_gate(monkeypatch):
    # revalidate is a caller-injected abstraction, exactly like
    # is_interesting -- minimize_poc itself never calls the real
    # determinism_gate (which would need a real fetch_fn/base_request).
    import cem_engine

    def _forbidden(*args, **kwargs):
        raise AssertionError("minimize_poc must never call the real determinism_gate")

    monkeypatch.setattr(cem_engine, "determinism_gate", _forbidden)
    result = minimize_poc(["auth_cookie", "trace_param"], lambda s: "auth_cookie" in s, lambda poc: _stable())
    assert result.accepted is True


def test_minimize_poc_result_reuses_determinismresult_type_unmodified():
    result = minimize_poc(["a"], lambda s: True, lambda poc: _stable())
    assert isinstance(result.determinism, DeterminismResult)


def test_minimize_poc_is_deterministic_across_repeated_calls():
    is_interesting = lambda s: "auth_cookie" in s
    results = [
        minimize_poc(["auth_cookie", "trace_param"], is_interesting, lambda poc: _stable())
        for _ in range(10)
    ]
    first = results[0]
    for r in results[1:]:
        assert r.poc == first.poc
        assert r.accepted == first.accepted
        assert r.predicate_calls == first.predicate_calls


def test_minimize_poc_empty_conditions_is_trivially_accepted_or_rejected_by_revalidate():
    result = minimize_poc([], lambda s: True, lambda poc: _stable())
    assert result.poc == frozenset()
    assert result.predicate_calls == 0
    assert result.accepted is True


def test_minimize_poc_signature_is_conditions_is_interesting_revalidate():
    sig = inspect.signature(minimize_poc)
    assert list(sig.parameters) == ["conditions", "is_interesting", "revalidate"]


# ---------------------------------------------------------------------------
# assemble_bundle (C8)
# ---------------------------------------------------------------------------

# A real-shaped (but fabricated) JWT -- the identical trigger shape
# test_redact.py's own FAKE_JWT fixture uses to prove redact_text's JWT-shape
# detection actually fires (header.payload.signature, valid base64url
# segments, header starting with the standard "eyJ").
_FAKE_SECRET_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def _alt(minimal_sets=None, interacting=frozenset(), interacting_pairs=None,
          sets_found=1, trials_used=0, bounded=False):
    if minimal_sets is None:
        minimal_sets = [frozenset()]
    if interacting_pairs is None:
        interacting_pairs = []
    return AlternateSetsResult(
        minimal_sets=minimal_sets, interacting=interacting,
        interacting_pairs=interacting_pairs, sets_found=sets_found,
        trials_used=trials_used, bounded=bounded,
    )


def _poc(poc=frozenset(), accepted=True, determinism=None, predicate_calls=0):
    if determinism is None:
        determinism = _stable(1)
    return PocMinimizationResult(
        poc=poc, accepted=accepted, determinism=determinism, predicate_calls=predicate_calls,
    )


def _minimal_bundle_kwargs(**overrides):
    kwargs = {
        "finding_id": 1,
        "original_baseline": {},
        "baseline_determinism": _stable(1),
        "intervention_matrix": [],
        "controls": {},
        "observed_confounders": [],
        "verdict_labels": {},
        "inconclusive_experiments": {},
        "alternate_sets": _alt(),
        "poc": _poc(),
        "audit_trail": [],
        "k": 1,
    }
    kwargs.update(overrides)
    return kwargs


# ---- Schema completeness: exactly the 16 keys (15 sec-2.8 fields + finding_id).

def test_assemble_bundle_returns_exactly_the_16_top_level_keys():
    bundle = assemble_bundle(**_minimal_bundle_kwargs())
    assert set(bundle.keys()) == {
        "finding_id",
        "original_baseline",
        "baseline_replication_results",
        "intervention_matrix",
        "replication_counts",
        "controlled_pinned_conditions",
        "observed_confounders",
        "inconclusive_experiments",
        "identified_necessary_conditions",
        "minimal_condition_sets",
        "minimized_reproduction_evidence",
        "complete_audit_trail",
        "verdict_labels",
        "controls",
        "k",
        "completeness_bound",
    }


# ---- Field derivation correctness, one test per field.

def test_assemble_bundle_finding_id_present_as_the_16th_key():
    bundle = assemble_bundle(**_minimal_bundle_kwargs(finding_id=42))
    assert bundle["finding_id"] == 42


def test_assemble_bundle_original_baseline_passed_through():
    baseline = {"url": "https://target.example/api/orders/4521", "method": "GET"}
    bundle = assemble_bundle(**_minimal_bundle_kwargs(original_baseline=baseline))
    assert bundle["original_baseline"] == baseline


def test_assemble_bundle_baseline_replication_results_derived_from_determinism_result():
    det = DeterminismResult(status="STABLE", hits=[True, True, True], k=3)
    bundle = assemble_bundle(**_minimal_bundle_kwargs(baseline_determinism=det, k=3))
    assert bundle["baseline_replication_results"] == {
        "status": "STABLE", "hits": [True, True, True], "k": 3,
    }


def test_assemble_bundle_intervention_matrix_passed_through():
    matrix = [{"condition": "auth_cookie", "perturbation": "strip", "effect": "MISS"}]
    bundle = assemble_bundle(**_minimal_bundle_kwargs(intervention_matrix=matrix))
    assert bundle["intervention_matrix"] == matrix


def test_assemble_bundle_replication_counts_equals_k():
    bundle = assemble_bundle(**_minimal_bundle_kwargs(k=5, baseline_determinism=_stable(5)))
    assert bundle["replication_counts"] == 5
    assert bundle["k"] == 5


def test_assemble_bundle_controlled_pinned_conditions_and_controls_are_the_same_value_under_two_keys():
    controls = {"pinned_user_id": "42", "pinned_locale": "en-US"}
    bundle = assemble_bundle(**_minimal_bundle_kwargs(controls=controls))
    assert bundle["controlled_pinned_conditions"] == controls
    assert bundle["controls"] == controls
    assert bundle["controlled_pinned_conditions"] == bundle["controls"]


def test_assemble_bundle_observed_confounders_passed_through():
    confounders = [{"name": "cdn_cache", "controllable": False}]
    bundle = assemble_bundle(**_minimal_bundle_kwargs(observed_confounders=confounders))
    assert bundle["observed_confounders"] == confounders


def test_assemble_bundle_inconclusive_experiments_passed_through():
    inconclusive = {"rate_limit_header": "throttled during trial 3"}
    bundle = assemble_bundle(**_minimal_bundle_kwargs(inconclusive_experiments=inconclusive))
    assert bundle["inconclusive_experiments"] == inconclusive


def test_assemble_bundle_identified_necessary_conditions_picks_necessary_verdicts_sorted():
    verdict_labels = {
        "trace_param": "apparently_not_necessary",
        "csrf_token": "necessary",
        "auth_cookie": "necessary",
        "session_id": "inconclusive",
    }
    bundle = assemble_bundle(**_minimal_bundle_kwargs(verdict_labels=verdict_labels))
    assert bundle["identified_necessary_conditions"] == ["auth_cookie", "csrf_token"]
    assert bundle["verdict_labels"] == verdict_labels


def test_assemble_bundle_minimal_condition_sets_unpacks_alternate_sets_result():
    alt = AlternateSetsResult(
        minimal_sets=[frozenset({"auth_cookie"}), frozenset({"csrf_token", "auth_cookie"})],
        interacting=frozenset({"trace_param", "session_id"}),
        interacting_pairs=[InteractionEvidence(pair=frozenset({"trace_param", "session_id"}))],
        sets_found=2, trials_used=6, bounded=True,
    )
    bundle = assemble_bundle(**_minimal_bundle_kwargs(alternate_sets=alt))
    assert bundle["minimal_condition_sets"] == {
        "minimal_sets": [["auth_cookie"], ["auth_cookie", "csrf_token"]],
        "interacting": ["session_id", "trace_param"],
        "interacting_pairs": [["session_id", "trace_param"]],
    }


def test_assemble_bundle_completeness_bound_unpacks_alternate_sets_result():
    alt = AlternateSetsResult(
        minimal_sets=[frozenset({"auth_cookie"})],
        interacting=frozenset(), interacting_pairs=[],
        sets_found=3, trials_used=9, bounded=True,
    )
    bundle = assemble_bundle(**_minimal_bundle_kwargs(alternate_sets=alt))
    assert bundle["completeness_bound"] == {"sets_found": 3, "trials_used": 9, "bounded": True}


def test_assemble_bundle_minimal_condition_sets_and_completeness_bound_stay_separate_keys():
    # field 9 vs field 15: same AlternateSetsResult, two distinct top-level
    # keys -- never nested one inside the other, per the brief.
    alt = _alt(sets_found=2, trials_used=4, bounded=False)
    bundle = assemble_bundle(**_minimal_bundle_kwargs(alternate_sets=alt))
    assert "completeness_bound" not in bundle["minimal_condition_sets"]
    assert "minimal_sets" not in bundle["completeness_bound"]


def test_assemble_bundle_minimized_reproduction_evidence_unpacks_poc_result():
    poc_result = PocMinimizationResult(
        poc=frozenset({"auth_cookie"}), accepted=True,
        determinism=DeterminismResult(status="STABLE", hits=[True, True], k=2),
        predicate_calls=4,
    )
    bundle = assemble_bundle(**_minimal_bundle_kwargs(
        poc=poc_result, k=2, baseline_determinism=_stable(2),
    ))
    assert bundle["minimized_reproduction_evidence"] == {
        "poc": ["auth_cookie"],
        "accepted": True,
        "determinism": {"status": "STABLE", "hits": [True, True], "k": 2},
    }


def test_assemble_bundle_complete_audit_trail_passed_through():
    trail = [{"call": "fetch", "url": "https://target.example/api/orders/4521"}]
    bundle = assemble_bundle(**_minimal_bundle_kwargs(audit_trail=trail))
    assert bundle["complete_audit_trail"] == trail


# ---- Redaction is real, not vacuous.

def test_fake_secret_jwt_fixture_is_non_vacuous():
    # Prove the fixture genuinely triggers redact_text's own JWT-shape
    # detection BEFORE relying on it disappearing inside assemble_bundle --
    # otherwise a totally broken redaction pass could pass the bundle-level
    # tests below by accident.
    assert redact_text(_FAKE_SECRET_JWT) != _FAKE_SECRET_JWT
    assert _FAKE_SECRET_JWT not in redact_text(_FAKE_SECRET_JWT)


def test_assemble_bundle_redacts_secret_in_original_baseline_header_value():
    baseline = {"headers": {"Authorization": f"Bearer {_FAKE_SECRET_JWT}"}}
    bundle = assemble_bundle(**_minimal_bundle_kwargs(original_baseline=baseline))
    assert _FAKE_SECRET_JWT not in json.dumps(bundle)


def test_assemble_bundle_redacts_secret_in_intervention_matrix_entry():
    matrix = [{"condition": "auth_cookie", "response_snippet": _FAKE_SECRET_JWT}]
    bundle = assemble_bundle(**_minimal_bundle_kwargs(intervention_matrix=matrix))
    assert _FAKE_SECRET_JWT not in json.dumps(bundle)


def test_assemble_bundle_redacts_secret_in_audit_trail_entry():
    trail = [{"call": "fetch", "raw_response_headers": f"Authorization: Bearer {_FAKE_SECRET_JWT}"}]
    bundle = assemble_bundle(**_minimal_bundle_kwargs(audit_trail=trail))
    assert _FAKE_SECRET_JWT not in json.dumps(bundle)


# ---- Non-string values survive the redaction walk untouched.

def test_assemble_bundle_non_string_values_survive_the_redaction_walk_untouched():
    bundle = assemble_bundle(**_minimal_bundle_kwargs(
        finding_id=7,
        alternate_sets=_alt(bounded=True),
        poc=_poc(accepted=False),
        k=1,
    ))
    assert bundle["finding_id"] == 7 and isinstance(bundle["finding_id"], int)
    assert bundle["k"] == 1 and isinstance(bundle["k"], int)
    assert bundle["completeness_bound"]["bounded"] is True
    assert bundle["minimized_reproduction_evidence"]["accepted"] is False


# ---- No live execution: assemble_bundle never runs a real CEM step itself.

def test_assemble_bundle_never_calls_any_live_cem_engine_function(monkeypatch):
    import cem_engine

    def _forbidden(*args, **kwargs):
        raise AssertionError("assemble_bundle must never call a live CEM engine function itself")

    for name in (
        "determinism_gate", "classify", "classify_race",
        "minimal_condition_sets", "find_alternate_condition_sets", "minimize_poc",
    ):
        monkeypatch.setattr(cem_engine, name, _forbidden)

    bundle = assemble_bundle(**_minimal_bundle_kwargs(finding_id=1))
    assert bundle["finding_id"] == 1


def test_assemble_bundle_never_touches_the_real_http_probe_fetch(monkeypatch):
    import http_probe

    def _forbidden(*args, **kwargs):
        raise AssertionError("assemble_bundle must never call the real http_probe.fetch")

    monkeypatch.setattr(http_probe, "fetch", _forbidden)
    bundle = assemble_bundle(**_minimal_bundle_kwargs(finding_id=1))
    assert bundle["finding_id"] == 1


# ---- Determinism: same inputs -> identical output across repeated calls.

def test_assemble_bundle_is_deterministic_across_repeated_calls():
    kwargs = _minimal_bundle_kwargs(
        original_baseline={"url": "https://target.example/x"},
        baseline_determinism=_stable(2),
        intervention_matrix=[{"condition": "auth_cookie", "effect": "MISS"}],
        controls={"pinned_user_id": "42"},
        observed_confounders=[{"name": "cdn_cache", "controllable": False}],
        verdict_labels={"auth_cookie": "necessary"},
        alternate_sets=_alt(minimal_sets=[frozenset({"auth_cookie"})], sets_found=1, trials_used=2),
        poc=_poc(poc=frozenset({"auth_cookie"})),
        audit_trail=[{"call": "fetch"}],
        k=2,
    )
    results = [assemble_bundle(**kwargs) for _ in range(5)]
    first = results[0]
    for r in results[1:]:
        assert r == first


# ---- Invalid-input rejection: TypeError on wrong result types (isinstance,
# not duck-typing -- mirrors C7's revalidate-type-check precedent).

def test_assemble_bundle_rejects_non_determinismresult_baseline_determinism():
    with pytest.raises(TypeError):
        assemble_bundle(**_minimal_bundle_kwargs(baseline_determinism={"status": "STABLE"}))


def test_assemble_bundle_rejects_non_alternatesetsresult_alternate_sets():
    with pytest.raises(TypeError):
        assemble_bundle(**_minimal_bundle_kwargs(alternate_sets={"minimal_sets": []}))


def test_assemble_bundle_rejects_non_pocminimizationresult_poc():
    with pytest.raises(TypeError):
        assemble_bundle(**_minimal_bundle_kwargs(poc={"poc": []}))


# ---- Signature-introspection pin (same pattern C3/C5/C6/C7 each used).

def test_assemble_bundle_signature_has_the_12_named_parameters_in_order():
    sig = inspect.signature(assemble_bundle)
    assert list(sig.parameters) == [
        "finding_id",
        "original_baseline",
        "baseline_determinism",
        "intervention_matrix",
        "controls",
        "observed_confounders",
        "verdict_labels",
        "inconclusive_experiments",
        "alternate_sets",
        "poc",
        "audit_trail",
        "k",
    ]
