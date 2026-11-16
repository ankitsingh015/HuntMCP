"""P4-BM -- integrity/blindness/oracle tests for the NEW blind, independent
LONG-HORIZON benchmark substrate under tests/fixtures/lh_target/.

These tests assert the benchmark's OWN properties -- NOT an agent's score:

  * blindness      -- no mcp-servers/* module can import the evaluator-only
                      answer key, and the blind scenario index leaks no
                      expected conclusion;
  * integrity      -- tampering with a locked fixture/scenario/answer-key file
                      is caught by its SHA-256 lock;
  * oracle         -- "a finding is real" is decided from the simulator's own
                      independent event log + the explicit oracle signature,
                      never from the agent's self-reported claim;
  * genuineness    -- each planted ground-truth behaviour is actually exhibited
                      by the deterministic simulator at BUILD time (the planted
                      labels are real, not fabricated);
  * causal         -- false-causal-conclusion rate is measured; `inconclusive`
                      is its own category and is NEVER a false causal conclusion;
  * no-finding     -- a correctly-concluded no-finding scores WELL (not a miss);
  * reproducibility-- the simulator + evaluator are deterministic across runs.

It does NOT drive HuntMCP's real pipeline (that live arm adapter is the deferred
consumer step, same precedent as P2-BENCH's reference arm).  Scoring here is
proven against a GOLDEN reference trajectory produced by lh_harness.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LH_DIR = os.path.join(ROOT, "tests", "fixtures", "lh_target")
sys.path.insert(0, _LH_DIR)
# bench_target is on the path in sibling tests; keep lh_* self-contained here.

import lh_answer_key as AK
import lh_evaluator as EV
import lh_harness as HN
import lh_integrity
import lh_scenarios as SC
from lh_evaluator import ObservedStep, ScenarioConclusion
from lh_target import LhTarget

# ----------------------------------------------------------------------------- #
# 1. Integrity locks (SHA-256) -- tamper detection
# ----------------------------------------------------------------------------- #
LOCKED_FILES = ("lh_scenarios.py", "lh_answer_key.py", "lh_target.py")


def test_locked_files_match_their_sha256_locks():
    for name in LOCKED_FILES:
        ok, msg = lh_integrity.verify(os.path.join(_LH_DIR, name))
        assert ok, msg


def test_integrity_lock_detects_a_tampered_file(tmp_path):
    target = tmp_path / "x.py"
    target.write_text("A = 1\n")
    lh_integrity.update(str(target))
    target.write_text("A = 2\n")  # tampered, not re-locked
    ok, msg = lh_integrity.verify(str(target))
    assert ok is False
    assert "INTEGRITY FAILURE" in msg


def test_integrity_lock_missing_is_a_failure(tmp_path):
    target = tmp_path / "y.py"
    target.write_text("A = 1\n")
    ok, msg = lh_integrity.verify(str(target))
    assert ok is False
    assert "integrity lock missing" in msg


# ----------------------------------------------------------------------------- #
# 2. Blindness -- scenario index leaks no answer; production has no key path
# ----------------------------------------------------------------------------- #
def test_every_scenario_has_an_answer_key_and_a_dimension():
    assert set(SC.SCENARIOS) == set(AK.EXPECTED)
    assert set(SC.SCENARIOS) == set(AK.DIMENSION)


def test_blind_scenario_index_never_leaks_a_forbidden_answer_field():
    import json

    blob = json.dumps({k: _plain(v) for k, v in SC.SCENARIOS.items()})
    for field in SC.FORBIDDEN_ANSWER_FIELDS:
        assert field not in blob, f"{field!r} leaked into the blind scenario index"


def test_scenario_ids_do_not_leak_the_dimension_or_verdict():
    # opaque ids only -- no "idor"/"nofinding"/"recovery"/... in the id itself
    leaky = ("idor", "xss", "sqli", "nofinding", "no_finding", "recovery",
             "resurrect", "business", "logic", "change", "negative", "planted")
    for sid in SC.SCENARIOS:
        low = sid.lower()
        for token in leaky:
            assert token not in low, f"scenario id {sid!r} leaks {token!r}"


def test_production_code_has_no_import_path_to_the_answer_key():
    """No module under mcp-servers/ may reference the evaluator-only answer key
    or any lh evaluator-only artifact."""
    import pathlib

    base = pathlib.Path(ROOT, "mcp-servers")
    offenders = []
    for p in base.rglob("*.py"):
        text = p.read_text()
        for needle in ("lh_answer_key", "lh_evaluator", "fixtures.lh_target", "lh_target"):
            if needle in text:
                offenders.append(f"{p.relative_to(base)} contains {needle!r}")
    assert not offenders, "PRODUCTION CODE REFERENCES THE LONG-HORIZON ANSWERS: " + "; ".join(offenders)


def test_simulator_does_not_import_the_answer_key():
    """Oracle independence: the ground-truth source (the simulator) must not
    read the expected labels -- its behaviour is the independent oracle. A
    docstring may NAME the files; what is forbidden is an import statement."""
    import ast

    with open(os.path.join(_LH_DIR, "lh_target.py")) as f:
        src = f.read()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert "lh_answer_key" not in imported, "simulator imports the answer key"
    assert "lh_evaluator" not in imported, "simulator imports the evaluator"


# ----------------------------------------------------------------------------- #
# 3. Genuineness -- the planted ground truth is REAL simulator behaviour
# ----------------------------------------------------------------------------- #
def test_sustained_finding_is_only_reachable_after_the_full_sequence():
    t = LhTarget()
    # jumping straight to access without enumerating the id leaks nothing
    r = t.act("lh_s_alpha", 0, "alice", "access", {"id": "guess"})
    assert "ALPHA-LEAK" not in r.body
    # the real multi-step path leaks
    t.act("lh_s_alpha", 0, "alice", "probe")
    enum = t.act("lh_s_alpha", 0, "alice", "enumerate")
    r2 = t.act("lh_s_alpha", 0, "alice", "access", {"id": enum.body.strip()})
    assert "ALPHA-LEAK" in r2.body


def test_multi_identity_leak_requires_a_non_owner_identity():
    t = LhTarget()
    owner = t.act("lh_s_bravo", 0, "alice", "read", {"id": "doc-1"})
    assert "BRAVO-DOC" not in owner.body  # owner reading own doc is not the leak
    attacker = t.act("lh_s_bravo", 0, "bob", "read", {"id": "doc-1"})
    assert "BRAVO-DOC" in attacker.body   # cross-identity read actually leaks


def test_business_logic_invariant_is_only_broken_by_replaying_the_coupon():
    t = LhTarget()
    t.act("lh_s_charlie", 0, "alice", "add_coupon")
    once = t.act("lh_s_charlie", 0, "alice", "checkout")
    assert "CREDIT" not in once.body   # a single coupon never goes negative
    t2 = LhTarget()
    t2.act("lh_s_charlie", 0, "alice", "add_coupon")
    t2.act("lh_s_charlie", 0, "alice", "add_coupon")  # replay == business-logic abuse
    twice = t2.act("lh_s_charlie", 0, "alice", "checkout")
    assert "CREDIT" in twice.body


def test_target_change_finding_exists_only_in_the_mutated_epoch():
    t = LhTarget()
    e0 = t.act("lh_s_delta", 0, "alice", "read")
    assert "DELTA-DEBUG" not in e0.body       # epoch 0 is secure
    e1 = t.act("lh_s_delta", 1, "alice", "read")
    assert "DELTA-DEBUG" in e1.body           # epoch 1 regressed


def test_resurrection_evidence_only_appears_in_the_later_epoch():
    t = LhTarget()
    early = t.act("lh_s_echo", 0, "alice", "callback")
    assert "ECHO-OOB" not in early.body       # callback has not fired yet -> inconclusive
    late = t.act("lh_s_echo", 1, "alice", "callback")
    assert "ECHO-OOB" in late.body            # deferred OOB evidence now lands


def test_recovery_finding_requires_a_retry_after_the_injected_failure():
    t = LhTarget()
    first = t.act("lh_s_foxtrot", 0, "alice", "scan")
    assert first.status == 503 and "FOXTROT-KEY" not in first.body
    second = t.act("lh_s_foxtrot", 0, "alice", "scan")   # recover
    assert second.status == 200 and "FOXTROT-KEY" in second.body


def test_the_no_finding_scenario_is_actually_secure_for_every_identity_and_epoch():
    t = LhTarget()
    for epoch in (0, 1):
        for identity in ("alice", "bob"):
            r = t.act("lh_s_golf", epoch, identity, "read", {"id": "doc-1"})
            assert "GOLF-DOC" not in r.body, (identity, epoch)
            if identity == "bob":
                assert r.status == 403


def test_answer_key_marks_exactly_one_scenario_as_a_correct_no_finding():
    not_planted = [s for s, e in AK.EXPECTED.items() if not e["planted"]]
    assert not_planted == ["lh_s_golf"]


# ----------------------------------------------------------------------------- #
# 4. Evaluator -- scoring contract properties
# ----------------------------------------------------------------------------- #
def test_a_correct_no_finding_scores_well_and_is_not_a_miss():
    t = LhTarget()
    # the agent correctly probed golf and concluded nothing is there
    steps = [ObservedStep("lh_s_golf", 0, "bob",
                          "read", _ref(t, "lh_s_golf", 0, "bob", "read", {"id": "doc-1"}))]
    concl = {"lh_s_golf": ScenarioConclusion(verdict="no_finding")}
    rep = EV.evaluate(t, steps, concl)
    assert rep.per_scenario["lh_s_golf"]["outcome"] == "correct_no_finding"
    assert rep.correct_no_finding == 1
    assert rep.misses == 0
    assert rep.false_positives == 0


def test_claiming_a_finding_on_the_secure_scenario_is_a_false_positive():
    t = LhTarget()
    steps = [ObservedStep("lh_s_golf", 0, "bob",
                          "read", _ref(t, "lh_s_golf", 0, "bob", "read", {"id": "doc-1"}))]
    concl = {"lh_s_golf": ScenarioConclusion(verdict="finding",
                                             evidence_refs={"leak": 0})}
    rep = EV.evaluate(t, steps, concl)
    assert rep.per_scenario["lh_s_golf"]["outcome"] == "false_positive"
    assert rep.false_positives == 1
    assert rep.correct_no_finding == 0


def test_a_planted_finding_that_is_missed_scores_as_a_miss():
    t = LhTarget()
    # agent only did the owner read of bravo and gave up
    steps = [ObservedStep("lh_s_bravo", 0, "alice",
                          "read", _ref(t, "lh_s_bravo", 0, "alice", "read", {"id": "doc-1"}))]
    concl = {"lh_s_bravo": ScenarioConclusion(verdict="no_finding")}
    rep = EV.evaluate(t, steps, concl)
    assert rep.per_scenario["lh_s_bravo"]["outcome"] == "miss"
    assert rep.misses == 1


def test_an_inconclusive_verdict_is_its_own_bucket_not_a_miss_or_fp():
    t = LhTarget()
    steps = [ObservedStep("lh_s_bravo", 0, "bob",
                          "read", _ref(t, "lh_s_bravo", 0, "bob", "read", {"id": "doc-1"}))]
    concl = {"lh_s_bravo": ScenarioConclusion(verdict="inconclusive")}
    rep = EV.evaluate(t, steps, concl)
    assert rep.per_scenario["lh_s_bravo"]["outcome"] == "inconclusive"
    assert rep.inconclusive == 1
    assert rep.misses == 0
    assert rep.false_positives == 0


def test_a_finding_claim_not_backed_by_a_real_leak_event_is_not_credited():
    """Oracle integrity: a `finding` verdict whose cited event does NOT exhibit
    the planted leak signature in the simulator's independent log earns no hit."""
    t = LhTarget()
    # bob did the read but the agent points at the WRONG event (an owner read
    # that never leaked) -- an unbacked claim.
    owner_ref = _ref(t, "lh_s_bravo", 0, "alice", "read", {"id": "doc-1"})  # idx 0, no leak
    _ref(t, "lh_s_bravo", 0, "bob", "read", {"id": "doc-1"})                # idx 1, real leak
    steps = [ObservedStep("lh_s_bravo", 0, "alice", "read", owner_ref)]
    concl = {"lh_s_bravo": ScenarioConclusion(verdict="finding",
                                              evidence_refs={"leak": owner_ref})}
    rep = EV.evaluate(t, steps, concl)
    assert rep.per_scenario["lh_s_bravo"]["outcome"] == "unbacked_claim"
    assert rep.hits == 0
    assert rep.unbacked_claims == 1


def test_a_backed_cross_identity_finding_is_a_hit():
    t = LhTarget()
    leak_ref = _ref(t, "lh_s_bravo", 0, "bob", "read", {"id": "doc-1"})
    steps = [ObservedStep("lh_s_bravo", 0, "bob", "read", leak_ref)]
    concl = {"lh_s_bravo": ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": leak_ref},
        condition_verdicts={"identity_not_owner": "necessary",
                            "extra_header": "apparently_not_necessary"})}
    rep = EV.evaluate(t, steps, concl)
    assert rep.per_scenario["lh_s_bravo"]["outcome"] == "hit"
    assert rep.hits >= 1


# ----------------------------------------------------------------------------- #
# 5. Causal -- false-causal-conclusion rate; inconclusive is never an FCCR hit
# ----------------------------------------------------------------------------- #
def test_calling_an_apparently_not_necessary_condition_necessary_counts_as_fccr():
    t = LhTarget()
    leak_ref = _ref(t, "lh_s_bravo", 0, "bob", "read", {"id": "doc-1"})
    steps = [ObservedStep("lh_s_bravo", 0, "bob", "read", leak_ref)]
    concl = {"lh_s_bravo": ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": leak_ref},
        condition_verdicts={"identity_not_owner": "necessary",
                            "extra_header": "necessary"})}  # WRONG: extra_header is not necessary
    rep = EV.evaluate(t, steps, concl)
    assert rep.fccr_numerator >= 1
    assert rep.fccr > 0.0


def test_calling_an_apparently_not_necessary_condition_inconclusive_is_not_fccr():
    t = LhTarget()
    leak_ref = _ref(t, "lh_s_bravo", 0, "bob", "read", {"id": "doc-1"})
    steps = [ObservedStep("lh_s_bravo", 0, "bob", "read", leak_ref)]
    concl = {"lh_s_bravo": ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": leak_ref},
        condition_verdicts={"identity_not_owner": "necessary",
                            "extra_header": "inconclusive"})}  # honest uncertainty, NOT a false claim
    rep = EV.evaluate(t, steps, concl)
    assert rep.fccr_numerator == 0
    assert rep.fccr == 0.0


# ----------------------------------------------------------------------------- #
# 6. Golden reference arm -- a correct run scores well, and is reproducible
# ----------------------------------------------------------------------------- #
def test_golden_trajectory_is_a_correct_run_covering_every_dimension():
    t = LhTarget()
    steps, concl = HN.golden_trajectory(t)
    rep = EV.evaluate(t, steps, concl)
    # every planted scenario hit, the secure one correctly a no-finding, zero FP
    assert rep.misses == 0, rep.per_scenario
    assert rep.false_positives == 0, rep.per_scenario
    assert rep.unbacked_claims == 0, rep.per_scenario
    assert rep.correct_no_finding == 1
    assert rep.fccr == 0.0
    # every dimension reported an outcome
    assert set(rep.per_dimension) == set(AK.DIMENSIONS)
    for dim, out in rep.per_dimension.items():
        assert out["outcome"] in ("hit", "correct_no_finding"), (dim, out)


def test_golden_run_is_reproducible_across_repeats():
    reports = []
    for _ in range(3):
        t = LhTarget()
        steps, concl = HN.golden_trajectory(t)
        reports.append(EV.evaluate(t, steps, concl))
    ok, msg = EV.reproducibility(reports)
    assert ok, msg


def test_reproducibility_rejects_divergent_reports():
    t1 = LhTarget()
    s1, c1 = HN.golden_trajectory(t1)
    r1 = EV.evaluate(t1, s1, c1)
    t2 = LhTarget()
    s2, c2 = HN.golden_trajectory(t2)
    # drop one scenario's finding to force divergence
    c2["lh_s_bravo"] = ScenarioConclusion(verdict="no_finding")
    r2 = EV.evaluate(t2, s2, c2)
    ok, _ = EV.reproducibility([r1, r2])
    assert not ok


def test_simulator_is_deterministic_for_the_same_action_sequence():
    def run():
        t = LhTarget()
        return [t.act(*a).body for a in (
            ("lh_s_alpha", 0, "alice", "probe"),
            ("lh_s_alpha", 0, "alice", "enumerate"),
            ("lh_s_delta", 1, "alice", "read"),
        )]
    assert run() == run()


# ----------------------------------------------------------------------------- #
# 7. Reproducibility record -- required benchmark metadata is emitted
# ----------------------------------------------------------------------------- #
def test_reproducibility_record_has_the_required_fields():
    t = LhTarget()
    steps, concl = HN.golden_trajectory(t)
    rep = EV.evaluate(t, steps, concl)
    record = HN.reproducibility_record([rep])
    for field in ("benchmark_version", "seed", "target_mode", "scenario_count",
                  "request_count", "verdicts", "fccr", "dimensions"):
        assert field in record, field
    assert record["benchmark_version"] == SC.LH_BENCH_VERSION


# ----------------------------------------------------------------------------- #
# 8. Evidence-trail cross-check (public helper)
# ----------------------------------------------------------------------------- #
def test_evidence_trail_confirms_a_real_cross_identity_pair():
    t = LhTarget()
    base = _ref(t, "lh_s_bravo", 0, "alice", "read", {"id": "doc-1"})
    pert = _ref(t, "lh_s_bravo", 0, "bob", "read", {"id": "doc-1"})
    ok, msg = EV.verify_evidence_trail(
        t, "lh_s_bravo",
        ScenarioConclusion(verdict="finding", evidence_refs={"baseline": base, "perturbed": pert}))
    assert ok, msg


def test_evidence_trail_rejects_identical_baseline_and_perturbed():
    t = LhTarget()
    a = _ref(t, "lh_s_bravo", 0, "alice", "read", {"id": "doc-1"})
    b = _ref(t, "lh_s_bravo", 0, "alice", "read", {"id": "doc-1"})
    ok, _ = EV.verify_evidence_trail(
        t, "lh_s_bravo",
        ScenarioConclusion(verdict="finding", evidence_refs={"baseline": a, "perturbed": b}))
    assert not ok


# ----------------------------------------------------------------------------- #
# helpers
# ----------------------------------------------------------------------------- #
def _ref(target, scenario, epoch, identity, action, args=None):
    """Drive one real simulator action and return its index in the independent
    event log (the only legitimate way an arm cites evidence)."""
    before = len(target.events)
    target.act(scenario, epoch, identity, action, args)
    return before


def _plain(obj):
    """Deep-convert MappingProxyType/tuple to plain json-able structures."""
    from collections import abc
    if isinstance(obj, abc.Mapping):
        return {k: _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    return obj
