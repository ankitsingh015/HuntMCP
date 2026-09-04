"""A2/B1/B3: the independent evaluator computes correctness, FCCR, coverage, missed,
false positives, reproducibility, and evidence-trail backing -- from SYNTHETIC CEM
conclusions (test doubles). No CEM production logic is involved.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "cem_target"))

import pytest  # noqa: E402
from evaluator import CaseConclusion, evaluate, reproducibility, verify_evidence_trail  # noqa: E402
from harness import CemBenchmarkServer, http_get  # noqa: E402


def _correct_vulnerable():
    return {
        "case_01": CaseConclusion(verdicts={"session_cookie": "necessary", "trace_param": "apparently_not_necessary"},
                                  minimal_sets=(("session_cookie",),)),
        "case_02": CaseConclusion(verdicts={"x_access_header": "interacting", "session_cookie": "interacting"},
                                  minimal_sets=(("x_access_header",), ("session_cookie",))),
        "case_03": CaseConclusion(verdicts={"role_admin": "interacting", "flag_on": "interacting"},
                                  minimal_sets=(("role_admin", "flag_on"),)),
        "case_04": CaseConclusion(verdicts={"probe_header": "inconclusive"}, determinism_status="NONDETERMINISTIC"),
        "case_05": CaseConclusion(verdicts={"probe_header": "inconclusive"}),
        "case_06": CaseConclusion(verdicts={"probe_header": "probabilistic"}),
        "case_07": CaseConclusion(verdicts={"session_cookie": "necessary", "target_object_id": "necessary"},
                                  minimal_sets=(("session_cookie", "target_object_id"),)),
    }


def test_correct_conclusion_scores_clean():
    r = evaluate(_correct_vulnerable(), mode="vulnerable")
    assert r.fccr == 0.0 and r.fccr_numerator == 0
    assert r.coverage == 1.0
    assert r.missed == 0
    assert r.false_positives == 0


def test_false_causal_conclusion_is_detected():
    c = _correct_vulnerable()
    c["case_04"] = CaseConclusion(verdicts={"probe_header": "necessary"})  # flaky mislabeled necessary
    r = evaluate(c, mode="vulnerable")
    assert r.fccr > 0.0 and r.fccr_numerator >= 1
    assert r.false_positives >= 1


def test_coverage_drops_on_wrong_verdict():
    c = _correct_vulnerable()
    c["case_01"] = CaseConclusion(verdicts={"session_cookie": "apparently_not_necessary",
                                            "trace_param": "apparently_not_necessary"})
    r = evaluate(c, mode="vulnerable")
    assert r.coverage < 1.0


def test_patched_mutation_expects_no_finding():
    # correct patched behavior: capability absent, no necessity emitted -> clean
    concl = {"case_07": CaseConclusion(verdicts={}, finding_reproduced=False)}
    r = evaluate(concl, mode="patched")
    assert r.per_case["case_07"]["ok"] is True and r.fccr == 0.0
    # wrong patched behavior: CEM still claims necessity on a fixed target -> false conclusion
    bad = {"case_07": CaseConclusion(verdicts={"session_cookie": "necessary"}, finding_reproduced=True)}
    rb = evaluate(bad, mode="patched")
    assert rb.per_case["case_07"]["ok"] is False and rb.fccr > 0.0 and rb.false_positives >= 1


def test_missed_finding_is_counted():
    c = _correct_vulnerable()
    c["case_01"] = CaseConclusion(verdicts={"session_cookie": "apparently_not_necessary",
                                            "trace_param": "apparently_not_necessary"}, minimal_sets=())
    r = evaluate(c, mode="vulnerable")
    assert r.missed >= 1


def test_reproducible_across_runs():
    ok, msg = reproducibility([evaluate(_correct_vulnerable()), evaluate(_correct_vulnerable())])
    assert ok, msg


def test_evidence_trail_backed_by_real_requests():
    srv = CemBenchmarkServer().start()
    try:
        http_get(f"{srv.base_url}/svc/alpha/42", headers={"Cookie": "session=u"})  # baseline idx 0
        http_get(f"{srv.base_url}/svc/alpha/42")                                    # perturbed idx 1
        concl = CaseConclusion(verdicts={"session_cookie": "necessary"},
                               evidence_refs={"session_cookie": {"baseline": 0, "perturbed": 1}})
        ok, msg = verify_evidence_trail(concl, srv.requests(), "session_cookie")
        assert ok, msg
        # an unbacked claim (both refs identical -> no real perturbation) is rejected
        bad = CaseConclusion(verdicts={"session_cookie": "necessary"},
                             evidence_refs={"session_cookie": {"baseline": 0, "perturbed": 0}})
        ok2, _ = verify_evidence_trail(bad, srv.requests(), "session_cookie")
        assert ok2 is False
    finally:
        srv.stop()
