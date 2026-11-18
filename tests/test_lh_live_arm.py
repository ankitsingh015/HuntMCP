"""P4-BM live arm + anti-gaming arm scorer.

Two deliverables:
  * `lh_evaluator.evaluate_arm` -- scores the FULL AK.EXPECTED set, so a scenario
    an arm never concludes on is counted as `inconclusive`, not silently dropped
    (an arm must not be able to dodge misses by staying silent). The per-scenario
    `evaluate` primitive is unchanged.
  * `lh_live_arm` -- a REAL-pipeline arm (drives the real invariant_probe ->
    run_cem_pipeline and real find_resurrectable_hypotheses) vs a naive baseline,
    showing a measured long-horizon uplift at FCCR==0.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "lh_target"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "invariant_target"))

import lh_answer_key as AK  # noqa: E402  -- EVALUATOR-ONLY (test side)
import lh_evaluator as EV  # noqa: E402
from lh_evaluator import ScenarioConclusion  # noqa: E402
from lh_target import LhTarget  # noqa: E402


# --------------------------------------------------------------------------- #
# Anti-gaming arm scorer                                                      #
# --------------------------------------------------------------------------- #
def test_evaluate_arm_scores_an_omitted_planted_scenario_as_inconclusive():
    t = LhTarget()
    # arm concludes ONLY on golf, staying silent on the 6 planted scenarios
    concl = {"lh_s_golf": ScenarioConclusion(verdict="no_finding")}
    rep = EV.evaluate_arm(t, [], concl)
    # every expected scenario is scored -- none silently dropped
    assert set(rep.per_scenario) == set(AK.EXPECTED)
    # the omitted planted scenarios are inconclusive, never hits, never silent
    assert rep.hits == 0
    assert rep.inconclusive == len(AK.EXPECTED) - 1  # all but golf
    assert rep.per_scenario["lh_s_bravo"]["outcome"] == "inconclusive"
    assert rep.correct_no_finding == 1  # golf still scored correctly


def test_evaluate_arm_equals_evaluate_when_nothing_is_omitted():
    import lh_harness as HN
    t = LhTarget()
    steps, concl = HN.golden_trajectory(t)
    full = EV.evaluate(t, steps, concl)
    armed = EV.evaluate_arm(t, steps, concl)
    assert (armed.hits, armed.misses, armed.inconclusive, armed.correct_no_finding,
            armed.false_positives, armed.fccr) == (
        full.hits, full.misses, full.inconclusive, full.correct_no_finding,
        full.false_positives, full.fccr)


def test_evaluate_arm_omission_never_counts_toward_fccr():
    t = LhTarget()
    rep = EV.evaluate_arm(t, [], {})  # arm concluded nothing at all
    assert rep.fccr == 0.0
    assert rep.hits == 0 and rep.false_positives == 0
    assert rep.inconclusive == len(AK.EXPECTED)


# --------------------------------------------------------------------------- #
# The live arm: real pipeline vs naive baseline                              #
# --------------------------------------------------------------------------- #
import inspect  # noqa: E402

import engagement_paths  # noqa: E402
import lh_live_arm as ARM  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    return str(tmp_path / "case.db")


def test_real_arm_hits_every_planted_dimension_at_fccr_zero(_db):
    t = LhTarget()
    steps, concl = ARM.real_pipeline_trajectory(t, db_path=_db)
    rep = EV.evaluate_arm(t, steps, concl)
    assert rep.hits == 6, rep.per_scenario           # all 6 planted dimensions
    assert rep.correct_no_finding == 1               # golf
    assert rep.misses == 0 and rep.unbacked_claims == 0, rep.per_scenario
    assert rep.false_positives == 0
    assert rep.fccr == 0.0


def test_real_arm_resurrects_echo_through_the_real_module(_db):
    t = LhTarget()
    _, concl = ARM.real_pipeline_trajectory(t, db_path=_db)
    # echo is a HIT specifically because find_resurrectable_hypotheses revived it
    assert concl["lh_s_echo"].verdict == "finding"
    assert any(h.status == "resurrected" for h in concl["lh_s_echo"].hypotheses)


def test_baseline_misses_the_long_horizon_dimensions(_db):
    t = LhTarget()
    steps, concl = ARM.baseline_trajectory(t)
    rep = EV.evaluate_arm(t, steps, concl)
    missed = {sid for sid, v in rep.per_scenario.items() if v["outcome"] == "miss"}
    assert missed == {"lh_s_charlie", "lh_s_delta", "lh_s_echo", "lh_s_foxtrot"}
    assert rep.false_positives == 0  # a naive arm must not be WRONG, only weaker


def test_measured_uplift_real_over_baseline(_db):
    t1 = LhTarget()
    real = EV.evaluate_arm(t1, *ARM.real_pipeline_trajectory(t1, db_path=_db))
    t2 = LhTarget()
    base = EV.evaluate_arm(t2, *ARM.baseline_trajectory(t2))
    assert real.hits - base.hits == 4          # charlie, delta, echo, foxtrot
    assert real.fccr == 0.0 and base.fccr == 0.0


def test_live_arm_is_blind_to_the_answer_key():
    assert "lh_answer_key" not in inspect.getsource(ARM)


def test_real_arm_is_reproducible(_db):
    reports = []
    for _ in range(2):
        t = LhTarget()
        reports.append(EV.evaluate_arm(t, *ARM.real_pipeline_trajectory(t, db_path=_db)))
    assert {(r.hits, r.misses, r.correct_no_finding, r.fccr) for r in reports} == {
        (6, 0, 1, 0.0)}
