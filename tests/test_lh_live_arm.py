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
