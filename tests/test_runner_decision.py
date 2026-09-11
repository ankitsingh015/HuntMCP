"""Tests for the dev-runner human-decision gate (scripts/runner/decision.py).

When the runner will not proceed, it emits a concise, structured decision request
containing every field a human needs to rule -- then STOPs.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import decision  # noqa: E402


def _req(**overrides):
    kwargs = dict(
        task_id="C6",
        ambiguity="Plan does not specify the alternates-search bound.",
        contract="PHASE1-PLAN §D defines interestingness but names no bound.",
        options=["Bound = number of conditions", "Bound = fixed k", "Ask spec owner"],
        recommendation="Bound = number of conditions (matches ddmin cost model).",
        downstream=["C8 bundle completeness field", "K2 FCCR gate"],
        stop_codes=["API_AMBIGUITY"],
    )
    kwargs.update(overrides)
    return decision.DecisionRequest(**kwargs)


def test_render_contains_all_required_sections():
    text = decision.format_decision_request(_req())
    for header in ("TASK", "AMBIGUITY", "CONTRACT", "OPTIONS", "RECOMMENDATION", "DOWNSTREAM"):
        assert header in text.upper()


def test_render_includes_task_and_options_and_downstream():
    text = decision.format_decision_request(_req())
    assert "C6" in text
    assert "Bound = fixed k" in text
    assert "K2 FCCR gate" in text


def test_render_handles_absent_recommendation():
    text = decision.format_decision_request(_req(recommendation=None))
    assert "no recommendation" in text.lower() or "human judgement" in text.lower()


def test_render_handles_empty_downstream():
    text = decision.format_decision_request(_req(downstream=[]))
    assert "none identified" in text.lower() or "no downstream" in text.lower()


def test_render_ends_with_explicit_stop():
    text = decision.format_decision_request(_req())
    assert "STOP" in text.upper()
    # the runner must not continue until a decision is supplied
    assert "await" in text.lower() or "supplied" in text.lower() or "do not proceed" in text.lower()


def test_stop_codes_are_shown():
    text = decision.format_decision_request(_req(stop_codes=["WORKTREE_MISMATCH", "API_AMBIGUITY"]))
    assert "WORKTREE_MISMATCH" in text
    assert "API_AMBIGUITY" in text
