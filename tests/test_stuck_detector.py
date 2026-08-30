import pytest

import stuck_detector


@pytest.fixture
def state_path(tmp_path):
    return str(tmp_path / "stuck_detector.json")


def test_tool_sig_identical_calls_produce_same_signature():
    sig1 = stuck_detector.tool_sig("nuclei", {"target": "example.com", "template": "cve"})
    sig2 = stuck_detector.tool_sig("nuclei", {"target": "example.com", "template": "cve"})
    assert sig1 == sig2


def test_tool_sig_key_order_does_not_matter():
    sig1 = stuck_detector.tool_sig("nuclei", {"a": 1, "b": 2})
    sig2 = stuck_detector.tool_sig("nuclei", {"b": 2, "a": 1})
    assert sig1 == sig2


def test_tool_sig_different_args_produce_different_signatures():
    # The exact case this detector must never trip on: a tester legitimately
    # probing different ids (a real IDOR sweep) must not look like a loop.
    sig1 = stuck_detector.tool_sig("sweep_idor", {"object_id": "1"})
    sig2 = stuck_detector.tool_sig("sweep_idor", {"object_id": "2"})
    assert sig1 != sig2


def test_tool_sig_different_tool_names_produce_different_signatures():
    sig1 = stuck_detector.tool_sig("nuclei", {"target": "example.com"})
    sig2 = stuck_detector.tool_sig("nmap", {"target": "example.com"})
    assert sig1 != sig2


def test_observe_returns_ok_below_limit(state_path):
    for _ in range(2):
        verdict = stuck_detector.observe("nuclei", {"target": "example.com"}, limit=3, path=state_path)
    assert verdict == "ok"


def test_observe_nudges_on_reaching_limit(state_path):
    for _ in range(2):
        stuck_detector.observe("nuclei", {"target": "example.com"}, limit=3, path=state_path)
    verdict = stuck_detector.observe("nuclei", {"target": "example.com"}, limit=3, path=state_path)
    assert verdict == "nudge"


def test_observe_does_not_nudge_for_varying_args(state_path):
    # 5 calls to the same tool, but every call has different args -- a
    # real IDOR/recon sweep, not a loop. Must never nudge or abort.
    for i in range(5):
        verdict = stuck_detector.observe(
            "sweep_idor", {"object_id": str(i)}, limit=3, path=state_path,
        )
        assert verdict == "ok"


def test_observe_aborts_on_same_signature_repeating_past_nudge(state_path):
    for _ in range(3):
        verdict = stuck_detector.observe("nuclei", {"target": "example.com"}, limit=3, path=state_path)
    assert verdict == "nudge"
    verdict = stuck_detector.observe("nuclei", {"target": "example.com"}, limit=3, path=state_path)
    assert verdict == "abort"


def test_observe_aborts_on_different_signature_repeating_after_nudge(state_path):
    # The two-strike escalation is deliberately NOT per-signature: once
    # nudged (by tool A repeating), tool B independently repeating past the
    # limit must escalate straight to abort, not get its own 3 free passes.
    for _ in range(3):
        stuck_detector.observe("nuclei", {"target": "a.com"}, limit=3, path=state_path)
    for _ in range(2):
        verdict = stuck_detector.observe("nmap", {"target": "b.com"}, limit=3, path=state_path)
        assert verdict == "ok"
    verdict = stuck_detector.observe("nmap", {"target": "b.com"}, limit=3, path=state_path)
    assert verdict == "abort"


def test_observe_persists_state_across_calls(state_path):
    stuck_detector.observe("nuclei", {"target": "example.com"}, limit=3, path=state_path)
    state = stuck_detector._load(state_path)
    sig = stuck_detector.tool_sig("nuclei", {"target": "example.com"})
    assert state["counts"][sig] == 1


def test_stable_stringify_nested_dict_key_order_independent():
    a = {"outer": {"z": 1, "a": 2}, "list": [1, 2]}
    b = {"list": [1, 2], "outer": {"a": 2, "z": 1}}
    assert stuck_detector.stable_stringify(a) == stuck_detector.stable_stringify(b)
