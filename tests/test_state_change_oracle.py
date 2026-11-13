"""#144 -- a state-changing control (CSRF / auth-bypass) may be concluded
bypassable ONLY after an INDEPENDENT read-back proves the state actually
changed, never from an HTTP 2xx / 302 / redirect / echoed-success response.

Encodes the behindthename.com (2026-11-12) false-positive: a benign 302 on a
silently-rejected write looked like a CSRF bypass until a read-back of the field
showed it was unchanged.
"""
import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import state_change_oracle as sco  # noqa: E402


# --- the conclusion oracle: confirm_state_change ------------------------------

def test_no_readback_is_inconclusive_not_confirmed():
    """The core #144 rule: with only the mutating response (no read-back), the
    verdict is INCONCLUSIVE -- never CONFIRMED. There is deliberately no way to
    pass the mutating response's status in at all."""
    verdict, reason = sco.confirm_state_change(None, None)
    assert verdict == sco.INCONCLUSIVE
    assert "read-back" in reason.lower()


def test_benign_302_silent_rejection_is_not_a_state_change():
    """behindthename.com: the write was silently rejected; an independent read
    before and after shows the SAME value. This is NOT_CHANGED, the opposite of a
    bypass -- even though the real server returned a 302."""
    before = {"signature": "original"}
    after = {"signature": "original"}  # unchanged on read-back despite the 302
    verdict, reason = sco.confirm_state_change(before, after)
    assert verdict == sco.NOT_CHANGED
    assert "held" in reason or "silently rejected" in reason


def test_a_real_change_against_a_baseline_is_confirmed():
    verdict, _ = sco.confirm_state_change({"signature": "original"},
                                          {"signature": "attacker-set"})
    assert verdict == sco.CONFIRMED


def test_expected_value_present_in_readback_is_confirmed():
    verdict, _ = sco.confirm_state_change("old email", "attacker@evil.example",
                                          expected_after="attacker@evil.example")
    assert verdict == sco.CONFIRMED


def test_changed_but_expected_value_absent_is_inconclusive():
    """The state changed, but not to what the attack intended -- could be an
    unrelated concurrent change. Not a confirmed bypass."""
    verdict, reason = sco.confirm_state_change("old", "something else entirely",
                                               expected_after="attacker@evil.example")
    assert verdict == sco.INCONCLUSIVE
    assert "intended" in reason


def test_expected_value_with_no_baseline_is_inconclusive_not_confirmed():
    """#144 one level in: a value merely PRESENT after the attack, with no baseline
    proving it was absent before, is not proof the state changed -- it may have
    held that value all along."""
    verdict, reason = sco.confirm_state_change(None, "role=admin now",
                                               expected_after="role=admin")
    assert verdict == sco.INCONCLUSIVE
    assert "baseline" in reason


def test_structured_expected_value_matches_by_normalized_equality():
    """A dict expected value that substring-matching would miss (re-sorted JSON
    braces) is still CONFIRMED via normalized equality, given a real baseline."""
    verdict, _ = sco.confirm_state_change({"role": "user"}, {"role": "admin"},
                                          expected_after={"role": "admin"})
    assert verdict == sco.CONFIRMED


def test_readback_after_but_no_baseline_and_no_expected_is_inconclusive():
    verdict, reason = sco.confirm_state_change(None, "current value")
    assert verdict == sco.INCONCLUSIVE
    assert "baseline" in reason


def test_oob_callback_confirms_independently():
    verdict, reason = sco.confirm_state_change(None, None, oob_confirmed=True)
    assert verdict == sco.CONFIRMED
    assert "out-of-band" in reason


def test_blank_readback_is_treated_as_no_observation():
    """An empty/whitespace read-back is not an observation to compare."""
    verdict, _ = sco.confirm_state_change("baseline", "   ")
    assert verdict == sco.INCONCLUSIVE


def test_structured_state_is_order_insensitive():
    """Dict key order must not create a phantom 'change'."""
    verdict, _ = sco.confirm_state_change({"a": 1, "b": 2}, {"b": 2, "a": 1})
    assert verdict == sco.NOT_CHANGED


def test_why_status_is_insufficient_names_the_status():
    assert "403" not in sco.why_status_is_insufficient(302)
    assert "302" in sco.why_status_is_insufficient(302)
    assert "not sufficient" in sco.why_status_is_insufficient().lower()


# --- the CEM success_signature advisory --------------------------------------

_STATUS_ONLY = {"status_in": [200, 302]}
_WITH_BODY = {"status_in": [200], "body_contains": "attacker-value-on-refetch"}


def test_state_changing_status_only_signature_is_flagged():
    warn = sco.readback_signature_advisory(_STATUS_ONLY, "POST", state_change_authorized=True)
    assert warn and "read-back" in warn.lower() and "#144" in warn


def test_status_only_but_read_only_method_is_not_flagged():
    assert sco.readback_signature_advisory(_STATUS_ONLY, "GET", state_change_authorized=False) is None


def test_state_changing_with_a_body_matcher_is_not_flagged():
    assert sco.readback_signature_advisory(_WITH_BODY, "POST", state_change_authorized=True) is None


def test_approval_forces_state_changing_even_if_method_missing():
    assert sco.readback_signature_advisory(_STATUS_ONLY, None, state_change_authorized=True) is not None


def test_non_read_only_method_alone_triggers_the_advisory():
    assert sco.readback_signature_advisory(_STATUS_ONLY, "delete", state_change_authorized=False) is not None


# --- integration: the advisory reaches the real case-mcp define_conditions ----

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_sco", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

IN = "in-scope-target.example"
_CONDS = [{"name": "csrf_token", "category": "header", "baseline_value": "t",
           "perturbation": {"drop": True}}]
_APPROVAL = {"methods": ["POST"], "reason": "confirmed CSRF needs a POST to show state change",
             "authorized_by": "operator-jdoe"}


@pytest.fixture
def cem(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path


def _confirmed_finding():
    f = json.loads(srv.create_finding("CSRF", "/members/doedit_settings.php"))
    srv.add_evidence("request", "r", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    return f["id"]


def _define(sig, approval=_APPROVAL):
    fid = _confirmed_finding()
    base = {"method": "POST", "url": f"https://{IN}/members/doedit_settings.php",
            "headers": {"Cookie": "s=1"}, "body": None}
    out = json.loads(srv.define_conditions(fid, json.dumps(base), json.dumps(sig),
                                           json.dumps(_CONDS), k=3,
                                           nonidempotent_approval=json.dumps(approval)))
    return out


def test_define_conditions_surfaces_the_readback_warning_for_a_status_only_csrf_oracle(cem):
    out = _define(_STATUS_ONLY)
    assert "error" not in out, out
    assert "condition_ids" in out                      # still defined successfully (advisory, not rejection)
    assert "readback_warning" in out and "#144" in out["readback_warning"]


def test_define_conditions_has_no_warning_when_the_oracle_checks_a_readback_body(cem):
    out = _define(_WITH_BODY)
    assert "error" not in out, out
    assert "readback_warning" not in out
