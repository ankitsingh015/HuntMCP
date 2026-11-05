"""P3-VALAUTHZ integration: finding emission to case_store and the idor-mcp
`replay_authz_two_step` tool (feature-flagged, default off -> existing sweep)."""
import importlib.util
import json
import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "idor-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "authz_target"))

import authz_diff  # noqa: E402
import case_store  # noqa: E402
from authz_app import ALICE, BOB, AuthzApp  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "idor_mcp_server_valauthz", os.path.join(ROOT, "mcp-servers", "idor-mcp", "server.py"))
idor_mcp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(idor_mcp)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path


@pytest.fixture
def vulnerable_app():
    app = AuthzApp(mode="vulnerable").start()
    yield app
    app.stop()


@pytest.fixture
def patched_app():
    app = AuthzApp(mode="patched").start()
    yield app
    app.stop()


def _wf(app):
    return authz_diff.Workflow(f"{app.base_url}/authz/refs", "cart_ref",
                               f"{app.base_url}/authz/carts/{{carried}}/invoice")


def _rows(sql, tmp_path):
    conn = sqlite3.connect(tmp_path / "case.db")
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql).fetchall()]
    finally:
        conn.close()


# --- emit_finding ---------------------------------------------------------

def test_a_leaked_result_becomes_a_discovered_finding_with_conditions_evidence(env, vulnerable_app):
    res = authz_diff.run_two_step(_wf(vulnerable_app), {"Authorization": f"Bearer {ALICE}"},
                                  {"Authorization": f"Bearer {BOB}"})
    out = authz_diff.emit_finding(res, _wf(vulnerable_app))
    assert out["status"] == "DISCOVERED"  # never advanced past DISCOVERED by this tool
    findings = _rows("SELECT * FROM findings", env)
    assert len(findings) == 1 and findings[0]["status"] == "DISCOVERED"
    assert findings[0]["vuln_class"] == "IDOR_MULTISTEP"
    assert findings[0]["parameter"] == "cart_ref"
    ev = _rows("SELECT * FROM evidence", env)
    assert len(ev) == 1 and ev[0]["finding_id"] == findings[0]["id"]
    blob = open(ev[0]["content_ref"]).read()
    cond = json.loads(blob)["conditions"]
    assert cond["identity"] == "other" and cond["carried_id"] == "ck-7f3a91" and cond["step_order"]
    assert ALICE not in blob and BOB not in blob and "Bearer" not in blob


@pytest.mark.parametrize("verdict", ["PROTECTED", "PUBLIC", "SHARED", "DIFFERENT", "INCONCLUSIVE",
                                     "BASELINE_FAILED", "ERROR", "BLOCKED"])
def test_nothing_but_leaked_is_ever_emitted(env, verdict):
    wf = authz_diff.Workflow("http://127.0.0.1:1/r", "x", "http://127.0.0.1:1/o/{carried}")
    assert authz_diff.emit_finding(authz_diff.AuthzResult(verdict=verdict), wf) is None
    assert not os.path.exists(env / "case.db") or _rows("SELECT * FROM findings", env) == []


# --- idor-mcp tool ----------------------------------------------------------

def _call(app, **kw):
    return idor_mcp.replay_authz_two_step(
        url=f"{app.base_url}/authz/refs", carried_path="cart_ref",
        step2_url_template=f"{app.base_url}/authz/carts/{{carried}}/invoice",
        owner_bearer_token=ALICE, other_bearer_token=BOB, **kw)


def test_tool_is_disabled_by_default_and_sends_nothing(env, vulnerable_app, monkeypatch):
    monkeypatch.delenv("HUNTMCP_VALAUTHZ", raising=False)
    out = _call(vulnerable_app)
    assert "disabled" in out.lower() and "sweep_idor" in out
    assert vulnerable_app.request_log == []


def test_tool_reports_leaked_when_enabled_and_never_writes_a_finding_unless_asked(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    out = _call(vulnerable_app)
    assert "LEAKED" in out
    assert not os.path.exists(env / "case.db") or _rows("SELECT * FROM findings", env) == []


def test_tool_with_emit_finding_records_a_discovered_finding(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    out = _call(vulnerable_app, emit_finding=True)
    assert "LEAKED" in out and "finding" in out.lower()
    assert [r["status"] for r in _rows("SELECT * FROM findings", env)] == ["DISCOVERED"]


def test_tool_reports_protected_in_patched_mode(env, patched_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    out = _call(patched_app, emit_finding=True)
    assert "PROTECTED" in out and "LEAKED" not in out
    assert not os.path.exists(env / "case.db") or _rows("SELECT * FROM findings", env) == []


def test_tool_charges_the_tier2_budget_once_per_real_request(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    calls = []
    monkeypatch.setattr(idor_mcp, "_enforce_budget", lambda name: calls.append(name))
    _call(vulnerable_app)
    assert calls == ["idor-mcp"] * len(vulnerable_app.request_log) == ["idor-mcp"] * 7


def test_tool_refuses_a_state_changing_step_without_a_human_approval(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    out = _call(vulnerable_app, step2_method="POST")
    assert "BLOCKED" in out
    assert vulnerable_app.request_log == [] and vulnerable_app.mutation_count == 0


def test_the_tool_no_longer_accepts_an_agent_written_approval(env):
    import inspect
    assert "nonidempotent_approval" not in inspect.signature(idor_mcp.replay_authz_two_step).parameters


def test_existing_sweep_tool_is_unchanged_by_the_flag(env, vulnerable_app, monkeypatch):
    monkeypatch.delenv("HUNTMCP_VALAUTHZ", raising=False)
    assert hasattr(idor_mcp, "sweep_idor") and hasattr(idor_mcp, "guess_idor")


# --- review-fix round -------------------------------------------------------

def test_emitting_the_same_leak_twice_records_one_finding(env, vulnerable_app):
    wf = _wf(vulnerable_app)
    res = authz_diff.run_two_step(wf, {"Authorization": f"Bearer {ALICE}"}, {"Authorization": f"Bearer {BOB}"})
    first = authz_diff.emit_finding(res, wf)
    second = authz_diff.emit_finding(res, wf)
    assert second["finding_id"] == first["finding_id"] and second.get("duplicate") is True
    assert len(_rows("SELECT * FROM findings", env)) == 1
    assert len(_rows("SELECT * FROM evidence", env)) == 1


def test_finding_endpoint_never_stores_a_url_secret(env):
    wf = authz_diff.Workflow("http://127.0.0.1:1/r", "x", "http://127.0.0.1:1/o/{carried}?api_key=SECRETKEY99")
    res = authz_diff.AuthzResult(verdict="LEAKED", evidence={"conditions": {}})
    authz_diff.emit_finding(res, wf)
    endpoint = _rows("SELECT endpoint FROM findings", env)[0]["endpoint"]
    assert "SECRETKEY99" not in endpoint and "REDACTED" in endpoint


def test_case_store_find_finding_matches_on_class_endpoint_and_parameter(env):
    assert case_store.find_finding("IDOR_MULTISTEP", "http://h/o/{carried}", "p") is None
    created = case_store.create_finding("IDOR_MULTISTEP", "http://h/o/{carried}", parameter="p")
    assert case_store.find_finding("IDOR_MULTISTEP", "http://h/o/{carried}", "p")["id"] == created["id"]
    assert case_store.find_finding("IDOR_MULTISTEP", "http://h/o/{carried}", "other") is None


def test_tool_output_never_echoes_url_query_secrets(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    out = idor_mcp.replay_authz_two_step(
        url=f"{vulnerable_app.base_url}/authz/refs?access_token=SECRETXYZ12345", carried_path="cart_ref",
        step2_url_template=f"{vulnerable_app.base_url}/authz/carts/{{carried}}/invoice?api_key=SECRETKEY99",
        owner_bearer_token=ALICE, other_bearer_token=BOB)
    assert "LEAKED" in out
    assert "SECRETXYZ12345" not in out and "SECRETKEY99" not in out


def test_a_later_run_attaches_its_evidence_to_the_existing_finding(env, vulnerable_app, monkeypatch):
    wf = _wf(vulnerable_app)
    res = authz_diff.run_two_step(wf, {"Authorization": f"Bearer {ALICE}"}, {"Authorization": f"Bearer {BOB}"})
    real = case_store.add_evidence
    monkeypatch.setattr(case_store, "add_evidence", lambda *a, **k: {"error": "disk full"})
    first = authz_diff.emit_finding(res, wf)
    assert first["evidence_recorded"] is False and _rows("SELECT * FROM evidence", env) == []
    monkeypatch.setattr(case_store, "add_evidence", real)
    again = authz_diff.emit_finding(res, wf)
    assert again["finding_id"] == first["finding_id"] and again["duplicate"] is True
    assert again["evidence_recorded"] is True and len(_rows("SELECT * FROM evidence", env)) == 1


def test_identical_rerun_does_not_add_a_second_evidence_row_but_new_evidence_does(env, vulnerable_app):
    wf = _wf(vulnerable_app)
    hdr = ({"Authorization": f"Bearer {ALICE}"}, {"Authorization": f"Bearer {BOB}"})
    res = authz_diff.run_two_step(wf, *hdr)
    authz_diff.emit_finding(res, wf)
    authz_diff.emit_finding(res, wf)
    assert len(_rows("SELECT * FROM evidence", env)) == 1
    res.evidence = {**res.evidence, "other_own_status": 299}  # different evidence content
    authz_diff.emit_finding(res, wf)
    assert len(_rows("SELECT * FROM evidence", env)) == 2


def test_case_store_has_evidence_matches_on_finding_and_hash(env):
    created = case_store.create_finding("IDOR_MULTISTEP", "http://h/o/{carried}", parameter="p")
    ev = case_store.add_evidence("metadata", "payload", finding_id=created["id"])
    assert case_store.has_evidence(created["id"], ev["hash"]) is True
    assert case_store.has_evidence(created["id"], "0" * 64) is False


# --- human gate (scripts/confirm-state-change.sh) for state-changing steps ---------------

import io  # noqa: E402

import state_change_confirm as scc  # noqa: E402


class _TTY(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def confirm_env(env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    monkeypatch.setenv("HUNTMCP_STATE_CHANGE_CONFIRM_PATH", str(env / "state-change-confirm.json"))
    return env


def _post_call(app):
    return idor_mcp.replay_authz_two_step(
        url=f"{app.base_url}/authz/refs", carried_path="cart_ref",
        step2_url_template=f"{app.base_url}/authz/carts/{{carried}}/cancel",
        owner_bearer_token=ALICE, other_bearer_token=BOB, step2_method="POST")


_OWNER_H = {"Authorization": f"Bearer {ALICE}"}
_OTHER_H = {"Authorization": f"Bearer {BOB}"}


def _wf_cancel(app):
    return authz_diff.Workflow(f"{app.base_url}/authz/refs", "cart_ref",
                               f"{app.base_url}/authz/carts/{{carried}}/cancel", step2_method="POST")


def _wf_create(app, path="drafts", key="draft_ref", body='{"title": "quarterly plan"}'):
    return authz_diff.Workflow(f"{app.base_url}/authz/{path}", key, f"{app.base_url}/authz/{path}/{{carried}}",
                               step1_method="POST", step1_body=body)


def _human_confirms(app, methods, wf=None):
    """What a human does: run scripts/confirm-state-change.sh with the host, methods and the
    fingerprint the tool printed for the exact workflow."""
    host = app.base_url.split("//", 1)[1]
    fp = authz_diff.workflow_fingerprint(wf or _wf_cancel(app), _OWNER_H, _OTHER_H)
    assert scc.request_confirmation(host, methods, fp, stdin=_TTY(scc.target_string(host, methods, fp) + "\n"),
                                    stdout=io.StringIO())


def test_a_state_changing_step_is_blocked_with_zero_requests_until_a_human_confirms(confirm_env, vulnerable_app):
    out = _post_call(vulnerable_app)
    assert "BLOCKED" in out and "confirm-state-change.sh" in out
    assert vulnerable_app.request_log == [] and vulnerable_app.mutation_count == 0


def test_a_human_confirmation_lets_exactly_one_state_changing_run_through(confirm_env, vulnerable_app):
    _human_confirms(vulnerable_app, ["POST"])
    out = _post_call(vulnerable_app)
    assert "BLOCKED" not in out and any(e["method"] == "POST" for e in vulnerable_app.request_log)
    before = len(vulnerable_app.request_log)
    again = _post_call(vulnerable_app)
    assert "BLOCKED" in again and len(vulnerable_app.request_log) == before  # token was single-use


def test_a_confirmation_for_other_methods_or_another_host_does_not_authorize_this_run(confirm_env, vulnerable_app):
    _human_confirms(vulnerable_app, ["DELETE"])
    assert "BLOCKED" in _post_call(vulnerable_app) and vulnerable_app.request_log == []


def test_a_structurally_bad_workflow_does_not_burn_the_human_token(confirm_env, vulnerable_app):
    _human_confirms(vulnerable_app, ["POST"])
    bad = idor_mcp.replay_authz_two_step(
        url=f"{vulnerable_app.base_url}/authz/refs", carried_path="cart_ref",
        step2_url_template=f"{vulnerable_app.base_url}/authz/no-placeholder", step2_method="POST",
        owner_bearer_token=ALICE, other_bearer_token=BOB)
    assert "ERROR" in bad and vulnerable_app.request_log == []
    assert "BLOCKED" not in _post_call(vulnerable_app)  # the same token still works afterwards


def test_every_exit_path_of_the_tool_is_written_to_the_audit_log(confirm_env, vulnerable_app):
    _post_call(vulnerable_app)  # BLOCKED: no human confirmation
    idor_mcp.replay_authz_two_step(  # ERROR: malformed workflow
        url=f"{vulnerable_app.base_url}/authz/refs", carried_path="cart_ref",
        step2_url_template=f"{vulnerable_app.base_url}/authz/no-placeholder",
        owner_bearer_token=ALICE, other_bearer_token=BOB)
    lines = [json.loads(line) for line in open(confirm_env / "audit.jsonl")]
    mine = [e for e in lines if "replay_authz_two_step" in json.dumps(e)]
    assert len(mine) == 2


def test_userinfo_in_the_url_is_rejected_and_never_reaches_the_confirm_prompt(confirm_env, vulnerable_app):
    host = vulnerable_app.base_url.split("//", 1)[1]
    out = idor_mcp.replay_authz_two_step(
        url=f"http://user:pw@{host}/authz/refs", carried_path="cart_ref",
        step2_url_template=f"http://user:pw@{host}/authz/carts/{{carried}}/cancel", step2_method="POST",
        owner_bearer_token=ALICE, other_bearer_token=BOB)
    assert "ERROR" in out and "pw" not in out and vulnerable_app.request_log == []


def test_an_unapprovable_method_is_an_error_not_a_confirmation_request(confirm_env, vulnerable_app):
    out = idor_mcp.replay_authz_two_step(
        url=f"{vulnerable_app.base_url}/authz/refs", carried_path="cart_ref",
        step2_url_template=f"{vulnerable_app.base_url}/authz/carts/{{carried}}/x", step2_method="TRACE",
        owner_bearer_token=ALICE, other_bearer_token=BOB)
    assert "ERROR" in out and "confirm-state-change.sh" not in out and vulnerable_app.request_log == []


def test_an_out_of_scope_host_does_not_burn_the_human_token(confirm_env, vulnerable_app, monkeypatch):
    import scope_guard
    _human_confirms(vulnerable_app, ["POST"])
    real = scope_guard.load_engagement
    # a non-safe host is out of scope under this engagement -> the pre-check must refuse before consuming
    monkeypatch.setattr(scope_guard, "load_engagement",
                        lambda path=None: scope_guard.Engagement(target="x", in_scope=["only.invalid"]))
    out = idor_mcp.replay_authz_two_step(
        url="http://target.invalid:1/refs", carried_path="r",
        step2_url_template="http://target.invalid:1/o/{carried}/cancel", step2_method="POST",
        owner_bearer_token=ALICE, other_bearer_token=BOB)
    assert "scope" in out.lower() and "no request was sent" in out.lower()
    monkeypatch.setattr(scope_guard, "load_engagement", real)
    assert "BLOCKED" not in _post_call(vulnerable_app)  # the human's token is still there


def test_the_suggested_confirm_command_is_shell_quoted(confirm_env, vulnerable_app):
    out = idor_mcp.replay_authz_two_step(
        url="http://127.0.0.1:1/r", carried_path="r",
        step2_url_template="http://127.0.0.1:1/o/{carried}", step2_method="POST",
        owner_bearer_token=ALICE, other_bearer_token=BOB)
    assert "scripts/confirm-state-change.sh 127.0.0.1:1 POST" in out


def test_an_ipv6_host_is_shell_quoted_in_the_suggested_confirm_command(confirm_env):
    out = idor_mcp.replay_authz_two_step(
        url="http://[::1]:1/r", carried_path="r", step2_url_template="http://[::1]:1/o/{carried}",
        step2_method="POST", owner_bearer_token=ALICE, other_bearer_token=BOB)
    assert "scripts/confirm-state-change.sh '[::1]:1' POST" in out


# --- create-then-read through the tool (POST step 1 with a body) -------------------------

def _create_call(app, **kw):
    return idor_mcp.replay_authz_two_step(
        url=f"{app.base_url}/authz/drafts", carried_path="draft_ref",
        step2_url_template=f"{app.base_url}/authz/drafts/{{carried}}",
        owner_bearer_token=ALICE, other_bearer_token=BOB, step1_method="POST",
        step1_body=kw.pop("step1_body", '{"title": "quarterly plan"}'), **kw)


def test_create_then_read_is_blocked_with_zero_requests_until_a_human_confirms(confirm_env, vulnerable_app):
    out = _create_call(vulnerable_app)
    assert "BLOCKED" in out and "confirm-state-change.sh" in out
    assert vulnerable_app.request_log == [] and vulnerable_app.mutation_count == 0


def test_create_then_read_finds_the_leak_in_vulnerable_mode(confirm_env, vulnerable_app):
    _human_confirms(vulnerable_app, ["POST"], _wf_create(vulnerable_app))
    out = _create_call(vulnerable_app)
    assert "LEAKED" in out, out
    posts = [e for e in vulnerable_app.request_log if e["method"] == "POST"]
    assert len(posts) == 2 and all("quarterly plan" in e["body"] for e in posts)  # owner + the other's own-object control
    assert vulnerable_app.mutation_count == 2
    assert "quarterly plan" not in out


def test_create_then_read_is_protected_in_patched_mode(confirm_env, patched_app):
    _human_confirms(patched_app, ["POST"], _wf_create(patched_app))
    out = _create_call(patched_app)
    assert "PROTECTED" in out and "LEAKED" not in out
    assert patched_app.mutation_count == 1  # only the owner's create; the other identity only reads


def test_an_owner_only_create_then_read_endpoint_is_never_reported(confirm_env, vulnerable_app):
    _human_confirms(vulnerable_app, ["POST"], _wf_create(vulnerable_app, "receipts", "receipt_ref", '{"title": "t"}'))
    out = idor_mcp.replay_authz_two_step(
        url=f"{vulnerable_app.base_url}/authz/receipts", carried_path="receipt_ref",
        step2_url_template=f"{vulnerable_app.base_url}/authz/receipts/{{carried}}",
        owner_bearer_token=ALICE, other_bearer_token=BOB, step1_method="POST", step1_body='{"title": "t"}')
    assert "PROTECTED" in out and "LEAKED" not in out


def test_a_bad_body_is_an_error_and_does_not_burn_the_human_token(confirm_env, vulnerable_app):
    _human_confirms(vulnerable_app, ["POST"], _wf_create(vulnerable_app))
    out = _create_call(vulnerable_app, step1_body="not json")
    assert "ERROR" in out and vulnerable_app.request_log == []
    assert "BLOCKED" not in _create_call(vulnerable_app)  # the token is still there


# --- matrix tool + per-identity findings ------------------------------------------------

from authz_app import CAROL, ROOT as ADMIN  # noqa: E402


def _matrix_call(app, key="ledger_ref", path="/authz/ledger/{carried}", ids=None, **kw):
    ids = ids if ids is not None else json.dumps([
        {"name": "bobby", "bearer_token": BOB}, {"name": "carol", "bearer_token": CAROL},
        {"name": "root", "bearer_token": ADMIN, "should_have_access": True}])
    return idor_mcp.replay_authz_matrix(
        url=f"{app.base_url}/authz/refs", carried_path=key, step2_url_template=f"{app.base_url}{path}",
        owner_bearer_token=ALICE, identities_json=ids, **kw)


def test_matrix_tool_is_disabled_by_default(env, vulnerable_app, monkeypatch):
    monkeypatch.delenv("HUNTMCP_VALAUTHZ", raising=False)
    out = _matrix_call(vulnerable_app)
    assert "disabled" in out.lower() and vulnerable_app.request_log == []


def test_matrix_tool_reports_each_identity(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    out = _matrix_call(vulnerable_app)
    assert "bobby: LEAKED" in out and "carol: LEAKED" in out and "root: EXPECTED_ACCESS" in out
    for tok in (ALICE, BOB, CAROL, ADMIN):
        assert tok not in out


def test_matrix_tool_emits_one_finding_per_wrongly_allowed_identity_only(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    _matrix_call(vulnerable_app, emit_finding=True)
    rows = _rows("SELECT parameter FROM findings ORDER BY id", env)
    assert [r["parameter"] for r in rows] == ["ledger_ref@bobby", "ledger_ref@carol"]
    ev = _rows("SELECT * FROM evidence", env)
    assert len(ev) == 2
    idents = sorted(json.loads(open(e["content_ref"]).read())["conditions"]["identity"] for e in ev)
    assert idents == ["bobby", "carol"]
    _matrix_call(vulnerable_app, emit_finding=True)  # re-run: no duplicates
    assert len(_rows("SELECT * FROM findings", env)) == 2 and len(_rows("SELECT * FROM evidence", env)) == 2


@pytest.mark.parametrize("bad", ["not json", "{}", "[]", '[{"name": "x"}]', '[{"bearer_token": "t"}]',
                                 '[{"name": "a", "bearer_token": "t", "should_have_access": "yes"}]'])
def test_matrix_tool_rejects_malformed_identities_without_requests(env, vulnerable_app, monkeypatch, bad):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    out = _matrix_call(vulnerable_app, ids=bad)
    assert "ERROR" in out and vulnerable_app.request_log == []


def test_matrix_tool_writes_the_audit_log_on_every_path(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    _matrix_call(vulnerable_app, ids="not json")
    _matrix_call(vulnerable_app)
    lines = [json.loads(line) for line in open(env / "audit.jsonl")]
    assert len([e for e in lines if "replay_authz_matrix" in json.dumps(e)]) == 2


def test_matrix_tool_charges_the_budget_per_request(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    calls = []
    monkeypatch.setattr(idor_mcp, "_enforce_budget", lambda name: calls.append(name))
    _matrix_call(vulnerable_app)
    assert len(calls) == len(vulnerable_app.request_log) > 0


# --- sixth/seventh review: the human token is bound to the exact workflow ----------------------

def test_the_blocked_message_shows_what_would_be_sent_and_the_fingerprint_to_confirm(confirm_env, vulnerable_app):
    out = _create_call(vulnerable_app, step1_body='{"title": "SECRET-TITLE-xyz"}')
    wf = _wf_create(vulnerable_app, body='{"title": "SECRET-TITLE-xyz"}')
    fp = authz_diff.workflow_fingerprint(wf, _OWNER_H, _OTHER_H)
    assert fp in out and "/authz/drafts" in out and "sha256:" in out and "again by the other identity" in out
    assert "SECRET-TITLE-xyz" not in out  # the body itself is never echoed, only its hash


def test_a_confirmation_for_another_body_or_path_does_not_authorize_this_workflow(confirm_env, vulnerable_app):
    _human_confirms(vulnerable_app, ["POST"], _wf_create(vulnerable_app, body='{"title": "something else"}'))
    assert "BLOCKED" in _create_call(vulnerable_app) and vulnerable_app.request_log == []
    _human_confirms(vulnerable_app, ["POST"], _wf_create(vulnerable_app, "receipts", "receipt_ref"))
    assert "BLOCKED" in _create_call(vulnerable_app) and vulnerable_app.request_log == []


def test_a_token_with_no_fingerprint_never_authorizes_the_tool(confirm_env, vulnerable_app):
    host = vulnerable_app.base_url.split("//", 1)[1]
    assert scc.request_confirmation(host, ["POST"], stdin=_TTY(scc.target_string(host, ["POST"]) + "\n"),
                                    stdout=io.StringIO())
    assert "BLOCKED" in _post_call(vulnerable_app) and vulnerable_app.request_log == []


def test_matrix_audit_log_records_each_identity_its_policy_and_verdict(env, vulnerable_app, monkeypatch):
    monkeypatch.setenv("HUNTMCP_VALAUTHZ", "1")
    _matrix_call(vulnerable_app)
    lines = [json.loads(line) for line in open(env / "audit.jsonl")]
    blob = json.dumps([e for e in lines if "replay_authz_matrix" in json.dumps(e)])
    for needle in ("bobby=LEAKED", "carol=LEAKED", "root=EXPECTED_ACCESS(policy:allowed)"):
        assert needle in blob
    for tok in (ALICE, BOB, CAROL, ADMIN):
        assert tok not in blob


def test_the_blocked_call_leaves_a_pending_summary_for_the_human_prompt(confirm_env, vulnerable_app):
    _create_call(vulnerable_app)
    fp = authz_diff.workflow_fingerprint(_wf_create(vulnerable_app), _OWNER_H, _OTHER_H)
    host = vulnerable_app.base_url.split("//", 1)[1]
    out = io.StringIO()
    phrase = scc.target_string(host, ["POST"], fp)
    assert scc.request_confirmation(host, ["POST"], fp, stdin=_TTY(phrase + "\n"), stdout=out)
    shown = out.getvalue()
    assert "/authz/drafts" in shown and "sha256:" in shown and "quarterly plan" not in shown


def test_a_workflow_whose_redacted_summary_is_too_long_to_confirm_is_refused_before_any_token(confirm_env, vulnerable_app):
    # 280 chars of token= pairs: redaction replaces each value with a ~40-char marker, so the
    # summary balloons far past what the prompt will show -> refuse instead of asking the human
    template = f"{vulnerable_app.base_url}/authz/drafts/{{carried}}?"
    q = "&".join(["token=1"] * 60)[:290 - len(template)]  # each URL stays under the 300-char cap
    out = idor_mcp.replay_authz_two_step(
        url=f"{vulnerable_app.base_url}/authz/drafts?{q}", carried_path="draft_ref",
        step2_url_template=f"{vulnerable_app.base_url}/authz/drafts/{{carried}}?{q}",
        owner_bearer_token=ALICE, other_bearer_token=BOB, step1_method="POST", step1_body='{"title": "t"}')
    assert "ERROR" in out and "too long" in out and vulnerable_app.request_log == []
    assert "confirm-state-change.sh" not in out
