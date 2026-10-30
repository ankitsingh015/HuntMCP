"""P3-CEMHUNT: case-mcp's run_cem_pipeline orchestrates the EXISTING CEM tools
(define_conditions -> determinism_gate -> run_counterfactual per condition ->
minimal_condition_sets -> evidence_bundle) in a fixed, gated order. It adds no
CEM logic and no new request path: every network call still goes through the
unchanged determinism_gate/run_counterfactual senders, so their CONFIRMED
guard, scope, budget, audit and read-only-method gates all still apply.

No real network -- http_probe.fetch is monkeypatched on the loaded server module.
"""
import importlib.util
import io
import json
import os
import sys

import engagement_paths
import pytest
import scope_gate_hook as hook

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_cemhunt", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)
FetchResult = srv.http_probe.FetchResult

IN_SCOPE = "in-scope-target.example"
OOS = "out-of-scope-evil.example"

_SIG = {"status_in": [200]}
_CONDS = [
    {"name": "auth_cookie", "category": "identity", "baseline_value": "present",
     "perturbation": {"drop": True}},
    {"name": "X-Trace", "category": "noise", "baseline_value": "1",
     "perturbation": {"drop": True}},
]


def _base(url=f"https://{IN_SCOPE}/doc/1"):
    return {"method": "GET", "url": url,
            "headers": {"Cookie": "sid=abc", "X-Trace": "1"}, "body": None}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    eng = tmp_path / "engagement.yaml"
    eng.write_text(f"target: {IN_SCOPE}\nin_scope:\n  - {IN_SCOPE}\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))


def _auth_gated_fetch(calls):
    """Deterministic target: 200 while the Cookie header is present, else 403.
    The X-Trace header never affects the outcome."""
    def _f(url, method, headers, body, timeout_s):
        calls.append(url)
        ok = any(h.lower() == "cookie" for h in (headers or {}))
        return FetchResult(status=200 if ok else 403, body="", error=None)
    return _f


def _confirmed_finding():
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "GET /doc/1", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    return f["id"]


def _run(fid, base=None, sig=None, conds=None, k=3, url=None, **kw):
    base = base or _base()
    return json.loads(srv.run_cem_pipeline(
        fid, url or base["url"], json.dumps(base), json.dumps(sig or _SIG),
        json.dumps(conds or _CONDS), k=k, **kw))


def test_tool_is_registered():
    assert callable(srv.run_cem_pipeline)


# --- happy path -------------------------------------------------------------

def test_full_pipeline_recovers_necessary_and_unnecessary_conditions(monkeypatch):
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    out = _run(_confirmed_finding())

    assert out["stopped_at"] is None
    assert out["incomplete"] is False
    assert out["determinism_status"] == "STABLE"
    assert out["verdicts"] == {"auth_cookie": "necessary", "X-Trace": "apparently_not_necessary"}
    assert out["minimal_condition_sets"]["minimal_sets"] == [["auth_cookie"]]
    assert out["evidence_bundle"]["identified_necessary_conditions"] == ["auth_cookie"]
    # gate (k) + per condition: baseline arm (k) + perturbed arm (k)
    assert len(calls) == 3 + 2 * (3 + 3)


def test_no_necessary_condition_skips_minimal_sets_but_still_returns_bundle(monkeypatch):
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    only_noise = [_CONDS[1]]
    out = _run(_confirmed_finding(), conds=only_noise)

    assert out["verdicts"] == {"X-Trace": "apparently_not_necessary"}
    assert out["minimal_condition_sets"] is None
    assert out["evidence_bundle"]["identified_necessary_conditions"] == []


# --- the determinism gate decides whether counterfactuals run at all --------

def test_nondeterministic_baseline_stops_before_any_counterfactual(monkeypatch):
    seen = {"n": 0}

    def _flaky(url, method, headers, body, timeout_s):
        seen["n"] += 1
        return FetchResult(status=200 if seen["n"] % 2 else 403, body="", error=None)

    monkeypatch.setattr(srv.http_probe, "fetch", _flaky)
    fid = _confirmed_finding()
    out = _run(fid)

    assert out["stopped_at"] == "determinism_gate"
    assert out["determinism_status"] == "NONDETERMINISTIC"
    assert out["verdicts"] == {}
    assert sorted(out["untested"]) == ["X-Trace", "auth_cookie"]
    assert seen["n"] == 3  # only the gate's k requests were ever sent
    assert srv.case_store.cem_load_state(fid)["verdicts"] == []


# --- every existing gate still applies --------------------------------------

def test_unconfirmed_finding_is_refused_and_sends_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))  # still DISCOVERED
    out = _run(f["id"])

    assert out["stopped_at"] == "define_conditions"
    assert "error" in out
    assert calls == []


def test_out_of_scope_base_request_is_refused_and_sends_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    out = _run(_confirmed_finding(), base=_base(f"https://{OOS}/doc/1"))

    assert out["stopped_at"] == "determinism_gate"
    assert out["incomplete"] is True
    assert "error" in out
    assert calls == []


def test_url_label_must_match_base_request_url(monkeypatch):
    """The hook can only pre-filter on the `url` argument, so a label that names
    a different host than the request actually sent would defeat that layer."""
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    fid = _confirmed_finding()
    out = _run(fid, url=f"https://{IN_SCOPE}/somewhere-else")

    assert out["stopped_at"] == "define_conditions"
    assert "error" in out
    assert calls == []
    assert srv.case_store.cem_load_state(fid).get("error")  # nothing was defined


@pytest.mark.parametrize("bad_k", [0, -1])
def test_invalid_k_is_refused_before_anything_is_persisted(monkeypatch, bad_k):
    """define_conditions is one-shot: a k the senders later reject must not leave
    behind an unusable CEM state that can never be redefined."""
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    fid = _confirmed_finding()
    out = _run(fid, k=bad_k)

    assert out["stopped_at"] == "define_conditions"
    assert "error" in out
    assert calls == []
    # nothing was defined, so a corrected retry still works end to end
    assert _run(fid, k=3)["stopped_at"] is None


def test_post_base_request_is_refused_without_approval(monkeypatch):
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    post = {**_base(), "method": "POST"}
    out = _run(_confirmed_finding(), base=post)

    assert out["stopped_at"] == "determinism_gate"
    assert calls == []


def test_every_early_exit_returns_the_same_result_shape(monkeypatch):
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch([]))
    full = set(_run(_confirmed_finding()))
    refusals = [
        _run(_confirmed_finding(), k=0),                                  # invalid k
        _run(_confirmed_finding(), url=f"https://{IN_SCOPE}/elsewhere"),  # label mismatch
        _run(json.loads(srv.create_finding("IDOR", "/x"))["id"]),         # not confirmed
    ]
    assert all(set(r) >= full for r in refusals)


def test_post_with_a_valid_human_approval_is_allowed_through(monkeypatch):
    """nonidempotent_approval must still reach define_conditions' validation and
    the senders' per-finding method gate -- the pipeline neither drops nor
    fabricates it."""
    methods = []

    def _post_ok(url, method, headers, body, timeout_s):
        methods.append(method)
        ok = any(h.lower() == "cookie" for h in (headers or {}))
        return FetchResult(status=200 if ok else 403, body="", error=None)

    monkeypatch.setattr(srv.http_probe, "fetch", _post_ok)
    approval = {"methods": ["POST"], "reason": "confirmed finding is a POST-only state change",
                "authorized_by": "analyst@example.com"}
    out = _run(_confirmed_finding(), base={**_base(), "method": "POST"},
               nonidempotent_approval=json.dumps(approval))

    assert out["stopped_at"] is None
    assert out["verdicts"]["auth_cookie"] == "necessary"
    assert set(methods) == {"POST"}


def test_malformed_approval_is_rejected_before_anything_is_sent(monkeypatch):
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    out = _run(_confirmed_finding(), base={**_base(), "method": "POST"},
               nonidempotent_approval=json.dumps({"methods": ["POST"]}))

    assert out["stopped_at"] == "define_conditions"
    assert calls == []


def test_second_call_for_the_same_finding_is_refused(monkeypatch):
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    fid = _confirmed_finding()
    assert _run(fid)["stopped_at"] is None
    sent = len(calls)

    again = _run(fid)
    assert again["stopped_at"] == "define_conditions"
    assert "already" in again["error"]
    assert len(calls) == sent


def test_per_finding_budget_exhaustion_returns_partial_and_stops(monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "5")
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    out = _run(_confirmed_finding())

    assert out["incomplete"] is True
    assert out["stopped_at"] == "run_counterfactual"
    assert len(calls) <= 5
    assert out["untested"]  # the loop stopped; later conditions were never run


# --- a per-condition problem is recorded, not fatal ------------------------

def test_unappliable_condition_is_recorded_and_the_rest_still_run(monkeypatch):
    calls = []
    monkeypatch.setattr(srv.http_probe, "fetch", _auth_gated_fetch(calls))
    conds = [
        {"name": "not_in_request", "category": "noise", "baseline_value": "x",
         "perturbation": {"drop": True}},
        _CONDS[0],
    ]
    out = _run(_confirmed_finding(), conds=conds)

    assert "not_in_request" in out["condition_errors"]
    assert out["verdicts"] == {"auth_cookie": "necessary"}
    assert out["stopped_at"] is None


# --- hook coverage ----------------------------------------------------------

def _run_hook(monkeypatch, tool_name, tool_input):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(
        {"tool_name": tool_name, "tool_input": tool_input})))
    return hook.main()


def test_hook_gates_the_pipeline_tool_like_the_other_senders():
    assert "run_cem_pipeline" in hook.TIER2_MCP_TOOLS["case-mcp"]


def test_hook_blocks_pipeline_with_out_of_scope_url(monkeypatch):
    rc = _run_hook(monkeypatch, "mcp__case-mcp__run_cem_pipeline",
                   {"finding_id": 1, "url": f"https://{OOS}/doc/1"})
    assert rc == 2


def test_hook_allows_pipeline_with_in_scope_url(monkeypatch):
    rc = _run_hook(monkeypatch, "mcp__case-mcp__run_cem_pipeline",
                   {"finding_id": 1, "url": f"https://{IN_SCOPE}/doc/1"})
    assert rc == 0
