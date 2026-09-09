"""E2 safety tests: the two CEM senders (determinism_gate, run_counterfactual)
enforce the Tier-2 budget per real request and write one audit line per tool
call, exactly like idor-mcp/server.py (PHASE1-EXECUTION-PLAN.md task E2;
verify: test_cem_safety.py). Scope gating (F1), the per-finding request ceiling
(F2) and non-idempotent-perturbation refusal (F3) are later tasks and are NOT
asserted here.
"""
import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_e2", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

FetchResult = srv.http_probe.FetchResult
BudgetExceeded = srv.BudgetExceeded

_SIG = {"status_in": [200]}
_BASE_REQ = {"method": "GET", "url": "https://t.example/doc/1",
             "headers": {"Cookie": "sid=abc"}, "body": None}
_CONDS = [{"name": "auth_cookie", "category": "identity", "baseline_value": "present",
          "perturbation": {"drop": True}}]


@pytest.fixture
def cem_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    # F1/SEC-1: the senders now scope-check base_request["url"] before sending.
    # Give the tests an engagement whose in_scope covers the test host
    # (t.example) -- a per-test-isolation fix forced by the new check, not a
    # weakening (every assertion below is unchanged).
    eng = tmp_path / "engagement.yaml"
    eng.write_text("target: t.example\nin_scope:\n  - t.example\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    return tmp_path


def _ok_fetch(*a):
    return FetchResult(status=200, body="", error=None)


def _fake_fetch(*statuses):
    it = iter(statuses)

    def _f(url, method, headers, body, timeout_s):
        s = next(it)
        return FetchResult(status=s, body="", error=None) if s is not None else \
            FetchResult(status=None, body="", error="boom")

    return _f


def _confirmed_with_conditions(k=3):
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "GET /doc/1", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    d = json.loads(srv.define_conditions(f["id"], json.dumps(_BASE_REQ), json.dumps(_SIG),
                                         json.dumps(_CONDS), k=k))
    return f["id"], d["condition_ids"][0]


# --- budget: per real request ---------------------------------------------

def test_determinism_gate_enforces_budget_once_per_request(cem_env, monkeypatch):
    fid, _ = _confirmed_with_conditions(k=3)
    seen = []
    monkeypatch.setattr(srv, "_enforce_budget", lambda name: seen.append(name))
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: None)
    monkeypatch.setattr(srv.http_probe, "fetch", _ok_fetch)
    srv.determinism_gate(fid, "https://t.example", k=3)
    assert seen == ["case-mcp", "case-mcp", "case-mcp"]  # one per trial/request


def test_run_counterfactual_enforces_budget_once_per_request(cem_env, monkeypatch):
    fid, cid = _confirmed_with_conditions(k=3)
    seen = []
    monkeypatch.setattr(srv, "_enforce_budget", lambda name: seen.append(name))
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: None)
    monkeypatch.setattr(srv.http_probe, "fetch", _ok_fetch)
    srv.run_counterfactual(fid, "https://t.example", cid, k=3)
    assert seen == ["case-mcp"] * 6  # baseline arm (3) + perturbed arm (3)


def test_budget_is_enforced_before_the_fetch(cem_env, monkeypatch):
    fid, _ = _confirmed_with_conditions(k=3)
    fetched = []

    def _boom(name):
        raise BudgetExceeded("cap")

    monkeypatch.setattr(srv, "_enforce_budget", _boom)
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: None)
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda *a: (fetched.append(1), _ok_fetch())[1])
    srv.determinism_gate(fid, "https://t.example", k=3)
    assert fetched == []  # budget check comes first -- no request was sent


# --- audit: one line per tool call --------------------------------------------

def test_determinism_gate_audits_once_per_call(cem_env, monkeypatch):
    fid, _ = _confirmed_with_conditions(k=3)
    logged = []
    monkeypatch.setattr(srv, "_enforce_budget", lambda name: None)
    monkeypatch.setattr(srv, "_log_call", lambda tool, args, **kw: logged.append((tool, args, kw)))
    monkeypatch.setattr(srv.http_probe, "fetch", _ok_fetch)
    srv.determinism_gate(fid, "https://t.example", k=3)
    assert len(logged) == 1
    tool, args, kw = logged[0]
    assert tool == "case-mcp"
    assert any("determinism_gate" in str(a) for a in args)
    assert any("https://t.example" in str(a) for a in args)
    assert "duration_ms" in kw


def test_run_counterfactual_audits_once_per_call(cem_env, monkeypatch):
    fid, cid = _confirmed_with_conditions(k=3)
    logged = []
    monkeypatch.setattr(srv, "_enforce_budget", lambda name: None)
    monkeypatch.setattr(srv, "_log_call", lambda tool, args, **kw: logged.append((tool, args)))
    monkeypatch.setattr(srv.http_probe, "fetch", _ok_fetch)
    srv.run_counterfactual(fid, "https://t.example", cid, k=3)
    assert len(logged) == 1
    assert logged[0][0] == "case-mcp"
    assert any("run_counterfactual" in str(a) for a in logged[0][1])


# --- budget exhaustion is handled, not crashed --------------------------------

def test_determinism_gate_budget_exhaustion_persists_nothing_and_stops_sending(cem_env, monkeypatch):
    # T-2: on a denied budget check, prove (a) no trials persisted, (b) no
    # network execution after the denial, (c) audit line still written & flagged.
    fid, _ = _confirmed_with_conditions(k=5)
    calls, logged, fetched = [], [], []

    def _budget(name):
        calls.append(name)
        if len(calls) == 3:  # deny the 3rd request
            raise BudgetExceeded("Tier-2 tool-call budget exceeded")

    monkeypatch.setattr(srv, "_enforce_budget", _budget)
    monkeypatch.setattr(srv, "_log_call", lambda tool, args, **kw: logged.append(kw))
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda *a: (fetched.append(1), _ok_fetch())[1])

    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=5))

    assert "error" in out and "budget" in out["error"].lower()
    assert out["incomplete"] is True
    assert len(fetched) == 2                       # only the 2 requests that passed the check ran
    state = srv.case_store.cem_load_state(fid)
    assert state["trials"] == []                   # nothing persisted
    assert state["verdicts"] == []
    assert len(logged) == 1 and logged[0]["block"] == "budget"   # audited, flagged


def test_run_counterfactual_budget_exhaustion_persists_nothing_and_stops_sending(cem_env, monkeypatch):
    # T-2: same guarantees for the counterfactual sender -- denial partway through
    # the perturbed arm must leave zero trials, zero verdicts, and send nothing
    # further.
    fid, cid = _confirmed_with_conditions(k=5)
    calls, fetched = [], []

    def _budget(name):
        calls.append(name)
        if len(calls) == 4:  # 1st request of the perturbed arm (baseline arm = calls 1-3)
            raise BudgetExceeded("cap")

    monkeypatch.setattr(srv, "_enforce_budget", _budget)
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: None)
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda *a: (fetched.append(1), _ok_fetch())[1])

    out = json.loads(srv.run_counterfactual(fid, "https://t.example", cid, k=5))

    assert "error" in out and out["incomplete"] is True
    assert len(fetched) == 3                       # baseline arm ran; perturbed arm never sent
    state = srv.case_store.cem_load_state(fid)
    assert state["trials"] == []                   # baseline arm's completed trials NOT persisted
    assert state["verdicts"] == []                 # no verdict on an incomplete run (F2 refines partial)


def test_budget_callback_factory_is_the_single_extension_point_for_both_senders(cem_env, monkeypatch):
    # B-1: F2 will add a per-finding request ceiling inside _make_budget_cb.
    # Prove both senders build their budget callback from that one factory, that
    # finding_id reaches it, and that a stricter callback from the factory is
    # honoured by both -- so F2 is a factory-body change, not a per-sender edit.
    seen_fids = []

    def _factory(finding_id):
        seen_fids.append(finding_id)

        def _cb():
            raise BudgetExceeded("per-finding ceiling (simulated F2)")

        return _cb

    monkeypatch.setattr(srv, "_make_budget_cb", _factory)
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: None)
    monkeypatch.setattr(srv.http_probe, "fetch", _ok_fetch)

    fid, cid = _confirmed_with_conditions(k=3)
    d = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    r = json.loads(srv.run_counterfactual(fid, "https://t.example", cid, k=3))

    # both senders picked up the stricter callback from the one factory, and
    # finding_id reached it -- with no per-sender edit
    assert d["incomplete"] is True and "ceiling" in d["error"]
    assert r["incomplete"] is True and "ceiling" in r["error"]
    assert seen_fids and all(f == fid for f in seen_fids)   # finding_id threaded through, every time
    assert seen_fids == [fid, fid]   # determinism_gate's arm + run_counterfactual's 1st arm (it bails)
    assert srv.case_store.cem_load_state(fid)["trials"] == []
    assert srv.case_store.cem_load_state(fid)["verdicts"] == []


# --- local tools neither enforce budget nor audit ---------------------------

def test_local_tools_do_not_enforce_budget_or_audit(cem_env, monkeypatch):
    fid, cid = _confirmed_with_conditions(k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _ok_fetch)
    srv.run_counterfactual(fid, "https://t.example", cid, k=3)  # produce a verdict first

    budget_calls, audit_calls = [], []
    monkeypatch.setattr(srv, "_enforce_budget", lambda name: budget_calls.append(name))
    monkeypatch.setattr(srv, "_log_call", lambda *a, **k: audit_calls.append(1))

    fid2, _ = _confirmed_with_conditions(k=3)          # define_conditions (local)
    srv.minimal_condition_sets(fid)
    srv.minimize_poc(fid)
    srv.evidence_bundle(fid2)
    assert budget_calls == []
    assert audit_calls == []


# --- E3: CONFIRMED-state + success_signature guards -------------------------
# define_conditions + both senders refuse a finding not in CONFIRMED/IMPACT_PROVEN
# state; define_conditions refuses a missing/invalid success_signature (UD-3 --
# never derived). The 3 local assemblers are NOT gated (they only read vetted
# state). Human-approved 2026-09-07 via AskUserQuestion.

def _bare_finding(status=None):
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    if status in ("CONFIRMED", "IMPACT_PROVEN"):
        srv.add_evidence("request", "GET /doc/1", finding_id=f["id"])
        srv.update_finding_status(f["id"], "CONFIRMED")
        if status == "IMPACT_PROVEN":
            srv.update_finding_status(f["id"], "IMPACT_PROVEN")
    elif status:
        srv.update_finding_status(f["id"], status)
    return f["id"]


def test_define_conditions_refuses_a_non_confirmed_finding(cem_env):
    fid = _bare_finding()  # DISCOVERED
    out = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                           json.dumps(_CONDS), k=3))
    assert "error" in out and "CONFIRMED" in out["error"]
    assert srv.case_store.cem_load_state(fid).get("error")  # nothing persisted


def test_define_conditions_accepts_impact_proven_finding(cem_env):
    fid = _bare_finding("IMPACT_PROVEN")
    out = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                           json.dumps(_CONDS), k=3))
    assert "error" not in out and len(out["condition_ids"]) == 1


def test_define_conditions_refuses_invalid_success_signature_shape(cem_env):
    fid = _bare_finding("CONFIRMED")
    out = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ),
                                           json.dumps({"bogus_key": 1}), json.dumps(_CONDS), k=3))
    assert "error" in out
    assert "success_signature" in out["error"]
    assert srv.case_store.cem_load_state(fid).get("error")  # not persisted, not derived


def test_define_conditions_refuses_success_signature_that_is_not_an_object(cem_env):
    fid = _bare_finding("CONFIRMED")
    out = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ),
                                           json.dumps([1, 2]), json.dumps(_CONDS), k=3))
    assert "error" in out and "success_signature" in out["error"]


def test_determinism_gate_refuses_a_finding_no_longer_confirmed(cem_env, monkeypatch):
    fid = _bare_finding("CONFIRMED")
    srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG), json.dumps(_CONDS), k=3)
    srv.update_finding_status(fid, "FALSE_POSITIVE")  # status changed after define
    fetched = []
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a: (fetched.append(1), _ok_fetch())[1])
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert "error" in out and "FALSE_POSITIVE" in out["error"]
    assert fetched == []  # refused before any request


def test_run_counterfactual_refuses_a_finding_no_longer_confirmed(cem_env, monkeypatch):
    fid = _bare_finding("CONFIRMED")
    d = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                         json.dumps(_CONDS), k=3))
    srv.update_finding_status(fid, "DUPLICATE")
    fetched = []
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a: (fetched.append(1), _ok_fetch())[1])
    out = json.loads(srv.run_counterfactual(fid, "https://t.example", d["condition_ids"][0], k=3))
    assert "error" in out and "DUPLICATE" in out["error"]
    assert fetched == []


def test_local_assemblers_are_not_gated_on_confirmed_state(cem_env, monkeypatch):
    fid = _bare_finding("CONFIRMED")
    d = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                         json.dumps(_CONDS), k=3))
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200, 200, 403, 403, 403))
    srv.run_counterfactual(fid, "https://t.example", d["condition_ids"][0], k=3)
    srv.update_finding_status(fid, "FALSE_POSITIVE")  # demoted after the verdict was recorded
    # local assemblers still operate on the already-recorded, vetted CEM state
    assert "error" not in json.loads(srv.minimal_condition_sets(fid))
    assert "error" not in json.loads(srv.minimize_poc(fid))
    b = json.loads(srv.evidence_bundle(fid))
    assert b["finding_id"] == fid
