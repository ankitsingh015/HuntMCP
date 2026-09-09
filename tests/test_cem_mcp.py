"""E1 smoke tests: the 6 CEM MCP tool wrappers in case-mcp/server.py are
registered and delegate to cem_engine + case_store (PHASE1-EXECUTION-PLAN.md
task E1; verify = "import + smoke test"). No real network -- http_probe.fetch is
monkeypatched on the loaded server module. Budget/audit (E2), CONFIRMED/UD-3
guards (E3), scope gating (F1) and content-addressed evidence (G1) are later
tasks and are NOT asserted here.
"""
import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# case-mcp/server.py does `import case_store / cem_engine / http_probe` relative
# to mcp-servers/ -- add it explicitly (a directly-run script would get this for
# free via sys.path[0]).
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

FetchResult = srv.http_probe.FetchResult

_SIG = {"status_in": [200]}
_BASE_REQ = {"method": "GET", "url": "https://t.example/doc/1",
             "headers": {"Cookie": "sid=abc"}, "body": None}
_CONDS = [
    {"name": "auth_cookie", "category": "identity", "baseline_value": "present",
     "perturbation": {"drop": True}},
    {"name": "trace", "category": "noise", "baseline_value": "1",
     "perturbation": {"drop": True}},
]


@pytest.fixture
def cem_db(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    # E2 wired the senders to budget_guard.enforce / audit_log.log_call -- isolate
    # those per-test too so the smoke tests don't bump the real Tier-2 budget or
    # append to the real audit log.
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    # F1/SEC-1: the senders now scope-check base_request["url"] (the URL
    # run_intervention actually fetches) against the active engagement via
    # scope_guard -- so the smoke tests need an engagement in whose scope the
    # test host (t.example) sits. Same class of per-test-isolation fix E2 made
    # when it wired in budget/audit; the assertions below are unchanged.
    eng = tmp_path / "engagement.yaml"
    eng.write_text("target: t.example\nin_scope:\n  - t.example\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    return tmp_path


def _fake_fetch(*statuses):
    it = iter(statuses)

    def _f(url, method, headers, body, timeout_s):
        s = next(it)
        return FetchResult(status=s, body="", error=None) if s is not None else \
            FetchResult(status=None, body="", error="boom")

    return _f


def _confirmed_finding():
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "GET /doc/1", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    return f["id"]


# --- registration -----------------------------------------------------------

def test_all_six_cem_tools_exist_and_are_callable():
    for name in ("define_conditions", "determinism_gate", "run_counterfactual",
                 "minimal_condition_sets", "minimize_poc", "evidence_bundle"):
        assert callable(getattr(srv, name)), name


def test_module_imports_cem_engine_and_http_probe():
    assert srv.cem_engine.__name__ == "cem_engine"
    assert srv.http_probe.__name__ == "http_probe"


# --- define_conditions ----------------------------------------------------

def test_define_conditions_delegates_to_case_store(cem_db):
    fid = _confirmed_finding()
    out = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                           json.dumps(_CONDS), k=5))
    assert "error" not in out
    assert len(out["condition_ids"]) == 2


def test_define_conditions_bad_json_is_a_clean_error(cem_db):
    fid = _confirmed_finding()
    out = json.loads(srv.define_conditions(fid, "not-json", json.dumps(_SIG), json.dumps(_CONDS)))
    assert "error" in out


def test_define_conditions_empty_signature_rejected_by_store(cem_db):
    fid = _confirmed_finding()
    out = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), "{}", json.dumps(_CONDS)))
    assert "error" in out  # UD-3 enforced at the persistence layer (B2)


# --- determinism_gate (sender) ------------------------------------------------

def test_determinism_gate_stable(cem_db, monkeypatch):
    fid = _confirmed_finding()
    srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG), json.dumps(_CONDS), k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200, 200))
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert out["determinism_status"] == "STABLE"
    assert out["hits"] == [True, True, True]
    # trials were persisted
    state = srv.case_store.cem_load_state(fid)
    assert len([t for t in state["trials"] if t["arm"] == "baseline"]) == 3


def test_determinism_gate_nondeterministic_on_mixed(cem_db, monkeypatch):
    fid = _confirmed_finding()
    srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG), json.dumps(_CONDS), k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 403, 200))
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert out["determinism_status"] == "NONDETERMINISTIC"


def test_determinism_gate_unknown_finding(cem_db):
    out = json.loads(srv.determinism_gate(99999, "https://t.example", k=3))
    assert "error" in out


# --- run_counterfactual (sender) --------------------------------------------

def test_run_counterfactual_necessary(cem_db, monkeypatch):
    fid = _confirmed_finding()
    defined = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                               json.dumps(_CONDS), k=3))
    cond_id = defined["condition_ids"][0]  # auth_cookie
    # baseline 200x3 (HIT), perturbed 403x3 (MISS) -> necessary
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200, 200, 403, 403, 403))
    out = json.loads(srv.run_counterfactual(fid, "https://t.example", cond_id, k=3))
    assert out["verdict"] == "necessary"
    assert out["baseline_hits"] == [True, True, True]
    assert out["perturbed_hits"] == [False, False, False]
    state = srv.case_store.cem_load_state(fid)
    assert len(state["trials"]) == 6
    assert len(state["verdicts"]) == 1
    assert state["verdicts"][0]["verdict"] == "necessary"


def test_run_counterfactual_apparently_not_necessary(cem_db, monkeypatch):
    fid = _confirmed_finding()
    base_with_trace = {**_BASE_REQ, "url": "https://t.example/doc/1?trace=1"}
    defined = json.loads(srv.define_conditions(fid, json.dumps(base_with_trace), json.dumps(_SIG),
                                               json.dumps(_CONDS), k=3))
    trace_id = defined["condition_ids"][1]  # the `trace` query-param condition
    # dropping `trace` never changes the oracle -> both arms all-HIT
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(*([200] * 6)))
    out = json.loads(srv.run_counterfactual(fid, "https://t.example", trace_id, k=3))
    assert out["verdict"] == "apparently_not_necessary"


def test_run_counterfactual_429_forces_inconclusive(cem_db, monkeypatch):
    fid = _confirmed_finding()
    defined = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                               json.dumps(_CONDS), k=3))
    cond_id = defined["condition_ids"][0]
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200, 200, 200, 429, 200))
    out = json.loads(srv.run_counterfactual(fid, "https://t.example", cond_id, k=3))
    assert out["verdict"] == "inconclusive"


def test_run_counterfactual_unsupported_perturbation(cem_db, monkeypatch):
    fid = _confirmed_finding()
    conds = [{"name": "x", "category": "y", "baseline_value": "z", "perturbation": {"set": 1}}]
    defined = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                               json.dumps(conds), k=3))
    out = json.loads(srv.run_counterfactual(fid, "https://t.example", defined["condition_ids"][0], k=3))
    assert "error" in out and "drop" in out["error"]


def test_run_counterfactual_unknown_condition(cem_db, monkeypatch):
    fid = _confirmed_finding()
    srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG), json.dumps(_CONDS), k=3)
    out = json.loads(srv.run_counterfactual(fid, "https://t.example", 99999, k=3))
    assert "error" in out


# --- minimal_condition_sets / minimize_poc / evidence_bundle ----------------

def test_minimal_condition_sets_needs_a_necessary_verdict_first(cem_db):
    fid = _confirmed_finding()
    srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG), json.dumps(_CONDS), k=3)
    out = json.loads(srv.minimal_condition_sets(fid))
    assert "error" in out


def test_minimal_condition_sets_after_run_counterfactual(cem_db, monkeypatch):
    fid = _confirmed_finding()
    defined = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                               json.dumps(_CONDS), k=3))
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200, 200, 403, 403, 403))
    srv.run_counterfactual(fid, "https://t.example", defined["condition_ids"][0], k=3)
    out = json.loads(srv.minimal_condition_sets(fid))
    assert "error" not in out
    assert out["minimal_sets"] == [["auth_cookie"]]


def test_minimize_poc_runs(cem_db, monkeypatch):
    fid = _confirmed_finding()
    defined = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                               json.dumps(_CONDS), k=3))
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200, 200, 403, 403, 403))
    srv.run_counterfactual(fid, "https://t.example", defined["condition_ids"][0], k=3)
    out = json.loads(srv.minimize_poc(fid))
    assert "error" not in out
    assert out["poc"] == ["auth_cookie"]


def test_evidence_bundle_assembles_from_state(cem_db, monkeypatch):
    fid = _confirmed_finding()
    defined = json.loads(srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG),
                                               json.dumps(_CONDS), k=3))
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200, 200, 403, 403, 403))
    srv.run_counterfactual(fid, "https://t.example", defined["condition_ids"][0], k=3)
    bundle = json.loads(srv.evidence_bundle(fid))
    assert bundle["finding_id"] == fid
    assert "verdict_labels" in bundle
    assert bundle["verdict_labels"]["auth_cookie"] == "necessary"
    assert "complete_audit_trail" in bundle


def test_evidence_bundle_unknown_finding(cem_db):
    out = json.loads(srv.evidence_bundle(99999))
    assert "error" in out
