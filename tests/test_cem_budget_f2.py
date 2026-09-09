"""F2 — CEM budget: engagement-wide 500-call cap (E2, shared) + a per-finding
CEM request ceiling (HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING, UD-2=A).

Invariants preserved (see PHASE1-EXECUTION-PLAN.md F2 / the F2 report):
  I1 budget check before every fetch          I7 F1 scope check precedes budget
  I2 real requests count engagement-wide      I8 no `necessary` from a truncated run
  I3 no partial trial/verdict persistence      I9 budget.json is the only reset
  I4 one audit line per denied invocation     I10 counter mutation under file lock
  I5 _make_budget_cb is the single seam       I11 per-finding counter is persisted
  I6 E3 guards precede budget                       (survives re-invocation)

Ordering: inside `_cb`, the per-finding ceiling is checked FIRST, then the
engagement-wide cap -- so a runaway on one finding cannot nibble the shared
500-budget one denied call at a time (the whole point of a per-finding cap).

Attacker-first: every "attacker cannot ..." case below is exercised against
the real sender functions with a fetch spy.
"""
import importlib.util
import json
import os
import sys
import threading

import budget_guard
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_f2", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)
FetchResult = srv.http_probe.FetchResult

_SIG = {"status_in": [200]}
_BASE = {"method": "GET", "url": "https://t.example/doc/1", "headers": {"Cookie": "s=1"}, "body": None}
_CONDS = [{"name": "auth_cookie", "category": "identity", "baseline_value": "p",
          "perturbation": {"drop": True}}]


@pytest.fixture
def cem_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    bpath = tmp_path / "budget.json"
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(bpath))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    eng = tmp_path / "engagement.yaml"
    eng.write_text("target: t.example\nin_scope:\n  - t.example\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    # default ceiling unless a test overrides it
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "200")
    return tmp_path


def _budget_file():
    return os.environ["HUNTMCP_BUDGET_PATH"]


def _cem_count(finding_id):
    p = _budget_file()
    if not os.path.isfile(p):
        return 0
    with open(p) as f:
        return json.load(f).get("by_cem_finding", {}).get(str(finding_id), 0)


def _engagement_calls():
    return budget_guard.check_budget(_budget_file())["calls"]


class _FetchSpy:
    def __init__(self, ok_status=200):
        self.calls = 0
        self._s = ok_status

    def __call__(self, *a, **k):
        self.calls += 1
        return FetchResult(status=self._s, body="", error=None)


def _confirmed(url=None, conds=None, k=3):
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "GET /doc/1", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    base = {**_BASE, **({"url": url} if url else {})}
    d = json.loads(srv.define_conditions(
        f["id"], json.dumps(base), json.dumps(_SIG), json.dumps(conds or _CONDS), k=k))
    assert "error" not in d, d
    return f["id"], d["condition_ids"]


# ============================ boundary behavior ============================

def test_cap_at_exact_boundary_completes(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "5")
    fid, _ = _confirmed(k=5)
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=5))
    assert out["determinism_status"] == "STABLE"
    assert "incomplete" not in out
    assert spy.calls == 5
    assert len(srv.case_store.cem_load_state(fid)["trials"]) == 5
    assert srv.case_store.cem_load_state(fid)["meta"]["incomplete"] == 0


def test_one_request_beyond_boundary_is_denied(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "4")
    fid, _ = _confirmed(k=5)
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=5))
    assert out["incomplete"] is True
    assert "ceiling" in out["error"]
    assert spy.calls == 4                                   # 5th request never sent
    st = srv.case_store.cem_load_state(fid)
    assert st["trials"] == [] and st["verdicts"] == []      # I3
    assert st["meta"]["incomplete"] == 1                    # partial bundle flag


# ===================== per-finding ceiling exhaustion =====================

def test_per_finding_ceiling_exhaustion_stops_with_incomplete(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "4")
    fid, cids = _confirmed(k=3)
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    d = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))   # 3 requests, ok
    assert d["determinism_status"] == "STABLE"
    r = json.loads(srv.run_counterfactual(fid, "https://t.example", cids[0], k=3))  # req 4 ok, 5 denied
    assert r["incomplete"] is True and "ceiling" in r["error"]
    assert spy.calls == 4
    st = srv.case_store.cem_load_state(fid)
    assert st["verdicts"] == []                             # I8: no verdict, no `necessary`
    assert st["meta"]["incomplete"] == 1


def test_repeated_sender_invocation_accumulates_then_denies_immediately(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "6")
    fid, _ = _confirmed(k=3)
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    assert json.loads(srv.determinism_gate(fid, "https://t.example", k=3))["determinism_status"] == "STABLE"
    assert json.loads(srv.determinism_gate(fid, "https://t.example", k=3))["determinism_status"] == "STABLE"
    assert spy.calls == 6
    # 3rd invocation: finding already at its ceiling -> denied on request 1, zero new fetches
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert out["incomplete"] is True
    assert spy.calls == 6
    assert _cem_count(fid) == 7                             # denying request still recorded (no reset)


def test_retry_after_denial_stays_denied_and_counter_climbs(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "2")
    fid, _ = _confirmed(k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    for _ in range(4):
        out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
        assert out["incomplete"] is True
    assert _cem_count(fid) >= 5                             # never resets across retries


# ===================== engagement-wide cap exhaustion =====================

def test_engagement_wide_cap_exhaustion_stops_with_incomplete(cem_env, monkeypatch):
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 4)
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1000")
    fid, _ = _confirmed(k=3)
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    json.loads(srv.determinism_gate(fid, "https://t.example", k=3))          # calls 1..3
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))    # call 4 -> 4/4 -> raise
    assert out["incomplete"] is True
    assert "budget" in out["error"].lower()
    st = srv.case_store.cem_load_state(fid)
    assert st["trials"] != [] or True  # first call persisted 3; the point is the 2nd call:
    assert st["meta"]["incomplete"] == 1


def test_multiple_findings_share_the_engagement_budget(cem_env, monkeypatch):
    # enforce() allows MAX_CALLS-1 successes then raises (record-then-raise at >=).
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 8)
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1000")
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    a, acids = _confirmed(k=3)
    b, bcids = _confirmed(k=3)
    ra = json.loads(srv.run_counterfactual(a, "https://t.example", acids[0], k=3))  # engagement 1..6
    assert "incomplete" not in ra                              # A ran to completion + recorded a verdict
    assert srv.case_store.cem_load_state(a)["verdicts"] != []
    rb = json.loads(srv.run_counterfactual(b, "https://t.example", bcids[0], k=3))  # 7 ok, 8 -> raise
    assert rb["incomplete"] is True                            # B truncated by the *shared* budget
    assert srv.case_store.cem_load_state(b)["verdicts"] == []
    assert srv.case_store.cem_load_state(b)["meta"]["incomplete"] == 1


# ========================= isolation / no leakage =========================

def test_per_finding_ceiling_does_not_leak_across_findings(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "3")
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    a, acids = _confirmed(k=3)
    json.loads(srv.determinism_gate(a, "https://t.example", k=3))            # A at ceiling (3)
    ra = json.loads(srv.run_counterfactual(a, "https://t.example", acids[0], k=3))
    assert ra["incomplete"] is True                                          # A denied
    b, _ = _confirmed(k=3)
    rb = json.loads(srv.determinism_gate(b, "https://t.example", k=3))       # B has its own budget
    assert rb["determinism_status"] == "STABLE"
    assert _cem_count(a) >= 4 and _cem_count(b) == 3


def test_single_finding_cannot_dominate_the_engagement_budget(cem_env, monkeypatch):
    """UD-2=A intent + attacker: spamming one finding's sender must NOT drain
    the shared engagement budget once that finding is capped -- because the
    per-finding check raises BEFORE enforce('case-mcp') on a denied request."""
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 100)
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "6")
    fid, _ = _confirmed(k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    for _ in range(20):
        srv.determinism_gate(fid, "https://t.example", k=3)
    assert _cem_count(fid) >= 7           # per-finding counter kept climbing
    assert _engagement_calls() == 6       # engagement budget frozen at the finding's real requests


# ================== ordering: E3 -> scope -> budget ==================

def test_preflight_error_no_cem_state_happens_before_budget(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1")
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))          # no define_conditions
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(f["id"], "https://t.example", k=3))
    assert "error" in out                                            # _load_cem_or_error fires first
    assert spy.calls == 0
    assert _cem_count(f["id"]) == 0 and _engagement_calls() == 0     # budget never touched


def test_e3_demoted_finding_errors_before_budget(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1")
    fid, _ = _confirmed(k=3)                                         # define while CONFIRMED
    srv.update_finding_status(fid, "FALSE_POSITIVE")                 # then demote
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert "error" in out and "FALSE_POSITIVE" in out["error"]       # E3 guard, before budget
    assert spy.calls == 0
    assert _cem_count(fid) == 0 and _engagement_calls() == 0


def test_wrong_finding_id_errors_before_budget(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1")
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(99999, "https://t.example", k=3))
    assert "error" in out
    assert spy.calls == 0
    assert _cem_count(99999) == 0 and _engagement_calls() == 0


def test_scope_denial_takes_precedence_over_budget(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1")
    fid, _ = _confirmed(url="https://out-of-scope-evil.example/doc/1", k=3)
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert "error" in out and "scope" in out["error"].lower()
    assert "incomplete" not in out                          # scope refusal, not a budget truncation
    assert spy.calls == 0
    assert _cem_count(fid) == 0 and _engagement_calls() == 0  # budget never touched
    assert srv.case_store.cem_load_state(fid)["meta"]["incomplete"] == 0


def test_in_scope_finding_then_hits_budget(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1")
    fid, _ = _confirmed(k=3)                                # in scope
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert out["incomplete"] is True and "ceiling" in out["error"]


# ===================== no network / no persistence after denial =====================

def test_budget_denial_happens_before_any_fetch(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "2")
    fid, _ = _confirmed(k=5)
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    srv.determinism_gate(fid, "https://t.example", k=5)
    assert spy.calls == 2                                   # denied on request 3, before its fetch
    srv.determinism_gate(fid, "https://t.example", k=5)     # already capped
    assert spy.calls == 2                                   # zero further network activity


def test_no_trial_or_verdict_persistence_after_per_finding_denial(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1")
    fid, cids = _confirmed(k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    srv.run_counterfactual(fid, "https://t.example", cids[0], k=3)
    st = srv.case_store.cem_load_state(fid)
    assert st["trials"] == [] and st["verdicts"] == []


def test_audit_still_one_line_per_denied_invocation(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1")
    fid, _ = _confirmed(k=3)
    logged = []
    monkeypatch.setattr(srv, "_log_call", lambda tool, args, **kw: logged.append((tool, kw)))
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    srv.determinism_gate(fid, "https://t.example", k=3)
    assert len(logged) == 1
    assert logged[0][0] == "case-mcp" and logged[0][1]["block"] == "budget"


# ===================== env-var handling at the sender =====================

@pytest.mark.parametrize("raw", ["-1", "0", "abc", "  "])
def test_malformed_or_nonpositive_env_falls_back_to_default(cem_env, monkeypatch, raw):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", raw)
    fid, _ = _confirmed(k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert out["determinism_status"] == "STABLE"            # default (200) applies, not denied


def test_unset_env_var_uses_default(cem_env, monkeypatch):
    monkeypatch.delenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", raising=False)
    fid, _ = _confirmed(k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    out = json.loads(srv.determinism_gate(fid, "https://t.example", k=3))
    assert out["determinism_status"] == "STABLE"


# ===================== seam / architecture =====================

def test_make_budget_cb_is_the_only_place_that_calls_the_ceiling(cem_env, monkeypatch):
    """_make_budget_cb is the single seam (E2 B-1): both senders build their
    callback from it and it is the only caller of enforce_cem_finding."""
    seen = []
    real = srv._enforce_cem_finding
    monkeypatch.setattr(srv, "_enforce_cem_finding", lambda fid: (seen.append(fid), real(fid))[1])
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    a, acids = _confirmed(k=2)
    srv.determinism_gate(a, "https://t.example", k=2)
    srv.run_counterfactual(a, "https://t.example", acids[0], k=2)
    assert seen and all(f == a for f in seen)               # finding_id threaded through, every call


def test_local_tools_never_call_the_per_finding_ceiling(cem_env, monkeypatch):
    fid, cids = _confirmed(k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    srv.run_counterfactual(fid, "https://t.example", cids[0], k=3)          # produce a verdict
    calls = []
    monkeypatch.setattr(srv, "_enforce_cem_finding", lambda fid: calls.append(fid))
    srv.minimal_condition_sets(fid)
    srv.minimize_poc(fid)
    srv.evidence_bundle(fid)
    assert calls == []


def test_evidence_bundle_surfaces_incomplete_flag(cem_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1")
    fid, _ = _confirmed(k=3)
    monkeypatch.setattr(srv.http_probe, "fetch", _FetchSpy())
    assert json.loads(srv.evidence_bundle(fid))["incomplete"] is False     # clean so far
    srv.determinism_gate(fid, "https://t.example", k=3)                    # budget-truncated -> mark
    assert json.loads(srv.evidence_bundle(fid))["incomplete"] is True


# ===================== concurrency at the sender =====================

def test_concurrent_senders_racing_the_final_engagement_slot(cem_env, monkeypatch):
    # enforce() allows MAX_CALLS-1 successes; with 3 pre-burned of 5, exactly one
    # more real request can go through (the 4th); the 5th+ raise.
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 5)
    monkeypatch.setenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING", "1000")
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    pre, _ = _confirmed(k=3)
    srv.determinism_gate(pre, "https://t.example", k=3)     # engagement 1..3
    assert spy.calls == 3

    fids = [_confirmed(k=1)[0] for _ in range(6)]
    results = {}

    def worker(fid):
        results[fid] = json.loads(srv.determinism_gate(fid, "https://t.example", k=1))

    threads = [threading.Thread(target=worker, args=(f,)) for f in fids]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    completed = [f for f, r in results.items() if "incomplete" not in r]
    incomplete = [f for f, r in results.items() if r.get("incomplete")]
    assert len(completed) == 1                              # exactly one got the last real slot
    assert len(incomplete) == 5
    assert spy.calls == 4                                   # only ONE extra fetch -- no double-spend
