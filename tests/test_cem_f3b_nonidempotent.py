"""F3b / UD-4 -- non-idempotent / state-changing perturbation refusal.

THE CONTROL
-----------
CEM is controlled read-only counterfactual experimentation. A perturbation (or a
stored base_request) that resolves the outbound HTTP method to anything other
than a Phase-1 read-only verb (GET/HEAD/OPTIONS) MUST be REFUSED BY DEFAULT.
It runs only if the finding's persisted CEM state carries an explicit, structured,
method-specific `nonidempotent_approval` that lists that exact method.

This is a SEPARATE gate from:
  * E3  -- finding must be CONFIRMED/IMPACT_PROVEN, signature valid  (runs first)
  * F1  -- outbound URL must be in scope                            (runs after UD-4)
  * F2  -- engagement + per-finding request budget                  (runs after F1)

Ordering per trial in run_intervention:
  pin -> perturbation -> method_check (UD-4) -> scope_check (F1) -> budget_cb (F2) -> fetch

The authoritative method is `req.get("method", "GET")` of the fully-resolved
per-trial request -- the exact value passed to fetch_fn. Approval is persisted in
cem_meta (finding-bound), never a caller argument.

These tests drive the REAL senders / run_intervention with a fetch spy.
"""
import importlib.util
import json
import os
import sqlite3
import sys

import cem_engine
import engagement_paths
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_f3b", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)
FetchResult = srv.http_probe.FetchResult

IN = "in-scope-target.example"
OOS = "out-of-scope-evil.example"
_SIG = {"status_in": [200]}
_CONDS = [{"name": "auth_cookie", "category": "identity", "baseline_value": "p",
           "perturbation": {"drop": True}}]
_APPROVAL = {"methods": ["POST"], "reason": "confirmed CSRF needs a POST to show state change",
             "authorized_by": "operator-jdoe"}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))


@pytest.fixture
def cem(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path


def _with_engagement(tmp_path, monkeypatch, hosts=(IN,)):
    p = tmp_path / "engagement.yaml"
    body = [f"target: {hosts[0]}", "in_scope:"] + [f"  - {h}" for h in hosts] + ["out_of_scope: []", ""]
    p.write_text("\n".join(body))
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(p))


def _define(host=IN, method="GET", approval=None, no_method=False):
    """CONFIRMED finding + CEM state. Returns (finding_id, condition_id, define_result)."""
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "r", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    base = {"url": f"https://{host}/doc/1", "headers": {"Cookie": "s=1"}, "body": None}
    if not no_method:
        base["method"] = method
    kw = {"k": 3}
    if approval is not None:
        kw["nonidempotent_approval"] = approval if isinstance(approval, str) else json.dumps(approval)
    d = json.loads(srv.define_conditions(f["id"], json.dumps(base), json.dumps(_SIG),
                                         json.dumps(_CONDS), **kw))
    cid = d["condition_ids"][0] if "condition_ids" in d else None
    return f["id"], cid, d


class _Spy:
    def __init__(self):
        self.calls = []          # list of (url, method)

    def __call__(self, url, method="GET", *a, **k):
        self.calls.append((url, method))
        return FetchResult(status=200, body="", error=None)

    @property
    def methods(self):
        return [m for _, m in self.calls]


def _assert_method_refused(out, spy):
    """Refused by UD-4 -- either the sender fail-fast (no run started; no
    `incomplete`, like F1's _scope_or_error) or the per-trial gate. Either way:
    a distinct machine-readable signal, and no state-changing verb on the wire."""
    assert "error" in out, out
    assert out.get("refused") == "nonidempotent_perturbation", out
    assert all(m in ("GET", "HEAD", "OPTIONS") for m in spy.methods), spy.methods


# ======================================================================
# ENGINE -- the pure policy (fast, exhaustive matrix)
# ======================================================================

@pytest.mark.parametrize("m", ["GET", "HEAD", "OPTIONS", "get", " get ", "\tGET\n"])
def test_policy_read_only_methods_need_no_approval(m):
    assert cem_engine.check_method_allowed(m, None) is None


@pytest.mark.parametrize("m", ["POST", "PUT", "PATCH", "DELETE", "post", " delete "])
def test_policy_state_changing_methods_refused_without_approval(m):
    assert cem_engine.check_method_allowed(m, None) is not None
    assert cem_engine.check_method_allowed(m, {}) is not None


@pytest.mark.parametrize("m", ["TRACE", "CONNECT", "FOOBAR", "", "   ", "GET DELETE", "GET;DELETE"])
def test_policy_unknown_or_malformed_methods_fail_closed(m):
    # not read-only, and can never be listed in an approval -> always refused
    assert cem_engine.check_method_allowed(m, None) is not None
    assert cem_engine.check_method_allowed(
        m, {"methods": ["POST"], "reason": "r", "authorized_by": "a"}) is not None
    assert cem_engine.check_method_allowed(
        m, {"methods": [m], "reason": "r", "authorized_by": "a"}) is not None  # can't approve it


def test_policy_non_string_method_fails_closed():
    assert cem_engine.check_method_allowed(123, _APPROVAL) is not None
    assert cem_engine.check_method_allowed(None, _APPROVAL) is not None


def test_policy_valid_approval_allows_only_the_listed_method():
    ap = {"methods": ["POST"], "reason": "r", "authorized_by": "a"}
    assert cem_engine.check_method_allowed("POST", ap) is None
    assert cem_engine.check_method_allowed("post", ap) is None          # normalized
    assert cem_engine.check_method_allowed("DELETE", ap) is not None    # not listed
    assert cem_engine.check_method_allowed("PUT", ap) is not None


def test_policy_multi_method_approval():
    ap = {"methods": ["POST", "delete"], "reason": "r", "authorized_by": "a"}
    assert cem_engine.check_method_allowed("POST", ap) is None
    assert cem_engine.check_method_allowed("DELETE", ap) is None
    assert cem_engine.check_method_allowed("PATCH", ap) is not None


@pytest.mark.parametrize("bad", [
    None, {}, [], "x", 5,
    {"methods": []},
    {"methods": "POST"},
    {"methods": ["POST"]},                                   # no reason/authorized_by
    {"methods": ["POST"], "reason": "r"},                    # no authorized_by
    {"methods": ["POST"], "reason": "", "authorized_by": "a"},   # blank reason
    {"methods": ["POST"], "reason": "r", "authorized_by": "  "},  # blank authorized_by
    {"methods": ["TRACE"], "reason": "r", "authorized_by": "a"},  # non-approvable verb
    {"methods": [123], "reason": "r", "authorized_by": "a"},      # non-str entry
])
def test_policy_malformed_approval_is_treated_as_no_approval(bad):
    assert cem_engine.check_method_allowed("POST", bad) is not None


@pytest.mark.parametrize("hdr", ["X-HTTP-Method-Override", "x-http-method-override",
                                 "X-HTTP-Method", "X-Method-Override"])
def test_policy_method_override_header_makes_a_GET_state_changing(hdr):
    # a "harmless" GET that smuggles the real verb via a framework override header
    assert cem_engine.check_request_allowed("GET", {hdr: "DELETE"}, None) is not None
    assert cem_engine.check_request_allowed("GET", {hdr: "DELETE"}, _APPROVAL) is not None  # approves POST only
    assert cem_engine.check_request_allowed(
        "GET", {hdr: "DELETE"},
        {"methods": ["DELETE"], "reason": "r", "authorized_by": "a"}) is None               # explicitly authorized


def test_policy_non_override_headers_do_not_gate_a_get():
    assert cem_engine.check_request_allowed(
        "GET", {"Cookie": "s=1", "X-Requested-With": "DELETE", "X-Real-Method": "PUT"}, None) is None


def test_policy_override_header_with_a_read_only_value_is_fine():
    assert cem_engine.check_request_allowed("GET", {"X-HTTP-Method-Override": "HEAD"}, None) is None


# ======================================================================
# PERSISTENCE
# ======================================================================

def test_cem_meta_has_nonidempotent_approval_column(cem):
    _define()   # creates the schema
    conn = sqlite3.connect(str(cem / "case.db"))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(cem_meta)")}
    conn.close()
    assert "nonidempotent_approval" in cols


def test_define_persists_a_valid_approval_and_load_decodes_it(cem):
    fid, _, d = _define(method="POST", approval=_APPROVAL)
    assert "error" not in d, d
    meta = srv.case_store.cem_load_state(fid)["meta"]
    assert meta["nonidempotent_approval"] == _APPROVAL


def test_define_with_no_approval_stores_none(cem):
    fid, _, d = _define(method="GET")
    assert "error" not in d
    assert srv.case_store.cem_load_state(fid)["meta"]["nonidempotent_approval"] is None


@pytest.mark.parametrize("bad", [
    "{}", "[1,2]", "not-json", '{"methods": ["POST"]}',
    '{"methods": ["TRACE"], "reason": "r", "authorized_by": "a"}',
    '{"methods": [], "reason": "r", "authorized_by": "a"}',
])
def test_define_rejects_a_malformed_approval_and_persists_nothing(cem, bad):
    f = json.loads(srv.create_finding("IDOR", "/x"))
    srv.add_evidence("request", "r", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    base = {"method": "POST", "url": f"https://{IN}/d", "headers": {}}
    out = json.loads(srv.define_conditions(f["id"], json.dumps(base), json.dumps(_SIG),
                                           json.dumps(_CONDS), k=3, nonidempotent_approval=bad))
    assert "error" in out
    assert srv.case_store.cem_load_state(f["id"]).get("error")   # no CEM state persisted


# ======================================================================
# SENDER -- state-changing base_request method, no approval -> BLOCKED
# ======================================================================

@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_state_changing_base_method_without_approval_is_blocked(cem, tmp_path, monkeypatch, method):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method=method)
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    _assert_method_refused(out, spy)
    assert spy.calls == []                                  # zero fetches at all
    st = srv.case_store.cem_load_state(fid)
    assert st["trials"] == [] and st["verdicts"] == []
    assert not st["meta"]["incomplete"]                     # fail-fast: the run never started


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_state_changing_base_method_blocked_in_determinism_gate_too(cem, tmp_path, monkeypatch, method):
    _with_engagement(tmp_path, monkeypatch)
    fid, _, _ = _define(method=method)
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, f"https://{IN}/doc/1", k=3))
    _assert_method_refused(out, spy)
    assert srv.case_store.cem_load_state(fid)["trials"] == []


def test_confirmed_status_alone_does_not_authorize_state_change(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="POST")                    # CONFIRMED, no approval
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    _assert_method_refused(out, spy)


def test_impact_proven_status_alone_does_not_authorize_state_change(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    f = json.loads(srv.create_finding("IDOR", "/x"))
    srv.add_evidence("request", "r", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    srv.update_finding_status(f["id"], "IMPACT_PROVEN")
    base = {"method": "DELETE", "url": f"https://{IN}/d", "headers": {}}
    d = json.loads(srv.define_conditions(f["id"], json.dumps(base), json.dumps(_SIG),
                                         json.dumps(_CONDS), k=3))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(f["id"], f"https://{IN}/d", d["condition_ids"][0], k=3))
    _assert_method_refused(out, spy)


# ======================================================================
# SENDER -- with valid approval -> reaches fetch (if every other guard passes)
# ======================================================================

def test_valid_approval_lets_a_post_experiment_reach_fetch(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, d = _define(method="POST", approval=_APPROVAL)
    assert "error" not in d
    it = iter([200, 200, 200, 403, 403, 403])
    spy_urls = []
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda u, m="GET", *a, **k: (spy_urls.append((u, m)), FetchResult(next(it), "", None))[1])
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "error" not in out
    assert out["verdict"] == "necessary"
    assert len(spy_urls) == 6
    assert all(m == "POST" for _, m in spy_urls)            # the approved verb actually went out
    st = srv.case_store.cem_load_state(fid)
    assert len(st["trials"]) == 6 and len(st["verdicts"]) == 1


def test_valid_approval_preserves_normal_audit_semantics(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="POST", approval=_APPROVAL)
    logged = []
    monkeypatch.setattr(srv, "_log_call", lambda tool, args, **kw: logged.append((tool, kw.get("block"))))
    monkeypatch.setattr(srv.http_probe, "fetch", _Spy())
    srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3)
    assert logged == [("case-mcp", None)]                   # one line, no block -- approved path is normal


def test_approval_only_covers_the_listed_method(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="DELETE",
                          approval={"methods": ["POST"], "reason": "r", "authorized_by": "a"})
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    _assert_method_refused(out, spy)                        # approved POST != requested DELETE


# ======================================================================
# SENDER -- approval is finding-bound, not transferable / not caller-supplied
# ======================================================================

def test_approval_does_not_leak_to_another_finding(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    _define(method="POST", approval=_APPROVAL)                       # finding A: approved
    fid_b, cid_b, _ = _define(method="POST")                        # finding B: NOT approved
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid_b, f"https://{IN}/doc/1", cid_b, k=3))
    _assert_method_refused(out, spy)


def test_senders_have_no_approval_argument_to_smuggle(cem):
    import inspect
    for fn in (srv.run_counterfactual, srv.determinism_gate):
        params = set(inspect.signature(fn).parameters)
        assert not (params & {"approval", "nonidempotent_approval", "allow_dangerous",
                              "authorization", "authorized"}), params


def test_approval_in_the_caller_url_arg_is_ignored(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="POST")                            # no persisted approval
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(
        fid, f"https://{IN}/doc/1?nonidempotent_approval=%7B%22methods%22%3A%5B%22POST%22%5D%7D", cid, k=3))
    _assert_method_refused(out, spy)


def test_corrupted_persisted_approval_fails_closed(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="POST", approval=_APPROVAL)
    # tamper the stored approval directly in the DB -> garbage
    conn = sqlite3.connect(str(cem / "case.db"))
    conn.execute("UPDATE cem_meta SET nonidempotent_approval = ? WHERE finding_id = ?",
                 ('{"methods": ["EVERYTHING"]}', fid))
    conn.commit(); conn.close()
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    _assert_method_refused(out, spy)


# ======================================================================
# ORDERING vs E3 / F1 / F2
# ======================================================================

def test_e3_demotion_beats_the_approval(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="POST", approval=_APPROVAL)
    srv.update_finding_status(fid, "FALSE_POSITIVE")
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "error" in out and "FALSE_POSITIVE" in out["error"]      # E3, not a method refusal
    assert out.get("refused") != "nonidempotent_perturbation"
    assert spy.calls == []


def test_oos_target_with_valid_approval_is_blocked_by_scope(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)                          # OOS host not in scope
    fid, cid, _ = _define(host=OOS, method="POST", approval=_APPROVAL)
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "error" in out and "scope" in out["error"].lower()       # F1, not a method refusal
    assert spy.calls == []


def test_in_scope_approved_post_but_exhausted_budget_is_blocked_by_budget(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="POST", approval=_APPROVAL)
    monkeypatch.setattr(srv, "_enforce_cem_finding",
                        lambda _fid: (_ for _ in ()).throw(srv.BudgetExceeded("per-finding ceiling")))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "error" in out and "budget" in out["error"].lower()      # F2, not a method refusal
    assert spy.calls == []


# ======================================================================
# FUTURE PERTURBATION rewrites the method (per-trial gate)
# ======================================================================

def test_future_perturbation_that_rewrites_method_to_DELETE_is_blocked(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="GET")                             # base is GET -> fail-fast passes
    monkeypatch.setattr(srv, "_perturbation_for",
                        lambda c: (lambda req: {**req, "method": "DELETE"}))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert out.get("refused") == "nonidempotent_perturbation"
    assert out.get("incomplete") is True
    assert "DELETE" not in spy.methods                              # never sent
    st = srv.case_store.cem_load_state(fid)
    assert st["trials"] == [] and st["verdicts"] == []              # baseline arm discarded too


def test_future_perturbation_method_rewrite_allowed_with_matching_approval(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="GET",
                          approval={"methods": ["DELETE"], "reason": "r", "authorized_by": "a"})
    monkeypatch.setattr(srv, "_perturbation_for",
                        lambda c: (lambda req: {**req, "method": "DELETE"}))
    it = iter([200, 200, 200, 403, 403, 403])
    seen = []
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda u, m="GET", *a, **k: (seen.append(m), FetchResult(next(it), "", None))[1])
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "error" not in out
    assert seen == ["GET", "GET", "GET", "DELETE", "DELETE", "DELETE"]   # baseline GET, perturbed DELETE


def test_future_perturbation_that_injects_a_method_override_header_is_blocked(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="GET")                             # base GET -> fail-fast passes
    monkeypatch.setattr(srv, "_perturbation_for", lambda c: (
        lambda req: {**req, "method": "GET",
                     "headers": {**(req.get("headers") or {}), "X-HTTP-Method-Override": "DELETE"}}))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    logged = []
    monkeypatch.setattr(srv, "_log_call", lambda tool, args, **kw: logged.append(kw.get("block")))
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert out.get("refused") == "nonidempotent_perturbation" and out.get("incomplete") is True
    assert srv.case_store.cem_load_state(fid)["trials"] == []
    assert logged == ["method"]                                     # distinct audit block


def test_future_perturbation_dict_subclass_method_cannot_diverge_checked_vs_sent():
    class _Sneaky(dict):
        def __getitem__(self, k):
            if k == "method":
                return "DELETE"                                     # what a naive fetch might read
            return super().__getitem__(k)

    checked, sent = [], []

    def perturb(r):
        d = _Sneaky(r)
        dict.__setitem__(d, "method", "GET")                        # what .get() returns
        return d

    cem_engine.run_intervention(
        {"url": "https://x.example/", "method": "GET"}, cem_engine.Controls(cache_buster=False),
        perturb, 2, lambda: None, cem_engine.SuccessSignature(status_in=[200]),
        lambda u, m="GET", *a, **k: (sent.append(m), FetchResult(200, "", None))[1],
        scope_check=lambda u: None,
        method_check=lambda req: checked.append(req.get("method", "GET")),
    )
    assert checked == sent == ["GET", "GET"]                        # .get() authoritative for both


def test_method_smuggled_in_a_side_field_is_not_what_gets_checked_or_sent(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="GET")
    # perturbation keeps method=GET but hides DELETE in a bogus field
    monkeypatch.setattr(srv, "_perturbation_for",
                        lambda c: (lambda req: {**req, "method": "GET", "x_real_method": "DELETE"}))
    seen = []
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda u, m="GET", *a, **k: (seen.append(m), FetchResult(200, "", None))[1])
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "error" not in out
    assert set(seen) == {"GET"}                                     # x_real_method ignored -> GET sent


def test_engine_requires_method_check_for_a_perturbed_arm():
    with pytest.raises(TypeError):
        cem_engine.run_intervention(
            {"url": "https://x.example/", "method": "GET"}, cem_engine.Controls(cache_buster=False),
            lambda r: {**r, "method": "POST"}, 2, lambda: None,
            cem_engine.SuccessSignature(status_in=[200]),
            lambda *a, **k: FetchResult(status=200, body="", error=None),
            scope_check=lambda u: None,          # F3 present, UD-4 missing
        )


def test_engine_method_check_sees_the_resolved_request_and_runs_before_scope_and_budget():
    order = []
    cem_engine.run_intervention(
        {"url": "https://b.example/", "method": "GET"}, cem_engine.Controls(cache_buster=False),
        lambda r: {**r, "method": "PATCH"}, 2,
        lambda: order.append("budget"),
        cem_engine.SuccessSignature(status_in=[200]),
        lambda u, m="GET", *a, **k: (order.append(("fetch", m)), FetchResult(200, "", None))[1],
        scope_check=lambda u: order.append("scope"),
        method_check=lambda req: order.append(("method", req.get("method"))),
    )
    assert order == [
        ("method", "PATCH"), "scope", "budget", ("fetch", "PATCH"),
        ("method", "PATCH"), "scope", "budget", ("fetch", "PATCH"),
    ]


# ======================================================================
# ALTERNATE METHOD REPRESENTATIONS (through the real sender)
# ======================================================================

def test_lowercase_state_changing_method_still_needs_approval(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="post")                            # lowercase in the stored request
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    _assert_method_refused(out, spy)


def test_lowercase_method_matches_a_normalized_approval(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(method="post", approval=_APPROVAL)        # approval lists "POST"
    monkeypatch.setattr(srv.http_probe, "fetch", _Spy())
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "error" not in out
    assert out["verdict"] in ("necessary", "apparently_not_necessary", "inconclusive")
    assert "refused" not in out


def test_missing_method_defaults_to_GET_and_is_allowed(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, _ = _define(no_method=True)                           # base_request has no "method" key
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "error" not in out
    assert set(spy.methods) == {"GET"}


@pytest.mark.parametrize("weird", ["  ", "FOOBAR", "GET DELETE", 123, None])
def test_weird_stored_method_fails_closed(cem, tmp_path, monkeypatch, weird):
    _with_engagement(tmp_path, monkeypatch)
    f = json.loads(srv.create_finding("IDOR", "/x"))
    srv.add_evidence("request", "r", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    base = {"method": weird, "url": f"https://{IN}/d", "headers": {}}
    d = json.loads(srv.define_conditions(f["id"], json.dumps(base), json.dumps(_SIG),
                                         json.dumps(_CONDS), k=3))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(f["id"], f"https://{IN}/d", d["condition_ids"][0], k=3))
    assert "error" in out and out.get("refused") == "nonidempotent_perturbation"
    assert spy.calls == []


def test_conflicting_method_keys_last_one_wins_and_is_checked(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    f = json.loads(srv.create_finding("IDOR", "/x"))
    srv.add_evidence("request", "r", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    # raw JSON with a duplicate key -> json.loads keeps the last -> POST
    raw = '{"method": "GET", "method": "POST", "url": "https://' + IN + '/d", "headers": {}}'
    d = json.loads(srv.define_conditions(f["id"], raw, json.dumps(_SIG), json.dumps(_CONDS), k=3))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(f["id"], f"https://{IN}/d", d["condition_ids"][0], k=3))
    _assert_method_refused(out, spy)


# ======================================================================
# REGRESSION -- ordinary GET CEM is completely unaffected
# ======================================================================

def test_plain_get_cem_run_is_unchanged(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid, d = _define(method="GET")
    assert "error" not in d
    it = iter([200, 200, 200, 403, 403, 403])
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda u, m="GET", *a, **k: (None, FetchResult(next(it), "", None))[1])
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert out["verdict"] == "necessary"
    assert "refused" not in out
    assert len(srv.case_store.cem_load_state(fid)["trials"]) == 6
