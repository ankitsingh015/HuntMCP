"""F3 — CEM perturbation handling cannot invalidate the F1 scope guarantee.

THE GAP F3 CLOSES
-----------------
F1's sender-level `_scope_or_error(meta["base_request"])` checks
`meta["base_request"]["url"]`. But `cem_engine.run_intervention` actually fetches
`perturbation(controls.pin(base_request, i))["url"]` -- the URL AFTER the
per-trial pin AND after the perturbation callable. Today's only perturbation
(`{"drop": true}`) is host-preserving, so base-URL == fetched-URL host. Nothing
STRUCTURAL guaranteed that: a future / corrupted / hostile perturbation that
rewrites scheme/host/port would be fetched with no scope check on the new host.

SECURITY INVARIANT (F3)
-----------------------
The URL handed to the authoritative scope boundary is the EXACT URL passed to
`fetch_fn`, for EVERY trial of EVERY network-emitting arm -- i.e.
`perturbation(controls.pin(base, i))["url"]`, resolved first, then scope-checked,
then fetched, all within one `run_intervention` loop iteration. A perturbed arm
cannot run without a `scope_check` (engine raises `TypeError`).

These tests drive the REAL senders / `run_intervention` path with a fetch spy and
prove the boundary, not helper behaviour.
"""
import importlib.util
import json
import os
import sys

import cem_engine
import engagement_paths
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_f3", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)
FetchResult = srv.http_probe.FetchResult

IN_SCOPE = "in-scope-target.example"
IN_SCOPE_2 = "other-allowed.example"
OOS = "out-of-scope-evil.example"
_SIG = {"status_in": [200]}
_CONDS = [{"name": "auth_cookie", "category": "identity", "baseline_value": "p",
           "perturbation": {"drop": True}}]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))


@pytest.fixture
def cem(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path


def _with_engagement(tmp_path, monkeypatch, in_scope=(IN_SCOPE,)):
    p = tmp_path / "engagement.yaml"
    body = [f"target: {in_scope[0]}", "in_scope:"]
    body += [f"  - {h}" for h in in_scope]
    body += ["out_of_scope: []", ""]
    p.write_text("\n".join(body))
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(p))


def _no_engagement(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(tmp_path / "nope.yaml"))


def _confirmed(base_url, conds=None):
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "GET /doc/1", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    base = {"method": "GET", "url": base_url, "headers": {"Cookie": "s=1"}, "body": None}
    d = json.loads(srv.define_conditions(
        f["id"], json.dumps(base), json.dumps(_SIG), json.dumps(conds or _CONDS), k=3))
    assert "error" not in d, d
    return f["id"], d["condition_ids"][0]


class _FetchSpy:
    """Records every fetch. `forbid=<host substr>` turns a fetch to that host
    into a hard failure -- run_counterfactual runs the BASELINE arm first (it
    legitimately fetches the in-scope base URL), so a blocked-perturbation test
    proves the boundary by showing the FORBIDDEN host is never reached, not that
    zero fetches happen."""
    def __init__(self, *, forbid=None, status=200):
        self.calls = 0
        self.urls = []
        self._forbid = forbid
        self._status = status

    def __call__(self, url, *a, **k):
        self.calls += 1
        self.urls.append(url)
        if self._forbid and self._forbid in (url or ""):
            raise AssertionError(f"fetch reached a forbidden (out-of-scope) host: {url!r}")
        return FetchResult(status=self._status, body="", error=None)


def _perturbation_returning(new_req_or_url):
    """Monkeypatch target for srv._perturbation_for -- simulates a FUTURE
    perturbation type. If given a str, the perturbation rewrites only `url`;
    if given a callable, it becomes the perturbation directly."""
    def _factory(_condition):
        if callable(new_req_or_url):
            return new_req_or_url
        return lambda req: {**req, "url": new_req_or_url}
    return _factory


def _cem_count(tmp_path, fid):
    p = tmp_path / "budget.json"
    if not p.exists():
        return 0
    return json.load(open(p)).get("by_cem_finding", {}).get(str(fid), 0)


def _assert_blocked_incomplete(out, spy, forbidden=OOS):
    """The perturbed URL's host was never fetched; the run is a graceful
    incomplete; nothing about the perturbed arm leaked to the network."""
    assert "error" in out and "scope" in out["error"].lower(), out
    assert out.get("incomplete") is True, out
    assert not any(forbidden in (u or "") for u in spy.urls), spy.urls


# ======================================================================
# A. host-preserving perturbation ({"drop": true}) still works
# ======================================================================

def test_A_host_preserving_drop_header_in_scope_still_runs(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" not in out
    assert out["verdict"] in ("necessary", "apparently_not_necessary", "inconclusive")
    assert spy.calls == 6                          # baseline 3 + perturbed 3
    assert all(IN_SCOPE in u for u in spy.urls)
    assert srv.case_store.cem_load_state(fid)["verdicts"] != []


def test_A_host_preserving_but_oos_base_still_blocked_by_F1(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{OOS}/doc/1")
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" in out and "scope" in out["error"].lower()
    assert spy.calls == 0


# ======================================================================
# B. host-changing perturbation (simulated future type)
# ======================================================================

def test_B_perturbation_rewrites_host_to_OOS_is_blocked_before_fetch(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")            # base IN SCOPE -> F1 passes
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{OOS}/pwned"))
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    _assert_blocked_incomplete(out, spy)
    st = srv.case_store.cem_load_state(fid)
    assert st["trials"] == [] and st["verdicts"] == []
    assert bool(st["meta"]["incomplete"]) is True


def test_B_perturbation_to_another_in_scope_host_is_allowed(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch, in_scope=(IN_SCOPE, IN_SCOPE_2))
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{IN_SCOPE_2}/doc/1"))
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" not in out
    assert spy.calls == 6
    assert any(IN_SCOPE_2 in u for u in spy.urls)          # perturbed arm hit the 2nd in-scope host


def test_B_perturbation_port_only_change_same_in_scope_host_allowed(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{IN_SCOPE}:8443/doc/1"))
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" not in out and spy.calls == 6           # scope is host-based; port is not a scope dimension


def test_B_perturbation_scheme_only_change_same_in_scope_host_allowed(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"http://{IN_SCOPE}/doc/1"))
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" not in out and spy.calls == 6           # host-based policy, applied consistently


def test_B_perturbation_userinfo_at_sign_real_host_is_OOS_blocked(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{IN_SCOPE}@{OOS}/doc/1"))
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    _assert_blocked_incomplete(out, spy)


@pytest.mark.parametrize("bad", ["::::", "http://", "", "   ", "not-a-url", "///x"])
def test_B_perturbation_to_malformed_url_fails_closed(cem, tmp_path, monkeypatch, bad):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for", _perturbation_returning(bad))
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    # unsafe/ambiguous perturbed URL -> fail closed; only the in-scope baseline arm ever fetched
    assert "error" in out and out.get("incomplete") is True
    assert spy.urls and all(IN_SCOPE in u for u in spy.urls)


def test_B_perturbation_uppercase_oos_host_is_normalized_and_blocked(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"HTTPS://{OOS.upper()}/DOC"))
    spy = _FetchSpy(forbid=OOS.upper())
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    _assert_blocked_incomplete(out, spy, forbidden=OOS.upper())


def test_B_perturbation_query_fragment_only_on_in_scope_host_allowed(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{IN_SCOPE}/doc/1?x=1#frag"))
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" not in out and spy.calls == 6


# ======================================================================
# C. caller-vs-actual-target confusion
# ======================================================================

def test_C_caller_url_and_base_both_in_scope_but_perturbed_OOS_blocks(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")           # base in scope
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{OOS}/doc/1"))
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    # caller-supplied url arg ALSO in scope -- must not save the OOS perturbed URL
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/legit", cid, k=3))
    _assert_blocked_incomplete(out, spy)


# ======================================================================
# D. indirect bypass attempts -- only the fetched URL decides
# ======================================================================

def test_D_extra_in_scope_url_field_in_perturbed_dict_does_not_help(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for", _perturbation_returning(
        lambda req: {**req, "url": f"https://{OOS}/x", "aux_url": f"https://{IN_SCOPE}/x",
                     "note": f"see https://{IN_SCOPE}/ok"}))
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    _assert_blocked_incomplete(out, spy)


def test_D_in_scope_host_header_does_not_override_oos_url(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for", _perturbation_returning(
        lambda req: {**req, "url": f"https://{OOS}/x",
                     "headers": {**req.get("headers", {}), "Host": IN_SCOPE}}))
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    _assert_blocked_incomplete(out, spy)


def test_D_perturbed_dict_missing_url_key_fails_closed(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for", _perturbation_returning(
        lambda req: {"method": "GET", "headers": {}}))              # no 'url'
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" in out and out.get("incomplete") is True
    assert spy.urls and all(IN_SCOPE in u for u in spy.urls)        # perturbed (url-less) trial never fetched


# ======================================================================
# E. error / default paths -- all fail closed
# ======================================================================

def test_E_unknown_perturbation_type_is_rejected_no_fetch(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1",
                          conds=[{"name": "x", "category": "y", "baseline_value": "z",
                                  "perturbation": {"set": 1}}])          # unsupported shape
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" in out and "drop" in out["error"] and spy.calls == 0


def test_E_perturbation_raising_valueerror_midrun_is_clean_error(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")

    def _boom(_c):
        def _apply(_req):
            raise ValueError("cannot apply perturbation")
        return _apply
    monkeypatch.setattr(srv, "_perturbation_for", _boom)
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" in out
    st = srv.case_store.cem_load_state(fid)
    assert st["trials"] == [] and st["verdicts"] == []


def test_E_oos_base_with_host_changing_perturbation_blocked_by_F1_first(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{OOS}/doc/1")                    # base OOS -> F1 fires first
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{IN_SCOPE}/doc/1"))  # even a "nice" perturb
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert "error" in out and "scope" in out["error"].lower() and spy.calls == 0


def test_E_no_engagement_perturbation_to_real_oos_host_blocked(cem, tmp_path, monkeypatch):
    _no_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed("http://127.0.0.1:9/doc/1")               # base safe -> F1 passes
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{OOS}/x"))
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, "http://127.0.0.1:9/doc/1", cid, k=3))
    _assert_blocked_incomplete(out, spy)


def test_E_no_engagement_perturbation_stays_on_loopback_allowed(cem, tmp_path, monkeypatch):
    _no_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed("http://127.0.0.1:9/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning("http://127.0.0.1:9/other"))
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, "http://127.0.0.1:9/doc/1", cid, k=3))
    assert "error" not in out and spy.calls == 6


# ======================================================================
# F. network-boundary evidence (both senders) + budget non-consumption
# ======================================================================

def test_F_boundary_run_counterfactual_blocked_perturbation(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{OOS}/x"))
    spy = _FetchSpy(forbid=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    logged = []
    monkeypatch.setattr(srv, "_log_call", lambda tool, args, **kw: logged.append((tool, kw.get("block"))))
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))

    _assert_blocked_incomplete(out, spy)
    st = srv.case_store.cem_load_state(fid)
    assert st["trials"] == [] and st["verdicts"] == []
    # scope check is upstream of budget_cb: the baseline arm spent 3, the
    # perturbed arm was denied BEFORE its first budget_cb -> exactly 3, not 4+.
    assert _cem_count(tmp_path, fid) == 3
    assert len(logged) == 1 and logged[0] == ("case-mcp", "scope")   # one audit line, flagged


def test_F_boundary_determinism_gate_reaches_fetch_when_in_scope(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, _ = _confirmed(f"https://{IN_SCOPE}/doc/1")
    spy = _FetchSpy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, f"https://{IN_SCOPE}/doc/1", k=3))
    assert "error" not in out and spy.calls == 3
    assert srv.case_store.cem_load_state(fid)["trials"] != []


def test_F_boundary_in_scope_perturbation_reaches_fetch_and_records_verdict(cem, tmp_path, monkeypatch):
    _with_engagement(tmp_path, monkeypatch)
    fid, cid = _confirmed(f"https://{IN_SCOPE}/doc/1")
    monkeypatch.setattr(srv, "_perturbation_for",
                        _perturbation_returning(f"https://{IN_SCOPE}/other"))
    it = iter([200, 200, 200, 403, 403, 403])
    monkeypatch.setattr(srv.http_probe, "fetch",
                        lambda u, *a: FetchResult(status=next(it), body="", error=None))
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN_SCOPE}/doc/1", cid, k=3))
    assert out["verdict"] == "necessary"
    assert len(srv.case_store.cem_load_state(fid)["trials"]) == 6


# ======================================================================
# G. future-extensibility regression
# ======================================================================

def test_G_engine_refuses_a_perturbed_arm_with_no_scope_check():
    """A developer who adds a new perturbation and calls run_intervention without
    a scope_check must be stopped at the type level -- not silently unguarded."""
    with pytest.raises(TypeError):
        cem_engine.run_intervention(
            {"url": "https://x.example/"}, cem_engine.Controls(cache_buster=False),
            lambda r: {**r, "url": "https://evil.example/"}, 2,
            lambda: None, cem_engine.SuccessSignature(status_in=[200]),
            lambda *a, **k: FetchResult(status=200, body="", error=None),
        )


def test_G_engine_scope_check_sees_the_resolved_perturbed_url_before_fetch():
    order = []
    seen = []

    def scope_check(url):
        order.append(("scope", url)); seen.append(url)

    def fetch_fn(url, *a, **k):
        order.append(("fetch", url))
        return FetchResult(status=200, body="", error=None)

    cem_engine.run_intervention(
        {"url": "https://base.example/p"}, cem_engine.Controls(cache_buster=True),
        lambda r: {**r, "url": "https://perturbed.example/q"}, 2,
        lambda: None, cem_engine.SuccessSignature(status_in=[200]), fetch_fn,
        scope_check=scope_check, method_check=lambda m: None,
    )
    # every trial: scope_check on the PERTURBED url, immediately before its fetch
    assert seen == ["https://perturbed.example/q", "https://perturbed.example/q"]
    assert order == [
        ("scope", "https://perturbed.example/q"), ("fetch", "https://perturbed.example/q"),
        ("scope", "https://perturbed.example/q"), ("fetch", "https://perturbed.example/q"),
    ]


def test_G_engine_scope_denial_stops_the_arm_before_that_fetch():
    fetches = []

    def scope_check(url):
        if len(fetches) >= 2:
            raise srv.ScopeDenied("out of scope")

    def fetch_fn(url, *a, **k):
        fetches.append(url)
        return FetchResult(status=200, body="", error=None)

    with pytest.raises(srv.ScopeDenied):
        cem_engine.run_intervention(
            {"url": "https://base.example/"}, cem_engine.Controls(cache_buster=False),
            lambda r: r, 5, lambda: None, cem_engine.SuccessSignature(status_in=[200]),
            fetch_fn, scope_check=scope_check, method_check=lambda m: None,
        )
    assert len(fetches) == 2                       # trials 0,1 sent; trial 2 denied before fetch


def test_G_engine_scope_check_runs_before_budget_cb():
    order = []
    cem_engine.run_intervention(
        {"url": "https://base.example/"}, cem_engine.Controls(cache_buster=False),
        lambda r: r, 2,
        lambda: order.append("budget"),
        cem_engine.SuccessSignature(status_in=[200]),
        lambda *a, **k: (order.append("fetch"), FetchResult(status=200, body="", error=None))[1],
        scope_check=lambda u: order.append("scope"), method_check=lambda m: None,
    )
    assert order == ["scope", "budget", "fetch", "scope", "budget", "fetch"]


def test_G_engine_hostile_dict_subclass_cannot_diverge_checked_vs_fetched_url():
    """A perturbation returning a dict SUBCLASS whose .get('url') and ['url']
    disagree must not let the fetch go somewhere the scope check never saw.
    run_intervention resolves the outbound URL ONCE (`req.get('url')`) and uses
    that same local for both the check and the fetch."""

    class _Sneaky(dict):
        def __getitem__(self, k):
            if k == "url":
                return "https://evil.example/actual"     # what a naive fetch would use
            return super().__getitem__(k)

    checked, fetched = [], []

    def perturb(r):
        d = _Sneaky(r)
        d["_marker"] = 1                                  # keep it a real dict subclass
        dict.__setitem__(d, "url", "https://in-scope.example/decoy")  # what .get() returns
        return d

    def scope_check(url):
        checked.append(url)
        if "evil" in (url or ""):
            raise srv.ScopeDenied("blocked")

    cem_engine.run_intervention(
        {"url": "https://in-scope.example/base"}, cem_engine.Controls(cache_buster=False),
        perturb, 2, lambda: None, cem_engine.SuccessSignature(status_in=[200]),
        lambda url, *a, **k: (fetched.append(url), FetchResult(status=200, body="", error=None))[1],
        scope_check=scope_check, method_check=lambda m: None,
    )
    # the value fetched is EXACTLY the value scope-checked, every trial
    assert checked == fetched
    assert all("evil" not in u for u in fetched)
