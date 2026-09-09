"""G1 — system-level adversarial integration review of the complete CEM Phase-1
control stack (E3 -> UD-4 -> F1 -> F2 -> run_intervention -> fetch).

These tests attack the COMPOSITION: cross-control ordering, first-authoritative-
denial + no-later-side-effect, evidence integrity under truncation, alternate
paths to fetch_fn, and concurrency. Everything drives the REAL case-mcp tools /
run_intervention with a recording fetch spy; assertions are on actual fetch
URLs/methods/counts, persisted trials/verdicts, cem_meta.incomplete, the audit
block, and the budget counters -- not implementation details.
"""
import importlib.util
import json
import os
import sqlite3
import sys
import threading

import engagement_paths
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_g1", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)
FetchResult = srv.http_probe.FetchResult

IN = "in-scope-target.example"
OOS = "out-of-scope-evil.example"
_SIG = {"status_in": [200]}
_CONDS = [{"name": "auth_cookie", "category": "identity", "baseline_value": "p",
           "perturbation": {"drop": True}}]
_APPROVAL = {"methods": ["POST"], "reason": "confirmed CSRF", "authorized_by": "op-jdoe"}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))


@pytest.fixture
def cem(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path


def _engagement(tmp_path, monkeypatch, hosts=(IN,)):
    p = tmp_path / "engagement.yaml"
    lines = [f"target: {hosts[0]}", "in_scope:"] + [f"  - {h}" for h in hosts] + ["out_of_scope: []", ""]
    p.write_text("\n".join(lines))
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(p))


def _define(host=IN, method="GET", approval=None, status="CONFIRMED",
            base_overrides=None, conds=None):
    """CONFIRMED finding + CEM state. Returns (finding_id, condition_id)."""
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "r", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    if status == "IMPACT_PROVEN":
        srv.update_finding_status(f["id"], "IMPACT_PROVEN")
    base = {"method": method, "url": f"https://{host}/doc/1", "headers": {"Cookie": "s=1"}, "body": None}
    if base_overrides:
        base.update(base_overrides)
    kw = {"k": 3}
    if approval is not None:
        kw["nonidempotent_approval"] = json.dumps(approval)
    d = json.loads(srv.define_conditions(f["id"], json.dumps(base), json.dumps(_SIG),
                                         json.dumps(conds or _CONDS), **kw))
    assert "error" not in d, d
    if status not in ("CONFIRMED", "IMPACT_PROVEN"):
        srv.update_finding_status(f["id"], status)
    return f["id"], d["condition_ids"][0]


class _Spy:
    def __init__(self, statuses=None):
        self.calls = []                       # (url, method)
        self._it = iter(statuses) if statuses else None

    def __call__(self, url, method="GET", *a, **k):
        self.calls.append((url, method))
        s = next(self._it) if self._it else 200
        return FetchResult(status=s, body="", error=None)

    @property
    def methods(self):
        return [m for _, m in self.calls]

    @property
    def hosts(self):
        return [u.split("/")[2] for u in (u for u, _ in self.calls)]


def _state(fid):
    return srv.case_store.cem_load_state(fid)


def _budget(tmp_path):
    p = tmp_path / "budget.json"
    return json.load(open(p)) if p.exists() else {}


def _no_side_effects(fid, spy, tmp_path, *, allow_fetch_hosts=()):
    """A denial produced NOTHING dangerous or misleading downstream."""
    st = _state(fid)
    assert st["trials"] == [], f"trials persisted after denial: {st['trials']}"
    assert st["verdicts"] == [], f"verdict persisted after denial: {st['verdicts']}"
    for h in spy.hosts:
        assert h in allow_fetch_hosts, f"fetch reached {h!r} (allowed: {allow_fetch_hosts})"
    for m in spy.methods:
        assert m in ("GET", "HEAD", "OPTIONS"), f"state-changing method on the wire: {m}"


# ======================================================================
# CROSS-CONTROL: first authoritative denial + no later side effect
# (task 3.G scenarios 1-6, plus the A-F pair interactions)
# ======================================================================

def test_G_scenario1_false_positive_beats_everything(cem, tmp_path, monkeypatch):
    # FALSE_POSITIVE + OOS + POST + budget available -> E3 denies first, nothing else runs
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=OOS, method="POST", approval=_APPROVAL, status="FALSE_POSITIVE")
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "FALSE_POSITIVE" in out["error"]                    # E3
    assert "refused" not in out and "scope" not in out["error"].lower()
    assert spy.calls == []
    _no_side_effects(fid, spy, tmp_path)
    assert _budget(tmp_path).get("by_cem_finding", {}) == {}   # no budget touched


def test_G_scenario2_confirmed_oos_post_budget_avail_scope_denies(cem, tmp_path, monkeypatch):
    # CONFIRMED + valid sig + OOS + POST + valid approval + budget -> UD-4 passes, F1 denies
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=OOS, method="POST", approval=_APPROVAL)
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "scope" in out["error"].lower() and "refused" not in out   # F1, not UD-4
    assert spy.calls == []
    _no_side_effects(fid, spy, tmp_path)
    assert _budget(tmp_path).get("by_cem_finding", {}) == {}


def test_G_scenario3_confirmed_inscope_post_no_approval_ud4_denies(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=IN, method="POST")                 # in scope, but no approval
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert out["refused"] == "nonidempotent_perturbation"      # UD-4
    assert spy.calls == []
    _no_side_effects(fid, spy, tmp_path)
    assert _budget(tmp_path).get("by_cem_finding", {}) == {}   # UD-4 fail-fast is before budget


def test_G_scenario4_all_pass_but_budget_exhausted(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=IN, method="POST", approval=_APPROVAL)
    monkeypatch.setattr(srv, "_enforce_cem_finding",
                        lambda _f: (_ for _ in ()).throw(srv.BudgetExceeded("per-finding ceiling")))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "budget" in out["error"].lower() and out["incomplete"] is True
    assert spy.calls == []                                     # budget check precedes fetch
    _no_side_effects(fid, spy, tmp_path)
    assert bool(_state(fid)["meta"]["incomplete"]) is True     # honestly marked incomplete


def test_G_scenario5_invalid_signature_beats_scope_and_ud4(cem, tmp_path, monkeypatch):
    # CONFIRMED + invalid stored signature + OOS + POST -> E3b (signature) denies first
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=OOS, method="POST", approval=_APPROVAL)
    # corrupt the persisted signature to an unparseable shape
    conn = sqlite3.connect(str(cem / "case.db"))
    conn.execute("UPDATE cem_meta SET success_signature = ? WHERE finding_id = ?",
                 (json.dumps({"bogus_key": 1}), fid))
    conn.commit(); conn.close()
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert "signature" in out["error"].lower()
    assert "scope" not in out["error"].lower() and "refused" not in out
    assert spy.calls == []
    _no_side_effects(fid, spy, tmp_path)


def test_G_scenario6_valid_everything_get_runs_and_records(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=IN, method="GET")
    spy = _Spy(statuses=[200, 200, 200, 403, 403, 403])
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    logged = []
    monkeypatch.setattr(srv, "_log_call", lambda t, a, **kw: logged.append(kw.get("block")))
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert out["verdict"] == "necessary" and "incomplete" not in out and "refused" not in out
    assert len(spy.calls) == 6 and set(spy.methods) == {"GET"} and set(spy.hosts) == {IN}
    st = _state(fid)
    assert len(st["trials"]) == 6 and len(st["verdicts"]) == 1
    assert not st["meta"]["incomplete"]
    assert logged == [None]                                    # one audit line, no block


# ---- pairwise: E3 x F2 (no budget spent before an E3 rejection) ----

def test_G_E3xF2_demoted_finding_spends_no_budget(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(status="FALSE_POSITIVE")
    monkeypatch.setattr(srv.http_probe, "fetch", _Spy())
    srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3)
    srv.determinism_gate(fid, f"https://{IN}/doc/1", k=3)
    assert _budget(tmp_path).get("calls", 0) == 0
    assert _budget(tmp_path).get("by_cem_finding", {}) == {}


# ---- pairwise: F1 x F2 (OOS must not consume budget; retry after denial) ----

def test_G_F1xF2_oos_never_consumes_budget_even_on_retry(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=OOS)
    monkeypatch.setattr(srv.http_probe, "fetch", _Spy())
    for _ in range(5):
        out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
        assert "scope" in out["error"].lower()
    assert _budget(tmp_path).get("calls", 0) == 0
    assert _budget(tmp_path).get("by_cem_finding", {}) == {}


# ======================================================================
# EVIDENCE INTEGRITY
# ======================================================================

def test_G_evidence_denied_perturbation_discards_the_completed_baseline_arm(cem, tmp_path, monkeypatch):
    """The baseline arm runs to completion (real GETs go out), THEN the perturbed
    arm's first trial is method-refused. The completed baseline arm must NOT be
    persisted -- no half-experiment masquerading as evidence."""
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=IN, method="GET")
    monkeypatch.setattr(srv, "_perturbation_for",
                        lambda c: (lambda req: {**req, "method": "DELETE"}))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert out["refused"] == "nonidempotent_perturbation" and out["incomplete"] is True
    assert spy.methods == ["GET", "GET", "GET"]                # baseline arm did run
    assert "DELETE" not in spy.methods                         # perturbed method never sent
    st = _state(fid)
    assert st["trials"] == [] and st["verdicts"] == []         # baseline arm DISCARDED
    assert bool(st["meta"]["incomplete"]) is True


def test_G_evidence_throttled_perturbed_arm_is_inconclusive_never_necessary(cem, tmp_path, monkeypatch):
    """Perturbed arm all-MISS-so-far then 429 abort -> classify() would say
    `necessary`, but the partial/throttle guard forces `inconclusive`."""
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=IN, method="GET")
    # baseline 200x3 (HIT); perturbed 403,403,429 -> all MISS + throttle abort
    spy = _Spy(statuses=[200, 200, 200, 403, 403, 429])
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    assert out["verdict"] == "inconclusive"                    # NOT "necessary"
    st = _state(fid)
    assert [v["verdict"] for v in st["verdicts"]] == ["inconclusive"]


def test_G_evidence_bundle_is_honest_about_a_denied_condition(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    conds = [
        {"name": "auth_cookie", "category": "id", "baseline_value": "p", "perturbation": {"drop": True}},
        {"name": "trace", "category": "noise", "baseline_value": "1", "perturbation": {"drop": True}},
    ]
    fid, cid_a = _define(host=IN, method="GET", conds=conds)
    st0 = _state(fid)
    cid_b = st0["conditions"][1]["id"]
    # condition A: a real run -> `necessary`
    monkeypatch.setattr(srv.http_probe, "fetch", _Spy(statuses=[200, 200, 200, 403, 403, 403]))
    srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid_a, k=3)
    # condition B: budget-denied mid-run -> nothing persisted, cem_meta.incomplete=1
    monkeypatch.setattr(srv, "_enforce_cem_finding",
                        lambda _f: (_ for _ in ()).throw(srv.BudgetExceeded("ceiling")))
    srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid_b, k=3)

    bundle = json.loads(srv.evidence_bundle(fid))
    assert bundle["incomplete"] is True
    labels = {row["condition"]: row["verdict"] for row in bundle["intervention_matrix"]}
    assert labels["auth_cookie"] == "necessary"
    assert labels["trace"] == "untested"                       # denied condition is NOT faked
    assert bundle["identified_necessary_conditions"] == ["auth_cookie"]


def test_G_evidence_determinism_gate_oos_base_is_a_bare_failfast_error(cem, tmp_path, monkeypatch):
    """OOS stored base URL -> F1 fail-fast: a bare {"error"} dict, no
    determinism_status / hits / incomplete keys to misread, nothing sent."""
    _engagement(tmp_path, monkeypatch)
    fid, _ = _define(host=OOS, method="GET")
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, f"https://{IN}/doc/1", k=3))
    assert set(out) == {"error"} and "scope" in out["error"].lower()
    assert spy.calls == [] and _state(fid)["trials"] == []


def test_G_evidence_determinism_gate_budget_denial_does_not_leave_a_stale_status(cem, tmp_path, monkeypatch):
    """A budget-denied determinism_gate must NOT report determinism_status
    "NONDETERMINISTIC" (a computed-from-zero-trials artifact a consumer could
    read on its own) -- it reports "INCOMPLETE" alongside error+incomplete."""
    _engagement(tmp_path, monkeypatch)
    fid, _ = _define(host=IN, method="GET")
    monkeypatch.setattr(srv, "_enforce_cem_finding",
                        lambda _f: (_ for _ in ()).throw(srv.BudgetExceeded("ceiling")))
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.determinism_gate(fid, f"https://{IN}/doc/1", k=3))
    assert out["incomplete"] is True and "budget" in out["error"].lower()
    assert out["determinism_status"] == "INCOMPLETE"           # not "NONDETERMINISTIC"
    assert out["hits"] == [] and spy.calls == []
    assert _state(fid)["trials"] == []


# ======================================================================
# ALTERNATE PATHS TO fetch_fn
# ======================================================================

def test_G_local_assemblers_never_fetch_even_on_a_demoted_finding(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=IN, method="GET")
    monkeypatch.setattr(srv.http_probe, "fetch", _Spy(statuses=[200, 200, 200, 403, 403, 403]))
    srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3)     # produce a `necessary` verdict
    srv.update_finding_status(fid, "FALSE_POSITIVE")                 # demote

    boom = _Spy()
    def _forbidden(*a, **k):
        boom.calls.append(a)
        raise AssertionError("local assembler reached fetch_fn")
    monkeypatch.setattr(srv.http_probe, "fetch", _forbidden)

    assert "error" not in json.loads(srv.minimal_condition_sets(fid))
    assert "error" not in json.loads(srv.minimize_poc(fid))
    assert json.loads(srv.evidence_bundle(fid))["finding_id"] == fid
    assert boom.calls == []


def test_G_only_the_two_senders_call_run_intervention(cem):
    import inspect
    lines = inspect.getsource(srv).splitlines()
    ri = [i for i, ln in enumerate(lines) if "cem_engine.run_intervention(" in ln]
    assert len(ri) == 3   # determinism_gate x1, run_counterfactual x2 (baseline + perturbed arm)
    # http_probe.fetch is only ever passed as the fetch_fn arg of run_intervention
    fetch_args = [i for i, ln in enumerate(lines)
                  if "http_probe.fetch," in ln]
    assert len(fetch_args) == 3
    for i in fetch_args:
        assert any("run_intervention(" in lines[j] for j in range(i - 4, i))


def test_G_url_arg_lie_does_not_help_an_oos_base(cem, tmp_path, monkeypatch):
    """The sender `url` arg is an audit label. An OOS stored base_request cannot
    be laundered by passing an in-scope `url` arg (F1 checks base_request['url'])."""
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=OOS, method="GET")
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    for lie in (f"https://{IN}/anything", "", "not-a-url", f"https://{IN}/x?y=z"):
        out = json.loads(srv.run_counterfactual(fid, lie, cid, k=3))
        assert "scope" in out["error"].lower()
    assert spy.calls == []
    _no_side_effects(fid, spy, tmp_path)


def test_G_retry_after_method_refusal_stays_refused_and_leaks_nothing(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=IN, method="DELETE")               # no approval
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    for _ in range(4):
        out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
        assert out["refused"] == "nonidempotent_perturbation"
        out2 = json.loads(srv.determinism_gate(fid, f"https://{IN}/doc/1", k=3))
        assert out2["refused"] == "nonidempotent_perturbation"
    assert spy.calls == []
    _no_side_effects(fid, spy, tmp_path)
    assert _budget(tmp_path).get("by_cem_finding", {}) == {}   # fail-fast: budget untouched


# ======================================================================
# CONCURRENCY
# ======================================================================

def test_G_concurrent_run_counterfactual_same_finding_no_corruption_no_false_verdict(cem, tmp_path, monkeypatch):
    _engagement(tmp_path, monkeypatch)
    fid, cid = _define(host=IN, method="GET")

    def _fetch(url, method="GET", *a, **k):
        return FetchResult(status=200, body="", error=None)   # all HIT both arms
    monkeypatch.setattr(srv.http_probe, "fetch", _fetch)

    outs = []
    def _run():
        outs.append(json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3)))
    ts = [threading.Thread(target=_run) for _ in range(6)]
    for t in ts: t.start()
    for t in ts: t.join()

    # every run completed with a real, honest verdict (all-HIT both arms -> apparently_not_necessary)
    assert all(o.get("verdict") == "apparently_not_necessary" for o in outs), outs
    assert not any(o.get("verdict") == "necessary" for o in outs)
    st = _state(fid)
    # trials/verdicts are additive & consistent: 6 trials + 1 verdict per run
    assert len(st["trials"]) == 6 * 6 and len(st["verdicts"]) == 6
    # per-finding budget counted every real request exactly once
    assert _budget(tmp_path)["by_cem_finding"][str(fid)] == 6 * 6


# ======================================================================
# HOSTILE PERSISTED STATE
# ======================================================================

@pytest.mark.parametrize("mutate", [
    ("base_request", '"not-a-dict"'),
    ("base_request", '{"method":"GET"}'),                       # missing url
    ("base_request", '{"url":"https://in-scope-target.example/x"}'),  # missing method -> GET default
    ("nonidempotent_approval", '{"methods":["ANYTHING"]}'),
    ("nonidempotent_approval", 'not json at all'),
])
def test_G_hostile_persisted_meta_fails_closed_or_safe(cem, tmp_path, monkeypatch, mutate):
    _engagement(tmp_path, monkeypatch)
    col, val = mutate
    fid, cid = _define(host=IN, method="POST" if col == "nonidempotent_approval" else "GET")
    conn = sqlite3.connect(str(cem / "case.db"))
    conn.execute(f"UPDATE cem_meta SET {col} = ? WHERE finding_id = ?", (val, fid))
    conn.commit(); conn.close()
    spy = _Spy()
    monkeypatch.setattr(srv.http_probe, "fetch", spy)
    out = json.loads(srv.run_counterfactual(fid, f"https://{IN}/doc/1", cid, k=3))
    # either a clean error, or (for the missing-method GET-default case) a normal run --
    # but NEVER a state-changing method, NEVER an OOS host, NEVER a crash.
    if "error" not in out:
        assert set(spy.methods) <= {"GET"} and set(spy.hosts) <= {IN}
    else:
        assert set(spy.methods) <= {"GET"}                      # baseline GETs at most
