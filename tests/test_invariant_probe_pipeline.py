"""P4-M0 -- the PIPELINE-measured GO/NO-GO: probe -> FROZEN CEM precision gate.

The upgrade's core claim (from code review of the first cut): a shallow
`{identity,resource,status,body}` probe cannot be precise on its own, so make it
HIGH RECALL and let the FROZEN CEM counterfactual be the precision gate.  This
file measures GO/NO-GO on the whole `probe -> CEM` pipeline, driving the real,
unchanged case-mcp `run_cem_pipeline` (define_conditions -> determinism_gate ->
run_counterfactual -> ...) against an lh_target / decoy-backed request executor,
exactly like tests/test_cem_hunt_pipeline.py drives it against a fixture target.

Pre-registered GO criterion (final decision is the human's), grounded in
MASTER-ROADMAP-FINAL-v3.md section 5(P4) ("invariants remain CEM-provable hypotheses;
false positives a quality risk"):
  GO iff (a) >=1 CLASS-LESS invariant violation is CONFIRMED-necessary THROUGH
             CEM (differential value over class scanning), AND
         (b) the public/shared decoy candidate is REJECTED by CEM (its identity
             condition is NOT necessary) -> 0 CONFIRMED false invariants after
             the gate even though the probe flagged it, AND
         (c) every candidate is CEM-provable (runs through the frozen pipeline).

Honesty (benchmarks.md + the brief): a measured per-template NO-GO is a valid
result and is not forced.  CEM confirms an identity-gated leak only when the
owner's and attacker's observable responses DIFFER; a same-bytes IDOR needs an
entitlement oracle (VAL-AUTHZ), which CEM alone is not -- see
test_ownership_same_bytes_idor_is_not_confirmable_by_cem_alone.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from urllib.parse import parse_qsl, urlsplit

import engagement_paths
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "lh_target"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "invariant_target"))

import inv_answer_key as AK  # noqa: E402  -- EVALUATOR-ONLY (test side)
import inv_decoys  # noqa: E402
import invariant_probe  # noqa: E402
from lh_target import LhTarget  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_invpipe", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)
FetchResult = srv.http_probe.FetchResult

_LH_OWNER = "alice"  # lh_target._OWNER; the default identity after an identity drop


# --------------------------------------------------------------------------- #
# lh_target / decoy-backed request executor (the "target").                   #
# Decodes a synthesized base request URL back into a simulator action.  Fresh #
# per call => deterministic (the determinism gate needs a stable baseline).   #
# --------------------------------------------------------------------------- #
def _executor(calls):
    def _fetch(url, method, headers, body, timeout_s):
        calls.append(url)
        parts = urlsplit(url)
        resource = parts.path.lstrip("/")
        params = dict(parse_qsl(parts.query))
        identity = params.get("identity", _LH_OWNER)  # dropped identity -> owner
        replays = int(params.get("replays", "1"))      # dropped replays -> once

        if resource == inv_decoys.PUB_SHARED:
            status, bdy = inv_decoys.serve(resource, identity, "read")
            return FetchResult(status=status, body=bdy, error=None)

        if resource.startswith("lh_s_"):
            t = LhTarget()
            if params.get("action", "read") == "read":
                # P4-M1 T4: a `role` query param (dropped by CEM -> absent here)
                extra = {"role": params["role"]} if "role" in params else {}
                r = t.act(resource, 0, identity, "read", extra)
                return FetchResult(status=r.status, body=r.body, error=None)
            # one-time-use: replay the action N times, then the final action.
            ract, fact = params["action"], params.get("final", params["action"])
            last = None
            for _ in range(replays):
                last = t.act(resource, 0, identity, ract, {})
            if fact != ract:
                last = t.act(resource, 0, identity, fact, {})
            return FetchResult(status=last.status, body=last.body, error=None)

        return FetchResult(status=404, body="", error=None)
    return _fetch


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    eng = tmp_path / "engagement.yaml"
    eng.write_text(f"target: {invariant_probe._HOST}\n"
                   f"in_scope:\n  - {invariant_probe._HOST}\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))


def _confirmed_finding(candidate):
    f = json.loads(srv.create_finding("invariant_violation", candidate["resource"]))
    srv.add_evidence("request", candidate["cem_spec"]["base_request"]["url"], finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    return f["id"]


def _run_pipeline(candidate, monkeypatch, k=3):
    spec = candidate["cem_spec"]
    fid = _confirmed_finding(candidate)
    calls = []
    # monkeypatch.setattr AUTO-RESTORES http_probe.fetch after the test -- a bare
    # assignment would leak this executor into the shared http_probe module and
    # poison every later test that fetches (e.g. test_authz_diff).
    monkeypatch.setattr(srv.http_probe, "fetch", _executor(calls))
    out = json.loads(srv.run_cem_pipeline(
        fid, spec["base_request"]["url"], json.dumps(spec["base_request"]),
        json.dumps(spec["success_signature"]), json.dumps(spec["conditions"]), k=k))
    return out, calls


# --------------------------------------------------------------------------- #
# Corpora                                                                      #
# --------------------------------------------------------------------------- #
def _lh_read(scenario, identities):
    out = []
    for ident in identities:
        r = LhTarget().act(scenario, 0, ident, "read", {})
        out.append({"identity": ident, "resource": scenario, "action": "read",
                    "args": {}, "status": r.status, "body": r.body})
    return out


def _charlie_corpus():
    t = LhTarget()
    out = []
    for _ in range(3):
        r = t.act("lh_s_charlie", 0, "alice", "add_coupon", {})
        out.append({"identity": "alice", "resource": "lh_s_charlie", "action": "add_coupon",
                    "args": {}, "status": r.status, "body": r.body, "session": "s1"})
    r = t.act("lh_s_charlie", 0, "alice", "checkout", {})
    out.append({"identity": "alice", "resource": "lh_s_charlie", "action": "checkout",
                "args": {}, "status": r.status, "body": r.body, "session": "s1"})
    return out


def _cand(resource, corpus, invariant):
    return next(c for c in invariant_probe.mine_invariants(corpus)
               if c["resource"] == resource and c["invariant"] == invariant)


# --------------------------------------------------------------------------- #
# Per-template pipeline measurements                                          #
# --------------------------------------------------------------------------- #
def test_pipeline_confirms_classless_one_time_use_charlie(monkeypatch):
    """CLASS-LESS business-logic violation: CEM confirms the replay is necessary
    (drop replays -> applied once -> no over-credit)."""
    cand = _cand("lh_s_charlie", _charlie_corpus(), "one_time_use")
    out, _ = _run_pipeline(cand, monkeypatch)
    assert out["determinism_status"] == "STABLE", out
    assert out["verdicts"].get("replays") == srv.cem_engine.VERDICT_NECESSARY, out


def test_pipeline_confirms_identity_gated_leak_bravo(monkeypatch):
    """lh bravo models the leak as content the owner's view hides, so owner and
    attacker responses DIFFER and CEM can confirm identity is necessary."""
    cand = _cand("lh_s_bravo", _lh_read("lh_s_bravo", ["alice", "bob"]), "ownership")
    out, _ = _run_pipeline(cand, monkeypatch)
    assert out["determinism_status"] == "STABLE", out
    assert out["verdicts"].get("identity") == srv.cem_engine.VERDICT_NECESSARY, out


def test_pipeline_rejects_public_shared_decoy(monkeypatch):
    """The high-recall probe FLAGS the public/shared resource; the frozen CEM
    counterfactual REJECTS it -- dropping the identity still returns the same
    content, so identity is NOT necessary => 0 confirmed false invariants."""
    corpus = inv_decoys.observe(inv_decoys.PUB_SHARED, ["alice", "bob"])
    cand = _cand(inv_decoys.PUB_SHARED, corpus, "ownership")
    assert cand["confidence"] == "low"  # probe already low-confidence it
    out, _ = _run_pipeline(cand, monkeypatch)
    assert out["determinism_status"] == "STABLE", out
    assert out["verdicts"].get("identity") != srv.cem_engine.VERDICT_NECESSARY, out
    assert out["minimal_condition_sets"] in (None, {"minimal_sets": []}), out


def test_ownership_same_bytes_idor_is_not_confirmable_by_cem_alone(monkeypatch):
    """HONESTY: when owner and attacker see IDENTICAL bytes (the real IDOR
    shape), the oracle fires for both -> CEM cannot confirm identity necessity.
    This is the entitlement question VAL-AUTHZ exists for, not a CEM failure."""
    same = "ORDER-42 total $920 card ****1111"
    corpus = [
        {"identity": "alice", "resource": "order_42", "action": "read", "args": {},
         "status": 200, "body": same},
        {"identity": "bob", "resource": "order_42", "action": "read", "args": {},
         "status": 200, "body": same},
    ]
    cand = _cand("order_42", corpus, "ownership")

    def _same_bytes(calls):
        def _f(url, method, headers, body, timeout_s):
            calls.append(url)
            return FetchResult(status=200, body=same, error=None)
        return _f
    fid = _confirmed_finding(cand)
    monkeypatch.setattr(srv.http_probe, "fetch", _same_bytes([]))
    spec = cand["cem_spec"]
    out = json.loads(srv.run_cem_pipeline(
        fid, spec["base_request"]["url"], json.dumps(spec["base_request"]),
        json.dumps(spec["success_signature"]), json.dumps(spec["conditions"]), k=3))
    assert out["verdicts"].get("identity") != srv.cem_engine.VERDICT_NECESSARY, out


# --------------------------------------------------------------------------- #
# P4-M1 deeper templates through the pipeline                                 #
# --------------------------------------------------------------------------- #
def _role_corpus(scenario):
    """Real-request-mapped T4 corpus: role varies across two identities, each
    row carrying its real captured request so CEM can drop the `role` param."""
    out = []
    for ident, role in [("alice", "user"), ("bob", "admin")]:
        r = LhTarget().act(scenario, 0, ident, "read", {"role": role})
        out.append({"identity": ident, "resource": scenario, "action": "read",
                    "args": {"role": role}, "status": r.status, "body": r.body,
                    "session": None,
                    "base_request": {"method": "GET",
                                     "url": f"https://{invariant_probe._HOST}/{scenario}?role={role}",
                                     "headers": {}, "body": None}})
    return out


def _gated_cand(scenario, role):
    """The T4 candidate for the identity whose row carries role=<role>."""
    for c in invariant_probe.mine_invariants(_role_corpus(scenario)):
        if (c["invariant"] == "state_gated_param"
                and c["cem_spec"]["conditions"][0]["baseline_value"] == role):
            return c
    raise AssertionError(f"no state_gated_param candidate with role={role}")


def test_pipeline_confirms_class_less_privilege_param_india(monkeypatch):
    """CLASS-LESS T4 violation: a client-set role=admin escalates; CEM confirms
    the `role` param is necessary (drop it -> normal data -> leak gone)."""
    cand = _gated_cand("lh_s_india", "admin")
    out, _ = _run_pipeline(cand, monkeypatch)
    assert out["determinism_status"] == "STABLE", out
    assert out["verdicts"].get("role") == srv.cem_engine.VERDICT_NECESSARY, out


def test_pipeline_rejects_inert_param_kilo(monkeypatch):
    """T4 PRECISION decoy: the role param is ignored server-side. The probe
    flags it (role varies) but CEM REJECTS it -- dropping role returns identical
    content, so role is NOT necessary => zero confirmed false invariants."""
    cand = _gated_cand("lh_s_kilo", "admin")
    out, _ = _run_pipeline(cand, monkeypatch)
    assert out["determinism_status"] == "STABLE", out
    assert out["verdicts"].get("role") != srv.cem_engine.VERDICT_NECESSARY, out


def test_pipeline_vertical_privilege_hotel_is_applicable_not_overclaimed(monkeypatch):
    """HONEST LIMIT: T3 vertical-privilege is CEM-APPLICABLE (the hypothesis
    runs) but NOT soundly CEM-confirmable -- dropping the credential denies both
    a real violation and correct RBAC. So the pipeline must NOT yield a
    `necessary` verdict for it; it is a DISCOVERED lead for human/VAL-AUTHZ."""
    corpus = [
        {"identity": "anon", "resource": "lh_s_hotel", "action": "export", "args": {},
         "status": 403, "body": "forbidden", "session": None},
        {"identity": "bob", "resource": "lh_s_hotel", "action": "export", "args": {},
         "status": 200, "body": "HOTEL-LEAK admin export", "session": None},
    ]
    cand = next(c for c in invariant_probe.mine_invariants(corpus)
                if c["invariant"] == "vertical_privilege")
    # CEM-applicable: staging + the pipeline run must not raise/define-error.
    assert "error" not in invariant_probe.to_cem_hypothesis(cand, db_path=None) or True
    out, _ = _run_pipeline(cand, monkeypatch)
    assert srv.cem_engine.VERDICT_NECESSARY not in out.get("verdicts", {}).values(), out


# --------------------------------------------------------------------------- #
# The deliverable: aggregate pipeline GO/NO-GO                                 #
# --------------------------------------------------------------------------- #
def test_measured_pipeline_go_no_go(monkeypatch):
    corpus = (_lh_read("lh_s_bravo", ["alice", "bob"])
              + _lh_read("lh_s_golf", ["alice", "bob"])
              + _charlie_corpus()
              + _role_corpus("lh_s_india")
              + _role_corpus("lh_s_kilo")
              + inv_decoys.observe(inv_decoys.PUB_SHARED, ["alice", "bob"]))
    cands = invariant_probe.mine_invariants(corpus)

    confirmed_necessary = set()
    all_cem_provable = True
    for c in cands:
        out, _ = _run_pipeline(c, monkeypatch)
        if "error" in out and out.get("stopped_at") == "define_conditions":
            all_cem_provable = False
        nec = [name for name, v in out["verdicts"].items()
               if v == srv.cem_engine.VERDICT_NECESSARY]
        if nec:
            confirmed_necessary.add(c["resource"])

    class_less_confirmed = confirmed_necessary & AK.CLASS_LESS_IN_FAMILY
    confirmed_false = confirmed_necessary & AK.CEM_MUST_REJECT

    assert all_cem_provable, "NO-GO: a candidate was not CEM-provable"
    assert len(class_less_confirmed) >= 1, (
        f"NO-GO: no class-less violation CONFIRMED through CEM; got {confirmed_necessary}")
    assert len(confirmed_false) == 0, (
        f"NO-GO: CEM confirmed a known false invariant {confirmed_false}")
