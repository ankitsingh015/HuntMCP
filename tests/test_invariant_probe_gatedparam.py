"""P4-M1 Task 4 -- state-gated-parameter template (T4).

Within a (resource, session) history, an action succeeds carrying a query param
that the sequence identifies as the authorization/ownership gate: the param is
present on a 2xx request and absent on a denied one. The candidate reduces to a
frozen-CEM test -- drop that query param and see whether the request still
succeeds (if so, the gate is not enforced). High recall; CEM is precision.
"""
from __future__ import annotations

import importlib.util
import os

import invariant_probe

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_gated", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def _row(ident, status, url, action="fetch", resource="/report", session="s1", idx=0):
    return {
        "identity": ident, "resource": resource, "action": action, "args": {},
        "status": status, "body": "", "session": session, "_idx": idx,
        "base_request": {"method": "GET", "url": url, "headers": {}, "body": None},
    }


def _gated(corpus):
    return [c for c in invariant_probe.mine_invariants(corpus)
            if c["invariant"] == "state_gated_param"]


def test_state_gated_param_candidate_names_the_gate_query_param():
    corpus = [
        _row("alice", 200, "https://app.example.com/report?token=abc123", idx=0),
        _row("bob", 403, "https://app.example.com/report", idx=1),  # denied, no token
    ]
    cands = _gated(corpus)
    assert len(cands) == 1
    cond = cands[0]["cem_spec"]["conditions"][0]
    assert cond["name"] == "token"
    assert "token=abc123" in cands[0]["cem_spec"]["base_request"]["url"]


def test_state_gated_param_condition_is_cem_applicable():
    corpus = [
        _row("alice", 200, "https://app.example.com/report?token=abc123", idx=0),
        _row("bob", 403, "https://app.example.com/report", idx=1),
    ]
    spec = _gated(corpus)[0]["cem_spec"]
    apply_fn = srv._perturbation_for(spec["conditions"][0])
    perturbed = apply_fn(spec["base_request"])         # must NOT raise
    assert "token=abc123" not in perturbed["url"]      # the query param was dropped


def test_no_candidate_when_no_param_distinguishes_gate():
    # a param present on BOTH a success and a denial does not distinguish the gate
    corpus = [
        _row("alice", 200, "https://app.example.com/report?lang=en", idx=0),
        _row("bob", 403, "https://app.example.com/report?lang=en", idx=1),
    ]
    assert _gated(corpus) == []


def test_param_varying_across_identities_is_flagged_without_a_denial():
    """High recall (CEM is precision): a param whose value varies across >=2
    identities' 2xx requests looks like an identity/privilege gate and is
    flagged even with no denial present -- CEM then decides enforcement."""
    corpus = [
        _row("alice", 200, "https://app.example.com/report?role=user", idx=0),
        _row("bob", 200, "https://app.example.com/report?role=admin", idx=1),
    ]
    cands = _gated(corpus)
    assert {c["cem_spec"]["conditions"][0]["name"] for c in cands} == {"role"}
    # one candidate per (param, identity) so CEM can test each real request
    assert len(cands) == 2


def test_param_constant_across_identities_without_denial_is_not_flagged():
    corpus = [
        _row("alice", 200, "https://app.example.com/report?lang=en", idx=0),
        _row("bob", 200, "https://app.example.com/report?lang=en", idx=1),
    ]
    assert _gated(corpus) == []
