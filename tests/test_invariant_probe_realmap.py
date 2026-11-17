"""P4-M1 Task 2 -- real-request mapping + body-optional ownership template.

When a mined exchange carries a REAL captured request (`base_request`, from
invariant_corpus), the ownership candidate's CEM hypothesis fires at that real
request and drops the real identity HEADER -- not the P4-M0 synthesized
`invariant.local` query-param scaffold. The hypothesis must be applicable by
the FROZEN case-mcp perturbation (`_perturbation_for(...)._apply(...)`), or it
would raise mid-pipeline. Body-optional: Burp stores no body, so ownership must
still fire (high recall) on identity-count alone, confidence capped.

One-time-use (T2) keeps its synthesized scaffold on purpose: a replay count is
not a droppable header/param of any single real request, so it is not
real-request-mapped (ledgered ruling).
"""
from __future__ import annotations

import importlib.util
import os

import invariant_corpus
import invariant_probe

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_realmap", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def _real_row(identity_hdr, body="", status=200, resource="/orders/42"):
    url = f"https://app.example.com{resource}"
    return {
        "identity": invariant_corpus.identity_label({"Authorization": identity_hdr}),
        "resource": resource, "action": "read", "args": {}, "status": status,
        "body": body, "session": None,
        "base_request": {"method": "GET", "url": url,
                         "headers": {"Authorization": identity_hdr}, "body": None},
    }


def _ownership(corpus):
    return next(c for c in invariant_probe.mine_invariants(corpus)
               if c["invariant"] == "ownership")


def test_ownership_uses_real_base_request_when_present():
    corpus = [_real_row("Bearer alice", body="alice doc"),
              _real_row("Bearer bob", body="bob sees alice doc")]
    cand = _ownership(corpus)
    assert cand["cem_spec"]["base_request"]["url"] == "https://app.example.com/orders/42"
    assert cand["cem_spec"]["base_request"]["headers"].get("Authorization")
    assert cand["cem_spec"]["conditions"][0]["name"] == "Authorization"


def test_real_request_condition_is_cem_applicable():
    corpus = [_real_row("Bearer alice", body="x"), _real_row("Bearer bob", body="y")]
    spec = _ownership(corpus)["cem_spec"]
    apply_fn = srv._perturbation_for(spec["conditions"][0])
    perturbed = apply_fn(spec["base_request"])          # must NOT raise
    assert "Authorization" not in perturbed["headers"]  # the header was dropped


def test_body_absent_still_yields_ownership_candidate_high_recall():
    corpus = [_real_row("Bearer alice", body=""), _real_row("Bearer bob", body="")]
    cand = _ownership(corpus)
    assert cand["negative_control"]["content_relation"] == "unknown"
    assert cand["confidence"] in ("low", "medium")   # capped when no body to compare


def test_body_present_behavior_unchanged():
    """A synthesized (no base_request) body-divergent corpus yields the same
    candidate P4-M0 produced: condition is the `identity` query param."""
    corpus = [
        {"identity": "alice", "resource": "lh_s_bravo", "action": "read",
         "args": {}, "status": 200, "body": "alice doc"},
        {"identity": "bob", "resource": "lh_s_bravo", "action": "read",
         "args": {}, "status": 200, "body": "bob reads alice doc"},
    ]
    cand = _ownership(corpus)
    assert "invariant.local" in cand["cem_spec"]["base_request"]["url"]
    assert cand["cem_spec"]["conditions"][0]["name"] == "identity"
    assert cand["cem_spec"]["conditions"][0]["category"] == "identity"
