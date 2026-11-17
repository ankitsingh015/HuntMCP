"""P4-M1 Task 3 -- state-transition view + T3 vertical-privilege template.

T3 fires on a DIFFERENTIAL: on one resource, at least one identity is DENIED
(401/403) for an action while a different identity SUCCEEDS (2xx). That is the
vertical-privilege signal class scanners miss. The candidate reduces to a
frozen-CEM droppable-condition hypothesis: drop the succeeding identity's
credential header and let CEM decide whether the identity was necessary. High
recall; CEM is precision.
"""
from __future__ import annotations

import importlib.util
import os

import invariant_corpus
import invariant_probe

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_vertical", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def _row(ident_hdr, status, action="export", resource="/admin/report", session="s1", idx=0):
    url = f"https://app.example.com{resource}"
    return {
        "identity": invariant_corpus.identity_label({"Authorization": ident_hdr}),
        "resource": resource, "action": action, "args": {}, "status": status,
        "body": "", "session": session, "_idx": idx,
        "base_request": {"method": "GET", "url": url,
                         "headers": {"Authorization": ident_hdr}, "body": None},
    }


def _vertical(corpus):
    return [c for c in invariant_probe.mine_invariants(corpus)
            if c["invariant"] == "vertical_privilege"]


def test_sequence_view_orders_actions_per_object_session():
    exchanges = [
        {"resource": "/a", "action": "read", "status": 200, "identity": "u1",
         "body": "x", "session": "s1", "_idx": 0},
        {"resource": "/a", "action": "edit", "status": 403, "identity": "u2",
         "body": "", "session": "s1", "_idx": 1},
        {"resource": "/a", "action": "read", "status": 200, "identity": "u1",
         "body": "x", "session": "s2", "_idx": 2},
    ]
    seqs = invariant_probe._sequence_by_object_session(exchanges)
    assert set(seqs.keys()) == {("/a", "s1"), ("/a", "s2")}
    s1 = seqs[("/a", "s1")]
    assert [step["action"] for step in s1] == ["read", "edit"]
    assert [step["actor"] for step in s1] == ["u1", "u2"]


def test_vertical_privilege_candidate_when_lowpriv_succeeds_where_another_is_denied():
    corpus = [_row("Bearer admin", 403, idx=0),   # one identity denied
              _row("Bearer lowpriv", 200, idx=1)]  # a different identity succeeds
    cands = _vertical(corpus)
    assert len(cands) == 1
    c = cands[0]
    assert c["confidence"] == "high"              # a denial was seen on the resource
    assert c["cem_spec"]["conditions"][0]["name"] == "Authorization"


def test_vertical_privilege_condition_is_cem_applicable():
    corpus = [_row("Bearer admin", 403, idx=0), _row("Bearer lowpriv", 200, idx=1)]
    spec = _vertical(corpus)[0]["cem_spec"]
    apply_fn = srv._perturbation_for(spec["conditions"][0])
    perturbed = apply_fn(spec["base_request"])     # must NOT raise
    assert "Authorization" not in perturbed["headers"]


def test_no_vertical_privilege_candidate_when_all_denied_or_all_allowed():
    all_denied = [_row("Bearer a", 403, idx=0), _row("Bearer b", 401, idx=1)]
    all_allowed = [_row("Bearer a", 200, idx=0), _row("Bearer b", 200, idx=1)]
    assert _vertical(all_denied) == []
    assert _vertical(all_allowed) == []


def test_vertical_privilege_still_fires_when_offender_read_before_the_privileged_op():
    """Review finding: the offender commonly RECONs (a read) before the
    privileged op. The non-read success must still be detected even though the
    same identity had an earlier read success on the resource."""
    corpus = [
        _row("Bearer lowpriv", 200, action="read", idx=0),   # bob reads first
        _row("Bearer admin", 403, action="export", idx=1),   # admin denied export
        _row("Bearer lowpriv", 200, action="export", idx=2),  # bob then exports
    ]
    cands = _vertical(corpus)
    assert len(cands) == 1, cands
    assert cands[0]["cem_spec"]["conditions"][0]["name"] == "Authorization"
