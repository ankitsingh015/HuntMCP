"""C1a (part 5/5): CEM's own fetch_fn (cem_engine.run_intervention's injected
http_probe.fetch) already performs a REAL HTTP request for every trial --
Trial.request/Trial.response ARE wire-level evidence by construction. But
case-mcp/server.py's determinism_gate()/run_counterfactual() only ever called
case_store.cem_record_trial() with http_status, never with the
request_evidence_hash/response_evidence_hash columns that table has carried
since its schema was first defined -- so every CEM trial's actual request/
response was discarded instead of being stored as provenance-tagged evidence,
leaving provenance_signal.py's CEM-backed findings uncountable as "wire"
despite CEM being the single most rigorous, real-request-backed evidence
source in this whole repo.

This closes that gap by routing each trial's request/response through
case_store.add_evidence() (type="request"/"response", same content-addressed
store oob-mcp/browser-mcp's own wire evidence would go through if an agent
attached it) with provenance={"class": "wire", "captured_by": "cem_engine",
"method": ..., "url": ...}, and feeding the resulting content hashes into
cem_record_trial(). Additive -- the CEM engine's own protected evaluator/
oracle logic (cem_engine.py) is untouched; this only changes what the
orchestration layer (case-mcp/server.py) does with an already-completed
trial's already-real result.
"""
import hashlib
import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_wire_provenance", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
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
]


@pytest.fixture
def cem_db(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    eng = tmp_path / "engagement.yaml"
    eng.write_text("target: t.example\nin_scope:\n  - t.example\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    return tmp_path


def _fake_fetch(*statuses):
    it = iter(statuses)

    def _f(url, method, headers, body, timeout_s):
        s = next(it)
        return FetchResult(status=s, body=f"body for {url}", error=None,
                            headers={"Content-Type": "text/html"})

    return _f


def _confirmed_finding():
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    srv.add_evidence("request", "GET /doc/1", finding_id=f["id"])
    srv.update_finding_status(f["id"], "CONFIRMED")
    return f["id"]


def test_determinism_gate_trials_carry_evidence_hashes(cem_db, monkeypatch):
    fid = _confirmed_finding()
    srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG), json.dumps(_CONDS), k=2)
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200))
    srv.determinism_gate(fid, "https://t.example", k=2)

    state = srv.case_store.cem_load_state(fid)
    trials = state["trials"]
    assert len(trials) == 2
    for t in trials:
        assert t["request_evidence_hash"], "request_evidence_hash must be populated, not NULL"
        assert t["response_evidence_hash"], "response_evidence_hash must be populated, not NULL"


def test_determinism_gate_evidence_is_real_content_addressed_and_wire_tagged(cem_db, monkeypatch):
    fid = _confirmed_finding()
    srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG), json.dumps(_CONDS), k=1)
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200))
    srv.determinism_gate(fid, "https://t.example", k=1)

    state = srv.case_store.cem_load_state(fid)
    trial = state["trials"][0]

    req_evidence = srv.case_store.get_evidence(
        _evidence_id_for_hash(cem_db, trial["request_evidence_hash"]),
        db_path=str(cem_db / "case.db"),
    )
    assert req_evidence["type"] == "request"
    # Controls.pin() legitimately appends a per-trial cache-buster query
    # param to the resolved URL (see cem_engine.Controls) -- the provenance
    # must reflect the REAL outbound URL actually fetched, cache-buster
    # included, not the original base_request URL.
    assert req_evidence["provenance"] == {
        "class": "wire", "captured_by": "cem_engine",
        "method": "GET", "url": "https://t.example/doc/1?_cb=0",
    }
    with open(req_evidence["content_ref"]) as f:
        req_content = f.read()

    resp_evidence = srv.case_store.get_evidence(
        _evidence_id_for_hash(cem_db, trial["response_evidence_hash"]),
        db_path=str(cem_db / "case.db"),
    )
    assert resp_evidence["type"] == "response"
    with open(resp_evidence["content_ref"]) as f:
        stored_response = json.loads(f.read())
    assert stored_response["status"] == 200
    assert stored_response["body"] == "body for https://t.example/doc/1?_cb=0"

    # Genuine content-addressing: the stored request content really does
    # hash to the recorded request_evidence_hash (not an arbitrary id/uuid).
    assert hashlib.sha256(req_content.encode("utf-8")).hexdigest() == trial["request_evidence_hash"]


def _evidence_id_for_hash(tmp_path, content_hash: str) -> int:
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "case.db"))
    try:
        row = conn.execute(
            "SELECT id FROM evidence WHERE content_hash = ? ORDER BY id DESC LIMIT 1", (content_hash,)
        ).fetchone()
        assert row, f"no evidence row for hash {content_hash!r}"
        return row[0]
    finally:
        conn.close()


def test_run_counterfactual_trials_carry_evidence_hashes(cem_db, monkeypatch):
    fid = _confirmed_finding()
    cond_id = json.loads(
        srv.define_conditions(fid, json.dumps(_BASE_REQ), json.dumps(_SIG), json.dumps(_CONDS), k=3)
    )["condition_ids"][0]
    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch(200, 200, 200, 403, 403, 403))
    srv.run_counterfactual(fid, "https://t.example", cond_id, k=3)

    state = srv.case_store.cem_load_state(fid)
    trials = [t for t in state["trials"] if t["arm"] in ("baseline", "perturbed")]
    assert len(trials) == 6
    for t in trials:
        assert t["request_evidence_hash"]
        assert t["response_evidence_hash"]


def test_record_trial_wire_evidence_returns_none_hashes_without_raising_on_bad_request(cem_db):
    """Isolated unit test of the new helper itself (not the full sender
    pipeline, which already fail-fasts a missing/blank url via scope_guard
    long before a trial could exist): a Trial attached to a finding_id that
    doesn't exist -- add_evidence()'s existing FK-check path -- must degrade
    gracefully (return None hashes) rather than raise or propagate the
    error, since a failure to attach provenance must never be allowed to
    lose an already-completed, already-real trial's outcome."""
    trial = srv.cem_engine.Trial(
        arm="baseline", k_index=0, http_status=200, oracle_hit=True,
        request={"method": "GET", "url": "https://t.example/x", "headers": {}, "body": None},
        response=FetchResult(status=200, body="ok", error=None, headers={}),
    )
    req_hash, resp_hash = srv._record_trial_wire_evidence(999999, trial)
    assert req_hash is None
    assert resp_hash is None


def test_record_trial_wire_evidence_degrades_on_any_add_evidence_exception(cem_db, monkeypatch):
    """Code-review finding (CONFIRMED): the helper's own docstring claims it
    "never raises", but nothing actually caught a genuine exception from
    add_evidence() itself (e.g. a disk write failure, or json.dumps() on an
    unexpected value) -- only add_evidence()'s own {"error": ...} return
    path degraded gracefully. An uncaught exception here would abort the
    `for t in trials:` loop entirely, losing EVERY remaining already-
    completed, already-budget-charged trial's recording, not just its
    evidence hashes."""
    fid = _confirmed_finding()

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(srv.case_store, "add_evidence", _boom)
    trial = srv.cem_engine.Trial(
        arm="baseline", k_index=0, http_status=200, oracle_hit=True,
        request={"method": "GET", "url": "https://t.example/x", "headers": {}, "body": None},
        response=FetchResult(status=200, body="ok", error=None, headers={}),
    )
    req_hash, resp_hash = srv._record_trial_wire_evidence(fid, trial)
    assert req_hash is None
    assert resp_hash is None


def test_record_trial_wire_evidence_redacts_secret_header_values(cem_db):
    """Code-review finding (CONFIRMED): cem_engine.Controls.record() already
    deliberately stores only header NAMES, never values, because "values
    are session secrets and never go in the DB or a report" -- but this
    helper was persisting trial.request/trial.response verbatim, including
    real Cookie/Authorization/Set-Cookie header VALUES, to on-disk evidence
    content. Must redact those values the same way _redact_provenance()
    already does for the provenance dict, via the SAME
    cem_engine._redact_recursive() -- not a second, divergent redaction
    implementation."""
    fid = _confirmed_finding()
    trial = srv.cem_engine.Trial(
        arm="baseline", k_index=0, http_status=200, oracle_hit=True,
        request={"method": "GET", "url": "https://t.example/x",
                 "headers": {"Cookie": "sid=supersecret123"}, "body": None},
        response=FetchResult(status=200, body="ok", error=None,
                              headers={"Set-Cookie": "sid=rotated-secret456"}),
    )
    req_hash, resp_hash = srv._record_trial_wire_evidence(fid, trial)

    req_evidence = srv.case_store.get_evidence(
        _evidence_id_for_hash(cem_db, req_hash), db_path=str(cem_db / "case.db"))
    with open(req_evidence["content_ref"]) as f:
        req_content = f.read()
    assert "supersecret123" not in req_content
    assert "[REDACTED:" in req_content

    resp_evidence = srv.case_store.get_evidence(
        _evidence_id_for_hash(cem_db, resp_hash), db_path=str(cem_db / "case.db"))
    with open(resp_evidence["content_ref"]) as f:
        resp_content = f.read()
    assert "rotated-secret456" not in resp_content
    assert "[REDACTED:" in resp_content
