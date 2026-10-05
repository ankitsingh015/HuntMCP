"""C1a (part 4/4): closes the last of 5 named wire-level provenance
sources -- curl/tool_resolver, "the dominant real-world evidence source
in actual hunts." An agent confirming a finding manually most often just
runs curl directly via its own Bash tool; nothing captured that request/
response as provenance. A PostToolUse hook that watches for raw Bash curl
calls was considered and rejected (a stateless hook has no way to know
WHICH finding_id a given curl call belongs to -- that's live agent/
session state). The actual fix reuses the exact pattern already proven
for oob-mcp/browser-mcp/CEM: a real MCP tool that performs the real
request itself -- through _cem_fetch(), the SAME redirect-disabled
wrapper CEM's own senders use (security-review finding, CONFIRMED: an
earlier version of this tool called http_probe.fetch() directly, which
defaults to following redirects, reopening the exact SSRF/scope-bypass-
via-redirect hole _cem_fetch() exists to close) -- and records it as
case_store evidence directly -- the agent gets the response AND
confirmation the evidence was recorded, no manual provenance-JSON
construction needed.

fetch_with_provenance() deliberately reuses _record_trial_wire_evidence()
(the exact helper C1a's CEM increment built and had independently
reviewed for exception-safety and secret-redaction) rather than a second,
divergent evidence-recording implementation -- it just needs an object
with .request/.response attributes, which a one-off fetch satisfies via
a tiny shim as readily as a real cem_engine.Trial does.
"""
import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_fetch_provenance", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

FetchResult = srv.http_probe.FetchResult


@pytest.fixture
def case_db(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    eng = tmp_path / "engagement.yaml"
    eng.write_text("target: t.example\nin_scope:\n  - t.example\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    return tmp_path


def _finding():
    return json.loads(srv.create_finding("IDOR", "/doc/{id}"))["id"]


def test_fetch_with_provenance_returns_the_real_response(case_db, monkeypatch):
    fid = _finding()
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a, **k: FetchResult(
        status=200, body="hello", error=None, headers={"Content-Type": "text/plain"}))

    out = json.loads(srv.fetch_with_provenance(fid, "https://t.example/doc/1"))

    assert out["status"] == 200
    assert out["body_preview"] == "hello"
    assert out["error"] is None


def test_fetch_with_provenance_records_real_case_store_evidence(case_db, monkeypatch):
    fid = _finding()
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a, **k: FetchResult(
        status=200, body="hello", error=None, headers={"Content-Type": "text/plain"}))

    out = json.loads(srv.fetch_with_provenance(fid, "https://t.example/doc/1"))

    assert out["request_evidence_hash"]
    assert out["response_evidence_hash"]
    req_ev = srv.case_store.get_evidence(
        _evidence_id_for_hash(case_db, out["request_evidence_hash"]), db_path=str(case_db / "case.db"))
    assert req_ev["type"] == "request"
    assert req_ev["provenance"] == {
        "class": "wire", "captured_by": "case-mcp", "method": "GET", "url": "https://t.example/doc/1",
    }


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


def test_fetch_with_provenance_refuses_out_of_scope_url(case_db, monkeypatch):
    fid = _finding()
    called = []
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a, **k: called.append(1) or FetchResult(
        status=200, body="", error=None, headers={}))

    out = json.loads(srv.fetch_with_provenance(fid, "https://evil.example/doc/1"))

    assert "error" in out
    assert "scope" in out["error"].lower()
    assert not called, "out-of-scope request must never actually fetch"


def test_fetch_with_provenance_refuses_cloud_metadata_url(case_db, monkeypatch):
    fid = _finding()
    called = []
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a, **k: called.append(1) or FetchResult(
        status=200, body="", error=None, headers={}))

    out = json.loads(srv.fetch_with_provenance(fid, "http://169.254.169.254/latest/meta-data/"))

    assert "error" in out
    assert not called, "a cloud-metadata destination must never actually fetch"


def test_fetch_with_provenance_refuses_non_http_scheme(case_db, monkeypatch):
    fid = _finding()
    called = []
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a, **k: called.append(1) or FetchResult(
        status=200, body="", error=None, headers={}))

    out = json.loads(srv.fetch_with_provenance(fid, "file:///etc/passwd"))

    assert "error" in out
    assert not called


def test_fetch_with_provenance_bad_headers_json_is_a_clean_error(case_db, monkeypatch):
    fid = _finding()
    called = []
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a, **k: called.append(1) or FetchResult(
        status=200, body="", error=None, headers={}))

    out = json.loads(srv.fetch_with_provenance(fid, "https://t.example/doc/1", headers="not json"))

    assert "error" in out
    assert not called


def test_fetch_with_provenance_budget_exhausted_is_graceful(case_db, monkeypatch):
    fid = _finding()
    monkeypatch.setattr(srv, "_enforce_budget", lambda name: (_ for _ in ()).throw(
        srv.BudgetExceeded("engagement Tier-2 cap reached")))
    called = []
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a, **k: called.append(1) or FetchResult(
        status=200, body="", error=None, headers={}))

    out = json.loads(srv.fetch_with_provenance(fid, "https://t.example/doc/1"))

    assert "error" in out
    assert out.get("incomplete") is True
    assert not called, "a request must never fire after budget enforcement raises"


def test_fetch_with_provenance_posts_custom_method_and_body(case_db, monkeypatch):
    fid = _finding()
    seen = {}

    def _fake_fetch(url, method, headers, body, timeout_s):
        seen["url"] = url
        seen["method"] = method
        seen["headers"] = headers
        seen["body"] = body
        return FetchResult(status=201, body="created", error=None, headers={})

    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch)
    out = json.loads(srv.fetch_with_provenance(
        fid, "https://t.example/doc", method="POST",
        headers=json.dumps({"Content-Type": "application/json"}), body='{"x":1}',
    ))

    assert out["status"] == 201
    assert seen["method"] == "POST"
    assert seen["headers"] == {"Content-Type": "application/json"}
    assert seen["body"] == '{"x":1}'


def test_fetch_with_provenance_does_not_follow_redirects(case_db, monkeypatch):
    """Security-review finding (CONFIRMED): calling http_probe.fetch()
    directly would default to allow_redirects=True, letting a 3xx
    response silently pull the fetch onto a host that was never scope-
    checked (the exact SSRF/scope-bypass-via-redirect hole _cem_fetch()
    exists to close for CEM's own senders). fetch_with_provenance() must
    route through that SAME redirect-disabled wrapper."""
    seen = {}

    # _cem_fetch() detects support for allow_redirects via
    # inspect.signature() on the real http_probe.fetch -- the fake here
    # must declare the SAME explicit, named keyword-only parameter (not
    # **kwargs, which inspect.signature can't see by name) to faithfully
    # stand in for it.
    def _fake_fetch(url, method, headers, body, timeout_s, *, allow_redirects=True):
        seen["allow_redirects"] = allow_redirects
        return FetchResult(status=302, body="", error=None, headers={"Location": "http://169.254.169.254/"})

    monkeypatch.setattr(srv.http_probe, "fetch", _fake_fetch)
    fid = _finding()
    out = json.loads(srv.fetch_with_provenance(fid, "https://t.example/doc/1"))

    assert seen["allow_redirects"] is False
    assert out["status"] == 302
    assert out["headers"]["Location"] == "http://169.254.169.254/"


def test_fetch_with_provenance_surfaces_degraded_evidence_recording(case_db, monkeypatch):
    """Correctness-review finding: if _record_trial_wire_evidence()
    degrades to (None, None) (its own documented graceful-degradation
    path), the response must make that visible rather than silently
    returning null hashes next to no other signal -- an agent trusting
    the docstring's "evidence recorded" claim could otherwise miss that
    nothing was actually attached to the finding."""
    monkeypatch.setattr(srv.http_probe, "fetch", lambda *a, **k: FetchResult(
        status=200, body="hello", error=None, headers={}))
    monkeypatch.setattr(srv, "_record_trial_wire_evidence", lambda *a, **k: (None, None))

    fid = _finding()
    out = json.loads(srv.fetch_with_provenance(fid, "https://t.example/doc/1"))

    assert out["request_evidence_hash"] is None
    assert out["response_evidence_hash"] is None
    assert out.get("evidence_recorded") is False
