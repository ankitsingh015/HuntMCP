"""C1a: case-mcp/server.py's add_evidence tool wrapper exposes the new
`provenance` param as a JSON-encoded string (same convention as
define_conditions()'s base_request/success_signature/conditions/
nonidempotent_approval params), parsed and delegated to
case_store.add_evidence()."""

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_provenance", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))


def test_add_evidence_tool_with_no_provenance_is_unchanged(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    f = json.loads(srv.create_finding("IDOR", "/doc/{id}"))
    result = json.loads(srv.add_evidence("request", "GET /doc/1", finding_id=f["id"]))
    assert "error" not in result
    assert "hash" in result


def test_add_evidence_tool_accepts_json_provenance_string(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    f = json.loads(srv.create_finding("SSRF", "/api/fetch"))
    prov = json.dumps({"class": "wire", "method": "GET", "url": "https://target.example/api/fetch"})
    result = json.loads(srv.add_evidence("request", "GET /api/fetch", finding_id=f["id"], provenance=prov))
    assert "error" not in result

    row = srv.case_store.get_evidence(result["id"])
    assert row["provenance"]["class"] == "wire"


def test_add_evidence_tool_rejects_malformed_provenance_json(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    f = json.loads(srv.create_finding("SSRF", "/api/fetch"))
    result = json.loads(srv.add_evidence("request", "x", finding_id=f["id"], provenance="{not json"))
    assert "error" in result
