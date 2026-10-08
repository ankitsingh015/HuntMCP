"""C1b: case-mcp/server.py's capture_research_manifest/get_research_manifest
tool wrappers -- thin JSON-string wrappers over research_manifest.py +
case_store's new persistence functions."""

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_research_manifest", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))


def test_capture_research_manifest_returns_valid_json_with_manifest_id(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    result = json.loads(srv.capture_research_manifest("example.com"))
    assert result["target"] == "example.com"
    assert "manifest_id" in result
    assert "tool_versions" in result


def test_get_research_manifest_round_trips_the_captured_one(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    srv.capture_research_manifest("example.com")

    fetched = json.loads(srv.get_research_manifest("example.com"))
    assert fetched["target"] == "example.com"
    assert fetched["manifest"]["target"] == "example.com"


def test_get_research_manifest_says_not_found_when_absent(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    result = srv.get_research_manifest("never-captured.example.com")
    assert "No research manifest" in result
    assert "never-captured.example.com" in result


def test_capture_research_manifest_does_not_require_scope_gate_clearance(tmp_path, monkeypatch):
    """No `url` param, no outbound request to the target -- this tool
    must stay out of TIER2_MCP_TOOLS['case-mcp'], unlike fetch_with_
    provenance/determinism_gate/run_counterfactual."""
    sys.path.insert(0, os.path.join(ROOT, "scripts", "hooks"))
    import scope_gate_hook

    assert "capture_research_manifest" not in scope_gate_hook.TIER2_MCP_TOOLS.get("case-mcp", frozenset())
    assert "get_research_manifest" not in scope_gate_hook.TIER2_MCP_TOOLS.get("case-mcp", frozenset())
