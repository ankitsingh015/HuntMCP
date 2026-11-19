"""Tests for the surface-map-mcp server wrappers and its registration.

Mirrors test_case_mcp_*: load the server via importlib and call tools directly
(this project's @app.tool() returns a callable). Isolation via the
HUNTMCP_SURFACE_MAP_PATH env the store honors.
"""
import importlib.util
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "surface_map_server", os.path.join(ROOT, "mcp-servers", "surface-map-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def test_mcp_add_then_next_untested(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SURFACE_MAP_PATH", str(tmp_path / "m.json"))
    srv.add_node("feature", "file upload", "upload:image")
    out = srv.next_untested()
    assert "file upload" in out


def _mcp_json_servers():
    return set(json.load(open(os.path.join(ROOT, ".mcp.json")))["mcpServers"].keys())


def _enabled_servers():
    d = json.load(open(os.path.join(ROOT, ".claude", "settings.json")))
    return set(d.get("enabledMcpjsonServers", []))


def test_mcp_registration_present_and_enabled():
    # Claude Code single source of truth (#160/#161): surface-map-mcp is
    # registered in .mcp.json and enabled by default in the committed
    # .claude/settings.json, so it loads in every engagement.
    assert "surface-map-mcp" in _mcp_json_servers()
    assert "surface-map-mcp" in _enabled_servers()


# --- Task 4: bind_precedent ----------------------------------------------

def test_bind_precedent_stores_on_node(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SURFACE_MAP_PATH", str(tmp_path / "m.json"))
    monkeypatch.setattr(srv, "_retrieve", lambda sig: f"PRECEDENT for {sig}: SSRF, IDOR")
    srv.add_node("feature", "webhook url", "ssrf:url-fetch")
    out = srv.bind_precedent(1)
    assert "PRECEDENT" in out
    import json
    node = json.loads(srv.get_node(1))
    assert "SSRF" in (node["precedent"] or "")
    assert node["state"] == "precedent-bound"


def test_bind_precedent_unknown_id(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SURFACE_MAP_PATH", str(tmp_path / "m.json"))
    out = srv.bind_precedent(999)
    assert "No node" in out
    import surface_map
    assert surface_map.load_map(path=str(tmp_path / "m.json")) == {"nodes": []}


def test_retrieve_loads_writeup_server_only_once(monkeypatch):
    # _retrieve must not re-import writeup-mcp (reload the embedding model) on
    # every call -- the expensive load is cached after the first call
    calls = {"n": 0}

    def fake_load():
        calls["n"] += 1
        return lambda sig: f"plan for {sig}"

    monkeypatch.setattr(srv, "_load_plan_feature", fake_load)
    monkeypatch.setattr(srv, "_PLAN_FEATURE", None)
    assert srv._retrieve("ssrf:x") == "plan for ssrf:x"
    srv._retrieve("xss:y")
    assert calls["n"] == 1


# --- mark_na (#159 coverage N/A escape valve) ------------------------------

import surface_map  # noqa: E402


def test_mark_na_stores_reason(tmp_path, monkeypatch):
    p = str(tmp_path / "m.json")
    nid = surface_map.add_node("endpoint", "/x", "ep:x", path=p)
    assert surface_map.mark_na(nid, "sqli", "no backend DB on this route", path=p) is True
    assert surface_map.get_node(nid, path=p)["na"]["sqli"] == "no backend DB on this route"


def test_mark_na_rejects_empty_reason(tmp_path):
    p = str(tmp_path / "m.json")
    nid = surface_map.add_node("endpoint", "/x", "ep:x", path=p)
    import pytest
    with pytest.raises(ValueError):
        surface_map.mark_na(nid, "sqli", "   ", path=p)


def test_mark_na_unknown_node_returns_false(tmp_path):
    p = str(tmp_path / "m.json")
    assert surface_map.mark_na(999, "sqli", "reason", path=p) is False


# --- coverage gate tools (#159) --------------------------------------------

def test_tool_is_exhausted_true_on_empty_map(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SURFACE_MAP_PATH", str(tmp_path / "m.json"))
    assert srv.is_exhausted().startswith("EXHAUSTED")


def test_tool_coverage_status_lists_open_cell_after_add_node(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SURFACE_MAP_PATH", str(tmp_path / "m.json"))
    srv.add_node("endpoint", "/api/x", "ep:x")
    status = srv.coverage_status()
    assert "open" in status.lower()
    assert "sqli" in status  # an endpoint-floor class shows as an open cell


def test_tool_mark_na_then_cell_not_open(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SURFACE_MAP_PATH", str(tmp_path / "m.json"))
    nid = int(srv.add_node("endpoint", "/api/x", "ep:x").split("#")[1].split(":")[0])
    for cls in ("xss", "sqli", "idor", "access-control", "ssrf", "open-redirect", "csrf"):
        srv.mark_na(nid, cls, "test harness: no live backend in this unit test")
    assert srv.is_exhausted().startswith("EXHAUSTED")  # all cells N/A -> exhausted


def test_tool_mark_na_rejects_empty_reason(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SURFACE_MAP_PATH", str(tmp_path / "m.json"))
    nid = int(srv.add_node("endpoint", "/api/x", "ep:x").split("#")[1].split(":")[0])
    assert srv.mark_na(nid, "sqli", "  ").startswith("Error:")
