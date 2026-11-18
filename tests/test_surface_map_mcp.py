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
