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


def _opencode_cfg():
    raw = open(os.path.join(ROOT, "opencode.jsonc")).read()
    clean = "\n".join(ln for ln in raw.split("\n") if not ln.strip().startswith("//"))
    return json.loads(clean)


def test_mcp_registration_present_and_not_force_enabled():
    cfg = _opencode_cfg()
    assert "surface-map-mcp" in cfg["mcp"]
    # disabled-by-default: hidden in the global tools block, opt-in per agent
    assert cfg["tools"].get("surface-map-mcp*") is False


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
