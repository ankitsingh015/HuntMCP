"""Session keep-alive wiring: MCP tools exist, the UI-walk renews on auth_lost,
and the agents that hold browser-mcp are told to renew before asking a human."""

import asyncio
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm  # noqa: E402
import server  # noqa: E402
import ui_walk  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402

AGENTS = os.path.join(ROOT, ".claude", "agents")


def _read(name):
    with open(os.path.join(AGENTS, name)) as fh:
        return fh.read()


def test_tools_registered():
    names = {t.name for t in asyncio.run(server.app.list_tools())}
    assert {"refresh_session", "session_health", "start_keepalive", "stop_keepalive"} <= names


def test_recon_agent_refreshes_before_relogin():
    t = _read("recon-agent.md")
    assert "refresh_session(<label>)" in t and "needs_human_login" in t


def test_exploit_agent_keeps_identities_alive():
    t = _read("exploit-agent.md")
    assert "start_keepalive" in t and "refresh_session(label)" in t and "needs_human_login" in t
    assert "ONE ask" in t


def test_huntbrain_passes_labels_not_relogin():
    t = _read("huntbrain.md")
    assert "start_keepalive" in t and "needs_human_login" in t


def test_refresh_hook_ignores_non_identity_file(tmp_path, monkeypatch):
    called = []
    import session_refresh

    async def fake(label, slug=None):
        called.append(label)

    monkeypatch.setattr(session_refresh, "refresh_session", fake)
    asyncio.run(ui_walk._refresh_identity_session(str(tmp_path / "random.json")))
    asyncio.run(ui_walk._refresh_identity_session(""))
    assert called == []


def test_refresh_hook_never_raises(monkeypatch):
    import session_refresh

    def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(session_refresh, "label_for_session_file", boom)
    asyncio.run(ui_walk._refresh_identity_session("/x/y.json"))


@requires_browser
def test_ui_walk_auth_lost_calls_refresh_then_continues(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve()
    sess = tmp_path / "xyz.json"
    sess.write_text(json.dumps({"cookies": [{"name": "sid", "value": "expired", "domain": "127.0.0.1",
                                             "path": "/"}], "origins": []}))
    calls = []

    async def fake_refresh(session_file):
        # stand-in for a successful silent renewal: a valid session lands in the file
        calls.append(session_file)
        sid = app.login_cookie().split("=", 1)[1]
        sess.write_text(json.dumps({"cookies": [{"name": "sid", "value": sid, "domain": "127.0.0.1",
                                                 "path": "/"}], "origins": []}))

    monkeypatch.setattr(ui_walk, "_refresh_identity_session", fake_refresh)
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/items", "map", scope_check=lambda u: True,
                                       screenshot_dir=str(tmp_path), session_file=str(sess), max_pages=3))
    finally:
        app.close()
    assert calls == [str(sess)]
    assert inv["status"] != "auth_lost", inv.get("error")
