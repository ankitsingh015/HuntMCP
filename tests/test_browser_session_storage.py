"""#164: sessionStorage persistence/restore + session_storage seed for browser-mcp.

Reproduces the bentley "logged-out shell" class of bug on a local fixture: an
SPA keeping its OIDC user in sessionStorage renders logged-out from a saved
session_file, because Playwright's storage_state drops sessionStorage.
"""

import asyncio
import json
import os
import stat
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm
from ui_walk_app import requires_browser, serve


@pytest.fixture
def app():
    a = serve()
    yield a
    a.close()


@pytest.fixture(autouse=True)
def _no_budget(monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})


def _render(url, **kw):
    return asyncio.run(browser_confirm.render_dom(url, wait_selector="#spa *", **kw))


@requires_browser
def test_session_storage_survives_save_and_restore(app, tmp_path):
    f = str(tmp_path / "s.json")
    asyncio.run(browser_confirm.render_dom(app.base_url + "/app/login", wait_selector="#spa *", session_file=f))
    r = _render(app.base_url + "/app", session_file=f)
    assert r["error"] is None
    assert "<p>Welcome, alice</p>" in r["html"]


@requires_browser
def test_session_storage_seed_param(app):
    r = _render(app.base_url + "/app", session_storage={"oidc.user": json.dumps({"name": "alice"})})
    assert r["error"] is None
    assert "<p>Welcome, alice</p>" in r["html"]


@requires_browser
def test_session_storage_is_origin_guarded(app, tmp_path):
    f = str(tmp_path / "s.json")
    asyncio.run(browser_confirm.render_dom(app.base_url + "/app/login", wait_selector="#spa *", session_file=f))
    r = _render(app.alt_base_url + "/app", session_file=f)
    assert "<button>Sign in</button>" in r["html"]
    assert "<p>Welcome, alice</p>" not in r["html"]


@requires_browser
def test_session_file_is_0600_after_save(app, tmp_path):
    f = str(tmp_path / "s.json")
    _render(app.base_url + "/app", session_file=f)
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600


@requires_browser
def test_session_file_records_session_storage_sidecar(app, tmp_path):
    f = str(tmp_path / "s.json")
    asyncio.run(browser_confirm.render_dom(app.base_url + "/app/login", wait_selector="#spa *", session_file=f))
    with open(f) as fh:
        data = json.load(fh)
    side = data[browser_confirm.SESSION_STORAGE_KEY]
    assert "oidc.user" in side[app.base_url]


@requires_browser
def test_existing_session_file_without_sidecar_still_loads(app, tmp_path):
    f = tmp_path / "old.json"
    f.write_text(json.dumps({"cookies": [], "origins": []}))
    r = _render(app.base_url + "/app", session_file=str(f))
    assert r["error"] is None
    assert "<button>Sign in</button>" in r["html"]
