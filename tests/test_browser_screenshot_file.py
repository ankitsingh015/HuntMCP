"""#164: screenshots saved as a viewable, size-capped JPEG file by default."""

import asyncio
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm  # noqa: E402
import server  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402


@pytest.fixture
def app():
    a = serve()
    yield a
    a.close()


@pytest.fixture(autouse=True)
def _no_budget(monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})


@requires_browser
def test_screenshot_to_file_is_capped_jpeg(app, tmp_path):
    r = asyncio.run(browser_confirm.screenshot_to_file(app.base_url + "/tall", wait_ms=100, out_dir=str(tmp_path)))
    assert r["error"] is None
    assert os.path.isfile(r["path"]) and r["path"].endswith(".jpg")
    with open(r["path"], "rb") as fh:
        assert fh.read(2) == b"\xff\xd8"
    assert r["height"] <= 4000 and r["width"] == 1280
    assert os.path.getsize(r["path"]) < 1_000_000
    assert r["status"] == 200


@requires_browser
def test_screenshot_tool_default_returns_path_and_provenance_last(app, tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_screenshot_dir", lambda: str(tmp_path))
    out = asyncio.run(server.screenshot(app.base_url + "/", wait_ms=100))
    assert "Screenshot saved:" in out and "Read" in out
    assert out.splitlines()[-1].startswith("Provenance (for case-mcp add_evidence):")
    assert "base64" not in out


@requires_browser
def test_screenshot_tool_as_base64_keeps_old_contract(app):
    out = asyncio.run(server.screenshot(app.base_url + "/", wait_ms=100, as_base64=True))
    assert out.startswith("data:image/png;base64,")
