import asyncio
import glob
import json
import os

import pytest

import engagement_paths
import scope_guard
import session_capture


def test_capture_oauth_redirect_writes_params_not_returns_them(monkeypatch):
    eng = scope_guard.Engagement(target="target.com", in_scope=["*.target.com"])
    monkeypatch.setattr(session_capture, "_load_engagement", lambda: eng)
    monkeypatch.setattr(session_capture, "enforce", lambda *a, **k: {"ok": True})

    async def fake_cb(start_url, callback_host, **kwargs):
        return "https://app.target.com/callback?code=SENTINEL_CODE&state=xyz"

    monkeypatch.setattr(session_capture, "_capture_callback_url", fake_cb)
    out = asyncio.run(
        session_capture.capture_oauth_redirect(
            "xyz", "https://app.target.com/oauth/start", "app.target.com"
        )
    )
    assert out["captured_params"] == 2
    assert out["callback_host"] == "app.target.com"
    assert "SENTINEL_CODE" not in json.dumps(out)
    # the code DID reach disk, 0600
    files = glob.glob(os.path.join(engagement_paths.resolve("secrets/oauth"), "*.json"))
    assert files
    assert "SENTINEL_CODE" in open(files[0]).read()
    assert oct(os.stat(files[0]).st_mode)[-3:] == "600"


def test_capture_oauth_redirect_rejects_traversal_label(monkeypatch):
    eng = scope_guard.Engagement(target="target.com", in_scope=["*.target.com"])
    monkeypatch.setattr(session_capture, "_load_engagement", lambda: eng)
    monkeypatch.setattr(session_capture, "enforce", lambda *a, **k: {"ok": True})
    called = {"cb": False}

    async def fake_cb(start_url, callback_host, **kwargs):
        called["cb"] = True
        return "https://app.target.com/callback?code=X"

    monkeypatch.setattr(session_capture, "_capture_callback_url", fake_cb)
    out = asyncio.run(
        session_capture.capture_oauth_redirect(
            "../../evil", "https://app.target.com/oauth/start", "app.target.com"
        )
    )
    assert "error" in out
    assert called["cb"] is False  # rejected before any browser launch
    assert not glob.glob(os.path.join(engagement_paths.resolve("secrets/oauth"), "*.json"))


def test_safe_label_accepts_and_rejects():
    assert session_capture._safe_label("adminvikram-1") == "adminvikram-1"
    for bad in ("../x", "a/b", "a b", "", "x" * 65):
        with pytest.raises(ValueError):
            session_capture._safe_label(bad)


def test_capture_oauth_redirect_out_of_scope_refused(monkeypatch):
    eng = scope_guard.Engagement(target="target.com", in_scope=["*.target.com"])
    monkeypatch.setattr(session_capture, "_load_engagement", lambda: eng)
    monkeypatch.setattr(session_capture, "enforce", lambda *a, **k: {"ok": True})
    out = asyncio.run(
        session_capture.capture_oauth_redirect(
            "xyz", "https://evil.example.org/oauth/start", "app.target.com"
        )
    )
    assert "error" in out
