import json
import sys
import time

import pytest

import capture_confirm
import session_capture


@pytest.fixture(autouse=True)
def _clear_registry():
    session_capture._live_captures.clear()
    yield
    session_capture._live_captures.clear()


class _Ctx:
    async def cookies(self):
        return []

    async def storage_state(self):
        return {"cookies": [], "origins": []}

    async def close(self):
        pass


class _P:
    async def stop(self):
        pass


def test_write_confirmation_refuses_non_tty(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit):
        capture_confirm.write_confirmation("slug", "xyz", "fp")


def test_verify_confirmation_missing_is_false():
    assert capture_confirm.verify_confirmation("slug", "xyz", "fp") is False


def test_verify_confirmation_fresh_match_is_true(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    capture_confirm.write_confirmation("slug", "xyz", "fp")
    assert capture_confirm.verify_confirmation("slug", "xyz", "fp") is True


def test_verify_confirmation_fingerprint_mismatch_is_false(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    capture_confirm.write_confirmation("slug", "xyz", "fp")
    assert capture_confirm.verify_confirmation("slug", "xyz", "OTHER") is False


def test_verify_confirmation_expired_is_false(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    capture_confirm.write_confirmation("slug", "xyz", "fp")
    path = capture_confirm.confirmation_token_path("slug", "xyz")
    tok = json.load(open(path))
    tok["ts"] = time.time() - 10_000
    with open(path, "w") as f:
        json.dump(tok, f)
    assert capture_confirm.verify_confirmation("slug", "xyz", "fp") is False


def test_finish_capture_refuses_without_confirmation():
    import scope_guard

    slug = session_capture._slug()
    eng = scope_guard.Engagement(target="target.com", in_scope=["*.target.com"])
    live = session_capture._LiveCapture(
        _P(), _Ctx(), None, "fp", {}, eng,
        "https://app.target.com/login", slug, "xyz", 0.0,
    )
    session_capture._live_captures[(slug, "xyz")] = live
    import asyncio

    out = asyncio.run(session_capture.finish_capture("xyz"))
    assert "error" in out and "confirm" in out["error"].lower()
    # nothing written
    import engagement_paths
    import os

    assert not os.path.isfile(engagement_paths.resolve("secrets/identities.json"))
