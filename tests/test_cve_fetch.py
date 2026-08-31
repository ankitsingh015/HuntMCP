"""Regression tests for cve_fetch._fetch_json's retry behavior.

Bug found live (2026-08-31, coderabbit.ai engagement): a connection reset
while fetching CVEs from NVD propagated immediately with zero retries,
despite _fetch_json's `retries` parameter implying it should retry
transient failures. Root cause: the retry loop only caught
urllib.error.HTTPError (for the 403/429 rate-limit case) -- a plain
URLError/TimeoutError/ConnectionResetError (no HTTP response at all) fell
straight through uncaught.
"""
import importlib.util
import json
import os
import urllib.error

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "cve_fetch", os.path.join(ROOT, "mcp-servers", "writeup-mcp", "cve_fetch.py"),
)
cve_fetch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cve_fetch)


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_json_retries_on_connection_reset(monkeypatch):
    """A ConnectionResetError on the first attempt must not be fatal --
    _fetch_json should retry and succeed on the second attempt, same as it
    already does for a 429."""
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionResetError("connection reset by peer")
        return _FakeResponse({"ok": True})

    monkeypatch.setattr(cve_fetch.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(cve_fetch.time, "sleep", lambda s: None)

    result = cve_fetch._fetch_json("https://example.invalid/x", {}, retries=3)
    assert result == {"ok": True}
    assert len(calls) == 2


def test_fetch_json_retries_on_url_error_then_raises_after_exhausting(monkeypatch):
    """A persistent URLError (e.g. DNS failure, timeout) across every
    attempt should still raise -- just after actually retrying, not
    immediately on the first failure."""
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(1)
        raise urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(cve_fetch.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(cve_fetch.time, "sleep", lambda s: None)

    with pytest.raises(urllib.error.URLError):
        cve_fetch._fetch_json("https://example.invalid/x", {}, retries=3)
    assert len(calls) == 3


def test_fetch_json_still_retries_on_429_rate_limit(monkeypatch):
    """Regression guard: the original 403/429 retry-with-backoff behavior
    must survive this fix unchanged."""
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError(req.full_url, 429, "rate limited", {}, None)
        return _FakeResponse({"ok": True})

    monkeypatch.setattr(cve_fetch.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(cve_fetch.time, "sleep", lambda s: None)

    result = cve_fetch._fetch_json("https://example.invalid/x", {}, retries=3)
    assert result == {"ok": True}
    assert len(calls) == 2
