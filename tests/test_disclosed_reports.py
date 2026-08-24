import json
import os

import disclosed_reports
import pytest

SAMPLE_JS = disclosed_reports.JS_PREFIX + json.dumps([
    {"id": "1", "title": "XSS in search box", "program": "Example Corp",
     "researcher": "alice", "platform": "HackerOne", "url": "https://hackerone.com/reports/1",
     "vulnerabilityClass": "Cross-site scripting", "severity": "medium", "bounty": 500,
     "disclosedAt": "2026-01-01", "cves": [], "kind": "Report"},
    {"id": "2", "title": "SQLi in login", "program": "Example Corp",
     "researcher": "bob", "platform": "Bugcrowd", "url": "https://bugcrowd.com/reports/2",
     "vulnerabilityClass": "Injection", "severity": "critical", "bounty": 5000,
     "disclosedAt": "2026-02-01", "cves": ["CVE-2026-1234"], "kind": "Report"},
]) + ";"


@pytest.fixture
def cache(tmp_path, monkeypatch):
    cache_dir = str(tmp_path / "disclosed-reports-cache")
    monkeypatch.setattr(disclosed_reports, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(disclosed_reports, "CACHE_PATH", os.path.join(cache_dir, "catalog.json"))
    monkeypatch.setattr(disclosed_reports, "LAST_REFRESH_PATH", os.path.join(cache_dir, ".last_refresh"))
    return cache_dir


def _fake_urlopen(raw_text):
    class _Resp:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return raw_text.encode()
    def _open(req, timeout=None):
        return _Resp()
    return _open


def test_refresh_parses_js_wrapper_into_json(cache, monkeypatch):
    monkeypatch.setattr(disclosed_reports.urllib.request, "urlopen", _fake_urlopen(SAMPLE_JS))
    result = disclosed_reports.refresh(force=True)
    assert result["refreshed"] is True
    assert result["count"] == 2


def test_refresh_rejects_unexpected_format(cache, monkeypatch):
    monkeypatch.setattr(disclosed_reports.urllib.request, "urlopen", _fake_urlopen("<html>not js</html>"))
    result = disclosed_reports.refresh(force=True)
    assert result["refreshed"] is False
    assert "unexpected" in result["reason"]


def test_refresh_skips_when_cache_fresh(cache, monkeypatch):
    monkeypatch.setattr(disclosed_reports.urllib.request, "urlopen", _fake_urlopen(SAMPLE_JS))
    disclosed_reports.refresh(force=True)
    calls = []
    monkeypatch.setattr(disclosed_reports.urllib.request, "urlopen",
                         lambda req, timeout=None: calls.append(1) or (_ for _ in ()).throw(AssertionError("should not fetch")))
    result = disclosed_reports.refresh()
    assert result["refreshed"] is False
    assert calls == []


def test_search_filters_by_vuln_class(cache, monkeypatch):
    monkeypatch.setattr(disclosed_reports.urllib.request, "urlopen", _fake_urlopen(SAMPLE_JS))
    disclosed_reports.refresh(force=True)
    results = disclosed_reports.search(vuln_class="cross-site scripting")
    assert len(results) == 1
    assert results[0]["id"] == "1"


def test_search_filters_by_platform_case_insensitive(cache, monkeypatch):
    monkeypatch.setattr(disclosed_reports.urllib.request, "urlopen", _fake_urlopen(SAMPLE_JS))
    disclosed_reports.refresh(force=True)
    results = disclosed_reports.search(platform="bugcrowd")
    assert len(results) == 1
    assert results[0]["id"] == "2"


def test_search_filters_by_keyword(cache, monkeypatch):
    monkeypatch.setattr(disclosed_reports.urllib.request, "urlopen", _fake_urlopen(SAMPLE_JS))
    disclosed_reports.refresh(force=True)
    results = disclosed_reports.search(keyword="login")
    assert len(results) == 1
    assert results[0]["id"] == "2"


def test_search_respects_limit(cache, monkeypatch):
    monkeypatch.setattr(disclosed_reports.urllib.request, "urlopen", _fake_urlopen(SAMPLE_JS))
    disclosed_reports.refresh(force=True)
    results = disclosed_reports.search(limit=1)
    assert len(results) == 1


def test_search_empty_cache_returns_empty(cache):
    assert disclosed_reports.search(vuln_class="anything") == []
