import json
import os

import disclosure_lookup
import pytest

PLATFORM_YAML = """
companies:
- company: Example Corp
  url: https://example.com/security
  contact: mailto:security@example.com
  rewards:
  - '*bounty'
  safe_harbor: full
  program_type: bounty
  status: active
"""

INDEPENDENT_YAML = """
companies:
- company: Standalone Co
  url: https://standalone.example/vdp
  contact: https://standalone.example/report
  rewards: []
  safe_harbor: partial
  domains:
  - www.standalone.example (Main site)
  - All subdomains (*.standalone.example)
"""


@pytest.fixture
def cache(tmp_path, monkeypatch):
    cache_dir = str(tmp_path / "disclosure-lookup-cache")
    monkeypatch.setattr(disclosure_lookup, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(disclosure_lookup, "CACHE_PATH", os.path.join(cache_dir, "companies.json"))
    monkeypatch.setattr(disclosure_lookup, "LAST_REFRESH_PATH", os.path.join(cache_dir, ".last_refresh"))
    return cache_dir


def _fake_urlopen(by_filename: dict[str, str]):
    class _Resp:
        def __init__(self, text):
            self._text = text
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def read(self):
            return self._text.encode()

    def _open(req, timeout=None):
        for filename, text in by_filename.items():
            if filename in req.full_url:
                return _Resp(text)
        raise AssertionError(f"unexpected URL: {req.full_url}")
    return _open


def test_refresh_merges_both_sources_and_tags_by_source(cache, monkeypatch):
    monkeypatch.setattr(
        disclosure_lookup.urllib.request, "urlopen",
        _fake_urlopen({"platform-programs.yml": PLATFORM_YAML, "independent-programs.yml": INDEPENDENT_YAML}),
    )
    result = disclosure_lookup.refresh(force=True)
    assert result["refreshed"] is True
    assert result["companies"] == 2
    assert result["failed_sources"] == []

    cached = disclosure_lookup._load_cache()
    sources = {c["_source"] for c in cached}
    assert sources == {"platform", "independent"}


def test_refresh_skips_when_cache_fresh(cache, monkeypatch):
    monkeypatch.setattr(
        disclosure_lookup.urllib.request, "urlopen",
        _fake_urlopen({"platform-programs.yml": PLATFORM_YAML, "independent-programs.yml": INDEPENDENT_YAML}),
    )
    disclosure_lookup.refresh(force=True)
    monkeypatch.setattr(
        disclosure_lookup.urllib.request, "urlopen",
        lambda req, timeout=None: (_ for _ in ()).throw(AssertionError("should not fetch when cache is fresh")),
    )
    result = disclosure_lookup.refresh(force=False)
    assert result["refreshed"] is False
    assert result["reason"] == "cache still fresh"


def test_refresh_one_source_failing_keeps_the_other(cache, monkeypatch):
    def _open(req, timeout=None):
        if "independent-programs.yml" in req.full_url:
            import urllib.error
            raise urllib.error.URLError("simulated failure")
        return _fake_urlopen({"platform-programs.yml": PLATFORM_YAML})(req, timeout)

    monkeypatch.setattr(disclosure_lookup.urllib.request, "urlopen", _open)
    result = disclosure_lookup.refresh(force=True)
    assert result["refreshed"] is True
    assert result["companies"] == 1
    assert len(result["failed_sources"]) == 1
    assert "independent" in result["failed_sources"][0]


def test_refresh_both_sources_failing_reports_not_refreshed(cache, monkeypatch):
    import urllib.error

    def _open(req, timeout=None):
        raise urllib.error.URLError("simulated failure")

    monkeypatch.setattr(disclosure_lookup.urllib.request, "urlopen", _open)
    result = disclosure_lookup.refresh(force=True)
    assert result["refreshed"] is False
    assert result["companies"] == 0
    assert len(result["failed_sources"]) == 2


def test_lookup_matches_by_url_hostname(cache, monkeypatch):
    monkeypatch.setattr(
        disclosure_lookup.urllib.request, "urlopen",
        _fake_urlopen({"platform-programs.yml": PLATFORM_YAML, "independent-programs.yml": INDEPENDENT_YAML}),
    )
    disclosure_lookup.refresh(force=True)
    matches = disclosure_lookup.lookup("example.com")
    assert len(matches) == 1
    assert matches[0]["company"] == "Example Corp"
    assert matches[0]["source"] == "platform"


def test_lookup_matches_by_subdomain_of_url_hostname(cache, monkeypatch):
    # url hostname is "example.com" -- a query for a SUBDOMAIN of that
    # (the program's bounty page lives at the apex, but plausibly covers
    # subdomains too) should still match.
    monkeypatch.setattr(
        disclosure_lookup.urllib.request, "urlopen",
        _fake_urlopen({"platform-programs.yml": PLATFORM_YAML, "independent-programs.yml": "companies: []"}),
    )
    disclosure_lookup.refresh(force=True)
    matches = disclosure_lookup.lookup("sub.example.com")
    assert len(matches) == 1
    assert matches[0]["company"] == "Example Corp"


def test_lookup_matches_free_text_domains_field(cache, monkeypatch):
    monkeypatch.setattr(
        disclosure_lookup.urllib.request, "urlopen",
        _fake_urlopen({"platform-programs.yml": "companies: []", "independent-programs.yml": INDEPENDENT_YAML}),
    )
    disclosure_lookup.refresh(force=True)
    matches = disclosure_lookup.lookup("standalone.example")
    assert len(matches) == 1
    assert matches[0]["company"] == "Standalone Co"
    assert matches[0]["source"] == "independent"


def test_lookup_no_match_returns_empty_list(cache, monkeypatch):
    monkeypatch.setattr(
        disclosure_lookup.urllib.request, "urlopen",
        _fake_urlopen({"platform-programs.yml": PLATFORM_YAML, "independent-programs.yml": INDEPENDENT_YAML}),
    )
    disclosure_lookup.refresh(force=True)
    assert disclosure_lookup.lookup("totally-unrelated-domain.com") == []


def test_lookup_returns_empty_before_any_refresh(cache):
    assert disclosure_lookup.lookup("example.com") == []


def test_matches_case_insensitive():
    entry = {"company": "Example", "url": "https://Example.COM/security", "domains": []}
    assert disclosure_lookup._matches(entry, "example.com") is True


def test_matches_strips_wildcard_prefix_from_query():
    entry = {"company": "Example", "url": "https://example.com", "domains": []}
    assert disclosure_lookup._matches(entry, "*.example.com") is True
