import json
import os

import bounty_scope
import pytest


@pytest.fixture
def cache(tmp_path, monkeypatch):
    cache_dir = str(tmp_path / "bounty-scope-cache")
    monkeypatch.setattr(bounty_scope, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(bounty_scope, "DOMAIN_INDEX_PATH", os.path.join(cache_dir, "domain_index.json"))
    monkeypatch.setattr(bounty_scope, "SCOPE_LOG_PATH", os.path.join(cache_dir, "scope_log.jsonl"))
    monkeypatch.setattr(bounty_scope, "LAST_REFRESH_PATH", os.path.join(cache_dir, ".last_refresh"))
    return cache_dir


HACKERONE_SAMPLE = [
    {
        "name": "Example Corp",
        "url": "https://hackerone.com/example",
        "offers_bounties": True,
        "submission_state": "open",
        "targets": {
            "in_scope": [
                {"asset_identifier": "*.example.com", "asset_type": "URL",
                 "eligible_for_bounty": True, "max_severity": "critical"},
                {"asset_identifier": "com.example.app", "asset_type": "GOOGLE_PLAY_APP_ID",
                 "eligible_for_bounty": True},
            ],
        },
    },
]


def _fake_fetch(platform_urls: dict):
    def _fetch(url):
        for key, data in platform_urls.items():
            if key in url:
                return data
        return None
    return _fetch


def test_extract_domain_from_asset_identifier():
    assert bounty_scope._extract_domain({"asset_identifier": "*.example.com"}) == "*.example.com"


def test_extract_domain_skips_non_domain_asset_types():
    assert bounty_scope._extract_domain(
        {"asset_identifier": "com.example.app", "asset_type": "GOOGLE_PLAY_APP_ID"}
    ) is None


def test_extract_domain_from_url_field():
    assert bounty_scope._extract_domain({"target": "https://api.example.com/v1"}) == "api.example.com"


def test_extract_domain_handles_malformed_url_gracefully():
    assert bounty_scope._extract_domain({"target": "http://[invalid"}) is None


def test_refresh_builds_domain_index(cache, monkeypatch):
    monkeypatch.setattr(bounty_scope, "_fetch_json", _fake_fetch({"hackerone": HACKERONE_SAMPLE}))
    result = bounty_scope.refresh(force=True)
    assert result["refreshed"] is True
    assert result["domains"] == 1
    assert result["added"] == 1


def test_lookup_domain_matches_wildcard(cache, monkeypatch):
    monkeypatch.setattr(bounty_scope, "_fetch_json", _fake_fetch({"hackerone": HACKERONE_SAMPLE}))
    bounty_scope.refresh(force=True)
    matches = bounty_scope.lookup_domain("api.example.com")
    assert len(matches) == 1
    assert matches[0]["program"] == "Example Corp"
    assert matches[0]["platform"] == "hackerone"


def test_lookup_domain_no_match(cache, monkeypatch):
    monkeypatch.setattr(bounty_scope, "_fetch_json", _fake_fetch({"hackerone": HACKERONE_SAMPLE}))
    bounty_scope.refresh(force=True)
    assert bounty_scope.lookup_domain("totally-unrelated.org") == []


def test_refresh_skips_when_cache_fresh(cache, monkeypatch):
    fetch_calls = []
    def _counting_fetch(url):
        fetch_calls.append(url)
        return HACKERONE_SAMPLE if "hackerone" in url else None
    monkeypatch.setattr(bounty_scope, "_fetch_json", _counting_fetch)
    bounty_scope.refresh(force=True)
    n_calls_after_first = len(fetch_calls)
    result = bounty_scope.refresh()  # no force, cache should be fresh
    assert result["refreshed"] is False
    assert len(fetch_calls) == n_calls_after_first  # no new fetches


def test_refresh_force_true_bypasses_freshness_check(cache, monkeypatch):
    monkeypatch.setattr(bounty_scope, "_fetch_json", _fake_fetch({"hackerone": HACKERONE_SAMPLE}))
    bounty_scope.refresh(force=True)
    result = bounty_scope.refresh(force=True)
    assert result["refreshed"] is True
    assert result["added"] == 0  # same data both times


def test_refresh_detects_newly_added_domain(cache, monkeypatch):
    monkeypatch.setattr(bounty_scope, "_fetch_json", _fake_fetch({"hackerone": HACKERONE_SAMPLE}))
    bounty_scope.refresh(force=True)

    expanded = json.loads(json.dumps(HACKERONE_SAMPLE))
    expanded[0]["targets"]["in_scope"].append(
        {"asset_identifier": "new.example.com", "eligible_for_bounty": True}
    )
    monkeypatch.setattr(bounty_scope, "_fetch_json", _fake_fetch({"hackerone": expanded}))
    result = bounty_scope.refresh(force=True)
    assert result["added"] == 1
    assert result["removed"] == 0


def test_list_new_scope_reads_recent_additions(cache, monkeypatch):
    monkeypatch.setattr(bounty_scope, "_fetch_json", _fake_fetch({"hackerone": HACKERONE_SAMPLE}))
    bounty_scope.refresh(force=True)
    events = bounty_scope.list_new_scope(since_hours=1)
    assert len(events) == 1
    assert events[0]["domain"] == "*.example.com"
    assert events[0]["event"] == "added"


def test_list_new_scope_empty_when_no_log(cache):
    assert bounty_scope.list_new_scope() == []


def test_refresh_keeps_prior_cache_when_all_fetches_fail(cache, monkeypatch):
    monkeypatch.setattr(bounty_scope, "_fetch_json", _fake_fetch({"hackerone": HACKERONE_SAMPLE}))
    bounty_scope.refresh(force=True)

    monkeypatch.setattr(bounty_scope, "_fetch_json", lambda url: None)
    result = bounty_scope.refresh(force=True)
    assert result["refreshed"] is False
    assert "failed" in result["reason"]
    # prior data should still be there
    assert bounty_scope.lookup_domain("api.example.com")
