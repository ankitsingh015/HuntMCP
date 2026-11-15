"""Issue #131: research_http is the ONLY supported way to make an ad-hoc HTTP
request during an engagement. Hand-written probe scripts used to call
urllib.request directly, bypassing scope_guard, budget_guard, the rate limit,
and the audit log (one engagement's ad-hoc scripts sent ~810 uncounted
requests). Every get()/post() must enforce all four, fail-closed, BEFORE the
socket opens -- these tests pin that the safety rails cannot be skipped."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import http_probe  # noqa: E402
import research_http  # noqa: E402


class _Eng:
    def __init__(self, in_scope, min_interval=0.0):
        self.target = "acme-corp.com"
        self.in_scope = in_scope
        self.out_of_scope = []
        self.min_request_interval_s = min_interval


@pytest.fixture
def budget(tmp_path, monkeypatch):
    path = str(tmp_path / "budget.json")
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", path)
    return path


@pytest.fixture
def audit(tmp_path, monkeypatch):
    path = str(tmp_path / "audit.jsonl")
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", path)
    return path


@pytest.fixture
def no_real_fetch(monkeypatch):
    """Record fetch calls instead of opening a socket."""
    calls = []

    def fake_fetch(url, method, headers, body, timeout_s, *, allow_redirects=True):
        calls.append({"url": url, "method": method, "headers": headers,
                      "body": body, "allow_redirects": allow_redirects})
        return http_probe.FetchResult(status=200, body="ok", headers={})

    monkeypatch.setattr(research_http.http_probe, "fetch", fake_fetch)
    return calls


def _scope(monkeypatch, eng):
    monkeypatch.setattr(research_http.scope_guard, "load_engagement", lambda *a, **k: eng)


# ---- scope enforcement (fail-closed) -----------------------------------------

def test_out_of_scope_url_is_refused_and_opens_no_socket(monkeypatch, budget, audit, no_real_fetch):
    _scope(monkeypatch, _Eng(in_scope=["acme-corp.com"]))
    with pytest.raises(research_http.OutOfScope):
        research_http.get("https://not-in-scope.example/x")
    assert no_real_fetch == []  # never fetched
    assert not os.path.exists(budget)  # no budget spent on an out-of-scope URL


def test_missing_engagement_refuses_every_request(monkeypatch, budget, audit, no_real_fetch):
    def boom(*a, **k):
        raise research_http.scope_guard.NoEngagementFile("no engagement.yaml")
    monkeypatch.setattr(research_http.scope_guard, "load_engagement", boom)
    with pytest.raises(research_http.OutOfScope):
        research_http.get("https://acme-corp.com/x")
    assert no_real_fetch == []


def test_non_http_scheme_and_metadata_host_are_refused(monkeypatch, budget, audit, no_real_fetch):
    _scope(monkeypatch, _Eng(in_scope=["acme-corp.com"]))
    for bad in ("file:///etc/passwd", "http://169.254.169.254/latest/meta-data/"):
        with pytest.raises(research_http.OutOfScope):
            research_http.get(bad)
    assert no_real_fetch == []


# ---- in-scope request enforces budget + audit + goes through http_probe ------

def test_in_scope_request_counts_budget_audits_and_fetches(monkeypatch, budget, audit, no_real_fetch):
    _scope(monkeypatch, _Eng(in_scope=["acme-corp.com"]))
    r = research_http.get("https://acme-corp.com/api", headers={"X-Test": "1"})
    assert r.status == 200
    # same budget.json real MCP tools use, under a research_http by_tool entry
    state = json.load(open(budget))
    assert state["by_tool"]["research_http"] == 1
    assert state["calls"] == 1
    # audit trail written
    assert os.path.isfile(audit) and "research_http" in open(audit).read()
    # went through http_probe.fetch with our header, and redirects OFF by default
    assert no_real_fetch[0]["url"] == "https://acme-corp.com/api"
    assert no_real_fetch[0]["headers"]["X-Test"] == "1"
    assert no_real_fetch[0]["allow_redirects"] is False


def test_post_sends_method_and_body(monkeypatch, budget, audit, no_real_fetch):
    _scope(monkeypatch, _Eng(in_scope=["acme-corp.com"]))
    research_http.post("https://acme-corp.com/x", body='{"a":1}', headers={})
    assert no_real_fetch[0]["method"] == "POST"
    assert no_real_fetch[0]["body"] == '{"a":1}'


def test_budget_cap_raises_before_any_fetch(monkeypatch, budget, audit, no_real_fetch):
    _scope(monkeypatch, _Eng(in_scope=["acme-corp.com"]))
    import budget_guard
    monkeypatch.setattr(budget_guard, "MAX_CALLS", 2)  # cap bound at import; patch the attr
    research_http.get("https://acme-corp.com/1")  # 1st call ok
    with pytest.raises(budget_guard.BudgetExceeded):
        research_http.get("https://acme-corp.com/2")  # 2nd call hits the cap
    assert len(no_real_fetch) == 1  # the over-budget call never fetched


# ---- rate limiter ------------------------------------------------------------

def test_wait_seconds_is_zero_without_a_prior_request_or_interval():
    assert research_http._wait_seconds(last_ts=0.0, now_ts=100.0, interval=2.0) == 0.0
    assert research_http._wait_seconds(last_ts=100.0, now_ts=100.5, interval=0.0) == 0.0


def test_wait_seconds_waits_out_the_remaining_interval():
    # 0.5s elapsed of a 2s minimum -> wait 1.5s
    assert research_http._wait_seconds(last_ts=100.0, now_ts=100.5, interval=2.0) == pytest.approx(1.5)
    # already past the interval -> no wait
    assert research_http._wait_seconds(last_ts=100.0, now_ts=103.0, interval=2.0) == 0.0


def test_load_engagement_sources_min_request_interval_from_yaml(tmp_path):
    import scope_guard
    p = tmp_path / "engagement.yaml"
    p.write_text("target: acme-corp.com\nin_scope:\n  - acme-corp.com\nmin_request_interval_s: 1.5\n")
    assert scope_guard.load_engagement(str(p)).min_request_interval_s == 1.5
    # malformed / missing -> 0.0, never a crash (load runs on every scope check)
    p.write_text("target: acme-corp.com\nin_scope:\n  - acme-corp.com\nmin_request_interval_s: nope\n")
    assert scope_guard.load_engagement(str(p)).min_request_interval_s == 0.0
    p.write_text("target: acme-corp.com\nin_scope:\n  - acme-corp.com\n")
    assert scope_guard.load_engagement(str(p)).min_request_interval_s == 0.0


def test_min_interval_delay_is_enforced_and_persists(monkeypatch, tmp_path, budget, audit, no_real_fetch):
    _scope(monkeypatch, _Eng(in_scope=["acme-corp.com"], min_interval=2.0))
    monkeypatch.setenv("HUNTMCP_RESEARCH_HTTP_RATE_PATH", str(tmp_path / "rate.json"))
    slept = []
    monkeypatch.setattr(research_http.time, "sleep", lambda s: slept.append(s))
    clock = {"t": 1000.0}
    monkeypatch.setattr(research_http.time, "time", lambda: clock["t"])

    research_http.get("https://acme-corp.com/1")  # first: no prior, no wait
    assert slept == []
    clock["t"] = 1000.5  # 0.5s later
    research_http.get("https://acme-corp.com/2")  # must wait out 1.5s of the 2s minimum
    assert slept and slept[-1] == pytest.approx(1.5)
