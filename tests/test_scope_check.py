"""Shared scope-check core (mcp-servers/scope_check.py): the one place that turns
scope_guard.outbound_policy_error + is_in_scope into a fail-closed refusal, so the MCP servers stop
hand-copying it. It CALLS scope_guard (a hook-protected file) and never edits it."""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import scope_check  # noqa: E402
import scope_guard  # noqa: E402

ENG = scope_guard.Engagement(target="realtarget-corp.com", in_scope=["realtarget-corp.com"])


@pytest.mark.parametrize("bad", [None, "", "   ", 5, b"http://x"])
def test_blank_or_non_string_urls_are_refused_as_empty(bad):
    assert scope_check.check_url(bad, ENG).kind == "empty"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://realtarget-corp.com/x",
                                 "http://169.254.169.254/latest/meta-data", "http://[fe80::1]/"])
def test_non_http_schemes_and_metadata_addresses_are_policy_refusals(url):
    r = scope_check.check_url(url, ENG)
    assert r.kind == "policy" and r.detail


def test_an_out_of_scope_host_is_refused_and_an_in_scope_host_passes():
    assert scope_check.check_url("https://someothersite.com/x", ENG).kind == "out_of_scope"
    assert scope_check.check_url("https://realtarget-corp.com/x", ENG) is None


def test_a_safe_test_host_needs_no_engagement():
    empty = scope_guard.Engagement(target="(no engagement.yaml)")
    assert scope_check.check_url("http://127.0.0.1:8080/x", empty) is None
    assert scope_check.check_url("https://realtarget-corp.com/x", empty).kind == "out_of_scope"


def test_any_evaluation_error_fails_closed_as_verify_failed(monkeypatch):
    def boom(url, engagement):
        raise RuntimeError("parse exploded")

    monkeypatch.setattr(scope_guard, "is_in_scope", boom)
    r = scope_check.check_url("https://realtarget-corp.com/x", ENG)
    assert r.kind == "verify_failed" and "RuntimeError" in r.detail


def test_resolve_engagement_falls_back_to_an_empty_engagement_without_a_file(monkeypatch):
    def none(path=None):
        raise scope_guard.NoEngagementFile("no file")

    monkeypatch.setattr(scope_guard, "load_engagement", none)
    eng = scope_check.resolve_engagement()
    assert eng.in_scope == [] and eng.target


def test_resolve_engagement_propagates_other_failures_so_callers_fail_closed(monkeypatch):
    def broken(path=None):
        raise RuntimeError("yaml exploded")

    monkeypatch.setattr(scope_guard, "load_engagement", broken)
    with pytest.raises(RuntimeError):
        scope_check.resolve_engagement()


def test_the_resolver_loads_once_and_caches_a_failure_too(monkeypatch):
    calls = []

    def counting(path=None):
        calls.append(1)
        return ENG

    monkeypatch.setattr(scope_guard, "load_engagement", counting)
    r = scope_check.EngagementResolver()
    assert r.get() is ENG and r.get() is ENG and len(calls) == 1

    calls.clear()

    def broken(path=None):
        calls.append(1)
        raise RuntimeError("nope")

    monkeypatch.setattr(scope_guard, "load_engagement", broken)
    r2 = scope_check.EngagementResolver()
    for _ in range(2):
        with pytest.raises(RuntimeError):
            r2.get()
    assert len(calls) == 1


def test_a_callable_engagement_is_resolved_only_after_the_blank_and_policy_checks():
    called = []

    def resolver():
        called.append(1)
        return ENG

    assert scope_check.check_url("", resolver).kind == "empty"
    assert scope_check.check_url("file:///etc/passwd", resolver).kind == "policy"
    assert called == []  # a bad URL never even touched the engagement file
    assert scope_check.check_url("https://realtarget-corp.com/", resolver) is None and called == [1]


def test_an_engagement_resolver_that_raises_is_a_verify_failed_refusal():
    def resolver():
        raise RuntimeError("yaml exploded")

    r = scope_check.check_url("https://realtarget-corp.com/", resolver)
    assert r.kind == "verify_failed" and "RuntimeError" in r.detail


def test_refusal_kinds_are_named_constants_not_loose_strings():
    assert (scope_check.EMPTY, scope_check.POLICY, scope_check.VERIFY_FAILED, scope_check.OUT_OF_SCOPE) == (
        "empty", "policy", "verify_failed", "out_of_scope")
    assert scope_check.check_url("", ENG).kind == scope_check.EMPTY
    assert scope_check.check_url("file:///x", ENG).kind == scope_check.POLICY
    assert scope_check.check_url("https://nope.example.org/", ENG).kind == scope_check.OUT_OF_SCOPE
