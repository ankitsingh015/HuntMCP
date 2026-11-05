"""Shared fail-closed scope check for MCP servers that send requests to a target.

Before this module, case-mcp (x4), schemathesis-mcp, discspec-mcp and authz_diff each hand-copied the same
sequence: blank-URL check -> scope_guard.outbound_policy_error -> scope_guard.is_in_scope with
every evaluation error treated as a refusal. This is that core, once. It only CALLS scope_guard
(a hook-protected file) -- the scope rules themselves live there, unchanged.

check_url() returns a ScopeRefusal(kind, detail) instead of a message so each server keeps its own
wording (several tests pin those messages): kind is "empty", "policy", "verify_failed" or
"out_of_scope"; None means the URL may be requested. Nothing here ever raises for a bad URL.
"""

from __future__ import annotations

from dataclasses import dataclass

import scope_guard

EMPTY = "empty"
POLICY = "policy"
VERIFY_FAILED = "verify_failed"
OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True)
class ScopeRefusal:
    kind: str    # one of EMPTY / POLICY / VERIFY_FAILED / OUT_OF_SCOPE
    detail: str  # policy text, or "ExcClass: message" for verify_failed; "" otherwise


def resolve_engagement() -> scope_guard.Engagement:
    """The active engagement. No engagement file -> an empty Engagement (a safe test host still passes
    via is_in_scope's is_safe_test_host branch; a real host does not). Any other load failure
    propagates, so the caller fails closed."""
    try:
        return scope_guard.load_engagement()
    except scope_guard.NoEngagementFile:
        return scope_guard.Engagement(target="(no engagement.yaml)")


class EngagementResolver:
    """Resolves the engagement at most once (lazily) and remembers a failure too, so a run does not
    re-read engagement.yaml per request and a broken file keeps refusing instead of being retried."""

    def __init__(self) -> None:
        self._cache: list = []  # [Engagement] or [Exception]

    def get(self) -> scope_guard.Engagement:
        if not self._cache:
            try:
                self._cache.append(resolve_engagement())
            except Exception as e:  # noqa: BLE001 -- remember it; every call re-raises -> callers fail closed
                self._cache.append(e)
        if isinstance(self._cache[0], Exception):
            raise self._cache[0]
        return self._cache[0]


def check_url(url, engagement) -> ScopeRefusal | None:
    """`engagement` may be an Engagement or a zero-arg callable returning one (e.g. a resolver's
    .get): a callable is only invoked AFTER the blank/policy checks, so a bad URL is reported as such
    even when the engagement file is broken, and an engagement that cannot be resolved is a
    verify_failed refusal."""
    if not isinstance(url, str) or not url.strip():
        return ScopeRefusal(EMPTY, "")
    policy = scope_guard.outbound_policy_error(url)
    if policy:
        return ScopeRefusal(POLICY, policy)
    try:
        in_scope = scope_guard.is_in_scope(url, engagement() if callable(engagement) else engagement)
    except Exception as e:  # noqa: BLE001 -- any resolution/parse failure -> refuse
        return ScopeRefusal(VERIFY_FAILED, f"{e.__class__.__name__}: {e}")
    return None if in_scope else ScopeRefusal(OUT_OF_SCOPE, "")
