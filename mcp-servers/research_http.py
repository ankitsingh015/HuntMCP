"""The ONLY supported way to make an ad-hoc HTTP request during an engagement
(issue #131).

Hand-written probe scripts -- a custom CORS matrix, a cookie-attribute check, a
cross-account replay helper -- used to reach straight for `urllib.request`,
bypassing scope_guard, budget_guard, rate limiting, and the audit log entirely.
One real engagement's ad-hoc scripts sent ~810 requests to in-scope hosts that
`budget.json` never counted; nothing in the system would have stopped a careless
script from hammering the target at full speed. Same structural gap tool_resolver
exists to close for binary resolution: whenever research needs something outside
the fixed MCP tool roster, the safety rails must not disappear by default.

This module bundles all four controls into a requests-like get()/post() that is
one line simpler than raw urllib, so there is no incentive to reach past it:

    from research_http import get, post
    r = get(url, headers=...)    # scope + budget + rate-limit + audit, unavoidable

Enforcement order, all fail-closed BEFORE the socket opens:
  1. scope: scope_guard.outbound_policy_error() (scheme / literal
     metadata-IP pre-check) then scope_guard.is_in_scope() against the active
     engagement.yaml -- the SAME check an MCP tool does. Raises OutOfScope on
     refusal (and when there is no engagement.yaml at all: no scope, no request).
  2. budget: budget_guard.enforce("research_http") -- counts the call in the
     SAME budget.json real MCP tools use (by_tool["research_http"]) and raises
     BudgetExceeded at the hard cap. Ad-hoc volume is now visible to an auditor.
  3. rate: a minimum inter-request delay from engagement.yaml
     `min_request_interval_s` (optional; 0 = no delay), shared across separate
     script invocations via a per-engagement state file, not each script's own
     time.sleep().
  4. audit: audit_log.log_call("research_http", ...).
The request itself then goes through http_probe.fetch(), which adds the real
per-connection SSRF boundary (scope_guard.resolved_ip_policy_error, which
catches DNS-rebinding/alternate-encoding metadata that the literal pre-check in
step 1 cannot) and redirect-scope enforcement. Redirects are NOT followed by
default (allow_redirects=False) so an in-scope URL cannot 3xx the request onto
an unchecked host.

This does not replace writing a real MCP server when a capability is genuinely
reusable; it closes the gap for the one-off probe written once, used for an
hour, and thrown away.
"""

from __future__ import annotations

import json
import os
import time

import audit_log
import budget_guard
import engagement_paths
import file_lock
import http_probe
import scope_guard

RATE_STATE_FILENAME = "research-http-rate.json"


class OutOfScope(RuntimeError):
    """Raised when an ad-hoc request is refused before any socket opens --
    an out-of-scope host, a non-http(s) scheme / metadata endpoint, or no
    engagement.yaml to check scope against. Fail-closed by design."""


def _enforce_scope(url: str) -> scope_guard.Engagement:
    """Fail-closed scope check; returns the loaded engagement so the caller
    can reuse it (e.g. for the rate limit) without re-parsing engagement.yaml."""
    # Cheap literal pre-check first: scheme (blocks file:/ftp:/gopher:/data:)
    # and a literal cloud-metadata/link-local host. http_probe.fetch() still
    # does the real resolved-IP SSRF boundary below; this just refuses the
    # obvious cases before spending a budget slot.
    policy = scope_guard.outbound_policy_error(url)
    if policy:
        raise OutOfScope(f"research_http refused: {policy}")
    try:
        engagement = scope_guard.load_engagement()
    except scope_guard.NoEngagementFile as e:
        raise OutOfScope(
            "research_http refused: no engagement.yaml, so scope cannot be checked and no "
            "ad-hoc request is allowed. Write the engagement first (same gate every MCP tool uses)."
        ) from e
    except RuntimeError as e:  # e.g. PyYAML missing
        raise OutOfScope(f"research_http refused: cannot load engagement to check scope ({e}).") from e
    if not scope_guard.is_in_scope(url, engagement):
        raise OutOfScope(
            f"research_http refused: {url} is NOT in scope for engagement {engagement.target!r}. "
            "Do not work around this -- add the host to engagement.yaml in_scope if it is authorized."
        )
    return engagement


def _interval_of(engagement) -> float:
    """engagement.yaml `min_request_interval_s` (optional), as a non-negative
    float. 0.0 (the default when unset / malformed) means no forced delay --
    scope + budget still apply regardless."""
    try:
        return max(0.0, float(getattr(engagement, "min_request_interval_s", 0.0) or 0.0))
    except (TypeError, ValueError):
        return 0.0


def _wait_seconds(last_ts: float, now_ts: float, interval: float) -> float:
    """Remaining seconds to wait so consecutive requests are >= `interval`
    apart. 0 when there is no prior request (last_ts falsy), no interval, or
    the interval has already elapsed. Pure -- the testable core of the limiter."""
    if interval <= 0 or not last_ts:
        return 0.0
    return max(0.0, interval - (now_ts - last_ts))


def _rate_state_path() -> str:
    return engagement_paths.resolve(RATE_STATE_FILENAME, override_env="HUNTMCP_RESEARCH_HTTP_RATE_PATH")


def _respect_min_interval(interval: float) -> None:
    """Enforce the per-engagement minimum inter-request delay, shared across
    separate script processes via a small state file holding the last request's
    wall-clock time. The read-wait-write runs under a file lock so two scripts
    firing at once serialize instead of both skipping the delay."""
    if interval <= 0:
        return
    path = _rate_state_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with file_lock.locked(path):
        last_ts = 0.0
        try:
            with open(path) as f:
                last_ts = float((json.load(f) or {}).get("last_ts", 0.0))
        except (OSError, ValueError, TypeError):
            last_ts = 0.0
        wait = _wait_seconds(last_ts, time.time(), interval)
        if wait > 0:
            time.sleep(wait)
        try:
            with open(path, "w") as f:
                json.dump({"last_ts": time.time()}, f)
        except OSError:
            pass


def request(method: str, url: str, *, headers: dict | None = None, body: str | None = None,
            timeout_s: float = 30.0, allow_redirects: bool = False) -> http_probe.FetchResult:
    """Make one ad-hoc HTTP request with all four engagement controls applied.
    Raises OutOfScope (scope) or budget_guard.BudgetExceeded (cap) before the
    socket opens; otherwise returns the http_probe.FetchResult.

    allow_redirects defaults False: an in-scope URL must not 3xx the request
    onto an unchecked host (same stance CEM's senders take)."""
    method = method.upper()
    engagement = _enforce_scope(url)                 # 1. scope (fail-closed)
    budget_guard.enforce("research_http")            # 2. budget (raises at cap)
    _respect_min_interval(_interval_of(engagement))  # 3. rate limit (reuse loaded engagement)
    audit_log.log_call("research_http", [method, url], returncode=None,  # 4. audit
                       duration_ms=0.0, block=None)
    return http_probe.fetch(url, method, headers or {}, body, timeout_s,
                            allow_redirects=allow_redirects)


def get(url: str, *, headers: dict | None = None, timeout_s: float = 30.0,
        allow_redirects: bool = False) -> http_probe.FetchResult:
    return request("GET", url, headers=headers, timeout_s=timeout_s, allow_redirects=allow_redirects)


def post(url: str, *, headers: dict | None = None, body: str | None = None,
         timeout_s: float = 30.0, allow_redirects: bool = False) -> http_probe.FetchResult:
    return request("POST", url, headers=headers, body=body, timeout_s=timeout_s,
                   allow_redirects=allow_redirects)
