"""Shared stdlib-only HTTP fetch primitive.

Extracted from idor-mcp/idor_sweep.py (Phase-1 UD-1=B, PHASE1-EXECUTION-PLAN task A4) so any
module under mcp-servers/ that needs a plain urllib fetch -- idor_sweep today, cem_engine in a
later task -- imports one implementation instead of duplicating it. Behavior-preserving
extraction: no change to the fetch mechanics themselves.

Uses only the standard library (urllib, socket) -- no new third-party dependency. Does import
the sibling scope_guard module (an internal project module, not an external package) for its
resolved_ip_policy_error() SSRF check -- see fetch()'s own docstring for why that check lives
here rather than purely in scope_guard's own callers.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import scan_headers
import scope_guard

DEFAULT_TIMEOUT_S = 15


@dataclass
class FetchResult:
    status: int | None
    body: str
    error: str | None = None
    # Response headers, case-preserved as sent by the server (urllib's
    # HTTPMessage is technically case-insensitive on lookup, but a plain
    # dict here is deliberately not -- callers that need case-insensitive
    # matching, e.g. a CORS check comparing header names, do their own
    # .get() with the exact casing the server sent). Additive field (default
    # empty dict) -- every existing caller (idor_sweep.py, cem_engine.py)
    # that never reads .headers is unaffected.
    headers: dict[str, str] = field(default_factory=dict)


def build_headers(cookie_header: str | None, bearer_token: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if cookie_header:
        headers["Cookie"] = cookie_header
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """redirect_request -> None means "do not follow"; the 3xx then surfaces as
    an HTTPError the caller sees as a real (non-followed) response."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


class _StripOnCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """P3-H4 destination-boundary enforcement for the redirect case: forwards
    a redirect normally (same behavior as urllib's own default handler) but
    strips any header name in `sensitive_names` before following it onto a
    DIFFERENT host than the one this fetch() call actually started with. The
    scan-identification header scan_headers attaches is only ever authorized
    for the engagement's own target -- a 3xx the target itself issues to a
    different host (CDN, OAuth provider, an open redirect) must not carry it
    along, scope_guard.is_in_scope() was never re-checked against the new
    host at all."""

    def __init__(self, sensitive_names: frozenset[str]) -> None:
        super().__init__()
        self._sensitive = {n.lower() for n in sensitive_names}

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None or not self._sensitive:
            return new_req
        if urlsplit(req.full_url).netloc == urlsplit(newurl).netloc:
            return new_req
        for name in list(new_req.headers.keys()):
            if name.lower() in self._sensitive:
                del new_req.headers[name]
        return new_req


def fetch(url: str, method: str, headers: dict[str, str], body: str | None,
          timeout_s: float, *, allow_redirects: bool = True) -> FetchResult:
    """`allow_redirects` defaults True (unchanged behaviour for idor_sweep and
    every existing caller). CEM's senders pass allow_redirects=False so a
    scope-checked in-scope URL cannot 3xx the fetch onto an unchecked host
    (SSRF / scope-bypass via redirect -- O1 final security audit).

    Before connecting, resolves `url`'s host and refuses if it resolves to a
    link-local/cloud-instance-metadata address (scope_guard.resolved_ip_policy_error)
    -- this is the real SSRF enforcement boundary for DNS-rebinding and
    alternate-IP-encoding bypasses that a caller's own earlier
    scope_guard.outbound_policy_error() pre-check cannot catch, since that
    check only ever sees the literal URL string, never what it actually
    resolves to. Every current and future caller of this shared primitive
    (idor_sweep, CEM via case-mcp's _cem_fetch, any later caller) gets this
    for free at the one real point a connection is made, rather than each
    needing to re-implement it. A resolution FAILURE is never treated as a
    refusal here -- it falls through to the real connection attempt below,
    which surfaces that same failure the way it always has."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        host = None
    if host:
        policy = scope_guard.resolved_ip_policy_error(host)
        if policy:
            return FetchResult(status=None, body="", error=f"Blocked before connecting: {policy}")
    data = body.encode() if body else None
    scan_hdrs = scan_headers.get_scan_headers(url)
    merged_headers = {**headers, **scan_hdrs} if scan_hdrs else headers
    req = urllib.request.Request(url, data=data, headers=merged_headers, method=method)
    if not allow_redirects:
        _open = _NO_REDIRECT_OPENER.open
    elif scan_hdrs:
        _open = urllib.request.build_opener(_StripOnCrossHostRedirect(frozenset(scan_hdrs))).open
    else:
        _open = urllib.request.urlopen
    try:
        with _open(req, timeout=timeout_s) as resp:
            return FetchResult(
                status=resp.status, body=resp.read().decode(errors="replace"),
                headers=dict(resp.headers.items()),
            )
    except urllib.error.HTTPError as e:
        # A 401/403/404 (the exact protected-vs-leaked signal callers care
        # about) raises HTTPError in urllib rather than returning
        # normally -- still a real, meaningful response, not a failure.
        return FetchResult(
            status=e.code, body=e.read().decode(errors="replace"),
            headers=dict(e.headers.items()) if e.headers else {},
        )
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return FetchResult(status=None, body="", error=str(e))
