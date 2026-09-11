"""Shared stdlib-only HTTP fetch primitive.

Extracted from idor-mcp/idor_sweep.py (Phase-1 UD-1=B, PHASE1-EXECUTION-PLAN task A4) so any
module under mcp-servers/ that needs a plain urllib fetch -- idor_sweep today, cem_engine in a
later task -- imports one implementation instead of duplicating it. Behavior-preserving
extraction: no change to the fetch mechanics themselves.

Uses only the standard library (urllib) -- no new dependency.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass

DEFAULT_TIMEOUT_S = 15


@dataclass
class FetchResult:
    status: int | None
    body: str
    error: str | None = None


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


def fetch(url: str, method: str, headers: dict[str, str], body: str | None,
          timeout_s: float, *, allow_redirects: bool = True) -> FetchResult:
    """`allow_redirects` defaults True (unchanged behaviour for idor_sweep and
    every existing caller). CEM's senders pass allow_redirects=False so a
    scope-checked in-scope URL cannot 3xx the fetch onto an unchecked host
    (SSRF / scope-bypass via redirect -- O1 final security audit)."""
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    _open = urllib.request.urlopen if allow_redirects else _NO_REDIRECT_OPENER.open
    try:
        with _open(req, timeout=timeout_s) as resp:
            return FetchResult(status=resp.status, body=resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as e:
        # A 401/403/404 (the exact protected-vs-leaked signal callers care
        # about) raises HTTPError in urllib rather than returning
        # normally -- still a real, meaningful response, not a failure.
        return FetchResult(status=e.code, body=e.read().decode(errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return FetchResult(status=None, body="", error=str(e))
