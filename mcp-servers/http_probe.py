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


def fetch(url: str, method: str, headers: dict[str, str], body: str | None,
          timeout_s: float) -> FetchResult:
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return FetchResult(status=resp.status, body=resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as e:
        # A 401/403/404 (the exact protected-vs-leaked signal callers care
        # about) raises HTTPError in urllib rather than returning
        # normally -- still a real, meaningful response, not a failure.
        return FetchResult(status=e.code, body=e.read().decode(errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return FetchResult(status=None, body="", error=str(e))
