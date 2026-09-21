"""Loopback-only HTTP client for this fixture's own auxiliary checks
(TEST FIXTURE ONLY). Real MCP tool invocations (sqlmap/dalfox/ffuf/
nuclei/curl) use their own network paths in tests/test_p2_bench_fixture.py --
this is only for the evaluator/test file's own sanity pings."""
from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class ExternalTargetRefused(Exception):
    """Raised if a call here is aimed at a non-loopback host."""


def _assert_loopback(url: str) -> None:
    host = urlparse(url).hostname or ""
    if host not in _LOOPBACK_HOSTS:
        raise ExternalTargetRefused(
            f"bench harness refuses non-loopback host {host!r} -- this fixture only "
            "ever talks to 127.0.0.1 by construction"
        )


def http_get(url: str, headers: dict[str, str] | None = None, timeout: float = 5.0) -> tuple[int, str]:
    _assert_loopback(url)
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
