"""Test harness for the CEM benchmark target (TEST FIXTURE ONLY, no pytest import).

Provides the ONLY HTTP client the environment tests use, with a hard loopback guard so
no test (now or later) can accidentally aim the benchmark client at an external host.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse

from cem_benchmark_app import CemBenchmarkServer  # noqa: F401  (re-exported for tests)

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class ExternalTargetRefused(Exception):
    """Raised if a benchmark HTTP call is aimed at a non-loopback host."""


def _assert_loopback(url: str) -> None:
    host = urlparse(url).hostname or ""
    if host not in _LOOPBACK_HOSTS:
        raise ExternalTargetRefused(
            f"benchmark harness refuses non-loopback host {host!r} -- the CEM test "
            "environment only ever talks to 127.0.0.1 by construction"
        )


def http_get(url: str, headers: dict[str, str] | None = None, timeout: float = 5.0) -> tuple[int, str]:
    """GET returning (status, body). Loopback-only. 4xx/5xx are returned, not raised."""
    _assert_loopback(url)
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
