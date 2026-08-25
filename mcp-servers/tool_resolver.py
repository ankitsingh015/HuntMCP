"""Resolve tool binary paths for MCP servers.

MCP servers call external tools (subfinder, httpx, etc.) via subprocess.
This module ensures they find the correct binary even when Python packages
shadow the Go/system binary names (e.g., Python httpx vs ProjectDiscovery httpx).
"""

import os
import re
import shutil
import subprocess
import time

from audit_log import log_call as _log_call
from budget_guard import enforce as _enforce_budget

GO_BIN = os.path.expanduser("~/go/bin")
GO_BIN_CANDIDATES = [
    GO_BIN,
    "/usr/local/go/bin",
    "/usr/lib/go/bin",
    "/snap/go/current/bin",
]

# Reactive-only signals. run_tool() never adds a delay unless one of these
# actually shows up in the tool's output — full speed by default, back off
# only when the target signals it. Deliberately NOT a proactive per-request
# sleep: that trades away real recon/scan speed for a problem that mostly
# never happens.
_RATE_LIMIT_PATTERNS = [
    re.compile(r"\b429\b"),
    re.compile(r"too many requests", re.I),
    re.compile(r"rate.?limit", re.I),
]
_WAF_BLOCK_PATTERNS = [
    re.compile(r"\b403\b.*(forbidden|blocked)", re.I),
    re.compile(r"cloudflare|akamai|imperva|incapsula", re.I),
    re.compile(r"access denied|request blocked|attack detected", re.I),
]


def classify_block(output: str) -> str | None:
    """Inspect tool stdout/stderr for a blocking signal. Returns 'rate_limit',
    'waf', or None. This is the only thing that should ever trigger a delay —
    never a blanket per-request sleep."""
    if not output:
        return None
    for pattern in _RATE_LIMIT_PATTERNS:
        if pattern.search(output):
            return "rate_limit"
    for pattern in _WAF_BLOCK_PATTERNS:
        if pattern.search(output):
            return "waf"
    return None


def resolve_tool(name: str) -> str:
    """Resolve a tool binary path, preferring Go/system binaries over Python wrappers."""
    # First check ~/go/bin directly (fast path)
    go_path = os.path.join(GO_BIN, name)
    if os.path.isfile(go_path) and os.access(go_path, os.X_OK):
        return go_path

    # Use shutil.which but exclude Python wrappers
    result = shutil.which(name)
    if result:
        return result

    # Search Go bin candidates
    for candidate in GO_BIN_CANDIDATES:
        candidate_path = os.path.join(candidate, name)
        if os.path.isfile(candidate_path) and os.access(candidate_path, os.X_OK):
            return candidate_path

    return name


def run_tool(
    name: str,
    args: list[str],
    retry_on_rate_limit: bool = True,
    **kwargs,
) -> subprocess.CompletedProcess:
    """Run a tool with the resolved binary path. No artificial delay is added
    up front. If the output signals an actual rate limit (429 / "rate limit"
    text), back off 5s and retry exactly once, per the master prompt's Phase
    21.5 decision tree — never more than one silent retry, since a second
    block means something else is wrong.

    If the output signals a WAF/bot-detection block instead of a rate limit,
    this does NOT sleep-and-hope: it returns as-is so the calling MCP server
    or agent can escalate to real bypass tooling (header/path tricks, or a
    browser-driven tool like Playwright for JS-challenge WAFs) rather than
    silently waiting on something a sleep won't fix. Use classify_block() on
    the result to check which case happened.

    Every call is recorded against the per-engagement budget circuit-breaker
    (mcp-servers/budget_guard.py) BEFORE the subprocess runs -- this is the
    single chokepoint all Tier-2 MCP servers share, so it's where a stuck
    loop or runaway attack surface actually gets caught. Raises
    BudgetExceeded instead of running the tool once the hard cap is hit.
    """
    _enforce_budget(name)
    binary = resolve_tool(name)
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    start = time.monotonic()
    result = subprocess.run([binary, *args], **kwargs)

    block = None
    if retry_on_rate_limit:
        combined = (result.stdout or "") + (result.stderr or "")
        block = classify_block(combined)
        if block == "rate_limit":
            time.sleep(5)
            result = subprocess.run([binary, *args], **kwargs)
            # Re-classify the retry's own output rather than assuming it
            # succeeded -- the retry can still be rate-limited (or now hit a
            # WAF), and logging block=None unconditionally here made the
            # audit trail claim it wasn't.
            combined = (result.stdout or "") + (result.stderr or "")
            block = classify_block(combined)

    _log_call(name, args, result.returncode, (time.monotonic() - start) * 1000, block)
    return result
