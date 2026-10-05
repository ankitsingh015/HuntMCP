"""Raw-HTTP-to-browser-driven-scan escalation tracker.

Why this exists: a CDN/bot-management platform defeated full automated
scan-template coverage even after an initial hard block was bypassed via a
request-header change -- a single manual request succeeded where the same
automated scanner, using the same bypass, still could not complete a full
run. `browser-mcp`/`playwright-mcp` (real headless-browser JS execution)
were already declared and available to the scanning specialist for exactly
this class of problem, but no playbook step defined WHEN to route to it --
reported live in an engagement retrospective as a real coverage-
completeness gap on an increasingly common class of target (CDN + bot
management in front of the origin).

This module is deliberately just the STATE TRACKING half of that fix: it
counts consecutive throttled/incomplete automated-scanner outcomes per
host (after an otherwise-successful initial bypass) and signals when the
threshold is reached. Routing that signal to an actual browser-driven scan
call is scan-agent's own playbook decision (see
.claude/agents/scan-agent.md's "WAF escalation" section) -- this module
has no tool-calling capability itself, same separation of concerns as
dedupe_check.py (tracks state, never decides what an agent does with it).

State is per-engagement, reset alongside engagement.yaml/budget.json.

CLI usage:
    python3 mcp-servers/scan_escalation.py record <host> <completed|throttled_after_bypass>
        -> JSON {consecutive_throttled, should_escalate_to_browser}
    python3 mcp-servers/scan_escalation.py check <host>
        -> JSON, same shape, without recording a new attempt
"""

from __future__ import annotations

import json
import os
import sys
import time

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

import file_lock

OUTCOMES = {"completed", "throttled_after_bypass"}

# Consecutive throttled/incomplete automated-scanner runs against the same
# host (following an otherwise-successful bypass) before signaling
# escalation to browser-driven scanning. Deliberately conservative (not 1):
# a single throttled run could be transient rate-limit backoff rather than
# sustained bot-management defeat; three in a row is a much stronger signal
# the raw-HTTP path is genuinely stuck, not just unlucky timing.
ESCALATION_THRESHOLD = 3

# Snapshot only, for introspection/backward-compat -- every function below
# re-resolves this fresh via _resolve_path() instead of using this frozen
# value (see scope_guard.load_engagement's comment for the full story).
DEFAULT_PATH = engagement_paths.resolve("scan-escalation.json", override_env="HUNTMCP_SCAN_ESCALATION_PATH")


def _resolve_path(path: str | None) -> str:
    if path is not None:
        return path
    return engagement_paths.resolve("scan-escalation.json", override_env="HUNTMCP_SCAN_ESCALATION_PATH")


def _load(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _save(state: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def _status(count: int) -> dict:
    return {"consecutive_throttled": count, "should_escalate_to_browser": count >= ESCALATION_THRESHOLD}


def record_scan_attempt(host: str, outcome: str, path: str | None = None) -> dict:
    """outcome: "completed" resets the host's counter to 0.
    "throttled_after_bypass" increments it. Returns the post-update status,
    or {"error": ...} for an unrecognized outcome (state left unchanged)."""
    if outcome not in OUTCOMES:
        return {"error": f"invalid outcome {outcome!r}, expected one of {sorted(OUTCOMES)}"}
    path = _resolve_path(path)
    with file_lock.locked(path):
        state = _load(path)
        entry = state.get(host, {"consecutive_throttled": 0})
        if outcome == "completed":
            entry["consecutive_throttled"] = 0
        else:
            entry["consecutive_throttled"] += 1
        entry["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        state[host] = entry
        _save(state, path)
        return _status(entry["consecutive_throttled"])


def should_escalate_to_browser(host: str, path: str | None = None) -> bool:
    """Read-only -- does not record a new attempt or mutate state. Still
    takes file_lock.locked() (code-review finding): _save() below is a
    plain open+write, not an atomic write-then-rename, so an unlocked read
    concurrent with a record_scan_attempt() write could observe a torn/
    partial JSON file and raise instead of returning a clean status --
    same reasoning every sibling guard module in this repo already applies
    to its own read-only accessors."""
    path = _resolve_path(path)
    with file_lock.locked(path):
        state = _load(path)
    count = state.get(host, {}).get("consecutive_throttled", 0)
    return count >= ESCALATION_THRESHOLD


def _cli() -> None:
    if len(sys.argv) < 3:
        print("usage: scan_escalation.py <record <host> <completed|throttled_after_bypass> | check <host>>",
              file=sys.stderr)
        sys.exit(2)
    cmd, host = sys.argv[1], sys.argv[2]
    if cmd == "record":
        if len(sys.argv) < 4:
            print("usage: scan_escalation.py record <host> <completed|throttled_after_bypass>", file=sys.stderr)
            sys.exit(2)
        result = record_scan_attempt(host, sys.argv[3])
        print(json.dumps(result, indent=2))
        sys.exit(1 if "error" in result else 0)
    elif cmd == "check":
        print(json.dumps({"should_escalate_to_browser": should_escalate_to_browser(host)}, indent=2))
    else:
        print(f"unknown command {cmd!r}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    _cli()
