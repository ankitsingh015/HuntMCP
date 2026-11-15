"""MCP-server connectivity smoke check -- surfaces a failed/not-connected
declared MCP server directly, instead of it only being visible via
separate host-level diagnostics.

Why this exists: one MCP integration (bridging to an always-must-be-
running external desktop application) was configured but failed to
connect for an ENTIRE session -- reported live in an engagement
retrospective: "only visible via host-level connection diagnostics, not
communicated to the agent that had declared it as an available tool. Any
specialist relying on that integration for its intended validation
workflow silently loses that capability for the whole run; an operator
only learns this by reading system-level diagnostics, not from the
agent's own narrative or output." The suggested fix: "An agent-startup
smoke check of every declared MCP server's live connection state,
surfaced directly in the relying agent's own opening context."

This wraps `opencode mcp list` (opencode's own built-in, pure read-only
introspection of every registered server's live connection state -- no
live target contact, no engagement/session state touched) and produces
the "surfaced directly" half: a short, agent-context-ready summary
naming only the servers that AREN'T healthy, rather than a wall of status
lines the agent's own opening context would otherwise have to parse or
ignore.

Uses only the standard library -- no new dependency.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

try:
    import engagement_paths
except ImportError:  # pragma: no cover - path shim for direct execution
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

import file_lock

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

HEALTH_FILENAME = "mcp-health.json"

# Per-capability fallback chain (issue #134 part 3): when a server is down,
# degrade to these, predictably, instead of ad hoc per session. Keyed by the
# server name as it appears in opencode.jsonc / `opencode mcp list`. Recorded
# into the health snapshot for every down server so a finding can cite not
# just "primary path unavailable" but exactly what it fell back to.
CAPABILITY_FALLBACKS: dict[str, str] = {
    "burp": (
        "Repeater -> raw curl with manually-set headers; "
        "Collaborator -> oob-mcp (interactsh) for OOB callback confirmation"
    ),
    "oob-mcp": "manual interactsh-client against a controlled collaborator URL",
    "browser-mcp": "obscura-mcp (same headless-browser role), else playwright-mcp",
    "obscura-mcp": "browser-mcp (same headless-browser role), else playwright-mcp",
    "playwright-mcp": "browser-mcp / obscura-mcp for JS/DOM execution confirmation",
    "second-opinion-mcp": (
        "no automated cross-model review -- disclose the gap on the finding "
        "(pre-submission-validation, issue #135)"
    ),
}


def fallback_for(server_name: str) -> str | None:
    """The documented fallback for a down server (issue #134 part 3), or
    None if no specific fallback is recorded for it."""
    return CAPABILITY_FALLBACKS.get(server_name)

# A server status line, after ANSI stripping, has the real, distinctive
# shape "<bullet><single-char-checkmark> <name> <status>" (e.g.
# "●  ✓ writeup-mcp connected") -- requiring the SECOND token to be
# exactly one character (the ✓/✗ symbol) is what distinguishes a real
# server line from the surrounding header ("──  MCP Servers") and footer
# ("└  32 server(s)") lines, which only have ONE leading symbol token
# before a multi-character word.
#
# The status word itself is captured as ANY trailing token (\S+), not a
# hardcoded alternation of four literals (connected/failed/error/
# disconnected) -- a code-review finding, confirmed via direct
# reproduction: a status word opencode emits that isn't one of those four
# (e.g. "connecting", "pending", "timeout" -- all plausible for a server
# mid-handshake or using OAuth) used to simply not match this regex at
# all, so that server's line vanished from parse_mcp_list_output()'s
# result ENTIRELY instead of being captured as non-connected -- which
# also silently shrank the "all N connected" denominator in
# summarize_for_agent_context(), compounding the problem. Downstream code
# (find_disconnected()) already treats anything other than the literal
# string "connected" as a problem, so capturing any token here and
# comparing it downstream is both correct and strictly more robust.
_SERVER_LINE_RE = re.compile(r"^\S+\s+\S\s+([A-Za-z0-9][A-Za-z0-9_.-]*)\s+(\S+)\s*$")


def parse_mcp_list_output(raw: str) -> dict[str, str]:
    """Returns {server_name: status_word} for every server line found in
    `opencode mcp list`'s stdout, ANSI escape codes stripped first."""
    statuses: dict[str, str] = {}
    for line in _ANSI_RE.sub("", raw).splitlines():
        m = _SERVER_LINE_RE.match(line.strip())
        if m:
            statuses[m.group(1)] = m.group(2)
    return statuses


def find_disconnected(statuses: dict[str, str]) -> dict[str, str]:
    """{server_name: status} for every server NOT reporting "connected"."""
    return {name: status for name, status in statuses.items() if status != "connected"}


def summarize_for_agent_context(statuses: dict[str, str]) -> str:
    """A short summary meant to be surfaced directly in an agent's own
    opening context (per the issue's own suggested fix) -- names only the
    PROBLEM servers, not every healthy one, so this stays a one-glance
    signal rather than noise on the overwhelmingly common all-healthy
    case."""
    disconnected = find_disconnected(statuses)
    if not disconnected:
        return f"MCP connectivity: all {len(statuses)} registered server(s) connected."
    problems = ", ".join(f"{name} ({status})" for name, status in sorted(disconnected.items()))
    return (
        f"⚠️ MCP connectivity: {len(disconnected)} of {len(statuses)} registered server(s) "
        f"NOT connected: {problems}. Any tool on these servers is silently unavailable this session."
    )


def collect_live_statuses(timeout: int = 30) -> dict[str, str]:
    """Run `opencode mcp list` (opencode's own read-only introspection -- no
    live target contact, no engagement state touched) and return the parsed
    {server: status}. Returns {} if the opencode binary isn't installed, the
    command fails, or it times out -- the caller treats {} as "could not
    check," which is distinct from "all connected" (a non-empty dict with no
    disconnected entries)."""
    if not shutil.which("opencode"):
        return {}
    try:
        result = subprocess.run(
            ["opencode", "mcp", "list"], capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.TimeoutExpired, OSError):
        return {}
    if result.returncode != 0:
        return {}
    return parse_mcp_list_output(result.stdout)


def _resolve_health_path(path: str | None) -> str:
    if path is not None:
        return path
    return engagement_paths.resolve(HEALTH_FILENAME, override_env="HUNTMCP_MCP_HEALTH_PATH")


def save_health_snapshot(statuses: dict[str, str], path: str | None = None) -> dict:
    """Persist the engagement-start connectivity result into the active
    engagement's own state (issue #134 part 2), so a finding whose primary
    validation path was down can cite it from the case store rather than
    only a transient agent report. Records ONLY the problem servers (plus a
    total and timestamp), with each down server's documented fallback, and
    returns the written snapshot.

    Path resolves per-target via engagement_paths (same as budget.json /
    work-registry.json) when not given explicitly -- so it lands under
    data/engagements/<slug>/ once the engagement is set."""
    disconnected = find_disconnected(statuses)
    # `checked` distinguishes a real result from collect_live_statuses()'s {}
    # "could not check" sentinel -- without it, "the check never ran" would
    # read back identically to "all servers healthy" (both: disconnected={}),
    # letting a finding cite "nothing was down" when nothing was actually
    # checked. Callers should also avoid OVERWRITING a good prior snapshot
    # with a could-not-check one (see the huntbrain Phase 0 guard).
    snapshot = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checked": bool(statuses),
        "total": len(statuses),
        "disconnected": disconnected,
        "fallbacks": {
            name: fallback_for(name) for name in disconnected if fallback_for(name)
        },
    }
    path = _resolve_health_path(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with file_lock.locked(path):
        with open(path, "w") as f:
            json.dump(snapshot, f, indent=2)
    return snapshot


def load_health_snapshot(path: str | None = None) -> dict:
    """Read back the persisted health snapshot (or {} if none was recorded /
    it's unreadable). Never raises -- a missing or corrupt snapshot just
    means "no recorded health info," not an error."""
    path = _resolve_health_path(path)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def unavailable_servers(path: str | None = None) -> dict[str, str]:
    """{server: status} for every declared MCP server that was NOT connected
    at the engagement-start health-check -- for case/report code to cite a
    'primary validation path unavailable' note on a finding (issue #134 part
    2). {} when all were healthy or no snapshot was recorded."""
    return load_health_snapshot(path).get("disconnected", {})
