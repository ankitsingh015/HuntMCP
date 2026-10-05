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

import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

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
