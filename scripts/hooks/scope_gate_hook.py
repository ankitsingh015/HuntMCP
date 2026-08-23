#!/usr/bin/env python3
"""Claude Code PreToolUse hook: make the scope gate structurally unskippable.

Today, scope compliance depends on each agent's system-prompt instruction to
run scripts/check-scope.sh before a Tier-2 action -- an LLM could in
principle skip that step. This hook runs the same scope_guard.py check
outside the model's control, before the tool call is allowed to execute at
all (Phase 2.8 backlog item, ARCHITECTURE.md).

Claude Code feeds {"tool_name": ..., "tool_input": {...}} on stdin before
every tool call. Exit 2 blocks the call and surfaces stderr to the agent as
the reason; exit 0 allows it.

Deliberately narrow scope, so ordinary repo development (git, go install,
pip install, editing files, curl-ing a package registry) never trips this:

- Bash commands only trigger a check when the invoked binary is one of the
  actual Tier-2 tools HuntMCP's own MCP servers shell out to (see
  mcp-servers/*/server.py's run_tool() calls) -- not any command that merely
  contains a domain-looking string.
- MCP tool calls only trigger a check for the Tier-2 (target-touching)
  servers -- writeup-mcp/memory-mcp/lessons-mcp/chainer-mcp operate on local
  knowledge, not a live target, and are exempt.
- example.com/example.org/example.net/localhost/loopback/RFC1918 hosts are
  always allowed with no engagement.yaml required -- that's normal MCP
  server development/testing, not a live engagement.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-servers"))
from scope_guard import NoEngagementFile, is_in_scope, load_engagement  # noqa: E402

# The exact binaries HuntMCP's MCP servers shell out to (mcp-servers/*/server.py
# run_tool() calls) -- the real Tier-2 boundary, not a guess.
TIER2_BASH_TOOLS = {
    "subfinder", "httpx", "katana", "nmap", "nuclei", "sqlmap", "dalfox", "ffuf",
}

# MCP servers that actually touch a live target vs. operate on local knowledge only.
TIER2_MCP_SERVERS = {
    "subfinder-mcp", "httpx-mcp", "katana-mcp", "nmap-mcp",
    "nuclei-mcp", "sqlmap-mcp", "dalfox-mcp", "ffuf-mcp", "watch-mcp",
    "waf-bypass-mcp",
}

SAFE_TEST_HOSTS = {"example.com", "example.org", "example.net", "localhost", "0.0.0.0"}

HOST_ARG_KEYS = ("domains", "domain", "target", "targets", "url", "host", "hosts")

HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


def _is_safe_test_host(host: str) -> bool:
    host = host.lower().strip(".")
    if host in SAFE_TEST_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def _first_word(command: str) -> str:
    stripped = command.strip()
    return stripped.split()[0].rsplit("/", 1)[-1] if stripped else ""


def _extract_hosts_from_bash(command: str) -> list[str]:
    if _first_word(command) not in TIER2_BASH_TOOLS:
        return []
    return [h for h in HOSTNAME_RE.findall(command) if not _is_safe_test_host(h)]


def _extract_hosts_from_tool_input(tool_input: dict) -> list[str]:
    hosts: list[str] = []
    for key in HOST_ARG_KEYS:
        val = tool_input.get(key)
        if not isinstance(val, str):
            continue
        for piece in re.split(r"[,\s]+", val):
            piece = piece.strip()
            if not piece:
                continue
            found = HOSTNAME_RE.findall(piece)
            candidate = found[0] if found else piece
            if not _is_safe_test_host(candidate):
                hosts.append(candidate)
    return hosts


def _mcp_server_name(tool_name: str) -> str:
    # Claude Code MCP tool names are "mcp__<server>__<tool>"
    parts = tool_name.split("__")
    return parts[1] if len(parts) >= 2 else ""


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0  # malformed input -- fail open, never break the session over this

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}

    if tool_name == "Bash":
        candidates = _extract_hosts_from_bash(tool_input.get("command", ""))
    elif tool_name.startswith("mcp__"):
        if _mcp_server_name(tool_name) not in TIER2_MCP_SERVERS:
            return 0
        candidates = _extract_hosts_from_tool_input(tool_input)
    else:
        return 0

    if not candidates:
        return 0

    try:
        engagement = load_engagement()
    except (NoEngagementFile, RuntimeError):
        print(
            "BLOCKED by scope gate: no engagement.yaml found, but this call "
            f"names a real-looking target host ({candidates[0]!r}). Write "
            "engagement.yaml at Phase 0 before any Tier-2 action, or use a "
            "known test host (example.com/localhost) for MCP server dev work.",
            file=sys.stderr,
        )
        return 2

    for host in candidates:
        if not is_in_scope(host, engagement):
            print(
                f"BLOCKED by scope gate: {host!r} is not in engagement.yaml's "
                f"in_scope list for {engagement.target!r}. Refusing this tool "
                "call -- do not work around this.",
                file=sys.stderr,
            )
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
