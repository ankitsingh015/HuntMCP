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
  mcp-servers/*/server.py's run_tool() calls), plus curl/wget -- not any
  command that merely contains a domain-looking string. curl/wget are
  included even though no dedicated MCP server wraps them, because they are
  the most direct unguarded path to a live target -- a raw `curl
  https://target.com/...` was previously invisible to this hook entirely.
- MCP tool calls only trigger a check for the Tier-2 (target-touching)
  servers -- writeup-mcp/memory-mcp/lessons-mcp/chainer-mcp operate on local
  knowledge, not a live target, and are exempt.
- example.com/example.org/example.net/localhost/loopback/RFC1918 hosts, plus
  a small allowlist of known dev infrastructure (GitHub, PyPI, npm, Go
  module proxy, Debian/Ubuntu package mirrors -- see DEV_INFRA_HOSTS), are
  always allowed with no engagement.yaml required -- that's normal
  development/testing, not a live engagement.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "mcp-servers"))
from audit_log import log_call as _log_call  # noqa: E402
from budget_guard import BudgetExceeded  # noqa: E402
from budget_guard import enforce as _enforce_budget  # noqa: E402
from scope_guard import NoEngagementFile, is_in_scope, load_engagement  # noqa: E402

# The exact binaries HuntMCP's MCP servers shell out to (mcp-servers/*/server.py
# run_tool() calls) -- the real Tier-2 boundary, not a guess. curl/wget are
# added separately below: unlike the others, they're not wrapped by any
# dedicated MCP server today, so a raw `curl https://target.com/...` was a
# genuine unguarded path to a live target, not just a defense-in-depth
# duplicate of an MCP wrapper. Found 2026-08-26 while reviewing an external
# skill library (uphiago/recon-skills) whose procedures are curl-heavy --
# adopting that style of content without this fix would have made scope
# enforcement bypassable by construction.
TIER2_BASH_TOOLS = {
    "subfinder", "httpx", "katana", "nmap", "nuclei", "sqlmap", "dalfox", "ffuf",
    "curl", "wget",
}

# curl/wget also legitimately touch non-target infrastructure during ordinary
# MCP-server development -- package registries, source hosting, docs -- which
# must stay exempt the same way SAFE_TEST_HOSTS exempts example.com/localhost.
# Kept separate from content_scanner.py's KNOWN_GOOD_HOSTS (that allowlist is
# for outbound calls made BY this repo's own Python code to known service
# integrations; this one is for a human/agent curl-ing the open internet
# during development -- different concern, deliberately not shared).
DEV_INFRA_HOSTS = {
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "api.github.com", "codeload.github.com",
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "nodejs.org",
    "golang.org", "proxy.golang.org", "go.dev",
    "deb.debian.org", "archive.ubuntu.com", "security.ubuntu.com",
}

# MCP servers that actually touch a live target vs. operate on local knowledge only.
TIER2_MCP_SERVERS = {
    "subfinder-mcp", "httpx-mcp", "katana-mcp", "nmap-mcp",
    "nuclei-mcp", "sqlmap-mcp", "dalfox-mcp", "ffuf-mcp", "watch-mcp",
    "waf-bypass-mcp", "browser-mcp", "playwright-mcp",
}

SAFE_TEST_HOSTS = {
    "example.com", "example.org", "example.net", "localhost", "0.0.0.0",
    # Universally-recognized attacker-origin placeholders (RFC-2606-adjacent
    # community convention, same status as example.com) -- needed once
    # curl/wget are Tier-2-checked: a CORS/CSRF PoC's `-H "Origin:
    # https://evil.com"` is a header VALUE describing the attacker's origin,
    # not a live target being contacted, but this hook's host-extraction is
    # a blanket regex over the whole command line (deliberately -- stripping
    # quoted substrings to distinguish "target" from "header value" risks
    # also stripping a legitimately-quoted target URL, which fails open
    # instead of just over-blocking; a false-positive block is the safe
    # failure mode here, a false-negative allow is not).
    "evil.com", "attacker.com", "malicious.com",
}

HOST_ARG_KEYS = ("domains", "domain", "target", "targets", "url", "host", "hosts")

HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# HOSTNAME_RE matches any "word.word" pattern -- it cannot distinguish a real
# domain from a filename with an extension (results.json, wordlist.txt,
# payload.py) on pattern shape alone, since e.g. "co"/"io"/"me" are real
# TLDs but structurally identical to a two-letter... this is the inverse
# problem: common non-TLD file extensions that would otherwise false-positive
# as a "hostname" once curl/wget are Tier-2-checked (curl -o results.json,
# -d @payload.json are the single most common curl invocation shapes there
# are). Not exhaustive -- a curated denylist of what's actually been seen to
# collide, not a claim of covering every possible extension.
NON_TLD_FILE_EXTENSIONS = {
    "txt", "json", "py", "md", "yaml", "yml", "csv", "html", "htm", "xml",
    "sh", "js", "ts", "log", "pdf", "zip", "tar", "gz", "cfg", "conf", "ini",
    "png", "jpg", "jpeg", "gif", "svg", "css", "sql", "db", "bak", "out",
}


def _is_safe_test_host(host: str) -> bool:
    host = host.lower().strip(".")
    if host in SAFE_TEST_HOSTS or host in DEV_INFRA_HOSTS:
        return True
    if host.rsplit(".", 1)[-1] in NON_TLD_FILE_EXTENSIONS:
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

    # Prefer real URL parsing over blanket regex where a scheme is present --
    # this is what actually distinguishes "the host curl is contacting" from
    # a same-looking substring in the URL's own path (curl .../main/file.txt
    # regex-matches "file.txt" as if it were a second hostname otherwise).
    hosts: list[str] = []
    seen_spans: list[tuple[int, int]] = []
    for m in URL_RE.finditer(command):
        seen_spans.append(m.span())
        host = urlsplit(m.group(0)).hostname
        if host:
            hosts.append(host)

    # Remove matched URL spans before the fallback bare-hostname scan, so a
    # URL's own path/query never gets double-scanned by HOSTNAME_RE.
    remainder = command
    for start, end in sorted(seen_spans, reverse=True):
        remainder = remainder[:start] + " " + remainder[end:]

    hosts.extend(HOSTNAME_RE.findall(remainder))
    return [h for h in hosts if not _is_safe_test_host(h)]


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

    command = tool_input.get("command", "")
    if tool_name == "Bash":
        candidates = _extract_hosts_from_bash(command)
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

    # curl/wget have no dedicated MCP wrapper (see the module docstring/
    # TIER2_BASH_TOOLS comment above), so nothing else in this codebase ever
    # routes them through tool_resolver.run_tool() -- meaning nothing else
    # ever calls budget_guard.enforce()/audit_log.log_call() for them either.
    # Wire both in here, once scope has genuinely passed for a real in-scope
    # host (not for the other seven TIER2_BASH_TOOLS -- those already get
    # budgeted/audited exactly once via their own MCP server's run_tool()
    # call, so doing it here too would double-count every raw-Bash
    # nmap/nuclei/etc. invocation that's also MCP-wrapped). This is a
    # PreToolUse hook -- the command hasn't run yet, so there's no real
    # returncode/duration/WAF-block classification available the way
    # run_tool() has after the fact; logged as None/0.0/None. That still
    # captures the primary audit value (exact command + args + timestamp of
    # every real Tier-2 curl/wget attempt) without the schema-risk of
    # correlating a second PostToolUse hook by callID.
    if tool_name == "Bash" and _first_word(command) in ("curl", "wget"):
        name = _first_word(command)
        try:
            _enforce_budget(name)
        except BudgetExceeded as e:
            print(f"BLOCKED by scope gate: Tier-2 budget exceeded ({e}).", file=sys.stderr)
            return 2
        try:
            args = shlex.split(command)[1:]
        except ValueError:
            args = []
        _log_call(name, args, returncode=None, duration_ms=0.0, block=None)

    return 0


if __name__ == "__main__":
    sys.exit(main())
