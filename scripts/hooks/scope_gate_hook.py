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
- WebFetch/webfetch (both harnesses' native URL-fetch tool) is
  deliberately NOT scope-gated at all, unlike Bash's curl/wget --
  briefly was (2026-08-29), then reverted the same day. curl/wget send
  attacker-controlled requests AT a target (probing, exploiting);
  WebFetch's actual use in this agent system is overwhelmingly read-only
  research (a CVE page, a writeup, vendor docs) that never touches the
  target at all, and gating it the same way as curl blocked that
  entirely -- any research URL that wasn't the target itself or on the
  dev-infra allowlist got refused as "not in scope," which isn't a
  meaningful authorization boundary for reading a public webpage the way
  it is for sending a crafted request to a target's own infrastructure.
- example.com/example.org/example.net/localhost/loopback/RFC1918 hosts, plus
  a small allowlist of known dev infrastructure (GitHub, PyPI, npm, Go
  module proxy, Debian/Ubuntu package mirrors -- see scope_guard.py's
  DEV_INFRA_HOSTS, the shared source of truth for this exemption), are
  always allowed with no engagement.yaml required -- that's normal
  development/testing, not a live engagement.
"""

from __future__ import annotations

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
from scope_guard import is_safe_test_host as _is_safe_test_host  # noqa: E402

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
    # scripts/curl-rl.sh is a drop-in curl wrapper (adds reactive 429/
    # Retry-After backoff a PreToolUse hook has no way to provide itself --
    # a hook can only allow/block a command before it runs, it can't wrap
    # or retry the actual subprocess execution). Listed here explicitly so
    # calling it instead of raw curl is not a way to silently skip scope
    # enforcement just because the binary name changed.
    "curl-rl.sh",
}

# curl/wget also legitimately touch non-target infrastructure during ordinary
# MCP-server development -- package registries, source hosting, docs -- which
# must stay exempt the same way scope_guard.SAFE_TEST_HOSTS exempts
# example.com/localhost. That allowlist (DEV_INFRA_HOSTS) now lives in
# scope_guard.py, the one shared source of truth _is_safe_test_host uses --
# not duplicated here anymore (was, until 2026-08-29; see module docstring).
# Kept separate from content_scanner.py's KNOWN_GOOD_HOSTS (that allowlist is
# for outbound calls made BY this repo's own Python code to known service
# integrations; this one is for a human/agent curl-ing the open internet
# during development -- different concern, deliberately not shared).

# MCP servers that actually touch a live target vs. operate on local knowledge only.
TIER2_MCP_SERVERS = {
    "subfinder-mcp", "httpx-mcp", "katana-mcp", "nmap-mcp",
    "nuclei-mcp", "sqlmap-mcp", "dalfox-mcp", "ffuf-mcp", "watch-mcp",
    "waf-bypass-mcp", "browser-mcp", "playwright-mcp", "idor-mcp",
}

HOST_ARG_KEYS = ("domains", "domain", "target", "targets", "url", "host", "hosts")

HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# SAFE_TEST_HOSTS/DEV_INFRA_HOSTS/NON_TLD_FILE_EXTENSIONS and the
# is_safe_test_host() check itself moved to scope_guard.py 2026-08-29 -- it's
# the shared authority scripts/check-scope.sh's CLI also needs (that script
# used to have NO such exemption at all, so an agent following its own
# "run check-scope.sh before touching any host" instruction would self-block
# on example.com/github.com the moment any unrelated engagement.yaml
# existed, something this hook itself never actually required). Imported
# as _is_safe_test_host above.

# Deliberately kept local, NOT part of scope_guard.is_safe_test_host(): these
# are for filtering candidates out of this hook's own blanket command-text
# regex scan specifically, not for deciding whether a host is authorized.
# `curl ... -H "Origin: https://evil.com"` has evil.com as a header VALUE,
# not the host actually being contacted -- but if evil.com were ever the
# actual target argument to a real Tier-2 tool, it still needs a genuine
# in_scope entry like any other domain (someone could really own it).
_ATTACKER_PLACEHOLDER_HOSTS = {"evil.com", "attacker.com", "malicious.com"}


def _is_candidate_exempt(host: str) -> bool:
    return _is_safe_test_host(host) or host.lower().strip(".") in _ATTACKER_PLACEHOLDER_HOSTS


def _first_word(command: str) -> str:
    stripped = command.strip()
    return stripped.split()[0].rsplit("/", 1)[-1] if stripped else ""


# Splits a bash command on the shell operators that start a new sub-command
# (chaining, piping, subshells, newlines) so a blocked command can't be
# smuggled in as the second half of `curl ... && rm -rf data/`. Deliberately
# NOT a blanket `\brm\b` substring scan -- that would also flag an unrelated
# file literally named `rm.log` in a redirect. Matching Bash(rm *)/Bash(rm)
# prefix semantics per sub-command is the same rule .claude/settings.json
# already enforces, just extended across `;`/`&&`/`|`/`$(`.
#
# Deliberately excludes a bare `)` as a split point -- regex can't balance
# parens, so treating every `)` as "end of a $(...) subshell" would also
# split on a stray `)` from unrelated command text (e.g. a Python literal
# passed via `python3 -c "..."`), putting whatever text follows it into its
# own piece and false-positive-blocking on an unrelated "rm" that appears
# later in the same command line, not at a real sub-command boundary.
#
# Also deliberately excludes a bare backtick -- confirmed live 2026-08-26:
# writing a PR body via `gh pr create --body "$(cat <<'EOF' ... EOF)"` with
# markdown inline code like `` `rm -f scratch-file.txt` `` in the body text
# tripped this exact check, because a lone backtick was treated as opening a
# command substitution and everything after it (starting with "rm") became
# its own piece. Backtick substitution is legacy syntax modern agents rarely
# use for real chaining, and this codebase writes a lot of markdown-heavy
# commit/PR-body text through Bash -- the false-positive cost of keeping it
# outweighs the real-smuggling coverage it would add on top of `$(`.
_CHAIN_SPLIT_RE = re.compile(r"&&|\|\||[;&|\n]|\$\(")


def _is_rm_command(command: str) -> bool:
    for piece in _CHAIN_SPLIT_RE.split(command):
        words = piece.split()
        if not words:
            continue
        first = words[0].rsplit("/", 1)[-1]
        if first in ("sudo", "env") and len(words) > 1:
            first = words[1].rsplit("/", 1)[-1]
        if first == "rm":
            return True
    return False


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
    return [h for h in hosts if not _is_candidate_exempt(h)]


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
            if not _is_candidate_exempt(candidate):
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

    # Blanket rm block -- unconditional, independent of scope/engagement
    # state entirely (this is a "never run rm, never ask" rule, not a
    # target-scope rule). .claude/settings.json's `Bash(rm *)`/`Bash(rm)`
    # permissions.deny already enforces this for Claude Code before the
    # call even reaches this hook; this check is what makes it real for
    # OpenCode too (via .opencode/plugin/scope-gate.ts, which invokes this
    # same script for every Bash call) -- opencode.jsonc's declarative
    # `permission.bash` glob deny (`"rm **": "deny"` alongside `"*":
    # "allow"`) was tested live and did not actually block rm across
    # several pattern/ordering attempts, so this hook is the real
    # enforcement point on that harness, same as it already is for scope.
    if tool_name == "Bash" and _is_rm_command(command):
        print(
            "BLOCKED: rm is disabled by default in this repo (both Claude "
            "Code and OpenCode) -- ask the user to delete the file "
            "themselves, or move it aside instead of removing it.",
            file=sys.stderr,
        )
        return 2

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

    # curl/wget/curl-rl.sh have no dedicated MCP wrapper (see the module
    # docstring/TIER2_BASH_TOOLS comment above), so nothing else in this
    # codebase ever routes them through tool_resolver.run_tool() -- meaning
    # nothing else ever calls budget_guard.enforce()/audit_log.log_call()
    # for them either. Wire both in here, once scope has genuinely passed
    # for a real in-scope host (not for the other TIER2_BASH_TOOLS members --
    # those already get budgeted/audited exactly once via their own MCP
    # server's run_tool() call, so doing it here too would double-count
    # every raw-Bash nmap/nuclei/etc. invocation that's also MCP-wrapped).
    # This is a PreToolUse hook -- the command hasn't run yet, so there's no
    # real returncode/duration/WAF-block classification available the way
    # run_tool() has after the fact; logged as None/0.0/None. That still
    # captures the primary audit value (exact command + args + timestamp of
    # every real Tier-2 curl/wget/curl-rl.sh attempt) without the
    # schema-risk of correlating a second PostToolUse hook by callID.
    if tool_name == "Bash" and _first_word(command) in ("curl", "wget", "curl-rl.sh"):
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
