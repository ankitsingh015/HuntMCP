"""CI check: `.mcp.json` is the single MCP registration source (Claude Code).

Closes the #163 drift blind spot. The previous version defined "registered"
as a `mcp-servers/<name>` directory **or** an `opencode.jsonc` "mcp" entry,
and never read `.mcp.json` or `.claude/settings.json` (the Claude Code MCP
path). So a server that had a directory but was **absent from `.mcp.json`**
(e.g. `surface-map-mcp`, #161) passed the drift test while being unreachable
in every real Claude Code engagement. Green CI, orphaned capability.

Now, with Claude Code as the single source of truth (OpenCode removed, #160):
- "registered" means a key in `.mcp.json`;
- every `mcp-servers/<name>-mcp` directory MUST be registered in `.mcp.json`
  (or be a documented, intentional exception) -- this is the assertion that
  would have caught #161;
- every registered server MUST be enabled in the committed
  `.claude/settings.json` `enabledMcpjsonServers`, or be a documented
  disabled-by-default exception;
- every `mcp__<name>` an agent's frontmatter declares must resolve to a
  registered server or a known personal (`--scope local`) exception.
"""
from __future__ import annotations

import json
import os
import re

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Personal, `--scope local` MCP registrations the operator opts into via
# scripts/connect-*.sh -- their own compiled binary/extension acts as the MCP
# server, not a mcp-servers/*/server.py FastMCP wrapper. Intentionally absent
# from .mcp.json and from mcp-servers/. Confirmed intentional (ARCHITECTURE.md,
# README.md, internal-research/audits/OPEN-SOURCE-AUDIT.md).
_KNOWN_UNTRACKED_PERSONAL_SERVERS = {"obscura-mcp", "burp"}

# Servers present in .mcp.json but intentionally NOT enabled by default in
# .claude/settings.json -- the operator opts in per engagement (cloud
# post-exploitation, AD recon, cross-model second opinion). Documented set.
_KNOWN_DISABLED = {
    "second-opinion-mcp",
    "azure-postexploit-mcp",
    "aws-postexploit-mcp",
    "gcp-postexploit-mcp",
    "local-privesc-mcp",
    "ad-recon-mcp",
}

# Server directories deliberately NOT registered in .mcp.json, each mapped to
# its tracking reason. This MUST stay as small as possible: an UNDOCUMENTED
# directory missing from .mcp.json is the exact #161/#163 orphan bug this file
# exists to catch, so a new entry here needs an explicit, maintainer-approved
# reason.
_KNOWN_UNWIRED_DIRS: dict[str, str] = {}


def _mcp_json_servers() -> set[str]:
    """Every MCP server registered in .mcp.json (the Claude Code source)."""
    d = json.load(open(os.path.join(ROOT, ".mcp.json")))
    return set(d.get("mcpServers", {}).keys())


def _server_dirs() -> set[str]:
    """Every mcp-servers/<name>-mcp directory (a real FastMCP server)."""
    base = os.path.join(ROOT, "mcp-servers")
    return {
        d for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d)) and d.endswith("-mcp")
    }


def _enabled_servers() -> set[str]:
    """Servers enabled in the committed, shared .claude/settings.json."""
    d = json.load(open(os.path.join(ROOT, ".claude", "settings.json")))
    return set(d.get("enabledMcpjsonServers", []))


def _frontmatter(path: str) -> dict:
    text = open(path).read()
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    assert m, f"{os.path.basename(path)}: missing YAML frontmatter"
    return yaml.safe_load(m.group(1)) or {}


def _claude_agent_mcp_refs(path: str) -> set[str]:
    """.claude/agents/*.md: tools: is a comma-separated string; extract every
    mcp__<name> token's <name>."""
    tools = _frontmatter(path).get("tools", "")
    if not isinstance(tools, str):
        return set()
    return {
        tok.strip()[len("mcp__"):]
        for tok in tools.split(",")
        if tok.strip().startswith("mcp__")
    }


def _md_files(directory: str) -> list[str]:
    return [os.path.join(directory, f) for f in sorted(os.listdir(directory)) if f.endswith(".md")]


def test_every_mcp_servers_dir_is_registered_in_mcp_json():
    """The #161/#163 fix: a built server (mcp-servers/<name>-mcp) that is NOT
    in .mcp.json is unreachable in every real Claude Code engagement. That
    orphaning passed the OLD drift test; it MUST fail now."""
    orphans = (
        _server_dirs()
        - _mcp_json_servers()
        - _KNOWN_UNTRACKED_PERSONAL_SERVERS
        - set(_KNOWN_UNWIRED_DIRS)
    )
    assert not orphans, (
        "built MCP server directory/directories are absent from .mcp.json, so "
        "they never load in a Claude Code engagement (the #161/#163 orphan "
        f"bug): {sorted(orphans)}. Add each to .mcp.json (+ enable in "
        ".claude/settings.json), or document it in _KNOWN_UNWIRED_DIRS with a "
        "maintainer-approved reason."
    )


def test_every_registered_server_is_enabled_or_documented_disabled():
    """Every .mcp.json server must be enabled in the committed
    .claude/settings.json, unless it is a documented disabled-by-default
    exception. settings.local.json is gitignored and is NOT consulted."""
    registered = _mcp_json_servers()
    enabled = _enabled_servers()
    not_enabled = registered - enabled - _KNOWN_DISABLED
    assert not not_enabled, (
        "registered MCP server(s) not enabled in .claude/settings.json and "
        f"not in the documented _KNOWN_DISABLED set: {sorted(not_enabled)}"
    )
    stale = (_KNOWN_DISABLED - registered) | (_KNOWN_DISABLED & enabled)
    assert not stale, (
        "_KNOWN_DISABLED is stale -- these are no longer registered-and-"
        f"disabled: {sorted(stale)}. Update the set in this test file."
    )


def test_claude_agent_mcp_refs_all_registered_or_known_exception():
    registered = _mcp_json_servers()
    agents_dir = os.path.join(ROOT, ".claude", "agents")
    orphans: dict[str, set[str]] = {}
    for path in _md_files(agents_dir):
        unknown = _claude_agent_mcp_refs(path) - registered - _KNOWN_UNTRACKED_PERSONAL_SERVERS
        if unknown:
            orphans[os.path.basename(path)] = unknown
    assert not orphans, (
        "agent frontmatter references mcp__<name> server(s) with no matching "
        ".mcp.json registration (and not in the known-untracked-personal-"
        f"server allowlist): {orphans}"
    )


def test_known_untracked_exception_list_is_not_stale():
    """If obscura-mcp/burp ever DO get registered (a .mcp.json entry or a
    mcp-servers/ directory), drop them from the allowlist -- a no-longer-needed
    allowlist entry is exactly the kind of drift this file exists to catch."""
    registered = _mcp_json_servers() | _server_dirs()
    still_needed = _KNOWN_UNTRACKED_PERSONAL_SERVERS & registered
    assert not still_needed, (
        f"{still_needed} are now registered (.mcp.json entry or mcp-servers/ "
        "directory exists) -- remove from _KNOWN_UNTRACKED_PERSONAL_SERVERS, "
        "it's stale."
    )
