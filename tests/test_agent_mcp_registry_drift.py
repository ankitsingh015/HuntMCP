"""CI check for agent-frontmatter-vs-MCP-registry drift.

Reported live in an engagement retrospective: a specialist agent's declared
tool allowlist referenced an MCP server name with no corresponding entry in
the repository's MCP registration file/directory, and nothing caught it.
This asserts every `mcp__<name>` (.claude/agents) / `<name>*` (.opencode/
agents) token an agent's frontmatter declares corresponds to either a real
`mcp-servers/<name>` directory, an `opencode.jsonc` "mcp" entry, or one of
the two KNOWN, documented, intentional exceptions (obscura-mcp, burp) that
are deliberately NOT tracked/registered -- personal, `--scope local` MCP
registrations the operator opts into via scripts/connect-*.sh (their own
compiled binary/extension acts as the MCP server, not a
mcp-servers/*/server.py FastMCP wrapper). Confirmed intentional, not drift,
by ARCHITECTURE.md, README.md, and
internal-research/audits/OPEN-SOURCE-AUDIT.md (already logged there as
P3/INFO "could confuse an operator", not a defect). Any OTHER undeclared
reference is real drift this test exists to catch before it ships.
"""
from __future__ import annotations

import json
import os
import re

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_KNOWN_UNTRACKED_PERSONAL_SERVERS = {"obscura-mcp", "burp"}


def _registered_server_names() -> set[str]:
    """Every real MCP server: an mcp-servers/<name> directory, or an
    opencode.jsonc "mcp" key (also covers a server registered only in
    config, if that ever diverges from the directory listing)."""
    mcp_servers_dir = os.path.join(ROOT, "mcp-servers")
    from_dirs = {
        d for d in os.listdir(mcp_servers_dir)
        if os.path.isdir(os.path.join(mcp_servers_dir, d)) and d.endswith("-mcp")
    }
    raw = open(os.path.join(ROOT, "opencode.jsonc")).read()
    clean = "\n".join(line for line in raw.split("\n") if not line.strip().startswith("//"))
    cfg = json.loads(clean)
    from_config = set(cfg.get("mcp", {}).keys())
    return from_dirs | from_config


def _frontmatter(path: str) -> dict:
    text = open(path).read()
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    assert m, f"{os.path.basename(path)}: missing YAML frontmatter"
    return yaml.safe_load(m.group(1)) or {}


def _claude_agent_mcp_refs(path: str) -> set[str]:
    """.claude/agents/*.md: tools: is a comma-separated string; extract
    every mcp__<name> token's <name>."""
    tools = _frontmatter(path).get("tools", "")
    if not isinstance(tools, str):
        return set()
    return {
        tok.strip()[len("mcp__"):]
        for tok in tools.split(",")
        if tok.strip().startswith("mcp__")
    }


def _opencode_agent_mcp_refs(path: str) -> set[str]:
    """.opencode/agents/*.md: tools: is a dict of "<name>*": true keys."""
    out = set()
    for key, val in (_frontmatter(path).get("tools") or {}).items():
        if val is True and key.endswith("*"):
            out.add(key[:-1])
    return out


def _md_files(directory: str) -> list[str]:
    return [os.path.join(directory, f) for f in sorted(os.listdir(directory)) if f.endswith(".md")]


def test_claude_agent_mcp_refs_all_registered_or_known_exception():
    registered = _registered_server_names()
    agents_dir = os.path.join(ROOT, ".claude", "agents")
    orphans: dict[str, set[str]] = {}
    for path in _md_files(agents_dir):
        unknown = _claude_agent_mcp_refs(path) - registered - _KNOWN_UNTRACKED_PERSONAL_SERVERS
        if unknown:
            orphans[os.path.basename(path)] = unknown
    assert not orphans, (
        "agent frontmatter references mcp__<name> server(s) with no matching "
        "mcp-servers/<name> directory or opencode.jsonc entry (and not in "
        f"the known-untracked-personal-server allowlist): {orphans}"
    )


def test_opencode_agent_mcp_refs_all_registered_or_known_exception():
    registered = _registered_server_names()
    agents_dir = os.path.join(ROOT, ".opencode", "agents")
    orphans: dict[str, set[str]] = {}
    for path in _md_files(agents_dir):
        unknown = _opencode_agent_mcp_refs(path) - registered - _KNOWN_UNTRACKED_PERSONAL_SERVERS
        if unknown:
            orphans[os.path.basename(path)] = unknown
    assert not orphans, (
        "agent frontmatter references <name>* server(s) with no matching "
        "mcp-servers/<name> directory or opencode.jsonc entry (and not in "
        f"the known-untracked-personal-server allowlist): {orphans}"
    )


def test_known_untracked_exception_list_is_not_stale():
    """If obscura-mcp/burp ever DO get registered (directory or
    opencode.jsonc entry added), drop them from the allowlist above -- a
    no-longer-needed allowlist entry is exactly the kind of drift this
    file exists to catch."""
    registered = _registered_server_names()
    still_needed = _KNOWN_UNTRACKED_PERSONAL_SERVERS & registered
    assert not still_needed, (
        f"{still_needed} are now registered (mcp-servers/ directory or "
        "opencode.jsonc entry exists) -- remove from "
        "_KNOWN_UNTRACKED_PERSONAL_SERVERS in this test file, it's stale."
    )
