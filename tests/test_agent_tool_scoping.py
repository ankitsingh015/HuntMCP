"""Per-agent MCP tool-scoping invariants (Claude Code single source of truth).

Claude Code model (after OpenCode removal, #160): the project MCP servers are
registered in `.mcp.json`, enabled/disabled for the project in the committed
`.claude/settings.json`, and each agent re-enables only the servers it needs
via an `mcp__<name>` allowlist in its `.claude/agents/*.md` `tools:`
frontmatter string. These tests lock in that architecture and guard the
dynamic-specialist case: ANY agent .md present (a future jwt-agent/
graphql-agent included) MUST declare a non-empty, scoped `tools:` allowlist.
They also assert no enabled MCP server is unreachable by every agent, and that
no High/Critical detection/validation tool is hidden from the agent that owns
it (finding-coverage preservation).

Replaces the old opencode.jsonc-based version: there is no central "global
tools map that disables everything" in Claude Code, so the two tests that
asserted that construct are gone; the remaining invariants are retargeted to
`.mcp.json` + `.claude/settings.json` + `.claude/agents`.
"""
from __future__ import annotations

import json
import os
import re

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENTS_DIR = os.path.join(ROOT, ".claude", "agents")

# Personal, --scope local servers the operator opts into via connect-*.sh;
# their own binary/extension is the server, not a mcp-servers/*/server.py.
_KNOWN_UNTRACKED_PERSONAL_SERVERS = {"obscura-mcp", "burp"}


def _registered_servers() -> set[str]:
    return set(json.load(open(os.path.join(ROOT, ".mcp.json")))["mcpServers"].keys())


def _enabled_servers() -> set[str]:
    d = json.load(open(os.path.join(ROOT, ".claude", "settings.json")))
    return set(d.get("enabledMcpjsonServers", []))


def _agent_files() -> list[str]:
    return [os.path.join(AGENTS_DIR, f) for f in os.listdir(AGENTS_DIR) if f.endswith(".md")]


def _frontmatter(path: str) -> dict:
    text = open(path).read()
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    assert m, f"{os.path.basename(path)}: missing YAML frontmatter"
    return yaml.safe_load(m.group(1)) or {}


def _agent_mcp_servers(fm: dict) -> set[str]:
    """MCP server names an agent re-enables (mcp__<name> tokens in the
    comma-separated tools: string)."""
    tools = fm.get("tools", "")
    if not isinstance(tools, str):
        return set()
    return {
        tok.strip()[len("mcp__"):]
        for tok in tools.split(",")
        if tok.strip().startswith("mcp__")
    }


# ------------------------------------------------ per-agent allowlist invariants

def test_every_agent_declares_a_nonempty_scoped_allowlist():
    """Dynamic-specialist guard: any agent .md (incl. a future on-demand one)
    must declare a non-empty MCP tools: allowlist, else it is tool-blind."""
    for path in _agent_files():
        servers = _agent_mcp_servers(_frontmatter(path))
        assert servers, (
            f"{os.path.basename(path)}: no MCP servers in its tools: allowlist -- "
            f"this agent would have ZERO MCP tools. Add a scoped `tools:` allowlist."
        )


def test_agent_allowlists_reference_only_registered_servers():
    """An agent may reference a registered server that is currently DISABLED in
    settings.json (operator opts in per engagement, e.g. the post-exploit
    servers exploit-agent owns) -- but never a server that is not registered in
    .mcp.json at all (that is real drift)."""
    registered = _registered_servers()
    for path in _agent_files():
        servers = _agent_mcp_servers(_frontmatter(path))
        unknown = servers - registered - _KNOWN_UNTRACKED_PERSONAL_SERVERS
        assert not unknown, (
            f"{os.path.basename(path)}: references MCP server(s) not registered "
            f"in .mcp.json (and not a known personal server): {sorted(unknown)}"
        )


def test_no_agent_reenables_all_servers():
    """Scoping must be real -- no agent gets the full fleet by default."""
    total = len(_registered_servers())
    for path in _agent_files():
        servers = _agent_mcp_servers(_frontmatter(path))
        assert len(servers) < total, (
            f"{os.path.basename(path)}: re-enables all {total} MCP servers -- scoping defeated."
        )


def test_orchestrator_is_tightly_scoped():
    """huntbrain (default primary orchestrator, the long-lived context) must be
    small; everything else is delegated to specialists."""
    servers = _agent_mcp_servers(_frontmatter(os.path.join(AGENTS_DIR, "huntbrain.md")))
    assert servers == {
        "memory-mcp", "writeup-mcp", "lessons-mcp", "hackerone-mcp",
        "case-mcp", "target-discovery-mcp", "watch-mcp",
    }, f"unexpected orchestrator MCP scope: {sorted(servers)}"


def test_no_orphan_enabled_server():
    """Every ENABLED MCP server must be reachable by at least one agent. A
    server enabled in settings.json but in no agent's allowlist loads but can
    never be invoked in the engagement flow (the agent-level analogue of the
    #161/#163 orphan bug)."""
    enabled = _enabled_servers()
    covered: set[str] = set()
    for path in _agent_files():
        covered |= _agent_mcp_servers(_frontmatter(path))
    orphan = enabled - covered
    assert not orphan, (
        "enabled MCP server(s) no agent can invoke (loaded but unreachable in "
        f"the flow): {sorted(orphan)}. Add each to the owning agent's tools:, "
        "or disable it in .claude/settings.json if intentionally not yet used."
    )


# ------------------------------------------------ High/Critical coverage mapping

# finding class -> (detecting/validating MCP server, agent that owns it)
HIGH_CRIT_COVERAGE = {
    "sql-injection":        ("sqlmap-mcp", "scan-agent"),
    "xss":                  ("dalfox-mcp", "scan-agent"),
    "cve-misconfig-nuclei": ("nuclei-mcp", "scan-agent"),
    "content-discovery":    ("ffuf-mcp", "scan-agent"),
    "idor-bola":            ("idor-mcp", "exploit-agent"),
    "blind-ssrf-oob":       ("oob-mcp", "exploit-agent"),
    "xss-js-confirmation":  ("browser-mcp", "exploit-agent"),
    "attack-chaining":      ("chainer-mcp", "exploit-agent"),
    "exposed-secrets":      ("secrets-mcp", "recon-agent"),
    "source-leak-github":   ("github-security-mcp", "recon-agent"),
    "subdomain-recon":      ("subfinder-mcp", "recon-agent"),
}


def test_high_critical_detection_tools_available_to_owning_agent():
    enabled = _enabled_servers()
    for finding, (server, agent) in HIGH_CRIT_COVERAGE.items():
        assert server in enabled, f"{finding}: {server} not enabled in .claude/settings.json"
        servers = _agent_mcp_servers(_frontmatter(os.path.join(AGENTS_DIR, f"{agent}.md")))
        assert server in servers, (
            f"COVERAGE REGRESSION: {finding} detected by {server}, but {agent} does not "
            f"re-enable it -- this High/Critical class could be missed."
        )
