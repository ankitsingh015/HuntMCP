"""Option A (per-agent MCP tool scoping) invariants.

The global config (opencode.jsonc) disables ALL MCP tool schemas; each agent
re-enables only the MCP servers it actually uses via a `tools:` allowlist in
its .opencode/agents/*.md frontmatter. These tests lock in that architecture and
-- critically -- guard the dynamic-specialist case: ANY agent .md present (a
future jwt-agent/graphql-agent written on demand included) MUST declare a
non-empty, scoped `tools:` allowlist, or it would be born tool-blind under the
global disable. They also assert that no High/Critical detection/validation tool
is hidden from the agent that owns it (finding-coverage preservation).
"""
from __future__ import annotations

import json
import os
import re

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENTS_DIR = os.path.join(ROOT, ".opencode", "agents")


def _load_opencode_config() -> dict:
    # opencode.jsonc is JSONC: strip //-comment lines (same as CI validate-config).
    raw = open(os.path.join(ROOT, "opencode.jsonc")).read()
    clean = "\n".join(l for l in raw.split("\n") if not l.strip().startswith("//"))
    return json.loads(clean)


def _enabled_mcp_servers(cfg: dict) -> set[str]:
    return {name for name, v in cfg.get("mcp", {}).items() if v.get("enabled")}


def _agent_files() -> list[str]:
    return [os.path.join(AGENTS_DIR, f) for f in os.listdir(AGENTS_DIR) if f.endswith(".md")]


def _frontmatter(path: str) -> dict:
    text = open(path).read()
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    assert m, f"{os.path.basename(path)}: missing YAML frontmatter"
    return yaml.safe_load(m.group(1)) or {}


def _reenabled_servers(fm: dict) -> set[str]:
    """MCP server names an agent re-enables (keys like 'nuclei-mcp*': true)."""
    out = set()
    for key, val in (fm.get("tools") or {}).items():
        if val is True and key.endswith("*"):
            out.add(key[:-1])  # strip trailing glob '*'
    return out


# ---------------------------------------------------------------- global disable

def test_global_disable_covers_every_enabled_mcp_server():
    cfg = _load_opencode_config()
    disabled = {k[:-1] for k, v in cfg.get("tools", {}).items()
                if v is False and k.endswith("*")}
    enabled = _enabled_mcp_servers(cfg)
    missing = enabled - disabled
    assert not missing, f"MCP servers enabled but not globally disabled (leak into every agent): {missing}"


def test_global_tools_map_only_disables_never_enables():
    cfg = _load_opencode_config()
    bad = {k: v for k, v in cfg.get("tools", {}).items() if v is not False}
    assert not bad, f"global tools map must only contain '<server>*: false' entries, found: {bad}"


# ------------------------------------------------ per-agent allowlist invariants

def test_every_agent_declares_a_nonempty_scoped_allowlist():
    """Dynamic-specialist guard: any agent .md (incl. a future on-demand one) must
    declare a non-empty tools: allowlist, else it is tool-blind under global disable."""
    for path in _agent_files():
        fm = _frontmatter(path)
        servers = _reenabled_servers(fm)
        assert servers, (
            f"{os.path.basename(path)}: no MCP servers re-enabled -- under the global "
            f"disable this agent would have ZERO MCP tools. Add a scoped `tools:` allowlist."
        )


def test_agent_allowlists_reference_only_real_enabled_servers():
    cfg = _load_opencode_config()
    enabled = _enabled_mcp_servers(cfg)
    for path in _agent_files():
        servers = _reenabled_servers(_frontmatter(path))
        unknown = servers - enabled
        assert not unknown, f"{os.path.basename(path)}: re-enables unknown/disabled MCP servers {unknown}"


def test_no_agent_reenables_all_servers():
    """Scoping must be real -- no agent (orchestrator or dynamic specialist) gets the
    full fleet by default."""
    cfg = _load_opencode_config()
    total = len(_enabled_mcp_servers(cfg))
    for path in _agent_files():
        servers = _reenabled_servers(_frontmatter(path))
        assert len(servers) < total, (
            f"{os.path.basename(path)}: re-enables all {total} MCP servers -- scoping defeated."
        )


def test_orchestrator_is_tightly_scoped():
    """huntbrain (default primary orchestrator, the long-lived context) must be small."""
    fm = _frontmatter(os.path.join(AGENTS_DIR, "huntbrain.md"))
    servers = _reenabled_servers(fm)
    # huntbrain only calls 7 MCP servers directly; everything else is delegated.
    assert servers == {
        "memory-mcp", "writeup-mcp", "lessons-mcp", "hackerone-mcp",
        "case-mcp", "target-discovery-mcp", "watch-mcp",
    }, f"unexpected orchestrator MCP scope: {sorted(servers)}"


def test_no_orphan_mcp_server():
    """Every enabled MCP server must be reachable by at least one agent."""
    cfg = _load_opencode_config()
    enabled = _enabled_mcp_servers(cfg)
    covered: set[str] = set()
    for path in _agent_files():
        covered |= _reenabled_servers(_frontmatter(path))
    orphan = enabled - covered
    assert not orphan, f"MCP servers no agent can use (unreachable): {orphan}"


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
    cfg = _load_opencode_config()
    enabled = _enabled_mcp_servers(cfg)
    for finding, (server, agent) in HIGH_CRIT_COVERAGE.items():
        assert server in enabled, f"{finding}: {server} not an enabled MCP server"
        fm = _frontmatter(os.path.join(AGENTS_DIR, f"{agent}.md"))
        servers = _reenabled_servers(fm)
        assert server in servers, (
            f"COVERAGE REGRESSION: {finding} detected by {server}, but {agent} does not "
            f"re-enable it under scoping -- this High/Critical class could be missed."
        )
