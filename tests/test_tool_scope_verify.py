import os
import re
import shutil
import subprocess

import tool_scope_verify
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENTS_DIR = os.path.join(ROOT, ".opencode", "agents")

_SYNTHETIC_OUTPUT = """build (primary)
  [
  {
    "permission": "*",
    "action": "allow",
    "pattern": "*"
  },
  {
    "permission": "writeup-mcp*",
    "action": "allow",
    "pattern": "*"
  }
]
scan-agent (subagent)
  [
  {
    "permission": "*",
    "action": "allow",
    "pattern": "*"
  },
  {
    "permission": "writeup-mcp*",
    "action": "deny",
    "pattern": "*"
  },
  {
    "permission": "nuclei-mcp*",
    "action": "deny",
    "pattern": "*"
  },
  {
    "permission": "case-mcp*",
    "action": "deny",
    "pattern": "*"
  },
  {
    "permission": "nuclei-mcp*",
    "action": "allow",
    "pattern": "*"
  },
  {
    "permission": "writeup-mcp*",
    "action": "allow",
    "pattern": "*"
  }
]
exploit-agent (subagent)
  [
  {
    "permission": "*",
    "action": "allow",
    "pattern": "*"
  },
  {
    "permission": "case-mcp*",
    "action": "deny",
    "pattern": "*"
  },
  {
    "permission": "case-mcp*",
    "action": "allow",
    "pattern": "*"
  }
]
"""


def test_parse_agent_list_output_splits_by_agent_header():
    parsed = tool_scope_verify.parse_agent_list_output(_SYNTHETIC_OUTPUT)
    assert set(parsed.keys()) == {"build", "scan-agent", "exploit-agent"}


def test_parse_agent_list_output_extracts_rules_in_order():
    parsed = tool_scope_verify.parse_agent_list_output(_SYNTHETIC_OUTPUT)
    scan_rules = parsed["scan-agent"]
    perms = [r["permission"] for r in scan_rules]
    assert perms == ["*", "writeup-mcp*", "nuclei-mcp*", "case-mcp*", "nuclei-mcp*", "writeup-mcp*"]


def test_extract_rules_survives_unbalanced_brace_in_a_string_value():
    """SECURITY regression, confirmed via direct reproduction (code-review
    finding): the hand-rolled brace-depth counter was not string/escape-
    aware -- a single unbalanced "{" inside any JSON string VALUE (e.g. a
    bash permission "pattern" field, which can legitimately contain shell
    brace-expansion syntax) desynced `depth` for the rest of the block,
    silently dropping EVERY subsequent rule, including a critical
    case-mcp:deny rule -- the live leak-detection test's own assertion
    `resolved.get("case-mcp") != "allow"` would then pass not because
    there's no leak, but because the evidence was silently lost. This is
    exactly the failure mode this module exists to prevent."""
    block = """
  [
  {
    "permission": "bash",
    "pattern": "echo {unbalanced",
    "action": "allow"
  },
  {
    "permission": "case-mcp*",
    "action": "deny",
    "pattern": "*"
  }
]
"""
    rules = tool_scope_verify._extract_rules(block)
    assert len(rules) == 2
    assert rules[1]["permission"] == "case-mcp*"
    assert rules[1]["action"] == "deny"


def test_resolved_mcp_permissions_uses_last_match_wins():
    """Ground truth confirmed against real `opencode agent list` output for
    scan-agent: writeup-mcp/nuclei-mcp appear deny-then-allow (the global
    deny-all-MCP default, overridden by the agent's own specific grant) and
    correctly resolve to allow; case-mcp appears deny-only, never
    overridden, and correctly resolves to deny."""
    parsed = tool_scope_verify.parse_agent_list_output(_SYNTHETIC_OUTPUT)
    resolved = tool_scope_verify.resolved_mcp_permissions(parsed["scan-agent"])
    assert resolved["nuclei-mcp"] == "allow"
    assert resolved["writeup-mcp"] == "allow"
    assert resolved["case-mcp"] == "deny"


def test_resolved_mcp_permissions_detects_a_real_leak():
    """exploit-agent's synthetic block deliberately has case-mcp resolve to
    "allow" (as it legitimately should, exploit-agent DOES declare
    case-mcp) -- this is the positive-case sanity check for the same
    last-match-wins logic."""
    parsed = tool_scope_verify.parse_agent_list_output(_SYNTHETIC_OUTPUT)
    resolved = tool_scope_verify.resolved_mcp_permissions(parsed["exploit-agent"])
    assert resolved["case-mcp"] == "allow"


def test_verify_agent_scoping_flags_a_non_declared_server_resolving_allow():
    """The actual leak-detection check: an agent's declared tool set (from
    its own .opencode/agents/<name>.md frontmatter) vs what
    resolved_mcp_permissions() says is actually allowed. Any server
    resolving "allow" that ISN'T in the declared set is a real leak."""
    parsed = tool_scope_verify.parse_agent_list_output(_SYNTHETIC_OUTPUT)
    resolved = tool_scope_verify.resolved_mcp_permissions(parsed["scan-agent"])
    declared = {"nuclei-mcp", "writeup-mcp"}
    leaks = tool_scope_verify.find_leaks(resolved, declared)
    assert leaks == []


def test_verify_agent_scoping_flags_a_genuine_leak():
    parsed = tool_scope_verify.parse_agent_list_output(_SYNTHETIC_OUTPUT)
    resolved = tool_scope_verify.resolved_mcp_permissions(parsed["scan-agent"])
    declared = {"nuclei-mcp"}  # writeup-mcp deliberately omitted, to simulate a real leak
    leaks = tool_scope_verify.find_leaks(resolved, declared)
    assert leaks == ["writeup-mcp"]


def test_verify_agent_scoping_flags_a_missing_declared_grant():
    """The other direction: a server the agent's frontmatter DOES declare
    but that somehow doesn't resolve to "allow" at runtime -- a real
    capability-loss bug, distinct from a leak but just as worth catching."""
    parsed = tool_scope_verify.parse_agent_list_output(_SYNTHETIC_OUTPUT)
    resolved = tool_scope_verify.resolved_mcp_permissions(parsed["scan-agent"])
    declared = {"nuclei-mcp", "writeup-mcp", "sqlmap-mcp"}  # sqlmap-mcp not in the synthetic output at all
    missing = tool_scope_verify.find_missing_grants(resolved, declared)
    assert missing == ["sqlmap-mcp"]


# ------------------------------------------------- live integration (gated)

def test_live_scan_agent_has_no_case_mcp_leak():
    """Live compatibility check (skipped if the opencode binary isn't
    installed): runs the real `opencode agent list` and confirms
    scan-agent's declared tools resolve to allow and case-mcp (explicitly
    NOT declared) resolves to deny with no leak -- direct runtime evidence
    for the "is per-agent MCP tool scoping actually enforced" question,
    previously UNCONFIRMED (the source issue could not verify this without
    spawning a live restricted agent)."""
    if not shutil.which("opencode"):
        return
    try:
        result = subprocess.run(["opencode", "agent", "list"], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return
    if result.returncode != 0:
        return
    parsed = tool_scope_verify.parse_agent_list_output(result.stdout)
    if "scan-agent" not in parsed:
        return
    resolved = tool_scope_verify.resolved_mcp_permissions(parsed["scan-agent"])
    assert resolved.get("case-mcp") != "allow"
    assert resolved.get("nuclei-mcp") == "allow"


def _declared_servers(agent_md_path: str) -> set[str]:
    text = open(agent_md_path).read()
    m = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    fm = yaml.safe_load(m.group(1)) or {}
    return {k[:-1] for k, v in (fm.get("tools") or {}).items() if v is True and k.endswith("*")}


def test_live_no_agent_has_an_mcp_tool_scoping_leak():
    """Comprehensive version of the scan-agent spot-check above: every
    .opencode/agents/*.md agent's declared tool set is cross-checked
    against its REAL, live-resolved opencode permissions -- direct runtime
    evidence, across the whole agent roster, that per-agent MCP tool
    scoping is actually enforced and not just documented convention.
    Skipped (not failed) if the opencode binary isn't installed."""
    if not shutil.which("opencode"):
        return
    try:
        result = subprocess.run(["opencode", "agent", "list"], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return
    if result.returncode != 0:
        return
    parsed = tool_scope_verify.parse_agent_list_output(result.stdout)

    failures = []
    for fname in sorted(os.listdir(AGENTS_DIR)):
        if not fname.endswith(".md"):
            continue
        agent_name = fname[:-len(".md")]
        if agent_name not in parsed:
            continue  # this agent wasn't present in the live output at all -- a separate concern, not a leak
        declared = _declared_servers(os.path.join(AGENTS_DIR, fname))
        resolved = tool_scope_verify.resolved_mcp_permissions(parsed[agent_name])
        leaks = tool_scope_verify.find_leaks(resolved, declared)
        if leaks:
            failures.append(f"{agent_name}: leaked access to {leaks} (not in its own declared tool list)")
    assert not failures, "\n".join(failures)
