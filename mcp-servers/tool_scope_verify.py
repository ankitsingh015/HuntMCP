"""Runtime verification of per-agent MCP tool scoping -- answers a
question a prior engagement retrospective could only leave UNCONFIRMED:
"a phase agent's declared tool allowlist does not include the persistent
case-store server... yet case-store rows appeared during that phase --
either the per-agent allowlist is not enforced as a strict allowlist, or
the phase ran under a broader fallback agent." Verifying this needed
"spawn the restricted agent with a canary task and assert the privileged
tool is unavailable" -- a live agent spawn, with real cost and, in a
shared/busy environment, real collision risk with any concurrently-
running engagement.

This gets the same evidence a different, safer way: `opencode agent
list` prints every agent's fully RESOLVED permission rule set (global
defaults, then the agent's own frontmatter overrides, evaluated in
order) -- pure read-only introspection, no live target contact, no
engagement/session state touched at all. Confirmed against real output:
scan-agent's rule list contains "nuclei-mcp*": deny (the global "disable
every MCP tool by default" rule) immediately followed later by
"nuclei-mcp*": allow (scan-agent's own frontmatter re-enabling it) --
LAST-MATCH-WINS is the effective resolution rule opencode itself uses.
case-mcp (never declared by scan-agent) appears only as "deny", with no
override anywhere in the list, confirming no leak.

Uses only the standard library -- no new dependency. The one live/
external part (running the real `opencode agent list` command) lives in
the integration test only (tests/test_tool_scope_verify.py's live_
scan_agent_has_no_case_mcp_leak, gated on the binary being installed) --
this module's own functions are pure text/data parsing, independently
testable against a synthetic fixture.
"""

from __future__ import annotations

import json
import re

_AGENT_HEADER_RE = re.compile(r"^(\S.*?) \((primary|subagent)\)\s*$", re.MULTILINE)


def parse_agent_list_output(raw: str) -> dict[str, list[dict]]:
    """Splits raw `opencode agent list` stdout into {agent_name: [rule,
    ...]}, each rule a {"permission", "action", "pattern"} dict, in the
    same order opencode printed them (evaluation order matters -- see
    resolved_mcp_permissions())."""
    headers = list(_AGENT_HEADER_RE.finditer(raw))
    result: dict[str, list[dict]] = {}
    for i, m in enumerate(headers):
        name = m.group(1)
        block_start = m.end()
        block_end = headers[i + 1].start() if i + 1 < len(headers) else len(raw)
        block = raw[block_start:block_end]
        result[name] = _extract_rules(block)
    return result


def _extract_rules(block: str) -> list[dict]:
    """Extracts every top-level `{...}` JSON object from `block` --
    deliberately NOT json.loads()-ing the whole block as one array (the
    real CLI output's surrounding `[`/`]`/indentation isn't guaranteed to
    be strictly valid standalone JSON in every opencode version), instead
    scanning for `{` characters and handing each one to
    json.JSONDecoder.raw_decode(), which is string/escape-aware per the
    real JSON grammar. A span that fails to parse is skipped rather than
    aborting the whole block.

    SECURITY regression this replaced (code-review finding, confirmed via
    direct reproduction): an earlier hand-rolled char-by-char brace-depth
    counter treated every "{"/"}" as structural, with no awareness of
    whether it was inside a JSON string VALUE -- a single unbalanced "{"
    inside any string (e.g. a bash permission "pattern" field, which can
    legitimately contain shell brace-expansion syntax like "{a,b}")
    desynced the counter for the REST of the block, silently dropping
    every subsequent rule, including a critical case-mcp:deny rule. The
    live leak-detection test's own assertion
    `resolved.get("case-mcp") != "allow"` would then pass not because
    there's no leak, but because the evidence was silently lost --
    exactly the failure mode this module exists to prevent.
    json.JSONDecoder is immune to this since it correctly tracks string/
    escape state per the JSON grammar itself."""
    rules = []
    decoder = json.JSONDecoder()
    i, n = 0, len(block)
    while i < n:
        if block[i] == "{":
            try:
                obj, end = decoder.raw_decode(block, i)
                rules.append(obj)
                i = end
                continue
            except ValueError:
                pass
        i += 1
    return rules


def resolved_mcp_permissions(rules: list[dict]) -> dict[str, str]:
    """Given one agent's rule list in printed/evaluation order, returns
    {server_name: "allow"|"deny"} for every `<name>-mcp*` permission seen
    -- the LAST occurrence of a given permission name in the list is its
    effective resolved action (later, more specific rules override
    earlier, broader ones), confirmed against real opencode output (see
    module docstring). server_name has the trailing "*" stripped (e.g.
    "case-mcp", not "case-mcp*")."""
    resolved: dict[str, str] = {}
    for rule in rules:
        perm = rule.get("permission", "")
        if perm.endswith("-mcp*"):
            resolved[perm[:-1]] = rule.get("action", "")
    return resolved


def find_leaks(resolved: dict[str, str], declared: set[str]) -> list[str]:
    """Servers that resolve to "allow" but are NOT in `declared` (the
    agent's own .opencode/agents/<name>.md frontmatter tool list) -- a
    real scope-enforcement leak. Sorted for deterministic output."""
    return sorted(name for name, action in resolved.items() if action == "allow" and name not in declared)


def find_missing_grants(resolved: dict[str, str], declared: set[str]) -> list[str]:
    """The other direction: a server the agent's frontmatter DOES declare
    but that doesn't resolve to "allow" at runtime (either absent from the
    resolved set entirely, or present but stuck at "deny") -- a real
    capability-loss bug, distinct from a leak but equally worth catching."""
    return sorted(name for name in declared if resolved.get(name) != "allow")
