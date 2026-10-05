"""P2-NK (part 2/2) -- capability-utilization signal: an offline,
read-only report of how often each known Tier-2 tool was actually invoked,
mined from the already-written audit_log.jsonl.

MASTER-ROADMAP-PROPOSAL.md P2-I3 ("Capability-utilization report", Opp-5):
"Offline mine of audit_log+inventory -> UNDERUSED/MISUSED/OVERUSED/GAP per
capability; eligibility signature per tool."

Honest v1 boundary, not silently overclaimed (same standard as every other
P2 module in this repo): this reports raw call counts per known tool --
which tools were NEVER called this session/engagement is a real, useful
signal on its own -- but does NOT attempt UNDERUSED/MISUSED/OVERUSED
classification. Those need judgment thresholds ("how many calls is too
many?") this repo has no calibrated data for yet; inventing arbitrary
numbers here would be confidence theater, not engineering (the same
reasoning case_store.py's own suggest_next_action()/suggest_root_cause()
docstring already gives for staying heuristic rather than inventing an
unscored formula). A future increment can add that classification once
real usage data across enough engagements exists to calibrate against.

Also honest about coverage: audit_log.jsonl only records calls routed
through tool_resolver.run_tool()/job_runtime.start_job() -- the external-
binary Tier-2 tools (subfinder/httpx/katana/nuclei/ffuf/dalfox/sqlmap/nmap/
curl/wget/gitleaks/impacket scripts). Pure-Python MCP tool calls (idor-mcp's
sweep_idor(), hackerone-mcp's scope sync, memory-mcp's save_hunt(), etc.)
never go through either chokepoint and are therefore invisible to this
signal -- a real architectural gap, not something this module can see
around, and out of scope to fix here (mirrors P2-TEL's own "0 hot-path
cost" decision not to add a new instrumentation hook).

The known-tool inventory is sandbox_runner._TOOL_MAP's own keys, not a
separately hand-maintained list -- reusing the SAME already-verified-
against-every-real-call-site allowlist S5 built, rather than a second copy
that could silently drift from it.
"""

from __future__ import annotations

import os
import sys

try:
    import sandbox_runner
    import telemetry
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import sandbox_runner
    import telemetry


def compute_utilization(audit_log_path: str | None = None) -> dict:
    """Offline, read-only. Reuses telemetry.audit_log_totals() (P2-TEL,
    already read-only) for the raw per-tool call counts rather than
    re-parsing audit.jsonl a second time. Returns {"by_tool": {<tool>: N,
    ...}, "never_used": [...], "unregistered_tools_seen": {<tool>: N, ...}}
    -- by_tool always has one entry per KNOWN tool (0 if never called);
    unregistered_tools_seen holds any audit_log tool name outside the known
    inventory, reported separately rather than silently dropped or silently
    folded into the known set."""
    totals = telemetry.audit_log_totals(audit_log_path)
    observed_by_tool = totals["by_tool"]

    known_tools = set(sandbox_runner._TOOL_MAP.keys())
    by_tool = {tool: observed_by_tool.get(tool, 0) for tool in known_tools}
    never_used = sorted(tool for tool, count in by_tool.items() if count == 0)
    unregistered_tools_seen = {
        tool: count for tool, count in observed_by_tool.items() if tool not in known_tools
    }

    return {"by_tool": by_tool, "never_used": never_used, "unregistered_tools_seen": unregistered_tools_seen}
