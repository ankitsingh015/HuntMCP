"""Budget circuit-breaker -- graduated warnings + hard stop on cumulative
Tier-2 tool-call volume per engagement (ARCHITECTURE.md Phase 2.9).

Why call-count, not literal LLM $ cost: no MCP server has visibility into
the orchestrating agent's own token spend -- that number lives inside
whichever harness (OpenCode / Claude Code) is driving the session, and
isn't exposed to a subprocess-launching tool server. Tier-2 tool-call
volume is the actual mechanism that would burn unlimited spend in practice
(a stuck retry loop, runaway recon against a huge attack surface) and IS
directly observable at tool_resolver.run_tool()'s single shared chokepoint
-- so this tracks that as an honest, effective proxy instead of pretending
to meter dollars it can't actually see.

Budget is per-engagement. Reset by deleting budget.json (do this alongside
writing a fresh engagement.yaml at Phase 0). Configurable via
HUNTMCP_MAX_TOOL_CALLS (default 500 -- generous for a full recon+scan+
exploit pass on one target, low enough to catch a genuinely stuck loop).

CLI usage (what HuntBrain can run via Bash to check status without waiting
for a warning):
    python3 mcp-servers/budget_guard.py
    -> prints current {calls, max_calls, pct_used, band, exceeded, by_tool}
"""

from __future__ import annotations

import json
import os
import sys

DEFAULT_PATH = os.getenv("HUNTMCP_BUDGET_PATH", "budget.json")
MAX_CALLS = int(os.getenv("HUNTMCP_MAX_TOOL_CALLS", "500"))
WARNING_BANDS = (0.70, 0.85, 0.95)


class BudgetExceeded(Exception):
    pass


def _load(path: str) -> dict:
    if not os.path.isfile(path):
        return {"calls": 0, "by_tool": {}, "warned_bands": []}
    with open(path) as f:
        return json.load(f)


def _save(state: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def _status(state: dict) -> dict:
    calls = state["calls"]
    pct = (calls / MAX_CALLS) if MAX_CALLS else 0.0
    band = None
    for b in WARNING_BANDS:
        if pct >= b:
            band = b
    return {
        "calls": calls,
        "max_calls": MAX_CALLS,
        "pct_used": round(pct * 100, 1),
        "band": band,
        "exceeded": calls >= MAX_CALLS,
        "by_tool": state["by_tool"],
    }


def check_budget(path: str = DEFAULT_PATH) -> dict:
    """Read-only status check -- does not record a call."""
    return _status(_load(path))


def enforce(tool_name: str, path: str = DEFAULT_PATH) -> dict:
    """Record one Tier-2 tool call and return the current status.

    Prints a one-line stderr notice the first time a new warning band
    (70/85/95%) is crossed, so the calling agent sees it without polling
    check_budget() itself. Raises BudgetExceeded (and does NOT let the
    caller proceed) once the hard cap is reached -- call this BEFORE
    running the actual subprocess, not after.
    """
    state = _load(path)
    state["calls"] += 1
    state["by_tool"][tool_name] = state["by_tool"].get(tool_name, 0) + 1
    status = _status(state)

    if status["band"] is not None and status["band"] not in state["warned_bands"]:
        state["warned_bands"].append(status["band"])
        print(
            f"BUDGET WARNING: {status['calls']}/{status['max_calls']} Tier-2 tool "
            f"calls used this engagement ({status['pct_used']}%).",
            file=sys.stderr,
        )

    _save(state, path)

    if status["exceeded"]:
        raise BudgetExceeded(
            f"Tier-2 tool-call budget exceeded: {status['calls']}/{status['max_calls']} "
            "calls used this engagement. Raise HUNTMCP_MAX_TOOL_CALLS if this is a "
            "genuinely large attack surface, or check budget.json's by_tool breakdown "
            "for a tool that's looping."
        )
    return status


def _cli() -> None:
    print(json.dumps(check_budget(), indent=2))


if __name__ == "__main__":
    _cli()
