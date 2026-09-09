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

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

import file_lock

# Snapshot only, for introspection/backward-compat -- check_budget()/
# enforce() below re-resolve this fresh on every call instead of using
# this frozen value (see scope_guard.load_engagement's comment for why:
# a literal `path: str = DEFAULT_PATH` parameter default freezes onto
# whatever active-engagement pointer existed at import time and never
# picks up a later engagement switch or test override).
DEFAULT_PATH = engagement_paths.resolve("budget.json", override_env="HUNTMCP_BUDGET_PATH")
MAX_CALLS = int(os.getenv("HUNTMCP_MAX_TOOL_CALLS", "500"))
WARNING_BANDS = (0.70, 0.85, 0.95)

# F2 (UD-2=A): CEM sends real HTTP requests that count against the engagement-
# wide MAX_CALLS cap above, AND against a per-finding ceiling so one confirmed
# finding's counterfactual sweep cannot dominate the shared hunting budget.
# The per-finding counter lives in the SAME budget.json (bucket
# `by_cem_finding`, keyed by finding id) under the SAME file lock -- so it is
# durable across sender re-invocations and is reset only by deleting budget.json,
# exactly like the engagement counter. Configurable via
# HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING; re-read fresh on every enforce so a
# malformed/non-positive/unset value transparently falls back to the default
# (unlike MAX_CALLS, which is bound once at import).
CEM_MAX_REQUESTS_PER_FINDING_DEFAULT = 200


def _cem_max_per_finding() -> int:
    raw = os.getenv("HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING")
    if raw is None:
        return CEM_MAX_REQUESTS_PER_FINDING_DEFAULT
    try:
        val = int(raw.strip())
    except ValueError:
        return CEM_MAX_REQUESTS_PER_FINDING_DEFAULT
    return val if val > 0 else CEM_MAX_REQUESTS_PER_FINDING_DEFAULT


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


def _resolve_path(path: str | None) -> str:
    if path is not None:
        return path
    return engagement_paths.resolve("budget.json", override_env="HUNTMCP_BUDGET_PATH")


def check_budget(path: str | None = None) -> dict:
    """Read-only status check -- does not record a call."""
    path = _resolve_path(path)
    with file_lock.locked(path):
        return _status(_load(path))


def enforce(tool_name: str, path: str | None = None) -> dict:
    """Record one Tier-2 tool call and return the current status.

    Prints a one-line stderr notice the first time a new warning band
    (70/85/95%) is crossed, so the calling agent sees it without polling
    check_budget() itself. Raises BudgetExceeded (and does NOT let the
    caller proceed) once the hard cap is reached -- call this BEFORE
    running the actual subprocess, not after.
    """
    path = _resolve_path(path)
    with file_lock.locked(path):
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


def enforce_cem_finding(finding_id: int, path: str | None = None) -> dict:
    """Record one CEM HTTP request for `finding_id` and enforce the per-finding
    ceiling (HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING, default 200).

    Call this BEFORE `enforce("case-mcp")` in the CEM budget callback: once a
    finding is at its ceiling this raises immediately, so a runaway on one
    finding never even reaches -- and so never nibbles -- the shared
    engagement-wide counter. Real requests (those that pass BOTH checks) still
    increment the engagement counter via `enforce()`.

    Same record-then-raise semantics as `enforce()`: the denying request IS
    counted (so retries keep climbing and never reset), and it raises once the
    finding's recorded count EXCEEDS the ceiling -- i.e. exactly `ceiling`
    requests are allowed through. State is `budget.json`'s `by_cem_finding`
    bucket, mutated under the shared file lock; isolated per finding id.

    Because this check runs first, a request that then fails the engagement-wide
    `enforce()` (only possible once the engagement is already at its hard cap) is
    still counted here -- symmetric with `enforce()` itself counting its own
    denied attempts. Both counters are cleared only by deleting `budget.json`.
    """
    path = _resolve_path(path)
    key = str(finding_id)
    ceiling = _cem_max_per_finding()
    with file_lock.locked(path):
        state = _load(path)
        bucket = state.setdefault("by_cem_finding", {})
        bucket[key] = bucket.get(key, 0) + 1
        used = bucket[key]
        _save(state, path)

    if used > ceiling:
        raise BudgetExceeded(
            f"CEM per-finding request ceiling exceeded for finding {finding_id}: "
            f"{used}/{ceiling} CEM requests used (HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING). "
            "Raise it if this finding genuinely needs a deeper counterfactual sweep, "
            "or accept the partial (incomplete=1) bundle for this finding."
        )
    return {"finding_id": finding_id, "cem_requests": used, "cem_max_per_finding": ceiling}


def cem_requests_used(finding_id: int, path: str | None = None) -> int:
    """Read-only: how many CEM requests `enforce_cem_finding` has recorded for
    this finding in the current engagement's budget.json (0 if none / no file)."""
    path = _resolve_path(path)
    with file_lock.locked(path):
        return _load(path).get("by_cem_finding", {}).get(str(finding_id), 0)


def _cli() -> None:
    print(json.dumps(check_budget(), indent=2))


if __name__ == "__main__":
    _cli()
