"""P2-TEL -- offline, passive telemetry: HTTP/tool/wall-clock/token-yield
signals aggregated and linked to findings, at zero hot-path cost.

Why offline/passive, not a new hook: adding a telemetry-recording call into
tool_resolver.run_tool()/job_runtime.start_job()'s shared chokepoints would
put a new dependency on this module's own correctness into every real
Tier-2 tool call -- exactly the "hot path" this task's own acceptance
criterion (IMPLEMENTATION-TASK-TRACKER.md P2-TEL: "0 hot-path cost") rules
out. Instead this module reads data ALREADY being recorded for other
reasons and aggregates it after the fact:
  - audit_log.jsonl -- every Tier-2 tool call's duration_ms, already written
    by tool_resolver.run_tool() via audit_log.log_call().
  - case_store.db's `experiments` table -- already links tool/cost/target to
    a finding_id via log_experiment()'s existing FK.
  - case_store.db's `cem_trials` table -- one row per REAL HTTP request
    issued during a CEM determinism/intervention run (confirmed exact by
    PHASE1-EXECUTION-PLAN.md's M1 measurement: "trials_persisted ==
    http_delta") -- the one place in this codebase today where a literal
    per-HTTP-request count already exists, linked to a finding_id.
  - test_telemetry.py::test_telemetry_not_wired_into_hot_path_chokepoints
    asserts by construction that this module is never imported by either
    real chokepoint, so "0 hot-path cost" isn't just a claim in this
    docstring -- it's enforced by a regression test.

Honest limits, not silently overclaimed (same standard as audit_log.py/
budget_guard.py's own documented gaps):
  (1) `token_yield` is ALWAYS caller-supplied, never measured here --
      budget_guard.py's own docstring already established why: no MCP
      server has visibility into the orchestrating agent's own token
      spend, that number lives inside whichever harness (OpenCode/Claude
      Code) is driving the session. Passing it through this module just
      gives it one consistent place to land next to the signals this layer
      CAN see, not a new measurement capability.
  (2) `to_bench_cost()`'s `requests` key is `tool_calls` under a different
      name, not a literal per-HTTP-request count -- most real Tier-2 tools
      (nuclei/sqlmap/httpx) issue many real HTTP requests per single tool
      call and don't expose a machine-readable request count back to the
      caller today. The one place a literal count DOES exist is
      `cem_trials` (above), which `finding_telemetry()` uses when present.
      Widening this to a real per-request count for every tool is a
      natural next increment, not built here (would need parsing each
      tool's own stats output -- out of this task's minimal scope).
  (3) `finding_telemetry()`'s experiment-based signal comes ONLY from
      `case_store.experiments` rows explicitly logged against that
      finding_id via `log_experiment()` -- it does NOT cross-reference
      audit_log.jsonl by tool/time-proximity heuristics (fragile, since
      audit_log entries carry no finding_id today). A caller that wants a
      finding's wall-clock cost captured here must call
      `log_experiment(..., finding_id=..., cost=<duration_ms or count>)`
      itself.
"""

from __future__ import annotations

import json
import os
import sys

try:
    import audit_log
    import case_store
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import audit_log
    import case_store


def audit_log_totals(audit_log_path: str | None = None) -> dict:
    """Read-only aggregate over audit.jsonl: {tool_calls, wall_clock_ms,
    by_tool}. Malformed/unparseable lines are skipped, not raised -- this is
    offline analytics reading a log file another process may still be
    appending to, not a correctness-critical parse.

    Path resolution is delegated to audit_log._resolve_path() (the same
    active-engagement-aware resolution audit_log.log_call() itself uses)
    rather than re-derived here, so the two modules can't silently diverge
    on where the file lives -- audit_log.py is a hook-tamper-resistance
    protected path (S6), so a *public* wrapper there needs a human-run
    `scripts/confirm-hook-edit.sh` confirm to add; calling its existing
    private resolver directly avoids that for a same-project, read-only
    reuse with no behavior change to audit_log.py itself."""
    path = audit_log._resolve_path(audit_log_path)
    if not os.path.isfile(path):
        return {"tool_calls": 0, "wall_clock_ms": 0.0, "by_tool": {}}

    tool_calls = 0
    wall_clock_ms = 0.0
    by_tool: dict[str, int] = {}
    with open(path) as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            tool = entry.get("tool")
            if not tool or not isinstance(tool, str):
                # A non-string "tool" (e.g. a JSON list/dict) is truthy and
                # would otherwise reach `by_tool[tool] = ...` below and raise
                # TypeError: unhashable type, crashing this offline aggregate
                # on a malformed line the same way the duration_ms bug above
                # did (round-2 review finding, independently confirmed twice).
                continue
            duration_raw = entry.get("duration_ms")
            try:
                # bool is a subclass of int -- float(True) == 1.0 succeeds
                # silently instead of being treated as the malformed value
                # it is (round-2 review finding: a duration_ms: true line
                # would otherwise contribute a wrong nonzero duration
                # instead of the documented "unknown/0" fallback).
                if isinstance(duration_raw, bool):
                    raise TypeError("duration_ms must not be a bool")
                duration = float(duration_raw or 0.0)
            except (TypeError, ValueError):
                # A validly-JSON but wrongly-typed duration_ms (e.g. a
                # hand-edited or corrupted line) shouldn't crash an offline
                # aggregate over a file another process may still be
                # appending to -- count the call, treat its duration as
                # unknown/0 rather than raising (found via code review:
                # this used to be an uncaught ValueError/TypeError that
                # propagated straight through postmortem.py's
                # run_postmortem(), breaking its always-produces-a-report
                # promise).
                duration = 0.0
            tool_calls += 1
            wall_clock_ms += duration
            by_tool[tool] = by_tool.get(tool, 0) + 1

    return {"tool_calls": tool_calls, "wall_clock_ms": round(wall_clock_ms, 1), "by_tool": by_tool}


def to_bench_cost(audit_log_path: str | None = None) -> dict:
    """Adapt audit_log_totals() into the `cost: dict[str, float]` shape
    tests/fixtures/bench_target/bench_evaluator.py's `evaluate(cost=...)`
    expects (`tool_calls, wall_clock_s, requests` -- see that module's own
    "token/$ cost later (P2-TEL)" design comment). `requests` is
    `tool_calls` under this module's own documented per-tool-call-not-
    per-HTTP-request limit (see module docstring, point 2)."""
    totals = audit_log_totals(audit_log_path)
    return {
        "tool_calls": float(totals["tool_calls"]),
        "wall_clock_s": round(totals["wall_clock_ms"] / 1000.0, 3),
        "requests": float(totals["tool_calls"]),
    }


def finding_telemetry(finding_id: int, db_path: str | None = None,
                       token_yield: float | None = None) -> dict:
    """Offline telemetry linked to one finding_id: experiment count/cost
    already recorded via case_store.log_experiment(..., finding_id=...),
    plus a real HTTP-request count when the finding has CEM state
    (case_store.count_cem_trials() -- cem_trials is one row per real
    request, see module docstring). `http_requests` is `None`, not `0`,
    when the finding was never run through CEM -- distinguishing "not
    measured" from "measured, zero requests" (the common case for a
    sqlmap/dalfox/nuclei-confirmed finding that never went through CEM
    would otherwise misleadingly read as zero-cost). token_yield is always
    caller-supplied (see module docstring, point 1); absent (None) by
    default. Returns {"error": ...} if the finding_id doesn't exist,
    matching case_store.py's own not-found convention.

    Resolves db_path ONCE and reuses the result for all three case_store
    calls below (code-review finding, 2026-09-25): passing the original
    (possibly None) db_path to each of get_finding()/list_experiments()/
    count_cem_trials() independently let each one re-resolve the active
    engagement separately inside its own case_store._get_conn() call -- if
    the active engagement were switched mid-call, the three reads could
    silently land against two different engagements' case.db files for
    the same numeric finding_id. Resolving once makes all three agree by
    construction."""
    resolved_db_path = case_store.resolve_db_path(db_path)
    finding = case_store.get_finding(finding_id, db_path=resolved_db_path)
    if finding is None:
        return {"error": f"no finding with id {finding_id}"}

    experiments = case_store.list_experiments(finding_id, db_path=resolved_db_path)
    experiment_cost_total = sum(e.get("cost") or 0 for e in experiments)

    return {
        "finding_id": finding_id,
        "experiment_count": len(experiments),
        "experiment_cost_total": experiment_cost_total,
        "http_requests": case_store.count_cem_trials(finding_id, db_path=resolved_db_path),
        "token_yield": token_yield,
    }
