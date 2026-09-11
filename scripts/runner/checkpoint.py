"""Checkpoint (resumable state) for the HuntMCP dev-runner.

The checkpoint is a runner-owned JSON cache -- an audit trail of the last
resolution, NOT the plan. The plan document remains the single source of truth;
the resolver always recomputes from it. The checkpoint exists so a fresh session
can see, without conversation memory, what the previous session concluded and
where it stopped.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

CHECKPOINT_NOTE = (
    "Runner-owned resumable cache. This is NOT the plan. The PHASE1-EXECUTION-PLAN.md "
    "document remains the source of truth; the runner recomputes state from it every run."
)


def build_checkpoint(
    plan_source: str,
    decision: str,
    next_task: str | None,
    next_task_title: str | None,
    counts: dict,
    blocked_tasks: list[str],
    stop_codes: list[str],
    worktree_branch: str | None,
    verification: dict | None = None,
) -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "plan_source": plan_source,
        "decision": decision,
        "next_task": next_task,
        "next_task_title": next_task_title,
        "counts": counts,
        "blocked_tasks": blocked_tasks,
        "stop_codes": stop_codes,
        "worktree_branch": worktree_branch,
        "verification": verification,
        "note": CHECKPOINT_NOTE,
    }


def write_checkpoint(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def read_checkpoint(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
