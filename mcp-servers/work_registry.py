"""Duplicate-work check (ARCHITECTURE.md Phase 2.9) -- a lightweight dedup
registry HuntBrain checks before spawning a specialist, mirroring Strix's
`view_agent_graph` tool. Deliberately NOT Strix's full dynamic any-agent-
spawns-any-agent graph -- just the "don't redo work" benefit, without the
shared-coordinator locking complexity HuntMCP's fixed roster doesn't need.

Concretely useful for HuntMCP's actual failure mode: a long engagement that
gets context-compacted mid-run (this exact repo has hit that) can lose
track of which specialists -- especially dynamic ones like a future
jwt-agent/graphql-agent -- were already spawned for which host. This
registry survives that, since it lives on disk, not in HuntBrain's own
conversation context.

State is per-engagement, reset alongside engagement.yaml/budget.json.

CLI usage (what HuntBrain runs via Bash around each specialist spawn):
    python3 mcp-servers/work_registry.py start <agent> <host> [task]
        -> prints a work_id
    python3 mcp-servers/work_registry.py complete <work_id> [outcome]
    python3 mcp-servers/work_registry.py active [host]
        -> JSON list of in-progress work, optionally filtered by host --
           check this BEFORE spawning to see if it's already running
    python3 mcp-servers/work_registry.py all
        -> JSON list of every start/complete this engagement
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

import file_lock

# Snapshot only, for introspection/backward-compat -- every function below
# re-resolves this fresh via _resolve_path() instead of using this frozen
# value (a literal `path: str = DEFAULT_PATH` parameter default freezes
# onto whatever active-engagement pointer existed at import time; see
# scope_guard.load_engagement's comment for the full story).
DEFAULT_PATH = engagement_paths.resolve("work-registry.json", override_env="HUNTMCP_WORK_REGISTRY_PATH")

# How long an "in_progress" entry is trusted before list_active_work()
# treats it as abandoned rather than genuinely still running. 2 hours is
# generous for any real specialist task (full nuclei/sqlmap runs
# included) while still letting a session recover from a dead lock
# within the same sitting instead of needing a manual registry reset.
STALE_AFTER_SECONDS = int(os.getenv("HUNTMCP_WORK_STALE_AFTER_S", str(2 * 60 * 60)))


def _resolve_path(path: str | None) -> str:
    if path is not None:
        return path
    return engagement_paths.resolve("work-registry.json", override_env="HUNTMCP_WORK_REGISTRY_PATH")


def _load(path: str | None = None) -> dict:
    path = _resolve_path(path)
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _save(state: dict, path: str | None = None) -> None:
    path = _resolve_path(path)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def start_work(agent: str, host: str, task: str = "", path: str | None = None) -> str:
    """Record a specialist as in-progress on a host. Returns a work_id to
    pass to complete_work() when it returns."""
    path = _resolve_path(path)
    with file_lock.locked(path):
        state = _load(path)
        work_id = uuid.uuid4().hex[:8]
        state[work_id] = {
            "agent": agent,
            "host": host,
            "task": task,
            "status": "in_progress",
            "started_at": time.time(),
            "completed_at": None,
            "outcome": None,
        }
        _save(state, path)
    return work_id


def complete_work(work_id: str, outcome: str = "", path: str | None = None) -> bool:
    path = _resolve_path(path)
    with file_lock.locked(path):
        state = _load(path)
        if work_id not in state:
            return False
        state[work_id]["status"] = "completed"
        state[work_id]["completed_at"] = time.time()
        state[work_id]["outcome"] = outcome
        _save(state, path)
        return True


def list_active_work(host: str | None = None, path: str | None = None) -> list[dict]:
    """Everything currently in_progress -- check this before spawning a
    specialist to avoid redundant work on the same host.

    An entry started more than STALE_AFTER_SECONDS ago and never marked
    complete is excluded (not treated as still-active). Bug found live:
    if the process that called start_work() dies mid-work -- a network
    hang, a kill, a crash -- nothing ever calls complete_work() for it,
    so the lock was permanent; a resumed session (which deliberately
    skips resetting this registry, see huntbrain.md's Phase 0 -- "the
    whole point of switching the pointer back is that the target's prior
    state is exactly as it was left") would see that host/agent as
    forever "already being worked on" and never retry it. Real work
    realistically finishes well under this threshold; a stuck entry past
    it is far more likely dead than still running."""
    path = _resolve_path(path)
    with file_lock.locked(path):
        state = _load(path)
    now = time.time()
    items = [
        dict(id=k, **v) for k, v in state.items()
        if v["status"] == "in_progress" and (now - v["started_at"]) < STALE_AFTER_SECONDS
    ]
    if host:
        items = [i for i in items if i["host"] == host]
    return items


def list_all_work(path: str | None = None) -> list[dict]:
    path = _resolve_path(path)
    with file_lock.locked(path):
        state = _load(path)
    return [dict(id=k, **v) for k, v in state.items()]


def _cli() -> None:
    if len(sys.argv) < 2:
        print("usage: work_registry.py <start|complete|active|all> ...", file=sys.stderr)
        sys.exit(2)

    cmd = sys.argv[1]
    if cmd == "start":
        if len(sys.argv) < 4:
            print("usage: work_registry.py start <agent> <host> [task]", file=sys.stderr)
            sys.exit(2)
        agent, host = sys.argv[2], sys.argv[3]
        task = sys.argv[4] if len(sys.argv) > 4 else ""
        print(start_work(agent, host, task))
    elif cmd == "complete":
        if len(sys.argv) < 3:
            print("usage: work_registry.py complete <work_id> [outcome]", file=sys.stderr)
            sys.exit(2)
        work_id = sys.argv[2]
        outcome = sys.argv[3] if len(sys.argv) > 3 else ""
        if not complete_work(work_id, outcome):
            print(f"BLOCKED: no such work_id {work_id!r}", file=sys.stderr)
            sys.exit(1)
        print(f"completed {work_id}")
    elif cmd == "active":
        host = sys.argv[2] if len(sys.argv) > 2 else None
        print(json.dumps(list_active_work(host), indent=2))
    elif cmd == "all":
        print(json.dumps(list_all_work(), indent=2))
    else:
        print(f"unknown command {cmd!r}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    _cli()
