"""Bounded concurrent fan-out over job_runtime for discovery tools that need
to run several independent calls against different targets at once --
e.g. nuclei-mcp running the same template set across a batch of live hosts
recon just turned up, instead of one scan_url() call per target serialized
through the agent's own tool-call loop.

## Why this exists

job_runtime.start_job()/poll_job() already give a single long-running
subprocess a non-blocking start-then-poll lifecycle. That's necessary but
not sufficient once a caller has N independent targets to run the SAME
tool against: doing it one start_job()/poll_job() pair at a time means the
agent either blocks waiting for each one to finish before starting the
next (exactly the serialization job_runtime was built to avoid), or has to
hand-roll its own cap-tracking and backfill logic per MCP server. This
module is that logic, written once, so a new discovery tool wires in
start_batch()/check_batch() instead of reinventing bounded concurrency.

## What this module does

Per-target dedupe skips a target already in progress elsewhere (tracked
via `work_registry`) instead of double-firing it against a live target.
Persistent, per-tool backoff (`_effective_cap()`/`_record_block()`) means
a tool that comes back blocked (rate-limited/WAF'd) gets a reduced slot
ceiling for COOLDOWN_SECONDS, surviving across separate start_batch()
calls rather than resetting each time -- the state lives in one JSON
file, keyed by tool_name only (not per-target), on the same read-lock-
mutate-save-unlock convention as `work_registry.py`.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from typing import Callable, NamedTuple

import job_runtime
import work_registry
# For test/integration isolation (e.g. a fixture-based e2e test), point the
# dedupe check at an isolated registry file via the HUNTMCP_WORK_REGISTRY_PATH
# env var -- work_registry._resolve_path() already honors it -- rather than
# adding a path= parameter to this module's own functions.

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

import file_lock

# Per-tool concurrency ceiling -- how many jobs for a given tool_name may be
# in_flight at once across all callers sharing one `jobs` dict. Read once at
# import, same convention as budget_guard.MAX_CALLS -- a mid-engagement env
# change isn't a supported scenario.
DEFAULT_CAPS: dict[str, int] = {
    "nuclei": int(os.getenv("HUNTMCP_FANOUT_MAX_NUCLEI", "5")),
}
DEFAULT_CAP_FALLBACK: int = int(os.getenv("HUNTMCP_FANOUT_MAX_DEFAULT", "3"))

# How long a per-tool backoff (set by _record_block()) holds the reduced cap
# before _effective_cap() lets it ramp back to DEFAULT_CAPS.
COOLDOWN_SECONDS: int = int(os.getenv("HUNTMCP_FANOUT_COOLDOWN_SECONDS", "300"))

# Snapshot only, for introspection -- _resolve_backoff_path() re-resolves
# fresh on every call instead of trusting this frozen value (same rationale
# as work_registry.DEFAULT_PATH / engagement_paths.resolve()'s own docstring:
# a literal default would freeze onto whatever active-engagement pointer
# existed at import time).
DEFAULT_PATH = engagement_paths.resolve("fanout-backoff.json", override_env="HUNTMCP_FANOUT_BACKOFF_PATH")


class _Batch(NamedTuple):
    tool_name: str
    prepare: Callable[[str], dict]
    pending: list[str]
    in_flight: dict[str, tuple[str, str]]  # target -> (job_id, work_id)
    results: dict[str, dict]


def _new_batch_id() -> str:
    return uuid.uuid4().hex[:12]


def _resolve_backoff_path(path: str | None) -> str:
    if path is not None:
        return path
    return engagement_paths.resolve("fanout-backoff.json", override_env="HUNTMCP_FANOUT_BACKOFF_PATH")


def _load_backoff(path: str | None = None) -> dict:
    path = _resolve_backoff_path(path)
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)


def _save_backoff(state: dict, path: str | None = None) -> None:
    path = _resolve_backoff_path(path)
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def _effective_cap(tool_name: str, path: str | None = None) -> int:
    """The slot ceiling to use for `tool_name` right now -- the per-tool
    DEFAULT_CAPS value, unless a prior _record_block() for this tool is
    still within its cooldown window, in which case the reduced cap
    recorded at that time applies instead."""
    path = _resolve_backoff_path(path)
    with file_lock.locked(path):
        state = _load_backoff(path)
    entry = state.get(tool_name)
    if entry and time.time() < entry["blocked_until"]:
        return entry["cap"]
    return DEFAULT_CAPS.get(tool_name, DEFAULT_CAP_FALLBACK)


def _record_block(tool_name: str, path: str | None = None) -> None:
    """Record that `tool_name` just came back blocked (rate-limited/WAF'd):
    halve its current effective cap and start a new COOLDOWN_SECONDS
    window. A second block before the first cooldown elapses compounds --
    it halves the ALREADY-reduced cap, rather than resetting from the
    tool's full DEFAULT_CAPS value -- since repeated blocks are evidence
    the first backoff wasn't cautious enough yet."""
    path = _resolve_backoff_path(path)
    with file_lock.locked(path):
        state = _load_backoff(path)
        baseline = state.get(tool_name, {}).get("cap", DEFAULT_CAPS.get(tool_name, DEFAULT_CAP_FALLBACK))
        state[tool_name] = {
            "cap": max(1, baseline // 2),
            "blocked_until": time.time() + COOLDOWN_SECONDS,
        }
        _save_backoff(state, path)


def _fill_slots(batch: _Batch, jobs: dict) -> None:
    """Launch targets off `batch.pending` into `batch.in_flight` until
    either the per-tool cap is hit or there's nothing left to start.

    A prepare() rejection (e.g. scope-blocked) is recorded straight into
    `results` and does NOT consume a slot -- it never became a job, so it
    shouldn't count against the concurrency ceiling the way a real running
    job does. This keeps the loop moving past rejected targets instead of
    stalling with open capacity and pending work.

    A target already showing up as in-progress elsewhere in
    `work_registry` (another batch, another specialist entirely) is
    likewise recorded without consuming a slot, as `{"kind":
    "skipped_in_flight"}` -- it never becomes a job here, so it shouldn't
    count against this batch's concurrency ceiling either.
    """
    cap = _effective_cap(batch.tool_name)
    while len(batch.in_flight) < cap and batch.pending:
        target = batch.pending.pop(0)
        if work_registry.list_active_work(host=target):
            batch.results[target] = {"kind": "skipped_in_flight"}
            continue
        prepared = batch.prepare(target)
        if "error" in prepared:
            batch.results[target] = {"kind": "prepare_error", "error": prepared["error"]}
            continue
        started = job_runtime.start_job(batch.tool_name, jobs=jobs, **prepared)
        work_id = work_registry.start_work("fanout", target, task=batch.tool_name)
        batch.in_flight[target] = (started["job_id"], work_id)


def _snapshot(batch_id: str, batch: _Batch) -> dict:
    status = "done" if not batch.pending and not batch.in_flight else "running"
    return {
        "batch_id": batch_id,
        "status": status,
        "pending": list(batch.pending),
        "in_flight": list(batch.in_flight.keys()),
        "results": dict(batch.results),
    }


def start_batch(tool_name: str, targets: list[str], prepare: Callable[[str], dict],
                 batches: dict, jobs: dict) -> dict:
    """Start a new batch of `tool_name` runs, one per target in `targets`,
    bounded by DEFAULT_CAPS. Returns the same snapshot shape check_batch()
    does -- callers poll with check_batch() using the returned batch_id
    until status is "done"."""
    batch_id = _new_batch_id()
    batch = _Batch(
        tool_name=tool_name,
        prepare=prepare,
        pending=list(targets),
        in_flight={},
        results={},
    )
    batches[batch_id] = batch
    _fill_slots(batch, jobs)

    if not batch.pending and not batch.in_flight:
        batches.pop(batch_id, None)
        return _snapshot(batch_id, batch)
    return _snapshot(batch_id, batch)


def check_batch(batch_id: str, batches: dict, jobs: dict) -> dict:
    """Poll every in-flight job in the batch, move terminal ones into
    `results`, backfill freed slots from `pending`, and pop the whole
    batch out of `batches` once both pending and in_flight are empty --
    same "pop on terminal" convention poll_job() itself uses."""
    batch = batches.get(batch_id)
    if batch is None:
        return {"error": f"no batch with batch_id={batch_id!r}"}

    for target, (job_id, work_id) in list(batch.in_flight.items()):
        polled = job_runtime.poll_job(job_id, jobs)
        if polled.get("status") != "running":
            work_registry.complete_work(work_id, outcome=polled.get("status", ""))
            if polled.get("block"):
                _record_block(batch.tool_name)
            batch.results[target] = {"kind": "job_result", **polled}
            del batch.in_flight[target]

    _fill_slots(batch, jobs)

    if not batch.pending and not batch.in_flight:
        batches.pop(batch_id, None)

    return _snapshot(batch_id, batch)
