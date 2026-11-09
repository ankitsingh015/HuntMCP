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

## What this task does NOT yet do

Per-target dedupe now skips a target already in progress elsewhere
(tracked via `work_registry`) instead of double-firing it against a live
target. A later task still owes inter-batch backoff, so a target that
errors isn't immediately relaunched into the next slot. The slot-ceiling
check in _fill_slots() is kept as a small, single-site piece specifically
so that task can extend it without touching call sites elsewhere in this
file.
"""

from __future__ import annotations

import time  # noqa: F401 -- unused here; Task 3 monkeypatches fanout.time.time for backoff
import uuid
from typing import Callable, NamedTuple

import job_runtime
import work_registry

# Per-tool concurrency ceiling -- how many jobs for a given tool_name may be
# in_flight at once across all callers sharing one `jobs` dict. A plain
# dict/int is enough for this task's tests to monkeypatch directly; real
# env-var-driven configuration of these values is Task 3's job.
DEFAULT_CAPS: dict[str, int] = {}
DEFAULT_CAP_FALLBACK: int = 3


class _Batch(NamedTuple):
    tool_name: str
    prepare: Callable[[str], dict]
    pending: list[str]
    in_flight: dict[str, tuple[str, str]]  # target -> (job_id, work_id)
    results: dict[str, dict]


def _new_batch_id() -> str:
    return uuid.uuid4().hex[:12]


def _cap_for(tool_name: str) -> int:
    return DEFAULT_CAPS.get(tool_name, DEFAULT_CAP_FALLBACK)


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
    cap = _cap_for(batch.tool_name)
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
            batch.results[target] = {"kind": "job_result", **polled}
            del batch.in_flight[target]

    _fill_slots(batch, jobs)

    if not batch.pending and not batch.in_flight:
        batches.pop(batch_id, None)

    return _snapshot(batch_id, batch)
