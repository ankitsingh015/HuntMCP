"""Background subprocess execution for scan tools whose runs can
legitimately take minutes -- nuclei, sqlmap, nmap, dalfox.

## Why this exists

Every one of those servers used to call tool_resolver.run_tool(), which
blocks on subprocess.run(timeout=...) until the tool finishes or the
tool's OWN timeout fires. That races the MCP client's own protocol-level
per-call timeout, which is shorter and not configurable from here. When
the client gives up first, the agent sees an opaque "-32001 Request timed
out" -- but the server was never told to stop, so the scan keeps running
in the background anyway (already charged against budget_guard.py before
the subprocess even started). Seeing what looks like a failed call, the
agent's natural next move is to retry -- launching a SECOND scan against
the same live target while the first is still running underneath it.
Confirmed live: a dalfox scan_url() call against a staging target hit
exactly this.

## The fix

scan_*() launches the tool via start_job() and returns a job_id
immediately -- fast enough that no client-side timeout can plausibly fire
on the launch call itself. The agent then polls check_scan(job_id)
(wired up per-server as a thin MCP tool) until status is "done". Exactly
one budget_guard call happens, at launch; polling is a local status read
with zero target contact, so it must never count as a second Tier-2 call.

## What's deliberately NOT preserved from run_tool()

run_tool() auto-retries once (after a 5s sleep) when its output signals a
rate limit. Replicating that here would mean sleeping inside a poll call
(reintroducing the exact blocking this module exists to avoid) or a more
elaborate deferred-relaunch scheduler for a corner case that isn't the
one actually reported. Instead, a rate-limit signal on a finished job is
surfaced via `block` in poll_job()'s return, same as a WAF block already
is -- the caller decides whether to relaunch, matching how run_tool()
itself already treats WAF blocks ("returns as-is so the calling MCP
server or agent can escalate", per its own docstring) rather than
silently retrying.

## Job storage

Each MCP server module owns its own `jobs: dict[str, _Job]` and passes it
into every call here -- job ids are therefore scoped per server process,
never shared or persisted across a restart. A Popen handle and open file
paths aren't meaningfully picklable to disk anyway (browser-mcp's
_live_interventions dict uses the same in-process-only pattern for its
own long-lived-across-calls state, for the same reason).
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import uuid
from typing import NamedTuple

from audit_log import log_call as _log_call
from budget_guard import enforce as _enforce_budget
from tool_resolver import classify_block, resolve_tool

# Past this many seconds since the last poll saw it running, list_jobs()
# flags a job as likely-abandoned -- informational only, never auto-killed
# here (that's still poll_job()'s own max_wall_seconds ceiling, which DOES
# kill, but only gets evaluated when someone actually polls). Mirrors
# browser-mcp's INTERVENTION_STALE_AFTER_SECONDS convention.
JOB_STALE_AFTER_SECONDS = 30 * 60


class _Job(NamedTuple):
    proc: subprocess.Popen
    tool_name: str
    args: list[str]
    stdout_path: str
    stderr_path: str
    started_monotonic: float
    max_wall_seconds: int


def start_job(tool_name: str, args: list[str], max_wall_seconds: int, jobs: dict,
              cwd: str | None = None) -> dict:
    """Launch `tool_name` with `args` in the background and return
    immediately. Stores the live handle in the caller's `jobs` dict under
    a fresh uuid4 job_id (collision-proof by construction, unlike
    caller-supplied keys -- no TOCTOU reservation dance needed here).

    Output is redirected to temp files rather than PIPE: a Popen with
    stdout=PIPE/stderr=PIPE deadlocks if the child writes enough output to
    fill the OS pipe buffer before anyone reads it, since nothing reads
    from a background job until poll_job() finds it finished. Files have
    no such limit.
    """
    _enforce_budget(tool_name)
    binary = resolve_tool(tool_name)

    stdout_fd, stdout_path = tempfile.mkstemp(prefix=f"{tool_name}-out-", suffix=".log")
    stderr_fd, stderr_path = tempfile.mkstemp(prefix=f"{tool_name}-err-", suffix=".log")
    os.close(stdout_fd)
    os.close(stderr_fd)

    try:
        with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
            proc = subprocess.Popen(
                [binary, *args],
                stdout=out, stderr=err, stdin=subprocess.DEVNULL, cwd=cwd,
            )
    except Exception:
        # Launch itself failed (e.g. binary missing) -- nothing was
        # started, so clean up the temp files immediately rather than
        # leaking them, and let the caller's own FileNotFoundError/
        # Exception handling produce the usual "tool not found" message.
        for p in (stdout_path, stderr_path):
            try:
                os.unlink(p)
            except OSError:
                pass
        raise

    job_id = uuid.uuid4().hex[:12]
    jobs[job_id] = _Job(
        proc=proc, tool_name=tool_name, args=args,
        stdout_path=stdout_path, stderr_path=stderr_path,
        started_monotonic=time.monotonic(), max_wall_seconds=max_wall_seconds,
    )
    return {"job_id": job_id, "status": "running", "tool": tool_name}


def _read_and_cleanup(job: _Job) -> tuple[str, str]:
    stdout = stderr = ""
    try:
        with open(job.stdout_path, errors="replace") as f:
            stdout = f.read()
    except OSError:
        pass
    try:
        with open(job.stderr_path, errors="replace") as f:
            stderr = f.read()
    except OSError:
        pass
    for p in (job.stdout_path, job.stderr_path):
        try:
            os.unlink(p)
        except OSError:
            pass
    return stdout, stderr


def _kill_and_collect(job_id: str, job: _Job, elapsed: float, jobs: dict) -> dict:
    job.proc.kill()
    job.proc.wait()
    stdout, stderr = _read_and_cleanup(job)
    jobs.pop(job_id, None)
    _log_call(job.tool_name, job.args, returncode=-9, duration_ms=elapsed * 1000, block=None)
    return {
        "status": "timeout", "job_id": job_id,
        "error": f"{job.tool_name} timed out after {job.max_wall_seconds}s "
                 f"and was killed -- partial output below, if any",
        "stdout": stdout, "stderr": stderr, "elapsed_s": round(elapsed, 1),
    }


def _reap_other_stale_jobs(jobs: dict, skip_job_id: str) -> None:
    """Piggyback on every real poll_job() call to also kill+collect any
    OTHER job in this same dict that's been running past its own
    max_wall_seconds -- not just the one job_id being polled.

    Why this exists: max_wall_seconds was only ever enforced by the
    branch below when THAT job's own job_id got polled again. A job an
    agent starts and then never checks back on (moves on to other work,
    the session ends, it just forgets) would keep running against the
    live target indefinitely, and its temp files/scratch dirs would never
    get cleaned up -- nothing else in this per-process, in-memory design
    can reap it. This doesn't fully close that gap (a session that starts
    exactly one job and polls nothing else, ever, still leaks that one
    job), but it means any ongoing agent activity against this same MCP
    server -- even polling a completely different, unrelated job --
    now also sweeps up abandoned siblings instead of leaving them running
    forever."""
    now = time.monotonic()
    for other_id, other_job in list(jobs.items()):
        if other_id == skip_job_id:
            continue
        elapsed = now - other_job.started_monotonic
        if elapsed > other_job.max_wall_seconds and other_job.proc.poll() is None:
            _kill_and_collect(other_id, other_job, elapsed, jobs)


def poll_job(job_id: str, jobs: dict) -> dict:
    """Check on a job started by start_job(). Never blocks: reads
    Popen.poll() (a plain waitpid(WNOHANG), non-blocking) rather than
    Popen.wait(). Pops the job out of `jobs` once it's done/timed-out/
    errored, so a second poll on the same job_id cleanly reports "no job"
    instead of re-returning stale results. Also opportunistically reaps
    any OTHER stale job in `jobs` -- see _reap_other_stale_jobs()."""
    _reap_other_stale_jobs(jobs, skip_job_id=job_id)

    job = jobs.get(job_id)
    if job is None:
        return {"error": f"no job with job_id={job_id!r} -- either it was already "
                          f"collected by an earlier check_scan() call, or this "
                          f"job_id was never started"}

    elapsed = time.monotonic() - job.started_monotonic
    returncode = job.proc.poll()

    if returncode is None:
        if elapsed > job.max_wall_seconds:
            return _kill_and_collect(job_id, job, elapsed, jobs)
        return {"status": "running", "job_id": job_id, "elapsed_s": round(elapsed, 1)}

    stdout, stderr = _read_and_cleanup(job)
    jobs.pop(job_id, None)
    block = classify_block(stdout + stderr)
    _log_call(job.tool_name, job.args, returncode=returncode,
              duration_ms=elapsed * 1000, block=block)
    return {
        "status": "done", "job_id": job_id, "returncode": returncode,
        "stdout": stdout, "stderr": stderr, "elapsed_s": round(elapsed, 1),
        "block": block,
    }


def list_jobs(jobs: dict) -> list[dict]:
    """Non-destructive snapshot of everything still running -- does not
    poll/collect/kill anything, just reports elapsed time so an abandoned
    job (agent stopped polling, session ended) is discoverable instead of
    silently running against the target forever with nobody watching."""
    now = time.monotonic()
    out = []
    for job_id, job in jobs.items():
        elapsed = now - job.started_monotonic
        out.append({
            "job_id": job_id,
            "tool": job.tool_name,
            "elapsed_s": round(elapsed, 1),
            "likely_abandoned": elapsed > JOB_STALE_AFTER_SECONDS,
        })
    return out


def block_prefix(result: dict) -> str:
    """A finished poll_job() result carries `block` ("rate_limit"/"waf"/
    None) from classify_block() -- this turns a truthy value into a
    prefix line, or "" when there's nothing to flag. Every server's
    check_scan() should prepend this to its formatted output: without it,
    a run that actually got rate-limited or WAF-blocked mid-scan (exit 0,
    little/no real output) is indistinguishable from a genuine clean "no
    findings" result. run_tool() used to auto-retry once on a rate limit;
    the background-job path deliberately doesn't (see this module's own
    docstring) specifically because the caller is meant to see this
    signal and decide whether to relaunch -- silently dropping it here
    would make backgrounding strictly worse than the old blocking calls,
    not just differently shaped."""
    block = result.get("block")
    if not block:
        return ""
    return f"[{block.upper()} BLOCK DETECTED -- results below may be incomplete]\n"
