import importlib.util
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "job_runtime", os.path.join(ROOT, "mcp-servers", "job_runtime.py")
)
job_runtime = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(job_runtime)


def _no_budget(monkeypatch):
    # start_job() enforces budget_guard before launching -- irrelevant to
    # what these tests check, and would otherwise touch the real (or
    # active-engagement) budget.json.
    monkeypatch.setattr(job_runtime, "_enforce_budget", lambda name: None)


def _no_audit(monkeypatch):
    monkeypatch.setattr(job_runtime, "_log_call", lambda *a, **k: None)


def test_start_job_returns_immediately_with_running_status(monkeypatch):
    _no_budget(monkeypatch)
    jobs = {}
    result = job_runtime.start_job("sleep", ["2"], max_wall_seconds=30, jobs=jobs)
    try:
        assert result["status"] == "running"
        assert result["job_id"] in jobs
    finally:
        jobs[result["job_id"]].proc.kill()
        jobs[result["job_id"]].proc.wait()


def test_poll_job_reports_running_before_completion(monkeypatch):
    _no_budget(monkeypatch)
    jobs = {}
    started = job_runtime.start_job("sleep", ["5"], max_wall_seconds=30, jobs=jobs)
    try:
        polled = job_runtime.poll_job(started["job_id"], jobs)
        assert polled["status"] == "running"
        assert started["job_id"] in jobs  # still-running jobs are never popped
    finally:
        jobs[started["job_id"]].proc.kill()
        jobs[started["job_id"]].proc.wait()


def test_poll_job_captures_stdout_once_finished(monkeypatch):
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)
    jobs = {}
    started = job_runtime.start_job(
        "echo", ["hello from the background"], max_wall_seconds=30, jobs=jobs
    )
    job_id = started["job_id"]
    # Non-blocking poll; the child is short-lived but not guaranteed to
    # have exited the instant Popen() returns -- poll until it has, same
    # as a real caller would, instead of assuming immediate completion.
    deadline = time.monotonic() + 5
    result = job_runtime.poll_job(job_id, jobs)
    while result["status"] == "running" and time.monotonic() < deadline:
        result = job_runtime.poll_job(job_id, jobs)

    assert result["status"] == "done"
    assert result["returncode"] == 0
    assert "hello from the background" in result["stdout"]
    # Finished jobs are popped -- a second poll must not resurrect it.
    assert job_id not in jobs


def test_poll_job_pops_job_so_second_poll_reports_no_job(monkeypatch):
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)
    jobs = {}
    started = job_runtime.start_job("true", [], max_wall_seconds=30, jobs=jobs)
    job_id = started["job_id"]
    deadline = time.monotonic() + 5
    result = job_runtime.poll_job(job_id, jobs)
    while result["status"] == "running" and time.monotonic() < deadline:
        result = job_runtime.poll_job(job_id, jobs)
    assert result["status"] == "done"

    second = job_runtime.poll_job(job_id, jobs)
    assert "error" in second
    assert job_id in second["error"]


def test_poll_job_unknown_job_id_returns_error():
    assert "error" in job_runtime.poll_job("does-not-exist", {})


def test_poll_job_kills_process_past_max_wall_seconds(monkeypatch):
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)
    jobs = {}
    started = job_runtime.start_job("sleep", ["30"], max_wall_seconds=30, jobs=jobs)
    job_id = started["job_id"]
    # Force the ceiling check to trip without actually waiting 30s.
    job = jobs[job_id]
    jobs[job_id] = job._replace(started_monotonic=time.monotonic() - job.max_wall_seconds - 1)

    result = job_runtime.poll_job(job_id, jobs)
    assert result["status"] == "timeout"
    assert job_id not in jobs


def test_start_job_missing_binary_raises_filenotfounderror(monkeypatch):
    _no_budget(monkeypatch)
    jobs = {}
    try:
        job_runtime.start_job("definitely-not-a-real-binary-xyz", [], max_wall_seconds=30, jobs=jobs)
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass
    assert jobs == {}  # nothing left behind on a failed launch


def test_list_jobs_reports_elapsed_time_and_no_destructive_side_effect(monkeypatch):
    _no_budget(monkeypatch)
    jobs = {}
    started = job_runtime.start_job("sleep", ["5"], max_wall_seconds=30, jobs=jobs)
    try:
        listed = job_runtime.list_jobs(jobs)
        assert len(listed) == 1
        assert listed[0]["job_id"] == started["job_id"]
        assert listed[0]["elapsed_s"] >= 0
        assert listed[0]["likely_abandoned"] is False
        # list_jobs() must not poll/collect -- the job is still there.
        assert started["job_id"] in jobs
    finally:
        jobs[started["job_id"]].proc.kill()
        jobs[started["job_id"]].proc.wait()


def test_list_jobs_flags_likely_abandoned_past_threshold(monkeypatch):
    _no_budget(monkeypatch)
    jobs = {}
    started = job_runtime.start_job("sleep", ["5"], max_wall_seconds=9999, jobs=jobs)
    job_id = started["job_id"]
    job = jobs[job_id]
    jobs[job_id] = job._replace(
        started_monotonic=time.monotonic() - job_runtime.JOB_STALE_AFTER_SECONDS - 1
    )
    try:
        listed = job_runtime.list_jobs(jobs)
        assert listed[0]["likely_abandoned"] is True
    finally:
        jobs[job_id].proc.kill()
        jobs[job_id].proc.wait()


def test_poll_job_reaps_other_stale_sibling_jobs(monkeypatch):
    # A job nobody ever polls again would otherwise keep running (and its
    # temp files leaking) forever -- poll_job() on ANY job_id should also
    # sweep up other abandoned jobs in the same dict past their own
    # max_wall_seconds, not just the one being polled.
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)
    jobs = {}
    abandoned = job_runtime.start_job("sleep", ["30"], max_wall_seconds=30, jobs=jobs)
    abandoned_id = abandoned["job_id"]
    job = jobs[abandoned_id]
    jobs[abandoned_id] = job._replace(started_monotonic=time.monotonic() - job.max_wall_seconds - 1)

    other = job_runtime.start_job("true", [], max_wall_seconds=9999, jobs=jobs)
    other_id = other["job_id"]
    try:
        deadline = time.monotonic() + 5
        result = job_runtime.poll_job(other_id, jobs)
        while result["status"] == "running" and time.monotonic() < deadline:
            result = job_runtime.poll_job(other_id, jobs)

        # Polling `other_id` must have reaped the abandoned sibling too.
        assert abandoned_id not in jobs
    finally:
        if other_id in jobs:
            jobs[other_id].proc.kill()
            jobs[other_id].proc.wait()


def test_budget_is_enforced_exactly_once_per_start_job_not_per_poll(monkeypatch):
    calls = []
    monkeypatch.setattr(job_runtime, "_enforce_budget", lambda name: calls.append(name))
    _no_audit(monkeypatch)
    jobs = {}
    started = job_runtime.start_job("true", [], max_wall_seconds=30, jobs=jobs)
    job_id = started["job_id"]
    assert calls == ["true"]

    deadline = time.monotonic() + 5
    result = job_runtime.poll_job(job_id, jobs)
    while result["status"] == "running" and time.monotonic() < deadline:
        result = job_runtime.poll_job(job_id, jobs)
    # Polling (running or done) must never call budget_guard again --
    # only the original start_job() call should have.
    assert calls == ["true"]


# ---- Thread-based jobs (start_thread_job/poll_thread_job/list_thread_jobs) --
# for a composite operation (several sequential run_tool() calls) rather
# than a single subprocess -- see watch-mcp's start_watch()/check_target().

def _poll_thread_until_done(job_id, jobs, timeout_s=5):
    deadline = time.monotonic() + timeout_s
    result = job_runtime.poll_thread_job(job_id, jobs)
    while result["status"] == "running" and time.monotonic() < deadline:
        time.sleep(0.01)
        result = job_runtime.poll_thread_job(job_id, jobs)
    return result


def test_start_thread_job_returns_immediately_with_running_status():
    jobs = {}
    done = threading.Event()

    def slow_fn():
        done.wait(timeout=5)
        return "finished"

    result = job_runtime.start_thread_job("watch-check", slow_fn, jobs)
    try:
        assert result["status"] == "running"
        assert result["job_id"] in jobs
    finally:
        done.set()


def test_poll_thread_job_reports_done_with_return_value():
    jobs = {}
    result = job_runtime.start_thread_job("watch-check", lambda: "the actual result text", jobs)
    job_id = result["job_id"]

    final = _poll_thread_until_done(job_id, jobs)
    assert final["status"] == "done"
    assert final["value"] == "the actual result text"
    # Must be popped -- a second poll reports "no job".
    assert job_id not in jobs
    again = job_runtime.poll_thread_job(job_id, jobs)
    assert "status" not in again
    assert "no job" in again["error"]


def test_poll_thread_job_surfaces_exception_as_error_status():
    jobs = {}

    def boom():
        raise ValueError("something inside fn broke")

    result = job_runtime.start_thread_job("watch-check", boom, jobs)
    job_id = result["job_id"]

    final = _poll_thread_until_done(job_id, jobs)
    assert final["status"] == "error"
    assert "something inside fn broke" in final["error"]
    assert job_id not in jobs


def test_start_thread_job_passes_args_and_kwargs_through_to_fn():
    jobs = {}
    result = job_runtime.start_thread_job(
        "watch-check", lambda a, b, c=None: f"{a}-{b}-{c}", jobs, "x", "y", c="z",
    )
    final = _poll_thread_until_done(result["job_id"], jobs)
    assert final["value"] == "x-y-z"


def test_start_thread_job_does_not_call_budget_guard_itself(monkeypatch):
    # Unlike start_job() (which wraps exactly the one subprocess it
    # charges for), start_thread_job()'s fn makes its own real run_tool()
    # calls, each of which already enforces budget individually -- an
    # extra charge here for the composite operation itself would inflate
    # the count relative to actual external calls made.
    calls = []
    monkeypatch.setattr(job_runtime, "_enforce_budget", lambda name: calls.append(name))
    jobs = {}
    result = job_runtime.start_thread_job("watch-check", lambda: "ok", jobs)
    _poll_thread_until_done(result["job_id"], jobs)
    assert calls == []


def test_list_thread_jobs_reports_elapsed_time_and_flags_abandoned():
    jobs = {}
    done = threading.Event()
    result = job_runtime.start_thread_job("watch-initial-snapshot", lambda: done.wait(timeout=5), jobs)
    job_id = result["job_id"]
    try:
        listed = job_runtime.list_thread_jobs(jobs)
        assert len(listed) == 1
        assert listed[0]["job_id"] == job_id
        assert listed[0]["tool"] == "watch-initial-snapshot"
        assert listed[0]["likely_abandoned"] is False

        job = jobs[job_id]
        jobs[job_id] = job._replace(started_monotonic=time.monotonic() - job_runtime.JOB_STALE_AFTER_SECONDS - 1)
        listed = job_runtime.list_thread_jobs(jobs)
        assert listed[0]["likely_abandoned"] is True
    finally:
        done.set()


def test_peek_thread_job_done_reports_false_while_running_true_once_finished_none_if_absent():
    jobs = {}
    done = threading.Event()
    result = job_runtime.start_thread_job("watch-check", lambda: done.wait(timeout=5), jobs)
    job_id = result["job_id"]

    assert job_runtime.peek_thread_job_done(job_id, jobs) is False
    done.set()
    deadline = time.time() + 5
    while job_runtime.peek_thread_job_done(job_id, jobs) is False and time.time() < deadline:
        time.sleep(0.005)
    assert job_runtime.peek_thread_job_done(job_id, jobs) is True

    # And critically: peeking must NOT have popped the job the way
    # poll_thread_job() does -- it's still there, still peekable.
    assert job_id in jobs

    assert job_runtime.peek_thread_job_done("no-such-job", jobs) is None
