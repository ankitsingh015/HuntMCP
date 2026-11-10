import time

import pytest

import budget_guard
import fanout
import job_runtime
import work_registry


@pytest.fixture(autouse=True)
def _isolate_fanout_and_registry_state(tmp_path, monkeypatch):
    """Every test in this module runs against tmp_path-based
    HUNTMCP_FANOUT_BACKOFF_PATH/HUNTMCP_WORK_REGISTRY_PATH files, never
    whatever engagement happens to be active on the machine running the
    suite -- same isolation tests/test_nuclei_mcp.py's own
    _stub_fanout_backoff() helper gives nuclei-mcp's batch tests (see its
    docstring for the real bug this closes: a real active engagement's
    on-disk fanout-backoff.json silently overriding an injected cap).
    Tests that already monkeypatch fanout._effective_cap()/_record_block()
    directly, or that pass their own `path=` explicitly, are unaffected --
    this only changes what the REAL, unpatched functions resolve to when
    no path is given."""
    monkeypatch.setenv("HUNTMCP_FANOUT_BACKOFF_PATH", str(tmp_path / "fanout-backoff.json"))
    monkeypatch.setenv("HUNTMCP_WORK_REGISTRY_PATH", str(tmp_path / "work-registry.json"))


def _stub_work_registry(monkeypatch, active_hosts=(), active_task="nuclei"):
    """Isolate fanout's work_registry calls from the real on-disk
    registry for tests that don't care about dedupe/registration
    themselves -- no host is ever "already in flight" and start/complete
    are no-ops that still hand back a usable work_id. The stubbed
    "active" entry carries agent="fanout"/task=active_task -- matching
    the exact values _fill_slots() itself filters on -- so tests opting
    into active_hosts still exercise a real dedupe skip rather than being
    silently filtered out by the agent/task check."""
    active_hosts = set(active_hosts)

    def fake_list_active_work(host=None, path=None):
        if host in active_hosts:
            return [{"id": "stub", "agent": "fanout", "task": active_task, "host": host}]
        return []

    def fake_start_work(agent, host, task="", path=None):
        return f"work-{host}"

    def fake_complete_work(work_id, outcome="", path=None):
        return True

    monkeypatch.setattr(work_registry, "list_active_work", fake_list_active_work)
    monkeypatch.setattr(work_registry, "start_work", fake_start_work)
    monkeypatch.setattr(work_registry, "complete_work", fake_complete_work)


def test_start_batch_launches_up_to_cap_and_leaves_rest_pending(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 2})
    _stub_work_registry(monkeypatch)

    started = []

    def fake_start_job(tool_name, jobs, **kwargs):
        job_id = f"job-{len(started)}"
        started.append(job_id)
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    targets = ["a.example.com", "b.example.com", "c.example.com"]
    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", targets, lambda t: {"args": []}, batches, jobs)

    assert result["status"] == "running"
    assert len(result["in_flight"]) == 2
    assert result["pending"] == ["c.example.com"]


def test_check_batch_backfills_pending_target_once_a_slot_frees(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 1})
    _stub_work_registry(monkeypatch)

    started = []

    def fake_start_job(tool_name, jobs, **kwargs):
        job_id = f"job-{len(started)}"
        started.append(job_id)
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    poll_results = {}

    def fake_poll_job(job_id, jobs):
        result = poll_results.get(job_id, {"status": "running", "job_id": job_id})
        if result["status"] != "running":
            # Real poll_job() pops a terminal job out of `jobs` -- matched
            # here so a freed slot is actually visible to
            # fanout._running_for_tool()'s cross-batch cap count.
            jobs.pop(job_id, None)
        return result

    monkeypatch.setattr(job_runtime, "poll_job", fake_poll_job)

    targets = ["a.example.com", "b.example.com"]
    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", targets, lambda t: {"args": []}, batches, jobs)

    assert len(result["in_flight"]) == 1
    assert result["pending"] == ["b.example.com"]

    first_job_id = started[0]
    poll_results[first_job_id] = {"status": "done", "job_id": first_job_id, "returncode": 0}

    result2 = fanout.check_batch(result["batch_id"], batches, jobs)

    assert result2["pending"] == []
    assert len(result2["in_flight"]) == 1
    assert "b.example.com" in result2["in_flight"]


def test_check_batch_reports_done_once_everything_terminal(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 2})
    _stub_work_registry(monkeypatch)

    started = []

    def fake_start_job(tool_name, jobs, **kwargs):
        job_id = f"job-{len(started)}"
        started.append(job_id)
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    def fake_poll_job(job_id, jobs):
        return {"status": "done", "job_id": job_id, "returncode": 0}

    monkeypatch.setattr(job_runtime, "poll_job", fake_poll_job)

    targets = ["a.example.com", "b.example.com"]
    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", targets, lambda t: {"args": []}, batches, jobs)
    batch_id = result["batch_id"]

    result2 = fanout.check_batch(batch_id, batches, jobs)

    assert result2["status"] == "done"
    assert result2["pending"] == []
    assert result2["in_flight"] == []
    assert len(result2["results"]) == 2
    assert batch_id not in batches


def test_prepare_error_recorded_without_starting_a_job(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})
    _stub_work_registry(monkeypatch)

    calls = []

    def fake_start_job(tool_name, jobs, **kwargs):
        calls.append(tool_name)
        job_id = f"job-{len(calls)}"
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    def prepare(target):
        if target == "blocked.example.com":
            return {"error": "BLOCKED by scope gate"}
        return {"args": []}

    targets = ["blocked.example.com", "ok.example.com"]
    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", targets, prepare, batches, jobs)

    assert calls == ["nuclei"]
    assert result["results"]["blocked.example.com"] == {
        "kind": "prepare_error",
        "error": "BLOCKED by scope gate",
    }
    assert "ok.example.com" in result["in_flight"]


def test_start_batch_with_empty_targets_returns_done_immediately():
    result = fanout.start_batch("nuclei", [], lambda t: {"args": []}, {}, {})
    assert result["status"] == "done"
    assert result["pending"] == result["in_flight"] == []


def test_check_batch_unknown_batch_id_returns_error():
    result = fanout.check_batch("no-such-batch", {}, {})
    assert "error" in result


def test_fill_slots_skips_target_already_in_work_registry(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})
    _stub_work_registry(monkeypatch, active_hosts={"target-a"})

    start_job_calls = []

    def fake_start_job(tool_name, jobs, **kwargs):
        start_job_calls.append(tool_name)
        job_id = f"job-{len(start_job_calls)}"
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    targets = ["target-a", "target-b"]
    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", targets, lambda t: {"args": []}, batches, jobs)

    assert start_job_calls == ["nuclei"]
    assert result["results"]["target-a"] == {"kind": "skipped_in_flight"}
    assert "target-b" in result["in_flight"]


def test_fill_slots_registers_and_completes_work_for_a_launched_target(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})

    def fake_list_active_work(host=None, path=None):
        return []

    start_work_calls = []

    def fake_start_work(agent, host, task="", path=None):
        start_work_calls.append((agent, host, task))
        return f"work-{host}"

    complete_work_calls = []

    def fake_complete_work(work_id, outcome="", path=None):
        complete_work_calls.append((work_id, outcome))
        return True

    monkeypatch.setattr(work_registry, "list_active_work", fake_list_active_work)
    monkeypatch.setattr(work_registry, "start_work", fake_start_work)
    monkeypatch.setattr(work_registry, "complete_work", fake_complete_work)

    def fake_start_job(tool_name, jobs, **kwargs):
        job_id = "job-0"
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    def fake_poll_job(job_id, jobs):
        return {"status": "done", "job_id": job_id, "returncode": 0}

    monkeypatch.setattr(job_runtime, "poll_job", fake_poll_job)

    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", ["target-c"], lambda t: {"args": []}, batches, jobs)

    assert start_work_calls == [("fanout", "target-c", "nuclei")]
    assert complete_work_calls == []

    batch_id = result["batch_id"]
    result2 = fanout.check_batch(batch_id, batches, jobs)

    assert complete_work_calls == [("work-target-c", "done")]
    assert result2["results"]["target-c"]["kind"] == "job_result"


def test_effective_cap_returns_default_with_no_prior_block(tmp_path):
    path = str(tmp_path / "fanout-backoff.json")
    assert fanout._effective_cap("nuclei", path=path) == fanout.DEFAULT_CAPS.get("nuclei", fanout.DEFAULT_CAP_FALLBACK)


def test_record_block_halves_the_cap_and_sets_a_cooldown(tmp_path, monkeypatch):
    monkeypatch.setattr(fanout, "COOLDOWN_SECONDS", 300)
    path = str(tmp_path / "fanout-backoff.json")
    full = fanout.DEFAULT_CAPS.get("nuclei", fanout.DEFAULT_CAP_FALLBACK)
    fanout._record_block("nuclei", path=path)
    assert fanout._effective_cap("nuclei", path=path) == max(1, full // 2)


def test_a_second_block_compounds_rather_than_resetting(tmp_path):
    path = str(tmp_path / "fanout-backoff.json")
    fanout._record_block("nuclei", path=path)
    once = fanout._effective_cap("nuclei", path=path)
    fanout._record_block("nuclei", path=path)
    assert fanout._effective_cap("nuclei", path=path) == max(1, once // 2)


def test_cap_ramps_back_to_default_once_cooldown_elapses(tmp_path, monkeypatch):
    path = str(tmp_path / "fanout-backoff.json")
    fanout._record_block("nuclei", path=path)
    # simulate time passing past blocked_until -- capture the future timestamp
    # BEFORE patching fanout.time.time, since fanout.time is the same module
    # object as this file's own `time` import: a lambda that calls time.time()
    # itself would recurse into its own patched version.
    future = time.time() + fanout.COOLDOWN_SECONDS + 1
    monkeypatch.setattr(fanout.time, "time", lambda: future)
    assert fanout._effective_cap("nuclei", path=path) == fanout.DEFAULT_CAPS.get("nuclei", fanout.DEFAULT_CAP_FALLBACK)


def test_check_batch_records_a_block_from_a_terminal_job_result(monkeypatch, tmp_path):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})
    recorded = []
    monkeypatch.setattr(fanout, "_record_block", lambda tool_name, path=None: recorded.append(tool_name))
    _stub_work_registry(monkeypatch)

    def fake_start_job(tool_name, jobs, **kwargs):
        job_id = "job-0"
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    def fake_poll_job(job_id, jobs):
        return {"status": "done", "job_id": job_id, "block": "rate_limit"}

    monkeypatch.setattr(job_runtime, "poll_job", fake_poll_job)

    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", ["target-a"], lambda t: {"args": []}, batches, jobs)
    fanout.check_batch(result["batch_id"], batches, jobs)

    assert recorded == ["nuclei"]


def test_default_caps_are_env_overridable(monkeypatch):
    import importlib

    monkeypatch.setenv("HUNTMCP_FANOUT_MAX_NUCLEI", "7")
    try:
        importlib.reload(fanout)
        assert fanout.DEFAULT_CAPS["nuclei"] == 7
    finally:
        monkeypatch.undo()
        importlib.reload(fanout)


# -- Finding 1: a launch exception mid-batch must never silently drop a
# target -- it always ends up in `results`, and a `start_batch()` call must
# always return a batch_id rather than letting the exception propagate and
# abandon the pending queue. --

def test_start_job_exception_is_recorded_as_start_error_not_dropped(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})
    _stub_work_registry(monkeypatch)

    def fake_start_job(tool_name, jobs, **kwargs):
        raise OSError("mkstemp failed: no space left on device")

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    targets = ["a.example.com"]
    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", targets, lambda t: {"args": []}, batches, jobs)

    assert result["results"]["a.example.com"]["kind"] == "start_error"
    assert "mkstemp failed" in result["results"]["a.example.com"]["error"]
    assert result["in_flight"] == []
    assert result["pending"] == []
    assert result["status"] == "done"
    # Every target is accounted for -- nowhere does it just vanish.
    assert set(result["results"]) == set(targets)


def test_start_job_exception_on_one_target_does_not_abandon_the_rest(monkeypatch):
    """A launch failure on target 2 of 4 must not propagate out and skip
    targets 3/4 entirely -- each non-budget exception only affects the one
    target that raised; the loop keeps going for the rest."""
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})
    _stub_work_registry(monkeypatch)

    calls = []

    def fake_start_job(tool_name, jobs, **kwargs):
        target = kwargs.get("marker")
        calls.append(target)
        if target == "b":
            raise FileNotFoundError("sandbox binary missing")
        job_id = f"job-{target}"
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    targets = ["a", "b", "c", "d"]
    batches = {}
    jobs = {}
    result = fanout.start_batch(
        "nuclei", targets, lambda t: {"marker": t}, batches, jobs,
    )

    assert calls == ["a", "b", "c", "d"]
    assert set(result["results"]) | set(result["in_flight"]) == set(targets)
    assert result["results"]["b"]["kind"] == "start_error"
    assert "sandbox binary missing" in result["results"]["b"]["error"]
    assert "a" in result["in_flight"]
    assert "c" in result["in_flight"]
    assert "d" in result["in_flight"]


def test_budget_exceeded_drains_remaining_pending_without_retrying_each_one(monkeypatch):
    """Once BudgetExceeded fires once, the budget won't un-exceed itself
    mid-batch -- every remaining pending target is moved straight into
    results as a start_error, rather than start_job() being called again
    for each one individually."""
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})
    _stub_work_registry(monkeypatch)

    calls = []

    def fake_start_job(tool_name, jobs, **kwargs):
        calls.append(kwargs.get("marker"))
        if kwargs.get("marker") == "b":
            raise budget_guard.BudgetExceeded("Tier-2 call budget exceeded (500/500)")
        job_id = f"job-{kwargs.get('marker')}"
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    targets = ["a", "b", "c", "d"]
    batches = {}
    jobs = {}
    result = fanout.start_batch(
        "nuclei", targets, lambda t: {"marker": t}, batches, jobs,
    )

    # start_job is never called again for c/d once the budget exception
    # fires on b -- they're drained directly into results.
    assert calls == ["a", "b"]
    assert result["results"]["b"]["kind"] == "start_error"
    assert "budget" in result["results"]["b"]["error"].lower()
    assert result["results"]["c"]["kind"] == "start_error"
    assert result["results"]["d"]["kind"] == "start_error"
    assert result["pending"] == []
    assert "a" in result["in_flight"]
    # All four targets accounted for -- none dropped.
    assert set(result["results"]) | set(result["in_flight"]) == set(targets)


def test_start_batch_always_returns_a_batch_id_even_when_the_first_launch_fails(monkeypatch):
    """The second failure mode in the CRITICAL finding: an exception on
    the very first start_job() call inside start_batch() must not prevent
    the caller from getting a batch_id back -- otherwise the batch object
    is unreachable in `batches` forever, and nothing can ever poll it."""
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})
    _stub_work_registry(monkeypatch)

    def fake_start_job(tool_name, jobs, **kwargs):
        raise budget_guard.BudgetExceeded("Tier-2 call budget exceeded")

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    batches = {}
    jobs = {}
    result = fanout.start_batch("nuclei", ["only-target"], lambda t: {"args": []}, batches, jobs)

    assert result["batch_id"]
    assert result["status"] == "done"
    assert result["results"]["only-target"]["kind"] == "start_error"
    # The batch is not left dangling, unreachable, in `batches`.
    assert result["batch_id"] not in batches


# -- Finding 2: dedupe must only skip a target on an in-progress entry
# registered BY fanout, for this same tool -- not one registered by an
# unrelated agent/task (e.g. HuntBrain's own work_registry usage before
# spawning a specialist). --

def test_fill_slots_does_not_skip_a_target_registered_by_a_different_agent(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})

    def fake_list_active_work(host=None, path=None):
        if host == "target-a":
            return [{"id": "stub", "agent": "scan-agent", "task": "", "host": host}]
        return []

    monkeypatch.setattr(work_registry, "list_active_work", fake_list_active_work)
    monkeypatch.setattr(work_registry, "start_work", lambda agent, host, task="", path=None: f"work-{host}")
    monkeypatch.setattr(work_registry, "complete_work", lambda work_id, outcome="", path=None: True)

    start_job_calls = []

    def fake_start_job(tool_name, jobs, **kwargs):
        start_job_calls.append(tool_name)
        job_id = f"job-{len(start_job_calls)}"
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    result = fanout.start_batch("nuclei", ["target-a"], lambda t: {"args": []}, {}, {})

    # A job IS started for target-a -- an unrelated agent's registration
    # (not fanout's own) must never cause a skip.
    assert start_job_calls == ["nuclei"]
    assert "target-a" in result["in_flight"]
    assert "target-a" not in result["results"]


def test_fill_slots_does_not_skip_a_target_registered_for_a_different_task(monkeypatch):
    """Even an entry registered by fanout itself, but for a DIFFERENT
    tool_name (task), must not cause a skip -- the dedupe check is scoped
    to this exact tool_name, not just this exact agent."""
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 5})

    def fake_list_active_work(host=None, path=None):
        if host == "target-a":
            return [{"id": "stub", "agent": "fanout", "task": "httpx", "host": host}]
        return []

    monkeypatch.setattr(work_registry, "list_active_work", fake_list_active_work)
    monkeypatch.setattr(work_registry, "start_work", lambda agent, host, task="", path=None: f"work-{host}")
    monkeypatch.setattr(work_registry, "complete_work", lambda work_id, outcome="", path=None: True)

    def fake_start_job(tool_name, jobs, **kwargs):
        job_id = "job-0"
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    result = fanout.start_batch("nuclei", ["target-a"], lambda t: {"args": []}, {}, {})

    assert "target-a" in result["in_flight"]


# -- Finding 3: the concurrency cap is a hard ceiling across ALL callers
# sharing one `jobs` dict, not just this one batch's own in_flight count. --

def test_fill_slots_caps_across_two_batches_sharing_the_same_jobs_dict(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 3})
    _stub_work_registry(monkeypatch)

    started = []

    def fake_start_job(tool_name, jobs, **kwargs):
        job_id = f"job-{len(started)}"
        started.append(job_id)
        jobs[job_id] = {"status": "running", "tool_name": tool_name}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    jobs = {}
    batches = {}

    batch1_targets = ["a1", "a2", "a3", "a4"]
    result1 = fanout.start_batch("nuclei", batch1_targets, lambda t: {"args": []}, batches, jobs)

    # Batch 1 alone fills the whole cap (3), one target left pending.
    assert len(result1["in_flight"]) == 3
    assert result1["pending"] == ["a4"]
    assert len(jobs) == 3

    batch2_targets = ["b1", "b2", "b3"]
    result2 = fanout.start_batch("nuclei", batch2_targets, lambda t: {"args": []}, batches, jobs)

    # Batch 2 must back off entirely -- the shared cap is already full
    # from batch 1's own in-flight jobs.
    assert len(result2["in_flight"]) == 0
    assert result2["pending"] == batch2_targets
    assert len(jobs) == 3  # never more than the cap, combined

    # Now free one of batch 1's slots and let check_batch() backfill --
    # only ONE more job total may start (across either batch), since the
    # cap is still 3.
    first_job_id = started[0]

    def fake_poll_job(job_id, jobs):
        if job_id == first_job_id:
            # Real poll_job() pops a terminal job out of the shared `jobs`
            # dict -- replicate that here so _running_for_tool() sees the
            # freed slot, same as production.
            jobs.pop(job_id, None)
            return {"status": "done", "job_id": job_id, "returncode": 0}
        return {"status": "running", "job_id": job_id}

    monkeypatch.setattr(job_runtime, "poll_job", fake_poll_job)

    result1_check = fanout.check_batch(result1["batch_id"], batches, jobs)
    # 2 of batch1's original 3 are still running, plus exactly 1 backfilled
    # (a4, the only remaining pending target) -- never exceeding the
    # shared cap of 3.
    assert len(jobs) == 3
    assert len(result1_check["in_flight"]) == 3
    assert result1_check["pending"] == []

    # Batch 2 still cannot start anything -- the cap is still fully used.
    result2_check = fanout.check_batch(result2["batch_id"], batches, jobs)
    assert len(result2_check["in_flight"]) == 0
    assert result2_check["pending"] == batch2_targets
    assert len(jobs) == 3
