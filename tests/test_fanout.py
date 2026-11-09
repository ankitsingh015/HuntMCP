import time

import fanout
import job_runtime
import work_registry


def _stub_work_registry(monkeypatch, active_hosts=()):
    """Isolate fanout's work_registry calls from the real on-disk
    registry for tests that don't care about dedupe/registration
    themselves -- no host is ever "already in flight" and start/complete
    are no-ops that still hand back a usable work_id."""
    active_hosts = set(active_hosts)

    def fake_list_active_work(host=None, path=None):
        if host in active_hosts:
            return [{"id": "stub", "agent": "fanout", "host": host}]
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
        jobs[job_id] = {"status": "running"}
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
        jobs[job_id] = {"status": "running"}
        return {"job_id": job_id, "status": "running", "tool": tool_name}

    monkeypatch.setattr(job_runtime, "start_job", fake_start_job)

    poll_results = {}

    def fake_poll_job(job_id, jobs):
        return poll_results.get(job_id, {"status": "running", "job_id": job_id})

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
        jobs[job_id] = {"status": "running"}
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
        jobs[job_id] = {"status": "running"}
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
        jobs[job_id] = {"status": "running"}
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
        jobs[job_id] = {"status": "running"}
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
        jobs[job_id] = {"status": "running"}
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
