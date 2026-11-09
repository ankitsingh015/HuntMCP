import fanout
import job_runtime


def test_start_batch_launches_up_to_cap_and_leaves_rest_pending(monkeypatch):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": 2})

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
