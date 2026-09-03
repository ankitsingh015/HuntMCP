"""Regression test for watch-mcp's scope-check exemption gap.

Bug found live (2026-09-01, MCP full-coverage testing pass): _scope_error()
called load_engagement() directly without first checking is_safe_test_host(),
unlike every other Tier-2 tool (scope_gate_hook.py's check_scope flow) --
watch-mcp was the only tool that couldn't be used against example.com/
localhost/etc. without a real engagement.yaml on disk.
"""
import importlib.util
import os
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "watch_mcp_server", os.path.join(ROOT, "mcp-servers", "watch-mcp", "server.py"),
)
watch_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(watch_server)


@pytest.fixture(autouse=True)
def _reset_watch_server_job_state():
    # _jobs/_in_flight_* are module-level dicts on the imported watch_server
    # module, shared across every test in this file (the module is only
    # imported once). A test that deliberately leaves a job uncollected
    # (e.g. to test the "finished but never polled" guard-recovery path)
    # would otherwise leak that state into every later test in the file.
    watch_server._jobs.clear()
    watch_server._in_flight_job_for_target.clear()
    watch_server._in_flight_target_for_job.clear()
    yield
    watch_server._jobs.clear()
    watch_server._in_flight_job_for_target.clear()
    watch_server._in_flight_target_for_job.clear()


def _poll_until_done(job_id, timeout_s=5):
    deadline = time.time() + timeout_s
    out = watch_server.check_status(job_id)
    while "Still running" in out and time.time() < deadline:
        time.sleep(0.01)
        out = watch_server.check_status(job_id)
    return out


def test_safe_test_host_exempt_even_with_no_engagement_file(monkeypatch, tmp_path):
    # No engagement.yaml anywhere reachable -- point HUNTMCP_ENGAGEMENT_PATH
    # at a path that can never exist, so this test can't accidentally pass
    # by reading a real engagement.yaml lying around in the repo/cwd.
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(tmp_path / "nope.yaml"))
    assert watch_server._scope_error("example.com") is None
    assert watch_server._scope_error("localhost") is None
    assert watch_server._scope_error("127.0.0.1") is None


def test_real_target_still_blocked_with_no_engagement_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(tmp_path / "nope.yaml"))
    err = watch_server._scope_error("realtarget-corp.com")
    assert err is not None
    assert "BLOCKED" in err


def test_real_target_allowed_when_in_scope(monkeypatch, tmp_path):
    eng_path = tmp_path / "engagement.yaml"
    eng_path.write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng_path))
    assert watch_server._scope_error("realtarget-corp.com") is None


def test_real_target_blocked_when_out_of_scope(monkeypatch, tmp_path):
    eng_path = tmp_path / "engagement.yaml"
    eng_path.write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng_path))
    err = watch_server._scope_error("someothersite.com")
    assert err is not None
    assert "BLOCKED" in err


# ---- start_watch()/check_target() run in the background (job_runtime's
# thread-job variant) -- same class of client-timeout bug this repo already
# fixed for dalfox/nuclei/sqlmap/nmap/ffuf/httpx/subfinder/katana-mcp,
# except watch-mcp chains three sequential run_tool() calls (subfinder ->
# httpx -> katana) in one logical operation instead of being one subprocess.

def _isolated_db(monkeypatch, tmp_path):
    monkeypatch.setattr(watch_server, "DB_PATH", str(tmp_path / "watch-test.db"))
    watch_server.init_db()


def test_start_watch_returns_job_id_and_check_status_reports_done(monkeypatch, tmp_path):
    _isolated_db(monkeypatch, tmp_path)
    monkeypatch.setattr(watch_server, "run_subfinder", lambda target: ["a.example.com"])
    monkeypatch.setattr(watch_server, "run_katana", lambda target: ["https://a.example.com/x"])

    start_msg = watch_server.start_watch("example.com")
    assert "job_id=" in start_msg
    job_id = start_msg.split('job_id="')[1].split('"')[0]

    out = _poll_until_done(job_id)
    assert "Still running" not in out

    # The initial snapshot must actually be persisted, not just "ran".
    snap = watch_server.load_last_snapshot("example.com")
    assert snap["subdomains"] == ["a.example.com"]
    assert snap["endpoints"] == ["https://a.example.com/x"]


def test_check_target_runs_in_background_and_reports_new_subdomain(monkeypatch, tmp_path):
    _isolated_db(monkeypatch, tmp_path)
    monkeypatch.setattr(watch_server, "run_subfinder", lambda target: [])
    monkeypatch.setattr(watch_server, "run_katana", lambda target: [])
    monkeypatch.setattr(watch_server, "run_httpx", lambda domains: [])

    start_msg = watch_server.start_watch("example.com")
    job_id = start_msg.split('job_id="')[1].split('"')[0]
    _poll_until_done(job_id)  # wait for the initial (empty) snapshot to land

    # Now simulate a new subdomain showing up on the next check.
    monkeypatch.setattr(watch_server, "run_subfinder", lambda target: ["new.example.com"])

    check_msg = watch_server.check_target("example.com")
    assert "job_id=" in check_msg
    check_job_id = check_msg.split('job_id="')[1].split('"')[0]

    out = _poll_until_done(check_job_id)
    assert "Changes detected" in out
    assert "new.example.com" in out

    # And the event must actually be persisted to watch_events, not just
    # reflected in the returned text.
    history = watch_server.get_watch_history("example.com")
    assert "new.example.com" in history


def test_check_target_not_watched_returns_synchronously_no_job(monkeypatch, tmp_path):
    _isolated_db(monkeypatch, tmp_path)
    out = watch_server.check_target("localhost")  # a safe-test-host that was never start_watch()'d
    assert "not being actively watched" in out
    assert "job_id" not in out


def test_check_status_unknown_job_id_returns_error():
    out = watch_server.check_status("no-such-job")
    assert "no job" in out


def test_start_watch_reports_actual_snapshot_summary_not_placeholder_text(monkeypatch, tmp_path):
    # Regression: take_snapshot() used to have no return value, so
    # check_status() on start_watch()'s job always showed the generic
    # "Done (no result text)." fallback instead of anything useful.
    _isolated_db(monkeypatch, tmp_path)
    monkeypatch.setattr(watch_server, "run_subfinder", lambda target: ["a.example.com", "b.example.com"])
    monkeypatch.setattr(watch_server, "run_katana", lambda target: ["https://a.example.com/x"])

    start_msg = watch_server.start_watch("example.com")
    job_id = start_msg.split('job_id="')[1].split('"')[0]
    out = _poll_until_done(job_id)
    assert "Snapshot captured for example.com: 2 subdomain(s), 1 endpoint(s)." in out


# ---- Per-target in-flight guard: two overlapping start_watch()/
# check_target() calls for the SAME target must not spawn two racing
# background threads (duplicate events, two independent diffs against the
# same stale snapshot, doubled subfinder/httpx/katana load).

def test_start_watch_twice_quickly_reuses_the_same_job_instead_of_racing(monkeypatch, tmp_path):
    import threading
    _isolated_db(monkeypatch, tmp_path)
    release = threading.Event()
    call_count = {"n": 0}

    def _blocking_subfinder(target):
        call_count["n"] += 1
        release.wait(timeout=5)
        return []

    monkeypatch.setattr(watch_server, "run_subfinder", _blocking_subfinder)
    monkeypatch.setattr(watch_server, "run_katana", lambda target: [])

    try:
        first = watch_server.start_watch("example.com")
        job_id = first.split('job_id="')[1].split('"')[0]
        deadline = time.time() + 5
        while call_count["n"] == 0 and time.time() < deadline:
            time.sleep(0.005)  # let the background thread actually start

        second = watch_server.start_watch("example.com")
        assert "already running" in second
        assert job_id in second
        # Only ONE background job should have actually started -- not two
        # independent threads both hitting subfinder for the same target.
        assert call_count["n"] == 1
    finally:
        release.set()
    _poll_until_done(job_id)


def test_check_target_twice_quickly_reuses_the_same_job_instead_of_racing(monkeypatch, tmp_path):
    import threading
    _isolated_db(monkeypatch, tmp_path)
    monkeypatch.setattr(watch_server, "run_subfinder", lambda target: [])
    monkeypatch.setattr(watch_server, "run_katana", lambda target: [])

    start_msg = watch_server.start_watch("example.com")
    _poll_until_done(start_msg.split('job_id="')[1].split('"')[0])

    release = threading.Event()
    call_count = {"n": 0}

    def _blocking_subfinder(target):
        call_count["n"] += 1
        release.wait(timeout=5)
        return ["new.example.com"]

    monkeypatch.setattr(watch_server, "run_subfinder", _blocking_subfinder)

    try:
        first = watch_server.check_target("example.com")
        job_id = first.split('job_id="')[1].split('"')[0]
        deadline = time.time() + 5
        while call_count["n"] == 0 and time.time() < deadline:
            time.sleep(0.005)  # let the background thread actually start

        second = watch_server.check_target("example.com")
        assert "already running" in second
        assert job_id in second
        assert call_count["n"] == 1
    finally:
        release.set()
    out = _poll_until_done(job_id)
    # And it must actually still complete normally once released, with
    # only ONE set of events logged (not duplicated by a second run).
    assert "new.example.com" in out
    history = watch_server.get_watch_history("example.com")
    assert history.count("new.example.com") == 1


def test_guard_releases_after_check_status_reports_done_allowing_a_new_job(monkeypatch, tmp_path):
    _isolated_db(monkeypatch, tmp_path)
    monkeypatch.setattr(watch_server, "run_subfinder", lambda target: [])
    monkeypatch.setattr(watch_server, "run_katana", lambda target: [])

    first = watch_server.start_watch("example.com")
    first_job_id = first.split('job_id="')[1].split('"')[0]
    _poll_until_done(first_job_id)  # releases the guard

    second = watch_server.start_watch("example.com")
    assert "already running" not in second
    second_job_id = second.split('job_id="')[1].split('"')[0]
    assert second_job_id != first_job_id
    _poll_until_done(second_job_id)


def test_guard_does_not_block_forever_if_job_finished_but_never_polled(monkeypatch, tmp_path):
    # If a job actually finished but nobody ever called check_status() to
    # release the guard, a later start_watch()/check_target() call for the
    # same target must not be blocked forever -- job_runtime.
    # peek_thread_job_done() lets _start_target_job() detect "finished,
    # just never collected" and proceed instead of reporting
    # already_running indefinitely.
    _isolated_db(monkeypatch, tmp_path)
    monkeypatch.setattr(watch_server, "run_subfinder", lambda target: [])
    monkeypatch.setattr(watch_server, "run_katana", lambda target: [])

    first = watch_server.start_watch("example.com")
    first_job_id = first.split('job_id="')[1].split('"')[0]

    # Wait for the thread to actually finish WITHOUT calling check_status()
    # (which would release the guard through the normal path).
    import time as _time
    deadline = _time.time() + 5
    while watch_server.job_runtime.peek_thread_job_done(first_job_id, watch_server._jobs) is not True:
        _time.sleep(0.01)
        assert _time.time() < deadline, "job never finished"

    second = watch_server.start_watch("example.com")
    assert "already running" not in second


def test_list_checks_reports_running_job_then_empty_after_done(monkeypatch, tmp_path):
    import threading
    _isolated_db(monkeypatch, tmp_path)
    release = threading.Event()

    def _blocking_subfinder(target):
        release.wait(timeout=5)
        return []

    monkeypatch.setattr(watch_server, "run_subfinder", _blocking_subfinder)
    monkeypatch.setattr(watch_server, "run_katana", lambda target: [])

    assert watch_server.list_checks() == "No watch-mcp checks currently running."

    start_msg = watch_server.start_watch("example.com")
    job_id = start_msg.split('job_id="')[1].split('"')[0]
    try:
        listed = watch_server.list_checks()
        assert job_id in listed
        assert "watch-initial-snapshot" in listed
    finally:
        release.set()

    _poll_until_done(job_id)
    assert watch_server.list_checks() == "No watch-mcp checks currently running."
