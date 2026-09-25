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
    monkeypatch.setenv("HUNTMCP_WATCH_DB_PATH", str(tmp_path / "watch-test.db"))
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


# P2-SC (IMPLEMENTATION-TASK-TRACKER.md): watch.db was the one guard-adjacent
# store still resolving a single flat data/watch.db path -- budget.json/
# work-registry.json/findings-seen.json/engagement.yaml/audit.jsonl already
# went through engagement_paths.resolve() so switching the active target
# mid-session moves where THEIR state lives; watch.db silently didn't,
# meaning two parallel-hunted targets would share one watch history. get_db()
# now re-resolves fresh on every call (never a frozen import-time constant --
# same reasoning as budget_guard.py's own DEFAULT_PATH comment) so a target
# switch via `engagement_paths.py set <target>` takes effect without
# restarting this server process.
def test_get_db_path_honors_override_env(monkeypatch, tmp_path):
    override = str(tmp_path / "override-watch.db")
    monkeypatch.setenv("HUNTMCP_WATCH_DB_PATH", override)
    assert watch_server._resolve_db_path() == override


def test_get_db_path_resolves_inside_active_engagement_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("HUNTMCP_WATCH_DB_PATH", raising=False)
    engagements_root = tmp_path / "engagements"
    pointer_path = tmp_path / ".active-engagement"
    monkeypatch.setattr(watch_server.engagement_paths, "ENGAGEMENTS_ROOT", str(engagements_root))
    monkeypatch.setattr(watch_server.engagement_paths, "ACTIVE_POINTER", str(pointer_path))
    watch_server.engagement_paths.set_active_target("example.com", pointer_path=str(pointer_path),
                                                      engagements_root=str(engagements_root))

    resolved = watch_server._resolve_db_path()

    assert resolved == os.path.join(str(engagements_root), "example-com", "watch.db")


def test_get_db_path_falls_back_to_legacy_default_with_no_active_engagement(monkeypatch, tmp_path):
    monkeypatch.delenv("HUNTMCP_WATCH_DB_PATH", raising=False)
    pointer_path = tmp_path / ".active-engagement"
    monkeypatch.setattr(watch_server.engagement_paths, "ACTIVE_POINTER", str(pointer_path))

    assert watch_server._resolve_db_path() == watch_server.DB_PATH


def test_get_db_actually_writes_to_the_resolved_path(monkeypatch, tmp_path):
    target_path = str(tmp_path / "actually-used.db")
    monkeypatch.setenv("HUNTMCP_WATCH_DB_PATH", target_path)

    conn = watch_server.get_db()
    conn.close()

    assert os.path.isfile(target_path)


def test_get_db_schema_exists_without_a_separate_init_db_call(monkeypatch, tmp_path):
    # Bug this guards against: init_db() used to run exactly once, at
    # server __main__ startup, against whatever single path get_db()
    # resolved to AT THAT MOMENT. Now that get_db() can resolve to a
    # DIFFERENT path per active engagement (this task's own change), a
    # target switched to AFTER startup (the normal HuntBrain Phase-0 flow --
    # engagement_paths.py set <target> -- run from a separate process/
    # terminal after this server is already running) would get a brand
    # new watch.db file whose schema was never created, so the very first
    # real query against it (watched_targets/snapshots/watch_events) would
    # raise "no such table". get_db() itself must guarantee the schema
    # exists for whatever path IT resolves to, not rely on a prior
    # separate init_db() call against a possibly-different path.
    target_path = str(tmp_path / "never-explicitly-initialized.db")
    monkeypatch.setenv("HUNTMCP_WATCH_DB_PATH", target_path)

    conn = watch_server.get_db()
    try:
        # Would raise sqlite3.OperationalError: no such table if get_db()
        # itself doesn't ensure the schema exists.
        conn.execute("SELECT COUNT(*) FROM watched_targets")
        conn.execute("SELECT COUNT(*) FROM snapshots")
        conn.execute("SELECT COUNT(*) FROM watch_events")
    finally:
        conn.close()


def test_get_db_recreates_schema_if_the_underlying_file_is_removed_mid_process(monkeypatch, tmp_path):
    # Correctness finding (independent code review, 2026-09-25, 4 of 8
    # finder angles converged on this): get_db() previously memoized
    # "already schema-initialized" per resolved PATH STRING via a
    # module-level _initialized_db_paths set, to avoid re-running the
    # (idempotent) schema script on every call. But the cache tracked the
    # PATH, not the FILE -- if the on-disk db at a memoized path is later
    # removed (a human resets one engagement's watch history, an
    # engagement directory gets cleaned up, disk issue) while this
    # process keeps running, the next get_db() call for that same path
    # would see it already in the memo set, skip schema creation
    # entirely, and sqlite3.connect()'s auto-create-if-missing behavior
    # would silently open a brand-new EMPTY file -- every subsequent real
    # query then raises "no such table", exactly the bug class this
    # function's own comment already claims was fixed, just reintroduced
    # via a different path. Reverted the memoization entirely: case_store.py's
    # own _get_conn()/_init_schema() already establishes, in this same
    # codebase, that running CREATE TABLE IF NOT EXISTS unconditionally on
    # every connection is the correct, simpler pattern -- it's a cheap
    # catalog check, not a cost worth a cache (and case_store.py's version
    # is called far more often, with no memoization, and no reported cost
    # problem). This test proves the fix: get_db() must always leave a
    # queryable schema behind, even for a path it has already "seen"
    # once, if that path's file is gone by the time it's asked again.
    target_path = str(tmp_path / "recreate-test.db")
    monkeypatch.setenv("HUNTMCP_WATCH_DB_PATH", target_path)

    conn1 = watch_server.get_db()
    conn1.close()
    os.remove(target_path)
    assert not os.path.isfile(target_path)

    conn2 = watch_server.get_db()
    try:
        # Would raise sqlite3.OperationalError: no such table if get_db()
        # skipped schema creation because it had seen this PATH before.
        conn2.execute("SELECT COUNT(*) FROM watched_targets")
    finally:
        conn2.close()


def test_get_db_closes_connection_and_reraises_if_schema_creation_fails(monkeypatch, tmp_path):
    # Removed-behavior finding (code review): schema creation moved from a
    # separate init_db() (which always closed its own connection) into
    # get_db() itself, now reachable from every read-only tool too. If
    # executescript()/commit() ever raises (locked db, disk full, corrupted
    # file), the just-opened connection must still be closed, not leaked.
    import sqlite3

    target_path = str(tmp_path / "boom.db")
    monkeypatch.setenv("HUNTMCP_WATCH_DB_PATH", target_path)
    monkeypatch.setattr(watch_server, "_SCHEMA", "THIS IS NOT VALID SQL;")

    real_connect = sqlite3.connect
    closed = {"n": 0}

    class _TrackingConnection(sqlite3.Connection):
        def close(self):
            closed["n"] += 1
            super().close()

    def _tracking_connect(*args, **kwargs):
        kwargs["factory"] = _TrackingConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(watch_server.sqlite3, "connect", _tracking_connect)

    with pytest.raises(sqlite3.OperationalError):
        watch_server.get_db()

    assert closed["n"] == 1, "connection was not closed when schema creation failed"
