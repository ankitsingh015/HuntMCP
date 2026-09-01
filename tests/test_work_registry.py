import threading
import time

import work_registry


def test_start_and_complete_work(tmp_path):
    p = str(tmp_path / "work-registry.json")
    work_id = work_registry.start_work("scan-agent", "example.com", "nuclei scan", path=p)
    active = work_registry.list_active_work(path=p)
    assert len(active) == 1
    assert active[0]["id"] == work_id
    assert active[0]["status"] == "in_progress"

    assert work_registry.complete_work(work_id, "3 findings", path=p) is True
    assert work_registry.list_active_work(path=p) == []

    all_work = work_registry.list_all_work(path=p)
    assert all_work[0]["status"] == "completed"
    assert all_work[0]["outcome"] == "3 findings"


def test_complete_unknown_work_id_returns_false(tmp_path):
    p = str(tmp_path / "work-registry.json")
    assert work_registry.complete_work("doesnotexist", path=p) is False


def test_active_work_filtered_by_host(tmp_path):
    p = str(tmp_path / "work-registry.json")
    id_a = work_registry.start_work("scan-agent", "a.example.com", path=p)
    work_registry.start_work("scan-agent", "b.example.com", path=p)

    only_a = work_registry.list_active_work(host="a.example.com", path=p)
    assert len(only_a) == 1
    assert only_a[0]["id"] == id_a


def test_two_specialists_same_host_both_tracked_independently(tmp_path):
    p = str(tmp_path / "work-registry.json")
    id1 = work_registry.start_work("scan-agent", "example.com", path=p)
    id2 = work_registry.start_work("exploit-agent", "example.com", path=p)
    assert len(work_registry.list_active_work(host="example.com", path=p)) == 2

    work_registry.complete_work(id1, path=p)
    remaining = work_registry.list_active_work(host="example.com", path=p)
    assert len(remaining) == 1
    assert remaining[0]["id"] == id2


def test_stale_in_progress_entry_excluded_from_active_work(monkeypatch, tmp_path):
    """Regression test for the permanent-lock bug: a process that dies
    mid-work (network hang, kill, crash) never calls complete_work(), so
    the entry stayed "in_progress" forever, and a resumed session (which
    deliberately does NOT reset this registry on resume) would see that
    host as permanently already-being-worked-on and never retry it."""
    p = str(tmp_path / "work-registry.json")
    monkeypatch.setattr(work_registry, "STALE_AFTER_SECONDS", 100)

    work_id = work_registry.start_work("scan-agent", "example.com", path=p)
    # Still fresh -- must show up as active.
    assert len(work_registry.list_active_work(path=p)) == 1

    # Simulate the starting process having died 2 hours ago (well past the
    # 100s threshold) without ever calling complete_work().
    state = work_registry._load(p)
    state[work_id]["started_at"] = time.time() - 7200
    work_registry._save(state, p)

    assert work_registry.list_active_work(path=p) == []
    assert work_registry.list_active_work(host="example.com", path=p) == []

    # The stale entry is still on disk (for audit/list_all_work), just no
    # longer treated as a live lock.
    all_work = work_registry.list_all_work(path=p)
    assert all_work[0]["id"] == work_id
    assert all_work[0]["status"] == "in_progress"


def test_start_work_is_safe_under_concurrent_calls(monkeypatch, tmp_path):
    """Regression test for the lost-update race: start_work() used to
    load-mutate-save with no locking, so concurrent spawns could clobber
    each other's registry entry. Widen the race window artificially so
    this fails reliably without file_lock."""
    p = str(tmp_path / "work-registry.json")
    orig_load = work_registry._load

    def slow_load(path):
        state = orig_load(path)
        time.sleep(0.01)
        return state

    monkeypatch.setattr(work_registry, "_load", slow_load)

    n = 20
    ids: list[str] = []
    lock = threading.Lock()

    def _spawn(i):
        work_id = work_registry.start_work("scan-agent", f"host{i}.example.com", path=p)
        with lock:
            ids.append(work_id)

    threads = [threading.Thread(target=_spawn, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ids) == len(set(ids)) == n
    all_work = work_registry.list_all_work(path=p)
    assert len(all_work) == n
