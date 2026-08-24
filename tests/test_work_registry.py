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
