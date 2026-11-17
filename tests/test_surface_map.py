"""Unit tests for the isolated per-engagement surface-map store.

surface_map.py lives in mcp-servers/ (on sys.path via conftest), so it imports
directly. Tests pass explicit paths for isolation; one test covers the
engagement_paths.resolve() default wiring via the HUNTMCP_SURFACE_MAP_PATH env.
"""
import os

import surface_map


def test_add_and_get_node(tmp_path):
    p = str(tmp_path / "m.json")
    nid = surface_map.add_node("feature", "file upload", "upload:image", path=p)
    node = surface_map.get_node(nid, path=p)
    assert node["label"] == "file upload"
    assert node["state"] == "discovered"
    assert node["signature"] == "upload:image"


def test_dedup_same_signature(tmp_path):
    p = str(tmp_path / "m.json")
    a = surface_map.add_node("feature", "upload", "upload:image", path=p)
    b = surface_map.add_node("feature", "upload again", "upload:image", path=p)
    assert a == b
    assert len(surface_map.load_map(path=p)["nodes"]) == 1


def test_isolation_per_engagement(tmp_path):
    p1 = str(tmp_path / "e1.json")
    p2 = str(tmp_path / "e2.json")
    surface_map.add_node("host", "a.com", "host:a.com", path=p1)
    assert surface_map.load_map(path=p2)["nodes"] == []
    assert len(surface_map.load_map(path=p1)["nodes"]) == 1


def test_load_corrupt_returns_empty(tmp_path):
    p = tmp_path / "m.json"
    p.write_text("{ this is not valid json ::::")
    assert surface_map.load_map(path=str(p)) == {"nodes": []}
    # a subsequent write still succeeds
    nid = surface_map.add_node("host", "x", "host:x", path=str(p))
    assert surface_map.get_node(nid, path=str(p))["label"] == "x"


def test_set_state_and_iter_untested(tmp_path):
    p = str(tmp_path / "m.json")
    a = surface_map.add_node("feature", "upload", "upload:image", path=p)
    b = surface_map.add_node("feature", "login", "auth:login", path=p)
    assert surface_map.set_state(a, "tested", path=p) is True
    untested = surface_map.iter_untested(path=p)
    labels = {n["label"] for n in untested}
    assert labels == {"login"}
    assert surface_map.get_node(b, path=p)["id"] in {n["id"] for n in untested}


def test_concurrent_add_node_loses_nothing(tmp_path):
    import threading
    p = str(tmp_path / "m.json")
    n = 30
    barrier = threading.Barrier(n)

    def worker(i):
        barrier.wait()  # maximize contention on the read-modify-write
        surface_map.add_node("host", f"h{i}", f"host:{i}", path=p)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(surface_map.load_map(path=p)["nodes"]) == n


def test_default_path_uses_resolve(tmp_path, monkeypatch):
    target = str(tmp_path / "resolved.json")
    monkeypatch.setenv("HUNTMCP_SURFACE_MAP_PATH", target)
    nid = surface_map.add_node("host", "y", "host:y")
    assert os.path.exists(target)
    assert surface_map.get_node(nid)["label"] == "y"
