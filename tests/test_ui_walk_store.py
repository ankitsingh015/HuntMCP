"""#164: UI-walk inventory store, canary registry, surface-map node emission."""

import json
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import surface_map  # noqa: E402
import ui_walk_store as S  # noqa: E402


@pytest.fixture(autouse=True)
def _dirs(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path / "ui-walk"))
    return tmp_path


def _inv():
    base = "http://app.test"
    return {
        "schema_version": 1, "walk_id": "w1", "start_url": base + "/", "mode": "map", "status": "complete",
        "pages": [{
            "url": base + "/items", "template": base + "/items", "title": "Items",
            "inputs": [{"name": "name", "form_action": base + "/api/items/7", "frame_origin": base,
                        "type": "text", "revealed_by": "abc"}],
            "controls": [{"signature": "s1", "text": "Delete", "classification": "destructive"}],
            "api_edges": [
                {"control_signature": "s1", "method": "DELETE", "url": base + "/api/items/7", "sent": False},
                {"control_signature": None, "method": "GET", "url": base + "/api/items", "sent": True},
            ],
        }],
    }


def test_save_and_load_inventory_roundtrip():
    path = S.save_inventory(_inv())
    assert path.endswith("w1.json") and os.path.isfile(path)
    assert S.load_inventory("w1")["pages"][0]["title"] == "Items"
    assert not [n for n in os.listdir(os.path.dirname(path)) if n.endswith(".tmp")]


def test_load_inventory_missing_is_none():
    assert S.load_inventory("nope") is None


def test_load_inventory_rejects_path_traversal_id():
    assert S.load_inventory("../../etc/passwd") is None


def test_canary_registry_concurrent_appends():
    def add(i):
        S.register_canary(f"hm0000000{i}", {"page": "/p", "input": "x", "walk_id": "w1"})
    ts = [threading.Thread(target=add, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    reg = S.load_canaries()
    assert len(reg) == 8 and reg["hm00000003"]["page"] == "/p"


def test_emit_nodes_signatures_parents_meta(tmp_path):
    mp = str(tmp_path / "map.json")
    counts = S.emit_nodes(_inv(), map_path=mp)
    assert counts == {"page": 1, "input": 1, "action": 1}
    nodes = surface_map.load_map(mp)["nodes"]
    page = next(n for n in nodes if n["kind"] == "page")
    inp = next(n for n in nodes if n["kind"] == "input")
    act = next(n for n in nodes if n["kind"] == "action")
    assert page["signature"] == "page:http://app.test/items"
    assert inp["signature"] == "input:http://app.test/api/items/{id}:name"
    assert act["signature"] == "action:DELETE http://app.test/api/items/{id}"
    assert inp["parent_id"] == page["id"] and act["parent_id"] == page["id"]
    assert act["meta"]["classification"] == "destructive"
    assert act["meta"]["control_text"] == "Delete" and act["meta"]["walk_id"] == "w1"
    assert act["meta"]["endpoint"] == "http://app.test/api/items/7"
    assert page["meta"]["endpoint"] == "http://app.test/items"


def test_emit_nodes_is_idempotent(tmp_path):
    mp = str(tmp_path / "map.json")
    S.emit_nodes(_inv(), map_path=mp)
    S.emit_nodes(_inv(), map_path=mp)
    nodes = surface_map.load_map(mp)["nodes"]
    assert len(nodes) == 3


def test_emit_nodes_skips_logged_out_pages(tmp_path):
    inv = _inv()
    inv["pages"][0]["auth_state"] = "logged-out"
    mp = str(tmp_path / "map.json")
    assert S.emit_nodes(inv, map_path=mp) == {"page": 0, "input": 0, "action": 0}


def test_inventory_file_is_valid_json_with_schema_version():
    path = S.save_inventory(_inv())
    with open(path) as fh:
        assert json.load(fh)["schema_version"] == 1


def test_walk_dir_without_active_engagement_is_not_repo_relative(monkeypatch, tmp_path):
    import engagement_paths
    monkeypatch.delenv("HUNTMCP_UI_WALK_DIR", raising=False)
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / "none"))
    d = S.walk_dir()
    assert os.path.isabs(d)
    assert d.startswith(os.path.abspath(engagement_paths.ENGAGEMENTS_ROOT))


def test_screenshot_dir_without_active_engagement_is_not_repo_relative(monkeypatch, tmp_path):
    import browser_confirm
    import engagement_paths
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / "none"))
    d = browser_confirm._screenshot_dir()
    assert os.path.isabs(d) and d.startswith(os.path.abspath(engagement_paths.ENGAGEMENTS_ROOT))


def test_register_canary_records_created_ids():
    S.register_created_id("hm1234abcd", "42")
    assert "42" in S.load_created_ids()
