"""#164 create -> destroy -> verify: deletes ONLY walker-owned objects and
checks they are really gone (broken delete), emitting delete-IDOR candidates."""

import asyncio
import os
import sys
from urllib.parse import urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm  # noqa: E402
import ui_walk  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402
from ui_walk_grant import Grant  # noqa: E402

ALICE = "Alice's report"


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


def _run(vulnerable, factory):
    mp = pytest.MonkeyPatch()
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    mp.setenv("HUNTMCP_UI_WALK_DIR", str(factory.mktemp("uw")))
    app = serve(vulnerable=vulnerable)
    alice_id = app.seed_item(ALICE)
    inv = asyncio.run(ui_walk.walk(app.base_url + "/items", "canary", cookie_header=app.login_cookie(),
                                   scope_check=_scope, grant=Grant(True, [], 200), max_pages=4,
                                   screenshot_dir=str(factory.mktemp("shots"))))
    mp.undo()
    return app, inv, alice_id


@pytest.fixture(scope="module")
def vuln(tmp_path_factory):
    app, inv, alice = _run(True, tmp_path_factory)
    yield app, inv, alice
    app.close()


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    app, inv, alice = _run(False, tmp_path_factory)
    yield app, inv, alice
    app.close()


def _created_ids(inv):
    return [r["created_id"] for r in inv["real_submits"] if r.get("created_id")]


@requires_browser
def test_destroy_accepts_confirm_and_deletes_walker_object(vuln):
    app, inv, _ = vuln
    assert inv["status"] == "complete", inv["error"]
    ids = _created_ids(inv)
    assert ids
    assert any(("DELETE", f"/api/items/{i}") in app.non_get_requests() for i in ids)


@requires_browser
def test_destroy_never_touches_preexisting_items(vuln):
    app, inv, alice = vuln
    assert ("DELETE", f"/api/items/{alice}") not in app.non_get_requests()
    assert app.items[alice]["deleted"] is False
    assert any(d["skipped_reason"] == "ownership-unproven" for d in inv["destroy_log"])


@requires_browser
def test_destroy_finds_broken_delete(vuln):
    app, inv, _ = vuln
    broken = [c for c in inv["candidates"] if c["type"] == "broken-delete"]
    assert broken
    ids = set(_created_ids(inv))
    assert any(urlsplit(c["reach_path"]).path.rsplit("/", 1)[-1] in ids for c in broken)
    deleted_item = app.items[urlsplit(broken[0]["reach_path"]).path.rsplit("/", 1)[-1]]
    assert any(t["token"] in deleted_item["name"] for t in inv["canaries"])


@requires_browser
def test_destroy_emits_delete_idor_candidate(vuln):
    _, inv, _ = vuln
    idor = [c for c in inv["candidates"] if c["type"] == "delete-idor-candidate"]
    assert idor and idor[0]["request"]["method"] == "DELETE"


@requires_browser
def test_destroy_hard_delete_no_candidate(patched):
    app, inv, alice = patched
    assert inv["status"] == "complete", inv["error"]
    assert any(m == "DELETE" for m, _ in app.non_get_requests())
    assert not [c for c in inv["candidates"] if c["type"] == "broken-delete"]
    assert alice in app.items
