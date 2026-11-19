"""#164 teardown: human-gated (state_change_confirm token bound to the exact
cleanup set), cleanup of walker-created objects, logout-invalidation test,
account-deletion test only for a disposable identity."""

import asyncio
import io
import os
import sys
from urllib.parse import urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm  # noqa: E402
import state_change_confirm as scc  # noqa: E402
import ui_walk  # noqa: E402
import ui_walk_store  # noqa: E402
import ui_walk_teardown as T  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path / "ui-walk"))
    monkeypatch.setenv("HUNTMCP_STATE_CHANGE_CONFIRM_PATH", str(tmp_path / "scc.json"))
    roster = tmp_path / "ids.yaml"
    roster.write_text("identities:\n  throwaway:\n    note: t\n    profile_dir: /x/t\n    disposable: true\n"
                      "  keep:\n    note: k\n    profile_dir: /x/k\n")
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(roster))
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})


def _human_confirms(plan):
    phrase = scc.target_string(plan["host"], T.TEARDOWN_METHODS, plan["fingerprint"])
    assert scc.request_confirmation(plan["host"], T.TEARDOWN_METHODS, plan["fingerprint"],
                                    stdin=_FakeTTY(phrase + "\n"), stdout=io.StringIO())


def test_fingerprint_changes_with_object_set_and_identity():
    a = T.teardown_fingerprint("s", "keep", "http://h/", ["hm1"], ["cleanup"])
    assert len(a) == 32
    assert a != T.teardown_fingerprint("s", "keep", "http://h/", ["hm1", "hm2"], ["cleanup"])
    assert a != T.teardown_fingerprint("s", "throwaway", "http://h/", ["hm1"], ["cleanup"])
    assert a == T.teardown_fingerprint("s", "keep", "http://h/", ["hm1"], ["cleanup"])


def test_plan_drops_account_delete_for_non_disposable():
    plan = T.plan_teardown("http://127.0.0.1:9/", "keep")
    assert "account_delete" not in plan["steps"]
    assert any("disposable" in n for n in plan["notes"])
    assert "account_delete" in T.plan_teardown("http://127.0.0.1:9/", "throwaway")["steps"]


def test_plan_rejects_unknown_step():
    with pytest.raises(ValueError):
        T.plan_teardown("http://127.0.0.1:9/", "keep", ["format_disk"])


def test_teardown_blocked_without_token(monkeypatch):
    launched = []
    monkeypatch.setattr(ui_walk._Walker, "run", lambda *a, **k: launched.append(1))
    ui_walk_store.register_canary("hmaaaa0001", {"page": "/items"})
    r = asyncio.run(T.run_teardown("http://127.0.0.1:9/", "keep", scope_check=_scope))
    assert r["status"] == "blocked"
    fp = r["plan"]["fingerprint"]
    assert r["command"] == f"scripts/confirm-state-change.sh 127.0.0.1 POST,PUT,PATCH,DELETE {fp}"
    assert os.path.isfile(scc._pending_path(fp))
    assert launched == []


def test_teardown_refuses_out_of_scope():
    r = asyncio.run(T.run_teardown("https://unlisted.example.org/", "keep", scope_check=lambda u: False))
    assert r["status"] == "refused"


def test_token_for_other_object_set_does_not_unlock(monkeypatch):
    monkeypatch.setattr(ui_walk._Walker, "run", lambda *a, **k: None)
    ui_walk_store.register_canary("hmaaaa0001", {"page": "/items"})
    plan = T.plan_teardown("http://127.0.0.1:9/", "keep")
    _human_confirms(plan)
    ui_walk_store.register_canary("hmaaaa0002", {"page": "/items"})  # object set changed
    r = asyncio.run(T.run_teardown("http://127.0.0.1:9/", "keep", scope_check=_scope))
    assert r["status"] == "blocked"


def _seed_canary_item(app, token):
    iid = app.seed_item(f"{token} canary item")
    ui_walk_store.register_canary(token, {"page": app.base_url + "/items", "input": "name"})
    return iid


def _teardown(app, identity, tmp_path):
    cookie = app.login_cookie()
    plan = T.plan_teardown(app.base_url + "/", identity)
    _human_confirms(plan)
    return asyncio.run(T.run_teardown(app.base_url + "/", identity, cookie_header=cookie, scope_check=_scope,
                                      screenshot_dir=str(tmp_path), max_pages=8))


@requires_browser
def test_teardown_cleans_up_and_finds_logout_survival(tmp_path):
    app = serve(vulnerable=True)
    try:
        mine = _seed_canary_item(app, "hmbbbb0001")
        other = app.seed_item("Alice's report")
        r = _teardown(app, "keep", tmp_path)
    finally:
        app.close()
    assert r["status"] == "complete", r.get("error")
    assert ("DELETE", f"/api/items/{mine}") in app.non_get_requests()
    assert ("DELETE", f"/api/items/{other}") not in app.non_get_requests()
    assert any(c["type"] == "logout-session-survives" for c in r["candidates"])
    assert ("POST", "/api/account/delete") not in app.non_get_requests()  # not disposable
    assert "logout" in r["steps_run"] and "cleanup" in r["steps_run"]


@requires_browser
def test_teardown_patched_logout_no_candidate(tmp_path):
    app = serve(vulnerable=False)
    try:
        r = _teardown(app, "keep", tmp_path)
    finally:
        app.close()
    assert r["status"] == "complete", r.get("error")
    assert not any(c["type"] == "logout-session-survives" for c in r["candidates"])


@requires_browser
def test_teardown_account_delete_for_disposable_identity(tmp_path):
    app = serve(vulnerable=True)
    try:
        r = _teardown(app, "throwaway", tmp_path)
    finally:
        app.close()
    assert r["status"] == "complete", r.get("error")
    assert ("POST", "/api/account/delete") in app.non_get_requests()
    assert any(c["type"] == "account-deleted-session-survives" for c in r["candidates"])
    assert any(c["type"] == "reregistration-candidate" for c in r["candidates"])
    assert not any("stripe" in u for _, u in app.requests)
