"""#164 Pass 1 (map, safe): black-box against the local fixture app.

The guarantee under test: Pass 1 sends NOTHING state-changing to the target,
yet still records every UI->API edge, every input (incl. lazy iframe, modal-
and tab-revealed ones), and never clicks logout/payment/account-delete.
"""

import asyncio
import os
import sys
from urllib.parse import urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm
import budget_guard
import ui_walk
import ui_walk_logic as L
from ui_walk_app import requires_browser, serve


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


def _walk(app, start, tmp, **kw):
    kw.setdefault("cookie_header", app.login_cookie())
    return asyncio.run(ui_walk.walk(start, "map", scope_check=_scope, screenshot_dir=str(tmp), **kw))


@pytest.fixture(scope="module")
def walked(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve()
    for i in range(20):
        app.seed_item(f"seed item {i}")
    inv = _walk(app, app.base_url + "/", tmp_path_factory.mktemp("shots"), max_pages=40)
    yield app, inv
    app.close()
    mp.undo()


def _page(inv, path):
    return [p for p in inv["pages"] if urlsplit(p["url"]).path == path]


def _edges(inv):
    return [e for p in inv["pages"] for e in p["api_edges"]]


def _controls(inv):
    return [c for p in inv["pages"] for c in p["controls"]]


# --------------------------------------------------------------- pure routing
def test_route_decision_blocks_payment_host_even_for_get_xhr():
    assert L.route_decision("POST", "https://api.stripe.com/v1/charges", "fetch", False,
                            scope_ok=False, send_allowed=False) == ("abort", "payment-host")


def test_route_decision_blocks_non_get_in_pass1():
    assert L.route_decision("DELETE", "http://127.0.0.1/api/items/1", "fetch", False,
                            scope_ok=True, send_allowed=False) == ("abort", "pass1-non-get")


def test_route_decision_blocks_out_of_scope_non_get_even_when_sending_allowed():
    assert L.route_decision("POST", "http://other.test/x", "fetch", False,
                            scope_ok=False, send_allowed=True) == ("abort", "out-of-scope")


def test_route_decision_blocks_out_of_scope_top_level_navigation():
    assert L.route_decision("GET", "http://other.test/", "document", True,
                            scope_ok=False, send_allowed=False) == ("abort", "out-of-scope")


def test_route_decision_allows_third_party_subresource_get():
    assert L.route_decision("GET", "http://cdn.other.test/a.js", "script", False,
                            scope_ok=False, send_allowed=False) == ("continue", None)


def test_route_decision_blocks_mutating_get_fetch():
    assert L.route_decision("GET", "http://127.0.0.1/api/logout", "fetch", False,
                            scope_ok=True, send_allowed=False) == ("abort", "mutating-get")


# --------------------------------------------------------------- black-box
@requires_browser
def test_pass1_completes(walked):
    _, inv = walked
    assert inv["status"] == "complete", inv.get("error")
    assert inv["schema_version"] == 1
    assert any("cannot be detected" in h for h in inv["honest_limits"])


@requires_browser
def test_pass1_sends_zero_non_get(walked):
    app, _ = walked
    assert app.non_get_requests() == []


@requires_browser
def test_pass1_records_intercepted_edges(walked):
    _, inv = walked
    edges = _edges(inv)
    assert any(e["method"] == "POST" and e["url"].endswith("/api/items") and not e["sent"]
               and e["blocked_reason"] == "pass1-non-get" for e in edges)
    assert any(e["method"] == "DELETE" and "/api/items/" in e["url"] and not e["sent"] for e in edges)
    assert any(e["method"] == "POST" and e["url"].endswith("/api/purge") and not e["sent"] for e in edges)


@requires_browser
def test_pass1_finds_lazy_cross_origin_iframe_inputs(walked):
    app, inv = walked
    (contact,) = _page(inv, "/contact")
    names = {i["name"]: i for i in contact["inputs"]}
    assert {"name", "message"} <= set(names)
    assert names["message"]["frame_origin"] == app.alt_base_url
    assert names["message"]["form_action"].endswith("/api/contact")


@requires_browser
def test_pass1_finds_modal_and_tab_revealed_inputs(walked):
    _, inv = walked
    (items,) = _page(inv, "/items")
    by = {i["name"]: i for i in items["inputs"]}
    assert by["name"]["revealed_by"] and by["description"]["revealed_by"]
    (settings,) = _page(inv, "/settings")
    keys = [i for i in settings["inputs"] if i["name"] == "key_label"]
    assert keys and keys[0]["revealed_by"]


@requires_browser
def test_pass1_never_clicks_logout_payment_account_delete(walked):
    app, inv = walked
    ctrls = _controls(inv)
    for text in ("Sign out", "Pay now", "Delete account"):
        hits = [c for c in ctrls if c["text"] == text]
        assert hits, text
        assert all(not c["clicked"] and c["skipped_reason"] == "never-click" for c in hits), text
    assert not any(m == "GET" and p.startswith("/logout") for m, p in app.requests)


@requires_browser
def test_pass1_out_of_scope_not_navigated(walked):
    _, inv = walked
    assert all(urlsplit(p["url"]).hostname == "127.0.0.1" for p in inv["pages"])
    assert any(e["blocked_reason"] == "out-of-scope" and "localhost" in e["url"] for e in _edges(inv))


@requires_browser
def test_pass1_unbounded_template_terminates(walked):
    _, inv = walked
    assert len(_page(inv, "/cal")) <= ui_walk.MAX_PER_TEMPLATE


@requires_browser
def test_pass1_window_open_popup_post_aborted(walked):
    app, inv = walked
    assert ("POST", "/api/popup-post") not in app.requests
    assert any(e["url"].endswith("/api/popup-post") and not e["sent"] for e in _edges(inv))


@requires_browser
def test_pass1_dedups_row_controls(walked):
    _, inv = walked
    (items,) = _page(inv, "/items")
    deletes = [c for c in items["controls"] if c["text"] == "Delete"]
    assert sum(1 for c in deletes if c["clicked"]) == 1
    assert len([p for p in inv["pages"] if urlsplit(p["url"]).path.startswith("/items/")]) <= ui_walk.MAX_PER_TEMPLATE


@requires_browser
def test_pass1_screenshot_per_page(walked):
    _, inv = walked
    assert inv["pages"]
    rendered = [p for p in inv["pages"] if not p.get("nav_error")]
    assert rendered and all(p["screenshot"] and os.path.isfile(p["screenshot"]) for p in rendered)
    # a page that never rendered in scope (blocked / redirected out of scope) is never captured
    assert all(not p["screenshot"] for p in inv["pages"] if p.get("nav_error"))


@requires_browser
def test_pass1_auth_lost_stops(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve()
    try:
        inv = _walk(app, app.base_url + "/items", tmp_path, cookie_header="sid=expired")
    finally:
        app.close()
    assert inv["status"] == "auth_lost"
    assert not any(urlsplit(p["url"]).path == "/items" and p["inputs"] for p in inv["pages"])


@requires_browser
def test_pass1_respects_max_pages(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve()
    try:
        inv = _walk(app, app.base_url + "/", tmp_path, max_pages=2)
    finally:
        app.close()
    assert len(inv["pages"]) <= 2


@requires_browser
def test_pass1_budget_enforced(tmp_path, monkeypatch):
    calls = {"n": 0}

    def fake(*_a, **_k):
        calls["n"] += 1
        if calls["n"] > 3:
            raise budget_guard.BudgetExceeded("cap")
        return {}

    monkeypatch.setattr(browser_confirm, "_enforce_budget", fake)
    app = serve()
    try:
        inv = _walk(app, app.base_url + "/", tmp_path)
    finally:
        app.close()
    assert inv["status"] == "budget_exhausted"
    assert len(inv["pages"]) <= 3


def test_walk_refuses_out_of_scope_start():
    inv = asyncio.run(ui_walk.walk("https://unlisted.example.org/", "map", scope_check=lambda u: False))
    assert inv["status"] == "refused"


@requires_browser
def test_pass1_out_of_scope_redirect_does_not_kill_walk(walked):
    _, inv = walked
    assert inv["status"] == "complete"
    sso = _page(inv, "/sso-protected")
    assert sso and sso[0]["nav_error"]
    assert _page(inv, "/cards")  # pages after it in the queue still mapped


def test_scope_verdict_cached_per_host():
    calls = []

    def scope(u):
        calls.append(u)
        return True
    w = ui_walk._Walker("http://127.0.0.1:1/", "map", scope=scope, max_pages=1, max_clicks_per_page=1,
                        same_origin_only=True, wall_clock_s=10, action_delay_s=0, screenshot_dir=None,
                        had_session=False, session_file=None, auth={}, walk_id="w")
    for i in range(50):
        w.scope(f"http://127.0.0.1:1/a{i}.js")
    assert len(calls) == 1
