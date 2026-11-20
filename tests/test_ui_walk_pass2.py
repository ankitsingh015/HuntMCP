"""#164 Pass 2 (canary): real submits only when the human grant allows it,
cross-page stored-XSS sink detection, caps, never payment/out-of-scope."""

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
import ui_walk_store  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402
from ui_walk_grant import Grant  # noqa: E402


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


def _canary(app, tmp, grant, **kw):
    return asyncio.run(ui_walk.walk(app.base_url + "/", "canary", cookie_header=app.login_cookie(),
                                    scope_check=_scope, grant=grant, screenshot_dir=str(tmp), **kw))


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path / "ui-walk"))


def _run_once(vulnerable, tmp_path_factory, grant):
    mp = pytest.MonkeyPatch()
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    mp.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path_factory.mktemp("uw")))
    app = serve(vulnerable=vulnerable)
    inv = _canary(app, tmp_path_factory.mktemp("shots"), grant, max_pages=12)
    mp.undo()
    return app, inv


@pytest.fixture(scope="module")
def vuln(tmp_path_factory):
    app, inv = _run_once(True, tmp_path_factory, Grant(True, [], 200))
    yield app, inv
    app.close()


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    app, inv = _run_once(False, tmp_path_factory, Grant(True, [], 200))
    yield app, inv
    app.close()


def test_canary_mode_refused_without_grant(monkeypatch):
    launched = []
    monkeypatch.setattr(ui_walk._Walker, "run", lambda *a, **k: launched.append(1))
    inv = asyncio.run(ui_walk.walk("http://127.0.0.1:9/", "canary", scope_check=_scope))
    assert inv["status"] == "refused"
    assert "ui-walk-authorized.yaml" in inv["error"]
    assert launched == []


def test_canary_mode_refused_for_host_not_in_grant(monkeypatch):
    inv = asyncio.run(ui_walk.walk("http://127.0.0.1:9/", "canary", scope_check=_scope,
                                   grant=Grant(True, ["other.test"], 200)))
    assert inv["status"] == "refused"


@requires_browser
def test_pass2_cross_page_executing_sink(vuln):
    _, inv = vuln
    assert inv["status"] == "complete", inv["error"]
    hits = [s for s in inv["sinks"] if urlsplit(s["origin_page"]).path == "/items"
            and urlsplit(s["sink_page"]).path == "/activity"]
    assert hits and any(s["executed"] and s["cross_page"] for s in hits)
    assert any(c["type"] == "stored-xss" for c in inv["candidates"])


@requires_browser
def test_pass2_registers_canaries_per_engagement(vuln):
    _, inv = vuln
    assert inv["canaries"]
    assert all(c["token"].startswith("hm") for c in inv["canaries"])


@requires_browser
def test_pass2_never_posts_to_payment_or_out_of_scope(vuln):
    app, inv = vuln
    assert all(urlsplit(r["url"]).hostname == "127.0.0.1" for r in inv["real_submits"])
    assert not any("stripe" in r["url"] for r in inv["real_submits"])
    assert ("POST", "/api/contact") not in app.non_get_requests()  # third-party-origin iframe form


@requires_browser
def test_pass2_records_created_id(vuln):
    _, inv = vuln
    creates = [r for r in inv["real_submits"] if r["method"] == "POST" and r["url"].endswith("/api/items")]
    assert creates and creates[0]["created_id"] and creates[0]["status"] == 201


@requires_browser
def test_pass2_sends_only_deliberate_submits(vuln):
    app, _ = vuln
    sent = {(m, p) for m, p in app.non_get_requests()}
    assert ("POST", "/api/purge") not in sent
    assert ("POST", "/api/popup-post") not in sent
    assert ("POST", "/api/account/delete") not in sent


@requires_browser
def test_pass2_respects_submit_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve()
    try:
        inv = _canary(app, tmp_path, Grant(True, [], 1), max_pages=12)
    finally:
        app.close()
    assert len(app.non_get_requests()) == 1
    assert any(e["blocked_reason"] == "cap-reached" for e in inv["pass2_edges"])


@requires_browser
def test_pass2_escaped_render_not_executing(patched):
    _, inv = patched
    assert inv["status"] == "complete", inv["error"]
    assert inv["sinks"]
    assert not any(s["executed"] for s in inv["sinks"])
    assert not any(c["type"] == "stored-xss" for c in inv["candidates"])
    assert any(c["type"] == "reflected-render" for c in inv["candidates"])


def test_registry_written(tmp_path):
    ui_walk_store.register_canary("hmabcdef12", {"page": "/x"})
    assert "hmabcdef12" in ui_walk_store.load_canaries()


@requires_browser
def test_pass2_never_submits_account_close_or_order_forms(vuln):
    app, _ = vuln
    sent = set(app.non_get_requests())
    assert ("POST", "/api/account/close") not in sent
    assert ("POST", "/api/orders") not in sent


@requires_browser
def test_pass2_submits_every_form_with_same_action(vuln):
    app, _ = vuln
    sent = set(app.non_get_requests())
    assert ("PUT", "/api/p1") in sent and ("PUT", "/api/p2") in sent


@requires_browser
def test_pass2_submit_window_never_sends_a_delete(vuln):
    app, _ = vuln
    assert ("DELETE", "/api/items/1") not in set(app.non_get_requests())


@requires_browser
def test_pass2_grant_hosts_enforced_on_every_send(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/contact", "canary", cookie_header=app.login_cookie(),
                                       scope_check=lambda u: urlsplit(u).hostname in ("127.0.0.1", "localhost"),
                                       grant=Grant(True, ["127.0.0.1"], 200), same_origin_only=False,
                                       max_pages=3, screenshot_dir=str(tmp_path)))
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    assert ("POST", "/api/contact") not in app.non_get_requests()  # localhost iframe form: not granted


def test_short_maxlength_field_gets_registered_short_token():
    import ui_walk_pass2
    tok = ui_walk_pass2._token_for({"type": "text", "maxlength": 6})
    assert tok and len(tok) <= 6
    assert ui_walk_pass2._token_for({"type": "text", "maxlength": 3}) is None
