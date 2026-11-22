"""Spec 2 (SSO surface), Task 3: no state/nonce/code/PKCE value is stored in
the inventory, the tool output or the surface map (builder-check decision 1),
and callback URLs are never re-requested (decision 2)."""

import asyncio
import contextlib
import json
import os
import sys
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm
import surface_map
import ui_walk
import ui_walk_store
from mock_idp import MockIdP, image_present
from ui_walk_app import requires_browser, serve


def _both(u):
    return urlsplit(u).hostname in ("127.0.0.1", "localhost")


@pytest.fixture(scope="module")
def walked(tmp_path_factory):
    if not image_present():
        pytest.skip("needs podman + the mock IdP image")
    with contextlib.ExitStack() as stack:
        mp = pytest.MonkeyPatch()
        stack.callback(mp.undo)
        mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
        mp.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path_factory.mktemp("uw")))
        idp_login = MockIdP(interactive=True)
        stack.callback(idp_login.close)
        idp_sess = MockIdP(interactive=False)
        stack.callback(idp_sess.close)
        app = serve(vulnerable=True, sso_login_issuer=idp_login.issuer_url, sso_session_issuer=idp_sess.issuer_url)
        stack.callback(app.close)
        sf = str(tmp_path_factory.mktemp("sess") / "s.json")
        app.write_session_file(sf)
        inv = asyncio.run(ui_walk.walk(app.base_url + "/sso", "map", scope_check=_both, session_file=sf,
                                       screenshot_dir=str(tmp_path_factory.mktemp("shots")), max_pages=25))
        yield app, inv


@requires_browser
def test_no_fixture_secret_in_inventory_or_output(walked):
    import server

    app, inv = walked
    assert inv["status"] == "complete", inv["error"]
    dump = json.dumps(inv)
    out = server._format_walk({"inventory": inv, "path": "x"})
    secrets_seen = [s for s in set(app.issued_secrets) if s]
    assert secrets_seen, "the walk should have started at least one flow"
    for s in secrets_seen:
        assert s not in dump, s
        assert s not in out, s


@requires_browser
def test_callback_never_requested_twice(walked):
    app, _inv = walked
    codes = []
    for m, _host, path in app.host_requests:
        u = urlsplit(path)
        if m == "GET" and u.path == "/sso/callback":
            codes += parse_qs(u.query).get("code", [])
    assert codes, "the session IdP should have bounced to the callback"
    assert len(codes) == len(set(codes))


@requires_browser
def test_callback_not_a_page(walked):
    _app, inv = walked
    assert not [p for p in inv["pages"] if urlsplit(p["url"]).path == "/sso/callback"]


def _bare_walker():
    return ui_walk._Walker("http://127.0.0.1:1/", "map", scope=lambda u: True, max_pages=1,
                           max_clicks_per_page=1, same_origin_only=True, wall_clock_s=10, action_delay_s=0,
                           screenshot_dir=None, had_session=False, session_file=None, auth={}, walk_id="w")


def test_enqueue_refuses_callback():
    w = _bare_walker()
    assert w._enqueue_ok("http://127.0.0.1:1/sso/home") is True
    assert w._enqueue_ok("http://127.0.0.1:1/sso/callback?code=abc&state=x") is False
    assert w._enqueue_ok("http://127.0.0.1:1/cb#access_token=abc") is False


def test_refused_inventory_redacted():
    inv = asyncio.run(ui_walk.walk("http://127.0.0.1:1/cb?code=SECRETREFUSED1", "nosuchmode",
                                   scope_check=lambda u: True))
    assert inv["status"] == "refused"
    assert "SECRETREFUSED1" not in json.dumps(inv)


def test_emit_nodes_redacts(tmp_path):
    mp = str(tmp_path / "map.json")
    inv = {"schema_version": 3, "walk_id": "w1", "pages": [{
        "url": "http://127.0.0.1:9/p?state=SECRETS1", "template": "/p", "title": None, "auth_state": "ok",
        "inputs": [{"name": "q", "form_action": "http://127.0.0.1:9/f?nonce=SECRETN1", "type": "text"}],
        "controls": [], "api_edges": [{"method": "POST", "url": "http://127.0.0.1:9/api?code=SECRETC1",
                                       "control_signature": None, "blocked_reason": "pass1-non-get"}]}]}
    ui_walk_store.emit_nodes(inv, map_path=mp)
    dump = json.dumps(surface_map.load_map(mp))
    for s in ("SECRETS1", "SECRETN1", "SECRETC1"):
        assert s not in dump


def test_non_sso_out_of_scope_redirect_not_labelled_idp():
    # review F6: a plain redirect to a partner site is not an IdP redirect
    w = _bare_walker()
    w._scope_fn = lambda u: urlsplit(u).hostname == "127.0.0.1"
    w._scope_cache.clear()
    w._on_chain(["http://127.0.0.1:1/go", "https://partner.test/landing"], None, "document")
    assert w.sso.data["out_of_scope_idp_redirects"] == []
    w._on_chain(["http://127.0.0.1:1/sso/login",
                 "https://idp.oos.test/authorize?client_id=a&response_type=code&state=s"], None, "document")
    assert [r["host"] for r in w.sso.data["out_of_scope_idp_redirects"]] == ["idp.oos.test"]


def test_teardown_result_redacted(monkeypatch, tmp_path):
    # review F3: run_teardown's inventory goes through the same redaction as walk()
    import ui_walk_teardown

    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path))

    async def fake_run(self, **_auth):
        self.inv["pages"].append({"url": "http://127.0.0.1:1/cb?code=SECRETTEARDOWN1", "api_edges": []})
        self.inv["error"] = "logged-out view at http://127.0.0.1:1/x?state=SECRETTEARDOWN2"
        return self.inv

    async def no_mirror(self, _proxy):
        return None

    monkeypatch.setattr(ui_walk_teardown.TeardownWalker, "run", fake_run)
    monkeypatch.setattr(ui_walk_teardown.TeardownWalker, "setup_mirror", no_mirror)
    plan = {"base_url": "http://127.0.0.1:1/", "identity": "t", "steps": [], "cleanup_tokens": [], "notes": [],
            "session": ui_walk_teardown.session_ref(None, None)}
    r = asyncio.run(ui_walk_teardown.execute(plan, scope_check=lambda u: True, upstream_proxy="off"))
    dump = json.dumps(r, default=str)
    assert "SECRETTEARDOWN1" not in dump and "SECRETTEARDOWN2" not in dump
