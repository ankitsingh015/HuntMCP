"""Spec 2 (SSO surface), Task 4: black-box walks over the fixture's /sso
pages with a real local test IdP (mock-oauth2-server), IdP in and out of
scope. RP = 127.0.0.1, IdP = localhost."""

import asyncio
import contextlib
import json
import os
import sys
from urllib.parse import urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm
import ui_walk
from mock_idp import MockIdP, image_present
from ui_walk_app import requires_browser, serve

pytestmark = requires_browser


def _scope_both(u):
    return urlsplit(u).hostname in ("127.0.0.1", "localhost")


def _scope_rp_only(u):
    return urlsplit(u).hostname == "127.0.0.1"


def _run(stack, tmp_path_factory, scope, vulnerable=True):
    """Every resource is registered on `stack` the moment it exists, so a
    failure at any step still stops the containers and the fixture app."""
    if not image_present():
        pytest.skip("needs podman + the mock IdP image")
    mp = pytest.MonkeyPatch()
    stack.callback(mp.undo)
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    mp.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path_factory.mktemp("uw")))
    idp_login = MockIdP(interactive=True)
    stack.callback(idp_login.close)
    idp_sess = MockIdP(interactive=False)
    stack.callback(idp_sess.close)
    app = serve(vulnerable=vulnerable, sso_login_issuer=idp_login.issuer_url,
                sso_session_issuer=idp_sess.issuer_url)
    stack.callback(app.close)
    sf = str(tmp_path_factory.mktemp("sess") / "s.json")
    app.write_session_file(sf)
    inv = asyncio.run(ui_walk.walk(app.base_url + "/sso", "map", scope_check=scope, session_file=sf,
                                   screenshot_dir=str(tmp_path_factory.mktemp("shots")), max_pages=25))
    return app, idp_login, idp_sess, inv


@pytest.fixture(scope="module")
def in_scope(tmp_path_factory):
    with contextlib.ExitStack() as stack:
        yield _run(stack, tmp_path_factory, _scope_both)


@pytest.fixture(scope="module")
def oos(tmp_path_factory):
    with contextlib.ExitStack() as stack:
        yield _run(stack, tmp_path_factory, _scope_rp_only)


def _idp_pages(inv, idp):
    return [p for p in inv["pages"] if urlsplit(p["url"]).port == urlsplit(idp.base_url).port]


# ------------------------------------------------------------------ in scope

def test_schema_v3_and_sso_section(in_scope):
    _app, _a, _b, inv = in_scope
    assert inv["status"] == "complete", inv["error"]
    assert inv["schema_version"] == 3
    assert set(inv["sso"]) >= {"flows", "endpoints", "discovery", "idp_hosts", "repeats",
                               "discovery_gets", "out_of_scope_idp_redirects"}
    assert inv["sso"]["flows"]


def test_idp_login_page_mapped_not_filled(in_scope):
    _app, idp_login, _b, inv = in_scope
    pages = _idp_pages(inv, idp_login)
    assert pages, [p["url"] for p in inv["pages"]]
    p = pages[0]
    assert p["auth_state"] == "sso" and p["sso_role"] == "login"
    assert any(i["name"] == "username" for i in p["inputs"])
    assert all(m == "GET" for m, _p in idp_login.requests), idp_login.requests


def test_idp_href_followed_despite_same_origin_only(in_scope):
    _app, _a, _b, inv = in_scope
    # the "SSO direct link" href points at the IdP origin: enqueued because
    # the host is a recorded in-scope IdP host
    sso_page = next(p for p in inv["pages"] if urlsplit(p["url"]).path == "/sso")
    link = next(c for c in sso_page["controls"] if c["text"] == "SSO direct link")
    assert link["skipped_reason"] == "enqueued"


def test_logout_endpoint_recorded_never_requested(in_scope):
    _app, _a, idp_sess, inv = in_scope
    lo = [e for e in inv["sso"]["endpoints"] if e["role"] == "logout"]
    assert lo and lo[0]["redirect_params"] == ["post_logout_redirect_uri"]
    assert "/default/endsession" not in idp_sess.paths()


def test_echo_flag_true_on_session_flow(in_scope):
    _app, _a, idp_sess, inv = in_scope
    flows = [f for f in inv["sso"]["flows"] if f["idp_host"] == urlsplit(idp_sess.base_url).netloc
             and f["authorize"]["response_type"] == "code"]
    assert flows and flows[0]["state_echoed_on_callback"] is True


def test_app_page_after_callback_is_not_an_idp_page(in_scope):
    _app, _a, _b, inv = in_scope
    home = [p for p in inv["pages"] if urlsplit(p["url"]).path == "/sso/home"]
    assert home and home[0]["auth_state"] == "ok" and not home[0].get("sso_role")


def test_pass1_zero_non_get(in_scope):
    app, a, b, _inv = in_scope
    assert app.non_get_requests() == []
    assert all(m == "GET" for m, _p in a.requests + b.requests)


# -------------------------------------------------------------- out of scope

def test_oos_only_followed_redirect_gets(oos):
    app, idp_login, idp_sess, inv = oos
    assert inv["status"] == "complete", inv["error"]
    for idp in (idp_login, idp_sess):
        assert all(m == "GET" for m, _p in idp.requests), idp.requests
        assert set(idp.paths()) <= {"/default/authorize"}, idp.paths()
    # every request to the login IdP came from an HTTP redirect of /sso/login:
    # the direct href was not followed and the SPA button's JS navigation was aborted
    rp_login_hits = [r for r in app.host_requests if urlsplit(r[2]).path == "/sso/login"]
    assert len(idp_login.requests) == len(rp_login_hits)


def test_oos_no_idp_pages_mapped(oos):
    _app, idp_login, idp_sess, inv = oos
    assert not _idp_pages(inv, idp_login) and not _idp_pages(inv, idp_sess)
    assert inv["sso"]["idp_hosts"] == []


def test_oos_redirects_recorded_with_honest_limit(oos):
    _app, idp_login, _b, inv = oos
    hosts = {r["host"] for r in inv["sso"]["out_of_scope_idp_redirects"]}
    assert urlsplit(idp_login.base_url).netloc in hosts
    assert any("out-of-scope identity provider" in h for h in inv["honest_limits"])


def test_oos_flows_recorded_not_in_scope(oos):
    _app, _a, _b, inv = oos
    assert inv["sso"]["flows"] and all(f["idp_in_scope"] is False for f in inv["sso"]["flows"])


def test_oos_session_bounce_back_continues(oos):
    _app, _a, _b, inv = oos
    assert [p for p in inv["pages"] if urlsplit(p["url"]).path == "/sso/home"]


def test_no_secret_in_either_walk(in_scope, oos):
    for app, _a, _b, inv in (in_scope, oos):
        dump = json.dumps(inv)
        for s in set(app.issued_secrets):
            if s:
                assert s not in dump


# ------------------------------------------------------- Task 7: Pass 2 refusal

def test_canary_walk_never_submits_idp_login(tmp_path_factory):
    if not image_present():
        pytest.skip("needs podman + the mock IdP image")
    from ui_walk_grant import Grant

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
        inv = asyncio.run(ui_walk.walk(app.base_url + "/sso", "canary", scope_check=_scope_both, session_file=sf,
                                       grant=Grant(True, ["127.0.0.1", "localhost"], 200),
                                       screenshot_dir=str(tmp_path_factory.mktemp("shots")), max_pages=8))
    assert inv["status"] == "complete", inv["error"]
    assert [p for p in inv["pages"] if p.get("auth_state") == "sso"], "the IdP login page should be mapped"
    assert all(m == "GET" for m, _p in idp_login.requests + idp_sess.requests)
    # Pass 2 only submits on auth_state "ok" pages; IdP pages are "sso", so no real submit touches them
    assert not [r for r in inv.get("real_submits") or [] if urlsplit(r.get("url") or "").hostname == "localhost"]
    assert inv["sso"]["repeats"] == 0 and inv["sso"]["discovery_gets"] == 0
