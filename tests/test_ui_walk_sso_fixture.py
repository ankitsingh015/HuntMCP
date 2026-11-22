"""Spec 2 (SSO surface), Task 2: the fixture's RP (relying-party) SSO pages
wired to a real local test IdP (mock-oauth2-server container), checked with
plain HTTP (no browser). RP = fixture 127.0.0.1 host; IdP = localhost."""

import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

from mock_idp import MockIdP, requires_mock_idp
from ui_walk_app import serve

pytestmark = requires_mock_idp


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _get(url):
    try:
        r = _OPENER.open(url, timeout=10)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _loc(h):
    return h.get("Location") or h.get("location")


def _q(url):
    return parse_qs(urlsplit(url).query)


@pytest.fixture(scope="module")
def idps():
    a, b = MockIdP(interactive=True), MockIdP(interactive=False)
    yield a, b
    a.close()
    b.close()


@pytest.fixture(params=[True, False], ids=["vulnerable", "patched"])
def app(request, idps):
    a = serve(vulnerable=request.param, sso_login_issuer=idps[0].issuer_url,
              sso_session_issuer=idps[1].issuer_url)
    yield a
    a.close()


def test_rp_login_redirects_to_interactive_idp(app, idps):
    st, h, _ = _get(app.base_url + "/sso/login")
    assert st == 302 and _loc(h).startswith(idps[0].issuer_url + "/authorize?")
    q = _q(_loc(h))
    assert q["client_id"] == ["fixture-app"] and q["redirect_uri"] == [app.base_url + "/sso/callback"]
    st, _h, body = _get(_loc(h))
    assert st == 200 and b'name="username"' in body   # the IdP's own login page


def test_state_static_when_vulnerable_random_when_patched(app):
    states = [_q(_loc(_get(app.base_url + "/sso/login")[1]))["state"][0] for _ in range(2)]
    assert (states[0] == states[1]) is app.vulnerable
    assert all(s in app.issued_secrets for s in states)


def test_pkce_and_implicit_variants(app):
    q = _q(_loc(_get(app.base_url + "/sso/login")[1]))
    assert ("code_challenge" in q) is (not app.vulnerable)
    q = _q(_loc(_get(app.base_url + "/sso/login-implicit")[1]))
    if app.vulnerable:
        assert q["response_type"] == ["id_token token"] and "nonce" not in q
    else:
        assert q["response_type"] == ["code"] and "nonce" in q


def test_session_idp_bounces_to_callback_with_echoed_state(app, idps):
    authz = _loc(_get(app.base_url + "/sso/login-silent")[1])
    assert authz.startswith(idps[1].issuer_url + "/authorize?")
    st, h, _ = _get(authz)
    cb = _loc(h)
    assert st == 302 and urlsplit(cb).path == "/sso/callback"
    assert _q(cb)["state"] == _q(authz)["state"]
    st, h, _ = _get(cb)
    assert st == 302 and _loc(h).endswith("/sso/home")
    assert _q(cb)["code"][0] in app.issued_secrets   # the RP records codes it received


def test_discovery_at_issuer_path(idps):
    st, _h, body = _get(idps[0].issuer_url + "/.well-known/openid-configuration")
    doc = json.loads(body)
    assert st == 200 and doc["issuer"] == idps[0].issuer_url
    assert doc["end_session_endpoint"] == idps[0].issuer_url + "/endsession"


def test_sso_index_links(app, idps):
    st, _h, body = _get(app.base_url + "/sso")
    assert st == 200
    for needle in (b'href="/sso/login"', b"/sso/login-silent", b"/sso/login-implicit",
                   (idps[0].issuer_url + "/authorize?").encode(), b'id="spa-signin"',
                   (idps[1].issuer_url + "/endsession?post_logout_redirect_uri=").encode()):
        assert needle in body, needle


def test_baked_href_state_static_when_vulnerable(app):
    import re
    hrefs = []
    for _ in range(2):
        body = _get(app.base_url + "/sso")[2].decode()
        hrefs.append(re.search(r'id="link-signin" href="([^"]+)"', body).group(1).replace("&amp;", "&"))
    s = [_q(h)["state"][0] for h in hrefs]
    assert (s[0] == s[1]) is app.vulnerable


def test_idp_requests_logged(idps):
    idps[0].clear()
    _get(idps[0].issuer_url + "/.well-known/openid-configuration")
    assert idps[0].paths() == ["/default/.well-known/openid-configuration"]


def test_rp_records_host_of_each_request(app):
    _get(app.base_url + "/sso")
    assert ("GET", "127.0.0.1", "/sso") in app.host_requests


def test_write_session_file(app, tmp_path):
    p = tmp_path / "s.json"
    app.write_session_file(str(p))
    state = json.loads(p.read_text())
    sid = next(c for c in state["cookies"] if c["name"] == "sid")
    assert sid["domain"] == "127.0.0.1" and sid["value"] in app.valid_sids
