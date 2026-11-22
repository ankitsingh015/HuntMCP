"""Session keep-alive: the local fixture app + mini OIDC IdP behaves like the
real thing (no browser needed). Ordinary test fixture, not a benchmark."""

import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "session_refresh_target"))

from oidc_fixture import serve  # noqa: E402


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        r = opener.open(req, timeout=10)
        return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _post(url, form, headers=None):
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def _pkce():
    ver = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
    return ver, chal


@pytest.fixture
def fx():
    f = serve()
    yield f
    f.close()


def _idp_url(fx, path):
    # urllib can't resolve *.localhost everywhere; talk to the loopback port and
    # send the Host header the IdP dispatches on.
    return f"http://127.0.0.1:{fx.idp_port}{path}"



def _hdr(fx, cookie=None):
    h = {"Host": f"idp.localhost:{fx.idp_port}"}
    if cookie:
        h["Cookie"] = cookie
    return h


def _authorize(fx, chal, cookie=None, prompt="none"):
    q = {"client_id": "spa", "redirect_uri": fx.app_url + "callback", "response_type": "code",
         "scope": "openid", "state": "st", "code_challenge": chal, "code_challenge_method": "S256"}
    if prompt:
        q["prompt"] = prompt
    return _get(_idp_url(fx, "/authorize?" + urllib.parse.urlencode(q)), _hdr(fx, cookie))


def _sso(fx):
    c = fx.sso_cookie()
    return f"{c['name']}={c['value']}"


def test_discovery_doc(fx):
    status, _, body = _get(_idp_url(fx, "/.well-known/openid-configuration"), _hdr(fx))
    doc = json.loads(body)
    assert status == 200
    assert doc["issuer"] == fx.idp_base
    assert doc["token_endpoint"] == fx.idp_base + "/token"


def test_authorize_prompt_none_with_sso_returns_code(fx):
    _, chal = _pkce()
    status, headers, _ = _authorize(fx, chal, _sso(fx))
    assert status == 302
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["Location"]).query)
    assert "code" in q and q["state"] == ["st"]


def test_authorize_prompt_none_without_sso_login_required(fx):
    _, chal = _pkce()
    status, headers, _ = _authorize(fx, chal)
    assert status == 302
    assert "error=login_required" in headers["Location"]


def test_authorize_interactive_without_sso_shows_password_form(fx):
    _, chal = _pkce()
    status, _, body = _authorize(fx, chal, prompt=None)
    assert status == 200 and 'type="password"' in body


def test_authorize_captcha_mode(fx):
    fx.authorize_mode = "captcha"
    _, chal = _pkce()
    status, _, body = _authorize(fx, chal, _sso(fx))
    assert status == 200 and "g-recaptcha" in body


def test_authorize_redirect_rogue_mode(fx):
    fx.authorize_mode = "redirect_rogue"
    _, chal = _pkce()
    status, headers, _ = _authorize(fx, chal, _sso(fx))
    assert status == 302 and headers["Location"].startswith(fx.rogue_base)


def _code(fx):
    ver, chal = _pkce()
    _, headers, _ = _authorize(fx, chal, _sso(fx))
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["Location"]).query)["code"][0]
    return code, ver


def _token(fx, form):
    return _post(_idp_url(fx, "/token"), form, _hdr(fx))


def test_token_pkce_mismatch_rejected(fx):
    code, _ = _code(fx)
    status, body = _token(fx, {"grant_type": "authorization_code", "code": code, "client_id": "spa",
                               "redirect_uri": fx.app_url + "callback", "code_verifier": "wrong"})
    assert status == 400 and body["error"] == "invalid_grant"


def test_token_code_exchange_issues_valid_access(fx):
    code, ver = _code(fx)
    status, body = _token(fx, {"grant_type": "authorization_code", "code": code, "client_id": "spa",
                               "redirect_uri": fx.app_url + "callback", "code_verifier": ver})
    assert status == 200 and fx.valid_access(body["access_token"])
    assert body["refresh_token"]


def test_refresh_token_rotates_and_old_one_rejected(fx):
    code, ver = _code(fx)
    _, first = _token(fx, {"grant_type": "authorization_code", "code": code, "client_id": "spa",
                           "redirect_uri": fx.app_url + "callback", "code_verifier": ver})
    old_rt = first["refresh_token"]
    status, second = _token(fx, {"grant_type": "refresh_token", "refresh_token": old_rt, "client_id": "spa"})
    assert status == 200 and second["refresh_token"] != old_rt
    assert fx.valid_access(second["access_token"])
    assert old_rt in fx.used_refresh_tokens
    status, again = _token(fx, {"grant_type": "refresh_token", "refresh_token": old_rt, "client_id": "spa"})
    assert status == 400 and again["error"] == "invalid_grant"


def test_api_me_401_on_expired_token(fx):
    state = fx.seed_state(access_valid=False, with_rt=False)
    side = state["huntmcp_session_storage"][fx.app_origin]
    token = json.loads(side[fx.storage_key])["access_token"]
    status, _, _ = _get(fx.app_url + "api/me", {"Authorization": f"Bearer {token}"})
    assert status == 401


def test_api_me_200_on_valid_token(fx):
    state = fx.seed_state(access_valid=True, with_rt=True)
    entry = json.loads(state["huntmcp_session_storage"][fx.app_origin][fx.storage_key])
    status, _, body = _get(fx.app_url + "api/me", {"Authorization": f"Bearer {entry['access_token']}"})
    assert status == 200 and json.loads(body)["sub"] == "user-A"
    assert entry["refresh_token"]


def test_sso_invalid_when_disabled(fx):
    fx.sso_valid = False
    _, chal = _pkce()
    _, headers, _ = _authorize(fx, chal, _sso(fx))
    assert "error=login_required" in headers["Location"]
