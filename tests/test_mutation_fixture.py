"""Spec 3a, Task 1: the fixture's v3 endpoints (mass-assignable profile,
removable OTP, HPP-confused preview, type-juggling promo check, ?query DOM
sink), each with a vulnerable and a patched mode. Plain HTTP, no browser."""

import json
import os
import sys
import urllib.error
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

from ui_walk_app import serve


def _req(app, method, path, body=None, cookie=True):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(app.base_url + path, data=data, method=method)
    if body is not None:
        r.add_header("Content-Type", "application/json")
    if cookie:
        r.add_header("Cookie", app.login_cookie())
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


@pytest.fixture(params=[True, False], ids=["vulnerable", "patched"])
def app(request):
    a = serve(vulnerable=request.param)
    yield a
    a.close()


@pytest.fixture
def vuln():
    a = serve(vulnerable=True)
    yield a
    a.close()


@pytest.fixture
def patched():
    a = serve(vulnerable=False)
    yield a
    a.close()


def test_me_shape(app):
    st, body = _req(app, "GET", "/api/v3/me")
    me = json.loads(body)
    assert st == 200 and me["id"] == "u-1001" and me["role"] == "user" and me["plan"] == "free"


def test_me_requires_auth(app):
    assert _req(app, "GET", "/api/v3/me", cookie=False)[0] == 401


def test_profile_mass_assign_vulnerable_persists_role(vuln):
    st, _ = _req(vuln, "PUT", "/api/v3/profile", {"display_name": "x", "role": "admin"})
    assert st == 200
    me = json.loads(_req(vuln, "GET", "/api/v3/me")[1])
    assert me["role"] == "admin" and me["display_name"] == "x" and vuln.v3_me["role"] == "admin"


def test_profile_patched_ignores_role(patched):
    st, _ = _req(patched, "PUT", "/api/v3/profile", {"display_name": "x", "role": "admin"})
    assert st == 200
    me = json.loads(_req(patched, "GET", "/api/v3/me")[1])
    assert me["role"] == "user" and me["display_name"] == "x"


def test_change_email_without_otp_vulnerable_200_patched_403(vuln, patched):
    assert _req(vuln, "POST", "/api/v3/account/change-email", {"email": "a@example.invalid"})[0] == 200
    assert vuln.v3_me["email"] == "a@example.invalid"
    assert _req(patched, "POST", "/api/v3/account/change-email", {"email": "a@example.invalid"})[0] == 403
    assert patched.v3_me["email"] != "a@example.invalid"


def test_change_email_wrong_otp_403_right_otp_200(app):
    assert _req(app, "POST", "/api/v3/account/change-email", {"email": "b@example.invalid", "otp": "000000"})[0] == 403
    assert _req(app, "POST", "/api/v3/account/change-email", {"email": "b@example.invalid", "otp": app.v3_otp})[0] == 200


def test_transfer_preview_single_values(app):
    assert _req(app, "GET", "/api/v3/transfer-preview?to=u-1001")[0] == 200
    assert _req(app, "GET", "/api/v3/transfer-preview?to=u-2002")[0] == 403


def test_transfer_preview_hpp_vulnerable_previews_last(vuln):
    st, body = _req(vuln, "GET", "/api/v3/transfer-preview?to=u-1001&to=u-2002")
    assert st == 200 and json.loads(body)["preview_for"] == "u-2002"


def test_transfer_preview_patched_rejects_duplicate(patched):
    assert _req(patched, "GET", "/api/v3/transfer-preview?to=u-1001&to=u-2002")[0] == 400


def test_promo_scalar(app):
    assert _req(app, "GET", "/api/v3/promo-check?promo=" + app.v3_promo)[0] == 200
    assert _req(app, "GET", "/api/v3/promo-check?promo=WELCOME0")[0] == 403


def test_promo_array_vulnerable_200_patched_400(vuln, patched):
    st, body = _req(vuln, "GET", "/api/v3/promo-check?promo[]=x")
    assert st == 200 and json.loads(body)["valid"] is True
    assert _req(patched, "GET", "/api/v3/promo-check?promo[]=x")[0] == 400


def test_acct_page_wires_the_requests(app):
    st, body = _req(app, "GET", "/acct")
    assert st == 200
    for s in ("/api/v3/me", "/api/v3/profile", "/api/v3/account/change-email",
              "/api/v3/transfer-preview?to=u-1001", "/api/v3/promo-check?promo=WELCOME0"):
        assert s in body


def test_qsink_vulnerable_uses_innerhtml(vuln, patched):
    st, body = _req(vuln, "GET", "/qsink?msg=hello", cookie=False)
    assert st == 200 and "innerHTML" in body
    st, body = _req(patched, "GET", "/qsink?msg=hello", cookie=False)
    assert st == 200 and "textContent" in body and "innerHTML" not in body
