"""Spec 3b, Task 1: the fixture's v4 endpoints (request-level weaknesses), each
with a vulnerable and a patched mode. Plain HTTP, no browser."""

import json
import os
import sys
import threading
import urllib.error
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

from ui_walk_app import serve  # noqa: E402


def _req(app, method, path, body=None, headers=None, cookie=True, raw=None):
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    r = urllib.request.Request(app.base_url + path, data=data, method=method)
    if data is not None and not (headers or {}).get("Content-Type"):
        r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if cookie:
        r.add_header("Cookie", app.login_cookie())
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read().decode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


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


def test_admin_xff_vulnerable_200_patched_403(vuln, patched):
    assert _req(vuln, "GET", "/api/v4/admin")[0] == 403
    assert _req(vuln, "GET", "/api/v4/admin", headers={"X-Forwarded-For": "127.0.0.1"})[0] == 200
    assert _req(vuln, "GET", "/api/v4/export", headers={"X-Original-URL": "/api/v4/admin"})[0] == 200
    assert _req(patched, "GET", "/api/v4/admin", headers={"X-Forwarded-For": "127.0.0.1"})[0] == 403
    assert _req(patched, "GET", "/api/v4/export", headers={"X-Original-URL": "/api/v4/admin"})[0] == 200
    # the patched export is just the export, not the admin payload
    assert "admin" not in _req(patched, "GET", "/api/v4/export", headers={"X-Original-URL": "/api/v4/admin"})[1]


def test_reports_path_tricks_vulnerable_200_patched_403(vuln, patched):
    assert _req(vuln, "GET", "/api/v4/reports")[0] == 403
    for p in ("/api/v4/reports/", "/API/V4/REPORTS", "/api/v4/reports;.css"):
        assert _req(vuln, "GET", p)[0] == 200, p
        assert _req(patched, "GET", p)[0] in (403, 404), p


def test_export_acl_head_swap_and_override(vuln, patched):
    assert _req(vuln, "GET", "/api/v4/export-acl")[0] == 403
    assert _req(vuln, "HEAD", "/api/v4/export-acl")[0] == 200
    assert _req(vuln, "GET", "/api/v4/export-acl", headers={"X-HTTP-Method-Override": "HEAD"})[0] == 200
    assert _req(patched, "HEAD", "/api/v4/export-acl")[0] == 403
    assert _req(patched, "GET", "/api/v4/export-acl", headers={"X-HTTP-Method-Override": "HEAD"})[0] == 403


def test_profile_content_types_vulnerable_accepts_form_and_text_patched_415(vuln, patched):
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    text = {"Content-Type": "text/plain"}
    assert _req(vuln, "PUT", "/api/v3/profile", headers=form, raw=b"display_name=viaform")[0] == 200
    assert json.loads(_req(vuln, "GET", "/api/v3/me")[1])["display_name"] == "viaform"
    assert _req(vuln, "PUT", "/api/v3/profile", headers=text, raw=b'{"display_name":"viatext"}')[0] == 200
    assert _req(patched, "PUT", "/api/v3/profile", headers=form, raw=b"display_name=viaform")[0] == 415
    assert _req(patched, "PUT", "/api/v3/profile", headers=text, raw=b'{"display_name":"x"}')[0] == 415
    assert _req(patched, "PUT", "/api/v3/profile", body={"display_name": "ok"})[0] == 200


def test_preferences_dup_key_vulnerable_stores_last_patched_400(vuln, patched):
    dup = b'{"theme": "dark", "theme": "evil"}'
    assert json.loads(_req(vuln, "GET", "/api/v4/preferences")[1]) == {"id": "u-1001", "theme": "dark"}
    assert _req(vuln, "PUT", "/api/v4/preferences", raw=dup)[0] == 200
    assert json.loads(_req(vuln, "GET", "/api/v4/preferences")[1])["theme"] == "evil"
    assert _req(vuln, "PUT", "/api/v4/preferences", body={"theme": "evil"})[0] == 400   # the value alone is rejected
    assert _req(patched, "PUT", "/api/v4/preferences", raw=dup)[0] == 400
    assert json.loads(_req(patched, "GET", "/api/v4/preferences")[1])["theme"] == "dark"


def test_page_cache_poison_vulnerable_serves_injected_host_to_second_request_patched_clean(vuln, patched):
    h = {"X-Forwarded-Host": "hmx.invalid"}
    st, body, hd = _req(vuln, "GET", "/v4/page?lang=en&hmcb=aa", headers=h, cookie=False)
    assert st == 200 and "hmx.invalid" in body and hd.get("X-Cache") == "MISS" and "Age" in hd
    st, body, hd = _req(vuln, "GET", "/v4/page?lang=en&hmcb=aa", cookie=False)
    assert "hmx.invalid" in body and hd.get("X-Cache") == "HIT"
    st, body, _ = _req(vuln, "GET", "/v4/page?lang=en&hmcb=bb", cookie=False)   # another key: clean
    assert "hmx.invalid" not in body
    _req(patched, "GET", "/v4/page?lang=en&hmcb=aa", headers=h, cookie=False)
    assert "hmx.invalid" not in _req(patched, "GET", "/v4/page?lang=en&hmcb=aa", cookie=False)[1]


def test_account_page_css_deception_vulnerable_served_unauth_second_time_patched_404(vuln, patched):
    assert "u-1001" in _req(vuln, "GET", "/v4/account-page?tab=1")[1]
    assert _req(vuln, "GET", "/v4/account-page?tab=1", cookie=False)[0] in (302, 401, 403)
    st, body, _ = _req(vuln, "GET", "/v4/account-page/x.css?hmcb=cc")
    assert st == 200 and "u-1001" in body
    st, body, _ = _req(vuln, "GET", "/v4/account-page/x.css?hmcb=cc", cookie=False)
    assert st == 200 and "u-1001" in body                      # the cached private page, no cookie
    assert _req(patched, "GET", "/v4/account-page/x.css?hmcb=cc")[0] == 404


def test_graphql_alias_and_array_vulnerable_ok_patched_rejected(vuln, patched):
    q1 = {"query": "query Me { me { id display_name } }"}
    q3 = {"query": "query Me { a1: me { id } a2: me { id } a3: me { id } }"}
    for a in (vuln, patched):
        st, body, _ = _req(a, "POST", "/api/v4/graphql", body=q1)
        assert st == 200 and json.loads(body)["data"]["me"]["id"] == "u-1001"
    st, body, _ = _req(vuln, "POST", "/api/v4/graphql", body=q3)
    assert st == 200 and set(json.loads(body)["data"]) == {"a1", "a2", "a3"}
    assert _req(vuln, "POST", "/api/v4/graphql", body=[q1, q1])[0] == 200
    st, body, _ = _req(patched, "POST", "/api/v4/graphql", body=q3)
    assert "alias limit" in body and "data" not in json.loads(body)
    assert _req(patched, "POST", "/api/v4/graphql", body=[q1, q1])[0] == 400
    # a mutation is answered and changes state (tests assert it is never sent without grant+owned)
    st, _, _ = _req(vuln, "POST", "/api/v4/graphql", body={"query": 'mutation { setName(name:"zz") { id } }'})
    assert st == 200 and json.loads(_req(vuln, "GET", "/api/v3/me")[1])["display_name"] == "zz"


def _race(app, n=5):
    out = []

    def go():
        out.append(_req(app, "POST", "/api/v4/coupons/c-1/redeem", body={})[0])
    ts = [threading.Thread(target=go) for _ in range(n)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return out


def test_coupon_race_vulnerable_all_succeed_patched_exactly_one(vuln, patched):
    assert json.loads(_req(vuln, "GET", "/api/v4/coupons/c-1")[1]) == {"id": "c-1", "redeemed": 0}
    v = _race(vuln)
    assert v.count(200) >= 2
    p = _race(patched)
    assert p.count(200) == 1 and p.count(409) == 4
    st, body, _ = _req(patched, "POST", "/api/v4/coupons", body={})
    assert st == 201 and json.loads(body)["id"].startswith("c-")


def test_v4_requires_auth_except_public_page(vuln):
    assert _req(vuln, "GET", "/api/v4/reports", cookie=False)[0] == 401
    assert _req(vuln, "GET", "/v4/page?lang=en", cookie=False)[0] == 200
    assert _req(vuln, "GET", "/v4")[0] == 200
