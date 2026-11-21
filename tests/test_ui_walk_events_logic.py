"""#164: pure event logic for the UI-walk event recorder (no browser)."""

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import ui_walk_events_logic as E

PAGE = "https://app.test/dash"


def _scope(url):
    return "app.test" in url


def _ev(type_, **kw):
    base = {"type": type_, "control_signature": "sig1", "t_ms": 1, "frame_origin": "https://app.test"}
    base.update(kw)
    return base


def _page(events, edges=None, controls=None):
    return {"url": PAGE, "events": events, "api_edges": edges or [], "controls": controls or []}


def _types(cands):
    return [c["type"] for c in cands]


def _headers(**kw):
    base = {"url": PAGE, "resource_type": "document", "request_origin": "https://app.test",
            "csp": None, "xfo": None, "frame_ancestors": None, "acao": None,
            "acac": False, "acam": None, "hsts": False}
    base.update(kw)
    return _ev("headers", **base)


def _cookie(raw, type_="set_cookie", url=PAGE):
    c = E.parse_set_cookie(raw)[0]
    c.update({"url": url, "blocked": []})
    return _ev(type_, **c)


# ---- parsing ----

def test_parse_set_cookie_drops_value_and_reads_flags():
    r = E.parse_set_cookie("SID=s3cr3t; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert r[0]["name"] == "SID" and r[0]["secure"] is True and r[0]["httponly"] is True
    assert r[0]["samesite"] == "Lax" and r[0]["path"] == "/"
    assert "s3cr3t" not in json.dumps(r)
    assert "value" not in r[0]


def test_parse_set_cookie_multiple_and_expires_comma():
    r = E.parse_set_cookie("a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\nb=2")
    assert [c["name"] for c in r] == ["a", "b"]
    assert r[0]["persistent"] is True and r[1]["persistent"] is False


def test_parse_set_cookie_attribute_casing_and_no_equals():
    r = E.parse_set_cookie("x=1; secure; HTTPONLY; samesite=none; Partitioned")
    assert r[0]["secure"] and r[0]["httponly"] and r[0]["samesite"] == "none" and r[0]["partitioned"]
    # contract change (review item 3): a segment without "=" is a nameless cookie whose
    # VALUE is that string, so it must never be reported as a name
    assert E.parse_set_cookie("novalue")[0]["name"] == ""
    assert E.parse_set_cookie("") == []


def test_parse_cookie_assignment():
    r = E.parse_cookie_assignment("tok=abc; Max-Age=60; Domain=.app.test; Secure; HttpOnly")
    assert r["name"] == "tok" and r["persistent"] and r["secure"] and r["domain"] == ".app.test"
    assert r["httponly"] is False
    assert "abc" not in json.dumps(r)


def test_is_authish_name():
    assert E.is_authish_name("SID") and E.is_authish_name("JSESSIONID") and E.is_authish_name("XSRF-TOKEN")
    assert not E.is_authish_name("theme")


def test_data_shape_never_returns_values():
    r = E.data_shape({"token": "abc123", "n": 1})
    assert r == {"type": "object", "keys": ["n", "token"], "length": 2}
    assert "abc123" not in str(r)
    assert E.data_shape("hello") == {"type": "string", "keys": [], "length": 5}
    assert E.data_shape([1, 2])["type"] == "array"
    assert len(E.data_shape({str(i): 1 for i in range(50)})["keys"]) == 30


def test_storage_diff():
    before = {"o": {"a": "h1", "b": "h2", "c": "h3"}}
    after = {"o": {"a": "h1", "b": "hX", "d": "h4"}}
    r = E.storage_diff(before, after)
    assert {"origin": "o", "key": "b", "change": "changed"} in r
    assert {"origin": "o", "key": "c", "change": "removed"} in r
    assert {"origin": "o", "key": "d", "change": "added"} in r
    assert len(r) == 3
    assert E.storage_diff(before, before) == []


def test_redirect_param_names():
    hops = [{"url": "https://a.test/go?next=https://b.test/x&z=1", "location": "https://b.test/x"}]
    assert E.redirect_param_names(hops) == ["next"]
    assert E.redirect_param_names([{"url": "https://a.test/?z=1", "location": "/home"}]) == []


def test_redirect_param_names_no_substring_false_positives():
    # short/numeric values must not match inside the location
    assert E.redirect_param_names([{"url": "https://a.test/go?z=1", "location": "https://b.test/x1"}]) == []
    assert E.redirect_param_names([{"url": "https://a.test/go?id=1234", "location": "https://b.test/item/51234"}]) == []
    assert E.redirect_param_names([{"url": "https://a.test/go?id=12", "location": "https://b.test/12"}]) == []
    # mid-component prefix is not a boundary
    assert E.redirect_param_names([{"url": "https://a.test/go?n=https://b.te", "location": "https://b.test/x"}]) == []


def test_redirect_param_names_component_matches():
    loc = "https://b.test/dash/home?ref=abcd1234&x=1"
    def r(q):
        return E.redirect_param_names([{"url": "https://a.test/go?" + q, "location": loc}])
    assert r("u=https%3A%2F%2Fb.test%2Fdash%2Fhome%3Fref%3Dabcd1234%26x%3D1") == ["u"]  # full, decoded
    assert r("u=https://b.test") == ["u"]            # scheme+host
    assert r("u=/dash/home") == ["u"]                # path
    assert r("u=abcd1234") == ["u"]                  # whole query value
    assert r("u=https://b.test/dash") == ["u"]       # prefix at / boundary


def test_security_headers():
    r = E.security_headers({
        "content-security-policy": "frame-ancestors 'none'; " + "x" * 600,
        "x-frame-options": "DENY",
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
        "strict-transport-security": "max-age=1"})
    assert len(r["csp"]) <= 500 and r["xfo"] == "DENY" and r["frame_ancestors"] == "'none'"
    assert r["acao"] == "*" and r["acac"] is True and r["hsts"] is True
    r2 = E.security_headers({})
    assert r2["csp"] is None and r2["acac"] is False and r2["hsts"] is False


def test_validate_proxy_url():
    for ok in ("http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"):
        assert E.validate_proxy_url(ok) is None, ok
    for bad in ("http://10.0.0.5:8080", "http://burp.example:8080", "http://u:p@127.0.0.1:8080",
                "socks5://127.0.0.1:1080", "http://127.0.0.1", ""):
        assert isinstance(E.validate_proxy_url(bad), str), bad


def test_validate_proxy_url_rejects_path_query_fragment():
    assert E.validate_proxy_url("http://127.0.0.1:8080/") is None          # an empty or "/" path is fine
    for bad in ("http://127.0.0.1:8080/x", "http://127.0.0.1:8080/proxy/", "http://127.0.0.1:8080?a=1",
                "http://127.0.0.1:8080/?a=1", "http://127.0.0.1:8080?", "http://127.0.0.1:8080#f",
                "http://127.0.0.1:8080/#", "http://localhost:8080/;p"):
        assert isinstance(E.validate_proxy_url(bad), str), bad


def test_canonical_proxy_url_is_rebuilt():
    assert E.canonical_proxy_url("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"
    assert E.canonical_proxy_url("HTTP://LOCALHOST:8080") == "http://localhost:8080"
    assert E.canonical_proxy_url("http://[::1]:8080") == "http://[::1]:8080"
    for bad in ("http://10.0.0.5:8080", "http://127.0.0.1:8080/x", "http://u:p@127.0.0.1:8080", ""):
        with pytest.raises(ValueError):
            E.canonical_proxy_url(bad)


def test_resolve_upstream_proxy_off_beats_env():
    assert E.resolve_upstream_proxy("off", "http://127.0.0.1:1") is None
    assert E.resolve_upstream_proxy("", "http://127.0.0.1:1") == "http://127.0.0.1:1"
    assert E.resolve_upstream_proxy("http://127.0.0.1:2", "http://127.0.0.1:1") == "http://127.0.0.1:2"


def test_resolve_upstream_proxy_defaults_to_auto():
    # 2026-11-21 addendum (user decision): no param + no env = auto-detect Burp
    assert E.resolve_upstream_proxy("", None) == E.AUTO_PROXY
    assert E.resolve_upstream_proxy("", "") == E.AUTO_PROXY
    assert E.resolve_upstream_proxy("", "auto") == E.AUTO_PROXY
    assert E.resolve_upstream_proxy("auto", "http://127.0.0.1:1") == E.AUTO_PROXY
    assert E.resolve_upstream_proxy("", "off") is None
    assert E.resolve_upstream_proxy("off", None) is None


def test_looks_like_burp():
    assert E.looks_like_burp("<html><title>Burp Suite Professional</title>")
    assert E.looks_like_burp("<h1>burp suite community edition</h1>")
    assert not E.looks_like_burp("<html>Welcome to my dev server</html>")
    assert not E.looks_like_burp("")
    assert not E.looks_like_burp(None)


# ---- candidates ----

def test_cookie_authish_without_secure_on_https():
    c = E.derive_candidates(_page([_cookie("SID=s3cr3tval; Path=/; HttpOnly; SameSite=Lax")]), scope=_scope)
    assert _types(c) == ["cookie-flags-candidate"]
    assert "s3cr3tval" not in json.dumps(c)
    assert c[0]["page"] == PAGE and c[0]["control_signature"] == "sig1"


def test_cookie_fully_flagged_no_candidate():
    c = E.derive_candidates(_page([_cookie("SID=x; Secure; HttpOnly; SameSite=Lax")]), scope=_scope)
    assert c == []


def test_cookie_non_authish_none():
    assert E.derive_candidates(_page([_cookie("theme=dark")]), scope=_scope) == []


def test_cookie_samesite_none_without_secure():
    page = _page([_cookie("SID=x; HttpOnly; SameSite=None", url="http://app.test/")])
    assert _types(E.derive_candidates(page, scope=_scope)) == ["cookie-flags-candidate"]


def test_cookie_missing_httponly_set_cookie_only():
    assert _types(E.derive_candidates(
        _page([_cookie("SID=x; Secure; SameSite=Lax")]), scope=_scope)) == ["cookie-flags-candidate"]
    # js_cookie is never httponly: not flagged for that alone
    assert E.derive_candidates(
        _page([_cookie("SID=x; Secure; SameSite=Lax", type_="js_cookie")]), scope=_scope) == []


def test_cookie_missing_samesite():
    assert _types(E.derive_candidates(
        _page([_cookie("SID=x; Secure; HttpOnly")]), scope=_scope)) == ["cookie-flags-candidate"]


def test_postmessage_wildcard_target():
    ev = _ev("postmessage", direction="send", target_origin="*",
             shape={"type": "object", "keys": ["access_token"], "length": 1}, frame_in_scope=True)
    assert _types(E.derive_candidates(_page([ev]), scope=_scope)) == ["postmessage-wildcard-target-candidate"]
    neg1 = dict(ev, target_origin="https://app.test")
    neg2 = dict(ev, shape={"type": "object", "keys": ["height"], "length": 1})
    neg3 = dict(ev, direction="listen")
    for n in (neg1, neg2, neg3):
        assert E.derive_candidates(_page([n]), scope=_scope) == []


def test_postmessage_no_origin_check():
    p = _page([])
    p["postmessage_probe"] = {"result": "reaction", "reactions": ["dom"]}
    assert _types(E.derive_candidates(p, scope=_scope)) == ["postmessage-no-origin-check-candidate"]
    p["postmessage_probe"] = {"result": "no-reaction", "reactions": []}
    assert E.derive_candidates(p, scope=_scope) == []


def test_storage_token():
    ev = _ev("storage", origin="https://app.test", key="auth_token", change="added")
    assert _types(E.derive_candidates(_page([ev]), scope=_scope)) == ["storage-token-candidate"]
    assert E.derive_candidates(_page([dict(ev, key="theme")]), scope=_scope) == []
    assert E.derive_candidates(_page([dict(ev, change="removed")]), scope=_scope) == []


def test_redirect_param():
    ev = _ev("redirect", hops=[{"url": "u", "status": 302, "in_scope": True}], param_names=["next"])
    assert _types(E.derive_candidates(_page([ev]), scope=_scope)) == ["redirect-param-candidate"]
    assert E.derive_candidates(_page([dict(ev, param_names=[])]), scope=_scope) == []


def test_clickjacking_positive_and_negatives():
    edges = [{"method": "POST", "sent": True}]
    h = _headers()
    assert "clickjacking-candidate" in _types(E.derive_candidates(_page([h], edges), scope=_scope))
    h2 = _headers(csp="frame-ancestors 'none'", frame_ancestors="'none'")
    assert E.derive_candidates(_page([h2], edges), scope=_scope) == []
    assert E.derive_candidates(_page([_headers(xfo="DENY")], edges), scope=_scope) == []
    # no state-changing surface at all
    assert E.derive_candidates(_page([h], [{"method": "GET", "sent": True}]), scope=_scope) == []
    # destructive control counts
    assert "clickjacking-candidate" in _types(E.derive_candidates(
        _page([h], [], [{"classification": "destructive"}]), scope=_scope))


def test_cors():
    pos = _headers(resource_type="fetch", acao="*", acac=True)
    assert "cors-candidate" in _types(E.derive_candidates(_page([pos]), scope=_scope))
    reflect = _headers(resource_type="fetch", acao="https://app.test", acac=True)
    assert "cors-candidate" in _types(E.derive_candidates(_page([reflect]), scope=_scope))
    fixed = _headers(resource_type="fetch", acao="https://partner.test", acac=True)
    assert "cors-candidate" not in _types(E.derive_candidates(_page([fixed]), scope=_scope))
    nocred = _headers(resource_type="fetch", acao="*", acac=False)
    assert "cors-candidate" not in _types(E.derive_candidates(_page([nocred]), scope=_scope))


def test_tabnabbing():
    ev = _ev("window_open", url="https://evil.test/x", noopener=False, via="anchor")
    assert _types(E.derive_candidates(_page([ev]), scope=_scope)) == ["tabnabbing-candidate"]
    assert E.derive_candidates(_page([dict(ev, noopener=True)]), scope=_scope) == []
    assert E.derive_candidates(_page([dict(ev, url="https://app.test/x")]), scope=_scope) == []


def test_dom_sink_and_xss_carry_csp():
    sink = _ev("dom_sink", source="location.hash", sink="innerHTML", executed=False,
               token="tok", script_url="https://app.test/a.js", line=3)
    h = _headers(csp="script-src 'self'")
    c = E.derive_candidates(_page([h, sink]), scope=_scope)
    assert _types(c) == ["dom-sink-candidate"] and c[0]["detail"]["csp"] == "script-src 'self'"
    c = E.derive_candidates(_page([h, dict(sink, executed=True)]), scope=_scope)
    assert _types(c) == ["dom-xss-candidate"] and c[0]["detail"]["csp"] == "script-src 'self'"
    c = E.derive_candidates(_page([dict(sink, executed=True)]), scope=_scope)
    assert c[0]["detail"]["csp"] is None


def test_dedup_per_page():
    ev = _ev("storage", origin="https://app.test", key="auth_token", change="added")
    assert len(E.derive_candidates(_page([ev, dict(ev)]), scope=_scope)) == 1


def test_cookie_segment_without_equals_has_no_name():
    # `document.cookie = "FIXTURESECRET"` sets a nameless cookie whose VALUE is that string
    c = E.parse_cookie_assignment("FIXTURESECRET; Secure; Path=/")
    assert c["name"] == "" and c["secure"] is True and c["path"] == "/"
    assert "FIXTURESECRET" not in json.dumps(c)
    assert E.parse_cookie_assignment("FIXTURESECRET")["name"] == ""
    assert E.parse_set_cookie("FIXTURESECRET\nsid=v; Path=/")[0]["name"] == ""
    assert E.parse_set_cookie("FIXTURESECRET\nsid=v; Path=/")[1]["name"] == "sid"
    assert E.parse_cookie_assignment("a=b")["name"] == "a"


# ---- fix wave: clickjacking needs THIS page's top-document headers (item 3) ----
def test_clickjacking_needs_a_top_document_headers_event():
    edges = [{"method": "POST", "sent": True}]
    # zero document headers events: nothing is known about the page's framing headers
    assert "clickjacking-candidate" not in _types(E.derive_candidates(_page([], edges), scope=_scope))
    # only a fetch/xhr headers event: still not the page's own document
    xhr = _headers(resource_type="fetch", url="https://app.test/api/x")
    assert "clickjacking-candidate" not in _types(E.derive_candidates(_page([xhr], edges), scope=_scope))
    # a document headers event for a DIFFERENT path (a subframe document) is not this page
    other = _headers(url="https://app.test/embed")
    assert "clickjacking-candidate" not in _types(E.derive_candidates(_page([other], edges), scope=_scope))
    # this page's top document without XFO / frame-ancestors -> candidate
    top = _headers(url=PAGE)
    c = [x for x in E.derive_candidates(_page([top], edges), scope=_scope) if x["type"] == "clickjacking-candidate"]
    assert len(c) == 1 and c[0]["detail"]["document_headers_seen"] == 1


def test_clickjacking_subframe_with_xfo_does_not_mask_top_page_without():
    edges = [{"method": "POST", "sent": True}]
    sub = _headers(url="https://app.test/embed", xfo="DENY")
    top = _headers(url=PAGE)
    assert "clickjacking-candidate" in _types(E.derive_candidates(_page([sub, top], edges), scope=_scope))
    assert "clickjacking-candidate" in _types(E.derive_candidates(_page([top, sub], edges), scope=_scope))
    # and the top page WITH XFO is never a candidate, whatever its subframes send
    top_ok = _headers(url=PAGE, xfo="SAMEORIGIN")
    sub_bad = _headers(url="https://app.test/embed")
    assert E.derive_candidates(_page([top_ok, sub_bad], edges), scope=_scope) == []


def test_clickjacking_page_url_query_and_fragment_ignored():
    edges = [{"method": "POST", "sent": True}]
    page = {"url": PAGE + "?tab=1", "events": [_headers(url=PAGE)], "api_edges": edges, "controls": []}
    assert "clickjacking-candidate" in _types(E.derive_candidates(page, scope=_scope))


# ---- fix wave: redirect param matching on the RESOLVED Location (item 9) ----
def test_redirect_param_names_relative_location_vs_absolute_param():
    hops = [{"url": "https://a.test/go?next=https://a.test/dash/home", "location": "/dash/home"}]
    assert E.redirect_param_names(hops) == ["next"]
    hops = [{"url": "https://a.test/sso/go?next=https://a.test/sso/cb", "location": "cb"}]   # path-relative
    assert E.redirect_param_names(hops) == ["next"]


def test_redirect_param_names_bare_host():
    hops = [{"url": "https://a.test/go?domain=evil.test&z=1", "location": "https://evil.test/landing"}]
    assert E.redirect_param_names(hops) == ["domain"]
    hops = [{"url": "https://a.test/go?h=b.te", "location": "https://b.test/"}]        # partial host: no
    assert E.redirect_param_names(hops) == []


def test_redirect_param_names_trailing_slash_difference():
    hops = [{"url": "https://a.test/go?next=https://b.test/x/", "location": "https://b.test/x"}]
    assert E.redirect_param_names(hops) == ["next"]
    hops = [{"url": "https://a.test/go?next=https://b.test/x", "location": "https://b.test/x/"}]
    assert E.redirect_param_names(hops) == ["next"]
    hops = [{"url": "https://a.test/go?next=https://b.test/", "location": "https://b.test"}]
    assert E.redirect_param_names(hops) == ["next"]
    # only ONE trailing slash is ignored, and the min-length rule still holds
    hops = [{"url": "https://a.test/go?n=//", "location": "https://b.test/"}]
    assert E.redirect_param_names(hops) == []
