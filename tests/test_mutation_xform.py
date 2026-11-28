"""Spec 3b, Task 2: request transforms, effective-method + gate hardening (pure)."""

import json
import os
import sys
from urllib.parse import parse_qsl, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M  # noqa: E402
import mutation_xform as X  # noqa: E402
from ui_walk_grant import Grant  # noqa: E402

H = "http://127.0.0.1:9000"
GRANT = Grant(canary_submit=True)
OWN = M.Ownership(True, "own-account", "test")
NOT_OWN = M.Ownership(False, "none", "test")


def scope(u):
    return u.startswith(H)


def R(url=H + "/api/x?a=1", method="GET", headers=None, body=None):
    h = headers or {}
    return M.Req("r1", method, url, h, body, M.body_kind_of(h, body), "x")


def gate(req, grant=None, owned=NOT_OWN, restore=False, **kw):
    return M.gate(req, scope=scope, grant=grant, owned=owned, has_restore_path=restore, never_mutated=False, **kw)


JSON_H = {"Content-Type": "application/json"}


# -- transforms -------------------------------------------------------------------
def test_apply_set_header_replaces_case_insensitive():
    r = X.apply_xforms(R(headers={"x-forwarded-for": "1.1.1.1", "A": "b"}),
                       [X.Xform("set_header", "X-Forwarded-For", "127.0.0.1")])
    assert [k for k in r.headers if k.lower() == "x-forwarded-for"] == ["X-Forwarded-For"]
    assert r.headers["X-Forwarded-For"] == "127.0.0.1" and r.headers["A"] == "b"
    r2 = X.apply_xforms(r, [X.Xform("remove_header", "x-forwarded-for")])
    assert "X-Forwarded-For" not in r2.headers


def test_apply_does_not_mutate_input():
    req = R(headers={"A": "b"})
    X.apply_xforms(req, [X.Xform("set_header", "C", "d"), X.Xform("method", value="POST"),
                         X.Xform("path", value="/other")])
    assert req.headers == {"A": "b"} and req.method == "GET" and req.url == H + "/api/x?a=1"


def test_apply_method_swap_and_override_header_and_param():
    assert X.apply_xforms(R(), [X.Xform("method", value="HEAD")]).method == "HEAD"
    r = X.apply_xforms(R(), [X.Xform("override", "header:X-HTTP-Method-Override", "HEAD")])
    assert r.method == "GET" and r.headers["X-HTTP-Method-Override"] == "HEAD"
    r = X.apply_xforms(R(), [X.Xform("override", "param:_method", "HEAD")])
    assert ("_method", "HEAD") in parse_qsl(urlsplit(r.url).query)
    j = X.apply_xforms(R(method="POST", headers=JSON_H, body='{"a": 1}'), [X.Xform("override", "param:_method", "PUT")])
    assert json.loads(j.body) == {"a": 1, "_method": "PUT"}


def test_apply_content_type_json_to_form_and_text_and_xml():
    base = R(method="PUT", headers=JSON_H, body=json.dumps({"display_name": "x", "n": 5}))
    f = X.apply_xforms(base, [X.Xform("content_type", value="form")])
    assert f.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert dict(parse_qsl(f.body)) == {"display_name": "x", "n": "5"}
    t = X.apply_xforms(base, [X.Xform("content_type", value="text")])
    assert t.headers["Content-Type"] == "text/plain" and json.loads(t.body) == {"display_name": "x", "n": 5}
    x = X.apply_xforms(base, [X.Xform("content_type", value="xml")])
    assert x.headers["Content-Type"] == "application/xml"
    assert "<display_name>x</display_name>" in x.body and "<n>5</n>" in x.body
    back = X.apply_xforms(f, [X.Xform("content_type", value="json")])
    assert json.loads(back.body) == {"display_name": "x", "n": "5"}
    assert [k for k in f.headers if k.lower() == "content-type"] == ["Content-Type"]


def test_apply_path_keeps_host_and_query():
    r = X.apply_xforms(R(), [X.Xform("path", value="/api/x/")])
    assert r.url == H + "/api/x/?a=1"


def test_cache_xforms_map_to_header_and_path_suffix():
    r = X.apply_xforms(R(), [X.Xform("cache_poison", "X-Forwarded-Host", "hm.invalid")])
    assert r.headers["X-Forwarded-Host"] == "hm.invalid"
    r = X.apply_xforms(R(), [X.Xform("cache_deception", value="/hm.css")])
    assert urlsplit(r.url).path == "/api/x/hm.css"


def test_with_buster_adds_and_replaces():
    u = X.with_buster(H + "/p?lang=en", "abc123")
    assert dict(parse_qsl(urlsplit(u).query)) == {"lang": "en", "hmcb": "abc123"}
    u2 = X.with_buster(u, "zzz999")
    assert dict(parse_qsl(urlsplit(u2).query)) == {"lang": "en", "hmcb": "zzz999"}


def test_variant_id_unchanged_without_xforms():
    ops = [M.Op("add_param", "query", ("role",), "admin")]
    legacy = M._vid("r1", ops)
    assert M._vid("r1", ops, ()) == legacy
    assert M._vid("r1", ops, [X.Xform("set_header", "A", "b")]) != legacy
    assert M._vid("r1", [], [X.Xform("set_header", "A", "b")]) != M._vid("r1", [], [X.Xform("set_header", "A", "c")])


# -- effective method hardening --------------------------------------------------
def test_effective_method_any_nonget_source_wins():
    assert M.effective_method(R(headers={"X-HTTP-Method-Override": "HEAD, DELETE"})) not in ("GET", "HEAD")
    assert M.effective_method(R(headers={"X-HTTP-Method-Override": "HEAD", "X-Method-Override": "DELETE"})) == "DELETE"
    assert M.effective_method(R(headers={"X-Foo-Method": "DELETE"})) == "DELETE"
    assert M.effective_method(R(url=H + "/a?_method=HEAD",
                                headers={"X-HTTP-Method": "PUT"})) == "PUT"
    j = R(method="POST", headers=JSON_H, body='{"_method": "DELETE"}')
    assert M.effective_method(j) == "DELETE"
    assert M.effective_method(R(headers={"X-HTTP-Method-Override": "HEAD"})) == "HEAD"
    assert M.effective_method(R()) == "GET"


def test_gate_get_with_conflicting_overrides_needs_grant():
    r = gate(R(headers={"X-HTTP-Method-Override": "HEAD", "X-Method-Override": "DELETE"}))
    assert not r.send and r.needs_grant
    r = gate(R(headers={"X-HTTP-Method-Override": "HEAD, DELETE"}))
    assert not r.send and r.needs_grant
    r = gate(R(headers={"X-Whatever-Method": "PUT"}))
    assert not r.send and r.needs_grant
    ok = gate(R(headers={"X-HTTP-Method-Override": "HEAD"}))
    assert ok.send and not ok.needs_grant


def test_gate_routing_header_to_mutating_path_blocked():
    for name in ("X-Original-URL", "X-Rewrite-URL"):
        r = gate(R(headers={name: "/api/account/delete"}))
        assert not r.send and r.reason == "routing-header-mutating", name
    r = gate(R(headers={"X-Original-URL": "/logout"}))
    assert not r.send and r.reason == "routing-header-mutating"
    r = gate(R(headers={"X-Original-URL": "http://other.invalid/x"}))
    assert not r.send and r.reason == "routing-header-mutating"
    assert gate(R(headers={"X-Original-URL": "/api/v4/admin"})).send
    assert M.routing_alt_urls(R(headers={"X-Original-URL": "/api/v4/admin"})) == [H + "/api/v4/admin"]


def test_gate_double_encoded_mutating_path_blocked():
    assert gate(R(url=H + "/api/%2564elete")).reason == "mutating-get"
    assert gate(R(url=H + "/api/%64elete")).reason == "mutating-get"
    assert gate(R(url=H + "/api/items")).send


def test_gate_graphql_readonly_post_sends_without_grant_but_not_to_payment_host_or_out_of_scope():
    body = json.dumps({"query": "query Me { me { id } }"})
    post = R(url=H + "/api/v4/graphql", method="POST", headers=JSON_H, body=body)
    assert not gate(post).send                                   # a plain POST still needs the grant
    ok = gate(post, graphql_readonly=True)
    assert ok.send and not ok.needs_grant
    pay = R(url="https://api.stripe.com/graphql", method="POST", headers=JSON_H, body=body)
    assert gate(pay, graphql_readonly=True).reason in ("payment-host", "out-of-scope")
    out = R(url="http://other.invalid/graphql", method="POST", headers=JSON_H, body=body)
    assert gate(out, graphql_readonly=True).reason == "out-of-scope"
    # an override header on the POST voids the exemption
    ov = R(url=H + "/api/v4/graphql", method="POST", headers={**JSON_H, "X-HTTP-Method-Override": "DELETE"}, body=body)
    assert not gate(ov, graphql_readonly=True).send
    # a PUT is never read-only
    put = R(url=H + "/api/v4/graphql", method="PUT", headers=JSON_H, body=body)
    assert not gate(put, graphql_readonly=True).send
    # mutating-looking URL still blocked
    mu = R(url=H + "/api/v4/graphql?action=delete", method="POST", headers=JSON_H, body=body)
    assert gate(mu, graphql_readonly=True).reason == "mutating-get"


def test_json_raw_bignum_targets_the_named_field_only():
    r = R(method="PUT", headers=JSON_H, body=json.dumps({"qty": 0, "n": 3, "role": "user"}))
    out = X.apply_xforms(r, [X.Xform("json_raw", "bignum", "n")]).body
    assert '"n": 99999999999999999999' in out and '"qty": 0' in out
    out = X.apply_xforms(r, [X.Xform("json_raw", "bignum", "qty")]).body
    assert '"qty": 99999999999999999999' in out and '"n": 3' in out
    u = X.apply_xforms(r, [X.Xform("json_raw", "unicode_key", "role")]).body
    assert '"role"' not in u and json.loads(u)["role"] == "user"
    assert json.loads(X.apply_xforms(r, [X.Xform("json_raw", "bignum", "n")]).body)["qty"] == 0
