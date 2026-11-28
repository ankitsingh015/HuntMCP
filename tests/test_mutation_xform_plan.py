"""Spec 3b, Task 4: the request-level profiler / ranked plan + waf data (pure)."""

import json
import os
import sys
from urllib.parse import urlsplit


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M  # noqa: E402
import mutation_xform as X  # noqa: E402

H = "http://127.0.0.1:9000"
JSON_H = {"Content-Type": "application/json"}
NON_GET = {"POST", "PUT", "PATCH", "DELETE"}


def R(url, method="GET", headers=None, body=None):
    h = headers or {}
    return M.Req("r1", method, url, h, body, M.body_kind_of(h, body), "x")


def plan(req, meta=None, ctx=None, **kw):
    return X.build_request_plan(req, ctx or M.Context(), meta or {}, **kw)


def fam(vs, f):
    return [v for v in vs if v.family == f]


def names(vs):
    return {x.name for v in vs for x in v.xforms if x.kind in ("set_header", "cache_poison")}


# -- waf data ----------------------------------------------------------------------
def test_waf_header_data_is_tier1_only_and_has_no_forbidden_names():
    data = X.waf_header_data()
    nm = {n.lower() for n, _ in data}
    assert {"x-forwarded-for", "x-real-ip", "x-client-ip", "true-client-ip", "forwarded"} <= nm
    assert len(data) == 9
    for bad in ("host", "cookie", "authorization", "content-length", "transfer-encoding", "user-agent"):
        assert bad not in nm
    assert not any(n.lower().startswith("proxy-") for n, _ in data)


def test_waf_data_never_references_tier3():
    mod = X._waf_module()
    calls = []

    def boom(*_a, **_k):
        calls.append(1)
        raise AssertionError("tier 3 / 4 must never be called")
    mod._tier3_variants = boom
    mod._tier4_variants = boom
    mod._TIER_BUILDERS["3"] = boom
    X.waf_header_data()
    X.waf_path_data(H + "/api/v4/reports?x=1")
    assert calls == []
    verbs = {"HEAD", "OPTIONS", "POST", "PUT", "PATCH", "TRACE", "CONNECT", "DELETE"}
    assert not (verbs & {label.split()[-1] for label, _ in X.waf_path_data(H + "/api/x")})


def test_waf_path_data_same_host_no_dangerous_forms():
    data = X.waf_path_data(H + "/api/v4/reports?x=1")
    paths = [p for _, p in data]
    assert "/api/v4/reports/" in paths and "/API/V4/REPORTS" in paths and "/api/v4/reports;.css" in paths
    assert all(p.startswith("/") and "?" not in p and "#" not in p and "\x00" not in p for p in paths)
    assert not any(p.endswith("/../") or "%00" in p for p in paths)


def test_path_transform_fixed_names():
    u = H + "/api/v4/reports?x=1"
    assert X.path_transform(u, "trailing-slash") == "/api/v4/reports/"
    assert X.path_transform(u, "trailing-dot") == "/api/v4/reports/."
    assert X.path_transform(u, "semicolon-css") == "/api/v4/reports;.css"
    assert X.path_transform(u, "uppercase") == "/API/V4/REPORTS"
    assert X.path_transform(u, "encode-slash") == "/api%2fv4/reports"
    assert X.path_transform(u, "double-encode").startswith("/%2561")
    assert X.path_transform(u, "dot-segment") == "/api/v4/./reports"
    assert X.path_transform(u, "nope") is None
    assert set(X.PATH_TRANSFORMS) == {"trailing-slash", "trailing-dot", "semicolon-css", "encode-slash",
                                      "uppercase", "double-encode", "dot-segment"}


# -- header family ------------------------------------------------------------------
def test_header_family_chosen_for_403_not_for_plain_200():
    denied = plan(R(H + "/api/v4/admin"), {"status": 403})
    hv = fam(denied, "header")
    assert hv and {"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Host"} <= names(hv)
    assert all(v.score >= 70 for v in hv) and max(v.score for v in hv) >= 80 and all(v.reason for v in hv)
    assert "403" in hv[0].reason
    assert not fam(plan(R(H + "/api/v4/export"), {"status": 200}), "header")
    assert fam(plan(R(H + "/api/v4/export"), {"status": 200, "proxy_signals": ["via"]}), "header")
    assert fam(plan(R(H + "/internal/stats"), {"status": 200}), "header")      # admin-ish path


def test_header_family_includes_original_url_with_denied_path_only_for_get():
    ctx = M.Context(denied_paths={"/api/v4/admin"})
    g = plan(R(H + "/api/v4/export"), {"status": 403}, ctx)
    ou = [x for v in fam(g, "header") for x in v.xforms if x.name in ("X-Original-URL", "X-Rewrite-URL")]
    assert {x.name for x in ou} == {"X-Original-URL", "X-Rewrite-URL"} and all(x.value == "/api/v4/admin" for x in ou)
    p = plan(R(H + "/api/v4/export", "POST", JSON_H, "{}"), {"status": 403}, ctx)
    assert not [x for v in fam(p, "header") for x in v.xforms if x.name in ("X-Original-URL", "X-Rewrite-URL")]
    own = plan(R(H + "/api/v4/admin"), {"status": 403}, ctx)           # never points at itself
    assert not [x for v in fam(own, "header") for x in v.xforms if x.name == "X-Original-URL"]


# -- method family -----------------------------------------------------------------
def test_method_family_get_vs_nonget_forms():
    g = fam(plan(R(H + "/api/v4/export-acl"), {"status": 403}), "method")
    kinds = {(x.kind, x.name, x.value) for v in g for x in v.xforms}
    assert ("method", "", "HEAD") in kinds
    assert ("override", "header:X-HTTP-Method-Override", "HEAD") in kinds
    assert ("override", "param:_method", "HEAD") in kinds
    assert any(x.kind == "override" and x.value == "DELETE" for v in g for x in v.xforms)   # gated later
    assert all(v.score >= 65 for v in g) and max(v.score for v in g) >= 75
    p = fam(plan(R(H + "/api/v3/profile", "PUT", JSON_H, '{"a": 1}'), {"status": 200}), "method")
    pk = {(x.kind, x.name, x.value) for v in p for x in v.xforms}
    assert ("override", "header:X-HTTP-Method-Override", "PUT") in pk
    assert ("method", "", "POST") in pk
    assert not any(x.value == "HEAD" for v in p for x in v.xforms)


# -- content type, json diff --------------------------------------------------------
def test_content_type_family_only_for_body_requests():
    body = json.dumps({"display_name": "x"})
    ct = fam(plan(R(H + "/api/v3/profile", "PUT", JSON_H, body)), "content-type")
    assert {x.value for v in ct for x in v.xforms} == {"form", "text", "xml"}
    assert not fam(plan(R(H + "/api/v4/export")), "content-type")
    assert not fam(plan(R(H + "/api/x", "POST", {"Content-Type": "text/plain"}, "hello")), "content-type")
    f = fam(plan(R(H + "/api/x", "POST", {"Content-Type": "application/x-www-form-urlencoded"}, "a=1")),
            "content-type")
    assert {x.value for v in f for x in v.xforms} == {"json"}


def test_json_diff_only_for_json_with_scalar():
    jd = fam(plan(R(H + "/api/v4/preferences", "PUT", JSON_H, '{"theme": "dark"}')), "json-diff")
    kinds = {x.name for v in jd for x in v.xforms} | {o.kind for v in jd for o in v.ops}
    assert "duplicate_param" in kinds and {"unicode_key", "trailing_comma", "comment"} <= kinds
    dup = [v for v in jd if v.ops][0]
    assert dup.ops[0].location == "json" and dup.ops[0].value != "dark"
    assert not fam(plan(R(H + "/api/x", "PUT", JSON_H, "[1, 2]")), "json-diff")
    assert not fam(plan(R(H + "/api/x", "POST", {"Content-Type": "application/x-www-form-urlencoded"}, "a=1")),
                   "json-diff")
    big = fam(plan(R(H + "/api/x", "PUT", JSON_H, '{"qty": 3}')), "json-diff")
    assert any(x.name == "bignum" for v in big for x in v.xforms)


# -- path ---------------------------------------------------------------------------
def test_path_family_cap_six_and_same_host():
    pv = fam(plan(R(H + "/api/v4/reports?x=1"), {"status": 403}), "path")
    assert 1 <= len(pv) <= 6 and all(v.score >= 70 for v in pv)
    for v in pv:
        out = X.apply_xforms(R(H + "/api/v4/reports?x=1"), v.xforms)
        assert urlsplit(out.url).netloc == urlsplit(H).netloc and urlsplit(out.url).query == "x=1"
    assert not fam(plan(R(H + "/api/v3/profile", "PUT", JSON_H, "{}")), "path")


# -- cache --------------------------------------------------------------------------
def test_cache_family_requires_cache_signal_and_every_variant_marked_cache():
    assert not fam(plan(R(H + "/v4/page?lang=en"), {"status": 200}), "cache")
    cv = fam(plan(R(H + "/v4/page?lang=en"), {"status": 200, "cache_signals": ["age", "x-cache"]}), "cache")
    kinds = {x.kind for v in cv for x in v.xforms}
    assert kinds == {"cache_poison", "cache_deception"}
    assert {"X-Forwarded-Host", "X-Host", "X-Forwarded-Proto"} <= {x.name for v in cv for x in v.xforms
                                                                   if x.kind == "cache_poison"}
    assert all("age" in v.reason or "x-cache" in v.reason for v in cv)
    assert not fam(plan(R(H + "/x", "POST", JSON_H, "{}"), {"cache_signals": ["age"]}), "cache")
    # an authenticated HTML page without cache headers still gets the deception check (only)
    html = fam(plan(R(H + "/v4/account-page?tab=1"), {"status": 200, "content_type": "text/html"}), "cache")
    assert [x.kind for v in html for x in v.xforms] == ["cache_deception"]
    assert not fam(plan(R(H + "/api/v4/export"), {"status": 200, "content_type": "application/json"}), "cache")


# -- race ---------------------------------------------------------------------------
def test_race_family_only_for_racey_names_and_create_n_is_three():
    rv = fam(plan(R(H + "/api/v4/coupons/c-1/redeem", "POST", JSON_H, "{}")), "race")
    assert len(rv) == 1 and rv[0].xforms[0].kind == "race" and rv[0].xforms[0].n == 5
    cv = fam(plan(R(H + "/api/v4/coupons", "POST", JSON_H, "{}"), is_create=True), "race")
    assert len(cv) == 1 and cv[0].xforms[0].n == 3
    assert not fam(plan(R(H + "/api/v3/profile", "PUT", JSON_H, '{"a": 1}')), "race")
    assert not fam(plan(R(H + "/api/v4/coupons/c-1/redeem")), "race")                # GET


# -- merge --------------------------------------------------------------------------
def test_merge_caps_per_family_and_total_and_dedupes():
    vs = plan(R(H + "/api/v4/admin"), {"status": 403, "proxy_signals": ["via"]})
    merged = X.merge_plans([], vs, max_variants=40, max_per_family=3)
    assert all(sum(1 for v in merged if v.family == f) <= 3 for f in {v.family for v in merged})
    assert len({v.variant_id for v in merged}) == len(merged)
    twice = X.merge_plans(vs, vs, max_variants=5, max_per_family=10)
    assert len(twice) == 5 and [v.score for v in twice] == sorted((v.score for v in twice), reverse=True)
    a3 = M.build_plan(R(H + "/api/v3/profile?x=1", "PUT", JSON_H, '{"display_name": "x"}'), M.Context())
    both = X.merge_plans(a3, vs, max_variants=40, max_per_family=10)
    assert {v.family for v in both} >= {"add", "header"}


def test_every_variant_has_reason_and_stable_id():
    req = R(H + "/api/v4/admin")
    a, b = plan(req, {"status": 403}), plan(req, {"status": 403})
    assert [v.variant_id for v in a] == [v.variant_id for v in b]
    assert len({v.variant_id for v in a}) == len(a)
    assert all(v.reason and v.origin == "rule" and v.replay_id == "r1" for v in a)
    assert all(v.family in X.REQUEST_FAMILIES for v in a)
