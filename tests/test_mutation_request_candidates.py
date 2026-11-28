"""Spec 3b, Task 7: request-level candidate rules (leads, never confirmed)."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M  # noqa: E402
import mutation_xform as X  # noqa: E402

NZ = {"volatile": frozenset(), "length_tol": 32}


def resp(status, body=""):
    return M.resp_from(status, body if isinstance(body, str) else json.dumps(body))


def V(family, *xforms, ops=None):
    return M.Variant("v1", "r1", family, ops or [], "why", 50, xforms=list(xforms))


def cands(v, base, var, **kw):
    d = M.diff(base, var, NZ, [x.value for x in v.xforms if isinstance(x.value, str)])
    return X.request_candidates(v, base, var, d, **kw)


def types(cs):
    return [c["type"] for c in cs]


def test_header_candidate_403_to_200_only():
    v = V("header", X.Xform("set_header", "X-Forwarded-For", "127.0.0.1"))
    cs = cands(v, resp(403, {"error": "forbidden"}), resp(200, {"admin": True}))
    assert types(cs) == ["header-authz-bypass-candidate"]
    c = cs[0]
    assert c["family"] == "header" and c["origin"] == "rule" and c["persisted"] == "n/a"
    assert c["change"] == [{"op": "set_header", "field": "X-Forwarded-For", "value": "127.0.0.1"}]
    assert c["evidence"]["base_status"] == 403 and c["evidence"]["variant_status"] == 200


def test_header_no_candidate_when_403_stays():
    v = V("header", X.Xform("set_header", "X-Forwarded-For", "127.0.0.1"))
    assert cands(v, resp(403, "no"), resp(403, "no")) == []
    assert cands(v, resp(200, "ok"), resp(200, "ok")) == []
    assert cands(v, resp(403, "no"), resp(500, "boom")) == []


def test_header_original_url_candidate_when_a_different_resource_is_served():
    v = V("header", X.Xform("set_header", "X-Original-URL", "/api/v4/admin"))
    assert types(cands(v, resp(200, {"rows": 3}), resp(200, {"admin": True, "users": ["a", "b", "c", "d"] * 20}))) \
        == ["header-authz-bypass-candidate"]
    assert cands(v, resp(200, {"rows": 3}), resp(200, {"rows": 3})) == []


def test_method_candidate_head_swap():
    v = V("method", X.Xform("method", "", "HEAD"))
    assert types(cands(v, resp(403, "no"), resp(200, ""))) == ["method-override-candidate"]
    assert cands(v, resp(403, "no"), resp(403, "no")) == []
    assert cands(v, resp(200, "x"), resp(200, "x")) == []
    # non-GET: needs the change to persist
    nv = V("method", X.Xform("method", "", "POST"), X.Xform("override", "header:X-HTTP-Method-Override", "PUT"))
    assert types(cands(nv, resp(403, "no"), resp(200, "ok"), readback="persisted")) == ["method-override-candidate"]
    assert cands(nv, resp(403, "no"), resp(200, "ok"), readback="not-persisted") == []


def test_content_type_candidate_form_accepted_persisted():
    v = V("content-type", X.Xform("content_type", "", "form"))
    assert types(cands(v, resp(200, "ok"), resp(200, "ok"), readback="persisted")) == ["content-type-confusion-candidate"]
    assert types(cands(v, resp(200, "ok"), resp(200, "ok"), readback="not-persisted")) == [
        "content-type-confusion-candidate"]                      # form/text are the CSRF-relevant ones
    xv = V("content-type", X.Xform("content_type", "", "xml"))
    assert cands(xv, resp(200, "ok"), resp(200, "ok"), readback="not-persisted") == []
    assert types(cands(xv, resp(200, "ok"), resp(200, "ok"), readback="persisted")) == [
        "content-type-confusion-candidate"]


def test_content_type_no_candidate_when_415():
    v = V("content-type", X.Xform("content_type", "", "form"))
    assert cands(v, resp(200, "ok"), resp(415, {"error": "unsupported media type"})) == []
    assert cands(v, resp(400, "bad"), resp(200, "ok")) == []        # base was not a working request


def test_json_diff_candidate_when_single_rejected_dup_accepted():
    v = V("json-diff", ops=[M.Op("duplicate_param", "json", ("theme",), "evil")])
    assert types(cands(v, resp(200, "ok"), resp(200, "ok"), readback="persisted",
                       single_value_resp=resp(400, "bad theme"))) == ["json-parser-differential-candidate"]
    assert cands(v, resp(200, "ok"), resp(200, "ok"), readback="persisted",
                 single_value_resp=resp(200, "ok")) == []
    assert cands(v, resp(200, "ok"), resp(400, "bad"), single_value_resp=resp(400, "bad")) == []
    assert cands(v, resp(200, "ok"), resp(200, "ok")) == []


def test_path_candidate_403_to_200():
    v = V("path", X.Xform("path", "", "/api/v4/reports/"))
    assert types(cands(v, resp(403, "no"), resp(200, {"reports": [1]}))) == ["path-normalization-candidate"]
    assert cands(v, resp(403, "no"), resp(404, "nf")) == []
    assert cands(v, resp(200, "ok"), resp(200, "ok")) == []


def test_cache_poison_requires_followup_reflection():
    v = V("cache", X.Xform("cache_poison", "X-Forwarded-Host", "hm-cache.invalid"))
    base, var = resp(200, "<p>host: none</p>"), resp(200, "<p>host: hm-cache.invalid</p>")
    assert types(cands(v, base, var, followup=resp(200, "<p>host: hm-cache.invalid</p>"))) == [
        "cache-poisoning-candidate"]
    assert cands(v, base, var, followup=resp(200, "<p>host: none</p>")) == []
    assert cands(v, base, var) == []
    assert cands(v, base, var, followup=resp(500, "hm-cache.invalid")) == []
    assert cands(v, resp(200, "hm-cache.invalid"), var, followup=resp(200, "hm-cache.invalid")) == []   # already there


def test_cache_deception_requires_anon_equal_and_original_differs():
    v = V("cache", X.Xform("cache_deception", "", "/hm.css"))
    mine = resp(200, "<p>account u-1001</p>")
    other = resp(403, '{"error": "login required"}')
    assert types(cands(v, mine, mine, anon_variant=mine, anon_original=other)) == ["cache-deception-candidate"]
    assert cands(v, mine, mine, anon_variant=other, anon_original=other) == []
    assert cands(v, mine, mine, anon_variant=mine, anon_original=mine) == []     # a public page, not private data
    assert cands(v, mine, mine) == []
    assert cands(v, mine, resp(404, "nf"), anon_variant=mine, anon_original=other) == []


def test_race_candidate_needs_two_ok_and_not_idempotent():
    v = V("race", X.Xform("race", "", None, 5))
    r = {"n": 5, "ok": 4, "statuses": {"200": 4, "409": 1}, "idempotent": False}
    assert types(cands(v, resp(200, "ok"), resp(200, "ok"), readback="persisted", race=r)) == ["race-candidate"]
    c = cands(v, resp(200, "ok"), resp(200, "ok"), readback="persisted", race=r)[0]
    assert c["evidence"]["race"] == r
    assert cands(v, resp(200, "ok"), resp(200, "ok"), readback="persisted", race={**r, "ok": 1}) == []
    assert cands(v, resp(200, "ok"), resp(200, "ok"), readback="persisted", race={**r, "idempotent": True}) == []
    assert cands(v, resp(200, "ok"), resp(200, "ok"), readback="not-persisted", race=r) == []


def test_candidate_evidence_redacts_recorded_values():
    v = V("header", X.Xform("set_header", "X-Forwarded-For", "127.0.0.1"))
    secret = "SuperSecretRecordedValue"
    var = resp(200, f'{{"admin": true, "note": "{secret}"}}')
    cs = cands(v, resp(403, '{"error": "forbidden"}'), var, recorded_values=[secret])
    assert cs and secret not in json.dumps(cs)
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"
    leak = resp(200, '{"session": "%s", "admin": true}' % jwt)
    assert jwt not in json.dumps(cands(v, resp(403, "no"), leak))
