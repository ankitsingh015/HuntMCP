"""Spec 3a, Task 3: the per-request profiler and ranked variant plan."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M

H = "http://127.0.0.1:9000"
JSON_CT = {"Content-Type": "application/json"}


def put_profile(obj):
    return M.Req("r1", "PUT", H + "/api/v3/profile", dict(JSON_CT), json.dumps(obj), "json", "pass1-aborted")


def get(url, rid="r2"):
    return M.Req(rid, "GET", H + url, {}, None, "none", "get-sent")


def ctx(**kw):
    return M.Context(response_keys=kw.get("response_keys", {}), sibling_fields=kw.get("sibling_fields", {}),
                     foreign_ids=kw.get("foreign_ids", set()))


def fam(plan, family):
    return [v for v in plan if v.family == family]


def test_plan_prefers_response_only_fields():
    tmpl = H + "/api/v3/profile"
    plan = M.build_plan(put_profile({"display_name": "x"}),
                        ctx(response_keys={tmpl: {"id", "display_name", "role"}}))
    top = plan[0]
    assert top.family == "add" and top.ops[0].path == ("role",)
    assert "response" in top.reason and "role" in top.reason
    assert top.score == 90


def test_plan_sibling_fields_rank_below_response_fields():
    tmpl = H + "/api/v3/profile"
    plan = M.build_plan(put_profile({"display_name": "x"}),
                        ctx(response_keys={tmpl: {"role"}}, sibling_fields={tmpl: {"nickname"}}))
    adds = fam(plan, "add")
    names = [v.ops[0].path for v in adds]
    assert names.index(("role",)) < names.index(("nickname",))
    assert {v.ops[0].path: v.score for v in adds}[("nickname",)] == 70


def test_plan_priv_fields_seeded():
    plan = M.build_plan(put_profile({"display_name": "x"}), ctx())
    added = {v.ops[0].path[0] for v in fam(plan, "add")}
    assert {"role", "is_admin"} <= added


def test_plan_remove_check_fields_otp():
    r = M.Req("r1", "POST", H + "/api/v3/change-email", dict(JSON_CT),
              json.dumps({"email": "a@b.invalid", "otp": "123456"}), "json", "pass2-sent")
    rem = fam(M.build_plan(r, ctx()), "remove")
    kinds = {(v.ops[0].kind, json.dumps(v.ops[0].value)) for v in rem if v.ops[0].path == ("otp",)}
    assert ("remove_param", "null") in kinds          # key gone
    assert ("set_param", '""') in kinds               # empty value
    assert ("set_param", "null") in kinds             # key present, value null
    assert all(v.score >= 80 for v in rem if v.ops[0].path == ("otp",))


def test_plan_withheld_field_only_remove():
    r = M.Req("r1", "POST", H + "/api/login-ish", dict(JSON_CT),
              json.dumps({"user": "a", "password": M.WITHHELD}), "json", "pass1-aborted")
    plan = M.build_plan(r, ctx())
    touching = [v for v in plan if any(op.path == ("password",) for op in v.ops)]
    assert touching and all(v.family == "remove" for v in touching)
    assert all(op.value != M.WITHHELD for v in plan for op in v.ops)


def test_plan_caps_per_family_and_total():
    obj = {f"f{i}": "v" for i in range(30)}
    plan = M.build_plan(put_profile(obj), ctx(), max_variants=25, max_per_family=4)
    assert len(plan) <= 25
    for f in ("add", "remove", "duplicate", "retype", "numeric-edge"):
        assert len(fam(plan, f)) <= 4


def test_plan_numeric_edges_only_for_numbers():
    r = put_profile({"qty": 2, "name": "x"})
    edges = fam(M.build_plan(r, ctx(), max_per_family=20), "numeric-edge")
    assert edges and all(v.ops[0].path == ("qty",) for v in edges)
    assert {json.dumps(v.ops[0].value) for v in edges} >= {"-1", "0", "2147483648"}


def test_plan_ids_are_stable():
    a = [v.variant_id for v in M.build_plan(put_profile({"display_name": "x"}), ctx())]
    b = [v.variant_id for v in M.build_plan(put_profile({"display_name": "x"}), ctx())]
    assert a == b and len(set(a)) == len(a) and all(len(i) == 12 for i in a)


def test_plan_sorted_by_score():
    plan = M.build_plan(put_profile({"display_name": "x", "otp": "1"}), ctx())
    scores = [v.score for v in plan]
    assert scores == sorted(scores, reverse=True)


def test_plan_no_variants_for_unparsed_body_except_query():
    r = M.Req("r1", "POST", H + "/api/up?id=5", {"Content-Type": "application/octet-stream"},
              "\x00\x01", "unparsed", "pass1-aborted")
    plan = M.build_plan(r, ctx())
    assert plan and all(op.location == "query" for v in plan for op in v.ops)


def test_plan_duplicate_query_both_orders():
    plan = M.build_plan(get("/api/v3/transfer-preview?to=u-1001"), ctx(foreign_ids={"u-2002"}))
    dups = [v for v in fam(plan, "duplicate") if v.ops[0].path == ("to",)]
    assert {v.ops[0].order for v in dups} >= {"orig_first", "new_first"}
    assert any(v.ops[0].value == "u-2002" for v in dups)


def test_plan_retype_query_array_form():
    plan = M.build_plan(get("/api/v3/promo-check?code=WELCOME0"), ctx())
    rt = [v for v in fam(plan, "retype") if v.ops[0].path == ("code",)]
    assert any(isinstance(v.ops[0].value, list) for v in rt)


def test_plan_foreign_ids_only_for_get():
    g = M.build_plan(get("/api/orders?user_id=u-1001"), ctx(foreign_ids={"u-2002"}))
    assert any(v.ops[0].kind == "set_param" and v.ops[0].value == "u-2002" for v in fam(g, "add"))
    p = M.build_plan(put_profile({"user_id": "u-1001"}), ctx(foreign_ids={"u-2002"}))
    assert all(op.value != "u-2002" for v in p for op in v.ops)
