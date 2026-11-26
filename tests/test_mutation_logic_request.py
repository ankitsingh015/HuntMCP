"""Spec 3a, Task 2: request model -- parse params, apply ops, effective method."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M


def _req(method="GET", url="http://127.0.0.1/api/x", headers=None, body=None, kind=None):
    return M.Req(replay_id="r1", method=method, url=url, headers=headers or {}, body=body,
                 body_kind=kind if kind else M.body_kind_of(headers or {}, body), source="get-sent")


def _names(params):
    return [(p.location, p.path) for p in params]


def test_parse_query_keeps_repeats_and_order():
    ps = M.parse_params(_req(url="http://h/a?b=1&a=2&b=3"))
    assert _names(ps) == [("query", ("b",)), ("query", ("a",)), ("query", ("b",))]
    assert [p.value for p in ps] == ["1", "2", "3"]


def test_parse_json_nested_paths():
    r = _req("PUT", headers={"Content-Type": "application/json"},
             body=json.dumps({"a": {"b": 1}, "c": [{"d": 2}]}))
    assert r.body_kind == "json"
    ps = M.parse_params(r)
    assert ("json", ("a", "b")) in _names(ps) and ("json", ("c", 0, "d")) in _names(ps)
    assert {p.path: p.value for p in ps}[("a", "b")] == 1


def test_parse_form_and_multipart_text_only():
    r = _req("POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, body="x=1&y=two")
    assert r.body_kind == "form" and _names(M.parse_params(r)) == [("form", ("x",)), ("form", ("y",))]
    mp = ("--BND\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n"
          "--BND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
          "Content-Type: text/plain\r\n\r\nFILEDATA\r\n--BND--\r\n")
    r = _req("POST", headers={"Content-Type": "multipart/form-data; boundary=BND"}, body=mp)
    assert r.body_kind == "multipart"
    ps = M.parse_params(r)
    assert _names(ps) == [("multipart", ("title",))] and ps[0].value == "hello"


def test_parse_unparseable_body_keeps_query_variants():
    r = _req("POST", url="http://h/u?q=1", headers={"Content-Type": "application/octet-stream"},
             body="\x00\x01garbage")
    assert r.body_kind == "unparsed"
    assert _names(M.parse_params(r)) == [("query", ("q",))]


def test_withheld_value_marked():
    r = _req("POST", headers={"Content-Type": "application/json"},
             body=json.dumps({"otp": M.WITHHELD, "email": "a@b.c"}))
    ps = {p.path: p for p in M.parse_params(r)}
    assert ps[("otp",)].withheld is True and ps[("email",)].withheld is False


def _json_req(obj):
    return _req("PUT", headers={"Content-Type": "application/json"}, body=json.dumps(obj))


def test_apply_add_json_top_level():
    out = M.apply_ops(_json_req({"display_name": "x"}), [M.Op("add_param", "json", ("role",), "admin")])
    assert json.loads(out.body) == {"display_name": "x", "role": "admin"}


def test_apply_add_query_and_form():
    out = M.apply_ops(_req(url="http://h/a?x=1"), [M.Op("add_param", "query", ("admin",), "true")])
    assert out.url == "http://h/a?x=1&admin=true"
    f = _req("POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, body="x=1")
    assert M.apply_ops(f, [M.Op("add_param", "form", ("role",), "admin")]).body == "x=1&role=admin"


def test_apply_remove_nested():
    out = M.apply_ops(_json_req({"a": {"b": 1, "c": 2}}), [M.Op("remove_param", "json", ("a", "b"))])
    assert json.loads(out.body) == {"a": {"c": 2}}


def test_apply_remove_query_all_copies():
    out = M.apply_ops(_req(url="http://h/a?otp=1&x=2&otp=3"), [M.Op("remove_param", "query", ("otp",))])
    assert out.url == "http://h/a?x=2"


def test_apply_set_param_null_and_empty():
    out = M.apply_ops(_json_req({"otp": "1"}), [M.Op("set_param", "json", ("otp",), None)])
    assert json.loads(out.body) == {"otp": None}
    out = M.apply_ops(_req(url="http://h/a?otp=1"), [M.Op("set_param", "query", ("otp",), "")])
    assert out.url == "http://h/a?otp="


def test_apply_duplicate_query_orders():
    r = _req(url="http://h/a?a=1")
    assert M.apply_ops(r, [M.Op("duplicate_param", "query", ("a",), "2")]).url == "http://h/a?a=1&a=2"
    assert M.apply_ops(r, [M.Op("duplicate_param", "query", ("a",), "2", order="new_first")]).url \
        == "http://h/a?a=2&a=1"


def test_apply_duplicate_json_raw_keys():
    out = M.apply_ops(_json_req({"role": "user", "n": 1}), [M.Op("duplicate_param", "json", ("role",), "admin")])
    assert out.body.count('"role"') == 2
    assert out.body.index('"user"') < out.body.index('"admin"')


def test_apply_duplicate_brackets_form():
    f = _req("POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, body="a=1&z=0")
    out = M.apply_ops(f, [M.Op("duplicate_param", "form", ("a",), "2", style="brackets")])
    assert out.body == "a%5B%5D=1&a%5B%5D=2&z=0"


def test_apply_retype_each_type():
    base = _json_req({"code": "abc"})
    for v in (1, [1], {"a": 1}, None, True):
        out = M.apply_ops(base, [M.Op("retype_param", "json", ("code",), v)])
        assert json.loads(out.body) == {"code": v}
    out = M.apply_ops(_req(url="http://h/p?code=X"), [M.Op("retype_param", "query", ("code",), ["X"])])
    assert out.url == "http://h/p?code%5B%5D=X"


def test_apply_multipart_rebuilds_with_boundary():
    mp = "--BND\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--BND--\r\n"
    r = _req("POST", headers={"Content-Type": "multipart/form-data; boundary=BND"}, body=mp)
    out = M.apply_ops(r, [M.Op("add_param", "multipart", ("role",), "admin")])
    assert out.body.startswith("--BND\r\n") and 'name="role"' in out.body and "admin" in out.body
    assert [p.path for p in M.parse_params(out)] == [("title",), ("role",)]


def test_apply_does_not_mutate_input():
    r = _json_req({"a": 1})
    before = (r.url, r.body, dict(r.headers))
    M.apply_ops(r, [M.Op("add_param", "json", ("b",), 2)])
    assert (r.url, r.body, dict(r.headers)) == before


def test_effective_method_override_header_and_param():
    assert M.effective_method(_req()) == "GET"
    assert M.effective_method(_req(url="http://h/a?_method=delete")) == "DELETE"
    assert M.effective_method(_req(headers={"X-HTTP-Method-Override": "put"})) == "PUT"
    assert M.effective_method(_req(headers={"x-method-override": "PATCH"})) == "PATCH"
    assert M.effective_method(_req(headers={"X-HTTP-Method": "DELETE"})) == "DELETE"
    f = _req("POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, body="_method=PUT")
    assert M.effective_method(f) == "PUT"
    assert M.effective_method(_json_req({"_method": "DELETE"})) == "DELETE"
