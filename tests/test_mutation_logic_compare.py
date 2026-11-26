"""Spec 3a, Task 5: noise, diff and candidate rules (leads only)."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M


def resp(status, obj=None, text=None):
    body = text if text is not None else json.dumps(obj if obj is not None else {})
    return M.resp_from(status, body)


def var(family, path=("role",), value="admin", kind="add_param"):
    op = M.Op(kind, "json", path, value)
    return M.Variant("v1", "r1", family, [op], "why", 50)


NO_NOISE = {"volatile": frozenset(), "length_tol": 32}


def test_resp_from_keys():
    r = resp(200, {"a": 1, "b": {"c": 2}})
    assert r.status == 200 and r.json_keys == frozenset({"a", "b"}) and r.length == len(r.body)
    assert resp(200, text="<html>").json_keys is None


def test_noise_masks_timestamp_fields():
    b1 = resp(200, {"id": 1, "ts": "2026-01-01T00:00:01", "name": "x"})
    b2 = resp(200, {"id": 1, "ts": "2026-01-01T00:00:02", "name": "x"})
    n = M.noise(b1, b2)
    assert any("ts" in p for p in n["volatile"]) and n["length_tol"] >= 32
    d = M.diff(b1, resp(200, {"id": 1, "ts": "2026-01-01T00:00:09", "name": "x"}), n, [])
    assert not d.status_changed and not d.significant_length and not d.keys_added


def test_diff_status_class_keys_reflection_error():
    d = M.diff(resp(403, {"error": "no"}), resp(200, {"ok": True, "role": "admin"}), NO_NOISE, ["admin"])
    assert d.status_changed and d.class_change == "4xx->2xx" and "role" in d.keys_added and d.reflected
    d = M.diff(resp(200, {}), resp(500, text="Traceback (most recent call last):"), NO_NOISE, [])
    assert d.error_signature


def test_mass_assignment_persisted():
    c = M.candidates_for(var("add"), resp(200, {"ok": True}), resp(200, {"ok": True}),
                         M.diff(resp(200, {"ok": True}), resp(200, {"ok": True}), NO_NOISE, ["admin"]),
                         readback="persisted")
    assert [x["type"] for x in c] == ["mass-assignment-candidate"] and c[0]["persisted"] is True


def test_mass_assignment_not_persisted_no_candidate():
    b, v = resp(200, {"ok": True}), resp(200, {"ok": True})
    assert M.candidates_for(var("add"), b, v, M.diff(b, v, NO_NOISE, ["admin"]), readback="not-persisted") == []


def test_reflection_without_readback_is_not_persisted():
    b, v = resp(200, {"ok": True}), resp(200, {"ok": True, "role": "admin"})
    d = M.diff(b, v, NO_NOISE, ["admin"])
    assert M.candidates_for(var("add"), b, v, d, readback="not-persisted") == []
    c = M.candidates_for(var("add"), b, v, d, readback="unknown")
    assert c and c[0]["persisted"] == "unknown" and c[0]["persisted"] is not True


def test_mass_assignment_rejected_variant_no_candidate():
    b, v = resp(200, {"ok": True}), resp(400, {"error": "unknown field role"})
    assert M.candidates_for(var("add"), b, v, M.diff(b, v, NO_NOISE, ["admin"]), readback="unknown") == []


def test_removal_bypass_positive_and_negative():
    vr = var("remove", ("otp",), None, "remove_param")
    b, v = resp(403, {"error": "bad code"}), resp(200, {"ok": True})
    c = M.candidates_for(vr, b, v, M.diff(b, v, NO_NOISE, []), readback="persisted")
    assert [x["type"] for x in c] == ["param-removal-bypass-candidate"]
    v2 = resp(403, {"error": "bad code"})
    assert M.candidates_for(vr, b, v2, M.diff(b, v2, NO_NOISE, []), readback="not-persisted") == []


def test_hpp_positive_and_negative():
    vd = var("duplicate", ("to",), "u-2002", "duplicate_param")
    base = resp(200, {"preview_for": "u-1001"})
    single = resp(403, {"error": "not your account"})
    hit = resp(200, {"preview_for": "u-2002"})
    c = M.candidates_for(vd, base, hit, M.diff(base, hit, NO_NOISE, ["u-2002"]), readback="n/a",
                         single_value_resp=single)
    assert [x["type"] for x in c] == ["hpp-candidate"]
    rej = resp(400, {"error": "duplicate to"})
    assert M.candidates_for(vd, base, rej, M.diff(base, rej, NO_NOISE, ["u-2002"]), readback="n/a",
                            single_value_resp=single) == []


def test_type_juggling_positive_and_negative():
    vt = var("retype", ("code",), ["x"], "retype_param")
    b, v = resp(403, {"valid": False}), resp(200, {"valid": True})
    assert [x["type"] for x in M.candidates_for(vt, b, v, M.diff(b, v, NO_NOISE, []), readback="n/a")] \
        == ["type-juggling-candidate"]
    v2 = resp(400, {"error": "bad code"})
    assert M.candidates_for(vt, b, v2, M.diff(b, v2, NO_NOISE, []), readback="n/a") == []


def test_numeric_edge_positive_and_negative():
    vn = var("numeric-edge", ("qty",), -1, "set_param")
    b = resp(200, {"ok": True})
    err = resp(500, text="ValueError: invalid literal")
    assert [x["type"] for x in M.candidates_for(vn, b, err, M.diff(b, err, NO_NOISE, []), readback="n/a")] \
        == ["numeric-edge-candidate"]
    ok = resp(200, {"ok": True})
    assert [x["type"] for x in M.candidates_for(vn, b, ok, M.diff(b, ok, NO_NOISE, []), readback="persisted")] \
        == ["numeric-edge-candidate"]
    assert M.candidates_for(vn, b, ok, M.diff(b, ok, NO_NOISE, []), readback="not-persisted") == []


def test_evidence_never_contains_recorded_values():
    vr = var("remove", ("otp",), None, "remove_param")
    b = resp(403, {"error": "bad code", "echo": "FIXTURESECRET9"})
    v = resp(200, {"ok": True, "token": "FIXTURESECRET9"})
    c = M.candidates_for(vr, b, v, M.diff(b, v, NO_NOISE, []), readback="persisted",
                         recorded_values=["FIXTURESECRET9"])
    assert c and "FIXTURESECRET9" not in json.dumps(c)
