"""Spec 3b, Task 5: the agent's request-level ops, validated in code."""

import os
import sys
from urllib.parse import urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M  # noqa: E402
import mutation_xform as X  # noqa: E402
from ui_walk_grant import Grant  # noqa: E402

H = "http://127.0.0.1:9000"
JSON_H = {"Content-Type": "application/json", "X-Trace": "t1"}
KNOWN = {"r1": M.Req("r1", "GET", H + "/api/v4/reports?x=1", {"X-Trace": "t1"}, None, "none", "x"),
         "r2": M.Req("r2", "PUT", H + "/api/v3/profile", JSON_H, '{"display_name": "x"}', "json", "x")}


def ok(item):
    vs, errs = X.validate_request_ops([{"replay_id": "r1", **item}], KNOWN)
    return vs, errs


@pytest.mark.parametrize("name", ["Host", "host", "Cookie", "Authorization", "Proxy-Foo", "proxy-authorization",
                                  "Content-Length", "Transfer-Encoding", ":authority", "Bad Name", "A:B", ""])
def test_forbidden_headers_rejected(name):
    vs, errs = ok({"op": "set_header", "name": name, "value": "x"})
    assert not vs and errs and errs[0].startswith("#0")
    vs, errs = ok({"op": "remove_header", "name": name})
    assert not vs and errs


def test_crlf_nul_rejected_in_name_value_path():
    for bad in ("a\r\nX-Evil: 1", "a\nb", "a\x00b", "a\rb"):
        assert not ok({"op": "set_header", "name": "X-A", "value": bad})[0]
        assert not ok({"op": "set_header", "name": "X-A" + bad, "value": "v"})[0]
        assert not ok({"op": "path", "literal": "/x" + bad})[0]
        assert not ok({"op": "method", "method": "GET\r\nX: 1"})[0]


def test_value_over_2kb_rejected():
    assert not ok({"op": "set_header", "name": "X-A", "value": "a" * 2049})[0]
    assert ok({"op": "set_header", "name": "X-A", "value": "a" * 2048})[0]


@pytest.mark.parametrize("lit", ["//evil.example/x", "http://evil.example/", "/a?b", "/a#b", "x/y", "/a\\b",
                                 "/" + "a" * 600, "", "/a b"])
def test_path_literal_cannot_change_host(lit):
    assert not ok({"op": "path", "literal": lit})[0]


def test_path_literal_and_transform_ok_and_same_host():
    vs, _ = ok({"op": "path", "literal": "/api/v4/export"})
    assert vs
    out = X.apply_xforms(KNOWN["r1"], vs[0].xforms)
    assert urlsplit(out.url).netloc == urlsplit(H).netloc and urlsplit(out.url).path == "/api/v4/export"
    vs, _ = ok({"op": "path", "transform": "uppercase"})
    assert vs and vs[0].xforms[0].value == "/API/V4/REPORTS"
    assert not ok({"op": "path", "transform": "nope"})[0]
    assert not ok({"op": "path"})[0]


def test_method_trace_connect_rejected():
    for m in ("TRACE", "CONNECT", "get;x", "FOO"):
        assert not ok({"op": "method", "method": m})[0]
    assert ok({"op": "method", "method": "head"})[0][0].xforms[0].value == "HEAD"
    vs, _ = ok({"op": "method", "via": "header", "override": "PUT"})
    assert vs[0].xforms[0].kind == "override" and vs[0].xforms[0].value == "PUT"
    assert not ok({"op": "method", "via": "header", "override": "TRACE"})[0]
    assert not ok({"op": "method", "via": "header"})[0]
    assert not ok({"op": "method", "via": "wat", "method": "GET"})[0]


def test_valid_ops_become_agent_variants():
    raw = [{"replay_id": "r1", "op": "set_header", "name": "X-Forwarded-For", "value": "127.0.0.1", "reason": "r"},
           {"replay_id": "r1", "op": "remove_header", "name": "x-trace"},
           {"replay_id": "r1", "op": "method", "method": "HEAD"},
           {"replay_id": "r2", "op": "content_type", "to": "form"},
           {"replay_id": "r1", "op": "path", "transform": "trailing-slash"}]
    vs, errs = X.validate_request_ops(raw, KNOWN)
    assert not errs and len(vs) == 5
    assert [v.family for v in vs] == ["header", "header", "method", "content-type", "path"]
    assert all(v.origin == "agent" and v.score == 100 and v.reason.startswith("agent: ") for v in vs)
    assert len({v.variant_id for v in vs}) == 5
    assert not X.validate_request_ops([{"replay_id": "r1", "op": "remove_header", "name": "X-Nope"}], KNOWN)[0]
    assert not ok({"op": "content_type", "to": "yaml"})[0]
    assert not ok({"op": "graphql_batch", "n": 9, "mode": "alias"})[0]
    assert not ok({"op": "graphql_batch", "n": 3, "mode": "weird"})[0]


def test_unknown_replay_id_and_junk_rejected():
    vs, errs = X.validate_request_ops([{"replay_id": "zz", "op": "set_header", "name": "A", "value": "b"},
                                      "nope", {"replay_id": "r1", "op": "format_disk"}], KNOWN)
    assert not vs and len(errs) == 3
    assert "unknown replay_id" in errs[0] and "not an object" in errs[1] and "not available" in errs[2]
    assert all(len(e) < 200 for e in errs)
    vs, errs = X.validate_request_ops([{"replay_id": "r1", "op": "A" * 500}], KNOWN)
    assert len(errs[0]) < 200


def _gate(req, grant=None):
    return M.gate(req, scope=lambda u: u.startswith(H), grant=grant, owned=M.Ownership(False, "none", ""),
                  has_restore_path=False, never_mutated=False)


def test_agent_override_variant_still_gated_as_nonget():
    vs, _ = ok({"op": "method", "via": "header", "override": "DELETE"})
    r = X.apply_xforms(KNOWN["r1"], vs[0].xforms)
    g = _gate(r, Grant(canary_submit=True))
    assert not g.send and g.needs_grant and g.reason == "not-owned"
    assert not _gate(r).send


def test_agent_set_header_x_original_url_to_mutating_path_blocked_by_gate():
    vs, errs = ok({"op": "set_header", "name": "X-Original-URL", "value": "/api/account/delete"})
    assert vs and not errs                      # a legal header ...
    r = X.apply_xforms(KNOWN["r1"], vs[0].xforms)
    g = _gate(r)
    assert not g.send and g.reason == "routing-header-mutating"   # ... the gate stops it
    vs, _ = ok({"op": "set_header", "name": "X-HTTP-Method-Override", "value": "DELETE"})
    assert not _gate(X.apply_xforms(KNOWN["r1"], vs[0].xforms)).send


def test_agent_path_literal_to_logout_or_sso_endpoint_is_never_sent():
    """never-mutated is checked on the FINAL url, not only on the recorded entry's url."""
    for lit in ("/logout", "/oauth2/authorize", "/api/signout"):
        vs, errs = ok({"op": "path", "literal": lit})
        assert vs and not errs, lit
        r = X.apply_xforms(KNOWN["r1"], vs[0].xforms)
        g = _gate(r)
        assert not g.send and g.reason in ("never-mutated", "mutating-get"), (lit, g)
    assert _gate(X.apply_xforms(KNOWN["r1"], ok({"op": "path", "literal": "/api/v4/export"})[0][0].xforms)).send
