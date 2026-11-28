"""Spec 3b, Task 6: GraphQL helpers (pure): kind, aliasing, batching, candidate."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M  # noqa: E402
import mutation_xform as X  # noqa: E402
from ui_walk_grant import Grant  # noqa: E402

H = "http://127.0.0.1:9000"
JSON_H = {"Content-Type": "application/json"}
Q = "query Me { me { id display_name } }"


def G(query=Q, method="POST", body=None, url=H + "/api/v4/graphql", headers=None):
    b = body if body is not None else json.dumps({"query": query})
    h = {**JSON_H, **(headers or {})}
    return M.Req("g1", method, url, h, b, M.body_kind_of(h, b), "x")


def test_graphql_readonly_conservative():
    assert X.graphql_kind(G()) == "query"
    assert X.graphql_kind(G("{ me { id } }")) == "query"
    # mutations / subscriptions anywhere -> not a query
    assert X.graphql_kind(G('mutation { setName(name: "x") { id } }')) == "mutation"
    assert X.graphql_kind(G("subscription { s { id } }")) == "mutation"
    assert X.graphql_kind(G("query A { me { id } } mutation B { x { id } }")) == "mutation"
    assert X.graphql_kind(G('query { me(note: "mutation") { id } }')) == "mutation"        # hidden in a string
    assert X.graphql_kind(G("query { me { id } } # mutation later")) == "mutation"         # hidden in a comment
    assert X.graphql_kind(G("query { me { id } ")) == "mutation"                            # unbalanced -> conservative
    # a batch is read-only only when EVERY element is a query
    two = json.dumps([{"query": Q}, {"query": Q}])
    assert X.graphql_kind(G(body=two)) == "query"
    mixed = json.dumps([{"query": Q}, {"query": "mutation { x { id } }"}])
    assert X.graphql_kind(G(body=mixed)) == "mutation"
    # GET / PUT / override voids "query" for the gate's read-only exemption
    assert X.graphql_kind(G(headers={"X-HTTP-Method-Override": "DELETE"})) == "mutation"
    assert X.graphql_kind(G(method="PUT")) == "mutation"


def test_graphql_kind_detects_non_graphql_json_as_none():
    assert X.graphql_kind(G(body=json.dumps({"display_name": "x"}), url=H + "/api/v3/profile")) is None
    assert X.graphql_kind(G(body="not json")) is None
    assert X.graphql_kind(G(body=json.dumps({"query": "search term"}), url=H + "/api/search")) is None
    assert X.graphql_kind(M.Req("g", "GET", H + "/x", {}, None, "none", "x")) is None
    assert X.graphql_kind(G(body=json.dumps({"query": "x { y }", "foo": 1}), url=H + "/api/z")) is None
    assert X.graphql_kind(G(body=json.dumps({"query": Q, "operationName": "Me"}), url=H + "/api/z")) == "query"


def test_alias_query_single_field_n_copies():
    out = X.alias_query(Q, 3)
    assert out.startswith("query Me {") and out.count("{ id display_name }") == 3
    assert "hmA1: me" in out and "hmA2: me" in out and "hmA3: me" in out
    assert X.alias_query("{ me { id } }", 2).count("me {") == 2
    assert X.alias_query("query { x: me(id: 1) @include(if: true) { id } }", 2).count("hmA") == 2
    assert "x:" not in X.alias_query("query { x: me { id } }", 2)                 # the old alias is replaced


def test_alias_query_skips_multi_field_and_braces_in_strings():
    assert X.alias_query("query { me { id } other { id } }", 3) is None            # more than one top-level field
    assert X.alias_query("query { ...F } fragment F on Q { me { id } }", 3) is None
    assert X.alias_query("query { me { id } ", 3) is None                           # unbalanced
    out = X.alias_query('query { me(note: "a { b } c") { id } }', 2)
    assert out is not None and out.count('"a { b } c"') == 2
    assert X.alias_query("query { me { id } } # { not a brace", 2) is not None


def test_array_batch_body_and_graphql_body():
    arr = json.loads(X.graphql_body(G(), "array", 3))
    assert isinstance(arr, list) and len(arr) == 3 and all(a == {"query": Q} for a in arr)
    al = json.loads(X.graphql_body(G(), "alias", 2))
    assert al["query"].count("hmA") == 2
    assert X.graphql_body(G(body=json.dumps([{"query": Q}])), "array", 2) is None
    assert X.graphql_body(G(query="query { a { id } b { id } }"), "alias", 2) is None
    out = X.apply_xforms(G(), [X.Xform("graphql", "array", None, 4)])
    assert len(json.loads(out.body)) == 4 and out.body_kind == "json"


def test_graphql_variants_for_query_and_mutation_requests():
    vs = X.build_request_plan(G(), M.Context(), {}, graphql=True)
    gv = [v for v in vs if v.family == "graphql"]
    assert {(x.name, x.n) for v in gv for x in v.xforms} == {("alias", 3), ("alias", 5), ("array", 2), ("array", 5)}
    assert all(v.reason for v in gv)
    mv = X.build_request_plan(G('mutation { setName(name: "x") { id } }'), M.Context(), {}, graphql=True)
    assert [v for v in mv if v.family == "graphql"]            # planned; the gate holds them
    assert not [v for v in X.build_request_plan(G(body=json.dumps({"a": 1}), url=H + "/api/v3/x"), M.Context(), {},
                                                graphql=True) if v.family == "graphql"]
    # a batch/alias variant of a query stays read-only for the gate; of a mutation it does not
    for v in gv:
        r = X.apply_xforms(G(), v.xforms)
        assert X.graphql_kind(r) == "query"
    g = M.gate(X.apply_xforms(G(), gv[0].xforms), scope=lambda u: u.startswith(H), grant=None,
               owned=M.Ownership(False, "none", ""), has_restore_path=False, never_mutated=False,
               graphql_readonly=True)
    assert g.send and not g.needs_grant
    m = X.apply_xforms(G('mutation { setName(name: "x") { id } }'), [X.Xform("graphql", "alias", None, 3)]) \
        if X.alias_query('mutation { setName(name: "x") { id } }', 3) else None
    assert m is None or X.graphql_kind(m) == "mutation"
    mg = M.gate(M.Req("g", "POST", H + "/api/v4/graphql", JSON_H, '{"query": "mutation { x { id } }"}', "json", "x"),
                scope=lambda u: u.startswith(H), grant=Grant(canary_submit=True),
                owned=M.Ownership(False, "none", ""), has_restore_path=True, never_mutated=False)
    assert not mg.send and mg.reason == "not-owned"


def test_agent_graphql_batch_op_valid_only_on_graphql_requests():
    known = {"g1": G(), "p1": M.Req("p1", "PUT", H + "/api/v3/profile", JSON_H, '{"a": 1}', "json", "x")}
    vs, errs = X.validate_request_ops([{"replay_id": "g1", "op": "graphql_batch", "n": 3, "mode": "alias"}], known)
    assert vs and not errs and vs[0].family == "graphql" and vs[0].xforms[0].n == 3
    vs, errs = X.validate_request_ops([{"replay_id": "p1", "op": "graphql_batch", "n": 3, "mode": "alias"}], known)
    assert not vs and "not a GraphQL request" in errs[0]


def _resp(status, obj):
    return M.resp_from(status, json.dumps(obj))


def test_graphql_candidate_only_when_all_n_succeed():
    v = M.Variant("v1", "g1", "graphql", [], "r", 60, xforms=[X.Xform("graphql", "alias", None, 3)])
    base = _resp(200, {"data": {"me": {"id": "u-1001"}}})
    full = _resp(200, {"data": {f"hmA{i}": {"id": "u-1001"} for i in (1, 2, 3)}})
    c = X.graphql_candidate(v, "alias", 3, base, full)
    assert c and c["type"] == "graphql-batching-candidate" and c["evidence"]["answered"] == 3
    assert "u-1001" not in json.dumps(c)
    part = _resp(200, {"data": {"hmA1": {"id": "u-1001"}}})
    assert X.graphql_candidate(v, "alias", 3, base, part) is None
    va = M.Variant("v2", "g1", "graphql", [], "r", 60, xforms=[X.Xform("graphql", "array", None, 2)])
    arr = _resp(200, [{"data": {"me": {"id": "u-1001"}}}, {"data": {"me": {"id": "u-1001"}}}])
    arr = M.resp_from(200, json.dumps([{"data": {"me": {"id": "u"}}}, {"data": {"me": {"id": "u"}}}]))
    assert X.graphql_candidate(va, "array", 2, base, arr)["evidence"]["answered"] == 2


def test_graphql_candidate_none_on_alias_limit_error():
    v = M.Variant("v1", "g1", "graphql", [], "r", 60, xforms=[X.Xform("graphql", "alias", None, 3)])
    base = _resp(200, {"data": {"me": {"id": "u"}}})
    assert X.graphql_candidate(v, "alias", 3, base, _resp(200, {"errors": [{"message": "alias limit"}]})) is None
    assert X.graphql_candidate(v, "alias", 3, base, M.resp_from(400, '{"error": "batching disabled"}')) is None
    assert X.graphql_candidate(v, "alias", 3, _resp(500, {}), _resp(200, {"data": {"hmA1": {}, "hmA2": {},
                                                                                      "hmA3": {}}})) is None


# -- review fixes ------------------------------------------------------------------
def test_graphql_duplicate_query_key_is_never_readonly():
    """json.loads keeps the LAST duplicate; another parser keeps the FIRST -- so any
    duplicate key in a GraphQL body means 'could be a mutation'."""
    mut, q = "mutation { x { id } }", "{ me { id } }"
    for body in ('{"query": "%s", "query": "%s"}' % (mut, q), '{"query": "%s", "query": "%s"}' % (q, mut),
                 '[{"query": "%s", "query": "%s"}]' % (mut, q),
                 '{"query": "%s", "variables": {"a": 1, "a": 2}}' % q):
        assert X.graphql_kind(G(body=body)) == "mutation", body
    assert X.graphql_kind(G(body='{"query": "%s", "variables": {"a": 1}}' % q)) == "query"
    # the raw text is scanned too (escapes of the keyword in a dropped duplicate)
    assert X.graphql_kind(G(body='{"query": "mutation { x { id } }", "q\\u0075ery": "%s"}' % q)) == "mutation"


def test_json_dup_variant_of_a_recorded_mutation_is_not_readonly_for_the_gate():
    from mutation_runner import gate_variant
    mut = G('mutation { x { id } }')
    dup = X.apply_xforms(mut, [])
    dup = M.apply_ops(dup, [M.Op("duplicate_param", "json", ("query",), "hm-dup", order="orig_first")])
    assert X.graphql_kind(dup) == "mutation"
    # and even for a variant that LOOKS read-only, a non-GET entry's variants never get the exemption
    ro = G()
    g = gate_variant(ro, None, scope=lambda u: u.startswith(H), grant=None, owned=M.Ownership(False, "none", ""),
                     restore=False, never=False, readonly_ok=False)
    assert not g.send and g.needs_grant
    g = gate_variant(ro, None, scope=lambda u: u.startswith(H), grant=None, owned=M.Ownership(False, "none", ""),
                     restore=False, never=False)
    assert g.send and not g.needs_grant
