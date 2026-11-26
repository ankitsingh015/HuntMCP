"""Spec 3a, Task 4: send gates, ownership rule, agent-op validation."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import mutation_logic as M
from ui_walk_grant import Grant

H = "http://127.0.0.1:9000"
GRANT = Grant(canary_submit=True)
OWN = M.Ownership(True, "own-account", "test")
NOT_OWN = M.Ownership(False, "none", "test")


def scope(u):
    return u.startswith(H)


def g(url, method="GET", headers=None, body=None, grant=None, owned=NOT_OWN, restore=False, never=False):
    req = M.Req("r1", method, url, headers or {}, body, M.body_kind_of(headers or {}, body), "x")
    return M.gate(req, scope=scope, grant=grant, owned=owned, has_restore_path=restore, never_mutated=never)


def test_get_variant_sent_without_grant():
    r = g(H + "/api/v3/promo-check?code[]=x")
    assert r.send and not r.needs_grant and r.reason == "ok"


def test_get_with_method_param_needs_grant():
    r = g(H + "/api/v3/items?_method=DELETE")
    assert not r.send and r.needs_grant and r.reason == "needs grant"
    r = g(H + "/api/v3/items", headers={"X-HTTP-Method-Override": "PUT"})
    assert not r.send and r.needs_grant


def test_variant_url_mutating_word_blocked():
    r = g(H + "/api/v3/items?action=delete")
    assert not r.send and r.reason == "mutating-get"
    # not even a grant + ownership lets a mutating-looking GET through
    assert g(H + "/api/v3/items?action=delete", grant=GRANT, owned=OWN, restore=True).reason == "mutating-get"


def test_payment_host_never():
    for m in ("GET", "PUT"):
        r = g("https://api.stripe.com/v1/x", method=m, grant=GRANT, owned=OWN, restore=True)
        assert not r.send and r.reason == "payment-host"


def test_out_of_scope_never():
    r = g("http://other.invalid/api", grant=GRANT, owned=OWN, restore=True)
    assert not r.send and r.reason == "out-of-scope"


def test_non_get_needs_grant_and_owned():
    body = json.dumps({"display_name": "x"})
    hj = {"Content-Type": "application/json"}
    assert g(H + "/api/v3/profile", "PUT", hj, body).reason == "needs grant"
    assert g(H + "/api/v3/profile", "PUT", hj, body, grant=Grant(True, hosts=["other.host"])).reason \
        == "host-not-granted"
    assert g(H + "/api/v3/profile", "PUT", hj, body, grant=GRANT, owned=NOT_OWN, restore=True).reason == "not-owned"
    ok = g(H + "/api/v3/profile", "PUT", hj, body, grant=GRANT, owned=OWN, restore=True)
    assert ok.send and ok.needs_grant and ok.reason == "ok"


def test_non_get_owned_without_restore_path_not_sent():
    r = g(H + "/api/v3/profile", "PUT", {"Content-Type": "application/json"}, "{}", grant=GRANT, owned=OWN)
    assert not r.send and r.reason == "no restore path"


def test_never_mutated_wins():
    r = g(H + "/api/v3/me", never=True)
    assert not r.send and r.reason == "never-mutated"


def test_own_account_route_rules():
    assert M.own_account_route(H + "/api/v3/profile")
    assert M.own_account_route(H + "/me")
    assert M.own_account_route(H + "/api/user/settings?tab=1")
    assert not M.own_account_route(H + "/api/v3/users/42/profile")
    assert not M.own_account_route(H + "/org/settings")
    assert not M.own_account_route(H + "/workspace/ab12cd34ef/settings")
    assert not M.own_account_route(H + "/api/items")
    assert not M.own_account_route(H + "/api/profile/9f3b2c1d-1111-2222-3333-444455556666")


def _req(method, url, body=None):
    hj = {"Content-Type": "application/json"} if body else {}
    return M.Req("r1", method, url, hj, body, M.body_kind_of(hj, body), "x")


def test_own_account_requires_snapshot_self_id():
    r = _req("PUT", H + "/api/v3/profile", "{}")
    assert M.ownership(r, set(), {"u-1001"}, True).kind == "own-account"
    assert not M.ownership(r, set(), {"u-1001"}, False).owned
    assert not M.ownership(r, set(), {"u-1001"}, None).owned
    assert not M.ownership(r, set(), set(), True).owned   # no self id learned at all


def test_created_id_ownership_exact_segment():
    assert M.ownership(_req("PUT", H + "/api/items/17"), {"17"}, set(), None).kind == "created"
    assert not M.ownership(_req("PUT", H + "/api/items/170"), {"17"}, set(), None).owned
    body = json.dumps({"item_id": "17", "name": "x"})
    assert M.ownership(_req("POST", H + "/api/items/update", body), {"17"}, set(), None).kind == "created"


def test_never_mutated_sso_logout_payment():
    assert M.never_mutated(H + "/logout")
    assert M.never_mutated(H + "/oauth2/authorize?response_type=code&client_id=a")
    assert M.never_mutated("https://checkout.stripe.com/pay")
    assert M.never_mutated(H + "/api/account/delete", classification="account-delete")
    assert not M.never_mutated(H + "/api/v3/profile")


def test_agent_ops_accept_valid():
    raw = [{"replay_id": "r1", "op": "add_param", "location": "json", "path": ["plan"], "value": "pro"}]
    ok, errs = M.validate_agent_ops(raw, {"r1"})
    assert not errs and len(ok) == 1
    v = ok[0]
    assert v.origin == "agent" and v.score == 100 and v.family == "add" and v.ops[0].path == ("plan",)


def test_agent_ops_reject_forbidden_headers_crlf_long_values_unknown_replay():
    bad = [
        {"replay_id": "zz", "op": "add_param", "location": "query", "path": ["a"], "value": "1"},
        {"replay_id": "r1", "op": "add_param", "location": "query", "path": ["a"], "value": "x" * 2049},
        {"replay_id": "r1", "op": "add_param", "location": "query", "path": ["a\r\nb"], "value": "1"},
        {"replay_id": "r1", "op": "add_param", "location": "query", "path": ["a"], "value": "1\n2"},
        {"replay_id": "r1", "op": "set_header", "name": "Cookie", "value": "x"},
        {"replay_id": "r1", "op": "frobnicate", "location": "query", "path": ["a"]},
        {"replay_id": "r1", "op": "add_param", "location": "cookie", "path": ["a"], "value": "1"},
    ]
    ok, errs = M.validate_agent_ops(bad, {"r1"})
    assert ok == [] and len(errs) == len(bad)


def test_agent_ops_cannot_change_host():
    raw = [{"replay_id": "r1", "op": "set_url", "value": "http://evil.invalid/x"}]
    ok, errs = M.validate_agent_ops(raw, {"r1"})
    assert ok == [] and errs
