"""Spec 2 (SSO surface), Task 6: sso-* candidates (pure), SSO surface-map
nodes, and the SSO coverage battery."""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import coverage_manifest
import surface_map
import ui_walk_sso_logic as S
import ui_walk_store

APP = "http://app.test"
IDP = "http://idp.test"


def _flags(**kw):
    base = {"param_names": [], "response_type": "code", "response_mode": None, "scope": "openid",
            "prompt": None, "client_id": "c1", "code_challenge_method": "S256", "redirect_uri": APP + "/cb",
            "pkce": True, "state": {"present": True, "strength": "ok", "length_bucket": "32+"},
            "nonce": {"present": True, "strength": "ok", "length_bucket": "32+"}}
    base.update(kw)
    return base


def _flow(idp_in_scope=True, **kw):
    f = {"key": "k", "authorize": _flags(**kw.pop("authorize", {})), "idp_host": "idp.test",
         "idp_in_scope": idp_in_scope, "page": APP + "/login", "control_signature": "s1", "seen_via": "href",
         "state_changes_per_request": True, "nonce_changes_per_request": True,
         "state_echoed_on_callback": "unknown", "repeat": {"kind": "a", "result": "compared"}}
    f.update(kw)
    return f


def _sso(flows=(), endpoints=()):
    return {"flows": list(flows), "endpoints": list(endpoints), "discovery": [], "idp_hosts": [],
            "repeats": 0, "discovery_gets": 0, "out_of_scope_idp_redirects": []}


def _types(cands):
    return sorted(c["type"] for c in cands)


def test_clean_flow_gives_only_redirect_uri_lead():
    assert _types(S.derive_sso_candidates(_sso([_flow()]))) == ["sso-redirect-uri-candidate"]


def test_redirect_uri_candidate_detail():
    c = S.derive_sso_candidates(_sso([_flow()]))[0]
    assert c["page"] == APP + "/login" and c["control_signature"] == "s1"
    assert c["detail"] == {"client_id": "c1", "redirect_uri": APP + "/cb", "response_type": "code",
                           "idp_host": "idp.test"}


@pytest.mark.parametrize("kw,reason", [
    ({"authorize": {"state": {"present": False, "strength": "absent", "length_bucket": None}}}, "missing"),
    ({"authorize": {"state": {"present": True, "strength": "short", "length_bucket": "<8"}}}, "weak:short"),
    ({"state_changes_per_request": False}, "static"),
    ({"state_echoed_on_callback": False}, "not-echoed"),
])
def test_state_candidate_reasons(kw, reason):
    cands = [c for c in S.derive_sso_candidates(_sso([_flow(**kw)])) if c["type"] == "sso-state-candidate"]
    assert len(cands) == 1 and reason in cands[0]["detail"]["reasons"]
    assert cands[0]["detail"]["idp_in_scope"] is True


def test_nonce_candidates():
    implicit = _flow(authorize={"response_type": "id_token token",
                                "nonce": {"present": False, "strength": "absent", "length_bucket": None}})
    t = _types(S.derive_sso_candidates(_sso([implicit])))
    assert "sso-nonce-candidate" in t and "sso-implicit-flow-candidate" in t
    static = _flow(nonce_changes_per_request=False)
    assert "sso-nonce-candidate" in _types(S.derive_sso_candidates(_sso([static])))
    # code flow without nonce is not an OIDC violation by itself
    code_no_nonce = _flow(authorize={"nonce": {"present": False, "strength": "absent", "length_bucket": None}},
                          nonce_changes_per_request="unknown")
    assert "sso-nonce-candidate" not in _types(S.derive_sso_candidates(_sso([code_no_nonce])))


def test_pkce_candidates():
    assert "sso-pkce-candidate" in _types(S.derive_sso_candidates(_sso([_flow(authorize={"pkce": False,
                                                                                       "code_challenge_method": None})])))
    assert "sso-pkce-candidate" in _types(S.derive_sso_candidates(_sso([_flow(authorize={"code_challenge_method": "plain"})])))
    implicit = _flow(authorize={"response_type": "token", "pkce": False})
    assert "sso-pkce-candidate" not in _types(S.derive_sso_candidates(_sso([implicit])))


def test_out_of_scope_idp_only_app_side_candidates():
    f = _flow(idp_in_scope=False, authorize={"pkce": False}, state_changes_per_request=False)
    t = _types(S.derive_sso_candidates(_sso([f])))
    assert t == ["sso-state-candidate"]
    c = S.derive_sso_candidates(_sso([f]))[0]
    assert c["detail"]["idp_in_scope"] is False


def test_endpoint_candidates():
    eps = [{"role": "logout", "method": "GET", "url": IDP + "/logout", "in_scope": True,
            "redirect_params": ["post_logout_redirect_uri"], "page": APP + "/", "control_signature": "lo"},
           {"role": "logout", "method": "GET", "url": APP + "/logout", "in_scope": True,
            "redirect_params": [], "page": APP + "/", "control_signature": None},
           {"role": "logout", "method": "GET", "url": "http://oos.test/logout", "in_scope": False,
            "redirect_params": ["returnto"], "page": APP + "/", "control_signature": None},
           {"role": "registration", "method": "POST", "url": IDP + "/register", "in_scope": True,
            "page": APP + "/", "control_signature": None},
           {"role": "registration", "method": "POST", "url": "http://oos.test/register", "in_scope": False,
            "page": APP + "/", "control_signature": None}]
    cands = S.derive_sso_candidates(_sso([], eps))
    assert _types(cands) == ["sso-logout-redirect-candidate", "sso-registration-candidate"]
    lo = next(c for c in cands if c["type"] == "sso-logout-redirect-candidate")
    assert lo["detail"] == {"url": IDP + "/logout", "redirect_params": ["post_logout_redirect_uri"]}


# ----------------------------------------------------------------- coverage

@pytest.mark.parametrize("kind,role,expected", [
    ("action", "authorize", {"auth", "open-redirect", "csrf"}),
    ("action", "callback", {"auth", "open-redirect"}),
    ("action", "logout", {"auth", "open-redirect"}),
    ("action", "token", {"auth"}),
    ("action", "jwks", {"auth"}),
    ("action", "discovery", {"auth"}),
    ("page", "login", {"xss", "access-control", "csrf", "auth"}),
    ("page", "consent", {"xss", "access-control", "csrf", "auth"}),
    ("page", "mfa", {"xss", "access-control", "csrf", "auth"}),
])
def test_sso_battery(kind, role, expected):
    assert coverage_manifest.required_classes({"kind": kind, "meta": {"sso_role": role}}) == expected


def test_non_sso_battery_unchanged():
    assert coverage_manifest.required_classes({"kind": "action", "meta": {}}) == \
        {"csrf", "idor", "access-control", "business-logic"}


# -------------------------------------------------------------------- nodes

@pytest.fixture
def _dirs(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path / "ui-walk"))
    return tmp_path


def _inv_v3():
    return {
        "schema_version": 3, "walk_id": "w1", "start_url": APP + "/", "mode": "map", "status": "complete",
        "pages": [
            {"url": APP + "/login", "template": APP + "/login", "title": "App", "auth_state": "ok",
             "inputs": [], "controls": [], "api_edges": []},
            {"url": IDP + "/authorize", "template": IDP + "/authorize", "title": "IdP login",
             "auth_state": "sso", "sso_role": "login", "inputs": [], "controls": [],
             "api_edges": [{"control_signature": None, "method": "POST", "url": IDP + "/oauth2/token",
                            "sent": False}]},
        ],
        "sso": _sso([], [
            {"role": "authorize", "method": "GET", "url": IDP + "/authorize", "in_scope": True,
             "param_names": ["client_id", "state"], "page": APP + "/login", "control_signature": "s1"},
            {"role": "token", "method": "POST", "url": IDP + "/oauth2/token", "in_scope": True,
             "param_names": [], "page": IDP + "/authorize", "control_signature": None},
            {"role": "jwks", "method": "GET", "url": "http://oos.test/jwks", "in_scope": False,
             "param_names": [], "page": APP + "/login", "control_signature": None},
        ]),
    }


def test_emit_nodes_sso_pages_and_actions(_dirs, tmp_path):
    mp = str(tmp_path / "map.json")
    counts = ui_walk_store.emit_nodes(_inv_v3(), map_path=mp)
    nodes = surface_map.load_map(mp)["nodes"]
    sso_pages = [n for n in nodes if n["kind"] == "page" and (n.get("meta") or {}).get("sso_role")]
    assert len(sso_pages) == 1 and sso_pages[0]["meta"]["sso_role"] == "login"
    actions = [n for n in nodes if n["kind"] == "action"]
    roles = sorted((n["meta"].get("sso_role"), n["signature"]) for n in actions)
    assert roles == [("authorize", f"action:GET {IDP}/authorize"), ("token", f"action:POST {IDP}/oauth2/token")]
    assert counts["sso_action"] == 2 and counts["action"] == 0   # the token edge is not a generic action too
    by_id = {n["id"]: n for n in nodes}
    authz = next(n for n in actions if n["meta"]["sso_role"] == "authorize")
    assert by_id[authz["parent_id"]]["meta"]["endpoint"] == APP + "/login"


def test_pass2_skips_sso_page_inputs():
    import asyncio

    import ui_walk_pass2

    w = ui_walk_pass2.CanaryWalker("http://app.test/", "canary", scope=lambda u: True, max_pages=1,
                                   max_clicks_per_page=1, same_origin_only=True, wall_clock_s=10,
                                   action_delay_s=0, screenshot_dir=None, had_session=False,
                                   session_file=None, auth={}, walk_id="w")
    w.inv.setdefault("skipped_forms", [])
    prec = {"url": IDP + "/authorize", "template": IDP + "/authorize", "auth_state": "sso",
            "inputs": [{"name": "username", "id": "", "type": "text", "frame_origin": IDP,
                        "form_action": IDP + "/authorize", "revealed_by": None, "maxlength": None}]}
    asyncio.run(w._submit_page(prec))   # must return before opening any page (no browser here)
    assert w.inv["skipped_forms"] == [{"page": IDP + "/authorize", "action": None, "reason": "sso-form"}]


def test_generic_action_kept_when_no_sso_endpoint_recorded(_dirs, tmp_path):
    # review F7: an SSO-looking non-GET edge the tracker never recorded keeps its generic action node
    mp = str(tmp_path / "map.json")
    inv = _inv_v3()
    inv["pages"][0]["api_edges"] = [{"control_signature": None, "method": "POST", "url": APP + "/logout",
                                     "sent": False}]
    counts = ui_walk_store.emit_nodes(inv, map_path=mp)
    sigs = {n["signature"] for n in surface_map.load_map(mp)["nodes"] if n["kind"] == "action"}
    assert f"action:POST {APP}/logout" in sigs
    assert counts["action"] == 1
