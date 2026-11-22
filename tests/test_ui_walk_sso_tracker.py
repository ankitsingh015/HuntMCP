"""Spec 2 (SSO surface), Task 4: SsoTracker unit tests (no browser)."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

from ui_walk_sso import SsoTracker

APP = "http://127.0.0.1:9"
IDP = "http://localhost:7/default"
AUTHZ = (IDP + "/authorize?response_type=code&client_id=fixture-app&redirect_uri=" + APP
         + "/sso/callback&state=SECRETSTATE00001&nonce=SECRETNONCE00001")


def _t(in_scope_hosts=("127.0.0.1", "localhost")):
    from urllib.parse import urlsplit
    return SsoTracker(lambda u: urlsplit(u).hostname in in_scope_hosts)


def test_observe_authorize_creates_flow_without_values():
    t = _t()
    assert t.observe_url(AUTHZ, seen_via="request", page=APP + "/sso", control_signature=None) == "authorize"
    assert len(t.data["flows"]) == 1
    f = t.data["flows"][0]
    assert f["idp_host"] == "localhost:7" and f["idp_in_scope"] is True
    assert f["authorize"]["client_id"] == "fixture-app"
    assert t.data["idp_hosts"] == ["localhost:7"]
    assert t.data["endpoints"][0]["role"] == "authorize"
    dump = json.dumps(t.data)
    assert "SECRETSTATE00001" not in dump and "SECRETNONCE00001" not in dump


def test_non_sso_url_ignored():
    t = _t()
    assert t.observe_url(APP + "/items", seen_via="request", page=APP, control_signature=None) is None
    assert t.data["endpoints"] == [] and t.data["flows"] == []


def test_chain_sets_echo_and_repeat_source():
    t = _t()
    cb = APP + "/sso/callback?code=SECRETCODE0001&state=SECRETSTATE00001"
    t.observe_chain([APP + "/sso/login-silent", AUTHZ, cb, APP + "/sso/home"], page=APP + "/sso",
                    control_signature="c1")
    f = t.data["flows"][0]
    assert f["state_echoed_on_callback"] is True
    pending = t.pending_repeats()
    assert pending and pending[0][1] == {"kind": "a", "url": APP + "/sso/login-silent"}
    assert {e["role"] for e in t.data["endpoints"]} == {"authorize", "callback"}
    assert "SECRETCODE0001" not in json.dumps(t.data)


def test_chain_echo_false_when_state_differs():
    t = _t()
    t.observe_chain([AUTHZ, APP + "/sso/callback?code=x1x1&state=OTHERSTATE"], page=APP, control_signature=None)
    assert t.data["flows"][0]["state_echoed_on_callback"] is False


def test_href_and_click_sources():
    t = _t()
    t.observe_url(AUTHZ, seen_via="href", page=APP + "/sso", control_signature="link1")
    assert t.pending_repeats()[0][1] == {"kind": "b", "page": APP + "/sso", "control_signature": "link1"}
    t2 = _t()
    t2.observe_url(AUTHZ, seen_via="request", page=APP + "/sso", control_signature="btn1")
    assert t2.pending_repeats()[0][1] == {"kind": "c", "page": APP + "/sso", "control_signature": "btn1"}
    t3 = _t()
    t3.observe_url(AUTHZ, seen_via="request", page=APP + "/sso", control_signature=None)
    assert t3.pending_repeats() == []   # a page-load nav has no trigger to repeat


def test_chain_25_hops_and_loop_never_raises():
    t = _t()
    hops = [APP + f"/r{i}" for i in range(24)] + [AUTHZ]
    t.observe_chain(hops, page=APP, control_signature=None)      # authorize is hop 25: beyond the cap
    assert t.data["flows"] == []
    t.observe_chain([AUTHZ, AUTHZ, AUTHZ] * 10, page=APP, control_signature=None)
    assert len(t.data["flows"]) == 1
    t.observe_chain([None, 5, "", "not a url"], page=APP, control_signature=None)


def test_same_flow_on_many_pages_one_flow():
    t = _t()
    for i in range(40):
        t.observe_url(AUTHZ.replace("SECRETSTATE00001", f"S{i:015d}"), seen_via="href",
                      page=APP + f"/p{i}", control_signature="l")
    assert len(t.data["flows"]) == 1
    assert len(t.pending_repeats()) == 1


def test_out_of_scope_idp_flow_and_redirect_recorded_stripped():
    t = _t(("127.0.0.1",))
    t.observe_url(AUTHZ, seen_via="redirect-hop", page=APP + "/sso", control_signature=None)
    assert t.data["flows"][0]["idp_in_scope"] is False
    assert not t.is_idp_host("localhost:7")   # out-of-scope IdPs are never treated as walkable IdP hosts
    t.note_out_of_scope_redirect(AUTHZ, page=APP + "/sso", control_signature="c")
    rec = t.data["out_of_scope_idp_redirects"][0]
    assert rec == {"host": "localhost:7", "url": IDP + "/authorize", "page": APP + "/sso", "control_signature": "c"}


def test_finish_repeat_compares_and_drops():
    t = _t()
    t.observe_chain([APP + "/sso/login", AUTHZ], page=APP, control_signature=None)
    key = t.pending_repeats()[0][0]
    t.finish_repeat(key, AUTHZ, "a")    # identical state and nonce again: static
    f = t.data["flows"][0]
    assert f["state_changes_per_request"] is False and f["nonce_changes_per_request"] is False
    assert f["repeat"] == {"kind": "a", "result": "compared"}
    assert t.pending_repeats() == []
    t2 = _t()
    t2.observe_chain([APP + "/sso/login", AUTHZ], page=APP, control_signature=None)
    k2 = t2.pending_repeats()[0][0]
    t2.finish_repeat(k2, None, "a")
    assert t2.data["flows"][0]["state_changes_per_request"] == "unknown"
    assert t2.data["flows"][0]["repeat"] == {"kind": "a", "result": "unknown"}


def test_drop_secrets_empties_memory():
    t = _t()
    t.observe_url(AUTHZ, seen_via="href", page=APP, control_signature="l")
    t.drop_secrets()
    assert "SECRETSTATE00001" not in repr(vars(t))


def test_logout_flags_on_endpoint():
    t = _t()
    t.observe_url(IDP + "/endsession?post_logout_redirect_uri=" + APP + "/sso&id_token_hint=TOKHINT9",
                  seen_via="href", page=APP + "/sso", control_signature="lo")
    ep = t.data["endpoints"][0]
    assert ep["role"] == "logout" and ep["redirect_params"] == ["post_logout_redirect_uri"]
    assert "TOKHINT9" not in json.dumps(t.data)


def test_is_idp_url():
    t = _t()
    t.observe_url(AUTHZ, seen_via="request", page=APP, control_signature=None)
    assert t.is_idp_url("http://localhost:7/default/authorize?x=1")
    assert not t.is_idp_url(APP + "/sso")


def test_finish_repeat_skipped_result():
    t = _t(("127.0.0.1",))
    t.observe_url(AUTHZ, seen_via="href", page=APP, control_signature="l")
    key = t.pending_repeats()[0][0]
    t.finish_repeat(key, None, "b", result="skipped-out-of-scope-idp")
    assert t.data["flows"][0]["repeat"] == {"kind": "b", "result": "skipped-out-of-scope-idp"}


def test_same_endpoint_on_many_pages_one_record():
    # review F4: one endpoint record (hence one node) per (role, method, template)
    t = _t()
    for i in range(40):
        t.observe_url(AUTHZ, seen_via="href", page=APP + f"/p{i}", control_signature="l")
    assert len([e for e in t.data["endpoints"] if e["role"] == "authorize"]) == 1
    assert t.data["endpoints"][0]["page"] == APP + "/p0"


def test_multi_hop_chain_repeat_source_is_last_hop_before_authorize():
    # review F5: A -> B -> authorize: B's Location is the authorize URL, A's is not
    t = _t()
    t.observe_chain([APP + "/login", APP + "/auth/start", AUTHZ], page=APP, control_signature=None)
    assert t.pending_repeats()[0][1] == {"kind": "a", "url": APP + "/auth/start"}
