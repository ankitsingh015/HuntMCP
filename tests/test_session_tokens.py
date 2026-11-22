"""session_tokens: find SPA token entries in a session_file and patch them."""

import base64
import json

import session_tokens as T

SIDE = "huntmcp_session_storage"
APP = "https://app.t.com"


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'none'})}.{enc(claims)}."


def _oidc_state(rt="RT-OLD", exp=1000):
    user = {"access_token": _jwt({"exp": exp}), "id_token": "ID-OLD", "refresh_token": rt,
            "token_type": "Bearer", "scope": "openid", "expires_at": exp}
    if rt is None:
        user.pop("refresh_token")
    return {"cookies": [], "origins": [{"origin": APP, "localStorage": [{"name": "other", "value": "keep"}]}],
            SIDE: {APP: {"oidc.user:https://idp.t.com/realms/x:spa": json.dumps(user), "unrelated": "u"}}}


def _auth0_state():
    body = {"access_token": _jwt({"exp": 2000}), "id_token": _jwt({"iss": "https://t.auth0.com/", "exp": 2000}),
            "refresh_token": "A0-RT", "scope": "openid", "expires_in": 86400, "token_type": "Bearer"}
    value = json.dumps({"body": body, "expiresAt": 2000})
    return {"cookies": [], "origins": [{"origin": APP, "localStorage": [
        {"name": "@@auth0spajs@@::CID::https://api.t.com::openid", "value": value}]}]}


def test_jwt_exp_reads_claim():
    assert T.jwt_exp(_jwt({"exp": 1234})) == 1234


def test_jwt_exp_none_for_opaque():
    assert T.jwt_exp("opaque-token") is None
    assert T.jwt_exp("") is None
    assert T.jwt_exp("a.!!!.c") is None


def test_find_oidc_client_ts_entry_in_session_sidecar():
    [e] = T.find_token_entries(_oidc_state())
    assert (e.origin, e.store, e.shape) == (APP, "session", "oidc-client-ts")
    assert e.key == "oidc.user:https://idp.t.com/realms/x:spa"
    assert e.issuer == "https://idp.t.com/realms/x"
    assert e.client_id == "spa"
    assert e.refresh_token == "RT-OLD"
    assert e.access_exp == 1000


def test_find_auth0_entry_in_local_storage():
    [e] = T.find_token_entries(_auth0_state())
    assert (e.store, e.shape, e.client_id) == ("local", "auth0-spa-js", "CID")
    assert e.issuer == "https://t.auth0.com/"
    assert e.refresh_token == "A0-RT"
    assert e.access_exp == 2000


def test_find_ignores_garbage_values():
    st = {"cookies": [], "origins": [{"origin": APP, "localStorage": [
        {"name": "oidc.user:https://i:spa", "value": "not json"},
        {"name": "@@auth0spajs@@::C::a::s", "value": "[]"}]}]}
    assert T.find_token_entries(st) == []


def test_apply_response_rotates_rt_and_preserves_other_keys():
    st = _oidc_state()
    [e] = T.find_token_entries(st)
    new_at = _jwt({"exp": 5000})
    out = T.apply_token_response(st, e, {"access_token": new_at, "id_token": "ID-NEW",
                                         "refresh_token": "RT-NEW", "expires_in": 300}, now=4700)
    user = json.loads(out[SIDE][APP][e.key])
    assert user["access_token"] == new_at and user["id_token"] == "ID-NEW"
    assert user["refresh_token"] == "RT-NEW" and user["expires_at"] == 5000
    assert out[SIDE][APP]["unrelated"] == "u"
    assert out["origins"][0]["localStorage"] == [{"name": "other", "value": "keep"}]
    # input not mutated
    assert json.loads(st[SIDE][APP][e.key])["refresh_token"] == "RT-OLD"


def test_apply_response_keeps_old_rt_when_absent():
    st = _oidc_state()
    [e] = T.find_token_entries(st)
    out = T.apply_token_response(st, e, {"access_token": "opaque", "expires_in": 60}, now=100)
    user = json.loads(out[SIDE][APP][e.key])
    assert user["refresh_token"] == "RT-OLD" and user["expires_at"] == 160


def test_apply_response_auth0_shape():
    st = _auth0_state()
    [e] = T.find_token_entries(st)
    out = T.apply_token_response(st, e, {"access_token": _jwt({"exp": 9000}), "refresh_token": "A0-NEW",
                                         "expires_in": 600}, now=8400)
    value = json.loads(out["origins"][0]["localStorage"][0]["value"])
    assert value["body"]["refresh_token"] == "A0-NEW" and value["expiresAt"] == 9000


def test_earliest_exp_includes_bearer_header():
    st = _oidc_state(exp=1000)
    assert T.earliest_access_exp(st, None) == 1000
    assert T.earliest_access_exp(st, "Bearer " + _jwt({"exp": 700})) == 700
    assert T.earliest_access_exp({"cookies": [], "origins": []}, None) is None
