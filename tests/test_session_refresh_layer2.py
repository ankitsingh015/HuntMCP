"""Session keep-alive layer 2: the tool uses a stored refresh token (fixture IdP)."""

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "session_refresh_target"))

import scope_guard  # noqa: E402
import session_refresh as R  # noqa: E402
from oidc_fixture import serve  # noqa: E402

SIDE = "huntmcp_session_storage"


@pytest.fixture(autouse=True)
def _fixture_names_resolve_public(monkeypatch):
    # *.localhost fixture names stand in for PUBLIC IdP hosts; real resolution
    # (loopback) is exercised by the strict-policy unit tests instead
    real = R._resolves_non_public
    monkeypatch.setattr(R, "_resolves_non_public",
                        lambda h: False if h.endswith(".localhost") else real(h))


@pytest.fixture
def fx():
    f = serve(app_silent_renew=False, app_uses_rt=False)
    yield f
    f.close()


def _policy(**kw):
    return R.RenewalPolicy(engagement=scope_guard.Engagement(target="127.0.0.1", in_scope=["127.0.0.1"], **kw),
                           learned=["idp.localhost"])


def _user(state, fx):
    return json.loads(state[SIDE][fx.app_origin][fx.storage_key])


def test_layer2_refresh_grant_writes_rotated_tokens(fx):
    st = fx.seed_state(access_valid=False, with_rt=True)
    old_rt = _user(st, fx)["refresh_token"]
    res = R.layer2_refresh_grant(st, _policy(), fx.app_origin)
    assert res.ok, res.reason
    user = _user(res.state, fx)
    assert fx.valid_access(user["access_token"])
    assert user["refresh_token"] != old_rt
    assert old_rt in fx.used_refresh_tokens
    # the input state is not mutated (caller decides what to write)
    assert _user(st, fx)["refresh_token"] == old_rt


def test_layer2_reused_rt_refused(fx):
    st = fx.seed_state(access_valid=False, with_rt=True)
    assert R.layer2_refresh_grant(st, _policy(), fx.app_origin).ok
    # the same (now rotated-away) refresh token again -> refused, never "ok"
    res = R.layer2_refresh_grant(st, _policy(), fx.app_origin)
    assert not res.ok and res.reason == "token_refused"


def test_layer2_issuer_not_allowed(fx):
    st = fx.seed_state(access_valid=False, with_rt=True)
    res = R.layer2_refresh_grant(st, _policy(out_of_scope=["idp.localhost"]), fx.app_origin)
    assert not res.ok and res.reason == "token_endpoint_not_allowed"
    assert not any(p in ("/token", "/.well-known/openid-configuration") for _m, _h, p in fx.requests)


def test_layer2_token_endpoint_on_other_host_not_allowed(fx, monkeypatch):
    st = fx.seed_state(access_valid=False, with_rt=True)
    monkeypatch.setattr(R, "_discover_token_endpoint", lambda issuer: "http://rogue.localhost:1/token")
    res = R.layer2_refresh_grant(st, _policy(), fx.app_origin)
    assert not res.ok and res.reason == "token_endpoint_not_allowed"


def test_layer2_no_rt(fx):
    st = fx.seed_state(access_valid=False, with_rt=False)
    res = R.layer2_refresh_grant(st, _policy(), fx.app_origin)
    assert not res.ok and res.reason == "no_refresh_token"


def test_layer2_sends_app_origin(fx, monkeypatch):
    sent = {}
    import http_probe

    real = http_probe.fetch

    def spy(url, method, headers, body, timeout_s, **kw):
        if method == "POST":
            sent.update(headers=headers, body=body, kw=kw)
        return real(url, method, headers, body, timeout_s, **kw)

    monkeypatch.setattr(http_probe, "fetch", spy)
    st = fx.seed_state(access_valid=False, with_rt=True)
    assert R.layer2_refresh_grant(st, _policy(), fx.app_origin).ok
    assert sent["headers"]["Origin"] == fx.app_origin
    assert "grant_type=refresh_token" in sent["body"] and "client_id=spa" in sent["body"]
    assert sent["kw"] == {"allow_redirects": False}


def test_layer2_token_endpoint_on_other_learned_host_refused(fx, monkeypatch):
    st = fx.seed_state(access_valid=False, with_rt=True)
    pol = R.RenewalPolicy(engagement=scope_guard.Engagement(target="127.0.0.1", in_scope=["127.0.0.1"]),
                          learned=["idp.localhost", "other.localhost"])
    monkeypatch.setattr(R, "_discover_token_endpoint", lambda issuer: "http://other.localhost:1/token")
    res = R.layer2_refresh_grant(st, pol, fx.app_origin)
    assert not res.ok and res.reason == "token_endpoint_not_allowed"


def test_layer2_ignores_entry_from_non_scope_origin(fx):
    # an attacker origin (e.g. one scope_guard's safe-host shortcut would keep)
    # planting an oidc.user entry must not steer a server-side POST anywhere
    st = {"cookies": [], "origins": [], SIDE: {"http://evil.sh": {
        "oidc.user:http://evil.sh:c": json.dumps({"access_token": "x", "refresh_token": "r", "expires_at": 1})}}}
    res = R.layer2_refresh_grant(st, _policy(), fx.app_origin)
    assert not res.ok and res.reason == "no_refresh_token"
    assert fx.requests == []


def test_layer2_loopback_issuer_refused_without_explicit_scope(fx):
    st = {"cookies": [], "origins": [], SIDE: {fx.app_origin: {
        "oidc.user:http://127.0.0.2:9/x:c": json.dumps({"access_token": "x", "refresh_token": "r", "expires_at": 1})}}}
    res = R.layer2_refresh_grant(st, _policy(), fx.app_origin)
    assert not res.ok and res.reason == "token_endpoint_not_allowed"
