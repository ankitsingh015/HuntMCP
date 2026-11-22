"""Session keep-alive: refresh_session ties layers 1->2->human together."""

import asyncio
import json
import os
import sys

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "session_refresh_target"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import engagement_paths  # noqa: E402
import scope_guard  # noqa: E402
import session_capture  # noqa: E402
import session_refresh as R  # noqa: E402
from oidc_fixture import seed_profile, serve  # noqa: E402
from ui_walk_app import requires_browser  # noqa: E402

SENTINEL = "S3NTINEL_TOKEN_VALUE"
ENG = scope_guard.Engagement(target="127.0.0.1", in_scope=["127.0.0.1", "app.t.com"])


@pytest.fixture(autouse=True)
def _fixture_names_resolve_public(monkeypatch):
    # *.localhost fixture names stand in for PUBLIC IdP hosts; real resolution
    # (loopback) is exercised by the strict-policy unit tests instead
    real = R._resolves_non_public
    monkeypatch.setattr(R, "_resolves_non_public",
                        lambda h: False if h.endswith(".localhost") else real(h))


@pytest.fixture
def ident(tmp_path, monkeypatch):
    profile = tmp_path / "profiles" / "xyz"
    profile.mkdir(parents=True)
    roster = tmp_path / "roster.yaml"
    roster.write_text(yaml.safe_dump({"identities": {"xyz": {"note": "t", "profile_dir": str(profile)}}}))
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(roster))
    monkeypatch.setattr(session_capture, "_load_engagement", lambda: ENG)
    calls = {"budget": 0, "notify": []}
    monkeypatch.setattr(R, "enforce", lambda tool: calls.__setitem__("budget", calls["budget"] + 1))
    monkeypatch.setattr(R, "notify", lambda title, body: calls["notify"].append((title, body)))
    monkeypatch.setattr(R, "_EXTRA_LAUNCH_ARGS", ("--disable-features=LocalNetworkAccessChecks",))
    session_capture._live_captures.clear()
    yield {"profile": str(profile), "calls": calls}
    session_capture._live_captures.clear()


def _write_identity(entry):
    ipath = engagement_paths.resolve("secrets/identities.json")
    os.makedirs(os.path.dirname(ipath), exist_ok=True)
    with open(ipath, "w") as fh:
        json.dump({"xyz": entry}, fh)
    return ipath


def _sess_path():
    return engagement_paths.resolve("secrets/sessions/xyz.json")


def _write_session(state):
    p = _sess_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        json.dump(state, fh)


def _ok_state(token=SENTINEL):
    return {"cookies": [{"name": "sid", "value": SENTINEL, "domain": "app.t.com", "path": "/"}], "origins": [],
            "huntmcp_session_storage": {"https://app.t.com": {"k": token}}}


def _fake_layers(monkeypatch, l1_results, l2_result=None):
    seq = list(l1_results)
    seen = {"l1": 0, "l2": 0}

    async def l1(profile_dir, app_url, session_file, policy, whoami_url, timeout_ms=20000):
        seen["l1"] += 1
        seen["app_url"] = app_url
        seen["learned"] = list(policy.learned)
        return seq.pop(0)

    def l2(state, policy, origin):
        seen["l2"] += 1
        return l2_result or R.LayerResult(False, "no_refresh_token")

    monkeypatch.setattr(R, "layer1_app_renew", l1)
    monkeypatch.setattr(R, "layer2_refresh_grant", l2)
    return seen


def _run(label="xyz"):
    return asyncio.run(R.refresh_session(label))


def _entry(**kw):
    e = {"cookies": [], "authorization": None, "source_login_url": "https://app.t.com/login",
         "app_url": "https://app.t.com/home", "renewal_hosts": ["t.auth0.com"], "whoami": {}}
    e.update(kw)
    return e


def test_refresh_returns_no_secret_and_writes_file(ident, monkeypatch):
    _write_identity(_entry())
    _write_session({"cookies": [], "origins": []})
    _fake_layers(monkeypatch, [R.LayerResult(True, None, _ok_state(), "Bearer " + SENTINEL, 1e12)])
    out = _run()
    assert SENTINEL not in json.dumps(out)
    assert set(out) <= R.ALLOWED_SUMMARY_KEYS
    assert out["refreshed"] is True and out["layer"] == "app" and out["needs_human_login"] is False
    with open(_sess_path()) as fh:
        assert SENTINEL in fh.read()
    assert oct(os.stat(_sess_path()).st_mode)[-3:] == "600"
    ident_data = json.load(open(engagement_paths.resolve("secrets/identities.json")))
    assert ident_data["xyz"]["authorization"] == "Bearer " + SENTINEL
    assert ident["calls"]["budget"] == 1


def test_refresh_busy_when_capture_open(ident, monkeypatch):
    _write_identity(_entry())
    seen = _fake_layers(monkeypatch, [])
    session_capture._live_captures[(session_capture._slug(None), "xyz")] = session_capture._PENDING
    out = _run()
    assert out["status"] == "busy" and out["refreshed"] is False
    assert seen["l1"] == 0 and ident["calls"]["budget"] == 0
    assert not os.path.exists(_sess_path())


def test_refresh_busy_when_profile_locked(ident, monkeypatch):
    _write_identity(_entry())

    async def locked(*a, **k):
        raise RuntimeError("Failed to create a ProcessSingleton for your profile directory")

    monkeypatch.setattr(R, "layer1_app_renew", locked)
    out = _run()
    assert out["status"] == "busy"


def test_refresh_old_entry_without_app_url(ident, monkeypatch):
    e = _entry()
    del e["app_url"], e["renewal_hosts"]
    _write_identity(e)
    seen = _fake_layers(monkeypatch, [R.LayerResult(True, None, _ok_state(), None, None)])
    out = _run()
    assert out["refreshed"] is True
    assert seen["app_url"] == "https://app.t.com/login" and seen["learned"] == []


def test_refresh_falls_to_layer2_then_reverifies(ident, monkeypatch):
    _write_identity(_entry())
    _write_session({"cookies": [], "origins": []})
    seen = _fake_layers(monkeypatch,
                        [R.LayerResult(False, "login_page"), R.LayerResult(True, None, _ok_state("NEW"), None, None)],
                        R.LayerResult(True, None, _ok_state("FROM-L2")))
    out = _run()
    assert out["refreshed"] is True and out["layer"] == "refresh_token"
    assert seen == {**seen, "l1": 2, "l2": 1}


def test_refresh_layer2_state_persisted_even_if_reverify_fails(ident, monkeypatch):
    # a rotated refresh token must never be lost
    _write_identity(_entry())
    _write_session({"cookies": [], "origins": []})
    _fake_layers(monkeypatch, [R.LayerResult(False, "login_page"), R.LayerResult(False, "login_page")],
                 R.LayerResult(True, None, _ok_state("ROTATED")))
    out = _run()
    assert out["needs_human_login"] is True
    assert "ROTATED" in open(_sess_path()).read()


def test_refresh_both_fail_needs_human_and_notifies_once(ident, monkeypatch):
    _write_identity(_entry())
    _write_session({"cookies": [], "origins": []})
    _fake_layers(monkeypatch, [R.LayerResult(False, "captcha")])
    out = _run()
    assert out["status"] == "needs_human_login" and out["needs_human_login"] is True
    assert out["reason"] == "captcha" and out["layer"] == "none"
    assert len(ident["calls"]["notify"]) == 1
    assert SENTINEL not in json.dumps(ident["calls"]["notify"])


def test_refresh_daily_cap(ident, monkeypatch):
    _write_identity(_entry())
    _write_session({"cookies": [], "origins": []})
    seen = _fake_layers(monkeypatch, [])
    st = R._load_refresh_state("xyz")
    st.update(day=R._today(), count=R.MAX_RENEWALS_PER_DAY)
    R._save_refresh_state("xyz", st)
    out = _run()
    assert out["status"] == "capped" and seen["l1"] == 0


def test_refresh_respects_min_request_interval(ident, monkeypatch):
    eng = scope_guard.Engagement(target="127.0.0.1", in_scope=["app.t.com"], min_request_interval_s=3600)
    monkeypatch.setattr(session_capture, "_load_engagement", lambda: eng)
    _write_identity(_entry())
    st = R._load_refresh_state("xyz")
    st.update(last_attempt=__import__("time").time())
    R._save_refresh_state("xyz", st)
    seen = _fake_layers(monkeypatch, [])
    assert _run()["status"] == "rate_limited" and seen["l1"] == 0


def test_refresh_rejects_bad_label(ident):
    out = _run("../etc")
    assert "error" in out and set(out) <= R.ALLOWED_SUMMARY_KEYS


def test_refresh_unknown_label(ident):
    assert "error" in _run("nobody")


def test_refresh_not_captured_needs_human(ident, monkeypatch):
    _fake_layers(monkeypatch, [])
    out = _run()
    assert out["needs_human_login"] is True and out["reason"] == "not_captured"


def test_refresh_app_url_out_of_scope_refused(ident, monkeypatch):
    _write_identity(_entry(app_url="https://evil.com/x", source_login_url="https://evil.com/login"))
    seen = _fake_layers(monkeypatch, [])
    out = _run()
    assert out["needs_human_login"] is True and out["reason"] == "no_app_url" and seen["l1"] == 0


def test_label_for_session_file(ident):
    assert R.label_for_session_file(_sess_path()) == "xyz"
    assert R.label_for_session_file("/tmp/whatever/xyz.json") is None
    assert R.label_for_session_file("") is None


@requires_browser
def test_refresh_end_to_end_layer1(ident, monkeypatch):
    fx = serve(app_uses_rt=False)
    try:
        eng = scope_guard.Engagement(target="127.0.0.1", in_scope=["127.0.0.1"])
        monkeypatch.setattr(session_capture, "_load_engagement", lambda: eng)
        asyncio.run(seed_profile(ident["profile"], [fx.sso_cookie()]))
        _write_identity(_entry(app_url=fx.app_url, source_login_url=fx.app_url + "login",
                               renewal_hosts=["idp.localhost"], whoami_url=fx.app_url + "api/me"))
        _write_session(fx.seed_state(access_valid=False, with_rt=False))
        out = _run()
        assert out["refreshed"] is True and out["layer"] == "app", out
        assert out["access_expires_in_s"] > 0
        user = json.loads(json.load(open(_sess_path()))["huntmcp_session_storage"][fx.app_origin][fx.storage_key])
        assert fx.valid_access(user["access_token"])
        fx.sso_valid = False
        _write_session(fx.seed_state(access_valid=False, with_rt=False))
        out2 = _run()
        assert out2["needs_human_login"] is True and out2["reason"] == "login_page"
    finally:
        fx.close()
