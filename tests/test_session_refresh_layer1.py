"""Session keep-alive layer 1: the app renews itself in the identity's dedicated
profile (headless), against the local fixture app + mini IdP. No real target."""

import asyncio
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "session_refresh_target"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import scope_guard  # noqa: E402
import session_refresh as R  # noqa: E402
from oidc_fixture import seed_profile, serve  # noqa: E402
from ui_walk_app import requires_browser  # noqa: E402

SIDE = "huntmcp_session_storage"


@pytest.fixture(autouse=True)
def _fixture_names_resolve_public(monkeypatch):
    # *.localhost fixture names stand in for PUBLIC IdP hosts; real resolution
    # (loopback) is exercised by the strict-policy unit tests instead
    real = R._resolves_non_public
    monkeypatch.setattr(R, "_resolves_non_public",
                        lambda h: False if h.endswith(".localhost") else real(h))


@pytest.fixture(autouse=True)
def _loopback_lna(monkeypatch):
    # fixture app and IdP are both loopback; see session_refresh._EXTRA_LAUNCH_ARGS
    monkeypatch.setattr(R, "_EXTRA_LAUNCH_ARGS", ("--disable-features=LocalNetworkAccessChecks",))


def _eng(**kw):
    return scope_guard.Engagement(target="127.0.0.1", in_scope=["127.0.0.1"], **kw)


def _policy(learned=("idp.localhost",), **kw):
    return R.RenewalPolicy(engagement=_eng(**kw), learned=list(learned))


# ------------------------------------------------------------- policy (unit)

def test_policy_allows_scope_learned_and_builtin():
    p = _policy()
    assert p.allowed("127.0.0.1") and p.allowed("idp.localhost")
    assert p.allowed("acme.auth0.com") and p.allowed("login.microsoftonline.com")
    assert not p.allowed("rogue.localhost") and not p.allowed("evil.com")


def test_policy_out_of_scope_beats_builtin_and_learned():
    p = _policy(out_of_scope=["*.auth0.com", "idp.localhost"])
    assert not p.allowed("acme.auth0.com")
    assert not p.allowed("idp.localhost")


def test_builtin_list_is_exact():
    assert R.BUILTIN_IDP_PATTERNS == (
        "*.auth0.com", "*.okta.com", "*.oktapreview.com", "login.microsoftonline.com",
        "login.live.com", "*.b2clogin.com", "accounts.google.com", "*.amazoncognito.com",
        "*.onelogin.com", "*.pingidentity.com", "*.pingone.com")


def test_route_blocks_document_to_disallowed_host():
    assert R.route_decision("GET", "http://rogue.localhost:1/x", "document", True, _policy()) == \
        ("abort", "blocked_host:rogue.localhost")


def test_route_blocks_form_post_even_in_scope():
    assert R.route_decision("POST", "http://127.0.0.1:1/login", "document", True, _policy()) == \
        ("abort", "form_post")


def test_route_allows_token_post_to_learned_host():
    assert R.route_decision("POST", "http://idp.localhost:1/token", "fetch", False, _policy()) == \
        ("continue", None)


def test_route_aborts_in_scope_non_token_mutation():
    assert R.route_decision("POST", "http://127.0.0.1:1/api/items", "xhr", False, _policy()) == \
        ("abort", "mutating_call")
    # only POST counts as a renewal call shape; DELETE /session is a logout
    assert R.route_decision("DELETE", "http://127.0.0.1:1/api/session", "fetch", False, _policy()) == \
        ("abort", "mutating_call")
    assert R.route_decision("DELETE", "http://idp.localhost:1/token", "fetch", False, _policy()) == \
        ("abort", "mutating_call")


def test_route_allows_in_scope_refresh_post():
    assert R.route_decision("POST", "http://127.0.0.1:1/auth/refresh", "fetch", False, _policy()) == \
        ("continue", None)


def test_route_allows_third_party_get_subresource():
    assert R.route_decision("GET", "https://cdn.example.net/app.js", "script", False, _policy()) == \
        ("continue", None)


def test_route_blocks_mutation_to_unknown_host():
    assert R.route_decision("POST", "https://collector.evil.com/t", "fetch", False, _policy()) == \
        ("abort", "mutating_call")


# --------------------------------------------------------- browser (fixture)

@pytest.fixture
def fx():
    f = serve()
    yield f
    f.close()


def _setup(tmp_path, fx, *, access_valid=False, with_rt=False):
    profile = tmp_path / "profile"
    sess = tmp_path / "session.json"
    sess.write_text(json.dumps(fx.seed_state(access_valid=access_valid, with_rt=with_rt)))
    asyncio.run(seed_profile(str(profile), [fx.sso_cookie()]))
    return str(profile), str(sess)


def _run(profile, sess, fx, policy=None):
    return asyncio.run(R.layer1_app_renew(profile, fx.app_url, sess, policy or _policy(), None))


def _user(state, fx):
    return json.loads(state[SIDE][fx.app_origin][fx.storage_key])


@requires_browser
def test_layer1_expired_token_silent_renew_succeeds(tmp_path, fx):
    fx.app_uses_rt = False
    profile, sess = _setup(tmp_path, fx)
    res = _run(profile, sess, fx)
    assert res.ok, res.reason
    user = _user(res.state, fx)
    assert fx.valid_access(user["access_token"])
    assert not any("idp.localhost" in c.get("domain", "") for c in res.state["cookies"])
    assert "__huntmcp_restored" not in res.state[SIDE][fx.app_origin]
    assert res.authorization and res.authorization.startswith("Bearer ")
    assert res.sso_expiry and res.sso_expiry > 0
    assert ("GET", "idp.localhost", "/authorize") in fx.requests


@requires_browser
def test_layer1_restore_runs_once_per_origin(tmp_path, fx):
    # the SPA reloads (/?renewed=1) after renewing; a restore that re-ran on that
    # navigation would put the stale token back and the app would land on /login.
    fx.app_uses_rt = False
    fx.reload_after_renew = True
    profile, sess = _setup(tmp_path, fx)
    res = _run(profile, sess, fx)
    assert res.ok, res.reason


@requires_browser
def test_layer1_app_uses_its_own_refresh_token(tmp_path, fx):
    fx.app_silent_renew = False
    profile, sess = _setup(tmp_path, fx, with_rt=True)
    res = _run(profile, sess, fx)
    assert res.ok, res.reason
    assert ("POST", "idp.localhost", "/token") in fx.requests


@requires_browser
def test_layer1_sso_expired_fails_login_page(tmp_path, fx):
    fx.app_uses_rt = False
    fx.sso_valid = False
    profile, sess = _setup(tmp_path, fx)
    res = _run(profile, sess, fx)
    assert not res.ok and res.reason == "login_page"


@requires_browser
def test_layer1_captcha_fails(tmp_path, fx):
    # the IdP serves a CAPTCHA at top level; a page that ends there is never "logged in"
    fx.app_uses_rt = False
    fx.app_silent_renew = False
    profile, sess = _setup(tmp_path, fx)
    import urllib.parse as up
    url = fx.idp_base + "/authorize?" + up.urlencode({"client_id": "spa", "redirect_uri": fx.app_url + "callback"})
    fx.authorize_mode = "captcha"
    res = asyncio.run(R.layer1_app_renew(profile, url, sess, _policy(), None))
    assert not res.ok and res.reason == "captcha"


@requires_browser
def test_layer1_redirect_to_rogue_blocked(tmp_path, fx):
    profile, sess = _setup(tmp_path, fx)
    url = fx.idp_base + "/authorize?prompt=none&redirect_uri=x"
    fx.authorize_mode = "redirect_rogue"
    res = asyncio.run(R.layer1_app_renew(profile, url, sess, _policy(), None))
    assert not res.ok and res.reason == "blocked_host:rogue.localhost"
    assert not any(h == "rogue.localhost" for _m, h, _p in fx.requests)


@requires_browser
def test_layer1_never_sends_document_post(tmp_path, fx):
    fx.app_uses_rt = False
    fx.sso_valid = False
    profile, sess = _setup(tmp_path, fx)
    _run(profile, sess, fx)
    assert not any(m == "POST" and p != "/token" for m, _h, p in fx.requests)


@requires_browser
def test_layer1_whoami_must_succeed(tmp_path, fx):
    fx.app_uses_rt = False
    profile, sess = _setup(tmp_path, fx)
    res = asyncio.run(R.layer1_app_renew(profile, fx.app_url, sess, _policy(), fx.app_url + "api/me"))
    assert res.ok, res.reason
    res2 = asyncio.run(R.layer1_app_renew(profile, fx.app_url, sess, _policy(), fx.app_url + "nope"))
    assert not res2.ok and res2.reason == "whoami_failed"


# ---------------------------------------- positive evidence of a renewed login

def _tok_state(exp):
    user = json.dumps({"access_token": "a.b.c", "expires_at": exp})
    return {"cookies": [], "origins": [], SIDE: {"http://127.0.0.1:1": {"oidc.user:http://idp:spa": user}}}


def test_auth_evidence_stale_token_not_renewed():
    assert R._auth_evidence(_tok_state(1000), [], now=2000) == "token_not_renewed"


def test_auth_evidence_fresh_token_ok():
    assert R._auth_evidence(_tok_state(5000), [200], now=2000) is None


def test_auth_evidence_api_401_without_later_2xx():
    st = {"cookies": [], "origins": []}
    assert R._auth_evidence(st, [200, 401], now=0) == "unauthorized_api"
    assert R._auth_evidence(st, [401, 200], now=0) is None
    assert R._auth_evidence(st, [], now=0) is None  # server-rendered cookie app: page checks decide


@requires_browser
def test_layer1_app_stuck_on_shell_is_not_success(tmp_path, fx):
    # renewal silently fails and the SPA neither redirects to /login nor calls the
    # API: the restored, still-expired token must NOT be reported as refreshed.
    fx.app_uses_rt = False
    fx.app_silent_renew = False
    fx.fail_mode = "stay"
    profile, sess = _setup(tmp_path, fx)
    res = _run(profile, sess, fx)
    assert not res.ok and res.reason == "token_not_renewed"


@requires_browser
def test_layer1_redirect_set_cookie_lands_in_profile(tmp_path, fx):
    # the IdP's 302 re-issues a (sliding) SSO cookie; going through the redirect
    # trampoline must not drop it, or keep-alive would never extend the session
    fx.app_uses_rt = False
    profile, sess = _setup(tmp_path, fx)
    assert _run(profile, sess, fx).ok
    assert fx.touch_count >= 1

    async def cookies():
        p, ctx = await R._launch_headless(profile)
        try:
            return await ctx.cookies()
        finally:
            await ctx.close()
            await p.stop()

    names = {(c["name"], c["domain"]) for c in asyncio.run(cookies())}
    assert ("idp_touch", "idp.localhost") in names
    assert ("idp_csrf", "idp.localhost") in names  # BOTH Set-Cookie headers of the 302 landed


# ------------------------------------------- strict renewal policy (security review)

def _strict(learned=(), resolver=None, **kw):
    eng = scope_guard.Engagement(target="t.com", in_scope=["*.t.com"], **kw)
    return R.RenewalPolicy(engagement=eng, learned=list(learned), resolver=resolver or (lambda h: False))


def test_policy_ignores_scope_guard_safe_host_shortcut():
    p = _strict()
    for host in ("evil.sh", "attacker.zip", "x.py", "localhost", "127.0.0.1", "10.0.0.5",
                 "169.254.169.254", "example.com", "github.com"):
        assert not p.allowed(host), host
    assert p.allowed("app.t.com")


def test_policy_learned_or_builtin_host_resolving_private_is_refused():
    p = _strict(learned=["sso.corp.example"], resolver=lambda h: True)
    assert not p.allowed("sso.corp.example")
    assert not p.allowed("acme.auth0.com")


def test_policy_ip_literals_only_when_explicitly_in_scope():
    assert not _strict(learned=["127.0.0.1"]).allowed("127.0.0.1")
    eng = scope_guard.Engagement(target="lab", in_scope=["10.0.0.5"])
    assert R.RenewalPolicy(engagement=eng).allowed("10.0.0.5")


def test_real_resolver_flags_loopback_and_metadata():
    assert R._resolves_non_public("127.0.0.1") and R._resolves_non_public("169.254.169.254")
    assert R._resolves_non_public("localhost")
    assert R._resolves_non_public("no-such-host.invalid")


def test_route_blocks_iframe_document_to_operator_localhost():
    p = _strict()
    assert R.route_decision("GET", "http://127.0.0.1:9876/", "document", False, p) == \
        ("abort", "blocked_host:127.0.0.1")
    assert R.route_decision("GET", "http://evil.sh:9876/x", "document", True, p) == \
        ("abort", "blocked_host:evil.sh")


def test_auth_evidence_one_fresh_entry_is_enough():
    st = _tok_state(1000)
    st[SIDE]["http://127.0.0.1:1"]["oidc.user:http://idp:other"] = json.dumps({"access_token": "a.b.c",
                                                                              "expires_at": 9000})
    assert R._auth_evidence(st, [], now=2000) is None


def test_auth_evidence_ignores_out_of_scope_origin_entries():
    assert R._auth_evidence(_tok_state(1000), [], now=2000, origin_ok=lambda o: False) is None
