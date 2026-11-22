"""Spec 2 (SSO surface), Task 5: the repeat (user decision B: one extra
request per flow, compare state/nonce in memory) and discovery, map mode
only, against the fixture RP + the local mock IdP."""

import asyncio
import contextlib
import json
import os
import sys
from urllib.parse import urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm
import ui_walk
from budget_guard import BudgetExceeded
from mock_idp import MockIdP, image_present
from ui_walk_app import requires_browser, serve


def _scope_both(u):
    return urlsplit(u).hostname in ("127.0.0.1", "localhost")


def _scope_rp_only(u):
    return urlsplit(u).hostname == "127.0.0.1"


class _Env:
    """Every resource is registered on an ExitStack as soon as it exists, so
    close() (or a failure in __init__) always stops containers and the app."""

    def __init__(self, tmp_path_factory, vulnerable):
        if not image_present():
            pytest.skip("needs podman + the mock IdP image")
        self._stack = contextlib.ExitStack()
        try:
            self.mp = pytest.MonkeyPatch()
            self._stack.callback(self.mp.undo)
            self.mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
            self.mp.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path_factory.mktemp("uw")))
            self.idp_login = MockIdP(interactive=True)
            self._stack.callback(self.idp_login.close)
            self.idp_sess = MockIdP(interactive=False)
            self._stack.callback(self.idp_sess.close)
            self.app = serve(vulnerable=vulnerable, sso_login_issuer=self.idp_login.issuer_url,
                             sso_session_issuer=self.idp_sess.issuer_url)
            self._stack.callback(self.app.close)
            self.sf = str(tmp_path_factory.mktemp("sess") / "s.json")
            self.app.write_session_file(self.sf)
            self.shots = str(tmp_path_factory.mktemp("shots"))
        except BaseException:
            self._stack.close()
            raise

    def walk(self, scope, **kw):
        return asyncio.run(ui_walk.walk(self.app.base_url + "/sso", "map", scope_check=scope,
                                        session_file=self.sf, screenshot_dir=self.shots,
                                        **{"max_pages": 25, **kw}))

    def close(self):
        self._stack.close()


def _module_walk(tmp_path_factory, vulnerable, scope):
    env = _Env(tmp_path_factory, vulnerable)
    try:
        inv = env.walk(scope)
    except BaseException:
        env.close()
        raise
    return env, inv


@pytest.fixture(scope="module")
def vuln(tmp_path_factory):
    env, inv = _module_walk(tmp_path_factory, True, _scope_both)
    yield env, inv
    env.close()


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    env, inv = _module_walk(tmp_path_factory, False, _scope_both)
    yield env, inv
    env.close()


@pytest.fixture(scope="module")
def oos(tmp_path_factory):
    env, inv = _module_walk(tmp_path_factory, True, _scope_rp_only)
    yield env, inv
    env.close()


def _flow(inv, idp, client="fixture-app", rtype="code"):
    netloc = urlsplit(idp.base_url).netloc
    return next(f for f in inv["sso"]["flows"] if f["idp_host"] == netloc
                and f["authorize"]["client_id"] == client and f["authorize"]["response_type"] == rtype)


def _rp_hits(env, path):
    return [r for r in env.app.host_requests if urlsplit(r[2]).path == path]


@requires_browser
def test_static_state_detected_vulnerable(vuln):
    env, inv = vuln
    assert inv["status"] == "complete", inv["error"]
    for f in (_flow(inv, env.idp_login), _flow(inv, env.idp_sess), _flow(inv, env.idp_login, "fixture-spa")):
        assert f["repeat"]["result"] == "compared", f
        assert f["state_changes_per_request"] is False
        assert f["nonce_changes_per_request"] is False
    kinds = {f["authorize"]["client_id"]: f["repeat"]["kind"] for f in inv["sso"]["flows"] if f["repeat"]}
    assert kinds["fixture-spa"] == "c"


@requires_browser
def test_random_state_patched(patched):
    env, inv = patched
    assert inv["status"] == "complete", inv["error"]
    for f in (_flow(inv, env.idp_login), _flow(inv, env.idp_sess), _flow(inv, env.idp_login, "fixture-spa")):
        assert f["state_changes_per_request"] is True, f
        assert f["nonce_changes_per_request"] is True


@requires_browser
def test_repeat_caps(vuln):
    _env, inv = vuln
    assert 1 <= inv["sso"]["repeats"] <= 5
    assert sum(1 for f in inv["sso"]["flows"] if f["repeat"]) <= 5


@requires_browser
def test_repeat_a_does_not_follow_redirects(vuln):
    env, inv = vuln
    kind_a = sum(1 for f in inv["sso"]["flows"] if (f["repeat"] or {}).get("kind") == "a")
    assert kind_a >= 1
    rp = len(_rp_hits(env, "/sso/login-silent")) + len(_rp_hits(env, "/sso/login-implicit"))
    # every browser visit of those RP URLs was followed to the session IdP; the repeat's GET was not
    assert len([p for p in env.idp_sess.paths() if p.endswith("/authorize")]) == rp - kind_a


@requires_browser
def test_discovery_at_issuer(vuln):
    env, inv = vuln
    ok = [d for d in inv["sso"]["discovery"] if d["status"] == 200]
    issuers = {d["issuer"] for d in ok}
    assert env.idp_login.issuer_url in issuers
    assert 1 <= inv["sso"]["discovery_gets"] <= 9
    disc = {(e["role"], e["url"]) for e in inv["sso"]["endpoints"] if e["seen_via"] == "discovery"}
    base = env.idp_login.issuer_url
    for role, path in (("token", "/token"), ("logout", "/endsession"), ("jwks", "/jwks"),
                       ("userinfo", "/userinfo"), ("revocation", "/revoke"), ("introspection", "/introspect")):
        assert (role, base + path) in disc, (role, disc)
    tok = next(e for e in inv["sso"]["endpoints"] if e["seen_via"] == "discovery" and e["role"] == "token")
    assert tok["method"] == "POST" and tok["in_scope"] is True


@requires_browser
def test_discovery_gets_never_more_than_three_per_host(vuln):
    env, _inv = vuln
    for idp in (env.idp_login, env.idp_sess):
        assert sum(1 for p in idp.paths() if "/.well-known/" in p) <= 3


@requires_browser
def test_oos_no_discovery_and_no_extra_idp_gets(oos):
    env, inv = oos
    assert inv["status"] == "complete", inv["error"]
    for idp in (env.idp_login, env.idp_sess):
        assert not [p for p in idp.paths() if "/.well-known/" in p]
    assert inv["sso"]["discovery"] == [] and inv["sso"]["discovery_gets"] == 0
    # only kind a runs for an out-of-scope IdP (it never follows the redirect); b/c are skipped
    for f in inv["sso"]["flows"]:
        r = f["repeat"] or {}
        if r.get("kind") in ("b", "c"):
            assert r["result"] == "skipped-out-of-scope-idp", f
    kind_a = sum(1 for f in inv["sso"]["flows"] if (f["repeat"] or {}).get("kind") == "a")
    rp = len(_rp_hits(env, "/sso/login-silent")) + len(_rp_hits(env, "/sso/login-implicit"))
    assert len([p for p in env.idp_sess.paths() if p.endswith("/authorize")]) == rp - kind_a


@requires_browser
def test_no_secret_in_inventories(vuln, patched, oos):
    for env, inv in (vuln, patched, oos):
        dump = json.dumps(inv)
        for s in set(env.app.issued_secrets):
            if s:
                assert s not in dump


@requires_browser
def test_budget_exhausted_mid_repeat(tmp_path_factory, monkeypatch):
    env = _Env(tmp_path_factory, True)
    state = {"in_repeat": False}
    orig = ui_walk._Walker._run_sso_repeats

    async def flagged(self):
        state["in_repeat"] = True
        try:
            return await orig(self)
        finally:
            state["in_repeat"] = False

    def budget(*_a, **_k):
        if state["in_repeat"]:
            raise BudgetExceeded("test budget exhausted")
        return {}

    monkeypatch.setattr(ui_walk._Walker, "_run_sso_repeats", flagged)
    env.mp.setattr(browser_confirm, "_enforce_budget", budget)
    try:
        inv = env.walk(_scope_both, max_pages=8)
    finally:
        env.close()
    assert inv["status"] == "budget_exhausted", inv["error"]
    dump = json.dumps(inv)
    for s in set(env.app.issued_secrets):
        if s:
            assert s not in dump


def test_canary_mode_runs_no_repeat_or_discovery():
    w = ui_walk._Walker("http://127.0.0.1:1/", "canary", scope=lambda u: True, max_pages=1,
                        max_clicks_per_page=1, same_origin_only=True, wall_clock_s=10, action_delay_s=0,
                        screenshot_dir=None, had_session=False, session_file=None, auth={}, walk_id="w")
    w.sso.observe_chain(["http://127.0.0.1:1/login",
                         "http://127.0.0.1:2/authorize?client_id=c&response_type=code&state=s1s1s1s1"],
                        page="http://127.0.0.1:1/", control_signature=None)
    assert w.sso.pending_repeats() and w.sso.data["idp_hosts"]
    asyncio.run(w._run_sso_repeats())
    asyncio.run(w._run_sso_discovery())
    assert w.sso.data["repeats"] == 0 and w.sso.data["discovery_gets"] == 0


# ------------------------------------------------------- Task 6: candidates

def _ctypes(inv):
    return {c["type"] for c in inv["candidates"]}


@requires_browser
def test_vulnerable_sso_candidates(vuln):
    _env, inv = vuln
    t = _ctypes(inv)
    for want in ("sso-state-candidate", "sso-pkce-candidate", "sso-implicit-flow-candidate",
                 "sso-logout-redirect-candidate", "sso-redirect-uri-candidate", "sso-nonce-candidate"):
        assert want in t, (want, t)
    static = [c for c in inv["candidates"] if c["type"] == "sso-state-candidate"]
    assert any("static" in c["detail"]["reasons"] for c in static)


@requires_browser
def test_patched_sso_candidates(patched):
    _env, inv = patched
    t = _ctypes(inv)
    assert "sso-pkce-candidate" not in t and "sso-implicit-flow-candidate" not in t
    assert not [c for c in inv["candidates"] if c["type"] == "sso-state-candidate"
                and "static" in c["detail"]["reasons"]]
    assert "sso-redirect-uri-candidate" in t   # a lead for spec 3 either way


@requires_browser
def test_oos_only_app_side_candidates(oos):
    _env, inv = oos
    t = _ctypes(inv)
    assert not t & {"sso-redirect-uri-candidate", "sso-pkce-candidate", "sso-logout-redirect-candidate",
                    "sso-registration-candidate"}
