"""#164 UI-walk event recorder, Task 6: the optional Burp mirror.

A stdlib stand-in proxy (tests/fixtures/ui_walk_target/standin_proxy.py) plays
Burp on 127.0.0.1. Pinned here: with the mirror on, everything the walker
really sent went through the proxy and nothing it aborted did; an unreachable
proxy or a target that refuses proxied traffic falls back to direct and says
so; a block mid-walk stops the walk (no mode switch); only loopback proxies
are accepted; "off" beats the env var; a walk without the mirror is unchanged
and never runs block detection; the direct fallback keeps TLS checks on.
"""

import asyncio
import os
import socket
import sys
from collections import Counter
from urllib.parse import urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm  # noqa: E402
import browser_launch  # noqa: E402
import tool_resolver  # noqa: E402
import ui_walk  # noqa: E402
import ui_walk_teardown as T  # noqa: E402
from standin_proxy import StandinProxy  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402
from ui_walk_grant import Grant  # noqa: E402

PASS2_FETCH_LIMIT = "Pass-2 real submits are sent by Playwright's fetch and do not appear in Burp"


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


def _mirror(inv):
    return inv["burp_mirror"]


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path / "ui-walk"))
    monkeypatch.delenv("HUNTMCP_UPSTREAM_PROXY", raising=False)
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})


@pytest.fixture
def proxy():
    p = StandinProxy()
    yield p
    p.stop()


class _Spies:
    """Records launch kwargs, context options and classify_block calls."""

    def __init__(self, mp):
        self.launches: list[dict] = []
        self.ctx_opts: list[dict] = []
        self.classify_calls = 0
        real_launch, real_new_page, real_classify = (browser_confirm._launch_kwargs, browser_confirm._new_page,
                                                     tool_resolver.classify_block)

        def launch(*a, **k):
            out = real_launch(*a, **k)
            self.launches.append(out)
            return out

        async def new_page(*a, **k):
            self.ctx_opts.append(dict(k.get("context_options") or {}))
            return await real_new_page(*a, **k)

        def classify(body):
            self.classify_calls += 1
            return real_classify(body)

        real_block_kind = ui_walk._Walker._block_kind
        self.block_checks = 0

        async def block_kind(walker, resp):
            self.block_checks += 1
            return await real_block_kind(walker, resp)

        mp.setattr(ui_walk._Walker, "_block_kind", block_kind)
        mp.setattr(browser_confirm, "_launch_kwargs", launch)
        mp.setattr(browser_confirm, "_new_page", new_page)
        mp.setattr(tool_resolver, "classify_block", classify)


def _walk_isolated(tmp_path_factory, start, app, *, spies=False, **kw):
    """One walk with its own registry dir and budget stub (module fixtures)."""
    mp = pytest.MonkeyPatch()
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    mp.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path_factory.mktemp("uw")))
    mp.delenv("HUNTMCP_UPSTREAM_PROXY", raising=False)
    sp = _Spies(mp) if spies else None
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + start, "map", scope_check=_scope,
                                       cookie_header=app.login_cookie(),
                                       screenshot_dir=str(tmp_path_factory.mktemp("shots")), **kw))
    finally:
        mp.undo()
    return inv, sp


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------------------- launch kwargs

def test_launch_kwargs_without_proxy_is_unchanged():
    base = browser_launch.launch_kwargs()
    assert "proxy" not in base
    assert not any(a.startswith("--proxy") for a in base["args"])
    assert browser_launch.launch_kwargs(proxy=None) == base
    assert browser_launch.launch_kwargs(True, None) == base


def test_launch_kwargs_with_proxy():
    k = browser_launch.launch_kwargs(proxy="http://127.0.0.1:8080")
    assert k["proxy"] == {"server": "http://127.0.0.1:8080"}
    assert k["args"][-1] == "--proxy-bypass-list=<-loopback>"
    # the non-mirror args, then (mirror only) the flags keeping Chromium's own
    # background traffic off the human's proxy
    assert k["args"][:-1] == browser_launch.launch_kwargs()["args"] + list(browser_launch.MIRROR_QUIET_ARGS)
    assert "--disable-background-networking" in k["args"] and "--disable-component-update" in k["args"]


# ------------------------------------------------------------- refusals (no browser)

@pytest.mark.parametrize("bad", ["http://10.1.2.3:8080", "http://burp.example.com:8080",
                                 "socks5://127.0.0.1:1080", "http://127.0.0.1", "http://u:pw@127.0.0.1:8080",
                                 "http://127.0.0.1:8080/pwpath", "http://127.0.0.1:8080?pw=1",
                                 "http://127.0.0.1:8080#pw"])
def test_remote_proxy_refused(bad, monkeypatch):
    def no_launch(*a, **k):
        raise AssertionError("browser must not launch for a refused proxy")

    monkeypatch.setattr(ui_walk._Walker, "run", no_launch)
    inv = asyncio.run(ui_walk.walk("http://127.0.0.1:9/", "map", scope_check=_scope, upstream_proxy=bad))
    assert inv["status"] == "refused"
    assert inv["error"].startswith("upstream_proxy refused: ")
    assert "pw@" not in inv["error"] and "pw" not in str(inv["burp_mirror"])
    assert _mirror(inv)["active"] is False


def test_remote_proxy_from_env_refused(monkeypatch):
    monkeypatch.setattr(ui_walk._Walker, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setenv("HUNTMCP_UPSTREAM_PROXY", "http://10.1.2.3:8080")
    inv = asyncio.run(ui_walk.walk("http://127.0.0.1:9/", "map", scope_check=_scope))
    assert inv["status"] == "refused" and inv["error"].startswith("upstream_proxy refused: ")


def test_teardown_execute_refuses_remote_proxy(monkeypatch):
    monkeypatch.setattr(ui_walk._Walker, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    plan = {"base_url": "http://127.0.0.1:9/", "identity": "keep", "steps": ["logout"], "notes": [],
            "cleanup_tokens": [], "session": T.session_ref(None, "sid=x")}
    r = asyncio.run(T.execute(plan, cookie_header="sid=x", scope_check=_scope,
                              upstream_proxy="http://10.1.2.3:8080"))
    assert r["status"] == "refused" and r["error"].startswith("upstream_proxy refused: ")


# ------------------------------------------------------------- mirror on, target fine

@pytest.fixture(scope="module")
def mirrored(tmp_path_factory):
    p = StandinProxy()
    app = serve()
    try:
        inv, _ = _walk_isolated(tmp_path_factory, "/", app, upstream_proxy=p.url, max_pages=5)
        yield app, p, inv
    finally:
        app.close()
        p.stop()


@requires_browser
def test_mirror_every_sent_request_went_through_proxy(mirrored):
    app, p, inv = mirrored
    assert inv["status"] == "complete", inv["error"]
    assert _mirror(inv) == {"requested": True, "active": True, "proxy": p.url, "reason": None}
    received = Counter(app.requests)
    proxied = Counter(p.paths_for_port(app.port))
    assert len(inv["pages"]) >= 3 and sum(received.values()) >= 3
    assert received == proxied          # nothing reached the fixture around the proxy
    # Chromium's own background traffic (e.g. clients2.google.com) also goes to
    # the proxy; the stand-in refuses it. None of it was fixture traffic.
    assert not [t for _m, t in p.refused if f":{app.port}" in t]


@requires_browser
def test_mirror_aborted_requests_never_reach_proxy(mirrored):
    app, p, inv = mirrored
    aborted = [(e["method"], e["url"]) for pg in inv["pages"] for e in pg["api_edges"]
               if not e["sent"] and e["method"] != "GET"]
    assert aborted, "the start page has buttons that POST; Pass 1 must have aborted them"
    assert {m for m, _ in p.log} <= {"GET"}
    assert not any((m, u) in p.log for m, u in aborted)
    assert not app.non_get_requests()


@requires_browser
def test_mirror_honest_limit_states_tls(mirrored):
    _, _, inv = mirrored
    assert any("ignore_https_errors" in h for h in inv["honest_limits"])


# ------------------------------------------------------------- unreachable proxy

@requires_browser
def test_mirror_unreachable_falls_back_direct_loudly(tmp_path_factory):
    app = serve()
    dead = f"http://127.0.0.1:{_closed_port()}"
    try:
        inv, sp = _walk_isolated(tmp_path_factory, "/", app, spies=True, upstream_proxy=dead, max_pages=2)
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    assert _mirror(inv) == {"requested": True, "active": False, "proxy": dead, "reason": "proxy unreachable",
                            "detail": "TCP connect to the proxy failed"}
    assert app.requests                                    # the walk ran, direct
    assert all("proxy" not in k for k in sp.launches)
    assert all("ignore_https_errors" not in o for o in sp.ctx_opts)
    assert sp.classify_calls == 0 and sp.block_checks == 0   # block detection is mirror-mode only


# ------------------------------------------------------------- target refuses proxied traffic

@pytest.fixture(scope="module")
def refused(tmp_path_factory):
    p = StandinProxy()
    app = serve(refuse_proxied=True)
    try:
        inv, sp = _walk_isolated(tmp_path_factory, "/", app, spies=True, upstream_proxy=p.url, max_pages=3)
        yield app, p, inv, sp
    finally:
        app.close()
        p.stop()


@requires_browser
def test_mirror_refused_falls_back_direct(refused):
    app, p, inv, _sp = refused
    assert inv["status"] == "complete", inv["error"]
    assert _mirror(inv) == {"requested": True, "active": False, "proxy": p.url,
                            "reason": "target refused proxied traffic", "detail": "HTTP 403 (waf)"}
    proxied = p.paths_for_port(app.port)
    assert ("GET", "/") in proxied
    assert set(proxied) <= {("GET", "/"), ("GET", "/favicon.ico")}   # only the refused start load
    assert inv["pages"][0]["title"] == "Home"                         # the real page, mapped direct
    assert not any(pg["title"] == "Access denied" for pg in inv["pages"])
    assert len(app.requests) > len(proxied)                           # the rest of the walk went direct


@requires_browser
def test_direct_fallback_has_tls_checks(refused):
    _app, p, _inv, sp = refused
    assert len(sp.launches) == 2 and len(sp.ctx_opts) == 2
    assert sp.launches[0]["proxy"] == {"server": p.url}
    assert sp.ctx_opts[0].get("ignore_https_errors") is True          # mirror mode only
    assert "proxy" not in sp.launches[1]
    assert not any(a.startswith("--proxy") for a in sp.launches[1]["args"])
    assert "ignore_https_errors" not in sp.ctx_opts[1]                 # direct: TLS checks on


@requires_browser
def test_mirror_blocked_via_proxy_and_direct(tmp_path_factory):
    # R11: the start page is a block page through the proxy AND directly
    p = StandinProxy()
    app = serve(refuse_all=True)
    try:
        inv, sp = _walk_isolated(tmp_path_factory, "/", app, spies=True, upstream_proxy=p.url, max_pages=3)
    finally:
        app.close()
        p.stop()
    assert _mirror(inv) == {"requested": True, "active": False, "proxy": p.url,
                            "reason": "blocked via proxy and direct",
                            "detail": "proxy: HTTP 403 (waf); direct: HTTP 403 (waf)"}
    assert inv["status"] == "blocked", (inv["status"], inv["error"])
    assert "not a proxy problem" in inv["error"]
    assert not inv["pages"]
    assert ("GET", "/") in p.paths_for_port(app.port)                 # one proxied start load ...
    assert len(sp.launches) == 2 and "proxy" not in sp.launches[1]    # ... and one direct comparison
    assert app.requests.count(("GET", "/")) == 2


# ------------------------------------------------------------- block mid-walk (R12)

SUSPECT = "proxy-block-suspected"


def _mx_walk(tmp_path_factory, start, **serve_kw):
    p = StandinProxy()
    app = serve(**serve_kw)
    try:
        inv, sp = _walk_isolated(tmp_path_factory, start, app, spies=True, upstream_proxy=p.url, max_pages=8)
    finally:
        app.close()
        p.stop()
    assert len(sp.launches) == 1                                      # never a switch to direct mid-walk
    assert Counter(app.requests) == Counter(p.paths_for_port(app.port))
    return inv, p


def _by_path(inv):
    return {urlsplit(pg["url"]).path: pg for pg in inv["pages"]}


@requires_browser
def test_mirror_single_block_page_is_marked_and_walk_continues(tmp_path_factory):
    # /mx/a: deny/1, deny/2, ok/1, deny/3 -- the app's own "Access denied" 403s,
    # never three in a row (ok/1 resets the count)
    inv, p = _mx_walk(tmp_path_factory, "/mx/a")
    assert inv["status"] == "complete", inv["error"]
    assert _mirror(inv) == {"requested": True, "active": True, "proxy": p.url, "reason": None}
    pages = _by_path(inv)
    for d in ("/mx/deny/1", "/mx/deny/2", "/mx/deny/3"):
        assert pages[d]["auth_state"] == SUSPECT, d
        assert pages[d]["nav_error"] == f"{SUSPECT}: HTTP 403 (waf)"
        assert not pages[d]["controls"]                               # a block page is never clicked through
    assert pages["/mx/ok/1"]["auth_state"] == "ok" and pages["/mx/ok/1"]["title"] == "OK 1"


@requires_browser
def test_mirror_three_block_pages_in_a_row_stop(tmp_path_factory):
    # /mx/b: deny/1, deny/2, deny/3, ok/1
    inv, p = _mx_walk(tmp_path_factory, "/mx/b")
    assert inv["status"] == "blocked", (inv["status"], inv["error"])
    assert _mirror(inv) == {"requested": True, "active": True, "proxy": p.url, "reason": "blocked mid-walk",
                            "detail": "HTTP 403 (waf), 3 page loads in a row"}
    pages = _by_path(inv)
    assert pages["/mx/deny/1"]["auth_state"] == SUSPECT and pages["/mx/deny/2"]["auth_state"] == SUSPECT
    assert "/mx/ok/1" not in pages                                    # stopped before it
    assert "127.0.0.1" in inv["error"] and "/mx/deny/3" not in inv["error"]   # host only (shown unquarantined)
    assert "re-run with the mirror off" in inv["error"]


@requires_browser
def test_mirror_proxy_caused_blocks_mid_walk_stop(tmp_path_factory):
    # the hub loads; every later proxied request is refused: ok/1..3 -> 3 in a row
    inv, _p = _mx_walk(tmp_path_factory, "/mx/c", refuse_proxied_after=1)
    assert inv["status"] == "blocked", (inv["status"], inv["error"])
    assert _mirror(inv)["reason"] == "blocked mid-walk"
    assert [urlsplit(pg["url"]).path for pg in inv["pages"]] == ["/mx/c", "/mx/ok/1", "/mx/ok/2"]


@requires_browser
def test_mirror_block_after_click_navigation_is_marked(tmp_path_factory):
    # on "/", clicking the nav "Home" link re-loads "/" -- that click-driven
    # navigation gets the block page: "/" is marked, not mapped further
    inv, _p = _mx_walk(tmp_path_factory, "/", refuse_proxied_after=1)
    assert inv["status"] == "complete", inv["error"]
    home = _by_path(inv)["/"]
    assert home["auth_state"] == SUSPECT and home["nav_error"] == f"{SUSPECT}: HTTP 403 (waf)"


# ------------------------------------------------------------- env / off / non-mirror

@requires_browser
def test_off_sentinel_beats_env(proxy, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_UPSTREAM_PROXY", proxy.url)
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/", "map", scope_check=_scope, max_pages=1,
                                       cookie_header=app.login_cookie(), screenshot_dir=str(tmp_path),
                                       upstream_proxy="off"))
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    assert _mirror(inv) == {"requested": False, "active": False, "proxy": None, "reason": None}
    assert app.requests and not proxy.log


@requires_browser
def test_env_proxy_used_when_param_empty(proxy, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_UPSTREAM_PROXY", proxy.url)
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/", "map", scope_check=_scope, max_pages=1,
                                       cookie_header=app.login_cookie(), screenshot_dir=str(tmp_path)))
    finally:
        app.close()
    assert _mirror(inv) == {"requested": True, "active": True, "proxy": proxy.url, "reason": None}
    assert ("GET", "/") in proxy.paths_for_port(app.port)


@requires_browser
def test_non_mirror_walk_unchanged(tmp_path, monkeypatch):
    sp = _Spies(monkeypatch)
    app = serve()
    try:
        # /mx/a serves 403 "Access denied" pages: without the mirror they are mapped as in #164
        inv = asyncio.run(ui_walk.walk(app.base_url + "/mx/a", "map", scope_check=_scope, max_pages=3,
                                       cookie_header=app.login_cookie(), screenshot_dir=str(tmp_path)))
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    assert [urlsplit(pg["url"]).path for pg in inv["pages"]] == ["/mx/a", "/mx/deny/1", "/mx/deny/2"]
    assert not any(pg["auth_state"] == SUSPECT for pg in inv["pages"])
    # auto mode (2026-11-21 addendum): nothing on the auto port -> direct, and it says why
    assert _mirror(inv) == {"requested": False, "active": False, "proxy": None, "reason": None,
                            "auto": "no Burp detected"}
    assert sp.launches == [browser_launch.launch_kwargs()]   # exactly the old launch options
    assert all("ignore_https_errors" not in o for o in sp.ctx_opts)
    assert sp.classify_calls == 0 and sp.block_checks == 0   # block detection never runs without the mirror
    assert not any("ignore_https_errors" in h for h in inv["honest_limits"])


# ------------------------------------------------------------- auto mode (2026-11-21 addendum)

@pytest.fixture
def fake_burp():
    p = StandinProxy(banner="<html><head><title>Burp Suite Professional</title></head></html>")
    yield p
    p.stop()


@requires_browser
def test_auto_mode_detects_burp_and_mirrors(fake_burp, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BURP_AUTO_PORT", str(fake_burp.port))
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/", "map", scope_check=_scope, max_pages=2,
                                       cookie_header=app.login_cookie(), screenshot_dir=str(tmp_path)))
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    m = _mirror(inv)
    assert m["active"] is True and m["requested"] is True and m["auto"] == "Burp detected"
    assert m["proxy"] == f"http://127.0.0.1:{fake_burp.port}"
    assert ("GET", "/") in fake_burp.paths_for_port(app.port)       # the walk really went through it
    assert not [x for x in fake_burp.paths_for_port(app.port) if x[0] not in ("GET", "HEAD", "OPTIONS")]


@requires_browser
def test_auto_mode_other_program_on_port_stays_direct(proxy, tmp_path, monkeypatch):
    # something IS listening on the auto port, but it is not Burp (no banner): never route through it
    sp = _Spies(monkeypatch)
    monkeypatch.setenv("HUNTMCP_BURP_AUTO_PORT", str(proxy.port))
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/", "map", scope_check=_scope, max_pages=2,
                                       cookie_header=app.login_cookie(), screenshot_dir=str(tmp_path)))
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    assert _mirror(inv)["active"] is False and _mirror(inv)["auto"] == "no Burp detected"
    assert proxy.paths_for_port(app.port) == []
    assert sp.launches == [browser_launch.launch_kwargs()]


def test_auto_detection_sends_nothing_but_one_get_to_the_listener(fake_burp, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BURP_AUTO_PORT", str(fake_burp.port))
    assert ui_walk._detect_burp() == f"http://127.0.0.1:{fake_burp.port}"
    assert fake_burp.log == [] and fake_burp.connects == []   # its own page only, nothing forwarded


def test_auto_detection_bad_port_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("HUNTMCP_BURP_AUTO_PORT", "not-a-port")
    assert ui_walk._auto_port() == 8080
    monkeypatch.setenv("HUNTMCP_BURP_AUTO_PORT", "70000")
    assert ui_walk._auto_port() == 8080


@requires_browser
def test_off_beats_auto(fake_burp, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BURP_AUTO_PORT", str(fake_burp.port))
    called = []
    monkeypatch.setattr(ui_walk, "_detect_burp", lambda: called.append(1))
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/", "map", scope_check=_scope, max_pages=1,
                                       cookie_header=app.login_cookie(), screenshot_dir=str(tmp_path),
                                       upstream_proxy="off"))
    finally:
        app.close()
    assert called == [] and _mirror(inv)["active"] is False and "auto" not in _mirror(inv)
    assert fake_burp.paths_for_port(app.port) == []


import http.server as _hs  # noqa: E402
import threading as _th  # noqa: E402
import time as _time  # noqa: E402


def _listener(handler_body):
    """A tiny loopback HTTP server whose GET / runs handler_body(self)."""
    class H(_hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            handler_body(self)
    srv = _hs.ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _send(h, status, body=b"", headers=()):
    h.send_response(status)
    for k, v in headers:
        h.send_header(k, v)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


@pytest.fixture(scope="module")
def module_scoped_env_seen():
    # module-scoped fixtures run BEFORE function-scoped autouse ones: isolation must already hold here
    return os.environ.get("HUNTMCP_BURP_AUTO_PORT")


def test_auto_isolation_holds_for_module_scoped_fixtures(module_scoped_env_seen):
    assert module_scoped_env_seen == "1"


def test_auto_detection_does_not_follow_redirects(fake_burp, monkeypatch):
    target = fake_burp.port
    srv = _listener(lambda h: _send(h, 302, headers=[("Location", f"http://127.0.0.1:{target}/")]))
    try:
        monkeypatch.setenv("HUNTMCP_BURP_AUTO_PORT", str(srv.server_address[1]))
        assert ui_walk._detect_burp() is None   # the "Burp" page was not served by the listener itself
    finally:
        srv.shutdown()


def test_auto_detection_requires_status_200():
    srv = _listener(lambda h: _send(h, 404, b"<title>Burp Suite Professional</title>"))
    try:
        os.environ["HUNTMCP_BURP_AUTO_PORT"] = str(srv.server_address[1])
        assert ui_walk._detect_burp() is None
    finally:
        os.environ["HUNTMCP_BURP_AUTO_PORT"] = "1"
        srv.shutdown()


def test_auto_detection_total_time_is_bounded(monkeypatch):
    def drip(h):
        h.send_response(200)
        h.send_header("Content-Length", "100000")
        h.end_headers()
        for _ in range(40):
            h.wfile.write(b"x")
            h.wfile.flush()
            _time.sleep(0.5)
    srv = _listener(drip)
    try:
        monkeypatch.setenv("HUNTMCP_BURP_AUTO_PORT", str(srv.server_address[1]))
        t0 = _time.monotonic()
        assert ui_walk._detect_burp() is None
        assert _time.monotonic() - t0 < 4.0
    finally:
        srv.shutdown()


@requires_browser
def test_auto_detected_but_unreachable_keeps_auto_key(tmp_path, monkeypatch):
    monkeypatch.setattr(ui_walk, "_detect_burp", lambda: "http://127.0.0.1:1")
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/", "map", scope_check=_scope, max_pages=1,
                                       cookie_header=app.login_cookie(), screenshot_dir=str(tmp_path)))
    finally:
        app.close()
    m = _mirror(inv)
    assert m["active"] is False and m["reason"] == "proxy unreachable" and m["auto"] == "Burp detected"


# ------------------------------------------------------------- Pass 2 / teardown through the mirror

@requires_browser
def test_pass2_real_submit_reaches_proxy(proxy, tmp_path):
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/p2contact", "canary", scope_check=_scope, max_pages=1,
                                       cookie_header=app.login_cookie(), screenshot_dir=str(tmp_path),
                                       grant=Grant(True, [], 200), upstream_proxy=proxy.url))
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    assert ("POST", "/api/contact") in app.non_get_requests()          # the real submit was sent
    assert ("POST", "/api/contact") in proxy.paths_for_port(app.port)  # ... and Burp saw it
    assert PASS2_FETCH_LIMIT not in inv["honest_limits"]
    assert Counter(app.requests) == Counter(proxy.paths_for_port(app.port))


@requires_browser
def test_teardown_goes_through_mirror(proxy, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_TEST_IDENTITIES", str(tmp_path / "none.yaml"))
    sp = _Spies(monkeypatch)
    app = serve()
    try:
        cookie = app.login_cookie()
        plan = {"base_url": app.base_url + "/", "identity": "keep", "steps": ["logout"], "notes": [],
                "cleanup_tokens": [], "session": T.session_ref(None, cookie)}
        r = asyncio.run(T.execute(plan, cookie_header=cookie, scope_check=_scope, screenshot_dir=str(tmp_path),
                                  max_pages=2, upstream_proxy=proxy.url))
    finally:
        app.close()
    assert r["status"] == "complete", r.get("error")
    assert _mirror(r["inventory"]) == {"requested": True, "active": True, "proxy": proxy.url, "reason": None}
    assert sp.launches[0]["proxy"] == {"server": proxy.url}
    assert ("GET", "/logout") in proxy.paths_for_port(app.port)
    # the logout-replay probes (context.request) go through the proxy too
    assert Counter(app.requests) == Counter(proxy.paths_for_port(app.port))


# ------------------------------------------------------------- validator hardening / setup_mirror / detail / budget

@requires_browser
def test_launch_gets_rebuilt_proxy_string(proxy, tmp_path, monkeypatch):
    sp = _Spies(monkeypatch)
    app = serve()
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/tall", "map", scope_check=_scope, max_pages=1,
                                       screenshot_dir=str(tmp_path), upstream_proxy=proxy.url + "/"))
    finally:
        app.close()
    assert sp.launches[0]["proxy"] == {"server": proxy.url}            # rebuilt, never the raw input
    assert _mirror(inv)["proxy"] == proxy.url


def _bare_walker():
    return ui_walk._Walker("http://127.0.0.1:9/", "map", scope=_scope, max_pages=1, max_clicks_per_page=1,
                           same_origin_only=True, wall_clock_s=10, action_delay_s=0, screenshot_dir=None,
                           had_session=False, session_file=None, auth={}, walk_id="t")


def test_setup_mirror_validates_its_input_and_ignores_env(proxy, monkeypatch):
    monkeypatch.setenv("HUNTMCP_UPSTREAM_PROXY", proxy.url)
    for bad in ("http://10.1.2.3:8080", "http://127.0.0.1:8080/x", "off"):
        with pytest.raises(ValueError):
            asyncio.run(_bare_walker().setup_mirror(bad))
    for off in (None, ""):
        w = _bare_walker()
        asyncio.run(w.setup_mirror(off))
        assert w.mirror_active is False and _mirror(w.inv)["requested"] is False   # the env var is not read here
    w = _bare_walker()
    asyncio.run(w.setup_mirror(proxy.url + "/"))
    assert w.proxy == proxy.url and w.mirror_active is True


@requires_browser
def test_proxy_dies_after_preflight_is_proxy_unreachable(tmp_path_factory, monkeypatch):
    p = StandinProxy()
    real = ui_walk._proxy_reachable

    def reachable_then_stop(url):
        ok = real(url)
        p.stop()            # the proxy goes away right after the preflight
        return ok

    monkeypatch.setattr(ui_walk, "_proxy_reachable", reachable_then_stop)
    app = serve()
    try:
        inv, sp = _walk_isolated(tmp_path_factory, "/tall", app, spies=True, upstream_proxy=p.url, max_pages=1)
    finally:
        app.close()
    m = _mirror(inv)
    assert inv["status"] == "complete", inv["error"]
    assert m["reason"] == "proxy unreachable" and m["active"] is False
    assert m["detail"] in ("net::ERR_PROXY_CONNECTION_FAILED", "net::ERR_TUNNEL_CONNECTION_FAILED"), m
    assert len(sp.launches) == 2 and "proxy" not in sp.launches[1]
    assert [pg["title"] for pg in inv["pages"]] == ["Tall"]            # mapped direct


@requires_browser
def test_direct_comparison_is_charged_to_the_budget_once(tmp_path_factory):
    p = StandinProxy()
    app = serve(refuse_proxied=True)
    timeline: list[str] = []
    mp = pytest.MonkeyPatch()
    mp.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path_factory.mktemp("uw")))
    mp.delenv("HUNTMCP_UPSTREAM_PROXY", raising=False)
    real_launch = browser_confirm._launch_kwargs
    mp.setattr(browser_confirm, "_launch_kwargs", lambda *a, **k: (timeline.append("launch"), real_launch(*a, **k))[1])
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: (timeline.append("budget"), {})[1])
    try:
        # /tall: one page load, nothing to click, no window.name reload
        inv = asyncio.run(ui_walk.walk(app.base_url + "/tall", "map", scope_check=_scope, max_pages=1,
                                       screenshot_dir=str(tmp_path_factory.mktemp("shots")),
                                       upstream_proxy=p.url, action_delay_s=0))
    finally:
        mp.undo()
        app.close()
        p.stop()
    assert _mirror(inv)["reason"] == "target refused proxied traffic"
    # proxied start load (1 charge), relaunch direct, the direct comparison load (exactly 1 charge)
    assert timeline == ["launch", "budget", "launch", "budget"], timeline


# ---- fix wave item 5: the mid-walk "blocked" error names the host only ------
def test_blocked_mid_walk_error_has_host_not_url():
    w = _bare_walker()
    w.mirror_active = True
    w._block_streak = ui_walk._MIRROR_BLOCK_STREAK - 1

    class _Resp:
        status = 403

        async def text(self):
            return "<h1>Access denied</h1><p>Request blocked by the edge firewall.</p>"

    with pytest.raises(ui_walk._Stop) as ei:
        asyncio.run(w._note_block(_Resp(), "http://127.0.0.1:9/mx/deny/3?code=FIXTURESECRET"))
    err = ei.value.error
    assert "127.0.0.1" in err and "/mx/deny/3" not in err and "FIXTURESECRET" not in err
    assert "re-run with the mirror off" in err


# ---- fix wave item 4: a block page reached by a click to ANOTHER URL is not counted at click time ----
@requires_browser
def test_mirror_click_to_other_url_block_page_not_counted_twice(tmp_path_factory):
    # /mx/e: clicking "Go" navigates to deny/2 (a block page at a different URL),
    # the way back to /mx/e is itself the app's 403, then deny/1, ok/1, deny/2.
    # Counting deny/2 at click time AND on its own visit would make
    # click + way-back + deny/1 three "in a row" and stop the walk.
    inv, _p = _mx_walk(tmp_path_factory, "/mx/e")
    assert inv["status"] == "complete", (inv["status"], inv["error"])
    pages = _by_path(inv)
    assert pages["/mx/e"]["auth_state"] == SUSPECT                  # its own re-load was the block page
    assert pages["/mx/deny/1"]["auth_state"] == SUSPECT
    assert pages["/mx/ok/1"]["auth_state"] == "ok"
    assert pages["/mx/deny/2"]["auth_state"] == SUSPECT              # counted once: on its own visit
    assert any(c["clicked"] for c in pages["/mx/e"]["controls"] if c["text"] == "Go")


# ---- fix wave item 12: the TLS honest limit makes no claim about the proxy's checks ----
def _tls_limit_ok(text):
    assert "ignore_https_errors" in text
    assert "validates the real server" not in text and "still validates" not in text
    assert "whatever the human's proxy is configured to do" in text


def test_mirror_tls_limit_does_not_claim_upstream_validation():
    _tls_limit_ok(ui_walk.MIRROR_TLS_LIMIT)
