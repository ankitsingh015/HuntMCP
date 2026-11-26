"""#164 UI-walk event recorder, Task 2: network-side events + inventory schema v2.

Black-box against the local fixture app's /ev/* pages: redirect chains,
Set-Cookie names+flags (never values), response security headers, console
errors tied to the click that caused them, and WebSocket client-frame
metadata (the frames themselves are never forwarded).
"""

import asyncio
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
import ui_walk_events
from ui_walk_app import requires_browser, serve

pytestmark = requires_browser


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


@pytest.fixture(scope="module")
def walked(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    # isolation only: a DOM-sink hit must never write into the live engagement's canary registry
    mp.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path_factory.mktemp("uw")))
    app = serve()
    inv = asyncio.run(ui_walk.walk(app.base_url + "/ev", "map", scope_check=_scope,
                                   screenshot_dir=str(tmp_path_factory.mktemp("shots")),
                                   cookie_header=app.login_cookie(), max_pages=40))
    yield app, inv
    app.close()
    mp.undo()


def _events(inv, type_):
    return [(p, e) for p in inv["pages"] for e in p.get("events", []) if e["type"] == type_]


def _sig(page, text):
    return next(c["signature"] for c in page["controls"] if c["text"] == text)


def test_inventory_schema_v2(walked):
    _app, inv = walked
    assert inv["status"] == "complete", inv["error"]
    assert inv["schema_version"] == 4
    assert inv["pages"]
    for p in inv["pages"]:
        assert isinstance(p["events"], list)
        assert isinstance(p["events_dropped"], int)


def test_redirect_chain_recorded(walked):
    _app, inv = walked
    chains = [e for _p, e in _events(inv, "redirect") if urlsplit(e["hops"][0]["url"]).path == "/ev/redirect"]
    assert chains, "no redirect event recorded for /ev/redirect"
    e = chains[0]
    assert len(chains) == 1, "a redirect chain must be emitted exactly once"
    assert len(e["hops"]) == 3
    assert all(isinstance(h["in_scope"], bool) and h["status"] for h in e["hops"])
    assert e["hops"][0]["status"] == 302
    assert "next" in e["param_names"]


def test_set_cookie_names_and_flags_only(walked):
    _app, inv = walked
    by_name = {e["name"]: e for _p, e in _events(inv, "set_cookie")}
    assert {"SID", "theme"} <= set(by_name)
    sid = by_name["SID"]
    assert sid["secure"] is False and sid["httponly"] is False   # vulnerable variant
    assert isinstance(sid["blocked"], list)                      # the CDP path ran
    assert sid["url"].endswith("/ev/cookies")


def test_headers_event_on_api_response(walked):
    _app, inv = walked
    hs = [e for _p, e in _events(inv, "headers") if urlsplit(e["url"]).path == "/api/cors"]
    assert hs, "no headers event for /api/cors"
    assert hs[0]["acac"] is True
    assert hs[0]["acao"].startswith("http://127.0.0.1")
    assert hs[0]["request_origin"].startswith("http://127.0.0.1")
    assert hs[0]["resource_type"] in ("fetch", "xhr")


def test_console_error_tied_to_click(walked):
    _app, inv = walked
    page = next(p for p in inv["pages"] if urlsplit(p["url"]).path == "/ev/console")
    sig = _sig(page, "Trigger fault")
    cons = [e for e in page["events"] if e["type"] == "console"]
    assert cons
    assert all(e["control_signature"] == sig for e in cons)
    assert all(len(e["text"]) <= 300 for e in cons)
    assert any("fixture" in e["text"] for e in cons)


def test_ws_client_frame_metadata_only(walked):
    app, inv = walked
    page = next(p for p in inv["pages"] if urlsplit(p["url"]).path == "/ev/ws")
    frames = [e for e in page["events"] if e["type"] == "websocket"]
    assert frames
    f = frames[0]
    assert f["direction"] == "client" and f["json_keys"] == ["op", "token"]
    assert f["size"] > 0 and f["control_signature"] == _sig(page, "Open channel")
    assert page["ws_frames_blocked"] >= 1
    assert not [r for r in app.requests if r[1].startswith("/ev/socket")]


def test_delayed_event_attributed_to_its_click(walked):
    _app, inv = walked
    page = next(p for p in inv["pages"] if urlsplit(p["url"]).path == "/ev/delayed")
    late = [e for e in page["events"] if e["type"] == "set_cookie" and e["name"] == "late"]
    assert late, "delayed Set-Cookie not recorded"
    assert late[0]["control_signature"] == _sig(page, "Load later")


def test_no_secret_value_anywhere(walked):
    _app, inv = walked
    assert "FIXTURESECRET" not in json.dumps(inv)


def test_pass1_still_sends_nothing_state_changing(walked):
    app, _inv = walked
    assert app.non_get_requests() == []


# ------------------------------------------------------------ recorder unit
def test_recorder_caps_count_dropped(monkeypatch):
    monkeypatch.setattr(ui_walk_events, "MAX_EVENTS_PER_PAGE", 3)
    r = ui_walk_events.Recorder()
    rec = {}
    r.begin_page(rec)
    r.set_control("sig")
    for i in range(5):
        r.record({"type": "console", "frame_origin": "o", "text": str(i)})
    assert len(rec["events"]) == 3 and rec["events_dropped"] == 2
    assert rec["events"][0]["control_signature"] == "sig"
    assert isinstance(rec["events"][0]["t_ms"], int)


def test_recorder_walk_cap_spans_pages(monkeypatch):
    monkeypatch.setattr(ui_walk_events, "MAX_EVENTS_PER_WALK", 4)
    r = ui_walk_events.Recorder()
    a, b = {}, {}
    r.begin_page(a)
    for _ in range(3):
        r.record({"type": "console", "frame_origin": "o"})
    r.begin_page(b)
    for _ in range(3):
        r.record({"type": "console", "frame_origin": "o"})
    assert len(a["events"]) == 3 and len(b["events"]) == 1 and b["events_dropped"] == 2


def test_recorder_record_without_page_is_noop():
    ui_walk_events.Recorder().record({"type": "console", "frame_origin": "o"})


def test_ws_frame_event_has_no_payload_values():
    ev = ui_walk_events.ws_frame_event("ws://h/x?token=FIXTURESECRET", '{"b":1,"a":"FIXTURESECRET"}')
    assert ev["json_keys"] == ["a", "b"] and ev["opcode"] == 1 and ev["direction"] == "client"
    assert "FIXTURESECRET" not in json.dumps(ev)
    assert ui_walk_events.ws_frame_event("ws://h/x", b"\x00\x01")["opcode"] == 2
    assert ui_walk_events.ws_frame_event("ws://h/x", "not json")["json_keys"] == []


def test_console_cap_20_per_page(walked):
    _app, inv = walked
    page = next(p for p in inv["pages"] if urlsplit(p["url"]).path == "/ev/noisy")
    cons = [e for e in page["events"] if e["type"] == "console"]
    assert len(cons) == 20
    assert page["events_dropped"] >= 5


def test_default_caps_pinned():
    assert ui_walk_events.MAX_EVENTS_PER_PAGE == 300
    assert ui_walk_events.MAX_CONSOLE_PER_PAGE == 20
    assert ui_walk_events.MAX_EVENTS_PER_WALK == 2000


def test_drain_budget_logic():
    r = ui_walk_events.Recorder()
    assert r.drain_budget(None) == ui_walk_events._DRAIN_TIMEOUT_S
    assert r.drain_budget(1000) == ui_walk_events._DRAIN_TIMEOUT_S
    assert r.drain_budget(ui_walk_events.MIN_WALL_CLOCK_FOR_DRAIN_S) == 0.0   # walk nearly out of time
    r._drain_spent = ui_walk_events.MAX_DRAIN_TOTAL_S - 1.0
    assert r.drain_budget(1000) == 1.0                                         # only what is left
    r._drain_spent = ui_walk_events.MAX_DRAIN_TOTAL_S
    assert r.drain_budget(1000) == 0.0


def test_drain_skip_is_counted_and_nonblocking():
    r = ui_walk_events.Recorder()
    r._drain_spent = ui_walk_events.MAX_DRAIN_TOTAL_S
    rec = {}
    r.begin_page(rec)
    r._inflight.add(object())          # a request that never finishes
    t0 = __import__("time").monotonic()
    asyncio.run(r.end_page(rec, remaining_s=1000))
    assert __import__("time").monotonic() - t0 < 1.0
    assert r.drains_skipped == 1


def _out_chain(inv, path):
    return [e for _p, e in _events(inv, "redirect") if urlsplit(e["hops"][0]["url"]).path == path]


def test_redirect_to_out_of_scope_two_hops_recorded_once(walked):
    _app, inv = walked
    assert inv["status"] == "complete", inv["error"]
    chains = _out_chain(inv, "/ev/redirect-out")
    assert len(chains) == 1
    hops = chains[0]["hops"]
    assert len(hops) == 3 and hops[-1]["in_scope"] is False
    assert all(h["in_scope"] for h in hops[:-1])
    assert hops[-1]["status"] in (None, 200)


def test_redirect_to_out_of_scope_single_hop_recorded_once(walked):
    _app, inv = walked
    chains = _out_chain(inv, "/ev/redirect-out1")
    assert len(chains) == 1
    hops = chains[0]["hops"]
    assert len(hops) == 2 and hops[-1]["in_scope"] is False and hops[0]["in_scope"] is True
    assert hops[0]["status"] == 302
    assert hops[-1]["status"] in (None, 200)


def test_redirect_chain_ending_in_network_failure_recorded_once(walked):
    _app, inv = walked
    assert inv["status"] == "complete", inv["error"]
    two = _out_chain(inv, "/ev/redirect-dead")
    one = _out_chain(inv, "/ev/redirect-dead1")
    assert len(two) == 1 and len(one) == 1
    assert len(two[0]["hops"]) == 3 and len(one[0]["hops"]) == 2
    for ev in (two[0], one[0]):
        assert ev["hops"][-1]["status"] is None            # never got a response
        assert ev["hops"][-2]["status"] == 302
        assert all(isinstance(h["in_scope"], bool) for h in ev["hops"])


# ----------------------------------------------- init-script events (Task 3)
def _page(inv, path):
    return next(p for p in inv["pages"] if urlsplit(p["url"]).path == path)


def test_postmessage_send_wildcard_shape(walked):
    _app, inv = walked
    page = _page(inv, "/ev/pm-send")
    sends = [e for e in page["events"] if e["type"] == "postmessage" and e["direction"] == "send"]
    assert sends
    e = sends[0]
    assert e["target_origin"] == "*" and e["frame_in_scope"] is True
    assert e["shape"]["type"] == "object" and e["shape"]["keys"] == ["op", "token"]
    assert e["control_signature"] == _sig(page, "Send message")
    assert "FIXTURESECRET" not in json.dumps(e)


def test_postmessage_listener_registered_in_scope_frame(walked):
    _app, inv = walked
    page = _page(inv, "/ev/pm-listen")
    ls = [e for e in page["events"] if e["type"] == "postmessage" and e["direction"] == "listen"]
    assert len(ls) >= 2, "top frame and the iframe both register a message listener"
    assert all(e["frame_in_scope"] is True and e["frame_origin"].startswith("http://127.0.0.1") for e in ls)
    assert all(isinstance(e["listeners"], int) and e["listeners"] >= 1 for e in ls)
    safe = [e for e in _page(inv, "/ev/pm-listen-safe")["events"] if e["type"] == "postmessage"]
    assert safe and safe[0]["direction"] == "listen"


def test_js_cookie_names_flags_no_value(walked):
    _app, inv = walked
    page = _page(inv, "/ev/jscookie")
    cs = [e for e in page["events"] if e["type"] == "js_cookie" and e["name"] == "jsid"]
    assert cs
    c = cs[0]
    assert c["name"] == "jsid" and c["samesite"] == "Lax" and c["path"] == "/"
    assert c["secure"] is False and c["httponly"] is False
    assert c["control_signature"] == _sig(page, "Remember me")
    assert "FIXTURESECRET" not in json.dumps(c)


def test_indexeddb_store_names(walked):
    _app, inv = walked
    evs = [e for e in _page(inv, "/ev/idb")["events"] if e["type"] == "indexeddb"]
    assert evs
    assert any(e["db"] == "fixturedb" and {"notes", "drafts"} <= set(e["stores"]) for e in evs)


def test_storage_diff_per_click(walked):
    _app, inv = walked
    page = _page(inv, "/ev/storage")
    rows = [e for e in page["events"] if e["type"] == "storage"]
    assert [(e["key"], e["change"]) for e in rows] == [("authToken", "added")]
    assert rows[0]["control_signature"] == _sig(page, "Keep me signed in")
    assert rows[0]["origin"].startswith("http://127.0.0.1")
    assert "FIXTURESECRET" not in json.dumps(rows)


def test_blank_link_noopener_flag(walked):
    _app, inv = walked
    page = _page(inv, "/ev/blank")
    anchors = [e for e in page["events"] if e["type"] == "window_open" and e["via"] == "anchor"]
    assert sorted(e["noopener"] for e in anchors) == [False, False, True]   # safe, unsafe, tracked
    pops = [e for e in page["events"] if e["type"] == "window_open" and e["via"] == "window.open"]
    assert pops and pops[0]["noopener"] is True and pops[0]["control_signature"] == _sig(page, "Open popup")


def test_service_worker_registration_recorded_and_still_blocked(walked):
    app, inv = walked
    page = _page(inv, "/ev/sw")
    sw = [e for e in page["events"] if e["type"] == "service_worker"]
    assert sw
    paths = [r[1] for r in app.requests]
    assert sw[0]["script_url"].endswith("/ev/sw.js") and "?" not in sw[0]["script_url"]
    assert any(p.startswith("/ev/sw-state?r=blocked") for p in paths)
    assert not any(p.startswith("/ev/sw-state?r=registered") for p in paths)
    assert not any(p.startswith("/ev/sw.js") for p in paths)


def test_init_script_wrappers_are_transparent():
    async def go():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            b = await p.chromium.launch(**browser_confirm._launch_kwargs())
            try:
                ctx = await b.new_context()
                await ctx.add_init_script(ui_walk_events.build_init_js("__hmtest", "nonce"))
                pg = await ctx.new_page()
                # http://localhost is a secure context (ServiceWorkerContainer exists); data: is not
                await pg.route("http://localhost/**", lambda r: r.fulfill(body="<p>x</p>", content_type="text/html"))
                await pg.goto("http://localhost/")
                return await pg.evaluate("""() => ({
                  pm: window.postMessage.toString(), open: window.open.toString(),
                  ael: EventTarget.prototype.addEventListener.toString(),
                  ts: Function.prototype.toString.toString(),
                  reg: ServiceWorkerContainer.prototype.register.toString(),
                  ck: Object.getOwnPropertyDescriptor(Document.prototype, 'cookie').set.toString(),
                  name: window.postMessage.name,
                  cookie: (document.cookie = 'a=1', document.cookie),
                  noBinding: typeof window.__hmtest})""")
            finally:
                await b.close()
    r = asyncio.run(go())
    for k in ("pm", "open", "ael", "ts", "reg", "ck"):
        assert "[native code]" in r[k], k
    assert r["name"] == "postMessage" and r["cookie"] == "a=1"     # calls through, no binding needed
    assert r["noBinding"] == "undefined"


def test_binding_handler_never_raises_or_echoes():
    r = ui_walk_events.Recorder()
    rec = {}
    r.begin_page(rec)
    class Src(dict):
        pass
    N = r._nonce
    for bad in (None, 5, "not json", N + "|[1]", N + '|{"k":"cookie","raw":5}', "x" * 9000,
                N + '|{"k":"pm_send","s":{"keys":[1]}}'):
        assert r._on_binding({"frame": type("F", (), {"url": "http://127.0.0.1/"})()}, bad) is None
    assert r._on_binding({}, N + '|{"k":"cookie"}') is None  # malformed source
    ok = r._on_binding({"frame": type("F", (), {"url": "http://127.0.0.1/x?q=FIXTURESECRET"})()},
                       N + '|{"k":"cookie","raw":"sid=; Secure; Path=/"}')
    ev = [e for e in rec["events"] if e["type"] == "js_cookie"][-1]
    assert ok is None and ev["secure"] is True and ev["name"] == "sid"
    assert "FIXTURESECRET" not in json.dumps(ev)


def test_double_attach_binds_once():
    class Ctx:
        calls = 0
        async def expose_binding(self, *_a): Ctx.calls += 1
        async def add_init_script(self, *_a): pass
    r, c = ui_walk_events.Recorder(), Ctx()
    asyncio.run(r._install_init(c))
    asyncio.run(r._install_init(c))
    assert Ctx.calls == 1


# ----------------------------------------------- review fixes (forgery, URLs, cookies, budget, overflow)
class _F:
    def __init__(self, url="http://127.0.0.1/p"):
        self.url = url


def test_forged_payload_without_nonce_dropped_and_counted():
    r = ui_walk_events.Recorder()
    rec = {}
    r.begin_page(rec)
    src = {"frame": _F()}
    r._on_binding(src, json.dumps({"k": "wopen", "url": "http://evil/", "noopener": False}))
    r._on_binding(src, "guess|" + json.dumps({"k": "wopen", "url": "http://evil/"}))
    r._on_binding(src, "not json")
    assert rec["events"] == [] and r.forged_dropped == 3
    r._on_binding(src, r._nonce + "|" + json.dumps({"k": "wopen", "url": "http://ok/", "noopener": False}))
    assert len(rec["events"]) == 1 and r.forged_dropped == 3


def test_nonce_and_binding_name_are_per_recorder_random():
    a, b = ui_walk_events.Recorder(), ui_walk_events.Recorder()
    assert a._nonce != b._nonce and len(a._nonce) == 32
    assert a._binding != b._binding and a._binding != "__hmEvent"


def test_forged_events_from_page_never_recorded(walked):
    _app, inv = walked
    page = _page(inv, "/ev/forge")
    assert not [e for e in page["events"] if e["type"] == "window_open"]
    assert "forged.invalid" not in json.dumps(inv)
    assert inv["events_forged_dropped"] >= 1


def test_overwriting_binding_does_not_hide_real_events(walked):
    _app, inv = walked
    page = _page(inv, "/ev/overwrite")
    sends = [e for e in page["events"] if e["type"] == "postmessage" and e["direction"] == "send"]
    assert sends and sends[0]["shape"]["keys"] == ["after"]
    assert sends[0]["control_signature"] == _sig(page, "Send after overwrite")


def test_urls_in_events_carry_no_query_or_fragment(walked):
    _app, inv = walked
    page = _page(inv, "/ev/blank")
    ev = [e for e in page["events"] if e["type"] == "window_open"]
    pops = [e for e in ev if e["via"] == "window.open"]
    assert pops and pops[0]["url"].endswith("/ev/landed") and "?" not in pops[0]["url"] and "#" not in pops[0]["url"]
    assert all("?" not in e["url"] and "#" not in e["url"] for e in ev)
    assert "ANCHORSECRET" not in json.dumps(ev) and "POPUPSECRET" not in json.dumps(ev)
    sw = [e for e in _page(inv, "/ev/sw")["events"] if e["type"] == "service_worker"]
    assert sw and "FIXTURESECRET" not in json.dumps(sw)            # sw script query stripped
    assert "FIXTURESECRET" not in json.dumps(inv)


def test_nameless_js_cookie_value_not_used_as_name(walked):
    _app, inv = walked
    page = _page(inv, "/ev/jscookie")
    cs = [e for e in page["events"] if e["type"] == "js_cookie" and e["control_signature"] == _sig(page, "Nameless cookie")]
    assert cs and cs[0]["name"] == ""
    assert "FIXTURESECRET" not in json.dumps(page["events"])


def test_snapshot_budget_bounds_total_time(monkeypatch):
    monkeypatch.setattr(ui_walk_events, "_SNAPSHOT_BUDGET_S", 0.4)

    class Hung(_F):
        async def evaluate(self, _js):
            await asyncio.sleep(30)

    class Pg:
        frames = [Hung() for _ in range(6)]
    r = ui_walk_events.Recorder()
    r._scope = lambda _u: True
    t0 = __import__("time").monotonic()
    out = asyncio.run(r.snapshot_storage(Pg()))
    assert __import__("time").monotonic() - t0 < 1.0     # not 6 x 3s
    assert out == {} and r.snapshot_frames_skipped >= 4


def test_page_event_overflow_counts_into_events_dropped(walked):
    _app, inv = walked
    page = _page(inv, "/ev/flood")
    assert len([e for e in page["events"] if e["type"] == "postmessage"]) <= 80
    assert page["events_dropped"] >= 20


@pytest.mark.parametrize("path", ["/ev/hook-a", "/ev/hook-b"])
def test_prototype_hooks_cannot_leak_nonce_to_forge_events(walked, path):
    _app, inv = walked
    page = _page(inv, path)
    real = [e for e in page["events"] if e["type"] in ("postmessage", "window_open")]
    assert any(e["type"] == "postmessage" and e["direction"] == "send" for e in real)   # real events still recorded
    assert any(e["type"] == "window_open" and e["via"] == "window.open" for e in real)
    assert "forged.invalid" not in json.dumps(inv)
    assert inv["events_forged_dropped"] >= 1


def test_nonce_never_sits_on_an_object_in_the_page():
    async def go():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            b = await p.chromium.launch(**browser_confirm._launch_kwargs())
            try:
                ctx = await b.new_context()
                await ctx.expose_binding("__hmt", lambda s, payload: None)
                await ctx.add_init_script(ui_walk_events.build_init_js("__hmt", "NONCE0123456789"))
                pg = await ctx.new_page()
                await pg.route("http://localhost/**", lambda r: r.fulfill(body="<p>x</p>", content_type="text/html"))
                await pg.goto("http://localhost/")
                return await pg.evaluate("""() => {
                  const seen = [];
                  Object.defineProperty(Object.prototype, 'n', {configurable: true, set(v) { seen.push(String(v)); }});
                  Object.defineProperty(Object.prototype, 'toJSON', {configurable: true,
                    value: function () { seen.push(JSON.stringify(Object.getOwnPropertyNames(this))); return undefined; }});
                  window.postMessage({a: 1}, '*');
                  return seen.join('|'); }""")
            finally:
                await b.close()
    assert "NONCE0123456789" not in asyncio.run(go())


def test_honest_limit_in_page_hooks_best_effort(walked):
    _app, inv = walked
    assert any("best-effort" in h and "leads" in h for h in inv["honest_limits"])
