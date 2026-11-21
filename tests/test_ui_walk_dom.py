"""#164 UI-walk event recorder, Task 4: DOM-XSS sink hooks, zero-traffic canary
sources (URL #hash, window.name, an in-page postMessage) and the postMessage
probe. Black-box against the local fixture app's /ev/dom* pages, vulnerable vs
patched. Also ruling R4: event URLs keep scheme://host/path plus query PARAM
NAMES only (`query_keys`), never query values.

Safety pinned here: Pass 1 still sends nothing state-changing, a planted canary
never reaches the server, and the probe never touches an out-of-scope frame.
"""

import asyncio
import json
import os
import re
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
import ui_walk_events_logic as EL
import ui_walk_pass2
from ui_walk_app import requires_browser, serve
from ui_walk_grant import Grant

pytestmark = requires_browser

DOM_TOKEN = re.compile(r"hm[0-9a-f]{10}")
DOM_PAGES = ("/ev/dom-hash", "/ev/dom-hash-raw", "/ev/dom-name", "/ev/pm-dom", "/ev/pm-oos",
             "/ev/spa", "/ev/dom-leak", "/ev/dom-cookie", "/ev/dom-alert", "/ev/dom-store", "/ev/q-secret")


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


def _run(vulnerable, tmp_path_factory, max_pages):
    mp = pytest.MonkeyPatch()
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    uw = tmp_path_factory.mktemp("uw")
    mp.setenv("HUNTMCP_UI_WALK_DIR", str(uw))   # canary registry never touches a real engagement
    app = serve(vulnerable=vulnerable)
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/ev/dom", "map", scope_check=_scope,
                                       screenshot_dir=str(tmp_path_factory.mktemp("shots")),
                                       cookie_header=app.login_cookie(), max_pages=max_pages))
    finally:
        mp.undo()
    return app, inv, uw


@pytest.fixture(scope="module")
def vuln(tmp_path_factory):
    # /ev/dom links every DOM page and then /ev, so this walk covers all /ev/* pages
    app, inv, uw = _run(True, tmp_path_factory, max_pages=80)
    yield app, inv, uw
    app.close()


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    # /ev/dom, "/" (nav Home) and the 12 DOM-index links come first in the BFS queue
    app, inv, uw = _run(False, tmp_path_factory, max_pages=14)
    yield app, inv, uw
    app.close()


def _page(inv, path):
    return next(p for p in inv["pages"] if urlsplit(p["url"]).path == path)


def _sinks(page):
    return [e for e in page["events"] if e["type"] == "dom_sink"]


def _cands(page, type_):
    return [c for c in EL.derive_candidates(page, scope=_scope) if c["type"] == type_]


# ------------------------------------------------------------------ hash source
def test_hash_source_innerhtml_vulnerable_is_dom_xss(vuln):
    _app, inv, _uw = vuln
    assert inv["status"] == "complete", inv["error"]
    page = _page(inv, "/ev/dom-hash")
    hits = [e for e in _sinks(page) if e["source"] == "hash" and e["sink"] == "innerHTML"]
    assert hits, page["events"]
    e = hits[0]
    assert e["executed"] is True
    assert DOM_TOKEN.fullmatch(e["token"])
    assert e["script_url"].endswith("/ev/dom-hash") and isinstance(e["line"], int)
    assert e["frame_origin"].startswith("http://127.0.0.1")
    assert _cands(page, "dom-xss-candidate")


def test_hash_source_textcontent_patched_no_candidate(patched):
    _app, inv, _uw = patched
    assert inv["status"] == "complete", inv["error"]
    page = _page(inv, "/ev/dom-hash")
    assert page["dom_sources"]["hash"] == "planted"          # the source was really tried
    assert _sinks(page) == []
    assert not _cands(page, "dom-xss-candidate") and not _cands(page, "dom-sink-candidate")


def test_sink_without_execution_is_dom_sink_candidate(vuln):
    _app, inv, _uw = vuln
    page = _page(inv, "/ev/dom-hash-raw")
    hits = [e for e in _sinks(page) if e["source"] == "hash"]
    assert hits and all(e["executed"] is False for e in hits)
    assert _cands(page, "dom-sink-candidate") and not _cands(page, "dom-xss-candidate")


# ------------------------------------------------------------- window.name source
def test_window_name_document_write_sink(vuln):
    _app, inv, _uw = vuln
    page = _page(inv, "/ev/dom-name")
    assert page["dom_sources"]["window.name"] == "planted"
    hits = [e for e in _sinks(page) if e["source"] == "window.name"]
    assert hits and hits[0]["sink"] == "document.write" and hits[0]["executed"] is True
    assert _cands(page, "dom-xss-candidate")


def test_window_name_only_planted_where_the_page_reads_it(vuln):
    _app, inv, _uw = vuln
    assert _page(inv, "/ev/dom-hash")["dom_sources"]["window.name"] == "not-read"


# -------------------------------------------------------------- postMessage probe
def test_postmessage_probe_reaction_vulnerable(vuln):
    _app, inv, _uw = vuln
    page = _page(inv, "/ev/pm-dom")
    probe = page["postmessage_probe"]
    assert probe["result"] == "reaction" and probe["probed_frames"] == 1
    assert any(r["kind"] == "dom" and r["frame_origin"].startswith("http://127.0.0.1")
               for r in probe["reactions"])
    hits = [e for e in _sinks(page) if e["source"] == "postmessage"]
    assert hits and hits[0]["sink"] == "innerHTML" and hits[0]["executed"] is True
    assert _cands(page, "postmessage-no-origin-check-candidate")


def test_postmessage_probe_patched_no_reaction(patched):
    _app, inv, _uw = patched
    page = _page(inv, "/ev/pm-dom")
    probe = page["postmessage_probe"]
    assert probe["result"] == "no-reaction" and probe["probed_frames"] == 1
    assert probe["reactions"] == []
    assert _sinks(page) == []
    assert not _cands(page, "postmessage-no-origin-check-candidate")


def test_probe_skips_out_of_scope_frames(vuln):
    app, inv, _uw = vuln
    page = _page(inv, "/ev/pm-oos")
    listen = [e for e in page["events"] if e["type"] == "postmessage" and e["direction"] == "listen"]
    assert listen and all(e["frame_in_scope"] is False for e in listen)   # the listener is third-party
    probe = page["postmessage_probe"]
    assert probe["result"] == "skipped-out-of-scope" and probe["probed_frames"] == 0
    assert not [r for r in app.requests if r[1].startswith("/ev/pm-oos-hit")]
    assert not _cands(page, "postmessage-no-origin-check-candidate")


def test_page_without_listener_is_no_listener(vuln):
    _app, inv, _uw = vuln
    assert _page(inv, "/ev/dom-hash")["postmessage_probe"]["result"] == "no-listener"


# ------------------------------------------------------- planting safety / SPA
def test_planting_is_not_a_sink(vuln, patched):
    for app, inv, _uw in (vuln, patched):
        quiet = [p for p in inv["pages"] if urlsplit(p["url"]).path not in
                 ("/ev/dom-hash", "/ev/dom-hash-raw", "/ev/dom-name", "/ev/pm-dom", "/ev/dom-leak",
                  "/ev/dom-cookie")]
        assert quiet
        planted = [p for p in quiet if (p.get("dom_sources") or {}).get("hash") == "planted"]
        assert planted, "hash planting never ran on a sink-free page"
        assert [e for p in quiet for e in _sinks(p)] == []
        # the walker's own window.name reload / hash write never shows up as a request sink
        assert not [e for p in inv["pages"] for e in _sinks(p)
                    if e["sink"] in ("request", "navigation")
                    and urlsplit(p["url"]).path not in ("/ev/dom-leak", "/ev/dom-cookie")]


def test_canary_never_reaches_server(vuln, patched):
    for app, inv, _uw in (vuln, patched):
        assert not [r for r in app.requests if DOM_TOKEN.search(r[1])]
        assert not [r for r in app.requests if r[1].startswith("/ev/leak")]   # aborted in the browser
    _app, inv, _uw = vuln
    page = _page(inv, "/ev/dom-leak")
    assert [e for e in _sinks(page) if e["sink"] == "request" and e["source"] == "hash"]


def test_canary_in_a_cookie_never_reaches_server(vuln, patched):
    for app, _inv, _uw in (vuln, patched):
        assert not [c for c in app.cookie_headers if DOM_TOKEN.search(c)]
        assert not [r for r in app.requests if r[1].startswith("/ev/landed?after=cookie")]
    _app, inv, _uw = vuln
    page = _page(inv, "/ev/dom-cookie")
    assert [e for e in _sinks(page) if e["sink"] == "document.cookie" and e["source"] == "hash"]
    assert [e for e in _sinks(page) if e["sink"] == "request"]           # the cookie-carrying fetch, aborted
    # the canary cookie is cleared at the end of that page, so later pages still load
    later = [p for p in inv["pages"] if urlsplit(p["url"]).path in ("/ev/q-secret", "/ev/cookies", "/ev/storage")]
    assert later and all(p["nav_error"] is None and not _sinks(p) for p in later)
    assert inv["status"] == "complete"


def test_dialog_that_only_shows_the_payload_is_not_execution(vuln):
    _app, inv, _uw = vuln
    page = _page(inv, "/ev/dom-alert")
    assert page["dom_sources"]["hash"] == "planted"
    assert not [e for e in _sinks(page) if e["executed"]]
    assert not _cands(page, "dom-xss-candidate")


def test_note_dialog_requires_exact_token():
    r = ui_walk_events.Recorder()
    rec = {"url": "http://127.0.0.1/p"}
    r.begin_page(rec)
    tok = r.new_dom_token("hash", rec)
    r._record_sink(tok, "innerHTML", "", None, "")
    r.note_dialog("Bad route: #hm=" + ui_walk_events.Recorder.dom_payload(tok))
    r.note_dialog(f"x {tok}")
    assert rec["events"][0]["executed"] is False
    r.note_dialog(f"  {tok}\n")
    assert rec["events"][0]["executed"] is True


def test_canary_in_web_storage_never_saved_to_session_file(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve()
    sess = tmp_path / "session.json"
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/ev/dom-store", "map", scope_check=_scope,
                                       screenshot_dir=str(tmp_path / "shots"), session_file=str(sess),
                                       cookie_header=app.login_cookie(), max_pages=1))
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    assert inv["pages"][0]["dom_sources"]["hash"] == "planted"
    saved = sess.read_text()
    assert not DOM_TOKEN.search(saved), "a planted canary was persisted into the session file"
    assert "kept-value" in saved                     # only canary-carrying entries are removed
    assert inv.get("dom_canary_storage_cleared", 0) >= 2


def test_registry_entry_keeps_no_query_values(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path / "uw"))
    w = ui_walk._Walker("http://127.0.0.1/", "map", scope=_scope, max_pages=1, max_clicks_per_page=1,
                        same_origin_only=True, wall_clock_s=60, action_delay_s=0,
                        screenshot_dir=str(tmp_path), had_session=False, session_file=None, auth={},
                        walk_id="w1")
    rec = {"url": "http://127.0.0.1/p?code=FIXTURESECRET&state=x"}
    w.recorder.begin_page(rec)
    tok = w.recorder.new_dom_token("hash", rec)
    w.recorder._record_sink(tok, "innerHTML", "", None, "http://127.0.0.1")
    raw = (tmp_path / "uw" / "canaries.json").read_text()
    entry = json.loads(raw)[tok]
    assert entry["page"] == "http://127.0.0.1/p" and entry["query_keys"] == ["code", "state"]
    assert "FIXTURESECRET" not in raw


def test_function_constructor_hooked_transparently():
    sent = []

    async def go():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            b = await p.chromium.launch(**browser_confirm._launch_kwargs())
            try:
                ctx = await b.new_context()
                await ctx.expose_binding("__hmt", lambda _s, payload: sent.append(payload))
                await ctx.add_init_script(ui_walk_events.build_init_js("__hmt", "N0", ctl="__hmc", key="K0"))
                pg = await ctx.new_page()
                await pg.route("http://localhost/**", lambda r: r.fulfill(body="<p>x</p>", content_type="text/html"))
                await pg.goto("http://localhost/")
                r = await pg.evaluate("""() => {
                  const f = function () {};
                  class X extends Function {}
                  const x = new X('return 7');
                  return {
                    ctorId: f.constructor === Function, protoCtor: Function.prototype.constructor === Function,
                    inst: f instanceof Function, arrowInst: (() => 1) instanceof Function,
                    protoId: Object.getPrototypeOf(f) === Function.prototype,
                    newF: new Function('a', 'b', 'return a + b')(2, 3), callF: Function('return 4')(),
                    viaCtor: (() => {}).constructor('return 5')(), name: Function.name, len: Function.length,
                    sub: x(), subInst: x instanceof X && x instanceof Function,
                    ts: Function.toString(), global: Function('return typeof window')(),
                    hit: Function('return "hm0123456789"')()};
                }""")
                await pg.wait_for_timeout(100)
                return r
            finally:
                await b.close()
    r = asyncio.run(go())
    assert r["ctorId"] and r["protoCtor"] and r["inst"] and r["arrowInst"] and r["protoId"]
    assert (r["newF"], r["callF"], r["viaCtor"], r["sub"]) == (5, 4, 5, 7) and r["subInst"]
    assert r["name"] == "Function" and r["len"] == 1 and r["global"] == "object"
    assert "[native code]" in r["ts"] and "Function" in r["ts"]
    assert r["hit"] == "hm0123456789"
    sinks = [json.loads(s.split("|", 1)[1]) for s in sent if '"k":"sink"' in s]
    assert [(s["sink"], s["tok"]) for s in sinks] == [("Function", "hm0123456789")]


def test_honest_limits_name_only_eval_location_and_transformed_canaries(vuln):
    _app, inv, _uw = vuln
    dom = [h for h in inv["honest_limits"] if "DOM-XSS sink hooks" in h]
    assert dom and "eval" in dom[0] and "Function are not" not in dom[0] and "Function(" in dom[0]
    assert any("transformed" in h and "base64" in h for h in inv["honest_limits"])


def test_hash_canary_keeps_spa_route(tmp_path):
    app = serve()

    async def go():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            b = await p.chromium.launch(**browser_confirm._launch_kwargs())
            try:
                ctx = await b.new_context()
                page = await ctx.new_page()
                rec_ = ui_walk_events.Recorder()
                await rec_.attach(ctx, page, scope=_scope)
                rec = {"url": app.base_url + "/ev/spa"}
                rec_.begin_page(rec)
                await page.goto(app.base_url + "/ev/spa", wait_until="domcontentloaded")
                await page.wait_for_timeout(300)
                before = await page.inner_text("#view")

                async def budget():
                    return None
                await rec_.plant_sources(page, app.base_url + "/ev/spa", rec, budget=budget)
                after = await page.inner_text("#view")
                frag = urlsplit(page.url).fragment
                await rec_.end_page(rec)
                return before, after, frag, rec
            finally:
                await b.close()
    try:
        before, after, frag, rec = asyncio.run(go())
    finally:
        app.close()
    assert before == "Route view: /route"
    assert after == "Route view: /route"            # the route survived planting
    assert frag.startswith("/route?hm=")            # canary appended as an extra hash parameter
    assert rec["dom_sources"]["hash"] == "planted"


def test_pass1_still_zero_non_get(vuln, patched):
    for app, inv, _uw in (vuln, patched):
        assert app.non_get_requests() == []
    _app, inv, _uw = vuln
    paths = {urlsplit(p["url"]).path for p in inv["pages"]}
    assert set(DOM_PAGES) <= paths
    assert {"/ev", "/ev/cookies", "/ev/pm-listen", "/ev/storage"} <= paths   # all /ev/* walked too


def test_dom_hit_token_registered_with_source(vuln):
    _app, inv, uw = vuln
    with open(os.path.join(str(uw), "canaries.json")) as fh:
        reg = json.load(fh)
    page = _page(inv, "/ev/dom-hash")
    tok = next(e for e in _sinks(page) if e["source"] == "hash")["token"]
    assert reg[tok]["source"] == "hash" and reg[tok]["walk_id"] == inv["walk_id"]
    assert {r.get("source") for r in reg.values()} >= {"hash", "window.name", "postmessage"}


# --------------------------------------------------------------- R4: URL values
def test_event_urls_keep_only_query_param_names(vuln):
    _app, inv, _uw = vuln
    chains = [e for p in inv["pages"] for e in p["events"] if e["type"] == "redirect"
              and urlsplit(e["hops"][0]["url"]).path == "/ev/redirect-secret"]
    assert chains
    hops = chains[0]["hops"]
    assert all("?" not in h["url"] and "#" not in h["url"] for h in hops)
    assert hops[1]["query_keys"] == ["code", "next"] and hops[0]["query_keys"] == []
    assert "next" in chains[0]["param_names"]          # computed from the full URLs, in memory
    page = _page(inv, "/ev/q-secret")
    hs = [e for e in page["events"] if e["type"] == "headers" and e["url"].endswith("/ev/cookies")]
    assert hs and hs[0]["query_keys"] == ["code"] and "?" not in hs[0]["url"]
    cs = [e for e in page["events"] if e["type"] == "set_cookie" and e["name"] == "SID"]
    assert cs and "?" not in cs[0]["url"] and cs[0]["query_keys"] == ["code"]
    assert "FIXTURESECRET" not in json.dumps(inv)


# ------------------------------------------------------------ unit / in-page
def test_sink_wrappers_transparent_and_report_only_tokens():
    sent = []

    async def go():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            b = await p.chromium.launch(**browser_confirm._launch_kwargs())
            try:
                ctx = await b.new_context()
                await ctx.expose_binding("__hmt", lambda _s, payload: sent.append(payload))
                await ctx.add_init_script(ui_walk_events.build_init_js("__hmt", "N0", ctl="__hmc", key="K0"))
                pg = await ctx.new_page()
                await pg.route("http://localhost/**", lambda r: r.fulfill(
                    body="<div id=d></div><script>document.write('<i id=w>written</i>')</script>",
                    content_type="text/html"))
                await pg.goto("http://localhost/")
                r = await pg.evaluate("""async () => {
                  const d = document.getElementById('d');
                  d.innerHTML = '<b>plain</b>';
                  const plain = d.innerHTML;
                  d.innerHTML = 'x hm0123456789 y';
                  d.insertAdjacentHTML('beforeend', '<u>ok</u>');
                  window.__ran = 0; setTimeout('window.__ran = 1', 0);
                  await new Promise(res => setTimeout(res, 50));
                  const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                  return {plain, now: d.innerHTML, ran: window.__ran, w: document.getElementById('w').textContent,
                          ts: desc.set.toString(), dw: document.write.toString(), st: setTimeout.toString(),
                          ctlNoKey: window.__hmc('bad', 'state'), name: (window.name = 'n1', window.name)};
                }""")
                await pg.wait_for_timeout(100)
                return r
            finally:
                await b.close()
    r = asyncio.run(go())
    assert r["plain"] == "<b>plain</b>" and r["now"] == "x hm0123456789 y<u>ok</u>"
    assert r["ran"] == 1 and r["w"] == "written" and r["name"] == "n1"
    for k in ("ts", "dw", "st"):
        assert "[native code]" in r[k], k
    assert r["ctlNoKey"] is None
    sinks = [json.loads(s.split("|", 1)[1]) for s in sent if '"k":"sink"' in s]
    assert [(s["sink"], s["tok"]) for s in sinks] == [("innerHTML", "hm0123456789")]


def test_dialog_marks_sink_executed_and_pass2_still_collects_dialogs(tmp_path):
    w = ui_walk_pass2.CanaryWalker("http://127.0.0.1/", "canary", scope=_scope, max_pages=1,
                                   max_clicks_per_page=1, same_origin_only=True, wall_clock_s=60,
                                   action_delay_s=0, screenshot_dir=str(tmp_path), had_session=False,
                                   session_file=None, auth={}, walk_id="w1")
    w.configure(Grant(True, [], 1))
    rec = {"url": "http://127.0.0.1/p"}
    w.recorder.begin_page(rec)
    tok = w.recorder.new_dom_token("hash", rec)
    w.recorder._record_sink(tok, "innerHTML", "http://127.0.0.1/p?x=1", 3, "http://127.0.0.1")

    class D:
        message = f"{tok}"
        type = "alert"
    w.on_dialog(D())
    assert w.dialog_msgs == [tok]                                   # Pass 2 detection intact (R2)
    ev = [e for e in rec["events"] if e["type"] == "dom_sink"]
    assert len(ev) == 1 and ev[0]["executed"] is True and ev[0]["source"] == "hash"
    assert ev[0]["script_url"] == "http://127.0.0.1/p" and ev[0]["query_keys"] == ["x"]


def test_executed_without_hooked_sink_still_recorded(tmp_path):
    r = ui_walk_events.Recorder()
    rec = {"url": "http://127.0.0.1/p"}
    r.begin_page(rec)
    tok = r.new_dom_token("window.name", rec)
    r.note_dialog(f"{tok}")
    asyncio.run(r.end_page(rec))
    ev = [e for e in rec["events"] if e["type"] == "dom_sink"]
    assert len(ev) == 1 and ev[0]["executed"] is True and ev[0]["sink"] == "unknown"


def test_unknown_or_stale_token_ignored():
    r = ui_walk_events.Recorder()
    a, b = {"url": "a"}, {"url": "b"}
    r.begin_page(a)
    tok = r.new_dom_token("hash", a)
    r.begin_page(b)
    r._record_sink(tok, "innerHTML", "", None, "")              # token from another page
    r._record_sink("hm0000000000", "innerHTML", "", None, "")   # never issued
    r.note_dialog(tok)
    assert b["events"] == []


# ---------------------------------------------- fix wave item 2: probe false positives
class _FFrame:
    def __init__(self, url):
        self.url = url


class _FPage:
    def __init__(self, *urls):
        self.frames = [_FFrame(u) for u in urls]
        self.main_frame = self.frames[0]
        self.url = urls[0]


class _FMsg:
    type = "error"

    def __init__(self, text, url):
        self.text = text
        self.location = {"url": url, "lineNumber": 1, "columnNumber": 1}


def _probe(monkeypatch, *, on_fire=None, done=None):
    """Drive probe_postmessage over a scripted page: an in-scope top frame whose
    listener checks the origin (no DOM change, no navigation) + an out-of-scope
    noisy ad iframe. Only the walker's control calls are faked."""
    monkeypatch.setattr(ui_walk_events, "PROBE_BASELINE_S", 0)
    monkeypatch.setattr(ui_walk_events, "PROBE_WATCH_S", 0)
    r = ui_walk_events.Recorder()
    r._scope = _scope
    page = _FPage("http://127.0.0.1:9/pm", "http://localhost:9/ad")
    rec = {"url": page.url}
    r.begin_page(rec)
    rec["events"].append({"type": "postmessage", "direction": "listen", "frame_in_scope": True,
                          "frame_origin": "http://127.0.0.1:9", "listeners": 1})

    async def snap(_page):
        return {}

    async def ctl(frame, cmd, arg=None, timeout=0):
        assert _scope(frame.url), "the probe must never evaluate in an out-of-scope frame"
        if cmd == "arm":
            return {"listeners": 1}
        if cmd == "fire":
            if on_fire:
                on_fire(r)
            return {"sync": 0}
        if cmd == "done":
            return done if done is not None else {"after": 0, "base": 0, "moved": False}
        return None

    monkeypatch.setattr(r, "snapshot_storage", snap)
    monkeypatch.setattr(r, "_ctl", ctl)
    out = asyncio.run(r.probe_postmessage(page, rec))
    return out, rec


def test_probe_oos_noisy_iframe_console_is_not_a_reaction(monkeypatch):
    # the third-party ad frame logs an error right in the reaction window
    out, rec = _probe(monkeypatch, on_fire=lambda r: r._on_console(_FMsg("ad noise", "http://localhost:9/ad.js")))
    assert out["result"] == "no-reaction", out
    assert not _cands(rec, "postmessage-no-origin-check-candidate")


def test_probe_oos_pageerror_is_not_a_reaction(monkeypatch):
    class _Err:
        message = "boom"
        stack = "Error: boom\n    at http://localhost:9/ad.js:3:9"
    out, rec = _probe(monkeypatch, on_fire=lambda r: r._on_pageerror(_Err()))
    assert out["result"] == "no-reaction", out
    assert not _cands(rec, "postmessage-no-origin-check-candidate")


def test_probe_done_control_failure_is_inconclusive_not_navigation(monkeypatch):
    out, rec = _probe(monkeypatch, done=ui_walk_events._CTL_ERR)
    assert out["result"] == "inconclusive", out
    assert not [x for x in out["reactions"] if x["kind"] == "navigation"]
    assert not _cands(rec, "postmessage-no-origin-check-candidate")


def test_probe_console_error_from_the_probed_frame_still_counts(monkeypatch):
    out, rec = _probe(monkeypatch, on_fire=lambda r: r._on_console(_FMsg("bad data", "http://127.0.0.1:9/pm")))
    assert out["result"] == "reaction"
    assert out["reactions"] == [{"frame_origin": "http://127.0.0.1:9", "kind": "console"}]
    assert _cands(rec, "postmessage-no-origin-check-candidate")


# ------------------------------------------- fix wave item 1: post-save canary scrub
def test_canary_in_storage_key_never_saved_to_session_file(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path / "uw"))
    app = serve()
    sess = tmp_path / "session.json"
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + "/ev/dom-store-key", "map", scope_check=_scope,
                                       screenshot_dir=str(tmp_path / "shots"), session_file=str(sess),
                                       cookie_header=app.login_cookie(), max_pages=1))
    finally:
        app.close()
    assert inv["status"] == "complete", inv["error"]
    assert inv["pages"][0]["dom_sources"]["hash"] == "planted"
    saved = sess.read_text()
    assert not DOM_TOKEN.search(saved), "a planted canary (in a storage KEY) was persisted into the session file"
    assert "kept-value" in saved                     # only canary-carrying entries are removed
    assert inv["dom_canary_saved_scrubbed"] >= 2     # the localStorage key + the sessionStorage sidecar key
    assert (os.stat(sess).st_mode & 0o777) == 0o600


def test_scrub_saved_session_removes_token_keys_and_values(tmp_path, capsys):
    tok, other = "hm0123456789", "hmabcdefabcd"
    sess = tmp_path / "s.json"
    state = {
        "cookies": [{"name": "sid", "value": "keepme", "domain": "a.test", "path": "/"},
                    {"name": "last", "value": f"x{tok}y", "domain": "a.test", "path": "/"},
                    {"name": f"c_{tok}", "value": "1", "domain": "a.test", "path": "/"}],
        "origins": [{"origin": "https://a.test",
                     "localStorage": [{"name": "keep", "value": "kept"},
                                      {"name": f"k_{tok}", "value": "1"},
                                      {"name": "v", "value": f"%3Cimg{tok}"},
                                      {"name": "unrelated", "value": other}]},
                    {"origin": "https://other.test", "localStorage": [{"name": f"o_{tok}", "value": "1"}]}],
        browser_confirm.SESSION_STORAGE_KEY: {"https://a.test": {"keep": "kept", f"s_{tok}": "1", "v": tok},
                                              "https://b.test": {"x": "y"}},
    }
    sess.write_text(json.dumps(state))
    os.chmod(sess, 0o644)
    n = ui_walk._scrub_saved_session(str(sess), [tok])
    raw = sess.read_text()
    assert n == 7 and tok not in raw
    out = json.loads(raw)
    assert [c["name"] for c in out["cookies"]] == ["sid"]
    assert [e["name"] for e in out["origins"][0]["localStorage"]] == ["keep", "unrelated"]   # not this walk's token
    assert out["origins"][1]["localStorage"] == []
    assert out[browser_confirm.SESSION_STORAGE_KEY] == {"https://a.test": {"keep": "kept"}, "https://b.test": {"x": "y"}}
    assert (os.stat(sess).st_mode & 0o777) == 0o600
    cap = capsys.readouterr()
    assert tok not in cap.out + cap.err and "kept" not in cap.out + cap.err      # never prints values
    # nothing to remove / no tokens / missing or unreadable file: the file is left exactly as it is
    before = sess.read_text()
    assert ui_walk._scrub_saved_session(str(sess), [tok]) == 0 and sess.read_text() == before
    assert ui_walk._scrub_saved_session(str(sess), []) == 0
    assert ui_walk._scrub_saved_session(str(tmp_path / "missing.json"), [tok]) == 0
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert ui_walk._scrub_saved_session(str(bad), [tok]) == 0 and bad.read_text() == "{not json"
