"""#164 UI-walk event recorder, Task 5: recorder events become inventory
candidates (inv["candidates"]) and Pass-2 scratch pages feed inv["pass2_events"].

Black-box against the local fixture app, vulnerable vs patched. Candidates are
leads, never findings, and never carry a cookie/storage/message VALUE: the
fixture plants FIXTURESECRET everywhere and it must not reach the inventory.
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
from ui_walk_app import requires_browser, serve
from ui_walk_grant import Grant

pytestmark = requires_browser


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


def _walk(vulnerable, tmp_path_factory, start, mode="map", grant=None, max_pages=80):
    mp = pytest.MonkeyPatch()
    mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    # isolation: the canary registry must never touch the live engagement
    mp.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path_factory.mktemp("uw")))
    app = serve(vulnerable=vulnerable)
    try:
        inv = asyncio.run(ui_walk.walk(app.base_url + start, mode, scope_check=_scope,
                                       screenshot_dir=str(tmp_path_factory.mktemp("shots")),
                                       cookie_header=app.login_cookie(), max_pages=max_pages,
                                       **({"grant": grant} if grant else {})))
    finally:
        mp.undo()
    return app, inv


@pytest.fixture(scope="module")
def vuln(tmp_path_factory):
    app, inv = _walk(True, tmp_path_factory, "/ev/dom")
    yield app, inv
    app.close()


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    app, inv = _walk(False, tmp_path_factory, "/ev/dom")
    yield app, inv
    app.close()


@pytest.fixture(scope="module")
def tabnab(tmp_path_factory):
    out = []
    for vulnerable in (True, False):
        app, inv = _walk(vulnerable, tmp_path_factory, "/ev/tabnab", max_pages=2)
        app.close()
        out.append(inv)
    return out


@pytest.fixture(scope="module")
def p2_vuln(tmp_path_factory):
    app, inv = _walk(True, tmp_path_factory, "/p2contact", "canary", Grant(True, [], 200), max_pages=2)
    yield app, inv
    app.close()


@pytest.fixture(scope="module")
def p2_patched(tmp_path_factory):
    app, inv = _walk(False, tmp_path_factory, "/p2contact", "canary", Grant(True, [], 200), max_pages=2)
    yield app, inv
    app.close()


def _of(inv, type_):
    return [c for c in inv["candidates"] if c["type"] == type_]


def _pages(cands):
    return {urlsplit(c["page"]).path for c in cands}


def test_walks_complete_and_inventory_keys(vuln, patched):
    for _app, inv in (vuln, patched):
        assert inv["status"] == "complete", inv["error"]
        assert inv["pass2_events"] == []
        # auto mode (2026-11-21): no Burp on the (isolated) auto port -> direct, and it says so
        assert inv["burp_mirror"] == {"requested": False, "active": False, "proxy": None, "reason": None,
                                      "auto": "no Burp detected"}


def test_refused_inventory_has_new_keys():
    inv = asyncio.run(ui_walk.walk("http://127.0.0.1:9/", "bogus", scope_check=_scope))
    assert inv["status"] == "refused"
    assert inv["pass2_events"] == []
    assert inv["burp_mirror"] == {"requested": False, "active": False, "proxy": None, "reason": None}


def test_cookie_flags_on_vulnerable_only(vuln, patched):
    assert "/ev/cookies" in _pages(_of(vuln[1], "cookie-flags-candidate"))
    assert _of(patched[1], "cookie-flags-candidate") == []


def test_postmessage_wildcard_on_vulnerable_only(vuln, patched):
    assert "/ev/pm-send" in _pages(_of(vuln[1], "postmessage-wildcard-target-candidate"))
    assert _of(patched[1], "postmessage-wildcard-target-candidate") == []


def test_redirect_param_on_vulnerable_only(vuln, patched):
    assert _of(vuln[1], "redirect-param-candidate")
    assert _of(patched[1], "redirect-param-candidate") == []


def test_cors_on_vulnerable_only(vuln, patched):
    assert "/ev/cors" in _pages(_of(vuln[1], "cors-candidate"))
    assert _of(patched[1], "cors-candidate") == []


def test_dom_xss_on_vulnerable_only(vuln, patched):
    assert _of(vuln[1], "dom-xss-candidate")
    assert _of(patched[1], "dom-xss-candidate") == []


def test_postmessage_no_origin_check_on_vulnerable_only(vuln, patched):
    assert _of(vuln[1], "postmessage-no-origin-check-candidate")
    assert _of(patched[1], "postmessage-no-origin-check-candidate") == []


def test_clickjacking_on_vulnerable_only(vuln, patched):
    assert _of(vuln[1], "clickjacking-candidate")
    assert _of(patched[1], "clickjacking-candidate") == []


def test_tabnabbing_present_in_both(tabnab):
    # identical page in both variants: an out-of-scope target=_blank link without noopener
    for inv in tabnab:
        assert inv["status"] == "complete", inv["error"]
        assert "/ev/tabnab" in _pages(_of(inv, "tabnabbing-candidate"))


def test_storage_token_present_in_both(vuln, patched):
    for _app, inv in (vuln, patched):
        assert "/ev/storage" in _pages(_of(inv, "storage-token-candidate"))


def test_candidates_carry_no_secret_values(vuln, patched, p2_vuln):
    for _app, inv in (vuln, patched, p2_vuln):
        assert "FIXTURESECRET" not in json.dumps(inv)
        for c in inv["candidates"]:
            if c["type"].endswith("-candidate"):
                assert set(c) == {"type", "page", "control_signature", "detail"}


def test_pass2_submit_cookie_recorded(p2_vuln):
    _app, inv = p2_vuln
    assert inv["status"] == "complete", inv["error"]
    assert inv["real_submits"], "the grant-gated contact submit never happened"
    evs = [e for e in inv["pass2_events"] if e["type"] == "set_cookie" and e["name"] == "SID"]
    assert evs, inv["pass2_events"]
    assert any(e.get("via") == "route.fetch" for e in evs)
    e = next(e for e in evs if e.get("via") == "route.fetch")
    assert e["page_template"]
    assert urlsplit(e["url"]).path == "/api/contact" and "?" not in e["url"]
    assert "value" not in e and "FIXTURESECRET" not in json.dumps(e)
    assert all(ev["page_template"] for ev in inv["pass2_events"])


def test_pass2_patched_sets_no_cookie(p2_patched):
    _app, inv = p2_patched
    assert inv["real_submits"]
    assert not [e for e in inv["pass2_events"] if e["type"] == "set_cookie"]


def _key(c):
    return json.dumps([c["type"], c["page"], c["control_signature"], c["detail"]], sort_keys=True)


def test_no_duplicate_candidates(vuln):
    keys = [_key(c) for c in vuln[1]["candidates"] if "detail" in c]
    assert keys and len(keys) == len(set(keys))


def test_pass2_rotated_cookie_yields_cookie_flags_candidate(p2_vuln, p2_patched):
    cands = _of(p2_vuln[1], "cookie-flags-candidate")
    assert any(c["detail"]["name"] == "SID" and "missing-httponly" in c["detail"]["reasons"] for c in cands)
    assert "FIXTURESECRET" not in json.dumps(cands)
    assert _of(p2_patched[1], "cookie-flags-candidate") == []
    assert p2_vuln[1]["events_candidate_errors"] == 0


def _bare_walker():
    w = object.__new__(ui_walk._Walker)
    w.recorder = ui_walk.ui_walk_events.Recorder()
    w.deadline = 1e12
    w.scope = _scope
    w.inv = {"honest_limits": [], "candidates": [], "events_candidate_errors": 0}
    return w


COOKIE_EV = {"type": "set_cookie", "name": "SID", "secure": False, "httponly": False, "samesite": None,
             "url": "http://127.0.0.1/x", "control_signature": None, "t_ms": 0, "frame_origin": "", "blocked": []}


def test_stopped_visit_derives_nothing(monkeypatch):
    w = _bare_walker()

    async def boom(rec, url, queue, is_start):
        rec["events"].append(dict(COOKIE_EV))
        raise ui_walk._Stop("auth_lost")

    w._visit_page = boom
    with pytest.raises(ui_walk._Stop):
        asyncio.run(w._visit("http://127.0.0.1/x", [], True))
    assert w.inv["candidates"] == []


def test_derive_page_is_idempotent_and_counts_errors(monkeypatch):
    w = _bare_walker()
    rec = {"url": "http://127.0.0.1/x", "events": [dict(COOKIE_EV)], "api_edges": [], "controls": []}
    w._derive_page(rec)
    w._derive_page(rec)
    assert len(w.inv["candidates"]) == 1
    monkeypatch.setattr(ui_walk.ui_walk_events_logic, "derive_candidates",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("rule bug")))
    w._derive_page(rec)
    assert w.inv["events_candidate_errors"] == 1


# ---- fix wave item 8: persistent candidate key set, identical behaviour ----
def test_add_candidates_uses_persistent_key_set(monkeypatch):
    w = _bare_walker()
    c1 = {"type": "cookie-flags-candidate", "page": "p", "control_signature": None, "detail": {"name": "a"}}
    w.inv["candidates"].append({"type": "stored-xss", "token": "hm1"})      # #164 candidate without "detail"
    w._add_candidates([dict(c1), dict(c1)])
    assert len(w.inv["candidates"]) == 2
    calls = []
    real = ui_walk.json.dumps
    monkeypatch.setattr(ui_walk.json, "dumps", lambda *a, **k: (calls.append(1), real(*a, **k))[1])
    c2 = dict(c1, detail={"name": "b"})
    w._add_candidates([dict(c1), c2])
    assert len(calls) == 2                       # one key per NEW candidate, never a rebuild of all
    assert [c.get("detail") for c in w.inv["candidates"]] == [None, {"name": "a"}, {"name": "b"}]
    # a candidate appended directly (destroy / pass 2) still dedupes later inserts of the same key
    c3 = dict(c1, detail={"name": "c"})
    w.inv["candidates"].append(dict(c3))
    w._add_candidates([dict(c3)])
    assert sum(1 for c in w.inv["candidates"] if c.get("detail") == {"name": "c"}) == 1
    # #164 candidates without "detail" are never deduped
    w.inv["candidates"].append({"type": "stored-xss", "token": "hm1"})
    assert sum(1 for c in w.inv["candidates"] if c["type"] == "stored-xss") == 2


# ---- fix wave item 6: Pass-2 derive never replaces a _Stop -------------------
def _p2_walker(tmp_path):
    import ui_walk_pass2
    w = ui_walk_pass2.CanaryWalker("http://127.0.0.1:9/", "canary", scope=_scope, max_pages=1,
                                   max_clicks_per_page=1, same_origin_only=True, wall_clock_s=60,
                                   action_delay_s=0, screenshot_dir=str(tmp_path), had_session=False,
                                   session_file=None, auth={}, walk_id="w1")
    w.configure(Grant(True, [], 1))
    return w


def test_pass2_derive_keyerror_cannot_replace_stop(tmp_path, monkeypatch):
    w = _p2_walker(tmp_path)
    w.inv["pages"] = []
    # a Pass-2 cookie event without page_template (old KeyError path)
    w.inv["pass2_events"].append(dict(COOKIE_EV, via="route.fetch"))

    async def stop(_pages):
        raise ui_walk._Stop("budget_exhausted", "budget exhausted during canary submits")

    w._detect_sinks = stop
    with pytest.raises(ui_walk._Stop) as ei:
        asyncio.run(w.after_map())
    assert ei.value.status == "budget_exhausted"


def test_pass2_fetch_cookie_event_has_page_template_without_p2_rec(tmp_path):
    w = _p2_walker(tmp_path)

    class _Page:
        url = "http://127.0.0.1:9/items/7?x=1"

    class _Resp:
        headers_array = [{"name": "Set-Cookie", "value": "SID=FIXTURESECRET; Path=/"}]

    w.page = _Page()
    w.cur_page = {"url": "http://127.0.0.1:9/items/7?x=1"}
    rec = {"url": w.cur_page["url"]}
    w.recorder.begin_page(rec)                  # recording into a Pass-1-style record, no _p2_rec
    assert w._p2_rec is None
    w._record_fetch_cookies(_Resp(), "http://127.0.0.1:9/api/items")
    evs = [e for e in rec["events"] if e["type"] == "set_cookie"]
    assert evs and evs[0]["page_template"] == ui_walk.endpoint_template("http://127.0.0.1:9/items/7?x=1")
    assert "FIXTURESECRET" not in json.dumps(evs)
