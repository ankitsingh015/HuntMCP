"""Spec 3a, Task 6: the replay store (real request values for mutation,
credentials + secret-named values withheld), self ids, the cumulative
per-walk send counter, and the walker wiring."""

import asyncio
import json
import os
import stat
import sys
from urllib.parse import urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import mutation_logic as M  # noqa: E402
import ui_walk_replay as R  # noqa: E402

H = "http://127.0.0.1:9000"


@pytest.fixture(autouse=True)
def walk_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path))
    return tmp_path


def scope(u):
    return u.startswith(H)


def buf():
    return R.ReplayBuffer(scope)


def test_buffer_withholds_credentials_and_secret_fields():
    b = buf()
    rid = b.add("POST", H + "/api/login?apiKey=K1", {"Cookie": "sid=S1", "Authorization": "Bearer T1",
                                                     "X-Api-Key": "K2", "Content-Type": "application/json"},
                json.dumps({"user": "a", "password": "P1", "newPassword": "P2", "otpCode": "123456",
                            "nested": {"card_number": "4111"}}), "aborted", H + "/login", None)
    e = b.to_dict("w1", None)["entries"][0]
    assert e["replay_id"] == rid
    hdr = {k.lower(): v for k, v in e["headers"].items()}
    assert "cookie" not in hdr and "authorization" not in hdr and hdr["x-api-key"] == M.WITHHELD
    body = json.loads(e["body"])
    assert body["password"] == body["newPassword"] == body["otpCode"] == M.WITHHELD
    assert body["nested"]["card_number"] == M.WITHHELD and body["user"] == "a"
    assert "apiKey=" + M.WITHHELD.replace("<", "%3C").replace(">", "%3E") in e["url"] or "K1" not in e["url"]
    blob = json.dumps(e)
    for secret in ("S1", "T1", "K1", "K2", "P1", "P2", "123456", "4111"):
        assert secret not in blob
    assert set(e["withheld_fields"]) >= {"password", "newPassword", "otpCode", "nested.card_number",
                                         "X-Api-Key", "apiKey"}


def test_buffer_keeps_csrf_value():
    b = buf()
    b.add("POST", H + "/api/x", {"X-CSRF-Token": "C1", "Content-Type": "application/x-www-form-urlencoded"},
          "csrf_token=C2&name=n", "aborted", None, None)
    e = b.to_dict("w1", None)["entries"][0]
    assert e["headers"]["X-CSRF-Token"] == "C1" and "csrf_token=C2" in e["body"]


def test_buffer_scope_and_cap_and_dedupe():
    b = buf()
    assert b.add("GET", "http://other.invalid/x", {}, None, "get-sent", None, None) is None
    a = b.add("GET", H + "/api/a?x=1", {}, None, "get-sent", None, None)
    assert b.add("GET", H + "/api/a?x=1", {}, None, "get-sent", None, None) == a
    b2 = R.ReplayBuffer(scope, max_entries=2)
    b2.add("GET", H + "/1", {}, None, "get-sent", None, None)
    b2.add("GET", H + "/2", {}, None, "get-sent", None, None)
    assert b2.add("GET", H + "/3", {}, None, "get-sent", None, None) is None


def test_buffer_skips_sso_and_callback_urls():
    b = buf()
    assert b.add("GET", H + "/oauth2/authorize?response_type=code&client_id=a&state=S", {}, None,
                 "get-sent", None, None) is None
    assert b.add("GET", H + "/cb?code=C&state=S", {}, None, "get-sent", None, None) is None


def test_buffer_body_cap():
    b = buf()
    b.add("POST", H + "/api/big", {"Content-Type": "text/plain"}, "x" * (R.MAX_BODY + 10), "aborted", None, None)
    e = b.to_dict("w1", None)["entries"][0]
    assert e["body_truncated"] is True and len(e["body"]) == R.MAX_BODY


def test_response_keys_and_self_ids():
    b = buf()
    rid = b.add("GET", H + "/api/v3/me", {}, None, "get-sent", None, None)
    b.note_response("GET", H + "/api/v3/me", json.dumps({"id": "u-1001", "role": "user"}))
    b.note_response("GET", H + "/api/items/7", json.dumps({"id": "7"}))   # not an own-account route
    d = b.to_dict("w1", "/tmp/s.json")
    assert d["self_ids"] == ["u-1001"]
    e = next(x for x in d["entries"] if x["replay_id"] == rid)
    assert e["response_keys"] == ["id", "role"]
    assert d["session_file_realpath"] == os.path.realpath("/tmp/s.json")


def test_save_is_0600_and_atomic(walk_dir):
    b = buf()
    b.add("GET", H + "/a", {}, None, "get-sent", None, None)
    p = R.save_replay(b.to_dict("w1", None))
    assert p == os.path.join(str(walk_dir), "w1.replay.json")
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert R.load_replay("w1")["entries"][0]["url"] == H + "/a"
    assert not [f for f in os.listdir(walk_dir) if f.endswith(".tmp")]


def test_load_rejects_bad_walk_id():
    assert R.load_replay("../etc") is None and R.load_replay("") is None


def test_delete_replays(walk_dir):
    for w in ("w1", "w2"):
        R.save_replay(buf().to_dict(w, None))
    assert R.delete_replays(["w1"]) == 1 and R.load_replay("w1") is None and R.load_replay("w2")
    assert R.delete_replays() == 1 and R.load_replay("w2") is None


def test_send_counter_cumulative_and_reserve():
    c = R.SendCounter("w1")
    assert all(c.try_take(1, restore=False, cap=20) for _ in range(15))
    assert c.try_take(1, restore=False, cap=20) is False      # reserve = max(5, 20 // 10) = 5
    assert c.try_take(1, restore=True, cap=20) is True
    assert c.used() == 16


def test_send_counter_survives_new_instance():
    R.SendCounter("w1").record(7)
    assert R.SendCounter("w1").used() == 7
    assert R.SendCounter("w1").try_take(1, restore=False, cap=10) is False   # 7 + 1 > 10 - 5


# -- black box: the walker writes the store ---------------------------------
from ui_walk_app import requires_browser, serve  # noqa: E402


@requires_browser
def test_map_walk_writes_replay_with_profile_put_and_self_id(tmp_path, monkeypatch, walk_dir):
    import browser_confirm
    import ui_walk

    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve(vulnerable=True)
    try:
        sf = str(tmp_path / "s.json")
        app.write_session_file(sf)
        sid = json.load(open(sf))["cookies"][0]["value"]
        inv = asyncio.run(ui_walk.walk(app.base_url + "/acct", "map", session_file=sf, max_pages=3,
                                       scope_check=lambda u: urlsplit(u).hostname == "127.0.0.1",
                                       screenshot_dir=str(tmp_path), walk_id="wrp1"))
        assert inv["schema_version"] == 4 and inv["replay"]["entries"] >= 2
        rep = R.load_replay("wrp1")
        assert rep["self_ids"] == ["u-1001"]
        put = [e for e in rep["entries"] if e["method"] == "PUT" and e["url"].endswith("/api/v3/profile")]
        assert put and json.loads(put[0]["body"]) == {"display_name": "Tester"}
        assert put[0]["source"] == "aborted"
        me = [e for e in rep["entries"] if e["url"].endswith("/api/v3/me")]
        assert me and set(me[0]["response_keys"]) >= {"id", "role", "plan"}
        edges = [e for p in inv["pages"] for e in p["api_edges"]]
        assert any(e.get("replay_id") == put[0]["replay_id"] for e in edges)
        inv_blob = open(os.path.join(str(walk_dir), "wrp1.replay.json")).read()
        assert sid not in inv_blob
        assert "Tester" not in json.dumps(inv)   # values never in the inventory
        assert app.non_get_requests() == []
    finally:
        app.close()


# -- spec 3b, Task 3: response_meta (status + header NAMES only) -----------------
def test_note_response_meta_stores_names_not_values():
    b = buf()
    b.add("GET", H + "/v4/page?lang=en", {}, None, "get-sent", None, None)
    b.note_response_meta("GET", H + "/v4/page?lang=en", 200,
                         {"Age": "12", "X-Cache": "HIT", "Set-Cookie": "sid=SECRETVALUE",
                          "Cache-Control": "public, max-age=60", "Content-Type": "text/html; charset=utf-8",
                          "Via": "1.1 varnish", "X-Akamai-Request-Id": "abc"})
    meta = b.to_dict("w", None)["entries"][0]["response_meta"]
    assert meta["status"] == 200 and meta["content_type"] == "text/html"
    assert set(meta["cache_signals"]) >= {"age", "x-cache", "cache-control:public", "via"}
    assert "x-akamai-request-id" in meta["proxy_signals"] and "via" in meta["proxy_signals"]
    blob = json.dumps(b.to_dict("w", None))
    assert "SECRETVALUE" not in blob and "varnish" not in blob and "set-cookie" not in blob.lower()


def test_meta_records_403_status_and_old_entries_have_no_meta():
    b = buf()
    b.add("GET", H + "/api/v4/reports", {}, None, "get-sent", None, None)
    b.add("GET", H + "/api/other", {}, None, "get-sent", None, None)
    b.note_response_meta("GET", H + "/api/v4/reports", 403, {"Content-Type": "application/json"})
    es = {e["url"]: e for e in b.to_dict("w", None)["entries"]}
    assert es[H + "/api/v4/reports"]["response_meta"]["status"] == 403
    assert es[H + "/api/other"].get("response_meta", {}) == {}


@requires_browser
def test_walk_records_response_meta_for_fixture_page(tmp_path, monkeypatch, walk_dir):
    import browser_confirm
    import ui_walk

    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    app = serve(vulnerable=True)
    try:
        sf = str(tmp_path / "s.json")
        app.write_session_file(sf)
        asyncio.run(ui_walk.walk(app.base_url + "/v4", "map", session_file=sf, max_pages=4,
                                 scope_check=lambda u: urlsplit(u).hostname == "127.0.0.1",
                                 screenshot_dir=str(tmp_path), walk_id="wrp2", action_delay_s=0))
        rep = R.load_replay("wrp2")
        by = {urlsplit(e["url"]).path: e for e in rep["entries"] if e["method"] == "GET"}
        assert by["/api/v4/reports"]["response_meta"]["status"] == 403
        assert by["/api/v4/admin"]["response_meta"]["status"] == 403
        assert by["/api/v4/export"]["response_meta"]["status"] == 200
        page = [e for e in rep["entries"] if urlsplit(e["url"]).path == "/v4/page"]
        assert page and "age" in page[0]["response_meta"]["cache_signals"]
    finally:
        app.close()
