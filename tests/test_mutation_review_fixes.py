"""Spec 3a review-and-audit fix pass: one test per finding (RED first)."""

import asyncio
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import browser_confirm  # noqa: E402
import mutation_logic as M  # noqa: E402
import mutation_runner as MR  # noqa: E402
import pytest  # noqa: E402
import ui_walk_events  # noqa: E402
import ui_walk_replay as R  # noqa: E402

H = "http://127.0.0.1:9000"


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path))


# -- CR5: token / session values are withheld (CSRF stays) ----------------------
def test_token_and_session_names_withheld():
    for n in ("access_token", "refresh_token", "id_token", "X-Auth-Token", "session", "sessionId",
              "jwt", "bearer", "authToken", "token"):
        assert R.is_withheld_name(n), n
    for n in ("csrf_token", "_token", "xsrf-token", "X-CSRF-Token", "X-XSRF-TOKEN", "csrfmiddlewaretoken",
              "display_name", "email", "promo", "to"):
        assert not R.is_withheld_name(n), n


# -- CR4: created-id ownership only by id position --------------------------------
def _req(method, url, body=None):
    hj = {"Content-Type": "application/json"} if body else {}
    return M.Req("r1", method, url, hj, body, M.body_kind_of(hj, body), "x")


def test_created_id_ownership_ignores_unrelated_values():
    created = {"1"}
    assert not M.ownership(_req("POST", H + "/api/orders?page=1"), created, set(), None).owned
    assert not M.ownership(_req("PUT", H + "/api/cart", '{"qty": 1}'), created, set(), None).owned
    assert M.ownership(_req("PUT", H + "/api/items/1"), created, set(), None).kind == "created"
    assert M.ownership(_req("POST", H + "/api/x", '{"item_id": "1"}'), created, set(), None).kind == "created"
    assert M.ownership(_req("POST", H + "/api/x?id=1"), created, set(), None).kind == "created"


# -- S1: no foreign ids in a non-GET variant, rule- or agent-built ----------------
def test_foreign_id_in_non_get_variant_blocked():
    ops = [M.Op("set_param", "json", ("owner_id",), "u-2002")]
    assert M.carries_foreign_id(ops, foreign_ids={"u-2002"}, created=set(), self_ids={"u-1001"})
    ops = [M.Op("add_param", "json", ("account_id",), "acct-77")]   # id field, value not ours
    assert M.carries_foreign_id(ops, foreign_ids=set(), created=set(), self_ids={"u-1001"})
    ops = [M.Op("add_param", "json", ("user_id",), "u-1001")]       # our own id
    assert not M.carries_foreign_id(ops, foreign_ids=set(), created=set(), self_ids={"u-1001"})
    ops = [M.Op("add_param", "json", ("role",), "admin")]
    assert not M.carries_foreign_id(ops, foreign_ids={"u-2002"}, created=set(), self_ids=set())


# -- CR3: persistence is attributed to the variant, not the baseline --------------
def test_persisted_ignores_baseline_induced_changes():
    assert M.attribute_readback("persisted", ["display_name"], {"display_name"}) == "not-persisted"
    assert M.attribute_readback("persisted", ["display_name", "role"], {"display_name"}) == "persisted"
    assert M.attribute_readback("unknown", [], set()) == "unknown"
    assert M.attribute_readback("not-persisted", [], {"x"}) == "not-persisted"


# -- CR6: only real block signals stop a host -------------------------------------
def test_block_signal_rules():
    assert M.is_block_signal(429, "")
    assert not M.is_block_signal(403, '{"error": "Access denied"}')
    assert not M.is_block_signal(403, "<h1>Access denied</h1>")
    assert M.is_block_signal(403, "<html>Attention Required! | Cloudflare</html>")
    assert M.is_block_signal(503, "<html>Request blocked. Incapsula incident ID</html>")
    assert not M.is_block_signal(200, "cloudflare")


# -- fake runner plumbing -------------------------------------------------------
class _FakeResp:
    def __init__(self, status, body=""):
        self.status, self._b = status, body

    async def text(self):
        return self._b


class _FakeReq:
    def __init__(self, status=200, body='{"id": "u-1001"}'):
        self.calls = 0
        self.status, self.body = status, body

    async def fetch(self, *_a, **_k):
        self.calls += 1
        return _FakeResp(self.status, self.body)


class _Ctx:
    def __init__(self, req):
        self.request = req


def _runner():
    plan = {"plan_id": "p1", "walk_id": "w1", "requests": []}
    rep = {"entries": [{"replay_id": "r1", "method": "GET", "url": H + "/api/me", "headers": {}, "body": None,
                        "response_keys": ["id"]}], "self_ids": ["u-1001"], "session_file_realpath": None}
    r = MR.Runner(plan, rep, scope=lambda u: u.startswith(H), grant=None, max_sent=50, delay=0, wall_clock_s=60)
    r.identity_probe = "r1"
    return r


# -- CR1 / CR8: every request the runner sends is budget-charged ---------------------
def test_auth_check_is_budget_charged(monkeypatch):
    calls = []
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: calls.append(1) or {})
    r = _runner()
    r.ctx = _Ctx(_FakeReq(200))
    asyncio.run(r._check_auth())
    assert calls == [1]


def test_identity_budget_exhausted_is_budget_status(monkeypatch):
    from budget_guard import BudgetExceeded

    def boom(*_a, **_k):
        raise BudgetExceeded("spent")

    monkeypatch.setattr(browser_confirm, "_enforce_budget", boom)
    r = _runner()
    r.ctx = _Ctx(_FakeReq(200))
    with pytest.raises(MR._Stop) as ei:
        asyncio.run(r._identity(""))
    assert ei.value.status == "budget_exhausted"


# -- CR2: an unknown read-back is restored, and a still-unknown one is loud ---------
def test_unknown_readback_restores_and_reports(monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    r = _runner()
    sent = []

    async def fake_send(req):
        sent.append(req)
        return M.resp_from(200, "{}")

    async def fake_readback(*_a, **_k):
        return "unknown", [], None

    async def fake_take(restore):
        return True

    r._send, r._readback, r._take = fake_send, fake_readback, fake_take
    e = {"replay_id": "r2", "url": H + "/api/v3/profile"}
    base = _req("PUT", H + "/api/v3/profile", '{"display_name": "x"}')
    var = _req("PUT", H + "/api/v3/profile", '{"display_name": "x", "role": "admin"}')
    rb, rs = asyncio.run(r._state_change(e, var, base, base, {"display_name": "x"}, set(), "obj"))
    assert rs == "failed" and sent and sent[0].body == base.body   # restore = the original request
    assert r.res["restore_failures"] and r.res["restore_failures"][0]["field"] == "unknown"


# -- S2: only the planted URL in Referer is exempt ----------------------------------
def test_referer_exemption_only_for_exact_planted_url():
    rec = ui_walk_events.Recorder()
    rec_page = {"events": []}
    q = rec.new_dom_token("query:a", rec_page)
    h = rec.new_dom_token("hash", rec_page)
    planted = f"{H}/p?a={q}"
    rec._query_navs[q] = planted
    assert rec.referer_is_planted(planted)
    assert rec.referer_is_planted(planted + "#frag")
    assert not rec.referer_is_planted(f"{H}/p?a={q}&b={h}")     # a second (hash) token rides along
    assert not rec.referer_is_planted(f"{H}/other?a={q}")       # not the planted URL
    assert not rec.referer_is_planted(f"{H}/p?a={h}")


# -- runtime finding: a key the restore cannot remove is not "ok" ---------------------
def test_added_key_left_as_null_is_not_reported_ok(monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    r = _runner()
    s1 = {"id": "u-1001", "role": "user"}
    reads = iter([{"id": "u-1001", "role": "user", "admin": True},     # after the variant
                  {"id": "u-1001", "role": "user", "admin": None}])    # after the restore
    sent = []

    async def fake_send(req):
        sent.append(req)
        if req.method != "GET":
            return M.resp_from(200, '{"ok": true}')
        return M.resp_from(200, __import__("json").dumps(next(reads)))

    async def fake_take(restore):
        return True

    r._send, r._take = fake_send, fake_take
    snap = _req("GET", H + "/api/me")
    e = {"replay_id": "r2", "url": H + "/api/v3/profile"}
    base = _req("PUT", H + "/api/v3/profile", '{"display_name": "x"}')
    var = _req("PUT", H + "/api/v3/profile", '{"display_name": "x", "admin": true}')
    rb, rs = asyncio.run(r._state_change(e, var, base, snap, s1, set(), "obj"))
    assert rb == "persisted" and rs == "left-null"
    assert r.res["left_null_keys"] == [{"route": H + "/api/v3/profile", "field": "admin"}]
    assert not r.res["restore_failures"]


def test_readback_tells_missing_from_null(monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    r = _runner()

    async def fake_send(req):
        return M.resp_from(200, '{"id": "u-1001", "admin": null}')

    r._send = fake_send
    rb, changed, _ = asyncio.run(r._readback(_req("GET", H + "/api/me"), {"id": "u-1001"}, set()))
    assert rb == "persisted" and changed == ["admin"]
