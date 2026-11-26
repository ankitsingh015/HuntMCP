"""Spec 3a, Task 8: plan + run over a real map walk of the fixture's /acct
page, vulnerable vs patched, with and without the Pass-2 grant."""

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

import browser_confirm  # noqa: E402
import mutation_runner as MR  # noqa: E402
import ui_walk  # noqa: E402
import ui_walk_replay as R  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402
from ui_walk_grant import Grant  # noqa: E402

pytestmark = requires_browser
GRANT = Grant(canary_submit=True, real_submit_cap_per_walk=200)


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


class Env:
    def __init__(self, tmp_path_factory, vulnerable=True, **app_kw):
        self.mp = pytest.MonkeyPatch()
        self.mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
        self.dir = tmp_path_factory.mktemp("uwm")
        self.mp.setenv("HUNTMCP_UI_WALK_DIR", str(self.dir))
        self.app = serve(vulnerable=vulnerable)
        for k, v in app_kw.items():
            setattr(self.app, k, v)
        self.sf = str(tmp_path_factory.mktemp("s") / "s.json")
        self.app.write_session_file(self.sf)
        self.inv = asyncio.run(ui_walk.walk(self.app.base_url + "/acct", "map", session_file=self.sf,
                                            scope_check=_scope, max_pages=6, action_delay_s=0,
                                            screenshot_dir=str(self.dir)))
        self.walk_id = self.inv["walk_id"]

    def plan(self, **kw):
        return MR.make_plan(self.walk_id, **kw)

    def run(self, grant=None, session_file=None, **kw):
        p = self.plan()
        return asyncio.run(MR.run(p["plan_id"], session_file=session_file or self.sf, scope_check=_scope,
                                  grant=grant, action_delay_s=0, **kw))

    def close(self):
        self.app.close()
        self.mp.undo()


def _types(res):
    return sorted({c["type"] for c in res["candidates"]})


@pytest.fixture(scope="module")
def vuln_granted(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    before = list(e.app.non_get_requests())
    res = e.run(grant=GRANT)
    yield e, res, before
    e.close()


@pytest.fixture(scope="module")
def patched_granted(tmp_path_factory):
    e = Env(tmp_path_factory, False)
    res = e.run(grant=GRANT)
    yield e, res
    e.close()


def test_plan_lists_variants_with_reasons_and_no_values(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        p = e.plan()
        routes = {r["route"] for r in p["requests"]}
        assert any(r.endswith("/api/v3/profile") for r in routes)
        put = next(r for r in p["requests"] if r["route"].endswith("/api/v3/profile"))
        role = [v for v in put["variants"] if v["family"] == "add" and "role" in v["change"]]
        assert role and "response" in role[0]["reason"]
        assert role[0]["needs_grant"] is True and role[0]["would_send"] is False
        assert role[0]["why_not"] == "needs grant"
        blob = json.dumps(p)
        assert "Tester" not in blob and "tester@example.invalid" not in blob
        assert os.path.isfile(os.path.join(str(e.dir), f"{e.walk_id}.plan-{p['plan_id']}.json"))
    finally:
        e.close()


def test_run_without_grant_sends_only_gets(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        before = list(e.app.non_get_requests())
        res = e.run(grant=None)
        assert res["status"] == "complete", res
        assert e.app.non_get_requests() == before
        assert e.app.v3_me["role"] == "user"
        assert "hpp-candidate" in _types(res) and "type-juggling-candidate" in _types(res)
        assert res["sent"] > 0
    finally:
        e.close()


def test_run_vulnerable_finds_mass_assignment_persisted_and_restores(vuln_granted):
    e, res, _before = vuln_granted
    assert res["status"] == "complete", res
    ma = [c for c in res["candidates"] if c["type"] == "mass-assignment-candidate"]
    assert any(c["persisted"] is True and "role" in json.dumps(c["change"]) for c in ma)
    assert e.app.v3_me["role"] == "user" and e.app.v3_me["plan"] == "free"
    assert e.app.v3_me["email"] == "tester@example.invalid"
    assert not res["restore_failures"]
    assert any(r.get("restore") == "ok" for r in res["results"])


def test_run_patched_no_mass_assignment(patched_granted):
    _e, res = patched_granted
    assert res["status"] == "complete", res
    assert "mass-assignment-candidate" not in _types(res)


def test_run_vulnerable_otp_removal_candidate(vuln_granted, patched_granted):
    _e, res, _ = vuln_granted
    assert any(c["type"] == "param-removal-bypass-candidate" and "otp" in json.dumps(c["change"])
               for c in res["candidates"])
    assert "param-removal-bypass-candidate" not in _types(patched_granted[1])


def test_run_hpp_and_type_juggling_vulnerable_only(vuln_granted, patched_granted):
    assert {"hpp-candidate", "type-juggling-candidate"} <= set(_types(vuln_granted[1]))
    assert not {"hpp-candidate", "type-juggling-candidate"} & set(_types(patched_granted[1]))


def test_non_get_only_to_owned_routes(vuln_granted):
    e, _res, before = vuln_granted
    sent = [r for r in e.app.non_get_requests() if r not in before]
    assert sent and all(urlsplit(p).path in ("/api/v3/profile", "/api/v3/account/change-email") for _m, p in sent)


def test_run_refuses_other_identity(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        other = str(tmp_path_factory.mktemp("o") / "o.json")
        e.app.write_session_file(other, other=True)
        res = e.run(grant=GRANT, session_file=other)
        assert res["status"] == "refused" and "identity" in res["error"]
        assert res["sent"] <= 1   # only the identity-check GET
        assert not [r for r in res["results"] if r.get("sent")]
    finally:
        e.close()


def test_auth_lost_mid_run_stops(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        e.app.v3_requests = 0
        e.app.v3_expire_after = 6
        res = e.run(grant=None)
        assert res["status"] == "auth_lost", res["status"]
        assert not [c for c in res["candidates"] if c["evidence"]["variant_status"] == 401]
    finally:
        e.close()


def test_restore_failure_stops_object(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        e.app.v3_sticky_role = True
        res = e.run(grant=GRANT)
        assert res["status"] == "restore_failed"
        f = res["restore_failures"][0]
        assert f["route"].endswith("/api/v3/profile") and f["field"] == "role"
        after = [r for r in res["results"] if r.get("route", "").endswith("/api/v3/profile")
                 and r.get("after_restore_failure")]
        assert not [r for r in after if r.get("sent")]
    finally:
        e.close()


def test_cap_cumulative_across_runs(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        small = Grant(canary_submit=True, real_submit_cap_per_walk=8)   # 3 usable + 5 restore reserve
        r1 = e.run(grant=small)
        used1 = R.SendCounter(e.walk_id).used()
        assert used1 <= 8
        r2 = e.run(grant=small)
        assert R.SendCounter(e.walk_id).used() <= 8
        assert any(x.get("why_not") == "cap-reached" for x in r1["results"] + r2["results"])
    finally:
        e.close()


def test_block_stops_host(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        e.app.v3_requests = 0
        e.app.v3_rate_limit_after = 4
        res = e.run(grant=None)
        assert res["status"] == "blocked"
        assert e.app.v3_requests <= 4 + 2
    finally:
        e.close()


def test_results_and_plan_files_hold_no_secret(vuln_granted):
    e, res, _ = vuln_granted
    sid = json.load(open(e.sf))["cookies"][0]["value"]
    for name in os.listdir(str(e.dir)):
        if name.endswith(".replay.json") or not name.endswith(".json"):
            continue
        text = open(os.path.join(str(e.dir), name)).read()
        assert sid not in text and e.app.v3_otp not in text, name
    assert sid not in json.dumps(res) and e.app.v3_otp not in json.dumps(res)
