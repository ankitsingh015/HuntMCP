"""Spec 3b, Task 9: the non-GET request-level families (content-type switch,
JSON parser differential, GraphQL mutation gating, races) over a real map walk
of the fixture's /v4 page -- WITH the Pass-2 grant, vulnerable vs patched."""

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
import mutation_logic as M  # noqa: E402
import mutation_runner as MR  # noqa: E402
import mutation_xform as MX  # noqa: E402
import ui_walk  # noqa: E402
import ui_walk_store  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402
from ui_walk_grant import Grant  # noqa: E402

pytestmark = requires_browser
GRANT = Grant(canary_submit=True, real_submit_cap_per_walk=600)
# the run's 400-request cap is per run: one focused run per object keeps every family inside it
FOCUS = ("/api/v3/profile", "/api/v4/preferences", "/api/v4/graphql", "/api/v4/coupons/c-1")
REDEEM = "/api/v4/coupons/c-1/redeem"


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


class Env:
    def __init__(self, tmp_path_factory, vulnerable=True, register_coupon=True, **app_kw):
        self.mp = pytest.MonkeyPatch()
        self.mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
        self.dir = tmp_path_factory.mktemp("uw3bn")
        self.app = serve(vulnerable=vulnerable)
        self.sf = str(tmp_path_factory.mktemp("s") / "s.json")
        self.app.write_session_file(self.sf)
        self._env()
        self.inv = asyncio.run(ui_walk.walk(self.app.base_url + "/v4", "map", session_file=self.sf,
                                            scope_check=_scope, max_pages=6, action_delay_s=0,
                                            screenshot_dir=str(self.dir)))
        self.walk_id = self.inv["walk_id"]
        if register_coupon:   # the walker "created" coupon c-1 (models a Pass-2 create)
            ui_walk_store.register_created_id("seed-c1", "c-1")
        for k, v in app_kw.items():
            setattr(self.app, k, v)

    def _env(self):
        os.environ["HUNTMCP_UI_WALK_DIR"] = str(self.dir)

    def plan(self, grant=GRANT, **kw):
        self._env()
        return MR.make_plan(self.walk_id, scope_check=_scope, grant=grant, **kw)

    def run_one(self, grant=GRANT, request_filter="", **kw):
        p = self.plan(grant, request_filter=request_filter)
        self._env()
        return asyncio.run(MR.run(p["plan_id"], session_file=self.sf, scope_check=_scope, grant=grant,
                                  action_delay_s=0, **kw))

    def run(self, grant=GRANT, filters=FOCUS, **kw):
        """One focused run per filter, merged (each run has its own 400-request cap)."""
        self.n0 = len(self.app.requests)
        out = {"status": "complete", "candidates": [], "results": [], "restore_failures": [], "sent": 0,
               "blocked_hosts": [], "agent_variant_errors": []}
        for f in filters:
            r = self.run_one(grant, f, **kw)
            for k in ("candidates", "results", "restore_failures", "blocked_hosts", "agent_variant_errors"):
                out[k] += r.get(k) or []
            out["sent"] += r.get("sent", 0)
            if r["status"] != "complete" and out["status"] == "complete":
                out["status"] = r["status"]
        return out

    def close(self):
        self.app.close()
        self.mp.undo()


def types(res, route_suffix=None):
    ids = {r["replay_id"] for r in res["results"] if route_suffix and r["route"].endswith(route_suffix)}
    return sorted({c["type"] for c in res["candidates"] if not route_suffix or c["replay_id"] in ids})


def posts(env, path):
    return [1 for m, p in env.app.requests[env.n0:] if m == "POST" and p == path]


@pytest.fixture(scope="module")
def vuln(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    e.res = e.run()
    yield e
    e.close()


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    e = Env(tmp_path_factory, False)
    e.res = e.run()
    yield e
    e.close()


def test_content_type_form_text_vulnerable_candidate_patched_none(vuln, patched):
    ids = {r["replay_id"] for r in vuln.res["results"] if r["route"].endswith("/api/v3/profile")}
    cs = [c for c in vuln.res["candidates"] if c["type"] == "content-type-confusion-candidate"
          and c["replay_id"] in ids]
    assert {c["change"][0]["value"] for c in cs} >= {"form", "text"}
    assert "content-type-confusion-candidate" not in types(patched.res, "/api/v3/profile")
    # the profile is as the walk found it (3a restore + 3b variants left nothing behind)
    assert vuln.app.v3_me["role"] == "user" and vuln.app.v3_me["display_name"] == "Tester"
    assert vuln.res["status"] in ("complete", "left-null") or not vuln.res["restore_failures"]


def test_json_dup_key_vulnerable_candidate_patched_none(vuln, patched):
    assert "json-parser-differential-candidate" in types(vuln.res)
    assert "json-parser-differential-candidate" not in types(patched.res)
    assert vuln.app.v4_prefs["theme"] == "dark"                      # restored
    assert not vuln.res["restore_failures"]


def test_graphql_mutation_never_sent_even_with_grant_when_not_owned(vuln):
    mut = [r for r in vuln.res["results"] if r["route"].endswith("/api/v4/graphql") and not r["sent"]
           and r["why_not"] == "not-owned"]
    assert mut
    assert vuln.app.v3_me["display_name"] == "Tester"                # setName never ran
    # the read-only query entry still ran without needing ownership
    assert "graphql-batching-candidate" in types(vuln.res)


def test_race_vulnerable_candidate_patched_none(vuln, patched):
    assert "race-candidate" in types(vuln.res)
    c = next(c for c in vuln.res["candidates"] if c["type"] == "race-candidate")
    ev = c["evidence"]["race"]
    assert ev["ok"] >= 2 and ev["n"] == 5 and not ev["idempotent"] and c["persisted"] is True
    assert "race-candidate" not in types(patched.res)
    assert any(r["family"] == "race" and r["sent"] for r in patched.res["results"])   # it ran, found nothing


def test_race_requires_grant_and_created_object(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        e.run(grant=None, filters=(REDEEM,))
        assert posts(e, REDEEM) == []                                  # no grant: nothing
    finally:
        e.close()
    e = Env(tmp_path_factory, True, register_coupon=False)
    try:
        res = e.run(filters=(REDEEM,))
        assert posts(e, REDEEM) == []                                  # grant, but not a walker-created object
        why = {r["why_not"] for r in res["results"] if r["family"] == "race"}
        assert why and why <= {"race needs walker-created object", "not-owned"}
    finally:
        e.close()


def test_race_idempotent_endpoint_skipped(tmp_path_factory):
    e = Env(tmp_path_factory, True, v4_idempotent_redeem=True)
    try:
        res = e.run(filters=(REDEEM,))
        assert "race-candidate" not in types(res)
        assert any(r["family"] == "race" and r.get("why_not") == "idempotent endpoint" for r in res["results"])
    finally:
        e.close()


def test_race_respects_cap_and_n_max(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        res = e.run(grant=Grant(canary_submit=True, real_submit_cap_per_walk=8), filters=(REDEEM,))   # 8 - reserve 5 = 3 usable
        assert len(posts(e, REDEEM)) <= 3                                # nothing beyond the cap...
        assert not [r for r in res["results"] if r["family"] == "race" and r["sent"]]   # ...and no race
        assert any(r["family"] == "race" and r.get("why_not") == "cap-reached" for r in res["results"])
    finally:
        e.close()
    assert MR.race_n(MX.Xform("race", "", None, 50), create=False) == 10
    assert MR.race_n(MX.Xform("race", "", None, 5), create=True) == 3
    assert MR.race_n(MX.Xform("race", "", None, 5), create=False) == 5
    assert MR.race_n(MX.Xform("race", "", None, 0), create=False) == 2
    vs, errs = MX.validate_request_ops([{"replay_id": "r1", "op": "race", "n": 50}],
                                       {"r1": M.Req("r1", "POST", "http://h/x", {}, "{}", "json", "x")})
    assert not vs and "not available" in errs[0]                       # the agent cannot ask for a race


def test_restore_failed_stops_further_3b_variants_on_object(tmp_path_factory):
    e = Env(tmp_path_factory, True, v3_sticky_role=True)
    try:
        res = e.run(filters=("/api/v3/profile",))
        assert res["status"] == "restore_failed"
        assert res["restore_failures"][0]["route"].endswith("/api/v3/profile")
        later = [r for r in res["results"] if r.get("after_restore_failure")]
        assert later and not any(r["sent"] for r in later)
    finally:
        e.close()


def test_no_secret_in_any_3b_output(vuln):
    otp = vuln.app.v3_otp
    sid = json.load(open(vuln.sf))["cookies"][0]["value"]
    d = str(vuln.dir)
    for name in os.listdir(d):
        if name.endswith(".replay.json") or not name.endswith(".json"):
            continue
        blob = open(os.path.join(d, name)).read()
        assert sid not in blob and otp not in blob, name
    assert sid not in json.dumps(vuln.res) and otp not in json.dumps(vuln.res)
