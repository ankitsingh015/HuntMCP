"""Spec 3b, Task 8: plan + run for the GET-class request-level families (routing
headers, method swap/override, path tricks, cache poison / deception, GraphQL
queries) over a real map walk of the fixture's /v4 page -- vulnerable vs patched,
WITHOUT the Pass-2 grant."""

import asyncio
import os
import sys
from urllib.parse import parse_qsl, urlsplit

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "ui_walk_target"))

import browser_confirm  # noqa: E402
import mutation_logic as M  # noqa: E402
import mutation_runner as MR  # noqa: E402
import ui_walk  # noqa: E402
from ui_walk_app import requires_browser, serve  # noqa: E402

pytestmark = requires_browser


def _scope(u):
    return urlsplit(u).hostname == "127.0.0.1"


class Env:
    def __init__(self, tmp_path_factory, vulnerable=True):
        self.mp = pytest.MonkeyPatch()
        self.mp.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
        self.dir = tmp_path_factory.mktemp("uw3b")
        self.mp.setenv("HUNTMCP_UI_WALK_DIR", str(self.dir))
        self.app = serve(vulnerable=vulnerable)
        self.sf = str(tmp_path_factory.mktemp("s") / "s.json")
        self.app.write_session_file(self.sf)
        self.inv = asyncio.run(ui_walk.walk(self.app.base_url + "/v4", "map", session_file=self.sf,
                                            scope_check=_scope, max_pages=6, action_delay_s=0,
                                            screenshot_dir=str(self.dir)))
        self.walk_id = self.inv["walk_id"]

    def _env(self):
        os.environ["HUNTMCP_UI_WALK_DIR"] = str(self.dir)   # several Envs can be alive at once

    def plan(self, **kw):
        self._env()
        return MR.make_plan(self.walk_id, scope_check=_scope, grant=None, **kw)

    def run(self, grant=None, **kw):
        p = self.plan()
        self._env()
        self.n0 = len(self.app.requests)
        return asyncio.run(MR.run(p["plan_id"], session_file=self.sf, scope_check=_scope, grant=grant,
                                  action_delay_s=0, **kw))

    def close(self):
        self.app.close()
        self.mp.undo()


def types(res, route_suffix=None):
    out = []
    for c in res["candidates"]:
        if route_suffix is None or any(r["replay_id"] == c["replay_id"] and r["route"].endswith(route_suffix)
                                       for r in res["results"]):
            out.append(c["type"])
    return sorted(out)


def rid_of(env, suffix, method="GET"):
    env._env()
    rep = MR.R.load_replay(env.walk_id)
    return next(e["replay_id"] for e in rep["entries"]
                if e["method"] == method and urlsplit(e["url"]).path == suffix)


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


def test_plan_has_request_families_with_reasons(vuln):
    p = vuln.plan()
    fams = {}
    for r in p["requests"]:
        for v in r["variants"]:
            fams.setdefault(urlsplit(r["route"]).path, set()).add(v["family"])
            assert v["reason"]
    assert "header" in fams["/api/v4/admin"] and "path" in fams["/api/v4/reports"]
    assert "method" in fams["/api/v4/export-acl"] and "cache" in fams["/v4/page"]
    assert "cache" in fams["/v4/account-page"]                       # authed HTML page: deception check
    assert "cache" not in fams["/api/v4/export"] and "header" not in fams["/api/v4/export"]
    gq = [v for r in p["requests"] for v in r["variants"] if v["family"] == "graphql"]
    assert any(v["would_send"] for v in gq)                          # read-only queries need no grant
    # ... while the recorded GraphQL *mutation* (setName) is planned but held
    assert any(not v["would_send"] and v["why_not"] == "needs grant" for v in gq)
    # non-GET variants are held without the grant (a read-only GraphQL query is the one POST that is not)
    held = [v for r in p["requests"] if not r["route"].endswith("/graphql") for v in r["variants"]
            if v["family"] in ("race", "content-type", "json-diff")]
    assert held and not any(v["would_send"] for v in held)


def test_header_authz_vulnerable_candidate_patched_none(vuln, patched):
    cs = [c for c in vuln.res["candidates"] if c["type"] == "header-authz-bypass-candidate"]
    assert cs and any(c["change"][0]["field"] == "X-Forwarded-For" for c in cs)
    assert "header-authz-bypass-candidate" not in types(patched.res)


def test_agent_set_header_original_url_finds_routing_bypass(vuln, patched):
    for env, expect in ((vuln, True), (patched, False)):
        rid = rid_of(env, "/api/v4/export")
        extra = [{"replay_id": rid, "op": "set_header", "name": "X-Original-URL", "value": "/api/v4/admin",
                  "reason": "export sits behind the same front end"}]
        res = env.run(extra_variants=extra)
        got = [c for c in res["candidates"] if c["origin"] == "agent"]
        assert bool(got) is expect, res.get("agent_variant_errors")
        assert not res["agent_variant_errors"]


def test_path_variants_carry_buster_too(vuln):
    reqs = [p for m, p in vuln.app.requests[vuln.n0:] if urlsplit(p).path.lower().startswith("/api/v4/reports")
            and urlsplit(p).path != "/api/v4/reports"]
    assert reqs and all("hmcb=" in p for p in reqs), reqs


def test_path_trick_vulnerable_candidate_patched_none(vuln, patched):
    assert "path-normalization-candidate" in types(vuln.res, "/api/v4/reports")
    assert "path-normalization-candidate" not in types(patched.res)


def test_method_head_swap_and_override_vulnerable_candidate_patched_none(vuln, patched):
    cs = [c for c in vuln.res["candidates"] if c["type"] == "method-override-candidate"]
    assert cs and any(c["change"][0]["op"] in ("method", "override") for c in cs)
    assert "method-override-candidate" not in types(patched.res)


def test_cache_poison_vulnerable_candidate_patched_none(vuln, patched):
    assert "cache-poisoning-candidate" in types(vuln.res, "/v4/page")
    assert "cache-poisoning-candidate" not in types(patched.res)


def test_cache_deception_vulnerable_candidate_patched_none(vuln, patched):
    assert "cache-deception-candidate" in types(vuln.res, "/v4/account-page")
    assert "cache-deception-candidate" not in types(patched.res)


def test_cache_variants_always_carry_buster(vuln):
    reqs = vuln.app.requests[vuln.n0:]
    page = [p for m, p in reqs if p.startswith("/v4/page") or p.startswith("/v4/account-page/")]
    assert page, "the run must have touched the cache fixtures"
    for p in page:
        assert dict(parse_qsl(urlsplit(p).query)).get("hmcb"), p
    # one unique token per request chain (variant + its follow-up share one; chains never share)
    toks = [dict(parse_qsl(urlsplit(p).query))["hmcb"] for p in page]
    assert len(set(toks)) > 1


def test_graphql_query_alias_and_batch_vulnerable_candidate_patched_none(vuln, patched):
    assert "graphql-batching-candidate" in types(vuln.res)
    assert "graphql-batching-candidate" not in types(patched.res)


def test_no_grant_run_sends_only_get_class(vuln):
    ng = [(m, p) for m, p in vuln.app.requests[vuln.n0:] if m not in ("GET", "HEAD", "OPTIONS")]
    assert ng and all((m, p) == ("POST", "/api/v4/graphql") for m, p in ng)       # read-only queries only
    # every held non-GET variant says why
    held = [r for r in vuln.res["results"] if not r["sent"] and r["family"] in
            ("race", "content-type", "json-diff", "method")]
    assert held and all(r["why_not"] for r in held)
    assert any(r["why_not"] == "needs grant" for r in held)


def test_override_delete_and_swap_post_are_held_without_grant(vuln):
    p = vuln.plan()
    exp = next(r for r in p["requests"] if r["route"].endswith("/api/v4/export-acl"))
    held = [v for v in exp["variants"] if v["family"] == "method" and not v["would_send"]]
    assert held and all(v["why_not"] == "needs grant" for v in held)
    sent = [v for v in exp["variants"] if v["family"] == "method" and v["would_send"]]
    assert sent                                                                  # HEAD forms still go


def test_forbidden_headers_stripped_from_variant_on_the_wire(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda *_a, **_k: {})
    seen = {}

    class Resp:
        status = 200

        async def text(self):
            return "ok"

    class Request:
        async def fetch(self, url, **kw):
            seen.update(kw)
            return Resp()

    class Ctx:
        request = Request()

    r = MR.Runner({"walk_id": "w", "plan_id": "p", "requests": []}, {"entries": []}, scope=_scope, grant=None,
                  max_sent=10, delay=0, wall_clock_s=60)
    r.ctx = Ctx()
    req = M.Req("r1", "GET", "http://127.0.0.1:1/x", {"Cookie": "a=1", "Authorization": "Bearer x", "Host": "evil",
                                                      "Proxy-Authorization": "p", "Proxy-Foo": "1",
                                                      "Transfer-Encoding": "chunked", "Content-Length": "9",
                                                      "X-Keep": "yes"}, None, "none", "x")
    asyncio.run(r._send(req))
    assert seen["headers"] == {"X-Keep": "yes"}


def test_block_signal_stops_host_for_3b_variants(tmp_path_factory):
    e = Env(tmp_path_factory, True)
    try:
        e.app.v4_block_after = 3
        res = e.run()
        n0 = e.n0
        assert res["status"] == "blocked" and res["blocked_hosts"]
        v4 = [p for m, p in e.app.requests[n0:] if "/v4" in p]
        assert len(v4) == 1                      # the blocked one: nothing else is sent to the host
        assert not res["candidates"]
    finally:
        e.close()
