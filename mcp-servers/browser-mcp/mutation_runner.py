"""Spec 3a (UI-walk request mutation): plan + run.

make_plan(walk_id)   -- no traffic. Profiles every replay-store request and
                        writes <walk-id>.plan-<plan_id>.json (variant ids,
                        field NAMES and our own injected values; never a
                        recorded value -- run() rebuilds the variants from the
                        replay store, the ids are stable).
run(plan_id, ...)    -- one browser context from the walk's session_file;
                        every request goes through context.request under the
                        send gates (mutation_logic.gate), budget_guard, the
                        cumulative per-walk cap, read-back + restore for
                        state-changing variants, and stops on a block signal,
                        auth loss, budget or time. Results file
                        <walk-id>.mutations-<run_id>.json (0600).

Candidates are LEADS for exploit-agent, never confirmed findings.
"""

from __future__ import annotations

import asyncio
import dataclasses
import glob
import json
import os
import sys
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import browser_confirm  # noqa: E402
import mutation_logic as M  # noqa: E402
import ui_walk  # noqa: E402
import ui_walk_events_logic  # noqa: E402
import ui_walk_grant  # noqa: E402
import ui_walk_logic as L  # noqa: E402
import ui_walk_pass2  # noqa: E402
import ui_walk_replay as R  # noqa: E402
import ui_walk_store  # noqa: E402
from budget_guard import BudgetExceeded  # noqa: E402
from endpoint_template import endpoint_template  # noqa: E402

DEFAULT_MAX_SENT = 400
DEFAULT_MAX_REQUESTS = 50
REQUEST_TIMEOUT_MS = 15000
RUN_WALL_CLOCK_S = 1200
_LOAD = object()   # run(grant=...) default: read the human-owned grant file
DUMMY_OTP = "000000"
DUMMY_VALUE = "hm-wrong"
HONEST_LIMITS = (
    "Candidates are leads: each needs manual confirmation (exploit-agent) before it is a finding.",
    ("Requests go through the browser's request context with the walk's cookies; an API that needs a "
     "bearer token held only in page memory works only if bearer_token is passed."),
    ("A state-changing variant is only sent with a read-back GET to verify and restore it; objects "
     "without one are planned but not sent."),
    "Duplicate HTTP headers and HTTP/2-only behaviour are not exercised (3b/3c).",
)


class _Stop(Exception):
    def __init__(self, status: str, error: str | None = None):
        super().__init__(status)
        self.status, self.error = status, error


_MISSING = object()


class _HostBlocked(Exception):
    """A block signal from one host: its remaining requests are skipped; other hosts go on."""


# -- plan ------------------------------------------------------------------------
def _req_of(e: dict) -> M.Req:
    return M.Req(e["replay_id"], e["method"], e["url"], dict(e.get("headers") or {}), e.get("body"),
                 M.body_kind_of(e.get("headers") or {}, e.get("body")), e.get("source") or "")


def _route(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def _classifications(inv: dict | None) -> dict:
    out = {}
    for page in (inv or {}).get("pages") or []:
        for c in page.get("controls") or []:
            if c.get("signature"):
                out[c["signature"]] = c.get("classification")
    return out


def _context(entries: list[dict], self_ids: set, created: set) -> M.Context:
    resp_keys: dict = {}
    sib: dict = {}
    foreign: set = set()
    for e in entries:
        tmpl = endpoint_template(e["url"])
        if e["method"] == "GET" and e.get("response_keys"):
            resp_keys.setdefault(tmpl, set()).update(e["response_keys"])
        try:
            params = M.parse_params(_req_of(e))
        except Exception:  # noqa: BLE001
            params = []
        sib.setdefault(tmpl, set()).update(str(p.path[0]) for p in params)
        if e["method"] == "GET":
            for p in params:
                if M.is_id_param(p) and isinstance(p.value, str) and p.value != M.WITHHELD \
                        and p.value not in self_ids and p.value not in created and len(p.value) <= 64:
                    foreign.add(p.value)
    return M.Context(resp_keys, sib, foreign)


def _snapshot_for(e: dict, entries: list[dict]) -> str | None:
    """The GET that reads back what a non-GET changes: same route template,
    else (own-account route) an own-account GET whose response was JSON."""
    tmpl = endpoint_template(e["url"])
    gets = [x for x in entries if x["method"] == "GET" and x.get("response_keys")]
    for x in gets:
        if endpoint_template(x["url"]) == tmpl:
            return x["replay_id"]
    if M.own_account_route(e["url"]):
        for x in gets:
            if M.own_account_route(x["url"]):
                return x["replay_id"]
    return None


def ctx_for(e: dict, ctx: M.Context, entries_by_id: dict, snapshot_id: str | None) -> M.Context:
    """The request's context plus its read-back GET's response keys (e.g.
    PUT /profile learns from GET /me): fields the object has but the UI never sends."""
    snap = entries_by_id.get(snapshot_id) if snapshot_id else None
    if not snap or not snap.get("response_keys"):
        return ctx
    tmpl = endpoint_template(e["url"])
    rk = {k: set(v) for k, v in ctx.response_keys.items()}
    rk.setdefault(tmpl, set()).update(snap["response_keys"])
    return M.Context(rk, ctx.sibling_fields, ctx.foreign_ids)


def _change_text(op: M.Op) -> str:
    field = ".".join(str(s) for s in op.path)
    shown = op.kind in ("add_param", "set_param", "duplicate_param")
    val = f" = {json.dumps(op.value)[:80]}" if shown else ""
    return f"{op.kind} {op.location}:{field}{val}"


def _variant_view(v: M.Variant) -> dict:
    return {"variant_id": v.variant_id, "family": v.family, "origin": v.origin, "score": v.score,
            "change": "; ".join(_change_text(o) for o in v.ops), "reason": v.reason}


def _never(e: dict, classes: dict) -> bool:
    return M.never_mutated(e["url"], classes.get(e.get("control_signature")))


def make_plan(walk_id: str, *, request_filter: str = "", max_requests: int = DEFAULT_MAX_REQUESTS,
              scope_check=None, grant=_LOAD) -> dict:
    rep = R.load_replay(walk_id)
    if rep is None:
        raise ValueError(f"no replay store for walk {walk_id!r} (run start_ui_walk first)")
    inv = ui_walk_store.load_inventory(walk_id)
    scope = scope_check or L._default_scope_check
    g = ui_walk_grant.load_grant() if grant is _LOAD else grant
    entries = [e for e in rep.get("entries") or [] if isinstance(e, dict)]
    self_ids = set(rep.get("self_ids") or [])
    created = set(ui_walk_store.load_created_ids())   # {created id: token} -> the ids
    ctx = _context(entries, self_ids, created)
    classes = _classifications(inv)
    by_id = {e["replay_id"]: e for e in entries}
    plan_id = "p" + uuid.uuid4().hex[:10]
    out = {"plan_id": plan_id, "walk_id": walk_id, "requests": [], "skipped": 0}
    for e in entries:
        if request_filter and request_filter not in e["url"]:
            continue
        if len(out["requests"]) >= max_requests:
            out["skipped"] += 1
            continue
        req = _req_of(e)
        never = _never(e, classes)
        is_get = M.effective_method(req) in ("GET", "HEAD") and req.method in ("GET", "HEAD")
        snap = None if is_get else _snapshot_for(e, entries)
        owned = M.ownership(req, created, self_ids, True if snap else None)
        views = []
        for v in M.build_plan(req, ctx_for(e, ctx, by_id, snap)):
            vreq = M.apply_ops(req, v.ops)
            gt = M.gate(vreq, scope=scope, grant=g, owned=owned, has_restore_path=bool(snap), never_mutated=never)
            if gt.send and not is_get and M.carries_foreign_id(v.ops, foreign_ids=ctx.foreign_ids,
                                                               created=created, self_ids=self_ids):
                gt = M.Gate(False, True, "foreign-id")
            views.append({**_variant_view(v), "needs_grant": gt.needs_grant, "would_send": gt.send,
                          "why_not": None if gt.send else gt.reason})
        out["requests"].append({"replay_id": e["replay_id"], "method": e["method"], "route": _route(e["url"]),
                                "source": e.get("source"), "never_mutated": never, "snapshot": snap,
                                "ownership": owned.kind, "ownership_reason": owned.reason,
                                "withheld_fields": e.get("withheld_fields") or [],
                                "body_truncated": bool(e.get("body_truncated")), "variants": views})
    R._write_private(os.path.join(ui_walk_store.walk_dir(), f"{walk_id}.plan-{plan_id}.json"), out)
    return out


def load_plan(plan_id: str) -> dict | None:
    if not isinstance(plan_id, str) or not plan_id.startswith("p") or not plan_id[1:].isalnum():
        return None
    hits = glob.glob(os.path.join(glob.escape(ui_walk_store.walk_dir()), f"*.plan-{plan_id}.json"))
    if len(hits) != 1:
        return None
    try:
        with open(hits[0]) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# -- run -------------------------------------------------------------------------
def _dummy_for(name: str) -> str:
    low = name.lower()
    return DUMMY_OTP if any(w in low for w in ("otp", "code", "pin", "mfa")) else DUMMY_VALUE


def fill_withheld(req: M.Req) -> M.Req:
    """Withheld values never go out: each becomes a wrong dummy of ours; a
    withheld header is dropped."""
    ops = [M.Op("set_param", p.location, p.path, _dummy_for(str(p.path[-1])))
           for p in M.parse_params(req) if p.withheld]
    out = M.apply_ops(req, ops) if ops else dataclasses.replace(req, headers=dict(req.headers))
    out.headers = {k: v for k, v in out.headers.items() if v != M.WITHHELD}
    return out


def _leaves(body: str):
    try:
        obj = json.loads(body or "")
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


class Runner:
    def __init__(self, plan: dict, rep: dict, *, scope, grant, max_sent: int, delay: float,
                 wall_clock_s: int, bearer_token: str = ""):
        self.plan, self.rep = plan, rep
        self.walk_id = plan["walk_id"]
        self.scope, self.grant = scope, grant
        self.cap = grant.real_submit_cap_per_walk if grant else 0
        self.counter = R.SendCounter(self.walk_id)
        self.max_sent, self.delay = max_sent, delay
        self.deadline = time.monotonic() + wall_clock_s
        self.bearer = bearer_token
        self.entries = {e["replay_id"]: e for e in rep.get("entries") or []}
        self.self_ids = set(rep.get("self_ids") or [])
        self.created = set(ui_walk_store.load_created_ids())
        self.run_id = "m" + uuid.uuid4().hex[:10]
        self.res = {"run_id": self.run_id, "plan_id": plan["plan_id"], "walk_id": self.walk_id,
                    "status": "complete", "error": None, "sent": 0, "results": [], "candidates": [],
                    "created_ids": [], "restore_failures": [], "left_null_keys": [], "blocked_hosts": [],
                    "honest_limits": list(HONEST_LIMITS), "burp_mirror": {"active": False}}
        self.ctx = None
        self.identity_probe: str | None = None
        self.recorded_values: list[str] = []
        self.failed_objects: set[str] = set()
        self.last_changed: list[str] = []
        self.ctx_data: M.Context | None = None

    # -- plumbing
    async def _send(self, req: M.Req) -> M.Resp:
        if time.monotonic() > self.deadline:
            raise _Stop("time_limit")
        if self.res["sent"] >= self.max_sent:
            raise _Stop("max_sent")
        host = urlsplit(req.url).hostname or ""
        if host in self.res["blocked_hosts"]:
            raise _HostBlocked(host)
        if not self.scope(req.url) or L.is_payment_host(host):
            raise RuntimeError("send gate bypassed")   # never reached: callers gate first
        await self._budget()
        headers = {k: v for k, v in req.headers.items()
                   if k.lower() not in ("content-length", "host", "cookie", "authorization")}
        if self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        self.res["sent"] += 1
        r = await self.ctx.request.fetch(req.url, method=req.method, headers=headers, data=req.body,
                                         max_redirects=0, fail_on_status_code=False,
                                         timeout=REQUEST_TIMEOUT_MS)
        try:
            body = await r.text()
        except Exception:  # noqa: BLE001 -- binary
            body = ""
        resp = M.resp_from(r.status, body)
        if M.is_block_signal(r.status, body):
            self.res["blocked_hosts"].append(host)
            raise _HostBlocked(host)
        if r.status == 401:
            await self._check_auth()
        return resp

    async def _budget(self) -> None:
        """budget_guard for EVERY request this runner sends (review fix)."""
        try:
            browser_confirm._enforce_budget("browser-mcp")
        except BudgetExceeded as e:
            raise _Stop("budget_exhausted", str(e)) from e
        if self.delay:
            await asyncio.sleep(self.delay)

    async def _check_auth(self) -> None:
        if not self.identity_probe:
            return
        e = self.entries[self.identity_probe]
        await self._budget()
        r = await self.ctx.request.fetch(e["url"], method="GET", max_redirects=0, fail_on_status_code=False,
                                         timeout=REQUEST_TIMEOUT_MS)
        self.res["sent"] += 1
        if r.status in (401, 403):
            raise _Stop("auth_lost", "the identity check GET is no longer authorized")

    async def _identity(self, session_file: str) -> None:
        """Spec decision 7: the walk's identity only."""
        probe = next((rid for rid, e in self.entries.items() if e["method"] == "GET"
                      and M.own_account_route(e["url"]) and e.get("response_keys")), None)
        self.identity_probe = probe
        same_file = bool(session_file) and os.path.realpath(session_file) == self.rep.get("session_file_realpath")
        if probe and self.self_ids:
            e = self.entries[probe]
            await self._budget()
            r = await self.ctx.request.fetch(e["url"], method="GET", max_redirects=0, fail_on_status_code=False,
                                             timeout=REQUEST_TIMEOUT_MS)
            self.res["sent"] += 1
            obj = _leaves(await r.text())
            got = {str(obj.get(k)) for k in ("id", "user_id", "userId", "uuid") if obj and obj.get(k) is not None}
            if not got & self.self_ids:
                raise _Stop("refused", "identity mismatch: this session is not the identity that walked")
            return
        if not same_file:
            raise _Stop("refused", "identity cannot be verified: use the walk's own session_file")

    def _result(self, e: dict, v: M.Variant | None, **kw) -> dict:
        r = {"replay_id": e["replay_id"], "route": _route(e["url"]),
             "variant_id": v.variant_id if v else None, "family": v.family if v else "baseline",
             "sent": False, "why_not": None}
        r.update(kw)
        self.res["results"].append(r)
        return r

    def _note_created(self, resp: M.Resp) -> None:
        if not 200 <= resp.status < 300:
            return
        cid = ui_walk_pass2._created_id(resp.body)
        if cid and cid not in self.res["created_ids"]:
            self.res["created_ids"].append(cid)
            tok = f"mut-{self.run_id}-{len(self.res['created_ids'])}"
            # a cleanup canary (not a DOM source): run_teardown's confirmed cleanup set includes it,
            # and the id proves ownership of the object for the destroy step
            ui_walk_store.register_canary(tok, {"token": tok, "kind": "mutation-created",
                                                "walk_id": self.walk_id, "run_id": self.run_id})
            ui_walk_store.register_created_id(tok, cid)
            self.created.add(cid)

    # -- variants
    def _variants_for(self, e: dict, pe: dict, ctx: M.Context, selected: set | None, extras: dict,
                      drops: set) -> list:
        req = _req_of(e)
        vs = [v for v in M.build_plan(req, ctx_for(e, ctx, self.entries, pe.get("snapshot")))
              if (selected is None or v.variant_id in selected)]
        vs += extras.get(e["replay_id"], [])
        return [v for v in vs if v.variant_id not in drops]

    async def run_entry(self, pe: dict, ctx: M.Context, selected, extras, drops) -> None:
        e = self.entries.get(pe["replay_id"])
        if e is None:
            return
        if e.get("body_truncated"):
            self._result(e, None, why_not="body truncated in the replay store")
            return
        variants = self._variants_for(e, pe, ctx, selected, extras, drops)
        base = fill_withheld(_req_of(e))
        self.recorded_values += [str(p.value) for p in M.parse_params(_req_of(e))
                                 if isinstance(p.value, str) and len(p.value) >= 3 and not p.withheld]
        if M.effective_method(base) in ("GET", "HEAD") and base.method in ("GET", "HEAD"):
            await self._run_get(e, pe, base, variants)
        else:
            await self._run_non_get(e, pe, base, variants)

    async def _run_get(self, e, pe, base, variants) -> None:
        g0 = M.gate(base, scope=self.scope, grant=None, owned=M.Ownership(False, "none", ""),
                    has_restore_path=False, never_mutated=pe["never_mutated"])
        if not g0.send:
            self._result(e, None, why_not=g0.reason)
            return
        b1 = await self._send(base)
        b2 = await self._send(base)
        nz = M.noise(b1, b2)
        for v in variants:
            vreq = M.apply_ops(base, v.ops)
            g = M.gate(vreq, scope=self.scope, grant=self.grant, owned=M.Ownership(False, "none", ""),
                       has_restore_path=False, never_mutated=pe["never_mutated"])
            if not g.send:
                self._result(e, v, why_not=g.reason)
                continue
            vr = await self._send(vreq)
            single = None
            if v.family == "duplicate":
                op = v.ops[0]
                sreq = M.apply_ops(base, [M.Op("set_param", op.location, op.path, op.value)])
                if M.gate(sreq, scope=self.scope, grant=None, owned=M.Ownership(False, "none", ""),
                          has_restore_path=False, never_mutated=pe["never_mutated"]).send:
                    single = await self._send(sreq)
            d = M.diff(b1, vr, nz, [o.value for o in v.ops if isinstance(o.value, str)])
            self._result(e, v, sent=True, base_status=b1.status, status=vr.status, readback="n/a")
            self.res["candidates"] += M.candidates_for(v, b1, vr, d, readback="n/a", single_value_resp=single,
                                                       recorded_values=self.recorded_values)

    async def _readback(self, snap_req: M.Req, s1: dict | None, vol: set) -> tuple[str, list[str], dict | None]:
        r = await self._send(snap_req)
        now = _leaves(r.body)
        if s1 is None or now is None or not 200 <= r.status < 300:
            return "unknown", [], now
        changed = sorted(k for k in set(s1) | set(now)
                         if k not in vol and s1.get(k, _MISSING) != now.get(k, _MISSING))   # missing != null
        return ("persisted" if changed else "not-persisted"), changed, now

    def _restore_req(self, sent: M.Req, base: M.Req, s1: dict, fields: list[str]) -> M.Req:
        if sent.body_kind not in ("json", "form"):
            return base
        top = {str(p.path[0]) for p in M.parse_params(sent) if p.location == sent.body_kind}
        ops = []
        for f in fields:
            val = s1.get(f)
            if sent.body_kind == "form" and not isinstance(val, (str, int, float)):
                continue
            ops.append(M.Op("set_param" if f in top else "add_param", sent.body_kind, (f,), val))
        try:
            return M.apply_ops(sent, ops)
        except (ValueError, KeyError, TypeError, IndexError):
            return base

    async def _take(self, restore: bool) -> bool:
        return await asyncio.to_thread(self.counter.try_take, 1, restore=restore, cap=self.cap)

    async def _state_change(self, e, sent: M.Req, base: M.Req, snap_req, s1, vol, obj_key):
        """After a sent non-GET: read back, restore when it changed. Returns
        (readback, restore status)."""
        rb, changed, _now = await self._readback(snap_req, s1, vol)
        self.last_changed = list(changed)
        if rb == "not-persisted":
            return rb, "not-needed"
        fields = changed if changed else []
        if rb == "unknown" or not fields:
            # review fix (spec decision 6): an unknown read-back is restored too --
            # with the original recorded request -- and a still-unknown one is loud
            if not await self._take(restore=True):
                self._fail(e, obj_key, "unknown", "no restore budget left")
                return rb, "failed"
            await self._send(base)
            rb2, _still, _ = await self._readback(snap_req, s1, vol)
            if rb2 == "not-persisted":
                return rb, "ok"
            self._fail(e, obj_key, "unknown", "read-back unavailable; restore could not be verified")
            return rb, "failed"
        if not await self._take(restore=True):
            self._fail(e, obj_key, fields[0], "no restore budget left")
            return rb, "failed"
        rreq = self._restore_req(sent, base, s1, fields)
        await self._send(rreq)
        rb2, still, now2 = await self._readback(snap_req, s1, vol)
        if rb2 == "not-persisted":
            return rb, "ok"
        if still and now2 is not None and all(k not in s1 and now2.get(k) is None for k in still):
            # a key the object did not have can be nulled but not removed by a write: say so, never "ok"
            for k in still:
                self.res["left_null_keys"].append({"route": _route(e["url"]), "field": k})
            return rb, "left-null"
        self._fail(e, obj_key, (still or fields)[0], "read-back still differs after restore")
        return rb, "failed"

    def _fail(self, e, obj_key: str, field: str, why: str) -> None:
        self.failed_objects.add(obj_key)
        self.res["restore_failures"].append({"route": _route(e["url"]), "field": field, "why": why})

    async def _run_non_get(self, e, pe, base, variants) -> None:
        snap_id = pe.get("snapshot")
        snap_e = self.entries.get(snap_id) if snap_id else None
        snap_req = fill_withheld(_req_of(snap_e)) if snap_e else None
        s1, vol, has_self = None, set(), None
        grant_ok = self.grant is not None and ui_walk_grant.grant_allows(self.grant, urlsplit(e["url"]).hostname or "")
        if snap_req is not None and grant_ok and self.scope(snap_req.url) and not pe["never_mutated"]:
            r1 = await self._send(snap_req)
            r2 = await self._send(snap_req)
            s1, l2 = _leaves(r1.body), _leaves(r2.body)
            if s1 is not None and l2 is not None:
                vol = {k for k in set(s1) | set(l2) if s1.get(k) != l2.get(k)}
            has_self = bool(s1) and any(str(s1.get(k)) in self.self_ids for k in ("id", "user_id", "userId", "uuid")
                                        if s1.get(k) is not None)
        owned = M.ownership(base, self.created, self.self_ids, has_self)
        restore_ok = s1 is not None
        g0 = M.gate(base, scope=self.scope, grant=self.grant, owned=owned, has_restore_path=restore_ok,
                    never_mutated=pe["never_mutated"])
        if not g0.send:
            self._result(e, None, why_not=g0.reason)
            for v in variants:
                self._result(e, v, why_not=g0.reason)
            return
        obj_key = _route(e["url"])
        if not await self._take(restore=False):
            self._result(e, None, why_not="cap-reached")
            for v in variants:
                self._result(e, v, why_not="cap-reached")
            return
        b = await self._send(base)
        self._note_created(b)
        rb, rs = await self._state_change(e, base, base, snap_req, s1, vol, obj_key)
        base_changed = set(self.last_changed)
        self._result(e, None, sent=True, status=b.status, readback=rb, restore=rs)
        fctx = self.ctx_data or M.Context()
        for v in variants:
            if obj_key in self.failed_objects:
                self._result(e, v, why_not="restore failed earlier on this object", after_restore_failure=True)
                continue
            vreq = M.apply_ops(base, v.ops)
            g = M.gate(vreq, scope=self.scope, grant=self.grant, owned=owned, has_restore_path=restore_ok,
                       never_mutated=pe["never_mutated"])
            if not g.send:
                self._result(e, v, why_not=g.reason)
                continue
            if M.carries_foreign_id(v.ops, foreign_ids=fctx.foreign_ids, created=self.created,
                                    self_ids=self.self_ids):
                self._result(e, v, why_not="foreign-id")   # spec decision 5, agent variants included
                continue
            if not await self._take(restore=False):
                self._result(e, v, why_not="cap-reached")
                continue
            vr = await self._send(vreq)
            self._note_created(vr)
            rb, rs = await self._state_change(e, vreq, base, snap_req, s1, vol, obj_key)
            rb = M.attribute_readback(rb, self.last_changed, base_changed)
            d = M.diff(b, vr, {"volatile": frozenset(), "length_tol": 32},
                       [o.value for o in v.ops if isinstance(o.value, str)])
            self._result(e, v, sent=True, base_status=b.status, status=vr.status, readback=rb, restore=rs)
            self.res["candidates"] += M.candidates_for(v, b, vr, d, readback=rb,
                                                       recorded_values=self.recorded_values)


def _agent_extras(raw, known: set) -> tuple[dict, list[str]]:
    ok, errs = M.validate_agent_ops(raw or [], known)
    by: dict = {}
    for v in ok:
        by.setdefault(v.replay_id, []).append(v)
    return by, errs


async def run(plan_id: str, *, session_file: str, variants: str = "auto", extra_variants=None,
              drop_variants=None, scope_check=None, grant=_LOAD, upstream_proxy: str = "",
              max_sent: int = DEFAULT_MAX_SENT, action_delay_s: float | None = None,
              wall_clock_s: int = RUN_WALL_CLOCK_S, bearer_token: str = "") -> dict:
    from playwright.async_api import async_playwright

    start = time.monotonic()
    plan = load_plan(plan_id)
    if plan is None:
        return {"status": "refused", "error": f"unknown plan_id {plan_id!r} (run plan_mutations first)",
                "sent": 0, "results": [], "candidates": [], "restore_failures": []}
    rep = R.load_replay(plan["walk_id"])
    if rep is None:
        return {"status": "refused", "error": "the walk's replay store is gone", "sent": 0, "results": [],
                "candidates": [], "restore_failures": []}
    g = ui_walk_grant.load_grant() if grant is _LOAD else grant
    delay = ui_walk._default_delay() if action_delay_s is None else action_delay_s
    runner = Runner(plan, rep, scope=scope_check or L._default_scope_check, grant=g,
                    max_sent=max(1, min(int(max_sent), DEFAULT_MAX_SENT)), delay=delay,
                    wall_clock_s=wall_clock_s, bearer_token=bearer_token)
    extras, errs = _agent_extras(extra_variants, set(runner.entries))
    runner.res["agent_variant_errors"] = errs
    selected = None
    if variants and variants != "auto":
        selected = {s.strip() for s in str(variants).split(",") if s.strip()}
    drops = set(drop_variants or [])
    proxy, mirror_err = ui_walk.resolve_mirror(upstream_proxy)
    if mirror_err:
        runner.res.update(status="refused", error=mirror_err)
        return runner.res
    entries = [runner.entries[r["replay_id"]] for r in plan["requests"] if r["replay_id"] in runner.entries]
    ctx_data = _context(entries, runner.self_ids, runner.created)
    async with async_playwright() as p:
        if proxy == ui_walk_events_logic.AUTO_PROXY:
            proxy = await asyncio.to_thread(ui_walk._detect_burp)
        if proxy and not await asyncio.to_thread(ui_walk._proxy_reachable, proxy):
            proxy = None
        kw = {"proxy": proxy} if proxy else {}
        browser = await p.chromium.launch(**browser_confirm._launch_kwargs(**kw))
        runner.res["burp_mirror"] = {"active": bool(proxy)}
        try:
            opts = {"ignore_https_errors": bool(proxy)}
            if session_file and os.path.isfile(session_file):
                opts["storage_state"] = session_file
            runner.ctx = await browser.new_context(**opts)
            runner.ctx_data = ctx_data
            await runner._identity(session_file)
            for pe in plan["requests"]:
                host = urlsplit(pe.get("route") or "").hostname or ""
                if host in runner.res["blocked_hosts"]:
                    runner._result(runner.entries[pe["replay_id"]], None, why_not="host blocked") \
                        if pe["replay_id"] in runner.entries else None
                    continue
                try:
                    await runner.run_entry(pe, ctx_data, selected, extras, drops)
                except _HostBlocked:
                    pass   # recorded in blocked_hosts; nothing tries to get around it
        except _Stop as s:
            runner.res["status"], runner.res["error"] = s.status, s.error
        except Exception as e:  # noqa: BLE001 -- reported, never raised to the agent
            runner.res["status"], runner.res["error"] = "error", type(e).__name__
        finally:
            await browser.close()
    if runner.res["restore_failures"] and runner.res["status"] == "complete":
        runner.res["status"] = "restore_failed"
    elif runner.res["blocked_hosts"] and runner.res["status"] == "complete":
        runner.res["status"] = "blocked"
        runner.res["error"] = "block signal (429 / WAF) from: " + ", ".join(runner.res["blocked_hosts"][:5])
    runner.res["recorded_values_scrubbed"] = True
    runner.recorded_values.clear()
    R._write_private(os.path.join(ui_walk_store.walk_dir(),
                                  f"{plan['walk_id']}.mutations-{runner.run_id}.json"), runner.res)
    browser_confirm._log_call("browser-mcp:mutations", [plan["walk_id"], plan_id, runner.run_id],
                              returncode=0 if runner.res["status"] == "complete" else 1,
                              duration_ms=(time.monotonic() - start) * 1000, block=None)
    return runner.res
