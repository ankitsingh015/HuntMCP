"""#164 UI-walk Pass 2 (mode="canary"): real canary submits + render-sink
detection (+ create->destroy->verify, see ui_walk_destroy.py).

Only runs when the human-owned grant file allows it (ui_walk_grant). It first
runs the full Pass-1 map (nothing sent), then -- with the browser still open:

1. For every mapped page with fillable in-scope inputs: re-open the page,
   re-reveal each input group (modal/tab), type a unique canary into every
   text-like input (token registered per engagement), and really submit the
   form. ONLY those deliberate submits are sent (in-scope, non-payment,
   capped by the grant's real_submit_cap_per_walk, budget per request); any
   other request -- and any stray click in this pass -- is still aborted.
2. Re-walk every mapped page and look for every registered token: where it
   renders (raw markup vs escaped text) and whether it EXECUTED (a dialog or
   document.title carrying the token). A token submitted on page A that renders
   on page B is a cross-page sink. Each sink becomes a CANDIDATE for
   exploit-agent -- never an auto-confirmed bug.

Submitted values are never stored (they derive from the token); edges keep
field names only.
"""

from __future__ import annotations

import json
import os
import sys
from urllib.parse import urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import browser_confirm  # noqa: E402
import ui_walk  # noqa: E402
import ui_walk_events  # noqa: E402
import ui_walk_events_logic as EL  # noqa: E402
import ui_walk_grant  # noqa: E402
import ui_walk_logic as L  # noqa: E402
import ui_walk_store  # noqa: E402
from budget_guard import BudgetExceeded  # noqa: E402
from endpoint_template import endpoint_template  # noqa: E402

_SINK_JS = r"""
() => ({html: document.documentElement.outerHTML, title: document.title,
        raw: [...document.querySelectorAll('[onerror]')].map(e => e.getAttribute('onerror') || '')})
"""

_FORM_JS = r"""
(e) => { const f = e.form || e.closest('form'); if (!f) return null;
  if (!f.dataset.hmForm) { window.__hmForm = (window.__hmForm || 0) + 1; f.dataset.hmForm = String(window.__hmForm); }
  const subs = [...f.querySelectorAll('button, input[type=submit], input[type=image]')]
    .filter(b => (b.getAttribute('type') || 'submit').toLowerCase() === 'submit' || b.tagName === 'BUTTON')
    .map(b => ({tag: b.tagName.toLowerCase(), type: (b.getAttribute('type') || 'submit').toLowerCase(),
                text: (b.innerText || b.value || '').trim().slice(0, 80), aria_label: b.getAttribute('aria-label') || ''}));
  return {key: f.dataset.hmForm, action: f.action || '', controls: subs}; }
"""

_SUBMIT_JS = r"""
(e) => { const f = e.form || e.closest('form'); if (!f) return false;
  if (f.requestSubmit) f.requestSubmit(); else f.submit(); return true; }
"""


def check_grant(start_url: str, grant=None) -> str | None:
    """None if canary mode is allowed for start_url's host, else the refusal."""
    g = grant if grant is not None else ui_walk_grant.load_grant()
    host = urlsplit(start_url).hostname or ""
    if ui_walk_grant.grant_allows(g, host):
        return None
    try:
        where = ui_walk_grant.grant_path()
    except RuntimeError:
        where = "data/engagements/<slug>/" + ui_walk_grant.GRANT_FILENAME
    extra = f" and {host!r} listed under hosts" if g is not None else ""
    return (f"canary mode needs a human-written grant file {where} with `canary_submit: true`{extra}; "
            "the agent cannot create it. Pass 1 (mode='map') is still available.")


def _created_id(body: str | None) -> str | None:
    try:
        obj = json.loads(body or "")
    except (ValueError, TypeError):
        return None
    for cand in (obj, obj.get("data") if isinstance(obj, dict) else None):
        if isinstance(cand, dict):
            for key in ("id", "uuid", "_id"):
                v = cand.get(key)
                if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v):
                    return str(v)
    return None


def _fillable(inp: dict) -> bool:
    return _token_for(inp, probe=True) is not None


def _token_for(inp: dict, probe: bool = False) -> str | None:
    """A fresh canary token sized for the field (None = field cannot carry a
    registrable token). A maxlength shorter than the default token gets a
    shorter token, never a truncated one that would not match the registry."""
    maxlength = inp.get("maxlength")
    length = 10 if not maxlength or maxlength >= 10 else maxlength
    if length < 4:
        return None
    tok = "hm" + "0" * (length - 2) if probe else L.make_canary(length)
    return tok if L.canary_value(tok, inp.get("type"), maxlength) != "" else None


class CanaryWalker(ui_walk._Walker):
    def configure(self, grant=None) -> None:
        g = grant if grant is not None else ui_walk_grant.load_grant()
        self.grant = g
        self.cap = g.real_submit_cap_per_walk if g else 0
        self.sent = 0
        # What may be SENT right now: None (nothing), "submit" (a deliberate
        # canary form submit: POST/PUT/PATCH only, never DELETE, never a
        # state-changing-looking URL), or ("exact", METHOD, URL) (an
        # ownership-proven delete: only the very request the dry run captured).
        self.window = None
        self.submit_tokens: list[str] = []
        self.budget_hit = False
        self.tokens: dict[str, dict] = {}
        self.created_ids: set[str] = set()
        self.dialog_msgs: list[str] = []
        self.inv["pass2_edges"] = []
        self.inv["destroy_log"] = []
        self.inv["skipped_forms"] = []
        self.last_aborted: dict | None = None
        self._p2_rec: dict | None = None

    # -- policy -------------------------------------------------------------
    @property
    def submitting(self) -> bool:
        return self.window is not None

    @submitting.setter
    def submitting(self, value: bool) -> None:
        # Back-compat for callers that only toggle a plain submit window.
        self.window = "submit" if value else None

    def _window_allows(self, method: str, url: str) -> bool:
        if not ui_walk_grant.grant_allows(self.grant, urlsplit(url).hostname or ""):
            return False
        if self.window == "submit":
            return method != "DELETE" and not L.is_mutating_get_url(url)
        if self.window == "teardown-control":
            # Teardown only: the one human-confirmed logout / account-delete control.
            return True
        if isinstance(self.window, tuple) and self.window[0] == "exact":
            return method == self.window[1] and ui_walk._defrag(url) == ui_walk._defrag(self.window[2])
        return False

    def allow_send(self, method: str, url: str) -> bool:
        if self.window is None or self.sent >= self.cap or self.budget_hit:
            return False
        if not self._window_allows(method, url):
            return False
        try:
            browser_confirm._enforce_budget("browser-mcp")
        except BudgetExceeded:
            self.budget_hit = True
            return False
        self.sent += 1
        return True

    def refine_block_reason(self, method, url, reason):
        if reason == "pass1-non-get" and self.window is not None:
            if self.budget_hit:
                return "budget"
            if self.sent >= self.cap:
                return "cap-reached"
            if not ui_walk_grant.grant_allows(self.grant, urlsplit(url).hostname or ""):
                return "host-not-granted"
            return "outside-submit-window"
        return reason

    async def forward_sent(self, route, method, url, post) -> None:
        rec = {"method": method, "url": url, "status": None, "created_id": None,
               "walk_id": self.inv["walk_id"], "page": (self.cur_page or {}).get("url")}
        try:
            resp = await route.fetch()
            body = await resp.text()
            await route.fulfill(response=resp, body=body)
            rec["status"] = resp.status
            self._record_fetch_cookies(resp, url)
            rec["created_id"] = _created_id(body)
            if rec["created_id"]:
                self.created_ids.add(rec["created_id"])
                for tok in self.submit_tokens:
                    ui_walk_store.register_created_id(tok, rec["created_id"])
        except Exception as e:  # noqa: BLE001 -- recorded; the walk goes on
            rec["error"] = f"{type(e).__name__}: {e}"
            try:
                await route.abort()
            except Exception:  # noqa: BLE001
                pass
        self.inv["real_submits"].append(rec)

    def _record_fetch_cookies(self, resp, url: str) -> None:
        """A route.fetch() response never reaches the page's network events, so its
        Set-Cookie headers are parsed here (flags only, never the value)."""
        try:
            arr = resp.headers_array   # a property on Playwright's APIResponse
            arr = arr() if callable(arr) else arr
            raw = "\n".join(h["value"] for h in arr
                            if (h.get("name") or "").lower() == "set-cookie")
            clean, qkeys = ui_walk_events._strip_url(url)
            # page_template is set here too: with no Pass-2 scratch page (_p2_rec),
            # _flush_p2 never adds one.
            tmpl = (self._p2_rec or {}).get("template") or endpoint_template(
                (self.cur_page or {}).get("url") or self.page.url)
            for c in EL.parse_set_cookie(raw):   # raw string is dropped right here
                ev = dict(c)
                ev.update({"type": "set_cookie", "url": clean, "query_keys": qkeys, "blocked": [],
                           "via": "route.fetch", "frame_origin": ui_walk_events._origin(self.page.url),
                           "page_template": tmpl})
                self.recorder.record(ev)
        except Exception:  # noqa: BLE001 -- recording is best-effort
            pass

    async def _flush_p2(self) -> None:
        """Finish the current scratch page's recording into inv['pass2_events']."""
        rec, self._p2_rec = self._p2_rec, None
        if rec is None:
            return
        try:
            await self.recorder.end_page(rec, remaining_s=self.deadline - ui_walk.time.monotonic())
        except Exception:  # noqa: BLE001
            pass
        for ev in rec.get("events") or []:
            self.inv["pass2_events"].append({**ev, "page_template": rec.get("template")
                                             or ev.get("page_template") or endpoint_template(rec.get("url") or "")})

    def on_dialog(self, dialog) -> None:
        super().on_dialog(dialog)   # ruling R2: Pass-1 DOM-canary execution detection stays on
        try:
            self.dialog_msgs.append(dialog.message or "")
        except Exception:  # noqa: BLE001
            pass

    # -- helpers --------------------------------------------------------------
    def _granted(self, url: str) -> bool:
        return self.scope(url) and ui_walk_grant.grant_allows(self.grant, urlsplit(url).hostname or "")

    def _p2(self, url: str) -> dict:
        """A scratch page record whose edges go to inv['pass2_edges']."""
        return {"url": url, "api_edges": self.inv["pass2_edges"], "third_party_hosts": [],
                "ws_frames_blocked": 0}

    async def _open_page(self, url: str) -> None:
        await self._flush_p2()
        self.cur_page = self._p2(url)
        self.cur_page["template"] = endpoint_template(url)
        self._p2_rec = self.cur_page
        self.recorder.begin_page(self.cur_page)
        self.current_control = None
        await self._budget()
        try:
            await self.page.goto(url, wait_until="domcontentloaded")
        except Exception:  # noqa: BLE001 -- blocked/unreachable: leave a blank page, nothing to act on
            await self.page.goto("about:blank")
            return
        if not self.scope(self.page.url):
            # followed redirect left scope: never act on that page
            await self.page.goto("about:blank")
            return
        await self._settle(self.page, first=True)

    async def _reveal(self, signature: str, tmpl: str) -> None:
        for frame, d in await self._snapshot(self.page):
            for c in d["controls"]:
                if L.control_signature(c, tmpl) == signature:
                    await self._click(frame, c, signature, {})
                    return

    # -- phases ----------------------------------------------------------------
    async def after_map(self) -> None:
        pages = [p for p in self.inv["pages"] if p.get("auth_state", "ok") == "ok"]
        try:
            for prec in pages:
                if any(_fillable(i) and self._granted(i["frame_origin"] + "/") for i in prec["inputs"]):
                    await self._submit_page(prec)
                if self.budget_hit:
                    raise ui_walk._Stop("budget_exhausted", "budget exhausted during canary submits")
            await self._detect_sinks(pages)
            await self.destroy_phase(pages)
        finally:
            await self._flush_p2()
            self._derive_pass2()

    def _derive_pass2(self) -> None:
        """R9: cookies rotated by real submits (set_cookie via route.fetch) are
        checked for flags too. Grouped per page template; de-duplicated."""
        # Runs in after_map's finally: nothing here may raise (it would replace
        # a _Stop on its way out), so the grouping is inside the try too.
        try:
            by_tmpl: dict[str, list[dict]] = {}
            for ev in self.inv["pass2_events"]:
                if ev.get("type") == "set_cookie" and ev.get("via") == "route.fetch":
                    by_tmpl.setdefault(ev.get("page_template") or "", []).append(ev)
        except Exception:  # noqa: BLE001
            self.inv["events_candidate_errors"] += 1
            return
        for tmpl, evs in by_tmpl.items():
            try:
                self._add_candidates(EL.derive_candidates(
                    {"url": tmpl, "events": evs, "api_edges": [], "controls": []}, scope=self.scope))
            except Exception:  # noqa: BLE001
                self.inv["events_candidate_errors"] += 1

    async def destroy_phase(self, pages: list[dict]) -> None:
        import ui_walk_destroy

        await ui_walk_destroy.run(self, pages)

    def on_aborted(self, method, url, post, reason) -> None:
        if method not in L.SAFE_METHODS:
            self.last_aborted = {"method": method, "url": url, "body": post}

    async def _submit_page(self, prec: dict) -> None:
        if prec.get("auth_state") == "sso" or self.sso.is_idp_url(prec.get("url") or ""):
            # spec 2: nothing on an IdP login / consent / MFA page is ever filled or submitted
            self.inv["skipped_forms"].append({"page": prec["url"], "action": None, "reason": "sso-form"})
            return
        groups: dict = {}
        for i in prec["inputs"]:
            if _fillable(i) and self._granted(i["frame_origin"] + "/"):
                groups.setdefault(i.get("revealed_by"), []).append(i)
        for revealed_by in sorted(groups, key=lambda k: (k is not None, k or "")):
            wanted = {(i["frame_origin"], i["form_action"], i["name"], i["id"], i["type"]): i
                      for i in groups[revealed_by]}
            await self._open_page(prec["url"])
            if revealed_by:
                await self._reveal(revealed_by, prec["template"])
            filled = []
            for frame, d in await self._snapshot(self.page):
                for live in d["inputs"]:
                    key = (d["origin"], live["form_action"], live["name"], live["id"], live["type"])
                    inp = wanted.get(key)
                    if inp is None:
                        continue
                    tok = _token_for(live)
                    if tok is None:
                        continue
                    try:
                        form = await frame.locator(f'[data-hm-idx="{live["idx"]}"]').first.evaluate(_FORM_JS)
                    except Exception:  # noqa: BLE001
                        form = None
                    if form is not None:
                        unsafe = L.form_unsafe_reason(form["controls"], form["action"],
                                                      sso_page=self.sso.is_idp_url(prec.get("url") or ""))
                        if unsafe:
                            self.inv["skipped_forms"].append({"page": prec["url"], "action": form["action"],
                                                              "reason": unsafe})
                            continue
                    try:
                        await frame.locator(f'[data-hm-idx="{live["idx"]}"]').first.fill(
                            L.canary_value(tok, live["type"], live["maxlength"]), timeout=3000)
                    except Exception:  # noqa: BLE001 -- not fillable after all
                        continue
                    rec = {"token": tok, "page": prec["url"], "input": inp["name"] or inp["id"],
                           "form_action": inp["form_action"], "walk_id": self.inv["walk_id"],
                           "form_key": form["key"] if form else None}
                    self.tokens[tok] = rec
                    self.inv["canaries"].append(rec)
                    ui_walk_store.register_canary(tok, rec)
                    filled.append((frame, live, d, form["key"] if form else None))
            if not filled:
                continue
            await self._submit(filled, prec)

    async def _submit(self, filled: list, prec: dict) -> None:
        page_url = ui_walk._defrag(self.page.url)
        done_forms: set = set()
        try:
            for frame, live, d, fkey in filled:
                form_key = (id(frame), fkey if fkey is not None else f"noform:{live['idx']}")
                if form_key in done_forms:
                    continue
                done_forms.add(form_key)
                self.submit_tokens = [t for t, r in self.tokens.items()
                                      if r["page"] == prec["url"] and r.get("form_key") == fkey]
                self.window = "submit"
                submitted = False
                try:
                    submitted = await frame.locator(f'[data-hm-idx="{live["idx"]}"]').first.evaluate(_SUBMIT_JS)
                except Exception:  # noqa: BLE001
                    submitted = False
                if not submitted:
                    for c in d["controls"]:
                        if L.classify_control(c) == "submit":
                            await self._click(frame, c, L.control_signature(c, prec["template"]), {})
                            break
                await self._settle(self.page)
                self.window = None
        finally:
            self.window = None
            self.submit_tokens = []
        if ui_walk._defrag(self.page.url) != page_url:
            await self._budget()
            await self.page.goto(page_url, wait_until="domcontentloaded")
            await self._settle(self.page)

    async def _detect_sinks(self, pages: list[dict]) -> None:
        if not self.tokens:
            return
        seen: set = set()
        for prec in pages:
            self.dialog_msgs = []
            await self._open_page(prec["url"])
            frames = []
            for frame in self.page.frames:
                try:
                    frames.append(await frame.evaluate(_SINK_JS))
                except Exception:  # noqa: BLE001
                    continue
            for tok, crec in self.tokens.items():
                if not any(tok in f["html"] for f in frames) or (tok, prec["url"]) in seen:
                    continue
                seen.add((tok, prec["url"]))
                sink = {
                    "token": tok, "origin_page": crec["page"], "origin_input": crec["input"],
                    "sink_page": prec["url"],
                    "rendered_raw": any(tok in a for f in frames for a in f["raw"]),
                    "executed": any(tok in m for m in self.dialog_msgs) or any(tok in f["title"] for f in frames),
                    "cross_page": crec["page"] != prec["url"],
                }
                self.inv["sinks"].append(sink)
                self.inv["candidates"].append({"type": "stored-xss" if sink["executed"] else "reflected-render",
                                               **sink})
