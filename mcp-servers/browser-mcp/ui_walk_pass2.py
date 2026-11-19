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
import ui_walk_grant  # noqa: E402
import ui_walk_logic as L  # noqa: E402
import ui_walk_store  # noqa: E402
from budget_guard import BudgetExceeded  # noqa: E402

_SINK_JS = r"""
() => ({html: document.documentElement.outerHTML, title: document.title,
        raw: [...document.querySelectorAll('[onerror]')].map(e => e.getAttribute('onerror') || '')})
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
    return L.canary_value("hm00000000", inp.get("type"), inp.get("maxlength")) != ""


class CanaryWalker(ui_walk._Walker):
    def configure(self, grant=None) -> None:
        g = grant if grant is not None else ui_walk_grant.load_grant()
        self.cap = g.real_submit_cap_per_walk if g else 0
        self.sent = 0
        self.submitting = False
        self.budget_hit = False
        self.tokens: dict[str, dict] = {}
        self.created_ids: set[str] = set()
        self.dialog_msgs: list[str] = []
        self.inv["pass2_edges"] = []
        self.inv["destroy_log"] = []
        self.last_aborted: dict | None = None

    # -- policy -------------------------------------------------------------
    def allow_send(self, method: str, url: str) -> bool:
        if not self.submitting or self.sent >= self.cap or self.budget_hit:
            return False
        try:
            browser_confirm._enforce_budget("browser-mcp")
        except BudgetExceeded:
            self.budget_hit = True
            return False
        self.sent += 1
        return True

    def refine_block_reason(self, method, url, reason):
        if reason == "pass1-non-get" and self.submitting:
            if self.budget_hit:
                return "budget"
            if self.sent >= self.cap:
                return "cap-reached"
        return reason

    async def forward_sent(self, route, method, url, post) -> None:
        rec = {"method": method, "url": url, "status": None, "created_id": None,
               "walk_id": self.inv["walk_id"], "page": (self.cur_page or {}).get("url")}
        try:
            resp = await route.fetch()
            body = await resp.text()
            await route.fulfill(response=resp, body=body)
            rec["status"] = resp.status
            rec["created_id"] = _created_id(body)
            if rec["created_id"]:
                self.created_ids.add(rec["created_id"])
        except Exception as e:  # noqa: BLE001 -- recorded; the walk goes on
            rec["error"] = f"{type(e).__name__}: {e}"
            try:
                await route.abort()
            except Exception:  # noqa: BLE001
                pass
        self.inv["real_submits"].append(rec)

    def on_dialog(self, dialog) -> None:
        try:
            self.dialog_msgs.append(dialog.message or "")
        except Exception:  # noqa: BLE001
            pass

    # -- helpers --------------------------------------------------------------
    def _p2(self, url: str) -> dict:
        """A scratch page record whose edges go to inv['pass2_edges']."""
        return {"url": url, "api_edges": self.inv["pass2_edges"], "third_party_hosts": [],
                "ws_frames_blocked": 0}

    async def _open_page(self, url: str) -> None:
        self.cur_page = self._p2(url)
        self.current_control = None
        await self._budget()
        await self.page.goto(url, wait_until="domcontentloaded")
        await self._settle(self.page, first=True)

    async def _reveal(self, signature: str, tmpl: str) -> None:
        for frame, d in await self._snapshot(self.page):
            for c in d["controls"]:
                if L.control_signature(c, tmpl) == signature:
                    await self._click(frame, c, signature, {})
                    return

    # -- phases ----------------------------------------------------------------
    async def after_map(self) -> None:
        pages = [p for p in self.inv["pages"] if p.get("auth_state") != "logged-out"]
        for prec in pages:
            if any(_fillable(i) and self.scope(i["frame_origin"] + "/") for i in prec["inputs"]):
                await self._submit_page(prec)
            if self.budget_hit:
                raise ui_walk._Stop("budget_exhausted", "budget exhausted during canary submits")
        await self._detect_sinks(pages)
        await self.destroy_phase(pages)

    async def destroy_phase(self, pages: list[dict]) -> None:
        import ui_walk_destroy

        await ui_walk_destroy.run(self, pages)

    def on_aborted(self, method, url, post, reason) -> None:
        if method not in L.SAFE_METHODS:
            self.last_aborted = {"method": method, "url": url, "body": post}

    async def _submit_page(self, prec: dict) -> None:
        groups: dict = {}
        for i in prec["inputs"]:
            if _fillable(i) and self.scope(i["frame_origin"] + "/"):
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
                    tok = L.make_canary()
                    try:
                        await frame.locator(f'[data-hm-idx="{live["idx"]}"]').first.fill(
                            L.canary_value(tok, live["type"], live["maxlength"]), timeout=3000)
                    except Exception:  # noqa: BLE001 -- not fillable after all
                        continue
                    rec = {"token": tok, "page": prec["url"], "input": inp["name"] or inp["id"],
                           "form_action": inp["form_action"], "walk_id": self.inv["walk_id"]}
                    self.tokens[tok] = rec
                    self.inv["canaries"].append(rec)
                    ui_walk_store.register_canary(tok, rec)
                    filled.append((frame, live, d))
            if not filled:
                continue
            await self._submit(filled, prec)

    async def _submit(self, filled: list, prec: dict) -> None:
        page_url = ui_walk._defrag(self.page.url)
        done_forms: set = set()
        self.submitting = True
        try:
            for frame, live, d in filled:
                form_key = (id(frame), live["form_action"])
                if form_key in done_forms:
                    continue
                done_forms.add(form_key)
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
        finally:
            self.submitting = False
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
