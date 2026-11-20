"""#164 UI-walk driver: render every page, enumerate its real inputs and
controls, click them, and record the UI->API map -- the PAGE (not the URL) is
the unit of testing.

Pass 1 (mode="map") is safe by construction: a context-level network
interceptor aborts every non-GET/HEAD/OPTIONS request (and every request to a
payment provider, every out-of-scope top-level navigation, every GET whose URL
looks state-changing), records it as a UI->API edge, and never sends it.
WebSocket client->server frames are never forwarded and service workers are
blocked. Logout / account-delete / payment controls are never clicked.

Design: docs/superpowers/specs/2026-11-19-page-comprehension-ui-walk-design.md
Pure decisions live in ui_walk_logic.py; this module only drives Playwright.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from collections.abc import Callable
from urllib.parse import parse_qsl, urldefrag, urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import browser_confirm
import ui_walk_logic as L
from budget_guard import BudgetExceeded
from endpoint_template import endpoint_template

SCHEMA_VERSION = 1
MAX_PER_TEMPLATE = 3
_SETTLE_MS = 3000
_CLICK_TIMEOUT_MS = 3000

HONEST_LIMITS = [
    ("A GET request whose URL looks harmless but changes server state cannot be detected "
     "in advance; only GETs whose URL contains logout/signout/delete/remove/revoke/cancel/"
     "unsubscribe/deactivate/destroy are blocked."),
    ("Control classification is English-vocabulary based; unrecognised (non-English, "
     "icon-only) controls are clicked as 'other'. Network interception, not "
     "classification, is what keeps Pass 1 from sending anything state-changing."),
]

# Enumerates visible controls + inputs in ONE frame (walks open shadow roots),
# tagging each element with data-hm-idx so Python can locate it again.
_ENUM_JS = r"""
() => {
  const visible = el => { const r = el.getClientRects(); if (!r.length) return false;
    const s = getComputedStyle(el); return s.visibility !== 'hidden' && s.display !== 'none'; };
  const all = [];
  const walk = root => { root.querySelectorAll('*').forEach(el => { all.push(el); if (el.shadowRoot) walk(el.shadowRoot); }); };
  walk(document);
  const path = el => { const parts = []; let e = el;
    while (e && e.nodeType === 1 && parts.length < 8) { let p = e.tagName.toLowerCase(); const par = e.parentElement;
      if (par) { const same = [...par.children].filter(c => c.tagName === e.tagName);
        if (same.length > 1) p += ':nth-of-type(' + (same.indexOf(e) + 1) + ')'; }
      parts.unshift(p); e = par; }
    return parts.join('>'); };
  window.__hmIdx = window.__hmIdx || 0;
  const tag = el => { if (!el.dataset.hmIdx) el.dataset.hmIdx = String(++window.__hmIdx); return el.dataset.hmIdx; };
  const CTRL = 'a[href],button,input[type=submit],input[type=button],input[type=image],[role=button],[role=tab],[role=menuitem],summary,[aria-expanded],[onclick]';
  const INP = 'input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=image]),textarea,select,[contenteditable="true"]';
  const controls = [], inputs = [];
  for (const el of all) {
    if (!visible(el)) continue;
    const f = el.form || el.closest('form');
    if (el.matches(CTRL)) {
      controls.push({idx: tag(el), tag: el.tagName.toLowerCase(), role: el.getAttribute('role') || '',
        text: (el.innerText || el.value || '').trim().slice(0, 80), aria_label: el.getAttribute('aria-label') || '',
        href: el.href || '', target: el.getAttribute('target') || '', type: (el.getAttribute('type') || '').toLowerCase(),
        form_action: f ? (f.action || '') : '', form_method: f ? (f.method || 'get') : '',
        aria_expanded: el.getAttribute('aria-expanded'), dom_path: path(el)});
    } else if (el.matches(INP)) {
      let label = '';
      if (el.labels && el.labels.length) label = el.labels[0].innerText.trim();
      else { const l = el.closest('label'); if (l) label = l.innerText.trim(); }
      inputs.push({idx: tag(el), tag: el.tagName.toLowerCase(), name: el.getAttribute('name') || '', id: el.id || '',
        type: (el.isContentEditable && !('value' in el) ? 'contenteditable' : (el.type || el.tagName)).toLowerCase(), label: label.slice(0, 80),
        placeholder: el.getAttribute('placeholder') || '', required: !!el.required,
        maxlength: el.maxLength > 0 ? el.maxLength : null,
        form_action: f ? (f.action || '') : '', form_method: f ? (f.method || 'get') : ''});
    }
  }
  return {origin: location.origin, controls, inputs};
}
"""


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _defrag(url: str) -> str:
    return urldefrag(url)[0]


def _body_shape(post_data: str | None):
    """Field NAMES only (never values) -- edges must not carry submitted data."""
    if not post_data:
        return None
    try:
        obj = json.loads(post_data)
        if isinstance(obj, dict):
            return {"json_keys": sorted(obj)}
        return {"json": type(obj).__name__}
    except (ValueError, TypeError):
        pass
    pairs = parse_qsl(post_data, keep_blank_values=True)
    if pairs:
        return {"form_keys": sorted({k for k, _ in pairs})}
    return {"bytes": len(post_data)}


class _Stop(Exception):
    def __init__(self, status: str, error: str | None = None):
        super().__init__(status)
        self.status = status
        self.error = error


class _Walker:
    def __init__(self, start_url: str, mode: str, *, scope: Callable[[str], bool],
                 max_pages: int, max_clicks_per_page: int, same_origin_only: bool,
                 wall_clock_s: int, action_delay_s: float, screenshot_dir: str | None,
                 had_session: bool, session_file: str | None, auth: dict, walk_id: str):
        self.start_url = start_url
        self.mode = mode
        # Scope is host-based; cache the verdict per host so the interceptor
        # does not re-read engagement.yaml for every subresource request.
        self._scope_fn = scope
        self._scope_cache: dict[str, bool] = {}
        self.max_pages = max_pages
        self.max_clicks = max_clicks_per_page
        self.same_origin_only = same_origin_only
        self.deadline = time.monotonic() + wall_clock_s
        self.delay = action_delay_s
        self.shot_dir = screenshot_dir
        self.had_session = had_session
        self.session_file = session_file
        self.auth = auth
        self.inv = {
            "schema_version": SCHEMA_VERSION, "walk_id": walk_id, "start_url": start_url,
            "mode": mode, "status": "complete", "error": None,
            "honest_limits": list(HONEST_LIMITS), "pages": [], "real_submits": [],
            "canaries": [], "sinks": [], "candidates": [],
        }
        self.cur_page: dict | None = None
        self.current_control: str | None = None
        self.context = None
        self.page = None
        self.browser = None
        self.get_log: list[dict] = []

    def scope(self, url: str) -> bool:
        key = (urlsplit(url).hostname or "").lower() or url
        if key not in self._scope_cache:
            self._scope_cache[key] = bool(self._scope_fn(url))
        return self._scope_cache[key]

    # -- policy hooks (Pass 2 overrides) ------------------------------------
    def allow_send(self, method: str, url: str) -> bool:
        return False

    def on_dialog_accept(self) -> bool:
        # Pass 1 accepts confirm() dialogs: the request they lead to is aborted
        # by the interceptor anyway, and dismissing would hide the UI->API edge.
        return True

    # -- plumbing ------------------------------------------------------------
    async def _budget(self) -> None:
        if time.monotonic() > self.deadline:
            raise _Stop("time_limit")
        try:
            browser_confirm._enforce_budget("browser-mcp")
        except BudgetExceeded as e:
            raise _Stop("budget_exhausted", str(e)) from e
        if self.delay:
            await asyncio.sleep(self.delay)

    def _edge(self, method: str, url: str, sent: bool, reason: str | None, post_data=None) -> None:
        target = self.cur_page
        if target is None:
            return
        target["api_edges"].append({
            "control_signature": self.current_control, "method": method, "url": url,
            "sent": sent, "blocked_reason": reason, "body_shape": _body_shape(post_data),
        })

    async def _on_route(self, route) -> None:
        req = route.request
        url = req.url
        method = req.method.upper()
        try:
            is_main_nav = req.is_navigation_request() and req.frame.parent_frame is None
        except Exception:  # noqa: BLE001 -- detached frame: treat as subresource
            is_main_nav = False
        scope_ok = self.scope(url)
        send_ok = method not in L.SAFE_METHODS and scope_ok and self.allow_send(method, url)
        action, reason = L.route_decision(method, url, req.resource_type, is_main_nav,
                                          scope_ok=scope_ok, send_allowed=send_ok)
        try:
            post = req.post_data
        except Exception:  # noqa: BLE001 -- binary body
            post = None
        if action == "abort" and reason == "mutating-get" and self.permit_mutating_get(url):
            action, reason = "continue", None
        if action == "abort":
            self._edge(method, url, False, self.refine_block_reason(method, url, reason), post)
            self.on_aborted(method, url, post, reason)
            await route.abort("blockedbyclient")
            return
        host = urlsplit(url).hostname or ""
        if host and not scope_ok and self.cur_page is not None and host not in self.cur_page["third_party_hosts"]:
            self.cur_page["third_party_hosts"].append(host)
        if method not in L.SAFE_METHODS:
            self._edge(method, url, True, None, post)
            await self.forward_sent(route, method, url, post)
            return
        if req.resource_type in ("xhr", "fetch"):
            self._edge(method, url, True, None)
            self.get_log.append({"url": url, "page": self.cur_page["url"] if self.cur_page else None})
        await route.continue_()

    def refine_block_reason(self, method: str, url: str, reason: str | None) -> str | None:
        """Pass 2 hook: a more specific reason for an aborted request."""
        return reason

    def permit_mutating_get(self, url: str) -> bool:
        """Teardown hook: let exactly one state-changing GET through (the
        human-confirmed logout link). Never true in Pass 1/2."""
        return False

    def on_aborted(self, method: str, url: str, post, reason: str | None) -> None:
        """Pass 2 hook: observe an aborted request (dry-click capture)."""

    async def forward_sent(self, route, method: str, url: str, post) -> None:
        """Pass 2 hook: send a non-GET the policy allowed (Pass 1 never gets here)."""
        await route.continue_()

    async def _on_ws(self, ws) -> None:
        # Never connect to the server in this pass: client frames go nowhere.
        def _count(_msg):
            if self.cur_page is not None:
                self.cur_page["ws_frames_blocked"] += 1
        ws.on_message(_count)

    def _attach_dialogs(self, page) -> None:
        async def handle(d):
            try:
                if d.type == "confirm" and self.on_dialog_accept():
                    await d.accept()
                else:
                    await d.dismiss()
            except Exception:  # noqa: BLE001 -- dialog already closed
                pass
            self.on_dialog(d)
        page.on("dialog", lambda d: asyncio.ensure_future(handle(d)))

    def on_dialog(self, dialog) -> None:
        """Pass 2 hook (execution detection)."""

    async def _settle(self, page, first: bool = False) -> None:
        try:
            await page.wait_for_load_state("networkidle", timeout=_SETTLE_MS)
        except Exception:  # noqa: BLE001 -- long-polling pages never go idle
            pass
        await page.wait_for_timeout(400 if first else 150)

    async def _snapshot(self, page) -> list[tuple]:
        out = []
        for frame in page.frames:
            try:
                data = await frame.evaluate(_ENUM_JS)
            except Exception:  # noqa: BLE001 -- frame navigated/detached mid-evaluate
                continue
            if data and (data.get("controls") or data.get("inputs")):
                out.append((frame, data))
        return out

    async def _open(self, session_file, cookie_header, bearer_token, local_storage, session_storage) -> None:
        self.context, self.page = await browser_confirm._new_page(
            self.browser, self.start_url, cookie_header, bearer_token, local_storage, session_file,
            session_storage=session_storage,
            context_options={"service_workers": "block", "viewport": browser_confirm.SCREENSHOT_VIEWPORT})
        await self.context.route("**/*", self._on_route)
        await self.context.route_web_socket("**/*", self._on_ws)
        self._attach_dialogs(self.page)
        self.context.on("page", self._attach_dialogs)

    def _enqueue_ok(self, url: str) -> bool:
        if not url.startswith(("http://", "https://")):
            return False
        if self.same_origin_only and _origin(url) != _origin(self.start_url):
            return False
        return self.scope(url)

    # -- one page ------------------------------------------------------------
    async def _visit(self, url: str, queue: list[str], is_start: bool) -> dict | None:
        page = self.page
        tmpl = endpoint_template(url)
        rec = {"url": url, "template": tmpl, "title": None, "screenshot": None, "auth_state": "ok",
               "nav_error": None,
               "inputs": [], "controls": [], "api_edges": [], "ws_frames_blocked": 0,
               "third_party_hosts": []}
        self.cur_page = rec
        self.current_control = None
        await self._budget()
        try:
            await page.goto(url, wait_until="domcontentloaded")
        except Exception as e:  # noqa: BLE001 -- e.g. a redirect to an out-of-scope host (SSO) was aborted
            rec["nav_error"] = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
            if is_start:
                raise _Stop("auth_lost" if self.had_session else "error",
                            f"start page did not load in scope: {rec['nav_error']}") from e
            return rec
        if not self.scope(page.url):
            # Playwright follows HTTP redirects without routing the redirected
            # request, so an in-scope URL can land on an out-of-scope host (an
            # SSO login). Never map or click anything there.
            host = urlsplit(page.url).hostname
            rec["nav_error"] = f"redirected out of scope to {host}"
            rec["auth_state"] = "out-of-scope-redirect"
            await page.goto("about:blank")
            if is_start:
                raise _Stop("auth_lost" if self.had_session else "error",
                            f"start page redirected out of scope to {host}")
            return rec
        await self._settle(page, first=True)
        snap = await self._snapshot(page)
        main_controls = [c for f, d in snap if f is page.main_frame for c in d["controls"]]
        if L.looks_logged_out(page.url, main_controls, self.had_session):
            login_redirect = bool(L._LOGIN_PATH_RE.search(urlsplit(page.url).path))
            if is_start or login_redirect:
                raise _Stop("auth_lost", f"logged-out view at {page.url}")
            rec["auth_state"] = "logged-out"
            rec["title"] = await page.title()
            await self._shoot(page, rec)
            return rec
        rec["url"] = _defrag(page.url) if self.scope(page.url) else url
        rec["title"] = await page.title()
        page_url = _defrag(page.url)
        known_inputs: set[tuple] = set()

        def absorb_inputs(snapshot, revealed_by):
            for _f, d in snapshot:
                for i in d["inputs"]:
                    key = (d["origin"], i["form_action"], i["name"], i["id"], i["type"])
                    if key in known_inputs:
                        continue
                    known_inputs.add(key)
                    item = {k: i[k] for k in ("name", "id", "type", "label", "placeholder",
                                              "required", "maxlength", "form_action", "form_method")}
                    item["frame_origin"] = d["origin"]
                    item["revealed_by"] = revealed_by
                    rec["inputs"].append(item)

        absorb_inputs(snap, None)
        seen: set[str] = set()
        clicks = 0
        while True:
            nxt = None
            for frame, d in snap:
                for c in d["controls"]:
                    sig = L.control_signature(c, tmpl)
                    if sig not in seen:
                        nxt = (frame, c, sig)
                        break
                if nxt:
                    break
            if nxt is None:
                break
            frame, c, sig = nxt
            seen.add(sig)
            cls = L.classify_control(c)
            crec = {"signature": sig, "text": c["text"] or c["aria_label"], "role": c["role"] or c["tag"],
                    "classification": cls, "href": c["href"], "clicked": False, "skipped_reason": None}
            rec["controls"].append(crec)
            href = _defrag(c["href"]) if c["tag"] == "a" and c["href"] else ""
            # A payment-labelled LINK ("Checkout") is still a page worth mapping:
            # visiting it is a GET, and every non-GET / payment-host request it
            # makes is aborted by the interceptor. Logout / account-delete links
            # are never followed (a GET logout would end the session).
            if cls in L.NEVER_CLICK and not (cls == "payment" and href):
                crec["skipped_reason"] = "never-click"
                continue
            if href and href != page_url and not c["href"].lower().startswith("javascript:"):
                if L.is_mutating_get_url(href):
                    crec["skipped_reason"] = "mutating-get"
                    self.current_control = sig
                    self._edge("GET", href, False, "mutating-get")
                elif self._enqueue_ok(href):
                    crec["skipped_reason"] = "enqueued"
                    if href not in queue:
                        queue.append(href)
                else:
                    crec["skipped_reason"] = "out-of-scope"
                    self.current_control = sig
                    self._edge("GET", href, False, "out-of-scope")
                self.current_control = None
                continue
            if clicks >= self.max_clicks:
                crec["skipped_reason"] = "click-cap"
                continue
            clicks += 1
            await self._click(frame, c, sig, crec)
            if _defrag(page.url) != page_url:
                landed = _defrag(page.url)
                if self._enqueue_ok(landed) and landed not in queue:
                    queue.append(landed)
                await self._budget()
                try:
                    await page.goto(page_url, wait_until="domcontentloaded")
                except Exception as e:  # noqa: BLE001 -- page no longer reachable: keep what we mapped
                    rec["nav_error"] = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
                    break
                await self._settle(page)
            for other in list(self.context.pages):
                if other is not page:
                    try:
                        await other.close()
                    except Exception:  # noqa: BLE001
                        pass
            self.current_control = None
            snap = await self._snapshot(page)
            absorb_inputs(snap, sig)
        await self._shoot(page, rec)
        return rec

    async def _shoot(self, page, rec) -> None:
        try:
            shot = await browser_confirm._capture_jpeg(page, self.shot_dir or browser_confirm._screenshot_dir())
            rec["screenshot"] = shot["path"]
        except Exception:  # noqa: BLE001 -- screenshot is best-effort evidence
            rec["screenshot"] = None

    async def _click(self, frame, c, sig, crec) -> None:
        if self.delay:
            await asyncio.sleep(self.delay)
        self.current_control = sig
        try:
            await frame.locator(f'[data-hm-idx="{c["idx"]}"]').first.click(timeout=_CLICK_TIMEOUT_MS)
            crec["clicked"] = True
        except Exception:  # noqa: BLE001 -- element detached/covered: recorded, not fatal
            crec["skipped_reason"] = "click-failed"
        await self._settle(self.page)

    # -- whole walk ------------------------------------------------------------
    async def run(self, **auth) -> dict:
        from playwright.async_api import async_playwright

        queue = [_defrag(self.start_url)]
        visited: set[str] = set()
        per_template: dict[str, int] = {}
        async with async_playwright() as p:
            self.browser = await p.chromium.launch(**browser_confirm._launch_kwargs())
            try:
                await self._open(**auth)
                retried = False
                while queue and len(self.inv["pages"]) < self.max_pages:
                    url = queue.pop(0)
                    if url in visited:
                        continue
                    tmpl = endpoint_template(url)
                    if per_template.get(tmpl, 0) >= MAX_PER_TEMPLATE:
                        continue
                    visited.add(url)
                    per_template[tmpl] = per_template.get(tmpl, 0) + 1
                    try:
                        rec = await self._visit(url, queue, is_start=not self.inv["pages"])
                    except _Stop as stop:
                        if stop.status == "auth_lost" and not retried and self.session_file:
                            # The session file may have been refreshed externally
                            # since the walk started: re-read it once and retry.
                            retried = True
                            await self.context.close()
                            await self._open(**auth)
                            visited.discard(url)
                            per_template[tmpl] -= 1
                            queue.insert(0, url)
                            continue
                        raise
                    if rec is not None:
                        self.inv["pages"].append(rec)
                await self.after_map()
            except _Stop as stop:
                self.inv["status"] = stop.status
                self.inv["error"] = stop.error
            except Exception as e:  # noqa: BLE001 -- reported in the inventory, never raised to the agent
                self.inv["status"] = "error"
                self.inv["error"] = f"{type(e).__name__}: {e}"
            finally:
                if self.context is not None:
                    try:
                        await browser_confirm._save_session(self.context, self.session_file)
                    except Exception:  # noqa: BLE001
                        pass
                await self.browser.close()
        return self.inv

    async def after_map(self) -> None:
        """Pass 2 hook: runs after the map with the browser still open."""


def _default_delay() -> float:
    try:
        import scope_guard

        return float(scope_guard.load_engagement().min_request_interval_s or 0.0)
    except Exception:  # noqa: BLE001 -- no engagement: no forced delay (scope+budget still apply)
        return 0.0


async def walk(start_url: str, mode: str = "map", *, session_file: str | None = None,
               cookie_header: str | None = None, bearer_token: str | None = None,
               local_storage: dict | None = None, session_storage: dict | None = None,
               max_pages: int = 50, max_clicks_per_page: int = 40, same_origin_only: bool = True,
               wall_clock_s: int = 1200, scope_check: Callable[[str], bool] | None = None,
               grant=None, walk_id: str | None = None, action_delay_s: float | None = None,
               screenshot_dir: str | None = None) -> dict:
    """Walk the app from start_url. Returns the inventory dict (schema_version 1);
    never raises for target-side failures (status/error carry them)."""
    scope = scope_check or L._default_scope_check
    walk_id = walk_id or uuid.uuid4().hex[:12]
    start = time.monotonic()
    auth = {"session_file": session_file, "cookie_header": cookie_header, "bearer_token": bearer_token,
            "local_storage": local_storage, "session_storage": session_storage}
    if mode not in ("map", "canary"):
        return _refused(start_url, mode, walk_id, f"unknown mode {mode!r}; expected 'map' or 'canary'")
    if not scope(start_url):
        return _refused(start_url, mode, walk_id, "start URL is out of scope")
    cls = _Walker
    if mode == "canary":
        import ui_walk_pass2

        refusal = ui_walk_pass2.check_grant(start_url, grant)
        if refusal:
            return _refused(start_url, mode, walk_id, refusal)
        cls = ui_walk_pass2.CanaryWalker
    w = cls(start_url, mode, scope=scope, max_pages=max_pages, max_clicks_per_page=max_clicks_per_page,
            same_origin_only=same_origin_only, wall_clock_s=wall_clock_s,
            action_delay_s=_default_delay() if action_delay_s is None else action_delay_s,
            screenshot_dir=screenshot_dir, had_session=any(auth.values()),
            session_file=session_file, auth=auth, walk_id=walk_id)
    if mode == "canary":
        w.configure(grant)
    inv = await w.run(**auth)
    browser_confirm._log_call("browser-mcp:ui-walk", [start_url, mode, walk_id],
                              returncode=0 if inv["status"] == "complete" else 1,
                              duration_ms=(time.monotonic() - start) * 1000, block=None)
    return inv


def _refused(start_url: str, mode: str, walk_id: str, why: str) -> dict:
    return {"schema_version": SCHEMA_VERSION, "walk_id": walk_id, "start_url": start_url, "mode": mode,
            "status": "refused", "error": why, "honest_limits": list(HONEST_LIMITS), "pages": [],
            "real_submits": [], "canaries": [], "sinks": [], "candidates": []}
