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
import re
import socket
import http.client
import sys
import time
import uuid
from collections.abc import Callable
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import browser_confirm
import tool_resolver
import ui_walk_events
import ui_walk_events_logic
import ui_walk_logic as L
import ui_walk_sso
import ui_walk_sso_logic as S
import ui_walk_store
from budget_guard import BudgetExceeded
from endpoint_template import endpoint_template


async def _refresh_identity_session(session_file: str) -> None:
    """Session keep-alive hook for auth_lost: if session_file is a captured
    identity's session file, silently renew it (session_refresh) before the
    walk re-reads it. Never raises; the walk's own single retry follows."""
    try:
        import session_refresh

        label = session_refresh.label_for_session_file(session_file)
        if label:
            await session_refresh.refresh_session(label)
    except Exception:  # noqa: BLE001 -- renewal is best-effort here
        pass


SCHEMA_VERSION = 3
MAX_PAGES_PER_IDP_HOST = 10   # spec 2
MAX_SSO_REPEATS = 5           # spec 2: the repeat (user decision B), per walk
MAX_DISCOVERY_HOSTS = 3
MAX_DISCOVERY_GETS_PER_HOST = 3
_SSO_REQUEST_TIMEOUT_MS = 10000
MAX_PER_TEMPLATE = 3
_SETTLE_MS = 3000
_CLICK_TIMEOUT_MS = 3000
_DOM_MIN_LEFT_S = 15.0   # no DOM-source planting / postMessage probe when the walk is nearly out of time

# Burp mirror (mirror mode only): a block page is one of these statuses whose
# body tool_resolver.classify_block() flags as a WAF / rate-limit page.
_BLOCK_STATUSES = frozenset({403, 429, 503})
_BLOCK_KINDS = frozenset({"waf", "rate_limit"})
_PROXY_PREFLIGHT_S = 2.0
_MIRROR_BLOCK_STREAK = 3          # R12: consecutive block-signature page loads before a mid-walk stop
_SUSPECT = "proxy-block-suspected"
_NET_ERR_RE = re.compile(r"net::(ERR_[A-Z0-9_]+)")
MIRROR_TLS_LIMIT = (
    "Burp mirror: the walk's browser accepted the proxy's re-signed TLS certificates (ignore_https_errors), "
    "because Burp re-signs HTTPS with its own CA. Checking the real server's (upstream) certificate is "
    "whatever the human's proxy is configured to do; the walker does not check it. Walks without the "
    "mirror, and the direct fallback, keep TLS checks on.")

HONEST_LIMITS = [
    ("A GET request whose URL looks harmless but changes server state cannot be detected "
     "in advance; only GETs whose URL contains logout/signout/delete/remove/revoke/cancel/"
     "unsubscribe/deactivate/destroy are blocked."),
    ("DOM-XSS sink hooks cover innerHTML/outerHTML, insertAdjacentHTML, document.write(ln), "
     "document.cookie, Function(...), string setTimeout/setInterval and script/iframe/anchor src/href "
     "setters. Only eval (wrapping it would change direct-eval semantics) and location (unforgeable) "
     "are not wrapped: a canary that reaches a navigation or request is caught as an aborted "
     "'navigation'/'request' sink, and one that executes through an unhooked sink is recorded as sink "
     "'unknown'. Only #hash, window.name (pages that read it) and an in-page postMessage are planted; "
     "?query is not (it would reach the server)."),
    ("A planted canary is only caught leaving the browser when it appears raw in a request URL, body or "
     "header value: a page that sends it transformed (base64, hashed, encrypted) can still send it out."),
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


def _scrub_saved_session(path: str | None, tokens) -> int:
    """The post-save GUARANTEE behind the in-browser canary scrub (which only
    sees the current page's frames and can miss a mid-navigation page): load
    the session file _save_session just wrote and drop every cookie whose value
    (or name) carries one of this walk's DOM tokens, and every localStorage /
    sessionStorage entry -- any origin, including the huntmcp_session_storage
    sidecar -- whose KEY or VALUE carries one. Rewritten atomically 0600 the
    same way browser_confirm._save_session writes it, and only when something
    was removed. Returns the number of entries removed; never prints or keeps
    a value. An unreadable / non-JSON file is left untouched."""
    toks = tuple(t for t in (tokens or ()) if isinstance(t, str) and t)
    if not path or not toks or not os.path.isfile(path):
        return 0
    try:
        with open(path) as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return 0
    if not isinstance(state, dict):
        return 0

    def hit(*vals) -> bool:
        return any(v is not None and any(t in (v if isinstance(v, str) else str(v)) for t in toks) for v in vals)

    removed = 0
    cookies = state.get("cookies")
    if isinstance(cookies, list):
        keep = [c for c in cookies if not (isinstance(c, dict) and hit(c.get("value"), c.get("name")))]
        removed += len(cookies) - len(keep)
        state["cookies"] = keep
    for o in state.get("origins") or []:
        if not isinstance(o, dict):
            continue
        for area in ("localStorage", "sessionStorage"):
            entries = o.get(area)
            if isinstance(entries, list):
                keep = [e for e in entries if not (isinstance(e, dict) and hit(e.get("name"), e.get("value")))]
                removed += len(entries) - len(keep)
                o[area] = keep
    side = state.get(browser_confirm.SESSION_STORAGE_KEY)
    if isinstance(side, dict):
        for kv in side.values():
            if isinstance(kv, dict):
                for k in [k for k, v in kv.items() if hit(k, v)]:
                    del kv[k]
                    removed += 1
    if removed:
        browser_confirm._write_private_json(path, state)
    return removed


class _Stop(Exception):
    def __init__(self, status: str, error: str | None = None):
        super().__init__(status)
        self.status = status
        self.error = error


class _ProxyRefused(Exception):
    """Mirror mode: the start page failed or was blocked through the proxy."""

    def __init__(self, reason: str, detail: str):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def _mirror_status(requested: bool = False, active: bool = False, proxy: str | None = None,
                   reason: str | None = None, detail: str | None = None) -> dict:
    """inv['burp_mirror']. 'detail' (short evidence: HTTP status + block kind,
    or a net-error name; never a body) is present only when there is some."""
    out = {"requested": requested, "active": active, "proxy": proxy, "reason": reason}
    if detail is not None:
        out["detail"] = detail
    return out


def resolve_mirror(upstream_proxy: str | None) -> tuple[str | None, str | None]:
    """(proxy, refusal). proxy is the freshly rebuilt "http://host:port" (the
    only form ever handed to a browser launch) or None for off; refusal is the
    text for a proxy that is not a bare loopback http URL (target traffic must
    never go to a remote proxy). The ONLY place HUNTMCP_UPSTREAM_PROXY is read.
    The raw URL is never echoed (it could carry credentials)."""
    p = ui_walk_events_logic.resolve_upstream_proxy(upstream_proxy or "",
                                                    os.environ.get("HUNTMCP_UPSTREAM_PROXY"))
    if p is None:
        return None, None
    if p == ui_walk_events_logic.AUTO_PROXY:
        return p, None   # setup_mirror() detects Burp; only a verified Burp listener is ever used
    err = ui_walk_events_logic.validate_proxy_url(p)
    if err:
        return None, f"upstream_proxy refused: {err}"
    return ui_walk_events_logic.canonical_proxy_url(p), None


def proxy_refusal(upstream_proxy: str | None) -> str | None:
    return resolve_mirror(upstream_proxy)[1]


_AUTO_BURP_DEFAULT_PORT = 8080
_AUTO_BURP_TIMEOUT_S = 2.0
_AUTO_BURP_MAX_BYTES = 65536


def _auto_port() -> int:
    """The loopback port auto mode probes for Burp (HUNTMCP_BURP_AUTO_PORT,
    default 8080; anything unusable falls back to the default)."""
    try:
        port = int(os.environ.get("HUNTMCP_BURP_AUTO_PORT", _AUTO_BURP_DEFAULT_PORT))
    except ValueError:
        return _AUTO_BURP_DEFAULT_PORT
    return port if 0 < port < 65536 else _AUTO_BURP_DEFAULT_PORT


def _detect_burp() -> str | None:
    """Auto mode: one plain GET / straight to the listener on 127.0.0.1 (no
    proxy, no redirects followed, nothing about the target in it). Returns
    the proxy URL only when THAT listener itself answers 200 with a page
    naming Burp Suite; the whole check is bounded by _AUTO_BURP_TIMEOUT_S."""
    port = _auto_port()
    deadline = time.monotonic() + _AUTO_BURP_TIMEOUT_S
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=_AUTO_BURP_TIMEOUT_S)
    try:
        conn.request("GET", "/", headers={"Connection": "close"})
        resp = conn.getresponse()
        if resp.status != 200:
            return None
        chunks, size = [], 0
        while size < _AUTO_BURP_MAX_BYTES:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            if conn.sock is not None:
                conn.sock.settimeout(left)
            chunk = resp.read1(min(8192, _AUTO_BURP_MAX_BYTES - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        body = b"".join(chunks).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 -- nothing listening / not HTTP / too slow: not Burp
        return None
    finally:
        conn.close()
    return f"http://127.0.0.1:{port}" if ui_walk_events_logic.looks_like_burp(body) else None


def _proxy_reachable(proxy_url: str) -> bool:
    u = urlsplit(proxy_url)
    try:
        with socket.create_connection((u.hostname, u.port), timeout=_PROXY_PREFLIGHT_S):
            return True
    except OSError:
        return False


def _proxy_level_error(e: Exception) -> bool:
    """A navigation failure at connection/TLS level (what a refusing proxy path
    looks like), not one the walker itself caused by aborting a request."""
    msg = str(e)
    if "ERR_BLOCKED_BY_CLIENT" in msg or "ERR_ABORTED" in msg:
        return False
    return "net::ERR_" in msg or type(e).__name__ == "TimeoutError"


def _net_error(e: Exception) -> str:
    m = _NET_ERR_RE.search(str(e))
    return f"net::{m.group(1)}" if m else type(e).__name__


def _proxy_side_error(name: str) -> bool:
    """Chromium's proxy/tunnel error family: the proxy itself failed, not the target."""
    return "PROXY" in name or name == "net::ERR_TUNNEL_CONNECTION_FAILED"


def _mark_block(rec: dict, detail: str) -> None:
    rec["auth_state"] = _SUSPECT
    rec["nav_error"] = f"{_SUSPECT}: {detail}"


class _Walker:
    def __init__(self, start_url: str, mode: str, *, scope: Callable[[str], bool],
                 max_pages: int, max_clicks_per_page: int, same_origin_only: bool,
                 wall_clock_s: int, action_delay_s: float, screenshot_dir: str | None,
                 had_session: bool, session_file: str | None, auth: dict, walk_id: str):
        self.start_url = start_url
        self.mode = mode
        self.recorder = ui_walk_events.Recorder()
        self.recorder.on_dom_hit = self._register_dom_hit
        self._current_control: str | None = None
        # Scope is host-based; cache the verdict per host so the interceptor
        # does not re-read engagement.yaml for every subresource request.
        self._scope_fn = scope
        self._scope_cache: dict[str, bool] = {}
        # spec 2: in-scope SSO / auth flows as surface (inv["sso"])
        self.sso = ui_walk_sso.SsoTracker(self.scope)
        self.recorder.on_redirect_chain = self._on_chain
        self._idp_enqueued: dict[str, set[str]] = {}
        self._pw = None   # the Playwright handle while run() is active (repeat / discovery request contexts)
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
            "pass2_events": [], "events_candidate_errors": 0,
            "burp_mirror": _mirror_status(), "sso": self.sso.data,
        }
        # Burp mirror: off unless setup_mirror() found a reachable loopback proxy.
        self.proxy: str | None = None
        self.mirror_active = False
        self._direct_comparison = False   # the one direct start-page load after a proxy refusal
        self._last_doc_resp = None        # mirror mode: latest main-frame document response
        self._block_streak = 0            # mirror mode: consecutive block-signature page loads (R12)
        self._cand_keys: set[str] = set()   # dedupe keys of inv["candidates"] (see _cand_index)
        self._cand_seen = 0
        self.cur_page: dict | None = None
        self.context = None
        self.page = None
        self.browser = None
        self.get_log: list[dict] = []

    @property
    def current_control(self) -> str | None:
        return self._current_control

    @current_control.setter
    def current_control(self, sig: str | None) -> None:
        self._current_control = sig
        self.recorder.set_control(sig)

    # -- spec 2: SSO tracking ---------------------------------------------------
    def _on_chain(self, urls: list[str], ctl: str | None, rtype: str) -> None:
        """A redirect chain (full URLs, memory only): SSO hops into the tracker,
        and every out-of-scope hop the browser followed is recorded honestly."""
        page = (self.cur_page or {}).get("url")
        self.sso.observe_chain(urls, page=page, control_signature=ctl)
        if rtype != "document" or not any(isinstance(u, str) and S.classify_url(u) is not None
                                           for u in urls[:ui_walk_sso.MAX_CHAIN_HOPS]):
            return   # only SSO chains: a plain off-site redirect is not an IdP redirect
        for u in urls[:ui_walk_sso.MAX_CHAIN_HOPS]:
            if isinstance(u, str) and u.startswith(("http://", "https://")) and not self.scope(u):
                self.sso.note_out_of_scope_redirect(u, page=page, control_signature=ctl)
                if not self.inv.get("sso_oos_limit_noted"):
                    self.inv["sso_oos_limit_noted"] = True
                    self.inv["honest_limits"].append(
                        "Following an HTTP redirect to an out-of-scope identity provider sends one GET per "
                        "hop there, as any browser does; nothing else is done on that host.")

    def _is_sso_page(self, page_url: str, chain: list[str]) -> bool:
        """An in-scope IdP page: the navigation reached it through an
        authorize / SAML-request hop with no callback after it, or it is on a
        recorded IdP host other than the app's own (start URL) host."""
        if not self.scope(page_url):
            return False
        roles = [S.classify_url(u) for u in chain if isinstance(u, str)]
        last = max((i for i, r in enumerate(roles) if r in ("authorize", "saml-request")), default=None)
        if last is not None and "callback" not in roles[last + 1:] and "saml-response" not in roles[last + 1:]:
            return True
        return self.sso.is_idp_url(page_url) and urlsplit(page_url).netloc.lower() != \
            urlsplit(self.start_url).netloc.lower()

    @staticmethod
    def _chain_urls(resp) -> list[str]:
        out, r = [], getattr(resp, "request", None)
        while r is not None and len(out) < ui_walk_sso.MAX_CHAIN_HOPS:
            out.insert(0, r.url)
            r = r.redirected_from
        return out

    def _register_dom_hit(self, token: str, source: str, page_url: str) -> None:
        """A DOM canary that reached a sink / executed goes into the canary
        registry with its source (registered on hit, not on plant, so a walk
        that finds nothing writes nothing)."""
        page, qkeys = ui_walk_events._strip_url(page_url)   # R8: no query values in the registry
        ui_walk_store.register_canary(token, {"token": token, "source": source, "page": page,
                                              "query_keys": qkeys, "walk_id": self.inv["walk_id"],
                                              "kind": "dom-source"})

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

    # -- Burp mirror -----------------------------------------------------------
    async def setup_mirror(self, proxy: str | None) -> None:
        """proxy: the rebuilt URL from resolve_mirror(), or None/"" for off.
        Validated again here (ValueError for anything that is not a bare
        loopback http URL); never reads the env var. Preflights the proxy."""
        if not proxy:
            return
        auto = proxy == ui_walk_events_logic.AUTO_PROXY
        if auto:
            proxy = await asyncio.to_thread(_detect_burp)
            if not proxy:
                self.inv["burp_mirror"]["auto"] = "no Burp detected"
                return
        proxy = ui_walk_events_logic.canonical_proxy_url(proxy)
        if not await asyncio.to_thread(_proxy_reachable, proxy):
            self.inv["burp_mirror"] = _mirror_status(True, False, proxy, "proxy unreachable",
                                                     "TCP connect to the proxy failed")
            if auto:
                self.inv["burp_mirror"]["auto"] = "Burp detected"
            return
        self.proxy, self.mirror_active = proxy, True
        self.inv["burp_mirror"] = _mirror_status(True, True, proxy, None)
        if auto:
            self.inv["burp_mirror"]["auto"] = "Burp detected"
        self.inv["honest_limits"].append(MIRROR_TLS_LIMIT)

    def _launch_options(self) -> dict:
        if self.mirror_active:
            return browser_confirm._launch_kwargs(proxy=self.proxy)
        return browser_confirm._launch_kwargs()

    async def _block_kind(self, resp) -> str | None:
        """Mirror mode only: 'waf'/'rate_limit' when resp is a block page."""
        if resp is None or resp.status not in _BLOCK_STATUSES:
            return None
        try:
            body = await resp.text()
        except Exception:  # noqa: BLE001 -- unreadable body: judge on an empty one
            body = ""
        kind = tool_resolver.classify_block(body)
        return kind if kind in _BLOCK_KINDS else None

    async def _note_block(self, resp, url: str) -> str | None:
        """Mid-walk, mirror mode only (R12): the detail ("HTTP 403 (waf)") when
        this page load returned a block-signature page, else None. One such
        page may just be the app's own 403/maintenance page, so it is only
        marked on its page record; the walk stops ("blocked mid-walk") after
        _MIRROR_BLOCK_STREAK of them in a row. Any normal page resets the
        count. The walk never switches to direct mid-way (that would mix
        evidence)."""
        if not self.mirror_active or resp is None:
            return None
        kind = await self._block_kind(resp)
        if not kind:
            self._block_streak = 0
            return None
        self._block_streak += 1
        detail = f"HTTP {resp.status} ({kind})"
        if self._block_streak >= _MIRROR_BLOCK_STREAK:
            self.inv["burp_mirror"].update(reason="blocked mid-walk",
                                           detail=f"{detail}, {self._block_streak} page loads in a row")
            # Host only: this error is shown outside the quarantine (the URL is target text).
            host = urlsplit(url).hostname or "(unknown host)"
            raise _Stop("blocked", f"a page on {host} was page load {self._block_streak} in a row to return a "
                                   f"block page through the proxy ({detail}); the walk stopped without switching "
                                   "to direct -- re-run with the mirror off")
        return detail

    def _note_doc_response(self, resp) -> None:
        """Mirror mode: remember the latest main-frame document response, so a
        navigation a click (or a reload) caused is checked for a block page too."""
        try:
            if resp.request.is_navigation_request() and resp.frame.parent_frame is None:
                self._last_doc_resp = resp
        except Exception:  # noqa: BLE001 -- detached frame
            pass

    async def _check_doc_block(self, own_url: str | None = None) -> str | None:
        """own_url (after a click): only a document response for THIS page's own
        URL counts toward the R12 streak. A block page a click reached at a
        different URL is not counted here -- that page counts once, on its own
        visit (it is enqueued), so one app 403 is never counted twice."""
        resp, self._last_doc_resp = self._last_doc_resp, None
        if resp is None:
            return None
        if own_url is not None and _defrag(resp.url) != own_url:
            return None
        return await self._note_block(resp, _defrag(resp.url))

    def _comparison_failed(self, direct_detail: str) -> None:
        """The direct start-page load failed too. Proxied-refusal + direct block
        = a real block, not a proxy problem (R11). The walk keeps its normal
        stop status; the mirror says why it is off and keeps both pieces of
        evidence."""
        self._direct_comparison = False
        m = self.inv["burp_mirror"]
        if m.get("reason") == "target refused proxied traffic":
            m["reason"] = "blocked via proxy and direct"
        m["detail"] = f"proxy: {m.get('detail')}; direct: {direct_detail}"

    async def _fall_back_direct(self, pw, auth: dict, refusal: _ProxyRefused) -> None:
        """The start page failed through the proxy: relaunch WITHOUT the proxy
        and WITHOUT ignore_https_errors. The next start-page visit is the one
        (budget-charged) direct comparison load."""
        self.mirror_active = False
        self._direct_comparison = True
        self.inv["burp_mirror"].update(active=False, reason=refusal.reason, detail=refusal.detail)
        for closable in (self.context, self.browser):
            try:
                await closable.close()
            except Exception:  # noqa: BLE001
                pass
        self.context = self.page = None
        self.browser = await pw.chromium.launch(**self._launch_options())
        await self._open(**auth)

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
        try:
            post = req.post_data
        except Exception:  # noqa: BLE001 -- binary body
            post = None
        try:
            hdr_values = list(req.headers.values())
        except Exception:  # noqa: BLE001
            hdr_values = []
        # A planted DOM canary must never reach the server (any mode, any host):
        # the request it flowed into is aborted in the browser and recorded as a sink.
        tok = self.recorder.dom_token_in(_defrag(url), post, *hdr_values)
        if tok is not None:
            try:
                fo = _origin(req.frame.url)
            except Exception:  # noqa: BLE001
                fo = ""
            try:
                nav = req.is_navigation_request()
            except Exception:  # noqa: BLE001
                nav = False
            self.recorder.record_request_sink(tok, url, nav, fo)
            await route.abort("blockedbyclient")
            return
        scope_ok = self.scope(url)
        send_ok = method not in L.SAFE_METHODS and scope_ok and self.allow_send(method, url)
        action, reason = L.route_decision(method, url, req.resource_type, is_main_nav,
                                          scope_ok=scope_ok, send_allowed=send_ok)
        if action == "abort" and reason == "mutating-get" and self.permit_mutating_get(url):
            action, reason = "continue", None
        if is_main_nav or req.resource_type in ("document", "xhr", "fetch"):
            try:
                shape = _body_shape(post) or {}
                self.sso.observe_url(url, method=method, seen_via="aborted" if action == "abort" else "request",
                                     page=(self.cur_page or {}).get("url"),
                                     control_signature=self.current_control,
                                     body_fields=shape.get("form_keys") or shape.get("json_keys"))
            except Exception:  # noqa: BLE001 -- SSO tracking never affects the walk
                pass
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
        def _count(msg):
            if self.cur_page is not None:
                self.cur_page["ws_frames_blocked"] += 1
            try:
                self.recorder.record(ui_walk_events.ws_frame_event(ws.url, msg))
            except Exception:  # noqa: BLE001 -- recording never affects the walk
                pass
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
        """Execution detection: a dialog carrying a planted DOM canary marks its
        dom_sink executed. Pass 2 extends this (and must call super)."""
        try:
            self.recorder.note_dialog(dialog.message or "")
        except Exception:  # noqa: BLE001 -- recording never affects the walk
            pass

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
        opts = {"service_workers": "block", "viewport": browser_confirm.SCREENSHOT_VIEWPORT}
        if self.mirror_active:
            opts["ignore_https_errors"] = True   # mirror mode only: Burp re-signs TLS with its own CA
        self.context, self.page = await browser_confirm._new_page(
            self.browser, self.start_url, cookie_header, bearer_token, local_storage, session_file,
            session_storage=session_storage, context_options=opts)
        await self.context.route("**/*", self._on_route)
        await self.context.route_web_socket("**/*", self._on_ws)
        if self.mirror_active:
            self.page.on("response", self._note_doc_response)
        self._attach_dialogs(self.page)
        await self.recorder.attach(self.context, self.page, scope=self.scope)
        self.context.on("page", self._attach_dialogs)

    def _enqueue_ok(self, url: str) -> bool:
        if not url.startswith(("http://", "https://")):
            return False
        if S.is_callback_url(url):
            return False   # spec 2: replaying a one-time code / token response changes state
        if self.same_origin_only and _origin(url) != _origin(self.start_url):
            # spec 2: a recorded in-scope IdP host is walkable too (<= 10 pages per host)
            if not (self.sso.is_idp_url(url) and self.scope(url)):
                return False
            seen = self._idp_enqueued.setdefault(urlsplit(url).netloc.lower(), set())
            if url not in seen and len(seen) >= MAX_PAGES_PER_IDP_HOST:
                return False
            seen.add(url)
            return True
        return self.scope(url)

    # -- one page ------------------------------------------------------------
    async def _visit(self, url: str, queue: list[str], is_start: bool) -> dict | None:
        rec = {"url": url, "template": endpoint_template(url), "title": None, "screenshot": None,
               "auth_state": "ok", "nav_error": None,
               "inputs": [], "controls": [], "api_edges": [], "ws_frames_blocked": 0,
               "third_party_hosts": []}
        self.recorder.begin_page(rec)
        try:
            return await self._visit_page(rec, url, queue, is_start)
        finally:
            await self._end_events(rec)

    def _derive_page(self, rec: dict) -> None:
        """Candidates from a FINISHED page's events. Called once, when the page
        lands in inv['pages'] -- never for an aborted (_Stop) visit, so a retried
        page cannot duplicate leads. A rule bug is counted, never fatal."""
        try:
            self._add_candidates(ui_walk_events_logic.derive_candidates(rec, scope=self.scope))
        except Exception:  # noqa: BLE001
            self.inv["events_candidate_errors"] += 1

    @staticmethod
    def _cand_key(c: dict) -> str:
        return json.dumps([c.get("type"), c.get("page"), c.get("control_signature"), c.get("detail")],
                          sort_keys=True, default=str)

    def _cand_index(self) -> set[str]:
        """The persistent dedupe key set, caught up with any candidate appended
        to inv['candidates'] directly (Pass 2 / destroy) since the last call --
        never rebuilt from all candidates. #164 candidates without a "detail"
        are not deduped, as before."""
        cl = self.inv["candidates"]
        keys = getattr(self, "_cand_keys", None)
        n = getattr(self, "_cand_seen", 0)
        if keys is None or n > len(cl):      # first use, or the list was replaced
            keys, n = set(), 0
        for c in cl[n:]:
            if "detail" in c:
                keys.add(self._cand_key(c))
        self._cand_keys, self._cand_seen = keys, len(cl)
        return keys

    def _add_candidates(self, cands: list[dict]) -> None:
        seen = self._cand_index()
        for c in cands:
            key = self._cand_key(c)
            if key not in seen:
                seen.add(key)
                self.inv["candidates"].append(c)
        self._cand_seen = len(self.inv["candidates"])

    async def _end_events(self, rec: dict) -> None:
        await self.recorder.end_page(rec, remaining_s=self.deadline - time.monotonic())
        if self.recorder.drains_skipped and not self.inv.get("events_drains_skipped"):
            self.inv["honest_limits"].append(
                "Event recording stopped waiting for in-flight requests (walk time or the 30s per-walk "
                "drain budget was used up); late responses on later pages may be missing from events.")
        self.inv["events_drains_skipped"] = self.recorder.drains_skipped
        self.inv["events_forged_dropped"] = self.recorder.forged_dropped
        if not self.inv.get("events_limit_noted"):
            self.inv["events_limit_noted"] = True
            self.inv["honest_limits"].append(
                "In-page event hooks are best-effort: a hostile page controls its own JavaScript and can "
                "suppress or distort the events it produces. Event-derived candidates are leads, never "
                "confirmed findings.")
        self.inv["events_snapshot_frames_skipped"] = self.recorder.snapshot_frames_skipped
        self.inv["dom_canary_cookies_cleared"] = self.recorder.canary_cookies_cleared
        self.inv["dom_canary_storage_cleared"] = self.recorder.canary_storage_cleared

    async def _scrub_canaries(self) -> None:
        """No planted canary may outlive its page: cookies and web-storage entries
        carrying one are removed (also right before the session file is saved;
        _scrub_saved_session then guarantees the saved file has none)."""
        await self.recorder.clear_canary_cookies(self.context)
        await self.recorder.scrub_storage(self.page)
        self.inv["dom_canary_cookies_cleared"] = self.recorder.canary_cookies_cleared
        self.inv["dom_canary_storage_cleared"] = self.recorder.canary_storage_cleared

    async def _visit_page(self, rec: dict, url: str, queue: list[str], is_start: bool) -> dict | None:
        page = self.page
        tmpl = rec["template"]
        self.cur_page = rec
        self.current_control = None
        await self._budget()
        try:
            resp = await page.goto(url, wait_until="domcontentloaded")
        except Exception as e:  # noqa: BLE001 -- e.g. a redirect to an out-of-scope host (SSO) was aborted
            rec["nav_error"] = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
            if is_start:
                if self.mirror_active and _proxy_level_error(e):
                    name = _net_error(e)
                    raise _ProxyRefused("proxy unreachable" if _proxy_side_error(name)
                                        else "target refused proxied traffic", name) from e
                if self._direct_comparison:
                    self._comparison_failed(_net_error(e))
                raise _Stop("auth_lost" if self.had_session else "error",
                            f"start page did not load in scope: {rec['nav_error']}") from e
            return rec
        chain = self._chain_urls(resp)
        try:
            self._on_chain(chain, None, "document")
        except Exception:  # noqa: BLE001
            pass
        if is_start and self.mirror_active:
            kind = await self._block_kind(resp)
            if kind:
                raise _ProxyRefused("target refused proxied traffic", f"HTTP {resp.status} ({kind})")
        elif is_start and self._direct_comparison:
            kind = await self._block_kind(resp)
            if kind:
                self._comparison_failed(f"HTTP {resp.status} ({kind})")
                raise _Stop("blocked", f"start page is blocked with and without the proxy (HTTP {resp.status}, "
                                       f"{kind}): a real block on the target, not a proxy problem; a human should look")
            self._direct_comparison = False
        else:
            detail = await self._note_block(resp, url)   # mirror mode only
            if detail:
                _mark_block(rec, detail)                  # never mapped or clicked through
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
        sso_page = not is_start and self._is_sso_page(page.url, chain)
        looked_logged_out = False
        if sso_page:
            # spec 2: an in-scope IdP login / consent / MFA page is surface, even
            # though it looks logged out; nothing on it is filled or submitted.
            rec["auth_state"] = "sso"
            looked_logged_out = L.looks_logged_out(page.url, main_controls, self.had_session)
        elif L.looks_logged_out(page.url, main_controls, self.had_session):
            login_redirect = bool(L._LOGIN_PATH_RE.search(urlsplit(page.url).path))
            if is_start:
                raise _Stop("auth_lost", f"logged-out view at {page.url}")
            rec["auth_state"] = "logged-out"
            rec["title"] = await page.title()
            await self._end_events(rec)
            await self._shoot(page, rec)
            if login_redirect:
                # One page bouncing to a login (a separately-protected / SSO
                # area) is not proof the whole session died: re-check the start
                # page, which rendered logged-in when the walk began.
                if not await self._session_still_valid():
                    raise _Stop("auth_lost", f"logged-out view at {page.url} and the start page is logged out too")
                rec["auth_state"] = "login-required"
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
        if sso_page:
            rec["sso_role"] = S.sso_page_role(rec["inputs"], main_controls)
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
            if c["tag"] == "a" and c["href"]:
                try:
                    self.sso.observe_url(c["href"], seen_via="href", page=rec["url"], control_signature=sig)
                except Exception:  # noqa: BLE001
                    pass
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
            self._last_doc_resp = None
            await self._click(frame, c, sig, crec)
            detail = await self._check_doc_block(page_url)   # mirror mode only (listener attached only then)
            if detail and _defrag(page.url) == page_url:
                _mark_block(rec, detail)              # this page itself re-loaded into a block page
                break
            if _defrag(page.url) != page_url:
                landed = _defrag(page.url)
                if self._enqueue_ok(landed) and landed not in queue:
                    queue.append(landed)
                if S.is_callback_url(page_url):
                    # spec 2: never re-request a callback (its code is one-time)
                    rec["nav_error"] = "callback page: not re-requested"
                    break
                await self._budget()
                try:
                    back = await page.goto(page_url, wait_until="domcontentloaded")
                except Exception as e:  # noqa: BLE001 -- page no longer reachable: keep what we mapped
                    rec["nav_error"] = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
                    break
                detail = await self._note_block(back, page_url)
                if detail:
                    _mark_block(rec, detail)
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
        if self.deadline - time.monotonic() > _DOM_MIN_LEFT_S and rec["auth_state"] != _SUSPECT:
            # zero-traffic DOM sources (the window.name reload is a budget-charged GET), then the probe
            try:
                self._last_doc_resp = None
                await self.recorder.plant_sources(page, page_url, rec, budget=self._budget)
                detail = await self._check_doc_block()   # the window.name reload, mirror mode only
                if detail:
                    _mark_block(rec, detail)
                else:
                    await self.recorder.probe_postmessage(page, rec)
            finally:
                await self._scrub_canaries()
        await self._end_events(rec)
        await self._shoot(page, rec)
        if looked_logged_out and self.had_session and not await self._session_still_valid():
            raise _Stop("auth_lost", f"logged-out view at {page.url} and the start page is logged out too")
        return rec

    async def _session_still_valid(self) -> bool:
        page = self.page
        saved, self.cur_page = self.cur_page, None  # probe edges belong to no page
        try:
            await self._budget()
            resp = await page.goto(self.start_url, wait_until="domcontentloaded")
            await self._note_block(resp, self.start_url)   # counts toward the R12 streak; mirror mode only
            await self._settle(page, first=True)
            if not self.scope(page.url):
                return False
            snap = await self._snapshot(page)
            ctrls = [c for f, d in snap if f is page.main_frame for c in d["controls"]]
            return not L.looks_logged_out(page.url, ctrls, self.had_session)
        except _Stop:
            raise
        except Exception:  # noqa: BLE001 -- cannot tell: treat as lost (fail safe)
            return False
        finally:
            self.cur_page = saved

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
        before = await self.recorder.snapshot_storage(self.page)
        try:
            await frame.locator(f'[data-hm-idx="{c["idx"]}"]').first.click(timeout=_CLICK_TIMEOUT_MS)
            crec["clicked"] = True
        except Exception:  # noqa: BLE001 -- element detached/covered: recorded, not fatal
            crec["skipped_reason"] = "click-failed"
        await self._settle(self.page)
        self.recorder.record_storage_diff(before, await self.recorder.snapshot_storage(self.page), sig)

    # -- whole walk ------------------------------------------------------------
    async def run(self, **auth) -> dict:
        from playwright.async_api import async_playwright

        queue = [_defrag(self.start_url)]
        visited: set[str] = set()
        per_template: dict[str, int] = {}
        async with async_playwright() as p:
            self._pw = p
            self.browser = await p.chromium.launch(**self._launch_options())
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
                    except _ProxyRefused as refusal:
                        # The start page failed / was blocked only through the
                        # proxy so far: one direct comparison load decides.
                        # Nothing is tried to get around the target's check.
                        await self._fall_back_direct(p, auth, refusal)
                        visited.discard(url)
                        per_template[tmpl] -= 1
                        queue.insert(0, url)
                        continue
                    except _Stop as stop:
                        if stop.status == "auth_lost" and not retried and self.session_file:
                            # The session file may have been refreshed externally
                            # since the walk started: re-read it once and retry.
                            # Session keep-alive: first try a silent renewal of the
                            # identity whose captured session_file this is.
                            retried = True
                            await _refresh_identity_session(self.session_file)
                            await self.context.close()
                            await self._open(**auth)
                            visited.discard(url)
                            per_template[tmpl] -= 1
                            queue.insert(0, url)
                            continue
                        raise
                    if rec is not None:
                        self.inv["pages"].append(rec)
                        self._derive_page(rec)
                if self.mode == "map":
                    await self._run_sso_repeats()
                    await self._run_sso_discovery()
                try:
                    self._add_candidates(S.derive_sso_candidates(self.sso.data))
                except Exception:  # noqa: BLE001 -- a rule bug is counted, never fatal
                    self.inv["events_candidate_errors"] += 1
                await self.after_map()
            except _Stop as stop:
                self.inv["status"] = stop.status
                self.inv["error"] = stop.error
            except Exception as e:  # noqa: BLE001 -- reported in the inventory, never raised to the agent
                self.inv["status"] = "error"
                self.inv["error"] = f"{type(e).__name__}: {e}"
            finally:
                self.sso.drop_secrets()
                if self.context is not None:
                    try:
                        await self._scrub_canaries()
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        await browser_confirm._save_session(self.context, self.session_file)
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        # the guarantee: whatever the in-browser scrub missed is removed from the file
                        self.inv["dom_canary_saved_scrubbed"] = _scrub_saved_session(
                            self.session_file, self.recorder.issued_dom_tokens())
                    except Exception as e:  # noqa: BLE001 -- never a value in the error
                        self.inv["dom_canary_saved_scrub_error"] = type(e).__name__
                await self.browser.close()
        return self.inv

    async def after_map(self) -> None:
        """Pass 2 hook: runs after the map with the browser still open."""

    # -- spec 2: the repeat and discovery (map mode only) ------------------------
    async def _request_context(self, with_cookies: bool):
        """A separate request context: its Set-Cookie never reaches the walk's
        cookie jar (decision 5); through the Burp mirror when it is active."""
        kw = {"ignore_https_errors": self.mirror_active}
        if self.mirror_active and self.proxy:
            kw["proxy"] = {"server": self.proxy}
        if with_cookies:
            kw["storage_state"] = await self.context.storage_state()
        return await self._pw.request.new_context(**kw)

    def _repeat_url_ok(self, url: str) -> bool:
        return (isinstance(url, str) and self.scope(url) and not L.is_mutating_get_url(url)
                and not S.is_callback_url(url))

    async def _run_sso_repeats(self) -> None:
        if self.mode != "map":
            return
        saved, self.cur_page = self.cur_page, None   # repeat edges/events belong to no page
        try:
            for key, src in self.sso.pending_repeats():
                if self.sso.data["repeats"] >= MAX_SSO_REPEATS:
                    break
                flow = self.sso.flow(key) or {}
                kind = src.get("kind")
                if kind != "a" and not flow.get("idp_in_scope"):
                    # an out-of-scope IdP: only the no-follow GET may run (no extra GET there)
                    self.sso.finish_repeat(key, None, kind, result="skipped-out-of-scope-idp")
                    continue
                second = None
                try:
                    if kind == "a":
                        second = await self._repeat_no_follow(src.get("url"))
                    elif kind in ("b", "c"):
                        second = await self._repeat_on_page(key, src, click=kind == "c")
                except _Stop:
                    raise
                except Exception:  # noqa: BLE001 -- never a value in the record
                    second = None
                if second is not None and S.flow_key(second) != key:
                    second = None
                self.sso.finish_repeat(key, second, kind)
        finally:
            self.cur_page = saved

    async def _repeat_no_follow(self, url: str) -> str | None:
        if not self._repeat_url_ok(url):
            return None
        await self._budget()
        self.sso.data["repeats"] += 1
        ctx = await self._request_context(with_cookies=True)
        try:
            resp = await ctx.get(url, max_redirects=0, timeout=_SSO_REQUEST_TIMEOUT_MS, fail_on_status_code=False)
            loc = resp.headers.get("location")
        finally:
            await ctx.dispose()
        return urljoin(url, loc) if loc else None

    async def _repeat_on_page(self, key: str, src: dict, *, click: bool) -> str | None:
        page_url, sig = src.get("page"), src.get("control_signature")
        if not page_url or not sig or not self._repeat_url_ok(page_url):
            return None
        await self._budget()
        self.sso.data["repeats"] += 1
        page = self.page
        await page.goto(page_url, wait_until="domcontentloaded")
        if not self.scope(page.url):
            return None
        await self._settle(page)
        tmpl = endpoint_template(page_url)
        for frame, d in await self._snapshot(page):
            for c in d["controls"]:
                if L.control_signature(c, tmpl) != sig:
                    continue
                if not click:
                    return c.get("href") or None
                self.sso.expect_authorize(key)
                try:
                    await frame.locator(f'[data-hm-idx="{c["idx"]}"]').first.click(timeout=_CLICK_TIMEOUT_MS)
                    await self._settle(page)
                finally:
                    self.sso.expect_authorize(None)
                return self.sso.take_second(key)
        return None

    async def _run_sso_discovery(self) -> None:
        if self.mode != "map":
            return
        for netloc in list(self.sso.data["idp_hosts"])[:MAX_DISCOVERY_HOSTS]:
            authz = self.sso.authorize_url_for(netloc)
            if not authz:
                continue
            origin = f"{urlsplit(authz).scheme}://{netloc}"
            urls = S.discovery_urls(authz) + [origin + "/.well-known/oauth-authorization-server"]
            page = self.sso.page_for_host(netloc)
            for u in urls[:MAX_DISCOVERY_GETS_PER_HOST]:
                if not self.scope(u):
                    continue
                status, parsed = await self._discovery_get(u)
                self.sso.record_discovery(netloc, u, status, parsed, page=page)
                if parsed is not None:
                    break

    async def _discovery_get(self, url: str) -> tuple[int | None, dict | None]:
        await self._budget()
        self.sso.data["discovery_gets"] += 1
        ctx = await self._request_context(with_cookies=False)
        try:
            resp = await ctx.get(url, max_redirects=0, timeout=_SSO_REQUEST_TIMEOUT_MS, fail_on_status_code=False)
            if resp.status != 200:
                return resp.status, None
            try:
                if int(resp.headers.get("content-length") or 0) > S._DISCOVERY_MAX_BYTES:
                    return resp.status, None
            except ValueError:
                pass
            return resp.status, S.parse_discovery(await resp.body(), scope=self.scope)
        except Exception:  # noqa: BLE001 -- network failure: recorded as no status
            return None, None
        finally:
            await ctx.dispose()


def _default_delay() -> float:
    try:
        import scope_guard

        return float(scope_guard.load_engagement().min_request_interval_s or 0.0)
    except Exception:  # noqa: BLE001 -- no engagement: no forced delay (scope+budget still apply)
        return 0.0


async def walk(start_url: str, mode: str = "map", **kw) -> dict:
    """Walk the app from start_url (see _walk for the parameters). The returned
    inventory never holds an OAuth/OIDC/SAML secret value: every URL in it is
    passed through ui_walk_sso_logic.redact_sso_params (spec 2, decision 1).
    Raw URLs exist only in memory while the walk runs."""
    return S.redact_urls_deep(await _walk(start_url, mode, **kw))


async def _walk(start_url: str, mode: str = "map", *, session_file: str | None = None,
               cookie_header: str | None = None, bearer_token: str | None = None,
               local_storage: dict | None = None, session_storage: dict | None = None,
               max_pages: int = 50, max_clicks_per_page: int = 40, same_origin_only: bool = True,
               wall_clock_s: int = 1200, scope_check: Callable[[str], bool] | None = None,
               grant=None, walk_id: str | None = None, action_delay_s: float | None = None,
               screenshot_dir: str | None = None, upstream_proxy: str = "") -> dict:
    """Walk the app from start_url. Returns the inventory dict (schema_version 2);
    never raises for target-side failures (status/error carry them).

    upstream_proxy: the Burp mirror ("" = HUNTMCP_UPSTREAM_PROXY, else auto:
    mirror only if a listener on 127.0.0.1:HUNTMCP_BURP_AUTO_PORT (8080) is
    Burp Suite; "off" = off even when the env var is set). Loopback http only."""
    scope = scope_check or L._default_scope_check
    walk_id = walk_id or uuid.uuid4().hex[:12]
    start = time.monotonic()
    auth = {"session_file": session_file, "cookie_header": cookie_header, "bearer_token": bearer_token,
            "local_storage": local_storage, "session_storage": session_storage}
    if mode not in ("map", "canary"):
        return _refused(start_url, mode, walk_id, f"unknown mode {mode!r}; expected 'map' or 'canary'")
    if not scope(start_url):
        return _refused(start_url, mode, walk_id, "start URL is out of scope")
    proxy, mirror_err = resolve_mirror(upstream_proxy)
    if mirror_err:
        inv = _refused(start_url, mode, walk_id, mirror_err)
        inv["burp_mirror"]["requested"] = True
        return inv
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
    await w.setup_mirror(proxy)
    inv = await w.run(**auth)
    browser_confirm._log_call("browser-mcp:ui-walk", [S.redact_sso_params(start_url), mode, walk_id],
                              returncode=0 if inv["status"] == "complete" else 1,
                              duration_ms=(time.monotonic() - start) * 1000, block=None)
    return inv


def _refused(start_url: str, mode: str, walk_id: str, why: str) -> dict:
    return {"schema_version": SCHEMA_VERSION, "walk_id": walk_id, "start_url": start_url, "mode": mode,
            "status": "refused", "error": why, "honest_limits": list(HONEST_LIMITS), "pages": [],
            "real_submits": [], "canaries": [], "sinks": [], "candidates": [],
            "pass2_events": [], "burp_mirror": _mirror_status(),
            "sso": ui_walk_sso.SsoTracker(lambda _u: False).data}
