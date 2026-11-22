"""#164 UI-walk event recorder (network side): produces the per-page `events`
list described by the contract in ui_walk_events_logic.py.

Events recorded here: redirect, set_cookie, headers, websocket, console, and
(via the init script + binding) postmessage, js_cookie, indexeddb, window_open,
service_worker, plus per-click storage diffs.
HARD RULES: no cookie / storage / WebSocket payload VALUE is ever stored
(Set-Cookie lines are parsed immediately and the raw string dropped; WS frames
keep opcode, size and top-level JSON key names only). Console text goes
through redact.redact_text and is cut to 300 chars. A recorder failure must
never crash or alter the walk: every handler swallows its own errors.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
import sys
import time
from collections.abc import Callable
from urllib.parse import parse_qsl, urldefrag, urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import ui_walk_events_logic as EL
import ui_walk_logic as L
from redact import redact_text

MAX_EVENTS_PER_PAGE = 300
MAX_EVENTS_PER_WALK = 2000
MAX_CONSOLE_PER_PAGE = 20
MAX_DRAIN_TOTAL_S = 30.0          # total in-flight drain time per walk
MIN_WALL_CLOCK_FOR_DRAIN_S = 10.0  # no drain when the walk is nearly out of time
MAX_CONSOLE_CHARS = 300
MAX_REDIRECT_HOPS = 10
_HEADER_TYPES = ("document", "xhr", "fetch")
_DRAIN_TIMEOUT_S = 3.0

# Task 4: DOM-XSS sources/sinks + postMessage probe.
DOM_TOKEN_LEN = 12                 # "hm" + 10 hex: distinct from Pass 2's 10-char form tokens
DOM_TOKEN_RE = re.compile(r"hm[0-9a-f]{10}(?![0-9a-f])")
DOM_SINKS = frozenset({"innerHTML", "outerHTML", "shadowRoot.innerHTML", "insertAdjacentHTML",
                       "document.write", "document.writeln", "document.cookie", "Function",
                       "setTimeout", "setInterval",
                       "script.src", "iframe.src", "iframe.srcdoc", "a.href"})
PROBE_BASELINE_S = 0.5             # quiet period before the synthetic message (noise baseline)
PROBE_WATCH_S = 1.5                # reaction window after it
PLANT_WAIT_S = 0.4                 # after a plant: let sinks run and a dialog arrive
_CTL_TIMEOUT_S = 5.0
_MAX_DOM_TOKENS = 2000             # per walk (3 per page at most)


# In-page recorder, installed with context.add_init_script in every frame.
# Every wrapper: own try/catch, always calls through to the original (except
# serviceWorker.register, which must stay blocked), and masks itself in
# Function.prototype.toString. No secret value leaves the page: postMessage
# data -> shape only; the document.cookie VALUE is dropped in the browser.
INIT_JS = r"""
(() => {
  const BINDING = "__HM_BINDING__", NONCE = "__HM_NONCE__";
  try {
    if (window.__hmInstalled) return;
    Object.defineProperty(window, '__hmInstalled', {value: true});
    const nativeToString = Function.prototype.toString;
    const masks = new WeakMap();
    const patchedToString = function toString() {
      const o = masks.get(this);
      return nativeToString.call(o !== undefined ? o : this);
    };
    masks.set(patchedToString, nativeToString);
    Object.defineProperty(Function.prototype, 'toString',
      {value: patchedToString, writable: true, configurable: true});
    const mask = (fn, orig, name) => {
      masks.set(fn, orig);
      try { Object.defineProperty(fn, 'name', {value: name, configurable: true}); } catch (e) {}
      try { Object.defineProperty(fn, 'length', {value: orig.length, configurable: true}); } catch (e) {}
      return fn;
    };
    const wrap = (obj, name, make) => {
      try {
        const d = Object.getOwnPropertyDescriptor(obj, name);
        if (!d || typeof d.value !== 'function') return;
        const orig = d.value;
        d.value = mask(make(orig), orig, name);
        Object.defineProperty(obj, name, d);
      } catch (e) {}
    };
    // Captured now: a page that later replaces window[BINDING] cannot intercept
    // or redirect real events, and cannot read NONCE (closure only).
    const bind = window[BINDING];
    const jstr = JSON.stringify;
    let sent = 0, dropped = 0, reported = 0, flushT = null;
    const send = o => {
      try {
        if (typeof bind !== 'function') return;
        // The nonce is only ever concatenated into the final string: it never
        // sits on an object, so Object.prototype setters / toJSON hooks cannot see it.
        const p = bind(NONCE + '|' + jstr(o));
        if (p && typeof p.catch === 'function') p.catch(() => {});
      } catch (e) {}
    };
    const flush = () => {
      flushT = null;
      if (dropped > reported) { const d = dropped - reported; reported = dropped; send({k: 'ovf', c: d}); }
    };
    const emit = o => {
      try {
        if (sent >= 80) {
          dropped++;
          if (flushT === null) flushT = setTimeout(flush, 100);
          return;
        }
        sent++;
        send(o);
      } catch (e) {}
    };
    window.addEventListener('pagehide', flush);
    const clean = u => {
      try {
        const x = new URL(String(u), document.baseURI);
        return /^https?:$/.test(x.protocol) ? x.origin + x.pathname : x.protocol;
      } catch (e) { return ''; }
    };
    const abs = u => { try { return new URL(String(u), document.baseURI).href; } catch (e) { return String(u); } };
    const shape = d => {
      try {
        if (d === null || d === undefined) return {type: 'null', keys: [], length: 0};
        if (Array.isArray(d)) return {type: 'array', keys: [], length: d.length};
        const t = typeof d;
        if (t === 'string') return {type: 'string', keys: [], length: d.length};
        if (t === 'object') {
          const ks = Object.keys(d);
          return {type: 'object', keys: ks.slice().sort().slice(0, 30).map(k => String(k).slice(0, 100)), length: ks.length};
        }
        return {type: t, keys: [], length: 0};
      } catch (e) { return null; }
    };

    // Task 4 builtins, captured before any wrapper below and before page scripts.
    const apply = Reflect.apply, sIdx = String.prototype.indexOf, sSlice = String.prototype.slice,
          sSplit = String.prototype.split, reExec = RegExp.prototype.exec, Str = String, ErrC = Error,
          Prom = Promise, sTO = window.setTimeout, MO = window.MutationObserver,
          ME = window.MessageEvent, HCE = window.HashChangeEvent,
          dispatch = EventTarget.prototype.dispatchEvent,
          origAEL = EventTarget.prototype.addEventListener,
          origREL = EventTarget.prototype.removeEventListener;
    const moObserve = MO && MO.prototype.observe, moTake = MO && MO.prototype.takeRecords,
          moDisc = MO && MO.prototype.disconnect;
    const SP = window.Storage && Storage.prototype;
    const stKey = SP && SP.key, stGet = SP && SP.getItem, stRem = SP && SP.removeItem,
          stLen = SP && (Object.getOwnPropertyDescriptor(SP, 'length') || {}).get;

    // postMessage (send)
    wrap(window, 'postMessage', orig => function postMessage(...a) {
      try {
        let t = a[1];
        if (t && typeof t === 'object') t = t.targetOrigin;
        emit({k: 'pm_send', t: t === undefined || t === null ? null : String(t).slice(0, 200), s: shape(a[0])});
      } catch (e) {}
      return orig.apply(this, a);
    });
    // message listeners (hidden per-frame registry, for the Task 4 probe)
    const reg = {count: 0, fns: []};
    try { Object.defineProperty(window, '__hmMsg', {value: reg, enumerable: false}); } catch (e) {}
    wrap(EventTarget.prototype, 'addEventListener', orig => function addEventListener(...a) {
      try {
        if (a[0] === 'message' && this === window) {
          reg.count++;
          if (reg.fns.length < 20 && typeof a[1] === 'function') reg.fns.push(a[1]);
          emit({k: 'pm_listen', n: reg.count});
        }
      } catch (e) {}
      return orig.apply(this, a);
    });

    // document.cookie setter: the VALUE is dropped here, only name + attributes go out
    try {
      const d = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
      if (d && typeof d.set === 'function') {
        const os = d.set;
        const ns = function (v) {
          try {
            const s = String(v), i = s.indexOf(';');
            const first = i < 0 ? s : s.slice(0, i), rest = i < 0 ? '' : s.slice(i);
            const eq = first.indexOf('=');
            emit({k: 'cookie', raw: (eq < 0 ? '' : first.slice(0, eq)).slice(0, 200) + '=' + rest.slice(0, 500)});
            report('document.cookie', v);   // Task 4 sink; defined below, runs only after init
          } catch (e) {}
          return os.call(this, v);
        };
        mask(ns, os, 'set cookie');
        Object.defineProperty(Document.prototype, 'cookie',
          {get: d.get, set: ns, enumerable: d.enumerable, configurable: true});
      }
    } catch (e) {}

    // IndexedDB
    if (window.IDBFactory) wrap(IDBFactory.prototype, 'open', orig => function open(...a) {
      const r = orig.apply(this, a);
      try {
        const name = String(a[0]).slice(0, 100);
        r.addEventListener('success', () => {
          try { emit({k: 'idb', db: name, stores: Array.from(r.result.objectStoreNames).slice(0, 30).map(x => String(x).slice(0, 100))}); } catch (e) {}
        });
      } catch (e) {}
      return r;
    });
    if (window.IDBDatabase) wrap(IDBDatabase.prototype, 'createObjectStore', orig => function createObjectStore(...a) {
      const r = orig.apply(this, a);
      try { emit({k: 'idb', db: String(this.name).slice(0, 100), stores: Array.from(this.objectStoreNames).slice(0, 30).map(x => String(x).slice(0, 100))}); } catch (e) {}
      return r;
    });

    // window.open + anchor _blank scan
    wrap(window, 'open', orig => function open(...a) {
      try {
        const f = typeof a[2] === 'string' ? a[2] : '';
        emit({k: 'wopen', url: clean(a[0] === undefined ? '' : a[0]).slice(0, 500), noopener: /\bno(opener|referrer)\b/i.test(f)});
      } catch (e) {}
      return orig.apply(this, a);
    });
    const seenBlank = new Set();
    const scanBlank = () => {
      try {
        document.querySelectorAll('a[target="_blank" i]').forEach(a => {
          const href = a.href;
          if (!href || seenBlank.has(href)) return;
          seenBlank.add(href);
          const rel = (a.getAttribute('rel') || '').toLowerCase().split(/\s+/);
          emit({k: 'anchor', url: clean(href).slice(0, 500), noopener: rel.includes('noopener') || rel.includes('noreferrer')});
        });
      } catch (e) {}
    };
    document.addEventListener('DOMContentLoaded', scanBlank);
    window.addEventListener('load', () => { scanBlank(); setTimeout(scanBlank, 500); });

    // service worker: record, keep registration blocked
    const mkRegister = orig => function register(...a) {
      try {
        const o = a[1];
        emit({k: 'sw', script: clean(a[0]).slice(0, 500), scope: o && o.scope ? clean(o.scope).slice(0, 500) : null});
      } catch (e) {}
      return Promise.reject(new DOMException('Service worker registration is blocked', 'SecurityError'));
    };
    if (window.ServiceWorkerContainer) wrap(ServiceWorkerContainer.prototype, 'register', mkRegister);
    // Playwright's service_workers="block" shadows register with an own property
    // on the container instance; wrap that one too.
    try { if (navigator.serviceWorker) wrap(navigator.serviceWorker, 'register', mkRegister); } catch (e) {}

    // ---- Task 4: DOM-XSS sink hooks. A wrapper reports only when a STRING it is
    // given carries a walker DOM token (hm + 10 hex; Python drops tokens it did not
    // issue), never converts a value itself (no page toString side effects), and
    // always calls the original with the same arguments.
    const TOK_RE = /hm[0-9a-f]{10}(?![0-9a-f])/;
    const FRAME_RE = /(https?:\/\/\S+?):(\d+):\d+\)?\s*$/;
    let planting = false;            // the walker's own source writes are never sink reports
    const seenSink = Object.create(null);
    let seenN = 0;
    const where = () => {
      try {
        const lines = apply(sSplit, Str(new ErrC().stack || ''), ['\n']);
        for (let i = 1; i < lines.length && i < 15; i++) {
          const m = apply(reExec, FRAME_RE, [lines[i]]);
          if (m) return [m[1], +m[2]];
        }
      } catch (e) {}
      return ['', null];
    };
    const report = (sink, v) => {
      try {
        if (planting || typeof v !== 'string') return;
        const m = apply(reExec, TOK_RE, [v]);
        if (!m) return;
        const key = m[0] + '|' + sink;
        if (seenSink[key] || seenN >= 50) return;
        seenSink[key] = 1; seenN++;
        const w = where();
        emit({k: 'sink', sink: sink, tok: m[0], su: apply(sSlice, w[0], [0, 500]), ln: w[1]});
      } catch (e) {}
    };
    const wrapSet = (proto, prop, sink) => {
      try {
        if (!proto) return;
        const d = Object.getOwnPropertyDescriptor(proto, prop);
        if (!d || typeof d.set !== 'function') return;
        const os = d.set;
        const ns = function (v) { report(sink, v); return apply(os, this, [v]); };
        mask(ns, os, 'set ' + prop);
        Object.defineProperty(proto, prop, {get: d.get, set: ns, enumerable: d.enumerable, configurable: true});
      } catch (e) {}
    };
    const wrapM = (obj, name, sink, argIdx) => wrap(obj, name, orig => function (...a) {
      if (argIdx < 0) { for (let i = 0; i < a.length; i++) report(sink, a[i]); } else report(sink, a[argIdx]);
      return apply(orig, this, a);
    });
    wrapSet(Element.prototype, 'innerHTML', 'innerHTML');
    wrapSet(Element.prototype, 'outerHTML', 'outerHTML');
    if (window.ShadowRoot) wrapSet(ShadowRoot.prototype, 'innerHTML', 'shadowRoot.innerHTML');
    wrapM(Element.prototype, 'insertAdjacentHTML', 'insertAdjacentHTML', 1);
    wrapM(Document.prototype, 'write', 'document.write', -1);
    wrapM(Document.prototype, 'writeln', 'document.writeln', -1);
    wrapM(window, 'setTimeout', 'setTimeout', 0);     // only the string form can match
    wrapM(window, 'setInterval', 'setInterval', 0);
    if (window.HTMLScriptElement) wrapSet(HTMLScriptElement.prototype, 'src', 'script.src');
    if (window.HTMLIFrameElement) {
      wrapSet(HTMLIFrameElement.prototype, 'src', 'iframe.src');
      wrapSet(HTMLIFrameElement.prototype, 'srcdoc', 'iframe.srcdoc');
    }
    if (window.HTMLAnchorElement) wrapSet(HTMLAnchorElement.prototype, 'href', 'a.href');
    // Function(...): a Proxy keeps every identity check (f.constructor === Function,
    // instanceof, prototype, subclassing, name/length); Function bodies always run
    // in global scope, so unlike eval nothing about the call changes.
    try {
      const OF = Function, PX = window.Proxy, rc = Reflect.construct;
      const fd = Object.getOwnPropertyDescriptor(window, 'Function');
      const cd = Object.getOwnPropertyDescriptor(OF.prototype, 'constructor');
      if (PX && fd && cd && fd.configurable && cd.configurable) {
        const rep = a => { for (let i = 0; i < a.length; i++) report('Function', a[i]); };
        const h = Object.create(null);    // no prototype: page Object.prototype traps never apply
        h.apply = (t, th, a) => { rep(a); return apply(t, th, a); };
        h.construct = (t, a, nt) => { rep(a); return rc(t, a, nt); };
        const pf = new PX(OF, h);
        masks.set(pf, OF);
        Object.defineProperty(window, 'Function', {value: pf, writable: fd.writable,
                                                   enumerable: fd.enumerable, configurable: true});
        Object.defineProperty(OF.prototype, 'constructor', {value: pf, writable: cd.writable,
                                                            enumerable: cd.enumerable, configurable: true});
      }
    } catch (e) {}

    // window.name: note whether the PAGE reads it (the walker plants it, with a
    // reload, only where it does).
    let nameRead = false, nameGet = null, nameSet = null;
    try {
      const nd = Object.getOwnPropertyDescriptor(window, 'name');
      if (nd && typeof nd.get === 'function' && typeof nd.set === 'function' && nd.configurable) {
        nameGet = nd.get; nameSet = nd.set;
        const ng = function () { if (!planting) nameRead = true; return apply(nameGet, this, []); };
        mask(ng, nameGet, 'get name');
        Object.defineProperty(window, 'name', {get: ng, set: nd.set, enumerable: nd.enumerable, configurable: true});
      }
    } catch (e) {}

    // Walker control (hidden, non-writable, key-checked): source planting and the
    // postMessage probe run here so they use the builtins captured above.
    const CTL = "__HM_CTL__", KEY = "__HM_KEY__";
    const listeners = () => reg.count + (typeof window.onmessage === 'function' ? 1 : 0);
    const plantHash = p => new Prom(res => {
      let fired = false;
      const on = () => { fired = true; };
      try {
        const h = Str(location.hash);
        const routed = apply(sIdx, h, ['#/']) === 0 || apply(sIdx, h, ['#!']) === 0;
        const nh = routed ? h + (apply(sIdx, h, ['?']) >= 0 ? '&' : '?') + 'hm=' + p : '#hm=' + p;
        const old = location.href;
        apply(origAEL, window, ['hashchange', on]);
        planting = true;
        try { location.hash = nh; } finally { planting = false; }   // fragment only: no request
        apply(sTO, window, [() => {
          try {
            apply(origREL, window, ['hashchange', on]);
            if (!fired) apply(dispatch, window, [new HCE('hashchange', {oldURL: old, newURL: location.href})]);
          } catch (e) {}
          res({routed: routed, fired: fired});
        }, 150]);
      } catch (e) { planting = false; res(null); }
    });
    let mo = null, moBase = 0, moAfter = 0, moPhase = 0, fireHref = '';
    const ctl = function (key, cmd, arg) {
      try {
        if (!KEY || key !== KEY) return null;
        if (cmd === 'state') return {nameRead: nameRead, listeners: listeners()};
        if (cmd === 'name') {   // returns the previous value so the walker can restore it
          if (!nameSet) return null;
          planting = true;
          try { const old = apply(nameGet, window, []); apply(nameSet, window, [Str(arg)]); return old; }
          finally { planting = false; }
        }
        if (cmd === 'hash') return plantHash(Str(arg));
        if (cmd === 'scrub') {   // drop storage entries carrying a walker token; values never leave
          if (!SP || !Array.isArray(arg)) return 0;
          let n = 0;
          const has = v => {
            if (!apply(reExec, TOK_RE, [v])) return false;
            for (let j = 0; j < arg.length; j++) if (apply(sIdx, v, [Str(arg[j])]) >= 0) return true;
            return false;
          };
          const stores = [];
          try { stores.push(window.localStorage); } catch (e) {}
          try { stores.push(window.sessionStorage); } catch (e) {}
          for (let si = 0; si < stores.length; si++) {
            try {
              const s = stores[si], dead = [];
              const len = apply(stLen, s, []);
              for (let i = 0; i < len; i++) {
                const k = apply(stKey, s, [i]);
                if (k !== null && has(Str(apply(stGet, s, [k])))) dead.push(k);
              }
              for (let i = 0; i < dead.length; i++) { apply(stRem, s, [dead[i]]); n++; }
            } catch (e) {}
          }
          return n;
        }
        if (cmd === 'arm') {
          const n = listeners();
          if (!n || !MO) return {listeners: 0};
          if (mo) apply(moDisc, mo, []);
          moBase = 0; moAfter = 0; moPhase = 0;
          mo = new MO(rs => { if (moPhase === 0) moBase += rs.length; else moAfter += rs.length; });
          apply(moObserve, mo, [document, {subtree: true, childList: true, attributes: true, characterData: true}]);
          return {listeners: n};
        }
        if (cmd === 'fire') {
          if (!mo) return null;
          moBase += apply(moTake, mo, []).length; moPhase = 1; fireHref = location.href;
          apply(dispatch, window, [new ME('message', {data: arg, origin: 'https://hm-probe.invalid'})]);
          return {sync: apply(moTake, mo, []).length};
        }
        if (cmd === 'done') {
          if (!mo) return null;
          moAfter += apply(moTake, mo, []).length; apply(moDisc, mo, []); mo = null;
          return {after: moAfter, base: moBase, moved: location.href !== fireHref};
        }
      } catch (e) {}
      return null;
    };
    if (CTL) { try { Object.defineProperty(window, CTL, {value: ctl}); } catch (e) {} }
  } catch (e) {}
})();
"""
_CTL_JS = "([n, k, c, a]) => { const f = window[n]; return typeof f === 'function' ? f(k, c, a) : null; }"
_CTL_ERR = object()   # sentinel: the control call failed (context destroyed, timeout, ...)
_STACK_URL_RE = re.compile(r"(https?://[^\s()]+?):\d+:\d+")

# Storage snapshot: {origin, keys: {key: fnv1a-hash-of-value}}; values never leave the page.
SNAPSHOT_JS = r"""
() => {
  const fnv = s => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; } return h.toString(16); };
  const m = new Map();
  for (const st of ['localStorage', 'sessionStorage']) {
    try {
      const s = window[st];
      for (let i = 0; i < s.length && m.size < 300; i++) {
        const k = s.key(i);
        if (k === null) continue;
        const h = fnv(String(s.getItem(k)));
        m.set(k, m.has(k) ? m.get(k) + '/' + h : h);
      }
    } catch (e) {}
  }
  return {origin: location.origin, keys: Object.fromEntries(m)};
}
"""
_SNAPSHOT_BUDGET_S = 3.0           # total per snapshot_storage call, across all frames


def build_init_js(binding: str, nonce: str, *, ctl: str = "", key: str = "") -> str:
    """INIT_JS with this walk's random binding name, nonce, and (Task 4) the hidden
    control function's name and key templated in. Without a key the control
    function is not installed."""
    return (INIT_JS.replace("__HM_BINDING__", binding).replace("__HM_NONCE__", nonce)
            .replace("__HM_CTL__", ctl).replace("__HM_KEY__", key))


def _clean_url(u) -> str:
    """scheme://host/path only: query and fragment can carry token values."""
    try:
        p = urlsplit(u if isinstance(u, str) else "")
    except ValueError:
        return ""
    if p.scheme in ("http", "https") and p.netloc:
        return f"{p.scheme}://{p.netloc}{p.path}"
    return f"{p.scheme}:" if p.scheme else ""


def _strip_url(u) -> tuple[str, list[str]]:
    """Ruling R4: scheme://host/path plus the sorted query parameter NAMES. Query
    values (OAuth code/state, tokens) and the fragment never leave this call."""
    clean = _clean_url(u)
    try:
        q = urlsplit(u if isinstance(u, str) else "").query
        keys = sorted({str(k)[:100] for k, _ in parse_qsl(q, keep_blank_values=True)})[:30]
    except ValueError:
        keys = []
    return clean, keys


def _origin(url: str) -> str:
    try:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""
    except ValueError:
        return ""


def ws_frame_event(url: str, message) -> dict:
    """Metadata of one client->server WebSocket frame. Never the payload."""
    import json

    is_text = isinstance(message, str)
    keys: list[str] = []
    if is_text:
        try:
            obj = json.loads(message)
            if isinstance(obj, dict):
                keys = sorted(str(k) for k in obj)[:30]
        except ValueError:
            pass
    try:
        p = urlsplit(url or "")
        clean = f"{p.scheme}://{p.netloc}{p.path}"  # no query/fragment: may carry tokens
        qkeys = sorted({str(k)[:100] for k, _ in parse_qsl(p.query, keep_blank_values=True)})[:30]
    except ValueError:
        clean, qkeys = "", []
    return {"type": "websocket", "direction": "client", "opcode": 1 if is_text else 2,
            "size": len(message), "json_keys": keys, "url": clean, "query_keys": qkeys,
            "frame_origin": _origin(clean)}


class Recorder:
    def __init__(self) -> None:
        self._rec: dict | None = None
        self._t0 = time.monotonic()
        self._control: str | None = None
        self._walk_total = 0
        self._scope: Callable[[str], bool] = lambda _u: False
        self._page = None
        self._cdp_ok = False
        self._pending: set = set()
        self._req_ctl: dict = {}
        self._cdp_reqs: dict = {}
        self._inflight: set = set()
        self._redirect_done: set = set()
        self._console_count = 0
        self._drain_spent = 0.0
        self.drains_skipped = 0
        self._bound_ctx: list = []
        self._nonce = secrets.token_hex(16)
        self._binding = "__hm" + secrets.token_hex(6)
        self.forged_dropped = 0
        self.snapshot_frames_skipped = 0
        # Task 4: hidden in-page control function + per-walk DOM canary registry
        self._ctl_name = "__hm" + secrets.token_hex(6)
        self._ctl_key = secrets.token_hex(16)
        self._dom_tokens: dict[str, dict] = {}   # token -> {"source", "rec"} (this walk only)
        self._executed: set[str] = set()         # tokens whose payload raised a dialog (this page)
        self._sink_seen: set = set()
        self._hit_done: set[str] = set()
        self._watch: dict | None = None          # postMessage probe reaction window
        self.on_dom_hit: Callable[[str, str, str], None] | None = None
        # spec 2: full hop URLs of each redirect chain (in memory, before R4 stripping)
        self.on_redirect_chain: Callable[[list[str], str | None, str], None] | None = None
        self.canary_cookies_cleared = 0
        self.canary_storage_cleared = 0

    # -- page lifecycle ---------------------------------------------------
    def begin_page(self, rec: dict) -> None:
        rec["events"] = []
        rec["events_dropped"] = 0
        self._rec = rec
        self._t0 = time.monotonic()
        self._req_ctl.clear()
        self._cdp_reqs.clear()
        self._inflight.clear()
        self._redirect_done.clear()
        self._console_count = 0
        self._executed = set()
        self._sink_seen = set()
        self._watch = None

    def drain_budget(self, remaining_s: float | None) -> float:
        """Seconds end_page may wait for in-flight requests: 0 when the walk's
        wall clock is nearly spent or the per-walk drain total is used up."""
        if remaining_s is not None and remaining_s <= MIN_WALL_CLOCK_FOR_DRAIN_S:
            return 0.0
        return max(0.0, min(_DRAIN_TIMEOUT_S, MAX_DRAIN_TOTAL_S - self._drain_spent))

    async def end_page(self, rec: dict, remaining_s: float | None = None) -> None:
        if self._rec is not rec:
            return
        # A response can land after the click's settle returned (the load state
        # is already "networkidle"): wait, bounded, for requests still in flight
        # so a delayed Set-Cookie is recorded against the click that caused it.
        budget = self.drain_budget(remaining_s)
        start = time.monotonic()
        deadline = start + budget
        if self._inflight and budget <= 0:
            self.drains_skipped += 1
        while self._inflight and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        self._drain_spent += time.monotonic() - start
        pending = [t for t in self._pending if not t.done()]
        if pending:
            try:
                await asyncio.wait(pending, timeout=max(0.1 if budget > 0 else 0.0, deadline - time.monotonic()))
            except Exception:  # noqa: BLE001
                pass
        self._finish_dom(rec)
        self._rec = None

    def set_control(self, sig: str | None) -> None:
        self._control = sig

    def record(self, event: dict) -> None:
        rec = self._rec
        if rec is None:
            return
        if len(rec["events"]) >= MAX_EVENTS_PER_PAGE or self._walk_total >= MAX_EVENTS_PER_WALK:
            rec["events_dropped"] += 1
            return
        if event.get("type") == "console":
            if self._console_count >= MAX_CONSOLE_PER_PAGE:
                rec["events_dropped"] += 1
                return
            self._console_count += 1
        event.setdefault("control_signature", self._control)
        event["t_ms"] = int((time.monotonic() - self._t0) * 1000)
        event.setdefault("frame_origin", "")
        rec["events"].append(event)
        self._walk_total += 1

    # -- attach -----------------------------------------------------------
    async def attach(self, context, page, *, scope: Callable[[str], bool]) -> None:
        self._scope = scope
        self._page = page
        self._cdp_ok = False
        self._pending = set()
        await self._install_init(context)
        try:
            context.on("request", self._safe(self._on_request))
            context.on("response", self._on_response_cb)
            context.on("requestfinished", self._safe(lambda r: self._inflight.discard(r)))
            context.on("requestfailed", self._safe(self._on_request_failed))
            page.on("console", self._safe(self._on_console))
            page.on("pageerror", self._safe(self._on_pageerror))
        except Exception:  # noqa: BLE001 -- recording is best-effort
            pass
        try:
            cdp = await context.new_cdp_session(page)
            cdp.on("Network.requestWillBeSent", self._safe(self._cdp_request))
            cdp.on("Network.responseReceivedExtraInfo", self._safe(self._cdp_extra))
            await cdp.send("Network.enable")
            self._cdp_ok = True
        except Exception:  # noqa: BLE001 -- fall back to Playwright response headers
            self._cdp_ok = False

    @staticmethod
    def _safe(fn):
        def wrapper(*a, **k):
            try:
                return fn(*a, **k)
            except Exception:  # noqa: BLE001
                return None
        return wrapper

    # -- Playwright side --------------------------------------------------
    def _on_request(self, req) -> None:
        self._req_ctl[req] = self._control
        self._inflight.add(req)
        w = self._watch
        if w is not None:
            try:
                fo = _origin(req.frame.url)
            except Exception:  # noqa: BLE001 -- service-worker request has no frame
                fo = ""
            try:
                nav = bool(req.is_navigation_request())
            except Exception:  # noqa: BLE001
                nav = False
            w["req"].append((w["phase"], fo, nav))

    def _control_for(self, req) -> str | None:
        r, found, hops = req, None, 0
        while r is not None and hops < 20:
            if r in self._req_ctl:
                found = self._req_ctl[r]
            r = r.redirected_from
            hops += 1
        return found if found is not None else self._control

    def _on_response_cb(self, resp) -> None:
        try:
            task = asyncio.ensure_future(self._on_response(resp))
        except Exception:  # noqa: BLE001
            return
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _on_response(self, resp) -> None:
        try:
            await self._handle_response(resp)
        except Exception:  # noqa: BLE001 -- page closed mid-read etc.
            pass

    async def _handle_response(self, resp) -> None:
        if self._rec is None:
            return
        req = resp.request
        url = resp.url
        ctl = self._control_for(req)
        rtype = req.resource_type
        try:
            frame_origin = _origin(req.frame.url) or _origin(url)
        except Exception:  # noqa: BLE001 -- service-worker request has no frame
            frame_origin = _origin(url)
        headers = {k.lower(): v for k, v in (await resp.all_headers()).items()}
        is_hop = 300 <= resp.status < 400 and bool(headers.get("location"))
        if req.redirected_from is not None and not is_hop:  # terminal response: one event per chain
            await self._record_redirect(req, resp, ctl, frame_origin)
        if rtype in _HEADER_TYPES:
            try:
                req_headers = await req.all_headers()
            except Exception:  # noqa: BLE001
                req_headers = req.headers
            origin = {k.lower(): v for k, v in req_headers.items()}.get("origin") or frame_origin
            clean, qkeys = _strip_url(url)
            ev = {"type": "headers", "control_signature": ctl, "frame_origin": frame_origin,
                  "url": clean, "query_keys": qkeys, "resource_type": rtype, "request_origin": origin}
            ev.update(EL.security_headers(headers))
            self.record(ev)
        if not self._cdp_ok:
            try:
                raw = "\n".join(h["value"] for h in await resp.headers_array()
                                if h["name"].lower() == "set-cookie")
            except Exception:  # noqa: BLE001
                raw = ""
            self._emit_cookies(raw, {}, url, ctl, frame_origin)

    async def _record_redirect(self, term_req, term_resp, ctl, frame_origin) -> None:
        """One redirect event per chain, keyed on the terminal request. The
        terminal hop has status None when it never got a response."""
        if term_req in self._redirect_done:
            return
        self._redirect_done.add(term_req)
        chain, r = [], term_req
        while r is not None and len(chain) < MAX_REDIRECT_HOPS:
            chain.insert(0, r)
            r = r.redirected_from
        hops, for_params = [], []
        for r in chain:
            rr = term_resp if r is term_req else await r.response()
            status = rr.status if rr is not None else None
            loc = ""
            if rr is not None and r is not term_req:
                loc = (await rr.header_value("location")) or ""
            clean, qkeys = _strip_url(r.url)
            hops.append({"url": clean, "query_keys": qkeys, "status": status,
                         "in_scope": bool(self._scope(r.url))})
            for_params.append({"url": r.url, "location": loc})
        hook = self.on_redirect_chain
        if hook is not None:
            try:
                hook([r.url for r in chain], ctl, term_req.resource_type)
            except Exception:  # noqa: BLE001 -- the SSO tracker never affects recording
                pass
        # param names are matched on the FULL URLs, in memory; only names are kept
        names = EL.redirect_param_names(for_params)
        del for_params
        self.record({"type": "redirect", "control_signature": ctl, "frame_origin": frame_origin,
                     "hops": hops, "param_names": names})

    def _on_request_failed(self, req) -> None:
        self._inflight.discard(req)
        if req.redirected_from is None:
            return
        try:
            task = asyncio.ensure_future(self._redirect_failed(req))
        except Exception:  # noqa: BLE001
            return
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _redirect_failed(self, req) -> None:
        try:
            if self._rec is None:
                return
            try:
                fo = _origin(req.frame.url) or _origin(req.url)
            except Exception:  # noqa: BLE001
                fo = _origin(req.url)
            await self._record_redirect(req, None, self._control_for(req), fo)
        except Exception:  # noqa: BLE001
            pass

    def _watch_console(self, origin: str) -> None:
        """Probe window: which frame origin logged the error (see _msg_origin)."""
        w = self._watch
        if w is not None:
            w["console"].append((w["phase"], origin))

    @staticmethod
    def _msg_origin(msg) -> str:
        """Origin of the script/document a console message came from (Playwright
        gives no frame for it). "" when unknown -- then it is never a reaction."""
        try:
            loc = msg.location
            return _origin((loc or {}).get("url") or "")
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _err_origin(err) -> str:
        """Origin of the first http(s) script frame in an uncaught error's stack."""
        try:
            m = _STACK_URL_RE.search(str(getattr(err, "stack", None) or ""))
            return _origin(m.group(1)) if m else ""
        except Exception:  # noqa: BLE001
            return ""

    def _on_console(self, msg) -> None:
        if msg.type != "error":
            return
        self._watch_console(self._msg_origin(msg))
        text = redact_text(msg.text or "")[:MAX_CONSOLE_CHARS]
        self.record({"type": "console", "level": "error", "text": text,
                     "frame_origin": _origin(self._page.url) if self._page else ""})

    def _on_pageerror(self, err) -> None:
        self._watch_console(self._err_origin(err))
        text = redact_text(getattr(err, "message", None) or str(err))[:MAX_CONSOLE_CHARS]
        self.record({"type": "console", "level": "pageerror", "text": text,
                     "frame_origin": _origin(self._page.url) if self._page else ""})

    # -- CDP side (Set-Cookie incl. HttpOnly + blocked reasons) -------------
    def _cdp_request(self, params: dict) -> None:
        rid = params.get("requestId")
        if rid is None:
            return
        ent = self._cdp_reqs.setdefault(rid, {"control": self._control, "urls": [], "infos": 0})
        ent["urls"].append((params.get("request") or {}).get("url") or "")

    def _cdp_extra(self, params: dict) -> None:
        if self._rec is None:
            return
        ent = self._cdp_reqs.get(params.get("requestId")) or {"control": self._control, "urls": [], "infos": 0}
        idx = ent["infos"]
        ent["infos"] += 1
        urls = ent["urls"]
        url = urls[min(idx, len(urls) - 1)] if urls else (self._page.url if self._page else "")
        headers = {str(k).lower(): v for k, v in (params.get("headers") or {}).items()}
        raw = headers.get("set-cookie") or ""
        blocked: dict[str, list[str]] = {}
        for b in params.get("blockedCookies") or []:
            name = ((b.get("cookie") or {}).get("name")
                    or (b.get("cookieLine") or "").split("=", 1)[0].strip())
            blocked.setdefault(name, []).extend(str(x) for x in b.get("blockedReasons") or [])
        self._emit_cookies(raw, blocked, url, ent["control"],
                           _origin(self._page.url) if self._page else _origin(url))

    def _emit_cookies(self, raw: str, blocked: dict, url: str, ctl, frame_origin: str) -> None:
        clean, qkeys = _strip_url(url)
        for c in EL.parse_set_cookie(raw):  # raw string is dropped right here
            ev = dict(c)
            ev.update({"type": "set_cookie", "control_signature": ctl, "frame_origin": frame_origin,
                       "url": clean, "query_keys": qkeys, "blocked": blocked.get(c["name"], [])})
            self.record(ev)

    # -- init-script events (postMessage, JS cookies, IndexedDB, window.open, SW) --
    async def _install_init(self, context) -> None:
        """Once per context (the walker re-opens the context on an auth retry)."""
        if any(c is context for c in self._bound_ctx):
            return
        self._bound_ctx.append(context)
        try:
            await context.expose_binding(self._binding, self._on_binding)
            await context.add_init_script(build_init_js(self._binding, self._nonce,
                                                        ctl=self._ctl_name, key=self._ctl_key))
        except Exception:  # noqa: BLE001 -- recording is best-effort
            pass

    def _on_binding(self, source, payload) -> None:
        """Never raises and never echoes the payload (the binding error path
        would otherwise carry it back into the page)."""
        try:
            self._handle_binding(source, payload)
        except Exception:  # noqa: BLE001
            pass
        return None

    @staticmethod
    def _s(v, n: int) -> str:
        return v[:n] if isinstance(v, str) else ""

    def _handle_binding(self, source, payload) -> None:
        if not isinstance(payload, str) or len(payload) > 8000:
            self.forged_dropped += 1
            return
        nonce, sep, body = payload.partition("|")
        o = None
        if sep and hmac.compare_digest(nonce.encode(), self._nonce.encode()):
            try:
                o = json.loads(body)
            except ValueError:
                o = None
        if not isinstance(o, dict):
            self.forged_dropped += 1   # page-originated call (or garbage): not from the init script
            return
        if o.get("k") == "ovf":
            c = o.get("c")
            if self._rec is not None and isinstance(c, int) and not isinstance(c, bool) and 0 < c <= 100000:
                self._rec["events_dropped"] += c
            return
        furl = source["frame"].url or ""
        fo = _origin(furl)
        k = o.get("k")
        ev: dict | None = None
        if k == "sink":
            sink, tok, ln = o.get("sink"), o.get("tok"), o.get("ln")
            # never record (or make a candidate) about a non-target frame
            if sink in DOM_SINKS and isinstance(tok, str) and self._scope(furl):
                line = ln if isinstance(ln, int) and not isinstance(ln, bool) else None
                self._record_sink(tok, sink, self._s(o.get("su"), 500), line, fo)
            return
        if k == "pm_send":
            t = o.get("t")
            shp = o.get("s")
            if isinstance(shp, dict):
                keys = [self._s(x, 100) for x in (shp.get("keys") or [])[:30] if isinstance(x, str)]
                ln = shp.get("length")
                shp = {"type": self._s(shp.get("type"), 20), "keys": keys,
                       "length": ln if isinstance(ln, int) and not isinstance(ln, bool) else 0}
            else:
                shp = None
            ev = {"type": "postmessage", "direction": "send",
                  "target_origin": t[:200] if isinstance(t, str) else None, "shape": shp}
        elif k == "pm_listen":
            n = o.get("n")
            ev = {"type": "postmessage", "direction": "listen", "target_origin": None, "shape": None,
                  "listeners": n if isinstance(n, int) and not isinstance(n, bool) else 1}
        elif k == "cookie":
            raw = self._s(o.get("raw"), 800)
            c = EL.parse_cookie_assignment(raw)
            del raw  # the assignment string is not kept
            try:
                p = urlsplit(furl)
                clean = f"{p.scheme}://{p.netloc}{p.path}"
            except ValueError:
                clean = ""
            ev = dict(c)
            ev.update({"type": "js_cookie", "url": clean})
        elif k == "idb":
            ev = {"type": "indexeddb", "db": self._s(o.get("db"), 100),
                  "stores": [self._s(x, 100) for x in (o.get("stores") or [])[:30] if isinstance(x, str)]}
        elif k in ("wopen", "anchor"):
            ev = {"type": "window_open", "url": _clean_url(self._s(o.get("url"), 500)),
                  "noopener": o.get("noopener") is True,
                  "via": "window.open" if k == "wopen" else "anchor"}
        elif k == "sw":
            sc = o.get("scope")
            ev = {"type": "service_worker", "script_url": _clean_url(self._s(o.get("script"), 500)),
                  "scope": _clean_url(sc[:500]) if isinstance(sc, str) else None}
        if ev is None:
            return
        if ev["type"] == "postmessage":
            ev["frame_in_scope"] = bool(self._scope(furl))
        ev["frame_origin"] = fo
        self.record(ev)

    # -- storage diff -------------------------------------------------------
    async def snapshot_storage(self, page) -> dict:
        """{origin: {key: fnv1a-hash}} over in-scope frames. Hashes are computed
        in the browser; values never reach Python. {} means 'could not read'."""
        out: dict = {}
        try:
            frames = list(page.frames)
        except Exception:  # noqa: BLE001
            return {}
        deadline = time.monotonic() + _SNAPSHOT_BUDGET_S
        for i, f in enumerate(frames):
            try:
                if not self._scope(f.url):
                    continue
                left = deadline - time.monotonic()
                if left <= 0:
                    self.snapshot_frames_skipped += 1   # budget spent: skip, never block the click
                    continue
                d = await asyncio.wait_for(f.evaluate(SNAPSHOT_JS), left)
                origin = d.get("origin")
                if not origin or origin == "null":
                    continue
                keys = out.setdefault(origin, {})
                for key, h in (d.get("keys") or {}).items():
                    keys[str(key)[:100]] = str(h)[:40]
            except Exception:  # noqa: BLE001
                continue
        return out

    def record_storage_diff(self, before: dict, after: dict, sig: str | None) -> None:
        """Skips the diff when either snapshot failed (an empty dict), so a
        failed read can never look like 'everything was added'."""
        try:
            if not before or not after:
                return
            for row in EL.storage_diff(before, after):
                self.record({"type": "storage", **row, "control_signature": sig,
                             "frame_origin": row["origin"]})
        except Exception:  # noqa: BLE001
            pass

    # -- Task 4: DOM-XSS sinks, zero-traffic sources, postMessage probe --------
    def new_dom_token(self, source: str, rec: dict) -> str | None:
        """A fresh DOM canary for one source on one page (None when the per-walk
        cap is reached). Tokens are only ever planted client-side."""
        if len(self._dom_tokens) >= _MAX_DOM_TOKENS:
            return None
        tok = L.make_canary(DOM_TOKEN_LEN)
        while tok in self._dom_tokens:
            tok = L.make_canary(DOM_TOKEN_LEN)
        self._dom_tokens[tok] = {"source": source, "rec": rec}
        return tok

    @staticmethod
    def dom_payload(tok: str) -> str:
        """The same payload form as Pass 2: token + an execution marker carrying it."""
        return L.canary_value(tok, "text", None)

    def _current(self, tok) -> dict | None:
        ent = self._dom_tokens.get(tok) if isinstance(tok, str) else None
        if ent is None or self._rec is None or ent["rec"] is not self._rec:
            return None   # never issued, or planted on another page: never attributed here
        return ent

    def _hit(self, tok: str, ent: dict) -> None:
        if tok in self._hit_done or self.on_dom_hit is None:
            return
        self._hit_done.add(tok)
        try:
            self.on_dom_hit(tok, ent["source"], (ent["rec"] or {}).get("url") or "")
        except Exception:  # noqa: BLE001 -- registry write failure never affects the walk
            pass

    def _record_sink(self, tok, sink: str, script_url: str, line, frame_origin: str,
                     extra: dict | None = None) -> None:
        try:
            ent = self._current(tok)
            if ent is None:
                return
            clean, qkeys = _strip_url(script_url)
            key = (tok, sink, clean, line)
            if key in self._sink_seen:
                return
            self._sink_seen.add(key)
            ev = {"type": "dom_sink", "source": ent["source"], "sink": sink,
                  "executed": tok in self._executed, "token": tok, "script_url": clean,
                  "query_keys": qkeys, "line": line, "frame_origin": frame_origin}
            ev.update(extra or {})
            self.record(ev)
            self._hit(tok, ent)
        except Exception:  # noqa: BLE001
            pass

    def note_dialog(self, message) -> None:
        """Execution marker: a dialog whose text IS exactly a DOM token planted on
        this page (the payload's alert('<token>')) marks that token's dom_sink
        events executed. A dialog that merely contains the token -- e.g. a page
        echoing the decoded payload in alert('Bad route: ' + hash) -- is not."""
        try:
            rec = self._rec
            if rec is None or not isinstance(message, str):
                return
            tok = message.strip()
            ent = self._current(tok) if DOM_TOKEN_RE.fullmatch(tok) else None
            if ent is None:
                return
            self._executed.add(tok)
            for ev in rec["events"]:
                if ev.get("type") == "dom_sink" and ev.get("token") == tok:
                    ev["executed"] = True
            self._hit(tok, ent)
        except Exception:  # noqa: BLE001
            pass

    def _finish_dom(self, rec: dict) -> None:
        """An executed token whose sink no hook saw (e.g. eval, javascript: URL)
        is still recorded, with sink "unknown"."""
        try:
            seen = {ev.get("token") for ev in rec.get("events") or [] if ev.get("type") == "dom_sink"}
            for tok in sorted(self._executed - seen):
                ent = self._dom_tokens.get(tok)
                if ent is None:
                    continue
                self.record({"type": "dom_sink", "source": ent["source"], "sink": "unknown",
                             "executed": True, "token": tok, "script_url": "", "query_keys": [],
                             "line": None, "frame_origin": _origin(rec.get("url") or "")})
        except Exception:  # noqa: BLE001
            pass

    def issued_dom_tokens(self) -> list[str]:
        """Every DOM canary this walk issued (for the post-save session scrub)."""
        return list(self._dom_tokens)

    def dom_token_in(self, *texts) -> str | None:
        """A walker DOM token (any page of this walk) inside a request's URL,
        body or header values: such a request must never reach the server."""
        for t in texts:
            if not isinstance(t, str) or "hm" not in t:
                continue
            for m in DOM_TOKEN_RE.findall(t):
                if m in self._dom_tokens:
                    return m
        return None

    def record_request_sink(self, tok: str, url: str, is_nav: bool, frame_origin: str) -> None:
        """The canary flowed into a navigation / request (location, fetch, img
        src...). The walker aborts that request; this records where it went."""
        clean, qkeys = _strip_url(url)
        self._record_sink(tok, "navigation" if is_nav else "request", "", None, frame_origin,
                          extra={"request_url": clean, "request_query_keys": qkeys})

    async def clear_canary_cookies(self, context) -> int:
        """Delete cookies whose value carries a walker DOM token (a page copied a
        planted source into document.cookie). Otherwise every later request would
        carry the canary and be aborted. Values are compared in memory only."""
        n = 0
        try:
            jar = await context.cookies()
            hits = [(c.get("name"), c.get("domain"), c.get("path")) for c in jar
                    if self.dom_token_in(c.get("value"))]
            del jar
            for name, domain, path in hits:
                await context.clear_cookies(name=name, domain=domain, path=path)
                n += 1
        except Exception:  # noqa: BLE001 -- the route check still blocks any request that carries one
            pass
        self.canary_cookies_cleared += n
        return n

    async def scrub_storage(self, page) -> int:
        """Remove every localStorage/sessionStorage entry (in-scope frames) whose
        value carries a walker DOM token, so no canary persists into a saved
        session file. The comparison runs in the browser; no value reaches Python."""
        if not self._dom_tokens or page is None:
            return 0
        toks = list(self._dom_tokens)
        n = 0
        try:
            frames = list(page.frames)
        except Exception:  # noqa: BLE001
            return 0
        for f in frames:
            try:
                if not self._scope(f.url):
                    continue
            except Exception:  # noqa: BLE001
                continue
            r = await self._ctl(f, "scrub", toks)
            if isinstance(r, int) and not isinstance(r, bool) and r > 0:
                n += r
        self.canary_storage_cleared += n
        return n

    async def _ctl(self, frame, cmd: str, arg=None, timeout: float = _CTL_TIMEOUT_S):
        try:
            return await asyncio.wait_for(
                frame.evaluate(_CTL_JS, [self._ctl_name, self._ctl_key, cmd, arg]), timeout)
        except Exception:  # noqa: BLE001 -- detached / navigated / no init script
            return _CTL_ERR

    async def _after_plant(self, page) -> None:
        try:
            await page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:  # noqa: BLE001 -- long-polling pages never go idle
            pass
        await asyncio.sleep(PLANT_WAIT_S)

    async def plant_sources(self, page, url: str, rec: dict, *, budget=None) -> dict:
        """Plant DOM canaries in sources that never reach the server: window.name
        (then ONE budget-charged GET reload of the same URL, only when the page
        read window.name) and the URL #hash (in-page, fragment only: no request).
        `budget` is the walker's per-page-load guard; its exception propagates."""
        src = {"hash": "skipped", "window.name": "skipped"}
        rec["dom_sources"] = src
        try:
            if not self._scope(page.url) or urldefrag(page.url)[0] != urldefrag(url)[0]:
                src.update({"hash": "not-on-page", "window.name": "not-on-page"})
                return src
            st = await self._ctl(page.main_frame, "state")
        except Exception:  # noqa: BLE001
            st = _CTL_ERR
        if not isinstance(st, dict):
            src.update({"hash": "unavailable", "window.name": "unavailable"})
            return src
        if st.get("nameRead") is not True:
            src["window.name"] = "not-read"
        else:
            tok = self.new_dom_token("window.name", rec)
            old = await self._ctl(page.main_frame, "name", self.dom_payload(tok)) if tok else _CTL_ERR
            if not isinstance(old, str):
                src["window.name"] = "failed"
            else:
                try:
                    if budget is not None:
                        await budget()
                    try:
                        await page.reload(wait_until="domcontentloaded")
                        if not self._scope(page.url):
                            await page.goto("about:blank")
                            src.update({"window.name": "left-scope", "hash": "left-scope"})
                            return src
                        await self._after_plant(page)
                        src["window.name"] = "planted"
                    except Exception:  # noqa: BLE001 -- reload failed: keep going with the hash
                        src["window.name"] = "failed"
                finally:
                    # the value is held only in this local, never stored
                    await self._ctl(page.main_frame, "name", old)
                    del old
        try:
            if not self._scope(page.url):
                src["hash"] = "left-scope"
                return src
            tok = self.new_dom_token("hash", rec)
            r = await self._ctl(page.main_frame, "hash", self.dom_payload(tok)) if tok else _CTL_ERR
            src["hash"] = "planted" if isinstance(r, dict) else "failed"
            await asyncio.sleep(PLANT_WAIT_S)
        except Exception:  # noqa: BLE001
            src["hash"] = "failed"
        return src

    def _probe_data(self, rec: dict, payload: str) -> dict:
        """Shaped like what the page itself posted (key names, all set to the
        payload), else {"type": payload}. Never a recorded value."""
        for ev in reversed(rec.get("events") or []):
            shp = ev.get("shape") if ev.get("type") == "postmessage" else None
            if ev.get("direction") == "send" and isinstance(shp, dict) and shp.get("type") == "object" \
                    and shp.get("keys"):
                return {str(k)[:100]: payload for k in shp["keys"][:10]}
        return {"type": payload}

    async def probe_postmessage(self, page, rec: dict) -> dict:
        """Dispatch one synthetic MessageEvent (origin https://hm-probe.invalid,
        browser-only) in every IN-SCOPE frame that registered a message listener
        and watch PROBE_WATCH_S for a reaction (DOM mutation, navigation,
        request, storage change, console error) against a PROBE_BASELINE_S quiet
        baseline. Out-of-scope frames are never evaluated or dispatched into.
        Only the probed frames' own origins count: a console error or request
        from any other frame (a noisy third-party iframe) is not a reaction. A
        probed frame whose final control call failed is "inconclusive" (it may
        have navigated, or just detached), never a navigation reaction."""
        out = {"probed_frames": 0, "reactions": [], "result": "no-listener"}
        rec["postmessage_probe"] = out
        try:
            listen = [e for e in rec.get("events") or []
                      if e.get("type") == "postmessage" and e.get("direction") == "listen"]
            oos = sorted({e.get("frame_origin") or "" for e in listen if not e.get("frame_in_scope")})
            if oos:
                out["skipped_out_of_scope"] = len(oos)
            if not listen:
                return out
            armed = []
            for f in list(page.frames):
                if not self._scope(f.url):
                    continue
                r = await self._ctl(f, "arm")
                if isinstance(r, dict) and r.get("listeners"):
                    armed.append(f)
            if not armed:
                out["result"] = "skipped-out-of-scope" if oos else "no-listener"
                return out
            out["probed_frames"] = len(armed)
            tok = self.new_dom_token("postmessage", rec)
            data = self._probe_data(rec, self.dom_payload(tok) if tok else "hm-probe")
            self._watch = {"phase": 0, "req": [], "console": []}
            await asyncio.sleep(PROBE_BASELINE_S)
            before = await self.snapshot_storage(page)
            self._watch["phase"] = 1
            fired = [(f, _origin(f.url), await self._ctl(f, "fire", data)) for f in armed]
            await asyncio.sleep(PROBE_WATCH_S)
            after = await self.snapshot_storage(page)
            reactions: set[tuple[str, str]] = set()
            inconclusive = 0
            for f, fo, fr in fired:
                d = await self._ctl(f, "done")
                if d is _CTL_ERR:
                    inconclusive += 1     # detached / navigated / timed out: cannot tell
                    continue
                if isinstance(d, dict) and d.get("moved"):
                    reactions.add((fo, "navigation"))
                sync = fr.get("sync", 0) if isinstance(fr, dict) else 0
                if isinstance(d, dict) and (sync or (d.get("after", 0) and not d.get("base", 0))):
                    reactions.add((fo, "dom"))
            w, self._watch = self._watch, None
            noisy = {fo for ph, fo, _nav in w["req"] if ph == 0}
            for ph, fo, nav in w["req"]:
                if ph == 1 and fo and fo not in noisy and self._scope(fo + "/"):
                    reactions.add((fo, "navigation" if nav else "request"))
            probed = {fo for _f, fo, _fr in fired if fo}
            quiet = {fo for ph, fo in w["console"] if ph == 0}
            for ph, fo in w["console"]:
                if ph == 1 and fo in probed and fo not in quiet and self._scope(fo + "/"):
                    reactions.add((fo, "console"))
            if before and after:
                for row in EL.storage_diff(before, after):
                    reactions.add((row["origin"], "storage"))
            out["reactions"] = [{"frame_origin": fo, "kind": k} for fo, k in sorted(reactions)]
            if inconclusive:
                out["inconclusive_frames"] = inconclusive
            out["result"] = "reaction" if reactions else ("inconclusive" if inconclusive else "no-reaction")
        except Exception as e:  # noqa: BLE001 -- the probe never breaks the walk
            out["result"] = out["result"] if out["probed_frames"] == 0 else "no-reaction"
            out["error"] = type(e).__name__
        finally:
            self._watch = None
        return out
