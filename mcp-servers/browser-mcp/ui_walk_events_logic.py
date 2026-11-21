"""#164 UI-walk event recorder: pure event logic (no browser, no network).

Parses/summarises recorded page events and derives *candidate* findings from
them. Candidates are leads for exploit-agent, never confirmed findings.

HARD RULE: no cookie, storage or message VALUES ever appear in anything this
module returns. Only names, flags, hashes, types, key names and lengths.

EVENT CONTRACT (controller ruling R1; recorder tasks emit exactly these):
Every event: {"type", "control_signature": str|None, "t_ms": int, "frame_origin": str}
plus, per type:
- set_cookie / js_cookie: the parse_set_cookie dict fields + "url" (page or
  response URL) + "blocked": list[str] (set_cookie only; [] if unknown)
- headers: "url", "resource_type", "request_origin" (request Origin header,
  else page origin), plus security_headers() fields (csp, xfo,
  frame_ancestors, acao, acac, acam, hsts)
- redirect: "hops": [{"url", "status", "in_scope": bool}], "param_names": list[str]
- postmessage: "direction": "send"|"listen", "target_origin": str|None,
  "shape": data_shape dict|None, "frame_in_scope": bool
- storage: "origin", "key", "change"
- window_open: "url", "noopener": bool, "via": "anchor"|"window.open"
- dom_sink: "source", "sink", "executed": bool, "token", "script_url", "line"
- console / websocket / indexeddb / service_worker: not read by derive_candidates.
Page dict keys read by derive_candidates: "url", "events", "api_edges"
(each {"method","sent",...}), "controls" (each {"classification",...}),
optional "postmessage_probe" ({"result": "reaction"|..., "reactions": [...]}).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import parse_qsl, urljoin, urlsplit

AUTHISH = ("sess", "sid", "auth", "token", "jwt", "remember", "login", "csrf",
           "xsrf", "refresh", "access", "id_token", "bearer")

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_MAX_KEYS = 30
_CSP_MAX = 500


def is_authish_name(name: str) -> bool:
    n = (name or "").lower()
    return any(s in n for s in AUTHISH)


def _parse_cookie_line(line: str, *, allow_httponly: bool) -> dict | None:
    parts = [p.strip() for p in line.split(";")]
    if not parts or not parts[0]:
        return None
    # A segment without "=" is a nameless cookie whose VALUE is that string:
    # never report it as a name.
    name = parts[0].split("=", 1)[0].strip() if "=" in parts[0] else ""
    out = {"name": name, "domain": None, "path": None, "secure": False,
           "httponly": False, "samesite": None, "persistent": False,
           "partitioned": False}
    for attr in parts[1:]:
        if not attr:
            continue
        k, _, v = attr.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "secure":
            out["secure"] = True
        elif k == "httponly":
            out["httponly"] = allow_httponly
        elif k == "samesite":
            out["samesite"] = v or None
        elif k == "domain":
            out["domain"] = v or None
        elif k == "path":
            out["path"] = v or None
        elif k in ("expires", "max-age"):
            out["persistent"] = True
        elif k == "partitioned":
            out["partitioned"] = True
    return out


def parse_set_cookie(raw: str) -> list[dict]:
    """Split on newlines (one Set-Cookie per line), flags only, no value."""
    res = []
    for line in (raw or "").split("\n"):
        c = _parse_cookie_line(line, allow_httponly=True)
        if c:
            res.append(c)
    return res


def parse_cookie_assignment(s: str) -> dict:
    """Parse a `document.cookie = s` string; httponly is always False."""
    return _parse_cookie_line(s or "", allow_httponly=False) or {
        "name": "", "domain": None, "path": None, "secure": False,
        "httponly": False, "samesite": None, "persistent": False,
        "partitioned": False}


def data_shape(obj) -> dict:
    """Type, sorted top-level keys (dict only, <=30) and length. Never values."""
    if isinstance(obj, dict):
        return {"type": "object", "keys": sorted(str(k) for k in obj)[:_MAX_KEYS],
                "length": len(obj)}
    if isinstance(obj, (list, tuple)):
        return {"type": "array", "keys": [], "length": len(obj)}
    if isinstance(obj, str):
        return {"type": "string", "keys": [], "length": len(obj)}
    if obj is None:
        return {"type": "null", "keys": [], "length": 0}
    if isinstance(obj, bool):
        return {"type": "boolean", "keys": [], "length": 0}
    if isinstance(obj, (int, float)):
        return {"type": "number", "keys": [], "length": 0}
    return {"type": type(obj).__name__, "keys": [], "length": 0}


def storage_diff(before: dict, after: dict) -> list[dict]:
    """{origin: {key: hash}} x2 -> added/removed/changed entries (no values)."""
    out = []
    for origin in sorted(set(before) | set(after)):
        b = before.get(origin) or {}
        a = after.get(origin) or {}
        for key in sorted(set(b) | set(a)):
            if key not in b:
                out.append({"origin": origin, "key": key, "change": "added"})
            elif key not in a:
                out.append({"origin": origin, "key": key, "change": "removed"})
            elif b[key] != a[key]:
                out.append({"origin": origin, "key": key, "change": "changed"})
    return out


_MIN_REDIRECT_VALUE_LEN = 4


def _value_in_location(v: str, loc: str, raw_loc: str = "") -> bool:
    """True if v equals a whole component of loc (the RESOLVED Location), or
    prefixes it at a boundary. Components: the full URL, scheme+host, the bare
    host, the path and each whole query value. A single trailing "/" difference
    is ignored. raw_loc (the header as sent) is also prefix-checked, so a
    relative Location keeps matching a relative value."""
    if len(v) < _MIN_REDIRECT_VALUE_LEN:
        return False
    sp = urlsplit(loc)
    comps = {loc}
    if sp.scheme and sp.netloc:
        comps.add(f"{sp.scheme}://{sp.netloc}")
    if sp.hostname:
        comps.add(sp.hostname)
    if sp.path:
        comps.add(sp.path)
    comps.update(qv for _, qv in parse_qsl(sp.query, keep_blank_values=False))
    alts = {v, v[:-1] if v.endswith("/") else v + "/"}
    if any(a in comps for a in alts if len(a) >= _MIN_REDIRECT_VALUE_LEN):
        return True
    for whole in {loc, raw_loc} - {""}:
        if whole.startswith(v) and (v.endswith("/") or len(whole) == len(v) or whole[len(v)] in "/?#"):
            return True
    return False


def redirect_param_names(hops: list[dict]) -> list[str]:
    """Names of hop-n query params whose (decoded) value matches hop-n's location.

    The Location is resolved against the hop's own URL first (a relative
    Location is compared as the absolute URL the browser went to). Matches
    whole components only (full URL, scheme+host, bare host, path, a whole
    query value, or a boundary-aligned prefix), ignoring one trailing "/";
    values under 4 chars never match.
    """
    names: list[str] = []
    for hop in hops or []:
        raw = hop.get("location") or ""
        if not raw:
            continue
        url = hop.get("url") or ""
        try:
            loc = urljoin(url, raw)
        except ValueError:
            loc = raw
        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=False):
            if _value_in_location(v, loc, raw) and k not in names:
                names.append(k)
    return names


def _frame_ancestors(csp: str | None) -> str | None:
    if not csp:
        return None
    for d in csp.split(";"):
        d = d.strip()
        if d.lower().startswith("frame-ancestors"):
            v = d[len("frame-ancestors"):].strip()
            return v or None
    return None


def security_headers(headers: dict) -> dict:
    h = headers or {}
    csp = h.get("content-security-policy")
    return {
        "csp": csp[:_CSP_MAX] if csp else None,
        "xfo": h.get("x-frame-options"),
        "frame_ancestors": _frame_ancestors(csp),
        "acao": h.get("access-control-allow-origin"),
        "acac": (h.get("access-control-allow-credentials") or "").strip().lower() == "true",
        "acam": h.get("access-control-allow-methods"),
        "hsts": bool(h.get("strict-transport-security")),
    }


def validate_proxy_url(url: str) -> str | None:
    """Loopback http proxy with explicit port and no userinfo, else error text."""
    try:
        p = urlsplit(url or "")
        port = p.port
    except ValueError:
        return "proxy URL is malformed"
    if p.scheme != "http":
        return "proxy URL must use the http scheme"
    if p.username is not None or p.password is not None:
        return "proxy URL must not contain credentials"
    if (p.hostname or "") not in _LOOPBACK_HOSTS:
        return "proxy host must be loopback (127.0.0.1, localhost or [::1])"
    if port is None:
        return "proxy URL must include a port"
    if p.path not in ("", "/") or "?" in url or "#" in url or ";" in url:
        return "proxy URL must be scheme://host:port only (no path, query or fragment)"
    return None


def canonical_proxy_url(url: str) -> str:
    """The freshly rebuilt "http://host:port" for a validated proxy URL -- the
    only form ever handed to a browser launch. ValueError when it is invalid."""
    err = validate_proxy_url(url)
    if err:
        raise ValueError(err)
    p = urlsplit(url)
    host = p.hostname.lower()
    return f"http://{'[' + host + ']' if ':' in host else host}:{p.port}"


AUTO_PROXY = "auto"   # 2026-11-21 addendum: detect a local Burp listener, mirror only if it is Burp


def resolve_upstream_proxy(param: str, env: str | None) -> str | None:
    """None = mirror off; AUTO_PROXY = auto-detect Burp; else the proxy URL
    (still to be validated). "off" always wins; an explicit param beats the
    env var; no param and no env var means auto."""
    if param == "off":
        return None
    if param == "":
        if not env:
            return AUTO_PROXY
        return None if env == "off" else env
    return param


def looks_like_burp(body: str | None) -> bool:
    """Burp's proxy listener answers a plain GET / with its own page naming
    "Burp Suite" (Professional / Community Edition). Anything else on the
    port is not Burp, so target traffic is never routed through it."""
    return "burp suite" in (body or "").lower()


# ---------------------------------------------------------------- candidates

def _has_state_change(page: dict) -> bool:
    for e in page.get("api_edges") or []:
        if str(e.get("method", "GET")).upper() != "GET":
            return True
    return any(c.get("classification") in ("destructive", "submit")
               for c in page.get("controls") or [])


def _doc_headers(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("type") == "headers"
            and e.get("resource_type") == "document"]


def _same_doc(event_url: str, page_url: str) -> bool:
    """Same host and path (query / fragment ignored: event URLs never carry them)."""
    try:
        a, b = urlsplit(event_url), urlsplit(page_url)
    except ValueError:
        return False
    return bool(a.netloc) and (a.netloc.lower(), a.path or "/") == (b.netloc.lower(), b.path or "/")


def derive_candidates(page: dict, *, scope: Callable[[str], bool]) -> list[dict]:
    page_url = page.get("url") or ""
    events = page.get("events") or []
    out: list[dict] = []
    seen: set[str] = set()

    def add(type_, sig, detail):
        key = json.dumps([type_, sig, detail], sort_keys=True, default=str)
        if key in seen:
            return
        seen.add(key)
        out.append({"type": type_, "page": page_url,
                    "control_signature": sig, "detail": detail})

    doc = _doc_headers(events)
    doc_csp = next((e.get("csp") for e in doc if e.get("csp")), None)

    for ev in events:
        t = ev.get("type")
        sig = ev.get("control_signature")
        if t in ("set_cookie", "js_cookie"):
            name = ev.get("name") or ""
            if not is_authish_name(name):
                continue
            secure = bool(ev.get("secure"))
            ss = ev.get("samesite")
            url = ev.get("url") or page_url
            reasons = []
            if url.lower().startswith("https:") and not secure:
                reasons.append("missing-secure")
            if t == "set_cookie" and not ev.get("httponly"):
                reasons.append("missing-httponly")
            if ss is None:
                reasons.append("missing-samesite")
            elif ss.lower() == "none" and not secure:
                reasons.append("samesite-none-without-secure")
            if reasons:
                add("cookie-flags-candidate", sig, {
                    "name": name, "source": t, "reasons": reasons,
                    "secure": secure, "httponly": bool(ev.get("httponly")),
                    "samesite": ss})
        elif t == "postmessage":
            shape = ev.get("shape") or {}
            if (ev.get("direction") == "send" and ev.get("target_origin") == "*"
                    and any(is_authish_name(k) for k in shape.get("keys") or [])):
                add("postmessage-wildcard-target-candidate", sig, {
                    "keys": [k for k in shape.get("keys") or [] if is_authish_name(k)],
                    "frame_in_scope": bool(ev.get("frame_in_scope"))})
        elif t == "storage":
            if ev.get("change") in ("added", "changed") and is_authish_name(ev.get("key") or ""):
                add("storage-token-candidate", sig, {
                    "origin": ev.get("origin"), "key": ev.get("key"),
                    "change": ev.get("change")})
        elif t == "redirect":
            if ev.get("param_names"):
                add("redirect-param-candidate", sig, {
                    "param_names": list(ev["param_names"]),
                    "hops": [{"status": h.get("status"), "in_scope": h.get("in_scope")}
                             for h in ev.get("hops") or []]})
        elif t == "headers":
            if ev.get("acac") and (ev.get("acao") == "*"
                                   or (ev.get("acao") and ev.get("acao") == ev.get("request_origin"))):
                add("cors-candidate", sig, {
                    "url": ev.get("url"), "acao": ev.get("acao"),
                    "request_origin": ev.get("request_origin"), "acac": True})
        elif t == "window_open":
            url = ev.get("url") or ""
            if not ev.get("noopener") and not scope(url):
                add("tabnabbing-candidate", sig, {
                    "url": url, "via": ev.get("via")})
        elif t == "dom_sink":
            kind = "dom-xss-candidate" if ev.get("executed") else "dom-sink-candidate"
            add(kind, sig, {
                "source": ev.get("source"), "sink": ev.get("sink"),
                "executed": bool(ev.get("executed")), "token": ev.get("token"),
                "script_url": ev.get("script_url"), "line": ev.get("line"),
                "csp": doc_csp})

    probe = page.get("postmessage_probe")
    if probe and probe.get("result") == "reaction":
        add("postmessage-no-origin-check-candidate", None, {
            "reactions": list(probe.get("reactions") or [])})

    # Only THIS page's own top document says whether the page can be framed: a
    # subframe document (other path) neither masks nor stands in for it, and
    # with no such headers event nothing is known, so nothing is claimed.
    top = [e for e in doc if _same_doc(e.get("url") or "", page_url)]
    if top and _has_state_change(page) and not any(e.get("xfo") or e.get("frame_ancestors") for e in top):
        add("clickjacking-candidate", None, {"document_headers_seen": len(top)})

    return out
