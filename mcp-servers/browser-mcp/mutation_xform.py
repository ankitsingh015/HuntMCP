"""Spec 3b (UI-walk request mutation, request level): PURE logic, no browser, no network.

- request transforms (headers, method / override, content type, path) applied
  to a recorded request;
- the request-level profiler + ranked plan (routing/authz headers, method
  override, content-type switch, JSON parser differentials, path tricks,
  cache-key confusion, GraphQL alias/batch, races);
- the agent's extra ops for those families, and the 3b candidate rules.

waf-bypass-mcp is used as DATA only (tier-1 headers, tier-2 path builders);
its tier-3 method list is never loaded. Everything sent still passes
mutation_logic.gate() like a 3a variant.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.sax.saxutils import escape as _xml_escape

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import mutation_logic as M  # noqa: E402
from mutation_logic import Xform, routing_alt_urls  # noqa: E402,F401  (re-exported)

CONTENT_TYPES = {"json": "application/json", "form": "application/x-www-form-urlencoded",
                 "text": "text/plain", "xml": "application/xml"}


# -- helpers -------------------------------------------------------------------
def _set_header(headers: dict, name: str, value) -> dict:
    out = {k: v for k, v in headers.items() if str(k).lower() != name.lower()}
    out[name] = str(value)
    return out


def _drop_header(headers: dict, name: str) -> dict:
    return {k: v for k, v in headers.items() if str(k).lower() != name.lower()}


def with_buster(url: str, token: str) -> str:
    """Add (or replace) the unique cache-buster `hmcb=<token>` query param."""
    p = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != "hmcb"]
    pairs.append(("hmcb", token))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), p.fragment))


def has_buster(url: str) -> bool:
    return any(k == "hmcb" and v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True))


def _fields_of(req: M.Req) -> dict | None:
    """Top-level fields of a JSON-object or form body (None when neither)."""
    if req.body_kind == "json":
        try:
            obj = json.loads(req.body or "")
        except (ValueError, RecursionError):
            return None
        return obj if isinstance(obj, dict) else None
    if req.body_kind == "form":
        return dict(parse_qsl(req.body or "", keep_blank_values=True))
    return None


def _scalar(v) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return M._scalar_str(v)


def _to_content_type(req: M.Req, target: str) -> M.Req:
    fields = _fields_of(req)
    if fields is None or target not in CONTENT_TYPES:
        return req
    if target == "json":
        body = json.dumps(fields)
    elif target == "text":
        body = json.dumps(fields)
    elif target == "form":
        body = urlencode([(k, _scalar(v)) for k, v in fields.items()])
    else:   # xml
        body = "<root>" + "".join(f"<{k}>{_xml_escape(_scalar(v))}</{k}>" for k, v in fields.items()
                                  if str(k).replace("_", "").replace("-", "").isalnum()) + "</root>"
    kind = M.body_kind_of({"Content-Type": CONTENT_TYPES[target]}, body)
    return replace(req, body=body, body_kind=kind if target in ("json", "form") else "unparsed",
                   headers=_set_header(req.headers, "Content-Type", CONTENT_TYPES[target]))


def _with_path(url: str, path: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, path, p.query, p.fragment))


def _override(req: M.Req, name: str, value) -> M.Req:
    kind, _, nm = name.partition(":")
    if kind == "header":
        return replace(req, headers=_set_header(req.headers, nm, value))
    if kind == "param":
        if req.body_kind == "json" and (req.method or "GET").upper() not in ("GET", "HEAD"):
            return M.apply_ops(req, [M.Op("add_param", "json", (nm,), value)])
        if req.body_kind == "form" and (req.method or "GET").upper() not in ("GET", "HEAD"):
            return M.apply_ops(req, [M.Op("add_param", "form", (nm,), value)])
        return M.apply_ops(req, [M.Op("add_param", "query", (nm,), value)])
    raise ValueError(f"unknown override {name!r}")


def apply_xforms(req: M.Req, xforms: list[Xform]) -> M.Req:
    """A NEW Req with every transform applied in order (the input is never changed)."""
    out = replace(req, headers=dict(req.headers))
    for x in xforms or []:
        if x.kind in ("set_header", "cache_poison"):
            out = replace(out, headers=_set_header(out.headers, x.name, x.value))
        elif x.kind == "remove_header":
            out = replace(out, headers=_drop_header(out.headers, x.name))
        elif x.kind == "method":
            out = replace(out, method=str(x.value).upper())
        elif x.kind == "override":
            out = _override(out, x.name, x.value)
        elif x.kind == "content_type":
            out = _to_content_type(out, str(x.value))
        elif x.kind == "path":
            out = replace(out, url=_with_path(out.url, str(x.value)))
        elif x.kind == "cache_deception":
            path = urlsplit(out.url).path
            out = replace(out, url=_with_path(out.url, path.rstrip("/") + str(x.value)))
        elif x.kind == "graphql":
            body = graphql_body(out, str(x.name), int(x.n))
            if body is None:
                raise ValueError("graphql transform does not apply to this request")
            out = replace(out, body=body, body_kind="json")
        elif x.kind == "json_raw":
            out = replace(out, body=_json_raw(out, str(x.name), x.value), body_kind="json")
        elif x.kind in ("race", "json_dup"):
            pass   # race: executed by the runner; json_dup: a marker (the duplicate key is a 3a op)
        else:
            raise ValueError(f"unknown transform {x.kind!r}")
    return out


def _json_raw(req: M.Req, mode: str, field_name) -> str:
    """Raw-text JSON tricks a strict parser would normalise away."""
    obj = json.loads(req.body or "{}")
    text = json.dumps(obj)
    if mode == "unicode_key":
        key = json.dumps(str(field_name))
        esc = '"' + "".join(f"\\u{ord(c):04x}" if c.isalnum() else c for c in str(field_name)) + '"'
        return text.replace(key + ":", esc + ":", 1)
    if mode == "trailing_comma":
        return text[:-1] + ",}" if text.endswith("}") else text
    if mode == "comment":
        return text.replace("{", "{/*hm*/", 1)
    if mode == "bignum":
        return json.dumps({**obj, str(field_name): "__hm_big__"}).replace('"__hm_big__"', "99999999999999999999", 1)
    raise ValueError(f"unknown json_raw mode {mode!r}")



# =============================================================================
# Task 4: waf data (tier 1 / tier 2 ONLY) + the request-level plan
# =============================================================================
import importlib.util  # noqa: E402
import re  # noqa: E402

REQUEST_FAMILIES = ("header", "method", "content-type", "json-diff", "path", "cache", "graphql", "race")
ALL_FAMILY_ORDER = ("add", "remove", "duplicate", "retype", "numeric-edge") + REQUEST_FAMILIES
FORBIDDEN_HEADERS = ("host", "cookie", "authorization", "content-length", "transfer-encoding")
PATH_TRANSFORMS = ("trailing-slash", "trailing-dot", "semicolon-css", "encode-slash", "uppercase",
                   "double-encode", "dot-segment")
ADMINISH_RE = re.compile(r"(?i)/(admin|internal|manage|console|debug|staff|dashboard|config)")
RACE_RE = re.compile(r"(?i)(redeem|claim|apply|use|withdraw|transfer|vote|like|invite|coupon|voucher|checkout|"
                     r"buy|order)")
DENIED = (401, 403, 404)
_WAF_PATH = os.path.join(os.path.dirname(_HERE), "waf-bypass-mcp", "server.py")
_waf_mod = None


def forbidden_header(name: str) -> bool:
    n = str(name).strip().lower()
    return n in FORBIDDEN_HEADERS or n.startswith("proxy-") or n.startswith(":")


def _waf_module():
    """waf-bypass-mcp's server.py, loaded by path. Only its pure tier-1 / tier-2
    builders are ever called (never tier 3: it lists non-GET methods)."""
    global _waf_mod
    if _waf_mod is None:
        spec = importlib.util.spec_from_file_location("hm_waf_bypass_data", _WAF_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _waf_mod = mod
    return _waf_mod


def waf_header_data() -> list[tuple[str, str]]:
    out = []
    for _label, args, _url in _waf_module()._tier1_variants("http://placeholder.invalid/"):
        if len(args) == 2 and args[0] == "-H" and ": " in args[1]:
            name, value = args[1].split(": ", 1)
            if not forbidden_header(name):
                out.append((name, value))
    return out


_PATH_PREFS = ("trailing /", "UPPERCASE", ";.css", "trailing /.", "%2f", "%-encode", "double //")


def waf_path_data(url: str) -> list[tuple[str, str]]:
    """(label, new path) from waf-bypass tier-2, minus forms that leave the
    path (`#`, `..`, NUL) -- preferred order, at most 6."""
    p = urlsplit(url)
    cand = []
    for label, _args, new_url in _waf_module()._tier2_variants(url):
        np = urlsplit(new_url).path
        if (not np.startswith("/") or "#" in np or "?" in np or "%00" in np or np.endswith("/../")
                or any(c in np for c in "\r\n\x00 ") or np == p.path):
            continue
        cand.append((label, np))
    def rank(item):
        for i, pref in enumerate(_PATH_PREFS):
            if pref in item[0]:
                return i
        return len(_PATH_PREFS)
    seen, out = set(), []
    for label, np in sorted(cand, key=rank):
        if np not in seen:
            seen.add(np)
            out.append((label, np))
    return out[:6]


def path_transform(url: str, name: str) -> str | None:
    path = urlsplit(url).path or "/"
    base = path.rstrip("/") or ""
    if name == "trailing-slash":
        return base + "/"
    if name == "trailing-dot":
        return base + "/."
    if name == "semicolon-css":
        return base + ";.css"
    if name == "uppercase":
        return path.upper() if path.upper() != path else None
    if name == "encode-slash":
        return path[:1] + path[1:].replace("/", "%2f", 1) if path.count("/") > 2 else None
    if name == "double-encode":
        i = next((k for k, c in enumerate(path) if c.isalpha()), None)
        return None if i is None else path[:i] + f"%25{ord(path[i]):02x}" + path[i + 1:]
    if name == "dot-segment":
        head, _, last = base.rpartition("/")
        return f"{head}/./{last}" if last else None
    return None


def _v(req: M.Req, family: str, ops: list, xforms: list, reason: str, score: int) -> M.Variant:
    return M.Variant(M._vid(req.replay_id, ops, xforms), req.replay_id, family, ops, reason, score,
                     xforms=xforms)


def _is_get(req: M.Req) -> bool:
    return (req.method or "GET").upper() in ("GET", "HEAD")


def _second_value(v):
    if isinstance(v, bool):
        return not v
    if isinstance(v, (int, float)):
        return 0 if v else 1
    return "hm-dup"


def build_request_plan(req: M.Req, ctx: M.Context, meta: dict, *, graphql: bool = False,
                       is_create: bool = False) -> list[M.Variant]:
    """Request-level variants that fit THIS request (each with its reason)."""
    meta = meta or {}
    status = int(meta.get("status") or 0)
    p = urlsplit(req.url)
    is_get = _is_get(req)
    denied = status in DENIED
    out: list[M.Variant] = []

    # routing / authz headers
    why = None
    if denied:
        why = f"the recorded response was {status}"
    elif ADMINISH_RE.search(p.path):
        why = "the path looks admin/internal"
    elif meta.get("proxy_signals"):
        why = "the response shows a proxy/CDN (" + ", ".join(meta["proxy_signals"][:3]) + ")"
    if why:
        sc = 80 if denied else 50
        for name, value in waf_header_data():
            out.append(_v(req, "header", [], [Xform("set_header", name, value)],
                          f"{why}: does `{name}` change who the server thinks you are?", sc))
        for name, value in (("X-Forwarded-Host", "localhost"), ("X-Host", "localhost"),
                            ("X-Forwarded-Proto", "http"), ("X-Forwarded-Scheme", "http")):
            out.append(_v(req, "header", [], [Xform("set_header", name, value)],
                          f"{why}: is `{name}` trusted for routing?", sc - 10))
        if is_get:
            for dp in sorted(ctx.denied_paths or ())[:2]:
                if dp != p.path:
                    for name in ("X-Original-URL", "X-Rewrite-URL"):
                        out.append(_v(req, "header", [], [Xform("set_header", name, dp)],
                                      f"`{dp}` was denied during the walk: does `{name}` route around it?", sc))

    # method override / swap
    msc = 75 if status in (401, 403, 405) else 35
    mwhy = f"recorded {status}; " if status in (401, 403, 405) else ""
    if is_get:
        for verb in ("HEAD", "POST", "PUT", "DELETE"):
            tag = "" if verb == "HEAD" else " (non-GET: needs the grant and an owned object)"
            out.append(_v(req, "method", [], [Xform("override", "header:X-HTTP-Method-Override", verb)],
                          f"{mwhy}override header names {verb}{tag}", msc))
            if verb in ("HEAD", "DELETE"):
                out.append(_v(req, "method", [], [Xform("override", "param:_method", verb)],
                              f"{mwhy}`_method={verb}`{tag}", msc - 5))
        out.append(_v(req, "method", [], [Xform("method", "", "HEAD")],
                      f"{mwhy}GET swapped to HEAD: is the access rule method-specific?", msc))
        out.append(_v(req, "method", [], [Xform("method", "", "POST")],
                      f"{mwhy}GET swapped to POST (non-GET: needs the grant and an owned object)", msc - 10))
    else:
        verb = (req.method or "POST").upper()
        for h in ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"):
            out.append(_v(req, "method", [], [Xform("method", "", "POST"), Xform("override", f"header:{h}", verb)],
                          f"the {verb} sent as POST with `{h}: {verb}`: is the method check on the request line?",
                          msc))
        out.append(_v(req, "method", [], [Xform("method", "", "POST"), Xform("override", "param:_method", verb)],
                      f"the {verb} sent as POST with `_method={verb}`", msc - 5))

    # content type
    if not is_get and req.body_kind in ("json", "form") and M.parse_params(req):
        targets = ("form", "text", "xml") if req.body_kind == "json" else ("json",)
        for t in targets:
            out.append(_v(req, "content-type", [], [Xform("content_type", "", t)],
                          f"same fields as {t}: does another parser path skip validation / CSRF protections?", 55))

    # JSON parser differentials
    if not is_get and req.body_kind == "json":
        try:
            obj = json.loads(req.body or "")
        except (ValueError, RecursionError):
            obj = None
        scalars = [(k, v) for k, v in (obj.items() if isinstance(obj, dict) else ())
                   if not isinstance(v, (dict, list))]
        for k, v in scalars[:2]:
            out.append(_v(req, "json-diff", [M.Op("duplicate_param", "json", (k,), _second_value(v))],
                          [Xform("json_dup", k)],
                          f"`{k}` as a duplicate JSON key: which copy does the validator and the store use?", 50))
            for mode in ("unicode_key", "trailing_comma", "comment"):
                out.append(_v(req, "json-diff", [], [Xform("json_raw", mode, k)],
                              f"`{k}` body written with {mode.replace('_', ' ')}: do two parsers agree?", 40))
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out.append(_v(req, "json-diff", [], [Xform("json_raw", "bignum", k)],
                              f"`{k}` as a 20-digit number: precision/overflow differences", 40))

    # path / encoding (tier-2 builders)
    if is_get:
        for label, np in waf_path_data(req.url):
            out.append(_v(req, "path", [], [Xform("path", "", np)],
                          f"{label}: is the access rule matched on the exact path string?", 70 if denied else 30))

    # cache-key confusion: poisoning only when the response shows caching; deception also for an
    # authenticated HTML page (dynamic pages carry no cache headers -- the CDN's suffix rule caches them)
    cs = meta.get("cache_signals") or []
    html_page = status == 200 and str(meta.get("content_type") or "").startswith("text/html")
    if is_get and (cs or html_page):
        sig = ", ".join(cs[:3])
        if cs:
            for name in ("X-Forwarded-Host", "X-Host", "X-Forwarded-Proto"):
                out.append(_v(req, "cache", [], [Xform("cache_poison", name, "hm-cache.invalid")],
                              f"response shows caching ({sig}): is `{name}` reflected but not part of the cache "
                              "key? (always on a unique hmcb= URL)", 60))
        wh = (f"response shows caching ({sig})" if cs else "authenticated HTML page")
        out.append(_v(req, "cache", [], [Xform("cache_deception", "", "/hm.css")],
                      f"{wh}: is the page cached when `/hm.css` is appended? (always on a unique hmcb= URL)", 55))

    # GraphQL alias / batch -- filled in by Task 6
    if graphql:
        out += graphql_variants(req)

    # races (non-GET only; the runner enforces grant + created object + N)
    if not is_get and req.body_kind in ("json", "form", "none") and (RACE_RE.search(p.path) or is_create):
        n = 3 if is_create else 5
        out.append(_v(req, "race", [], [Xform("race", "", None, n)],
                      f"{'create endpoint' if is_create else 'one-shot-looking action'}: {n} parallel copies "
                      "(walker-created object only)", 65))

    uniq: dict[str, M.Variant] = {}
    for v in out:
        uniq.setdefault(v.variant_id, v)
    return list(uniq.values())



def merge_plans(param_variants: list, request_variants: list, *, max_variants: int = 40,
                max_per_family: int = 10) -> list[M.Variant]:
    uniq: dict[str, M.Variant] = {}
    for v in [*param_variants, *request_variants]:
        uniq.setdefault(v.variant_id, v)
    order = {f: i for i, f in enumerate(ALL_FAMILY_ORDER)}
    ranked = sorted(uniq.values(), key=lambda v: (-v.score, order.get(v.family, 99)))
    per: dict[str, int] = {}
    plan = []
    for v in ranked:
        if per.get(v.family, 0) >= max_per_family:
            continue
        per[v.family] = per.get(v.family, 0) + 1
        plan.append(v)
        if len(plan) >= max_variants:
            break
    return plan


# =============================================================================
# Task 5: the agent's request-level ops
# =============================================================================
MAX_AGENT_VALUE = 2048
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
AGENT_VERBS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
REQUEST_OPS = ("set_header", "remove_header", "method", "content_type", "path", "graphql_batch")
_BAD = ("\r", "\n", "\x00")


def _clean(s) -> bool:
    return isinstance(s, str) and not any(c in s for c in _BAD)


def _bad_header_name(name) -> bool:
    return (not isinstance(name, str) or not HEADER_NAME_RE.match(name) or forbidden_header(name))


def _short(x, n: int = 40) -> str:
    return str(x)[:n]


def _literal_path_ok(lit, req: M.Req) -> bool:
    if not isinstance(lit, str) or not _clean(lit) or not 1 <= len(lit) <= 512:
        return False
    if not lit.startswith("/") or lit.startswith("//") or any(c in lit for c in "?#\\ "):
        return False
    return urlsplit(_with_path(req.url, lit)).netloc == urlsplit(req.url).netloc


def validate_request_ops(raw: list, known: dict) -> tuple[list[M.Variant], list[str]]:
    """The agent's request-level variants (approach C). `known` maps replay_id ->
    M.Req. Rejected items get a message (never echoing much target text);
    accepted ones still pass gate() like any rule variant."""
    ok_: list[M.Variant] = []
    errs: list[str] = []
    for i, item in enumerate(raw or []):
        if not isinstance(item, dict):
            errs.append(f"#{i}: not an object")
            continue
        rid, kind = item.get("replay_id"), item.get("op")
        req = known.get(rid) if isinstance(rid, str) else None
        if req is None:
            errs.append(f"#{i}: unknown replay_id")
            continue
        if kind not in REQUEST_OPS:
            errs.append(f"#{i}: op {_short(kind)!r} is not available (request ops: {', '.join(REQUEST_OPS)})")
            continue
        xf, family, err = None, None, None
        if kind in ("set_header", "remove_header"):
            family, name = "header", item.get("name")
            if _bad_header_name(name):
                err = "bad or forbidden header name"
            elif kind == "set_header":
                val = item.get("value")
                val = str(val) if isinstance(val, (int, float)) and not isinstance(val, bool) else val
                if not _clean(val) or len(val) > MAX_AGENT_VALUE:
                    err = "header value too long or contains CR/LF/NUL"
                else:
                    xf = Xform("set_header", name, val)
            elif not any(str(k).lower() == name.lower() for k in req.headers):
                err = "remove_header: the recorded request has no such header"
            else:
                xf = Xform("remove_header", name)
        elif kind == "method":
            family, via = "method", item.get("via", "swap")
            verb = item.get("method") if via == "swap" else item.get("override")
            if via not in ("swap", "header", "param"):
                err = "via must be swap, header or param"
            elif not isinstance(verb, str) or verb.upper() not in AGENT_VERBS:
                err = f"method must be one of {', '.join(AGENT_VERBS)}"
            elif via == "swap":
                xf = Xform("method", "", verb.upper())
            else:
                xf = Xform("override", "header:X-HTTP-Method-Override" if via == "header" else "param:_method",
                           verb.upper())
        elif kind == "content_type":
            family, to = "content-type", item.get("to")
            if to not in CONTENT_TYPES:
                err = "to must be json, form, text or xml"
            else:
                xf = Xform("content_type", "", to)
        elif kind == "path":
            family = "path"
            if "transform" in item:
                np = path_transform(req.url, item["transform"]) if item["transform"] in PATH_TRANSFORMS else None
                if np is None or not _literal_path_ok(np, req):
                    err = "path transform unknown or not applicable"
                else:
                    xf = Xform("path", "", np)
            elif _literal_path_ok(item.get("literal"), req):
                xf = Xform("path", "", item["literal"])
            else:
                err = "path literal must be a same-host path (/..., no //, ?, #, CR/LF/NUL, <= 512)"
        elif kind == "graphql_batch":
            family = "graphql"
            n, mode = item.get("n"), item.get("mode")
            if not isinstance(n, int) or isinstance(n, bool) or not 2 <= n <= 5 or mode not in ("alias", "array"):
                err = "graphql_batch needs n in 2..5 and mode alias|array"
            elif graphql_kind(req) is None:
                err = "not a GraphQL request"
            else:
                xf = Xform("graphql", mode, None, n)
        if err or xf is None:
            errs.append(f"#{i}: {err or 'invalid'}")
            continue
        reason = _short(item.get("reason") or "agent-added", 200)
        ok_.append(M.Variant(M._vid(rid, [], [xf]), rid, family, [], "agent: " + reason, 100, origin="agent",
                             xforms=[xf]))
    return ok_, errs



# =============================================================================
# Task 6: GraphQL helpers (alias / batch) + the shared candidate builder
# =============================================================================
_GQL_KEYS = {"query", "variables", "operationName", "extensions"}
_GQL_WRITE_RE = re.compile(r"(?i)\b(mutation|subscription)\b")


def _skip_str_or_comment(s: str, i: int) -> int:
    """If s[i] starts a string or a # comment, the index just past it, else i."""
    if s.startswith('"""', i):
        j = s.find('"""', i + 3)
        return len(s) if j < 0 else j + 3
    if s[i] == '"':
        j = i + 1
        while j < len(s) and s[j] != '"':
            j += 2 if s[j] == "\\" else 1
        return min(j + 1, len(s))
    if s[i] == "#":
        j = s.find("\n", i)
        return len(s) if j < 0 else j + 1
    return i


def _match(s: str, i: int, open_c: str, close_c: str) -> int:
    """Index of the bracket matching s[i] (strings/comments skipped), or -1."""
    depth, j = 0, i
    while j < len(s):
        k = _skip_str_or_comment(s, j)
        if k != j:
            j = k
            continue
        if s[j] == open_c:
            depth += 1
        elif s[j] == close_c:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def _balanced(s: str) -> bool:
    depth = {"{": 0, "(": 0, "[": 0}
    close = {"}": "{", ")": "(", "]": "["}
    j = 0
    while j < len(s):
        k = _skip_str_or_comment(s, j)
        if k != j:
            j = k
            continue
        c = s[j]
        if c in depth:
            depth[c] += 1
        elif c in close:
            depth[close[c]] -= 1
            if depth[close[c]] < 0:
                return False
        j += 1
    return not any(depth.values())


def _gql_docs(req: M.Req):
    """(docs, has_duplicate_keys) or None. json.loads keeps the LAST duplicate key while another
    parser may keep the FIRST, so a body with any duplicate key can never be called read-only."""
    dup: list = []

    def hook(pairs):
        if len({k for k, _ in pairs}) != len(pairs):
            dup.append(1)
        return dict(pairs)
    try:
        obj = json.loads(req.body or "", object_pairs_hook=hook)
    except (ValueError, RecursionError, TypeError):
        return None
    docs = obj if isinstance(obj, list) and obj else [obj]
    if not all(isinstance(d, dict) and isinstance(d.get("query"), str) for d in docs):
        return None
    path = urlsplit(req.url).path.lower()
    for d in docs:
        if not ("graphql" in path or (set(d) <= _GQL_KEYS and "{" in d["query"])):
            return None
    return docs, bool(dup)


def graphql_kind(req: M.Req) -> str | None:
    """None: not GraphQL. "query": a POST of pure queries (one object, or a batch of them),
    no override -- the only GraphQL the gate treats as read-only. Anything else
    GraphQL (a `mutation`/`subscription` token ANYWHERE, a comment or string
    included; unbalanced text; another method; an override) is "mutation"."""
    parsed = _gql_docs(req)
    if parsed is None:
        return None
    docs, dup = parsed
    if dup or (req.method or "").upper() != "POST" or M.override_values(req) or _GQL_WRITE_RE.search(req.body or ""):
        return "mutation"
    for d in docs:
        if _GQL_WRITE_RE.search(d["query"]) or not _balanced(d["query"]):
            return "mutation"
    return "query"


def _single_field(inner: str) -> str | None:
    s = inner.strip()
    m = re.match(r"(?:(\w+)\s*:\s*)?(\w+)", s)
    if not m or s.startswith("..."):
        return None
    i = m.end()
    while i < len(s) and s[i].isspace():
        i += 1
    if i < len(s) and s[i] == "(":
        j = _match(s, i, "(", ")")
        if j < 0:
            return None
        i = j + 1
    while True:
        while i < len(s) and s[i].isspace():
            i += 1
        d = re.match(r"@\w+", s[i:])
        if not d:
            break
        i += d.end()
        while i < len(s) and s[i].isspace():
            i += 1
        if i < len(s) and s[i] == "(":
            j = _match(s, i, "(", ")")
            if j < 0:
                return None
            i = j + 1
    while i < len(s) and s[i].isspace():
        i += 1
    if i < len(s):
        if s[i] != "{" or _match(s, i, "{", "}") != len(s) - 1:
            return None
    return s[len(m.group(0)) - len(m.group(2)) if m.group(1) else 0:]


def alias_query(query: str, n: int) -> str | None:
    """`n` aliased copies (hmA1..hmAn) of the operation's ONLY top-level field."""
    if not isinstance(query, str) or not _balanced(query):
        return None
    paren = 0
    start = -1
    j = 0
    while j < len(query):
        k = _skip_str_or_comment(query, j)
        if k != j:
            j = k
            continue
        c = query[j]
        paren += (c == "(") - (c == ")")
        if c == "{" and paren == 0:
            start = j
            break
        j += 1
    if start < 0:
        return None
    end = _match(query, start, "{", "}")
    if end < 0:
        return None
    rest = re.sub(r"#[^\n]*", "", query[end + 1:]).strip()
    if rest and not rest.startswith("fragment"):
        return None
    bare = _single_field(query[start + 1:end])
    if bare is None:
        return None
    copies = " ".join(f"hmA{k}: {bare}" for k in range(1, n + 1))
    return query[:start + 1] + " " + copies + " " + query[end:]


def graphql_body(req: M.Req, mode: str, n: int) -> str | None:
    try:
        obj = json.loads(req.body or "")
    except (ValueError, RecursionError, TypeError):
        return None
    if not isinstance(obj, dict) or not isinstance(obj.get("query"), str):
        return None
    if mode == "array":
        return json.dumps([obj] * n)
    if mode == "alias":
        q = alias_query(obj["query"], n)
        return None if q is None else json.dumps({**obj, "query": q})
    return None


def graphql_variants(req: M.Req) -> list[M.Variant]:
    if graphql_kind(req) is None:
        return []
    out = []
    for mode, n in (("alias", 3), ("alias", 5), ("array", 2), ("array", 5)):
        if graphql_body(req, mode, n) is None:
            continue   # e.g. a query with several top-level fields cannot be aliased
        xf = [Xform("graphql", mode, None, n)]
        what = f"{n} aliased copies of the query in one request" if mode == "alias" else f"a batch of {n} operations"
        out.append(_v(req, "graphql", [], xf,
                      f"GraphQL endpoint: {what} (no alias/batch limit = rate-limit and brute-force amplification)",
                      60))
    return out


# -- the shared candidate builder (3b types) -----------------------------------
_SHOW_VALUE = ("set_header", "cache_poison", "method", "override", "content_type", "path", "cache_deception")


def _change_of(variant: M.Variant) -> list[dict]:
    out = [{"op": o.kind, "location": o.location, "field": ".".join(str(s) for s in o.path)}
           for o in variant.ops]
    for x in variant.xforms:
        c = {"op": x.kind, "field": x.name}
        if x.kind in _SHOW_VALUE and x.value is not None:
            c["value"] = str(x.value)[:80]
        if x.n:
            c["n"] = x.n
        out.append(c)
    return out


def _cand(variant: M.Variant, ctype: str, why: str, base: M.Resp, var: M.Resp, *, readback: str = "n/a",
          d: M.Diff | None = None, single: M.Resp | None = None, recorded_values=None, extra: dict | None = None,
          excerpt: bool = True) -> dict:
    ev = {"base_status": base.status, "variant_status": var.status, "base_length": base.length,
          "variant_length": var.length, "keys_added": (d.keys_added[:20] if d else []),
          "keys_removed": (d.keys_removed[:20] if d else []),
          "single_value_status": single.status if single else None, "readback": readback,
          "excerpt": M._excerpt(base, var, recorded_values) if excerpt else ""}
    ev.update(extra or {})
    return {"type": ctype, "variant_id": variant.variant_id, "replay_id": variant.replay_id,
            "family": variant.family, "origin": variant.origin, "reason": why,
            "persisted": M._persisted_flag(readback), "change": _change_of(variant), "evidence": ev}


def graphql_candidate(variant: M.Variant, mode: str, n: int, base: M.Resp, var: M.Resp) -> dict | None:
    if not (M._ok(base) and M._ok(var)):
        return None
    try:
        obj = json.loads(var.body)
    except (ValueError, RecursionError):
        return None
    answered = 0
    if mode == "alias" and isinstance(obj, dict) and isinstance(obj.get("data"), dict) and not obj.get("errors"):
        answered = sum(1 for k in obj["data"] if str(k).startswith("hmA"))
    elif mode == "array" and isinstance(obj, list) and len(obj) == n:
        answered = sum(1 for e in obj if isinstance(e, dict) and e.get("data") and not e.get("errors"))
    if answered != n:
        return None
    return _cand(variant, "graphql-batching-candidate",
                 f"one request answered {answered} {'aliased' if mode == 'alias' else 'batched'} operations "
                 "(no alias/batch limit)", base, var, extra={"answered": answered, "mode": mode},
                 excerpt=False)


# =============================================================================
# Task 7: 3b candidate rules (leads, never confirmed)
# =============================================================================
def _xf(variant: M.Variant, *kinds):
    return next((x for x in variant.xforms if x.kind in kinds), None)


def request_candidates(variant: M.Variant, base: M.Resp, var: M.Resp, d: M.Diff, *, readback: str = "n/a",
                       single_value_resp: M.Resp | None = None, followup: M.Resp | None = None,
                       anon_original: M.Resp | None = None, anon_variant: M.Resp | None = None,
                       race: dict | None = None, recorded_values=None) -> list[dict]:
    fam = variant.family
    ctype = why = None
    extra = None
    if fam == "header":
        hdr = _xf(variant, "set_header")
        if base.status in DENIED and M._ok(var):
            ctype, why = "header-authz-bypass-candidate", \
                f"{base.status} without the header, {var.status} with `{hdr.name if hdr else '?'}`"
        elif hdr and hdr.name in ("X-Original-URL", "X-Rewrite-URL") and M._ok(base) and M._ok(var) \
                and (d.significant_length or d.keys_added or d.keys_removed):
            ctype, why = "header-authz-bypass-candidate", f"`{hdr.name}` made the server answer a different resource"
    elif fam == "method":
        if _is_get_variant(variant):
            if base.status in (401, 403, 405) and M._ok(var):
                ctype, why = "method-override-candidate", f"{base.status} as sent, {var.status} with a method swap/override"
        elif M._rejected(base) and M._ok(var) and readback == "persisted":
            ctype, why = "method-override-candidate", "rejected as sent, accepted and persisted via a method override"
    elif fam == "content-type":
        ct = _xf(variant, "content_type")
        if M._ok(base) and M._ok(var):
            if readback == "persisted":
                ctype, why = "content-type-confusion-candidate", \
                    f"the same fields as {ct.value if ct else '?'} were accepted and persisted"
            elif ct and ct.value in ("form", "text"):
                ctype, why = "content-type-confusion-candidate", \
                    f"accepted as {ct.value} (a CSRF-relevant content type; the endpoint still processed it)"
    elif fam == "json-diff":
        if M._ok(var) and ((single_value_resp is not None and M._rejected(single_value_resp))
                           or (M._rejected(base) and not variant.ops)):
            ctype, why = "json-parser-differential-candidate", \
                "the value alone is rejected, but the same request passes with the JSON tricked past validation"
    elif fam == "path":
        if base.status in DENIED and M._ok(var):
            ctype, why = "path-normalization-candidate", f"{base.status} on the exact path, {var.status} on a path variant"
    elif fam == "cache":
        poison = _xf(variant, "cache_poison")
        if poison is not None:
            val = str(poison.value)
            if followup is not None and M._ok(followup) and val in followup.body and val not in base.body:
                ctype, why = "cache-poisoning-candidate", \
                    f"`{poison.name}` was served back to a plain request on the same (buster) URL"
        elif _xf(variant, "cache_deception") is not None and anon_variant is not None and anon_original is not None:
            if M._ok(var) and M._ok(anon_variant) and M._ok(base) \
                    and M._comparable(anon_variant, frozenset()) == M._comparable(var, frozenset()) \
                    and M._comparable(anon_original, frozenset()) != M._comparable(base, frozenset()):
                ctype, why = "cache-deception-candidate", \
                    "an unauthenticated request got the authenticated page back from the cache via a static-looking suffix"
    elif fam == "race" and race:
        if race.get("ok", 0) >= 2 and not race.get("idempotent") and readback == "persisted":
            ctype, why = "race-candidate", f"{race['ok']} of {race['n']} parallel copies succeeded and the state persisted"
            extra = {"race": race}
    if ctype is None:
        return []
    return [_cand(variant, ctype, why, base, var, readback=readback, d=d, single=single_value_resp,
                  recorded_values=recorded_values, extra=extra)]


def _is_get_variant(variant: M.Variant) -> bool:
    """A method variant is GET-class when it never leaves GET/HEAD."""
    verbs = {str(x.value).upper() for x in variant.xforms if x.kind in ("method", "override")}
    return bool(verbs) and verbs <= {"GET", "HEAD"}
