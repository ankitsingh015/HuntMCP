"""Spec 3a (UI-walk request mutation): PURE logic, no browser, no network.

- the request model: parse a recorded request into parameters (query, form,
  JSON incl. nested, multipart text fields) and apply mutation ops to it;
- the effective method (method-override headers / `_method` params);
- (later tasks) the per-request profiler + ranked plan, the send gates and
  ownership rule, and the comparator + candidate rules.

Values only ever exist in memory here. A request value the replay store
withheld (password, OTP, ...) arrives as WITHHELD and is never sent as-is.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field, replace
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

WITHHELD = "<hm-withheld>"

OVERRIDE_HEADERS = ("x-http-method-override", "x-http-method", "x-method-override")
MAX_JSON_DEPTH = 5


@dataclass
class Param:
    location: str          # "query" | "form" | "json" | "multipart"
    path: tuple            # (name,) or a JSON key path (str keys, int list indexes)
    value: object
    withheld: bool = False


@dataclass
class Req:
    replay_id: str
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: str | None = None
    body_kind: str = "none"   # "none" | "json" | "form" | "multipart" | "unparsed"
    source: str = ""


@dataclass
class Op:
    kind: str              # add_param | remove_param | duplicate_param | retype_param | set_param
    location: str
    path: tuple
    value: object = None
    order: str = "orig_first"   # duplicate only: "orig_first" | "new_first"
    style: str = "repeat"       # duplicate only (query/form): "repeat" | "brackets"


# -- helpers -------------------------------------------------------------------
def header(headers: dict, name: str) -> str | None:
    n = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == n:
            return v
    return None


def _boundary(headers: dict) -> str | None:
    ct = header(headers, "content-type") or ""
    m = re.search(r'boundary="?([^";]+)"?', ct, re.IGNORECASE)
    return m.group(1) if m else None


def body_kind_of(headers: dict, body: str | None) -> str:
    if not body:
        return "none"
    ct = (header(headers, "content-type") or "").lower()
    if "multipart/form-data" in ct:
        return "multipart" if _boundary(headers) else "unparsed"
    if "x-www-form-urlencoded" in ct:
        return "form"
    if "json" in ct or not ct:
        try:
            obj = json.loads(body)
        except (ValueError, RecursionError):
            return "unparsed"
        return "json" if isinstance(obj, (dict, list)) else "unparsed"
    return "unparsed"


def _qs_pairs(s: str) -> list[tuple[str, str]]:
    return parse_qsl(s or "", keep_blank_values=True)


def _with_query(url: str, pairs: list[tuple[str, str]]) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), p.fragment))


def _scalar_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


# -- multipart ---------------------------------------------------------------
_CD_NAME = re.compile(r'name="([^"]*)"', re.IGNORECASE)
_CD_FILE = re.compile(r'filename="', re.IGNORECASE)


def _mp_parts(body: str, boundary: str) -> list[dict]:
    """[{"name", "file": bool, "head": str, "content": str}] -- raw part text kept."""
    out = []
    delim = "--" + boundary
    for chunk in body.split(delim)[1:]:
        if chunk.startswith("--"):
            break
        chunk = chunk.removeprefix("\r\n")
        chunk = chunk.removesuffix("\r\n")
        head, sep, content = chunk.partition("\r\n\r\n")
        if not sep:
            continue
        m = _CD_NAME.search(head)
        out.append({"name": m.group(1) if m else "", "file": bool(_CD_FILE.search(head)),
                    "head": head, "content": content})
    return out


def _mp_build(parts: list[dict], boundary: str) -> str:
    delim = "--" + boundary
    return "".join(f"{delim}\r\n{p['head']}\r\n\r\n{p['content']}\r\n" for p in parts) + f"{delim}--\r\n"


def _mp_text(name: str, value) -> dict:
    return {"name": name, "file": False, "head": f'Content-Disposition: form-data; name="{name}"',
            "content": _scalar_str(value)}


# -- JSON --------------------------------------------------------------------
def _json_leaves(node, path=(), depth=0):
    if depth > MAX_JSON_DEPTH:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, (dict, list)) and v:
                yield from _json_leaves(v, (*path, k), depth + 1)
            else:
                yield (*path, k), v
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, (dict, list)) and v:
                yield from _json_leaves(v, (*path, i), depth + 1)
            else:
                yield (*path, i), v


def _json_parent(obj, path: tuple):
    node = obj
    for seg in path[:-1]:
        node = node[seg]
    return node


def _dump_with_dup(node, target: tuple, value, order: str, path=()) -> str:
    """json.dumps, except the key at `target` is emitted twice (raw text)."""
    if isinstance(node, dict):
        items = []
        for k, v in node.items():
            here = f"{json.dumps(str(k))}: {_dump_with_dup(v, target, value, order, (*path, k))}"
            if (*path, k) == target:
                extra = f"{json.dumps(str(k))}: {json.dumps(value)}"
                items.extend([here, extra] if order == "orig_first" else [extra, here])
            else:
                items.append(here)
        return "{" + ", ".join(items) + "}"
    if isinstance(node, list):
        return "[" + ", ".join(_dump_with_dup(v, target, value, order, (*path, i))
                               for i, v in enumerate(node)) + "]"
    return json.dumps(node)


# -- public API ----------------------------------------------------------------
def parse_params(req: Req) -> list[Param]:
    out = [Param("query", (k,), v, v == WITHHELD) for k, v in _qs_pairs(urlsplit(req.url).query)]
    if req.body_kind == "form":
        out += [Param("form", (k,), v, v == WITHHELD) for k, v in _qs_pairs(req.body or "")]
    elif req.body_kind == "json":
        try:
            obj = json.loads(req.body or "")
        except (ValueError, RecursionError):
            obj = None
        if obj is not None:
            out += [Param("json", p, v, v == WITHHELD) for p, v in _json_leaves(obj)]
    elif req.body_kind == "multipart":
        b = _boundary(req.headers)
        if b:
            out += [Param("multipart", (p["name"],), p["content"], p["content"] == WITHHELD)
                    for p in _mp_parts(req.body or "", b) if not p["file"] and p["name"]]
    return out


def _apply_pairs(pairs: list[tuple[str, str]], op: Op) -> list[tuple[str, str]]:
    name = op.path[0]
    if op.kind == "add_param":
        return [*pairs, (name, _scalar_str(op.value))]
    if op.kind == "remove_param":
        return [(k, v) for k, v in pairs if k != name]
    if op.kind == "set_param":
        return [(k, _scalar_str(op.value) if k == name else v) for k, v in pairs]
    if op.kind == "retype_param":
        out = []
        for k, v in pairs:
            if k != name:
                out.append((k, v))
            elif isinstance(op.value, list):
                out.extend((f"{k}[]", _scalar_str(x)) for x in op.value)
            elif isinstance(op.value, dict):
                out.extend((f"{k}[{kk}]", _scalar_str(vv)) for kk, vv in op.value.items())
            else:
                out.append((k, _scalar_str(op.value)))
        return out
    if op.kind == "duplicate_param":
        new = _scalar_str(op.value)
        out = []
        for k, v in pairs:
            if k != name:
                out.append((k, v))
                continue
            kk = f"{k}[]" if op.style == "brackets" else k
            out.extend([(kk, v), (kk, new)] if op.order == "orig_first" else [(kk, new), (kk, v)])
        return out
    raise ValueError(f"unknown op {op.kind!r}")


def _apply_json(body: str, op: Op) -> str:
    obj = json.loads(body)
    if op.kind == "duplicate_param":
        return _dump_with_dup(obj, tuple(op.path), op.value, op.order)
    parent = _json_parent(obj, op.path)
    key = op.path[-1]
    if op.kind == "remove_param":
        if isinstance(parent, dict):
            parent.pop(key, None)
        elif isinstance(parent, list) and isinstance(key, int) and key < len(parent):
            parent.pop(key)
    elif op.kind in ("add_param", "set_param", "retype_param"):
        parent[key] = copy.deepcopy(op.value)
    else:
        raise ValueError(f"unknown op {op.kind!r}")
    return json.dumps(obj)


def _apply_multipart(body: str, boundary: str, op: Op) -> str:
    parts = _mp_parts(body, boundary)
    name = op.path[0]
    if op.kind == "add_param":
        parts.append(_mp_text(name, op.value))
    elif op.kind == "remove_param":
        parts = [p for p in parts if p["file"] or p["name"] != name]
    elif op.kind in ("set_param", "retype_param"):
        for p in parts:
            if not p["file"] and p["name"] == name:
                p["content"] = op.value if isinstance(op.value, str) else json.dumps(op.value)
    elif op.kind == "duplicate_param":
        out = []
        for p in parts:
            out.append(p)
            if not p["file"] and p["name"] == name:
                if op.order == "orig_first":
                    out.append(_mp_text(name, op.value))
                else:
                    out.insert(len(out) - 1, _mp_text(name, op.value))
        parts = out
    else:
        raise ValueError(f"unknown op {op.kind!r}")
    return _mp_build(parts, boundary)


def apply_ops(req: Req, ops: list[Op]) -> Req:
    """A NEW Req with every op applied in order (the input is never changed)."""
    url, body = req.url, req.body
    for op in ops:
        if op.location == "query":
            url = _with_query(url, _apply_pairs(_qs_pairs(urlsplit(url).query), op))
        elif op.location == "form":
            body = urlencode(_apply_pairs(_qs_pairs(body or ""), op))
        elif op.location == "json":
            body = _apply_json(body or "{}", op)
        elif op.location == "multipart":
            b = _boundary(req.headers)
            if not b:
                raise ValueError("multipart op on a request without a boundary")
            body = _apply_multipart(body or "", b, op)
        else:
            raise ValueError(f"unknown location {op.location!r}")
    return replace(req, url=url, body=body, headers=dict(req.headers))


def effective_method(req: Req) -> str:
    """The method the server may act on: an override header, or a `_method`
    in the query / form / top-level JSON body, wins over the request line."""
    for h in OVERRIDE_HEADERS:
        v = header(req.headers, h)
        if v and str(v).strip():
            return str(v).strip().upper()
    for k, v in _qs_pairs(urlsplit(req.url).query):
        if k == "_method" and v.strip():
            return v.strip().upper()
    if req.body_kind == "form":
        for k, v in _qs_pairs(req.body or ""):
            if k == "_method" and v.strip():
                return v.strip().upper()
    elif req.body_kind == "json":
        try:
            obj = json.loads(req.body or "")
        except (ValueError, RecursionError):
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("_method"), str) and obj["_method"].strip():
            return obj["_method"].strip().upper()
    return (req.method or "GET").upper()


# =============================================================================
# Task 3: request profile + ranked, request-specific plan
# =============================================================================
import hashlib
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from endpoint_template import endpoint_template

PRIV_FIELDS = ("role", "roles", "admin", "is_admin", "isAdmin", "permissions", "user_id", "userId",
               "owner_id", "account_id", "email_verified", "verified", "status", "plan", "tier",
               "price", "amount", "discount", "credits", "balance")
CHECK_FIELD_RE = re.compile(
    r"(?i)^(otp|code|mfa|totp|captcha|csrf|_token|xsrf|old_password|current_password|signature|sig|hmac|nonce"
    r"|[a-z0-9_-]*(?:otp|captcha|csrf|xsrf)[a-z0-9_-]*)$")
ID_NAME_RE = re.compile(r"(?i)(^id$|_id$|[a-z]Id$|^uid$|^to$|^from$|user|account|owner|recipient)")
ID_VALUE_RE = re.compile(r"^(?:[A-Za-z]{0,4}-?\d+|[0-9a-fA-F-]{8,})$")
NUMERIC_EDGES = (-1, 0, 0.0001, 1e9, 2147483648, 9007199254740993, "-0", "1 ")
FAMILY_ORDER = ("add", "remove", "duplicate", "retype", "numeric-edge")
MAX_FOREIGN_IDS = 3


@dataclass
class Variant:
    variant_id: str
    replay_id: str
    family: str
    ops: list
    reason: str
    score: int
    origin: str = "rule"   # "rule" | "agent"


@dataclass
class Context:
    response_keys: dict = field(default_factory=dict)   # route template -> JSON keys seen in GET responses
    sibling_fields: dict = field(default_factory=dict)  # route template -> field names other requests send
    foreign_ids: set = field(default_factory=set)       # object ids seen in the walk, not ours


def _vid(replay_id: str, ops: list) -> str:
    raw = json.dumps([replay_id, [[o.kind, o.location, list(o.path), o.value, o.order, o.style] for o in ops]],
                     sort_keys=True, default=str)
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def _leaf(path: tuple) -> str:
    return str(path[-1]) if path else ""


def is_check_field(name: str) -> bool:
    return bool(CHECK_FIELD_RE.match(name or ""))


def is_id_param(p: Param) -> bool:
    if ID_NAME_RE.search(_leaf(p.path)):
        return True
    v = p.value
    if not isinstance(v, str):
        return False
    if v.isdigit():
        return len(v) >= 3   # short numbers are counts/flags, not object ids
    return bool(ID_VALUE_RE.match(v))


def _is_number(v) -> bool:
    return (isinstance(v, (int, float)) and not isinstance(v, bool)) or (isinstance(v, str) and v.isdigit())


def _plausible(name: str):
    n = name.lower()
    if n == "roles":
        return ["admin"]
    if n == "role":
        return "admin"
    if n in ("admin", "is_admin", "isadmin", "verified", "email_verified"):
        return True
    if n == "permissions":
        return ["*"]
    if n == "status":
        return "active"
    if n in ("plan", "tier"):
        return "enterprise"
    if n in ("price", "amount"):
        return 0
    if n == "discount":
        return 100
    if n in ("credits", "balance"):
        return 999999
    return "hm-test"


def _body_location(req: Req) -> str:
    return {"json": "json", "form": "form", "multipart": "multipart"}.get(req.body_kind, "query")


def build_plan(req: Req, ctx: Context, *, max_variants: int = 40, max_per_family: int = 10) -> list[Variant]:
    """Variants that fit THIS request, each with a reason, best first."""
    params = parse_params(req)
    tmpl = endpoint_template(req.url)
    is_get = (req.method or "GET").upper() in ("GET", "HEAD")
    sent = {str(p.path[0]) for p in params}
    loc = _body_location(req)
    foreign = sorted(str(i) for i in (ctx.foreign_ids or ()))[:MAX_FOREIGN_IDS] if is_get else []
    out: list[Variant] = []

    def emit(family: str, ops: list, reason: str, score: int) -> None:
        out.append(Variant(_vid(req.replay_id, ops), req.replay_id, family, ops, reason, score))

    # add (mass assignment)
    resp_keys = set((ctx.response_keys or {}).get(tmpl, ()))
    sib = set((ctx.sibling_fields or {}).get(tmpl, ()))
    seen_add: set[str] = set()
    for names, score, why in (
            (sorted(resp_keys - sent), 90, "`{n}` is in a response of this resource but never sent by the UI"),
            (sorted(sib - sent), 70, "`{n}` is sent by another request to this resource but not by this one"),
            ([n for n in PRIV_FIELDS if n not in sent], 50, "`{n}` is a privilege/ownership/price field the UI does not send")):
        for n in names:
            if n in seen_add:
                continue
            seen_add.add(n)
            if ID_NAME_RE.search(n) and not is_get:
                continue   # spec decision 5: no foreign ids in non-GET variants
            if ID_NAME_RE.search(n) and is_get:
                for fid in foreign:
                    emit("add", [Op("add_param", loc, (n,), fid)], why.format(n=n) + " (another object's id)", score)
                continue
            emit("add", [Op("add_param", loc, (n,), _plausible(n))], why.format(n=n), score)

    for p in params:
        name = _leaf(p.path)
        check = is_check_field(name)
        idp = is_id_param(p)
        # remove (missing-check bypass); a withheld value only ever gets these
        if check or p.withheld:
            base = 85 if check else 60
            what = "looks like a check field" if check else "holds a withheld secret value"
            emit("remove", [Op("remove_param", p.location, p.path)], f"`{name}` {what}: drop it", base)
            emit("remove", [Op("set_param", p.location, p.path, "")], f"`{name}` {what}: send it empty", base - 5)
            emit("remove", [Op("set_param", p.location, p.path, None)], f"`{name}` {what}: send it as null",
                 base - 5)
        if p.withheld:
            continue
        # set a foreign id on a GET (read-only IDOR-style lead)
        if is_get and idp:
            for fid in foreign:
                if fid != p.value:
                    emit("add", [Op("set_param", p.location, p.path, fid)],
                         f"`{name}` looks like an object id: try another object's id", 60)
        # duplicate (HPP)
        dscore = 75 if (check or idp) else 40
        dvals = [f for f in foreign if f != p.value] or ["hm-dup"]
        for dv in dvals:
            for order in ("orig_first", "new_first"):
                emit("duplicate", [Op("duplicate_param", p.location, p.path, dv, order=order)],
                     f"`{name}` sent twice ({order.replace('_', ' ')}): which copy does each layer use?", dscore)
        if p.location in ("query", "form"):
            emit("duplicate", [Op("duplicate_param", p.location, p.path, dvals[0], style="brackets")],
                 f"`{name}` as an array (`{name}[]`) with two values", dscore - 5)
        # retype (type juggling)
        rscore = 70 if (check or idp) else 30
        if p.location in ("query", "form"):
            types = [[p.value]]
        else:
            types = [0 if not _is_number(p.value) else str(p.value), [p.value], {}, None, True]
        if check and isinstance(p.value, str):
            types.append("0e1")
        for t in types:
            emit("retype", [Op("retype_param", p.location, p.path, t)],
                 f"`{name}` as {type(t).__name__ if t is not None else 'null'} instead of {type(p.value).__name__}",
                 rscore)
        # numeric edges
        if _is_number(p.value):
            for e in NUMERIC_EDGES:
                v = e if p.location in ("json",) and not isinstance(p.value, str) else str(e)
                emit("numeric-edge", [Op("set_param", p.location, p.path, v)],
                     f"`{name}` is numeric: edge value {e!r}", 45)

    uniq: dict[str, Variant] = {}
    for v in out:
        uniq.setdefault(v.variant_id, v)
    ranked = sorted(uniq.values(), key=lambda v: (-v.score, FAMILY_ORDER.index(v.family)))
    per: dict[str, int] = {}
    plan: list[Variant] = []
    for v in ranked:
        if per.get(v.family, 0) >= max_per_family:
            continue
        per[v.family] = per.get(v.family, 0) + 1
        plan.append(v)
        if len(plan) >= max_variants:
            break
    return plan


# =============================================================================
# Task 4: send gates, ownership, agent-op validation
# =============================================================================
import ui_walk_grant
import ui_walk_logic as _L
import ui_walk_sso_logic as _S
from endpoint_template import _is_id_like

OWN_ACCOUNT_SEGMENTS = ("me", "self", "profile", "account", "accounts", "settings", "preferences", "user")
SHARED_SEGMENTS = ("org", "orgs", "organization", "team", "teams", "workspace", "workspaces", "tenant",
                   "tenants", "project", "projects", "group", "groups", "company", "companies")
NEVER_CLASSES = ("logout", "account-delete", "payment")
_HEX8_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
AGENT_OPS = {"add_param": "add", "set_param": "add", "remove_param": "remove",
             "duplicate_param": "duplicate", "retype_param": "retype"}
AGENT_LOCATIONS = ("query", "form", "json", "multipart")
MAX_AGENT_VALUE = 2048
_BAD_CHARS = ("\r", "\n", "\x00")


@dataclass
class Ownership:
    owned: bool
    kind: str    # "created" | "own-account" | "none"
    reason: str


@dataclass
class Gate:
    send: bool
    needs_grant: bool
    reason: str


def _segments(url: str) -> list[str]:
    return [s for s in urlsplit(url).path.split("/") if s]


def _id_segment(seg: str) -> bool:
    return _is_id_like(seg) or seg.isdigit() or bool(_HEX8_RE.match(seg))


def own_account_route(url: str) -> bool:
    segs = [s.lower() for s in _segments(url)]
    if not any(s in OWN_ACCOUNT_SEGMENTS for s in segs):
        return False
    if any(s in SHARED_SEGMENTS for s in segs):
        return False
    return not any(_id_segment(s) for s in _segments(url))


def _request_values(req: Req) -> list[str]:
    """Values in an id POSITION only: path segments and id-named params (review
    fix: a short created id like "1" must not match page=1 or qty=1)."""
    vals = list(_segments(req.url))
    vals += [str(p.value) for p in parse_params(req)
             if isinstance(p.value, (str, int)) and not isinstance(p.value, bool) and ID_NAME_RE.search(_leaf(p.path))]
    return vals


def carries_foreign_id(ops: list, *, foreign_ids: set, created: set, self_ids: set) -> bool:
    """Spec decision 5 for EVERY non-GET variant (rule- or agent-built): no
    value seen on another object, and no id-named field set to an id that is
    neither walker-created nor the identity's own."""
    ours = {str(i) for i in (created or ())} | {str(i) for i in (self_ids or ())}
    for op in ops:
        vals = op.value if isinstance(op.value, list) else [op.value]
        for v in vals:
            if isinstance(v, bool) or not isinstance(v, (str, int)):
                continue
            sv = str(v)
            if sv in {str(f) for f in (foreign_ids or ())} and sv not in ours:
                return True
            if op.kind != "remove_param" and ID_NAME_RE.search(_leaf(op.path)) and sv and sv not in ours:
                return True
    return False


def attribute_readback(readback: str, changed, baseline_changed) -> str:
    """'persisted' only when the read-back shows a change beyond what the
    unmodified baseline request itself changes (review fix)."""
    if readback != "persisted":
        return readback
    return "persisted" if set(changed or ()) - set(baseline_changed or ()) else "not-persisted"


_BLOCK_BODY_RE = re.compile(r"(?i)cloudflare|akamai|imperva|incapsula|sucuri|attack detected|request blocked"
                            r"|captcha|bot protection")


def is_block_signal(status: int, body: str) -> bool:
    """A real block (stop the host) vs an ordinary authz denial (a result):
    429 always; 403/503 only with a WAF / bot-protection signature in a
    non-JSON body."""
    if status == 429:
        return True
    if status not in (403, 503):
        return False
    text = (body or "")[:20000]
    try:
        json.loads(text)
        return False
    except (ValueError, RecursionError):
        pass
    return bool(_BLOCK_BODY_RE.search(text))


def ownership(req: Req, created_ids: set, self_ids: set, snapshot_has_self_id: bool | None) -> Ownership:
    """Spec 'Ownership': walker-created (exact id match) or the narrow own-account rule."""
    if created_ids:
        hit = sorted(set(_request_values(req)) & {str(i) for i in created_ids})
        if hit:
            return Ownership(True, "created", f"carries walker-created id {hit[0]}")
    if own_account_route(req.url):
        if not self_ids:
            return Ownership(False, "none", "own-account route, but no self id was learned during the walk")
        if snapshot_has_self_id is True:
            return Ownership(True, "own-account", "own-account route whose snapshot holds the identity's id")
        return Ownership(False, "none", "own-account route, but its snapshot does not show the identity's id")
    return Ownership(False, "none", "not walker-created and not the identity's own account")


def never_mutated(url: str, classification: str | None = None) -> bool:
    if classification in NEVER_CLASSES:
        return True
    if _L.is_payment_host(urlsplit(url).hostname or ""):
        return True
    if _S.is_logout_endpoint(url) or any(s.lower() in ("logout", "signout", "sign-out", "log-out")
                                         for s in _segments(url)):
        return True
    return _S.classify_url(url) is not None


def gate(variant_req: Req, *, scope, grant, owned: Ownership, has_restore_path: bool,
         never_mutated: bool) -> Gate:
    """May this variant be SENT? Order: payment > scope > never-mutated >
    effective method (GET: mutating-URL block; non-GET: grant, host, owned,
    restore path)."""
    url = variant_req.url
    host = urlsplit(url).hostname or ""
    if _L.is_payment_host(host):
        return Gate(False, False, "payment-host")
    if not scope(url):
        return Gate(False, False, "out-of-scope")
    if never_mutated:
        return Gate(False, False, "never-mutated")
    method = effective_method(variant_req)
    if method in ("GET", "HEAD") and (variant_req.method or "GET").upper() in ("GET", "HEAD"):
        if _L.is_mutating_get_url(url):
            return Gate(False, False, "mutating-get")
        return Gate(True, False, "ok")
    if grant is None or getattr(grant, "canary_submit", False) is not True:
        return Gate(False, True, "needs grant")
    if not ui_walk_grant.grant_allows(grant, host):
        return Gate(False, True, "host-not-granted")
    if not owned.owned:
        return Gate(False, True, "not-owned")
    if not has_restore_path:
        return Gate(False, True, "no restore path")
    return Gate(True, True, "ok")


def _clean_text(s) -> bool:
    return isinstance(s, str) and not any(c in s for c in _BAD_CHARS)


def _clean_value(v) -> bool:
    if isinstance(v, str):
        return _clean_text(v)
    if isinstance(v, list):
        return all(_clean_value(x) for x in v)
    if isinstance(v, dict):
        return all(_clean_text(k) and _clean_value(x) for k, x in v.items())
    return v is None or isinstance(v, (bool, int, float))


def validate_agent_ops(raw: list, known_replay_ids: set) -> tuple[list[Variant], list[str]]:
    """The agent's extra variants (approach C), each one op. Rejected items get
    a message; accepted ones still pass gate() like any rule variant."""
    ok: list[Variant] = []
    errs: list[str] = []
    for i, item in enumerate(raw or []):
        if not isinstance(item, dict):
            errs.append(f"#{i}: not an object")
            continue
        rid, kind = item.get("replay_id"), item.get("op")
        if rid not in known_replay_ids:
            errs.append(f"#{i}: unknown replay_id")
            continue
        if kind not in AGENT_OPS:
            errs.append(f"#{i}: op {str(kind)[:40]!r} is not available (3a ops: {', '.join(sorted(AGENT_OPS))})")
            continue
        loc, path = item.get("location"), item.get("path")
        if loc not in AGENT_LOCATIONS:
            errs.append(f"#{i}: location must be one of {', '.join(AGENT_LOCATIONS)}")
            continue
        if not isinstance(path, list) or not path or len(path) > MAX_JSON_DEPTH + 1 or not all(
                (isinstance(s, int) and not isinstance(s, bool)) or (_clean_text(s) and 0 < len(s) <= 256)
                for s in path):
            errs.append(f"#{i}: bad path")
            continue
        value = item.get("value")
        try:
            size = len(json.dumps(value))
        except (TypeError, ValueError):
            errs.append(f"#{i}: value is not JSON")
            continue
        if size > MAX_AGENT_VALUE or not _clean_value(value):
            errs.append(f"#{i}: value too long or contains CR/LF/NUL")
            continue
        order = item.get("order", "orig_first")
        style = item.get("style", "repeat")
        if order not in ("orig_first", "new_first") or style not in ("repeat", "brackets"):
            errs.append(f"#{i}: bad order/style")
            continue
        op = Op(kind, loc, tuple(path), value, order=order, style=style)
        reason = str(item.get("reason") or "agent-added")[:200]
        ok.append(Variant(_vid(rid, [op]), rid, AGENT_OPS[kind], [op], "agent: " + reason, 100, origin="agent"))
    return ok, errs


# =============================================================================
# Task 5: comparator + candidate rules (leads, never confirmed)
# =============================================================================
import authz_diff as _AD
import redact as _redact

MAX_BODY_IN_MEMORY = 256 * 1024
EXCERPT_CHARS = 400
ERROR_RE = re.compile(
    r"(Traceback \(most recent call last\)|\b[A-Z][A-Za-z]*(Error|Exception)\b|stack trace|SQL syntax|SQLSTATE|"
    r"ORA-\d{5}|NullPointer|at [a-z]+\.[a-z]+\.[A-Za-z]+\(|Unexpected token|JSON\.parse|invalid literal)")


@dataclass
class Resp:
    status: int
    length: int
    body: str
    json_keys: frozenset | None


def resp_from(status: int, body: str | None) -> Resp:
    text = (body or "")[:MAX_BODY_IN_MEMORY]
    keys = None
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            keys = frozenset(str(k) for k in obj)
    except (ValueError, RecursionError):
        pass
    return Resp(int(status or 0), len(body or ""), text, keys)


@dataclass
class Diff:
    status_changed: bool
    class_change: str | None
    length_delta: int
    significant_length: bool
    keys_added: list
    keys_removed: list
    reflected: bool
    error_signature: bool


def _cls(status: int) -> str:
    return f"{status // 100}xx" if status else "none"


def noise(b1: Resp, b2: Resp) -> dict:
    l1, l2 = _AD._json_leaves(b1.body), _AD._json_leaves(b2.body)
    vol = frozenset()
    if l1 is not None and l2 is not None:
        vol = frozenset(p for p in l1.keys() | l2.keys() if l1.get(p, _AD._MISSING) != l2.get(p, _AD._MISSING))
    return {"volatile": vol, "length_tol": max(32, abs(b1.length - b2.length) * 2)}


def _comparable(r: Resp, vol: frozenset) -> str:
    leaves = _AD._json_leaves(r.body)
    return r.body if leaves is None else _AD._masked_dump(leaves, vol)


def diff(base: Resp, var: Resp, nz: dict, injected: list) -> Diff:
    cb, cv = _cls(base.status), _cls(var.status)
    delta = var.length - base.length
    bk, vk = base.json_keys or frozenset(), var.json_keys or frozenset()
    sig_len = abs(delta) > nz.get("length_tol", 32) and _comparable(base, nz.get("volatile", frozenset())) \
        != _comparable(var, nz.get("volatile", frozenset()))
    inj = [str(i) for i in injected if i is not None and str(i) and len(str(i)) >= 3]
    reflected = any(i in var.body and i not in base.body for i in inj)
    return Diff(base.status != var.status, None if cb == cv else f"{cb}->{cv}", delta, sig_len,
                sorted(vk - bk), sorted(bk - vk), reflected,
                var.status >= 500 or bool(ERROR_RE.search(var.body[:20000])))


def _excerpt(base: Resp, var: Resp, recorded_values) -> str:
    a, b = base.body, var.body
    i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b)))
    start = max(0, i - EXCERPT_CHARS // 2)
    text = _redact.redact_text(b[start:start + EXCERPT_CHARS])
    for v in recorded_values or ():
        if isinstance(v, str) and len(v) >= 3:
            text = text.replace(v, "[recorded value]")
    return text


def _ok(r: Resp) -> bool:
    return 200 <= r.status < 300


def _rejected(r: Resp) -> bool:
    return 400 <= r.status < 500


def _persisted_flag(readback: str):
    return {"persisted": True, "not-persisted": False}.get(readback, "unknown" if readback == "unknown" else "n/a")


def candidates_for(variant: Variant, base: Resp, var: Resp, d: Diff, *, readback: str,
                   single_value_resp: Resp | None = None, recorded_values=None) -> list[dict]:
    """0..n candidate dicts for one sent variant. readback: persisted |
    not-persisted | unknown | n/a (a GET: nothing to read back)."""
    fam, why = variant.family, None
    ctype = None
    if fam == "add" and _ok(var):
        if readback == "persisted":
            ctype, why = "mass-assignment-candidate", "the added field persisted (read-back shows it)"
        elif readback == "unknown" and d.reflected:
            ctype, why = "mass-assignment-candidate", "accepted and echoed; persistence could not be read back"
        elif readback == "n/a" and (d.status_changed or d.significant_length or d.keys_added):
            ctype, why = "mass-assignment-candidate", "the response changed when the field was added"
    elif fam == "remove":
        if _rejected(base) and _ok(var):
            ctype, why = "param-removal-bypass-candidate", f"rejected with the field ({base.status}), accepted without it"
        elif _ok(base) and _ok(var) and readback == "persisted":
            ctype, why = "param-removal-bypass-candidate", "accepted without the field and the change persisted"
    elif fam == "duplicate" and _ok(var):
        if single_value_resp is not None and _rejected(single_value_resp):
            ctype, why = "hpp-candidate", ("the second value alone is rejected "
                                           f"({single_value_resp.status}) but passes when duplicated")
        elif single_value_resp is not None and d.reflected and d.significant_length and \
                var.body != single_value_resp.body:
            ctype, why = "hpp-candidate", "duplicated value changes the result versus either single value"
    elif fam == "retype" and _rejected(base) and _ok(var):
        ctype, why = "type-juggling-candidate", f"rejected as sent ({base.status}), accepted with another type"
    elif fam == "numeric-edge":
        if d.error_signature:
            ctype, why = "numeric-edge-candidate", "edge value produced a server error signature"
        elif _ok(var) and readback == "persisted":
            ctype, why = "numeric-edge-candidate", "edge value accepted and persisted"
    if ctype is None:
        return []
    return [{
        "type": ctype, "variant_id": variant.variant_id, "replay_id": variant.replay_id,
        "family": fam, "origin": variant.origin, "reason": why, "persisted": _persisted_flag(readback),
        "change": [{"op": o.kind, "location": o.location, "field": ".".join(str(s) for s in o.path)}
                   for o in variant.ops],
        "evidence": {"base_status": base.status, "variant_status": var.status,
                     "base_length": base.length, "variant_length": var.length,
                     "keys_added": d.keys_added[:20], "keys_removed": d.keys_removed[:20],
                     "single_value_status": single_value_resp.status if single_value_resp else None,
                     "readback": readback, "excerpt": _excerpt(base, var, recorded_values)},
    }]
