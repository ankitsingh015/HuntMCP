"""Spec 3a (request mutation): the replay store + the cumulative send counter.

Mutation needs the REAL values of the requests the walk recorded, so the
walker keeps them here -- and only here:
  data/engagements/<slug>/ui-walk/<walk-id>.replay.json   (0600, atomic)
Never printed by any tool; the inventory carries only `replay_id`s.

Never stored: Cookie / Authorization / Proxy-Authorization header values
(credentials come from session_file at run time) and every value whose
field/header/query NAME looks like a password, OTP/MFA code, card, PIN,
secret or API key -- replaced by mutation_logic.WITHHELD and listed by name
in `withheld_fields`. OAuth/OIDC/SAML (SSO) URLs and callbacks are not
recorded at all (spec 2 values policy; they are never mutated either).

The send counter makes the grant's real_submit_cap_per_walk cumulative over
the walk's own Pass-2 submits plus every run_mutations on that walk, with a
restore-only reserve of max(5, cap // 10).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import file_lock  # noqa: E402
import mutation_logic as M  # noqa: E402
import ui_walk_sso_logic as S  # noqa: E402
import ui_walk_store  # noqa: E402

MAX_BODY = 64 * 1024
MAX_ENTRIES = 2000
MAX_RESPONSE_KEYS = 200
CREDENTIAL_HEADERS = ("cookie", "authorization", "proxy-authorization")
_WITHHELD_WORDS = {"password", "passwd", "pwd", "otp", "totp", "mfa", "cvv", "cvc", "card", "pin", "secret",
                   "apikey", "privatekey", "passcode",
                   # review fix: bearer / refresh / session credentials (spec 1 auth-ish names)
                   "token", "tokens", "session", "sessionid", "sid", "jwt", "bearer", "auth"}
_CSRF_RE = re.compile(r"(?i)(csrf|xsrf)|^_token$")
_WITHHELD_SUBSTR = ("password", "passwd", "secret", "apikey", "api_key", "api-key", "privatekey",
                    "private_key", "cardnumber", "card_number", "otp")
_CACHE_HEADERS = ("age", "x-cache", "x-cache-hits", "cf-cache-status", "x-served-by", "via")
_PROXY_HEADERS = ("via", "x-forwarded-for", "x-forwarded-host", "cf-ray", "x-amz-cf-id", "x-varnish",
                  "x-served-by")
_SELF_ID_KEYS = ("id", "user_id", "userId", "uuid")
_WALK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def is_withheld_name(name: str) -> bool:
    n = str(name or "")
    if _CSRF_RE.search(n):
        return False   # CSRF tokens are kept: replay needs them and they expire
    words = {w.lower() for w in re.split(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])", n) if w}
    if words & _WITHHELD_WORDS:
        return True
    low = n.lower()
    if low in ("otp", "totp"):
        return True
    return any(s in low for s in _WITHHELD_SUBSTR if s != "otp") or bool(re.search(r"(^|[^a-z])otp", low))


def _withhold_pairs(pairs, prefix, withheld):
    out = []
    for k, v in pairs:
        if is_withheld_name(k):
            withheld.append(prefix + k if prefix else k)
            out.append((k, M.WITHHELD))
        else:
            out.append((k, v))
    return out


def _withhold_json(node, path, withheld, depth=0):
    if depth > M.MAX_JSON_DEPTH + 2:
        return node
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            p = (*path, str(k))
            if is_withheld_name(k) and not isinstance(v, (dict, list)):
                withheld.append(".".join(p))
                out[k] = M.WITHHELD
            else:
                out[k] = _withhold_json(v, p, withheld, depth + 1)
        return out
    if isinstance(node, list):
        return [_withhold_json(v, (*path, str(i)), withheld, depth + 1) for i, v in enumerate(node)]
    return node


def _withhold_body(headers: dict, body: str | None, withheld: list) -> str | None:
    if body is None:
        return None
    kind = M.body_kind_of(headers, body)
    if kind == "json":
        return json.dumps(_withhold_json(json.loads(body), (), withheld))
    if kind == "form":
        return urlencode(_withhold_pairs(parse_qsl(body, keep_blank_values=True), "", withheld))
    if kind == "multipart":
        b = M._boundary(headers)
        parts = M._mp_parts(body, b)
        for p in parts:
            if not p["file"] and is_withheld_name(p["name"]):
                withheld.append(p["name"])
                p["content"] = M.WITHHELD
        return M._mp_build(parts, b)
    return body


class ReplayBuffer:
    """In-memory store the walker fills while it runs; to_dict() for saving."""

    def __init__(self, scope, max_entries: int = MAX_ENTRIES):
        self._scope = scope
        self._max = max_entries
        self._entries: list[dict] = []
        self._by_key: dict[tuple[str, str], str] = {}
        self._self_ids: list[str] = []

    def add(self, method: str, url: str, headers: dict, post: str | None, source: str,
            page: str | None, control_signature: str | None) -> str | None:
        try:
            if not isinstance(url, str) or not url.startswith(("http://", "https://")) or not self._scope(url):
                return None
            if S.classify_url(url, method) is not None or S.is_callback_url(url):
                return None
            withheld: list[str] = []
            parts = urlsplit(url)
            pairs = _withhold_pairs(parse_qsl(parts.query, keep_blank_values=True), "", withheld)
            clean_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), "")) \
                if withheld else urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
            hdrs = {}
            for k, v in (headers or {}).items():
                lk = str(k).lower()
                if lk in CREDENTIAL_HEADERS or lk.startswith(":"):
                    continue
                if is_withheld_name(k):
                    withheld.append(str(k))
                    hdrs[str(k)] = M.WITHHELD
                else:
                    hdrs[str(k)] = str(v)
            truncated = False
            body = post
            if body is not None and len(body) > MAX_BODY:
                body, truncated = body[:MAX_BODY], True
            if body is not None and not truncated:
                try:
                    body = _withhold_body(hdrs, body, withheld)
                except (ValueError, KeyError, TypeError):
                    pass
            key = ((method or "GET").upper(), clean_url + "\n" + (body or ""))
            if key in self._by_key:
                return self._by_key[key]
            if len(self._entries) >= self._max:
                return None
            rid = "r" + os.urandom(5).hex()
            self._entries.append({
                "replay_id": rid, "method": key[0], "url": clean_url, "headers": hdrs, "body": body,
                "body_truncated": truncated, "withheld_fields": sorted(set(withheld)), "source": source,
                "page": page, "control_signature": control_signature, "response_keys": [],
                "response_meta": {},
            })
            self._by_key[key] = rid
            self._by_key[(key[0], clean_url)] = self._by_key.get((key[0], clean_url), rid)
            return rid
        except Exception:  # noqa: BLE001 -- recording never affects the walk
            return None

    def note_response(self, method: str, url: str, body: str | None) -> None:
        """Top-level JSON key NAMES of a GET response (and, on an own-account
        route, the identity's id)."""
        try:
            obj = json.loads(body or "")
        except (ValueError, RecursionError, TypeError):
            return
        if not isinstance(obj, dict):
            return
        parts = urlsplit(url)
        clean = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        rid = self._by_key.get(((method or "GET").upper(), clean))
        if rid:
            for e in self._entries:
                if e["replay_id"] == rid:
                    e["response_keys"] = sorted(str(k) for k in obj)[:MAX_RESPONSE_KEYS]
                    break
        if M.own_account_route(url):
            for k in _SELF_ID_KEYS:
                v = obj.get(k)
                if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v) and str(v) not in self._self_ids:
                    self._self_ids.append(str(v))
                    break

    def note_response_meta(self, method: str, url: str, status: int, headers: dict) -> None:
        """Spec 3b: the response status + header NAMES (never values) that decide
        which request-level families fit: cache signals, proxy/CDN signals."""
        try:
            parts = urlsplit(url)
            clean = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
            rid = self._by_key.get(((method or "GET").upper(), clean))
            if not rid:
                return
            low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
            cache = sorted(n for n in _CACHE_HEADERS if n in low)
            cc = low.get("cache-control", "").lower()
            if "public" in cc or "s-maxage" in cc:
                cache.append("cache-control:public")
            proxy = sorted(n for n in low if n in _PROXY_HEADERS or n.startswith("x-akamai"))
            meta = {"status": int(status or 0),
                    "content_type": low.get("content-type", "").split(";")[0].strip().lower()[:60],
                    "cache_signals": cache, "proxy_signals": proxy}
            for e in self._entries:
                if e["replay_id"] == rid:
                    e["response_meta"] = meta
                    break
        except Exception:  # noqa: BLE001 -- recording never affects the walk
            return

    def to_dict(self, walk_id: str, session_file: str | None) -> dict:
        return {"schema": 1, "walk_id": walk_id,
                "session_file_realpath": os.path.realpath(session_file) if session_file else None,
                "self_ids": list(self._self_ids), "entries": [dict(e) for e in self._entries]}

    def summary(self) -> dict:
        return {"entries": len(self._entries),
                "withheld_fields": sorted({f for e in self._entries for f in e["withheld_fields"]})[:50],
                "self_ids_learned": len(self._self_ids)}


def _path(walk_id: str, suffix: str) -> str:
    if not _WALK_ID_RE.match(walk_id or ""):
        raise ValueError(f"invalid walk_id {walk_id!r}")
    return os.path.join(ui_walk_store.walk_dir(), f"{walk_id}{suffix}")


def _write_private(path: str, data) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def save_replay(data: dict) -> str:
    path = _path(str(data.get("walk_id") or ""), ".replay.json")
    _write_private(path, data)
    return path


def load_replay(walk_id: str) -> dict | None:
    try:
        path = _path(walk_id, ".replay.json")
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def delete_replays(walk_ids: list[str] | None = None) -> int:
    d = ui_walk_store.walk_dir()
    n = 0
    try:
        names = os.listdir(d)
    except OSError:
        return 0
    want = None if walk_ids is None else {f"{w}.replay.json" for w in walk_ids if _WALK_ID_RE.match(w or "")}
    for name in names:
        if name.endswith(".replay.json") and (want is None or name in want):
            try:
                os.remove(os.path.join(d, name))
                n += 1
            except OSError:
                pass
    return n


def restore_reserve(cap: int) -> int:
    return max(5, cap // 10)


class SendCounter:
    """Cumulative per-walk count of sent state-changing requests (file-locked)."""

    def __init__(self, walk_id: str):
        self.path = _path(walk_id, ".sendcount.json")

    def _read(self) -> int:
        try:
            with open(self.path) as fh:
                v = json.load(fh).get("used", 0)
            return v if isinstance(v, int) and v >= 0 else 0
        except (OSError, ValueError, AttributeError):
            return 0

    def used(self) -> int:
        with file_lock.locked(self.path):
            return self._read()

    def record(self, n: int) -> None:
        with file_lock.locked(self.path):
            _write_private(self.path, {"used": self._read() + max(0, int(n))})

    def try_take(self, n: int, *, restore: bool, cap: int) -> bool:
        limit = cap if restore else cap - restore_reserve(cap)
        with file_lock.locked(self.path):
            used = self._read()
            if used + n > limit:
                return False
            _write_private(self.path, {"used": used + n})
            return True
