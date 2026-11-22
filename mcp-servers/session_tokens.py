"""Find and patch SPA token entries inside a browser-mcp session_file (pure).

A session_file is a Playwright storage_state ({cookies, origins[].localStorage})
plus browser_confirm's sessionStorage sidecar ({origin: {key: value}}). Two
common SPA token-cache shapes are recognised:

- oidc-client-ts / oidc-client-js: key ``oidc.user:<authority>:<client_id>``,
  value = User JSON {access_token, id_token, refresh_token?, expires_at, ...}
- auth0-spa-js: key ``@@auth0spajs@@::<client_id>::<audience>::<scope>``,
  value = {"body": {access_token, id_token, refresh_token?, ...}, "expiresAt"}

Everything here is in-process only: callers must never return token values to
the agent. JWTs are decoded WITHOUT verification, only to read ``exp``/``iss``.
"""

from __future__ import annotations

import base64
import copy
import json
from dataclasses import dataclass
from typing import Literal

SESSION_STORAGE_KEY = "huntmcp_session_storage"  # == browser_confirm.SESSION_STORAGE_KEY

_OIDC_PREFIX = "oidc.user:"
_AUTH0_PREFIX = "@@auth0spajs@@::"


def jwt_claims(token: str) -> dict | None:
    """Unverified JWT payload, or None if token is not a decodable JWT."""
    if not isinstance(token, str) or token.count(".") != 2:
        return None
    part = token.split(".")[1]
    try:
        data = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def jwt_exp(token: str) -> float | None:
    claims = jwt_claims(token)
    exp = (claims or {}).get("exp")
    return float(exp) if isinstance(exp, (int, float)) else None


@dataclass
class TokenEntry:
    origin: str
    store: Literal["local", "session"]
    key: str
    shape: Literal["oidc-client-ts", "auth0-spa-js"]
    issuer: str | None
    client_id: str | None
    refresh_token: str | None
    access_exp: float | None


def _parse(origin: str, store: str, key: str, value: str) -> TokenEntry | None:
    try:
        data = json.loads(value)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if key.startswith(_OIDC_PREFIX):
        rest = key[len(_OIDC_PREFIX):]
        authority, sep, client_id = rest.rpartition(":")
        if not sep or not authority or not isinstance(data.get("access_token"), str):
            return None
        exp = data.get("expires_at")
        access_exp = float(exp) if isinstance(exp, (int, float)) else jwt_exp(data["access_token"])
        return TokenEntry(origin, store, key, "oidc-client-ts", authority, client_id,
                          data.get("refresh_token") or None, access_exp)
    if key.startswith(_AUTH0_PREFIX):
        body = data.get("body")
        if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
            return None
        client_id = key[len(_AUTH0_PREFIX):].split("::", 1)[0] or None
        issuer = (jwt_claims(body.get("id_token") or "") or {}).get("iss")
        exp = data.get("expiresAt")
        access_exp = float(exp) if isinstance(exp, (int, float)) else jwt_exp(body["access_token"])
        return TokenEntry(origin, store, key, "auth0-spa-js", issuer if isinstance(issuer, str) else None,
                          client_id, body.get("refresh_token") or None, access_exp)
    return None


def _iter_items(state: dict):
    for o in state.get("origins") or []:
        if not isinstance(o, dict):
            continue
        for item in o.get("localStorage") or []:
            if isinstance(item, dict) and isinstance(item.get("name"), str) and isinstance(item.get("value"), str):
                yield o.get("origin", ""), "local", item["name"], item["value"]
    side = state.get(SESSION_STORAGE_KEY) or {}
    if isinstance(side, dict):
        for origin, kv in side.items():
            if isinstance(kv, dict):
                for k, v in kv.items():
                    if isinstance(k, str) and isinstance(v, str):
                        yield origin, "session", k, v


def find_token_entries(state: dict) -> list[TokenEntry]:
    out = []
    for origin, store, key, value in _iter_items(state or {}):
        entry = _parse(origin, store, key, value)
        if entry is not None:
            out.append(entry)
    return out


def _new_exp(resp: dict, now: float) -> int | None:
    exp = jwt_exp(resp.get("access_token") or "")
    if exp is None and isinstance(resp.get("expires_in"), (int, float)):
        exp = now + resp["expires_in"]
    return int(exp) if exp is not None else None


def _patched_value(entry: TokenEntry, value: str, resp: dict, now: float) -> str:
    data = json.loads(value)
    exp = _new_exp(resp, now)
    if entry.shape == "oidc-client-ts":
        target = data
        for k in ("access_token", "id_token", "refresh_token", "token_type", "scope"):
            if resp.get(k):
                target[k] = resp[k]
        if exp is not None:
            target["expires_at"] = exp
    else:
        body = data.setdefault("body", {})
        for k in ("access_token", "id_token", "refresh_token", "token_type", "scope", "expires_in"):
            if resp.get(k):
                body[k] = resp[k]
        if exp is not None:
            data["expiresAt"] = exp
    return json.dumps(data)


def apply_token_response(state: dict, entry: TokenEntry, resp: dict, now: float) -> dict:
    """Return a NEW state with only `entry` updated from a token-endpoint
    response (same shape; the old refresh_token is kept if none is returned)."""
    out = copy.deepcopy(state)
    if entry.store == "session":
        kv = out[SESSION_STORAGE_KEY][entry.origin]
        kv[entry.key] = _patched_value(entry, kv[entry.key], resp, now)
        return out
    for o in out.get("origins") or []:
        if o.get("origin") != entry.origin:
            continue
        for item in o.get("localStorage") or []:
            if item.get("name") == entry.key:
                item["value"] = _patched_value(entry, item["value"], resp, now)
                return out
    raise KeyError(entry.key)


def earliest_access_exp(state: dict, authorization: str | None, after: float | None = None) -> float | None:
    """Earliest access-token expiry; with `after`, ignore already-expired ones
    (a stale leftover entry must not drive the refresh schedule)."""
    exps = [e.access_exp for e in find_token_entries(state) if e.access_exp is not None]
    if authorization and authorization.lower().startswith("bearer "):
        exp = jwt_exp(authorization[7:].strip())
        if exp is not None:
            exps.append(exp)
    if after is not None:
        exps = [e for e in exps if e > after]
    return min(exps) if exps else None
