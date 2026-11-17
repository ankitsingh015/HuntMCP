"""P4-M1 Task 1 -- read-only observed-exchange corpus builder.

Assembles the `{identity, resource, action, args, status, body, session,
base_request}` corpus that `invariant_probe.mine_invariants()` consumes, from
ALREADY-CAPTURED data -- no new probing of the target. The primary source is
`burp-import-mcp`'s imported endpoints: a human hunter's authenticated traffic,
the one place real multi-identity requests against the same object instance
actually exist.

Scope discipline (same posture as invariant_probe.py / causal_signature.py):
  * PURE + read-only: no network, no subprocess, no randomness, no writes.
    stdlib + existing project helpers only (redact), no new dependency.
  * Burp stores the request (method/url/headers) but NOT the response body
    (confirmed: burp_endpoints schema has no body column), so `body` is "" and
    the probe degrades to HIGH RECALL on identity/status/repetition; the frozen
    CEM counterfactual stays the precision gate (same design as P4-M0).
  * identity is derived from the Cookie / Authorization header and REDACTED
    (a stable hash label), never the raw secret.
  * each row carries the REAL captured request as `base_request`
    ({method, url, headers, body}) so the candidate's CEM hypothesis fires at
    the real target (Task 2), not a synthesized `invariant.local` stub.
  * a non-GET/HEAD/OPTIONS capture is kept (method preserved) but Task 2 must
    not turn it into a droppable-GET counterfactual it never issued.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

import redact

_READ_METHODS = {"GET", "HEAD"}
# Headers that carry the issuing identity, most specific first.
_IDENTITY_HEADERS = ("Authorization", "Cookie", "X-Api-Key", "X-Auth-Token")


def identity_label(headers: dict) -> str:
    """Stable, redacted label for the identity that issued a request, derived
    from its auth/cookie header. Same raw header -> same label; the raw secret
    never appears in the label. 'anon' when no identity header is present."""
    if not isinstance(headers, dict):
        return "anon"
    lowered = {str(k).lower(): v for k, v in headers.items()}
    for name in _IDENTITY_HEADERS:
        val = lowered.get(name.lower())
        if val:
            return f"id:{redact.hash_value(str(val))[:12]}"
    return "anon"


def resource_of(url: str) -> str:
    """The object-instance path a request acted on (query stripped)."""
    return urlsplit(url).path or "/"


def action_of(method: str) -> str:
    """Map an HTTP method to the probe's action vocabulary."""
    m = (method or "GET").upper()
    return "read" if m in _READ_METHODS else m.lower()


def _exchange_from_burp_row(row: dict) -> dict | None:
    """One corpus exchange from one burp_endpoints row, or None if malformed."""
    try:
        method = str(row["method"]).upper()
        url = str(row["url"])
        if not url:
            return None
        headers = json.loads(row.get("headers_json") or "{}")
        if not isinstance(headers, dict):
            return None
        status = int(row["status"]) if row.get("status") is not None else 0
        return {
            "identity": identity_label(headers),
            "resource": resource_of(url),
            "action": action_of(method),
            "args": {},
            "status": status,
            "body": "",          # Burp stores no response body
            "session": None,
            "base_request": {
                "method": method,
                "url": url,
                "headers": headers,
                "body": None,
            },
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def build_corpus(target: str, *, burp_rows: list[dict] | None = None,
                 db_path: str | None = None) -> list[dict]:
    """Return the observed-exchange corpus for `target`.

    `burp_rows` (injectable for tests) is a list of burp_endpoints-shaped dicts;
    when None, they are read via burp-import-mcp's db for `target`. Any
    unreadable source or malformed row degrades to skipping it -- never raises
    into the hunt; a fully unreadable source returns []."""
    rows = burp_rows
    if rows is None:
        try:
            import importlib.util
            import os
            db_mod_path = os.path.join(os.path.dirname(__file__),
                                       "burp-import-mcp", "db.py")
            spec = importlib.util.spec_from_file_location("_burp_db", db_mod_path)
            burp_db = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(burp_db)
            kwargs = {"target": target}
            rows = burp_db.list_endpoints(**kwargs) if db_path is None \
                else burp_db.list_endpoints(target=target, path=db_path)
        except Exception:
            return []
    if not rows:
        return []

    corpus: list[dict] = []
    for row in rows:
        ex = _exchange_from_burp_row(row)
        if ex is not None:
            corpus.append(ex)
    return corpus
