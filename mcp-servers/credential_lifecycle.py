"""Structured credential/session intake & lifecycle -- metadata tracking
ONLY, never the credential value itself.

Why this exists: authenticated engagements depend on a live credential,
but nothing structured the intake (what artifact type is actually
needed?), validated it, watched for expiry, or reminded about revocation
-- reported live in an engagement retrospective: three separate
round-trips (cookies, then a CORS preflight response, then finally the
right bearer token) because nothing classified the artifact type early,
and no expiry/revocation discipline beyond ad-hoc agent judgment.

SECURITY -- the one rule this entire module is built around: it tracks
FACTS ABOUT a credential (its classified type, when it was obtained, a
human-supplied source description, validation timestamps/outcomes,
recent probe statuses for expiry detection), never the credential's own
raw value. classify_artifact()/validate_credential() both accept the raw
value as an input parameter (they have to, to inspect its shape or use it
in a real request) but neither one, nor record_intake(), ever writes that
value to disk, into a return value, or anywhere else it could leak a
second time -- see each function's own docstring and the SECURITY-labeled
tests in tests/test_credential_lifecycle.py. The actual credential
continues to flow exactly the way it already does everywhere else in this
repo: as a cookie_header/bearer_token/session_file parameter passed
directly to the tool that needs it (browser-mcp, idor-mcp, ws-rpc-mcp,
this module's own validate_credential()) -- this module adds
classification/validation/expiry/revocation bookkeeping ALONGSIDE that
existing flow, it does not create a new place secrets live.

Credential-SCOPED DELEGATION (the orchestrator handing a credential to a
specialist without pasting the raw secret into the subagent's own prompt
text) is a prompting/orchestration discipline, not something this module
can enforce in code -- see huntbrain.md's own guidance on passing a
credential by reference (an env var name, a session_file path) rather
than inline.

State is per-engagement, reset alongside engagement.yaml/budget.json.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time

try:
    import engagement_paths
    from http_probe import fetch as _fetch
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths
    from http_probe import fetch as _fetch

DEFAULT_TIMEOUT_S = 10

# Checked FIRST: a multi-line blob of "Header-Name: value" pairs including
# at least one Access-Control- header is a CORS preflight RESPONSE, not a
# usable credential at all -- reported live as one of the two insufficient
# artifacts pasted before the real bearer token was found.
_PREFLIGHT_RESPONSE_RE = re.compile(r"(?im)^Access-Control-[A-Za-z-]+\s*:")

# A JWT: three base64url segments separated by dots, the header segment
# conventionally starting "eyJ" (base64 of '{"'). Anchored to the whole
# stripped sample -- a JWT embedded inside a longer sentence is not this
# case (that's "unknown": ambiguous prose, not a clean artifact paste).
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}$")

# "name=value; name2=value2" (or a single pair) -- the Cookie header shape
# browser-mcp/idor-mcp's own cookie_header parameter already expects.
_COOKIE_RE = re.compile(r"^[\w.-]+=[^;=\s]+(?:;\s*[\w.-]+=[^;=\s]+)*$")

# A single opaque token: no whitespace, no "=", reasonably long -- the
# fallback bearer-token shape for a provider whose tokens aren't JWTs
# (e.g. "sk_live_...", a plain API key).
_OPAQUE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-]{16,}$")


def classify_artifact(sample: str) -> dict:
    """Classifies the SHAPE of a pasted credential artifact -- does not
    retain, log, or return the raw `sample` text itself anywhere in the
    result (see this module's own docstring). Returns {"artifact_type":
    "bearer_token" | "cookie_header" | "preflight_insufficient" |
    "unknown", "note": <short generic guidance>}."""
    stripped = sample.strip()
    if _PREFLIGHT_RESPONSE_RE.search(stripped):
        artifact_type = "preflight_insufficient"
        note = ("This looks like a CORS preflight response (Access-Control-* headers), not a usable "
                "credential. Ask for the actual session cookie or bearer token instead.")
    elif _JWT_RE.match(stripped):
        artifact_type = "bearer_token"
        note = "JWT-shaped bearer token. Pass as bearer_token to the tool making the request."
    elif "=" in stripped and _COOKIE_RE.match(stripped):
        artifact_type = "cookie_header"
        note = "Cookie-header-shaped (name=value pairs). Pass as cookie_header to the tool making the request."
    elif " " not in stripped and _OPAQUE_TOKEN_RE.match(stripped):
        artifact_type = "bearer_token"
        note = "Opaque-token-shaped. Pass as bearer_token to the tool making the request."
    else:
        artifact_type = "unknown"
        note = "Doesn't match a recognized credential shape -- ask the operator what artifact this is."
    return {"artifact_type": artifact_type, "note": note}


def _resolve_path(path: str | None) -> str:
    if path is not None:
        return path
    return engagement_paths.resolve("credential-intake.jsonl", override_env="HUNTMCP_CREDENTIAL_INTAKE_PATH")


def record_intake(artifact_type: str, obtained_via: str, path: str | None = None) -> dict:
    """Records metadata about a credential intake event -- artifact_type
    (e.g. from classify_artifact()) and a human-supplied description of
    HOW it was obtained (e.g. "pasted from browser devtools"). Takes no
    raw-value parameter at all -- there is structurally nothing here to
    accidentally persist."""
    path = _resolve_path(path)
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifact_type": artifact_type,
        "obtained_via": obtained_via,
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def list_intake_history(path: str | None = None) -> list[dict]:
    path = _resolve_path(path)
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def validate_credential(url: str, cookie_header: str | None = None, bearer_token: str | None = None,
                         method: str = "GET", timeout_s: float = DEFAULT_TIMEOUT_S) -> dict:
    """Sends ONE real request to `url` with the given credential and
    classifies the outcome: "valid" (a non-401/403 status -- the
    credential is at least being accepted by something), "invalid_or_
    expired" (401/403), or "probe_failed" (connection/transport error,
    inconclusive either way). The credential value is used to build the
    request but never appears in the returned dict -- only the resulting
    HTTP status and classification."""
    headers: dict[str, str] = {}
    if cookie_header:
        headers["Cookie"] = cookie_header
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    r = _fetch(url, method, headers, None, timeout_s)
    if r.error is not None:
        return {"status": "probe_failed", "http_status": None, "error": r.error}
    if r.status in (401, 403):
        return {"status": "invalid_or_expired", "http_status": r.status}
    return {"status": "valid", "http_status": r.status}


def check_expiry_signal(recent_statuses: list[int], window: int = 3) -> bool:
    """True if the most recent `window` HTTP status codes are ALL 401/403
    -- a credential that was working earlier and then starts failing
    consistently is almost certainly expired/revoked mid-engagement, not
    coincidentally-invalid requests. Requires at least `window` samples --
    a single 401 right after obtaining a credential is more likely a
    wrong-artifact-type mistake than proof of expiry."""
    if len(recent_statuses) < window:
        return False
    return all(status in (401, 403) for status in recent_statuses[-window:])


def revocation_reminder(artifact_type: str) -> str:
    """A canned reminder to surface to the operator once a credential is
    no longer needed -- the revocation-advice habit this repo's own prior
    engagements found worked well, made into a reusable, consistent
    message instead of ad-hoc phrasing each time."""
    if artifact_type == "bearer_token":
        return ("This bearer token was used for live testing -- recommend the operator rotate/revoke it "
                "now that it's no longer needed, since it was pasted into this session.")
    if artifact_type == "cookie_header":
        return ("This session cookie was used for live testing -- recommend the operator log out "
                "(invalidates the session server-side) now that it's no longer needed.")
    return "This credential was used for live testing -- recommend the operator rotate/revoke it now."
