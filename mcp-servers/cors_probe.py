"""CORS exploitability probe -- distinguishes "a CORS misconfiguration
exists" from "the misconfiguration is actually exploitable," the decisive
gap reported live in an engagement retrospective: a CORS reflection
(`Access-Control-Allow-Origin` reflecting the attacker's `Origin` +
`Access-Control-Allow-Credentials: true`) was initially reported as a
finding, then found NOT exploitable in a later review pass once the
target's actual auth mechanism was checked -- the API used a bearer token
held in client storage rather than a cookie, so cross-origin credential
theft was impossible. That check (cookie-based auth is auto-attached
cross-origin by the browser and IS exploitable; a bearer token in an
`Authorization` header is NOT auto-attached and is NOT exploitable via
CORS alone) is the entire difference between "reportable" and "not
reportable," and was previously only ever done manually.

Encodes the same hard rule already established in
.claude/skills/csrf-cors-origin/SKILL.md: `ACAO: *` cannot legally be
combined with credentials (a browser refuses to expose the response body
to a `credentials: include` request against a wildcard ACAO, full stop) --
that's informational, not a finding, regardless of what a header-only
`curl` inspection shows.

This is a read-only classification helper over one real request/response
pair -- it does NOT itself constitute the "browser-proven readable body"
evidence bar the CORS skill requires for a High-severity claim (that still
needs `mcp__browser-mcp`, `credentials:"include"`, confirming the body
actually renders). It exists to cheaply rule OUT the bearer-only and
wildcard-ACAO cases before spending that heavier verification step on a
misconfiguration that was never exploitable to begin with.

Uses only the standard library (via http_probe.py) -- no new dependency.
"""

from __future__ import annotations

from dataclasses import dataclass

from http_probe import DEFAULT_TIMEOUT_S
from http_probe import fetch as _fetch


@dataclass
class CorsProbeResult:
    acao: str | None
    acac: str | None
    classification: str
    # True/False once a real exploitability verdict is reached; None when
    # the probe failed outright, OR when a misconfiguration was observed
    # but the caller supplied no auth context (cookie_header/bearer_token)
    # to evaluate it against -- "unknown," not silently "safe."
    exploitable: bool | None
    error: str | None = None


def probe_cors(url: str, attacker_origin: str, *, cookie_header: str | None = None,
                bearer_token: str | None = None, method: str = "GET",
                timeout_s: float = DEFAULT_TIMEOUT_S) -> CorsProbeResult:
    """Send one request with `Origin: attacker_origin` (plus whichever of
    cookie_header/bearer_token the caller supplies, same convention as
    http_probe.build_headers), and classify the response's CORS headers.

    cookie_header/bearer_token are the SAME auth this call is made with --
    pass the real credential you're testing under, not a hypothetical. If
    neither is supplied, a real reflected+credentialed misconfiguration is
    still reported (exploitable=None, classification=
    "misconfigured_no_auth_context_supplied") rather than silently assumed
    safe -- the caller must supply auth context to get a definite verdict.
    """
    headers = {"Origin": attacker_origin}
    if cookie_header:
        headers["Cookie"] = cookie_header
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    result = _fetch(url, method, headers, None, timeout_s)
    if result.error is not None:
        return CorsProbeResult(acao=None, acac=None, classification="probe_failed",
                                exploitable=None, error=result.error)

    # Case-insensitive lookup (code-review finding, directly reproduced):
    # HTTP/1.1 header NAMES are case-insensitive on the wire (RFC 7230) --
    # many real backends (Node/Express, nginx add_header) send lowercase
    # header names. http_probe.FetchResult.headers deliberately preserves
    # whatever casing the server actually sent (see that module's own
    # comment) rather than normalizing it, so an exact-case-only lookup
    # here silently misclassified a real, exploitable misconfiguration as
    # "no CORS misconfiguration" -- a false negative in this probe's own
    # core job, worse than the bearer-vs-cookie mistake it exists to catch.
    _lower_headers = {k.lower(): v for k, v in result.headers.items()}
    acao = _lower_headers.get("access-control-allow-origin")
    acac = _lower_headers.get("access-control-allow-credentials")

    if acao is None:
        return CorsProbeResult(acao=acao, acac=acac, classification="no_cors_misconfiguration",
                                exploitable=False)

    if acao == "*":
        # Hard rule: a browser refuses credentialed reads against a
        # wildcard ACAO regardless of any ACAC value the server also sent.
        return CorsProbeResult(acao=acao, acac=acac, classification="not_exploitable_wildcard_acao",
                                exploitable=False)

    reflects_attacker_origin = acao == attacker_origin
    credentials_allowed = (acac or "").strip().lower() == "true"

    if not (reflects_attacker_origin and credentials_allowed):
        # ACAO reflects an origin (or names one) but credentials aren't
        # both allowed AND attacker-controlled at once -- not a
        # credential-theft primitive via this probe's check.
        return CorsProbeResult(acao=acao, acac=acac,
                                classification="reflected_without_credentials_flag", exploitable=False)

    if cookie_header:
        # Cookies are auto-attached by the browser on a cross-origin
        # credentialed request -- real exploitability.
        return CorsProbeResult(acao=acao, acac=acac, classification="exploitable_cookie_based",
                                exploitable=True)

    if bearer_token:
        # A bearer token in an Authorization header is NOT auto-attached
        # cross-origin -- an attacker page can't forge it without already
        # having it, so this specific misconfiguration is not exploitable
        # via CORS alone even though ACAO/ACAC both look permissive.
        return CorsProbeResult(acao=acao, acac=acac, classification="not_exploitable_bearer_only",
                                exploitable=False)

    return CorsProbeResult(acao=acao, acac=acac,
                            classification="misconfigured_no_auth_context_supplied", exploitable=None)
