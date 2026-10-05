"""Unit tests for mcp-servers/cors_probe.py -- exercises the real urllib
code path against a loopback-only stdlib HTTP server (same pattern as
test_http_probe.py/test_idor_sweep.py), not a monkeypatched fake, since
CORS exploitability is fundamentally about real response headers.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import cors_probe
import pytest


class _CorsHandler(BaseHTTPRequestHandler):
    """Route-controlled CORS response shapes, one per test scenario."""

    def do_GET(self) -> None:
        origin = self.headers.get("Origin", "")
        auth = self.headers.get("Authorization", "")
        cookie = self.headers.get("Cookie", "")

        if self.path == "/wildcard":
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"public data")
            return

        if self.path == "/reflected-credentialed":
            # Reflects the attacker origin + allows credentials -- a real
            # misconfiguration; exploitability then depends on whether the
            # caller's auth is cookie-based (auto-attached cross-origin) or
            # bearer-token-based (not auto-attached, so not exploitable via
            # CORS alone).
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            body = "secret data"
            if cookie:
                body += f" cookie={cookie}"
            if auth:
                body += f" auth={auth}"
            self.wfile.write(body.encode())
            return

        if self.path == "/reflected-no-credentials-flag":
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.end_headers()
            self.wfile.write(b"data, no ACAC header at all")
            return

        if self.path == "/no-cors-headers":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"no CORS headers sent at all")
            return

        if self.path == "/reflected-credentialed-lowercase-headers":
            # Real-world case: many Node/Express backends and nginx
            # add_header configs emit lowercase header NAMES on the wire
            # (HTTP/1.1 header names are case-insensitive per RFC 7230, so
            # this is fully spec-legal) -- urllib's own response parsing
            # preserves whatever casing the server actually sent (verified
            # directly, not assumed) rather than normalizing it.
            self.send_response(200)
            self.send_header("access-control-allow-origin", origin)
            self.send_header("access-control-allow-credentials", "true")
            self.end_headers()
            body = "secret data"
            if cookie:
                body += f" cookie={cookie}"
            self.wfile.write(body.encode())
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, *args) -> None:  # silence stdlib request logging
        pass


@pytest.fixture
def cors_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _CorsHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


ATTACKER_ORIGIN = "https://attacker.example"


def test_wildcard_acao_is_not_exploitable(cors_server):
    """Hard rule from .claude/skills/csrf-cors-origin/SKILL.md: ACAO: *
    cannot legally be combined with credentials -- a browser refuses to
    expose the response body to a credentials:include request against a
    wildcard ACAO, full stop. Informational, not a finding, regardless of
    what curl shows."""
    result = cors_probe.probe_cors(f"{cors_server}/wildcard", ATTACKER_ORIGIN)
    assert result.exploitable is False
    assert result.classification == "not_exploitable_wildcard_acao"


def test_no_cors_headers_at_all_is_not_exploitable(cors_server):
    result = cors_probe.probe_cors(f"{cors_server}/no-cors-headers", ATTACKER_ORIGIN)
    assert result.exploitable is False
    assert result.classification == "no_cors_misconfiguration"


def test_reflected_origin_no_acac_is_not_credential_exploitable(cors_server):
    """ACAO reflects the attacker origin but there's no ACAC: true at all --
    a browser won't send/expose credentials either way, so this can't be a
    credential-theft finding (may still be a low-severity data-exposure
    issue for a public/unauthenticated response, but that's a different
    claim than what this probe classifies)."""
    result = cors_probe.probe_cors(f"{cors_server}/reflected-no-credentials-flag", ATTACKER_ORIGIN)
    assert result.exploitable is False
    assert result.classification == "reflected_without_credentials_flag"


def test_reflected_and_credentialed_with_cookie_auth_is_exploitable(cors_server):
    """The decisive distinction this probe exists for: cookie-based auth is
    auto-attached by the browser cross-origin, so ACAO-reflects +
    ACAC:true + a real cookie session IS exploitable via CORS."""
    result = cors_probe.probe_cors(
        f"{cors_server}/reflected-credentialed", ATTACKER_ORIGIN, cookie_header="session=abc123",
    )
    assert result.exploitable is True
    assert result.classification == "exploitable_cookie_based"


def test_reflected_and_credentialed_with_lowercase_header_names_is_still_exploitable(cors_server):
    """Code-review finding, directly reproduced: HTTP/1.1 header NAMES are
    case-insensitive on the wire (RFC 7230) -- many real backends
    (Node/Express, nginx add_header) send lowercase header names.
    http_probe.FetchResult.headers deliberately preserves whatever casing
    the server actually sent (verified: urllib does not normalize it), so
    an exact-case-only lookup here would silently misclassify a real,
    exploitable misconfiguration as "no_cors_misconfiguration" -- worse
    than the bearer-vs-cookie distinction this module exists to get right,
    since it's a false NEGATIVE in the tool's own core job."""
    result = cors_probe.probe_cors(
        f"{cors_server}/reflected-credentialed-lowercase-headers", ATTACKER_ORIGIN,
        cookie_header="session=abc123",
    )
    assert result.exploitable is True
    assert result.classification == "exploitable_cookie_based"


def test_reflected_and_credentialed_with_bearer_only_is_not_exploitable(cors_server):
    """The other half of the same distinction: a bearer token lives in
    JS-accessible client storage and is NOT auto-attached to a cross-origin
    request by the browser -- an attacker page can't forge the
    Authorization header without already having the token, so ACAO-
    reflects + ACAC:true is NOT exploitable via CORS when auth is
    bearer-only (this was the exact overstatement reported live in an
    engagement retrospective: a CORS reflection was initially reported,
    then found non-exploitable once bearer-vs-cookie was checked)."""
    result = cors_probe.probe_cors(
        f"{cors_server}/reflected-credentialed", ATTACKER_ORIGIN, bearer_token="tok_xyz",
    )
    assert result.exploitable is False
    assert result.classification == "not_exploitable_bearer_only"


def test_reflected_and_credentialed_with_no_auth_context_is_informational(cors_server):
    """No cookie AND no bearer token supplied at all -- the misconfiguration
    is real (ACAO reflects + ACAC:true) but the caller gave no session
    mechanism to evaluate exploitability against; flagged as needing manual
    verification rather than silently defaulting either way."""
    result = cors_probe.probe_cors(f"{cors_server}/reflected-credentialed", ATTACKER_ORIGIN)
    assert result.exploitable is None
    assert result.classification == "misconfigured_no_auth_context_supplied"


def test_connection_refused_surfaces_as_error_not_exception():
    result = cors_probe.probe_cors("http://127.0.0.1:1/x", ATTACKER_ORIGIN, timeout_s=1)
    assert result.exploitable is None
    assert result.classification == "probe_failed"
    assert result.error is not None
