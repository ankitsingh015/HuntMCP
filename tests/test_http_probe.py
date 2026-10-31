"""Unit tests for the shared HTTP fetch primitive (mcp-servers/http_probe.py).

Extracted from idor-mcp/idor_sweep.py (UD-1=B, PHASE1-EXECUTION-PLAN task A4) so both
idor_sweep and the future cem_engine can import one fetch implementation instead of
duplicating it. Exercises the real urllib code path (not a monkeypatched fake) against a
loopback-only stdlib HTTP server -- test_idor_sweep.py's existing suite is the regression
guard for idor_sweep's own behavior after the refactor; this file is the direct-coverage
counterpart for the extracted module itself.
"""
import json
import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import http_probe


class _EchoHandler(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if self.path == "/not-found":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"not found here")
            return
        if self.path == "/cors-echo":
            # Reflects the request's Origin header into ACAO + sets ACAC:
            # true -- a deliberately-misconfigured CORS response, for
            # test_http_probe's own response-header-capture tests and
            # test_cors_probe's exploitability-classification tests.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            origin = self.headers.get("Origin", "")
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b"secret account data")
            return
        payload = {
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body": body.decode(errors="replace"),
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def log_message(self, *args) -> None:  # silence stdlib request logging
        pass


@pytest.fixture
def echo_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# build_headers
# ---------------------------------------------------------------------------

def test_build_headers_both_present():
    headers = http_probe.build_headers("session=abc123", "tok_xyz")
    assert headers == {"Cookie": "session=abc123", "Authorization": "Bearer tok_xyz"}


def test_build_headers_neither_present():
    assert http_probe.build_headers(None, None) == {}


def test_build_headers_cookie_only():
    assert http_probe.build_headers("session=abc123", None) == {"Cookie": "session=abc123"}


def test_build_headers_bearer_only():
    assert http_probe.build_headers(None, "tok_xyz") == {"Authorization": "Bearer tok_xyz"}


# ---------------------------------------------------------------------------
# fetch -- real requests against a loopback echo server
# ---------------------------------------------------------------------------

def test_fetch_get_200(echo_server):
    result = http_probe.fetch(f"{echo_server}/orders/1", "GET", {}, None, 5)
    assert result.status == 200
    assert result.error is None
    payload = json.loads(result.body)
    assert payload["method"] == "GET"
    assert payload["path"] == "/orders/1"


def test_fetch_sends_headers(echo_server):
    result = http_probe.fetch(f"{echo_server}/orders/1", "GET", {"Cookie": "session=abc"}, None, 5)
    payload = json.loads(result.body)
    assert payload["headers"].get("Cookie") == "session=abc"


def test_fetch_sends_body_on_post(echo_server):
    result = http_probe.fetch(f"{echo_server}/orders", "POST", {}, '{"x":1}', 5)
    payload = json.loads(result.body)
    assert payload["method"] == "POST"
    assert payload["body"] == '{"x":1}'


def test_fetch_404_returns_response_not_exception(echo_server):
    # A 401/403/404 raises urllib.error.HTTPError -- http_probe.fetch must still
    # return a normal FetchResult, since it's a real, meaningful response.
    result = http_probe.fetch(f"{echo_server}/not-found", "GET", {}, None, 5)
    assert result.status == 404
    assert result.error is None
    assert "not found here" in result.body


def test_fetch_connection_refused_sets_error_not_exception():
    # Nothing listens on this port -- must be a graceful FetchResult(error=...),
    # never a raised exception (callers loop over many ids/trials).
    result = http_probe.fetch("http://127.0.0.1:1", "GET", {}, None, 1)
    assert result.status is None
    assert result.error is not None
    assert result.body == ""


def test_fetch_result_is_reusable_dataclass():
    r = http_probe.FetchResult(status=200, body="x")
    assert r.error is None
    assert r.headers == {}


def test_fetch_captures_response_headers(echo_server):
    """Regression: FetchResult used to carry only status/body/error -- a
    caller needing to inspect response HEADERS (e.g. a CORS exploitability
    check reading Access-Control-Allow-Origin/-Credentials) had no way to
    get them without a separate, duplicated fetch implementation."""
    result = http_probe.fetch(f"{echo_server}/cors-echo", "GET", {"Origin": "https://evil.example"}, None, 5)
    assert result.status == 200
    assert result.headers.get("Access-Control-Allow-Origin") == "https://evil.example"
    assert result.headers.get("Access-Control-Allow-Credentials") == "true"


def test_fetch_captures_response_headers_on_http_error(echo_server):
    """Headers must also be captured on the HTTPError path (401/403/404),
    not just the success path -- the two are separate code branches in
    fetch()."""
    result = http_probe.fetch(f"{echo_server}/not-found", "GET", {}, None, 5)
    assert result.status == 404
    assert result.headers.get("Content-Type") == "text/plain"


# fetch()'s own SSRF enforcement boundary (added after a security review
# found scope_guard.outbound_policy_error() alone -- the literal-string
# pre-check callers like case-mcp's CEM senders run before this -- cannot
# catch a hostname that resolves to a metadata/link-local address at
# connect time). These tests mock socket.getaddrinfo the way a real
# DNS-rebinding attack works (the hostname's own records point wherever
# the attacker wants), never real DNS/network infrastructure.


def _fake_getaddrinfo(answer: str):
    def _fn(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answer, 0))]
    return _fn


def test_fetch_refuses_before_connecting_when_host_resolves_to_metadata_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))

    def _unreachable_urlopen(*a, **k):
        raise AssertionError("fetch() must refuse before ever calling urlopen")
    monkeypatch.setattr(urllib.request, "urlopen", _unreachable_urlopen)

    result = http_probe.fetch("http://sub.target.example/", "GET", {}, None, 5)

    assert result.status is None
    assert result.error is not None
    assert "169.254.169.254" in result.error


def test_fetch_proceeds_normally_when_host_resolves_to_an_ordinary_address(monkeypatch, echo_server):
    """Confirms the new pre-check is a narrow deny, not a broad allowlist --
    a real loopback fetch (echo_server) must still work unaffected, without
    even needing socket.getaddrinfo mocked (127.0.0.1 is already a literal
    IP, so fetch()'s urlsplit().hostname -> resolved_ip_policy_error() path
    resolves it trivially and permits it, the same as it always has)."""
    result = http_probe.fetch(f"{echo_server}/orders/1", "GET", {}, None, 5)
    assert result.status == 200


# ---------------------------------------------------------------------------
# P3-H4 -- scan-identification header auto-attachment + destination
# boundary (the header must reach the engagement's own target, and must
# never survive a redirect onto a different host).
# ---------------------------------------------------------------------------

def _write_engagement_with_scan_header(tmp_path, target_host, header_name="X-Bug-Bounty",
                                        header_value="ankit015"):
    p = tmp_path / "engagement.yaml"
    p.write_text(
        f"target: {target_host}\nin_scope:\n  - {target_host}\n"
        f"scan_header_name: {header_name}\nscan_header_value: {header_value}\n",
    )
    return str(p)


def test_fetch_attaches_scan_header_for_in_scope_target(monkeypatch, echo_server, tmp_path):
    path = _write_engagement_with_scan_header(tmp_path, "127.0.0.1")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", path)

    result = http_probe.fetch(f"{echo_server}/orders/1", "GET", {}, None, 5)
    payload = json.loads(result.body)
    assert payload["headers"].get("X-Bug-Bounty") == "ankit015"


def test_fetch_sends_scan_header_with_exact_configured_case_on_the_wire(monkeypatch, echo_server, tmp_path):
    """Regression: urllib.request.Request.add_header() title-cases every
    header key it's given (str.capitalize() -- first char up, rest down),
    so a naive headers={**headers, **scan_hdrs} merge sent "X-Bug-Bounty"
    out as "X-bug-bounty" on the wire, while the CLI scanners (httpx/
    nuclei/etc., which pass the literal "-H" string untouched by urllib)
    sent the correct case -- the same engagement produced two differently
    -cased headers. The configured name must reach the wire byte-for-byte
    as written in engagement.yaml."""
    path = _write_engagement_with_scan_header(tmp_path, "127.0.0.1")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", path)

    result = http_probe.fetch(f"{echo_server}/orders/1", "GET", {}, None, 5)
    payload = json.loads(result.body)
    assert "X-Bug-Bounty" in payload["headers"]
    assert "X-bug-bounty" not in payload["headers"]


def test_fetch_does_not_attach_scan_header_when_url_is_out_of_scope(monkeypatch, echo_server):
    """The destination-boundary decision itself (is this URL the
    authorized target?) is scan_headers.get_scan_headers()'s own job and
    is fully unit-tested in test_scan_headers.py -- a loopback address used
    for a real network fixture here is always scope_guard's "safe test
    host" regardless of engagement.yaml, so this test instead verifies
    fetch() actually calls get_scan_headers() and respects an empty
    result, rather than trying to fabricate a real out-of-scope network
    target."""
    monkeypatch.setattr(http_probe.scan_headers, "get_scan_headers", lambda url: {})

    result = http_probe.fetch(f"{echo_server}/orders/1", "GET", {}, None, 5)
    payload = json.loads(result.body)
    assert "X-Bug-Bounty" not in payload["headers"]


def test_fetch_omits_scan_header_when_nothing_configured(monkeypatch, echo_server, tmp_path):
    path = tmp_path / "engagement.yaml"
    path.write_text("target: 127.0.0.1\nin_scope:\n  - 127.0.0.1\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(path))

    result = http_probe.fetch(f"{echo_server}/orders/1", "GET", {}, None, 5)
    payload = json.loads(result.body)
    assert "X-Bug-Bounty" not in payload["headers"]


class _RedirectHandler(BaseHTTPRequestHandler):
    """Redirects every request to another ORIGIN entirely (a different
    host:port) so the test can assert the scan-identification header is
    stripped before the redirect is followed -- it must never reach a host
    other than the one the engagement actually authorizes, including via
    a redirect the target itself issues."""
    other_origin = ""

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(302)
        self.send_header("Location", f"{self.other_origin}/landed")
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def redirect_pair():
    """Two loopback servers: `origin` (the authorized target, issues a
    redirect) and `other` (a different host:port the redirect points at,
    captures whatever headers actually arrived)."""
    captured: dict[str, dict] = {}

    class _CaptureHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            captured["headers"] = {k: v for k, v in self.headers.items()}
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"landed")

        def log_message(self, *args) -> None:
            pass

    other_httpd = ThreadingHTTPServer(("127.0.0.1", 0), _CaptureHandler)
    other_thread = threading.Thread(target=other_httpd.serve_forever, daemon=True)
    other_thread.start()
    other_origin = f"http://127.0.0.1:{other_httpd.server_address[1]}"

    _RedirectHandler.other_origin = other_origin
    origin_httpd = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    origin_thread = threading.Thread(target=origin_httpd.serve_forever, daemon=True)
    origin_thread.start()
    origin = f"http://127.0.0.1:{origin_httpd.server_address[1]}"

    try:
        yield origin, captured
    finally:
        origin_httpd.shutdown()
        origin_httpd.server_close()
        origin_thread.join(timeout=5)
        other_httpd.shutdown()
        other_httpd.server_close()
        other_thread.join(timeout=5)


def test_fetch_never_raises_when_scan_header_config_is_malformed(monkeypatch, echo_server, tmp_path):
    """Regression: fetch()'s own documented contract is "always returns a
    FetchResult, never raises" -- a malformed scan_header_name (here, a
    bare YAML int, a plausible typo for `scan_header_name: X-Bug-Bounty`)
    must not break that for every caller (idor-mcp, CEM, cors_probe, ...)."""
    path = tmp_path / "engagement.yaml"
    path.write_text(
        "target: 127.0.0.1\nin_scope:\n  - 127.0.0.1\n"
        "scan_header_name: 123\nscan_header_value: ankit015\n",
    )
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(path))

    result = http_probe.fetch(f"{echo_server}/orders/1", "GET", {}, None, 5)
    assert result.status == 200


def test_fetch_strips_scan_header_on_cross_host_redirect(monkeypatch, redirect_pair, tmp_path):
    origin, captured = redirect_pair
    path = tmp_path / "engagement.yaml"
    path.write_text(
        "target: 127.0.0.1\nin_scope:\n  - 127.0.0.1\n"
        "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(path))

    result = http_probe.fetch(origin, "GET", {}, None, 5)

    assert result.status == 200
    assert "X-Bug-Bounty" not in captured["headers"]
