"""Unit tests for the shared HTTP fetch primitive (mcp-servers/http_probe.py).

Extracted from idor-mcp/idor_sweep.py (UD-1=B, PHASE1-EXECUTION-PLAN task A4) so both
idor_sweep and the future cem_engine can import one fetch implementation instead of
duplicating it. Exercises the real urllib code path (not a monkeypatched fake) against a
loopback-only stdlib HTTP server -- test_idor_sweep.py's existing suite is the regression
guard for idor_sweep's own behavior after the refactor; this file is the direct-coverage
counterpart for the extracted module itself.
"""
import json
import threading
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
