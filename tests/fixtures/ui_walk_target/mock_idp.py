"""Spec 2 (SSO surface) test helper: a real, off-the-shelf local test IdP.

Runs NAV's open-source `mock-oauth2-server` container (user-approved test
dependency, 2026-11-22) on a loopback port, behind a tiny stdlib logging
pass-through so tests can see every request that reached the IdP (method,
path?query). Nothing here implements an IdP; the container does.

- `interactive=True`: /authorize serves the server's own login page (200).
- `interactive=False`: /authorize 302s straight to redirect_uri with a fresh
  `code` and the echoed `state` (an "existing IdP session").

Tests that need it skip unless podman AND the pinned image are present
(gating on the binary alone was a real bug class: P2-BENCH).

NOT a protected benchmark -- an ordinary test fixture.
"""

from __future__ import annotations

import http.client
import shutil
import socket
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

IMAGE = "ghcr.io/navikt/mock-oauth2-server:2.1.10"
ISSUER = "default"
_HOP = {"connection", "keep-alive", "proxy-connection", "te", "trailers", "transfer-encoding", "upgrade"}


def image_present() -> bool:
    if not shutil.which("podman"):
        return False
    try:
        r = subprocess.run(["podman", "image", "exists", IMAGE], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


requires_mock_idp = pytest.mark.skipif(not image_present(),
                                       reason=f"needs podman + the {IMAGE} image")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MockIdP:
    """The container on 127.0.0.1:<backend>, fronted by a logging pass-through
    on 127.0.0.1:<port>. Public base URL uses the host name `localhost`, so
    a test's scope check can put the IdP in or out of scope by host."""

    def __init__(self, interactive: bool):
        self.interactive = interactive
        self.requests: list[tuple[str, str]] = []
        self._lock = threading.Lock()
        self._backend = _free_port()
        self._name = f"hm-mock-idp-{uuid.uuid4().hex[:8]}"
        cfg = '{"interactiveLogin":%s}' % ("true" if interactive else "false")
        subprocess.run(["podman", "run", "-d", "--rm", "--name", self._name,
                        "-p", f"127.0.0.1:{self._backend}:8080", "-e", f"JSON_CONFIG={cfg}", IMAGE],
                       check=True, capture_output=True, timeout=60)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(self))
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self.base_url = f"http://localhost:{self.port}"
        self.issuer_url = f"{self.base_url}/{ISSUER}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self._wait_ready()

    def _wait_ready(self, timeout_s: float = 60.0) -> None:
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            try:
                c = http.client.HTTPConnection("127.0.0.1", self._backend, timeout=2)
                c.request("GET", f"/{ISSUER}/.well-known/openid-configuration")
                if c.getresponse().status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.5)
        self.close()
        raise RuntimeError("mock IdP did not become ready")

    def note(self, method: str, path: str) -> None:
        with self._lock:
            self.requests.append((method, path))

    def paths(self) -> list[str]:
        return [p.split("?", 1)[0] for _m, p in list(self.requests)]

    def clear(self) -> None:
        with self._lock:
            self.requests.clear()

    def close(self) -> None:
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:  # noqa: BLE001
            pass
        subprocess.run(["podman", "stop", "-t", "2", self._name], capture_output=True, timeout=60)


def _make_handler(idp: MockIdP):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _forward(self):
            idp.note(self.command, self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
            c = http.client.HTTPConnection("127.0.0.1", idp._backend, timeout=15)
            c.request(self.command, self.path, body=body, headers=headers)   # Host kept: issuer = public URL
            r = c.getresponse()
            data = r.read()
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in _HOP and k.lower() != "content-length":
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        do_GET = do_POST = do_HEAD = do_OPTIONS = do_PUT = do_DELETE = _forward

    return Handler
