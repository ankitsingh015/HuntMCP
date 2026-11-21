"""Test-only stand-in for Burp: a stdlib, loopback-only HTTP forward proxy.

- Listens on 127.0.0.1, port 0 (an ephemeral port); stop() shuts it down.
- Plain-HTTP absolute-URI requests (GET/POST/...) are forwarded to the origin
  with `Via: 1.1 hm-standin` added, and logged as (method, url).
- CONNECT is accepted ONLY to a loopback host (127.0.0.1 / localhost / ::1),
  and the tunnel must carry plain HTTP, which is parsed and forwarded the same
  way (Playwright's own Node-side fetch tunnels http:// through CONNECT).
  Any other CONNECT target, and any request to a non-loopback host, is refused
  without opening a connection -- this helper never reaches the internet.

NOT a protected benchmark -- an ordinary test fixture.
"""

from __future__ import annotations

import http.client
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
VIA = "1.1 hm-standin"
_HOP = {"connection", "proxy-connection", "keep-alive", "proxy-authorization", "proxy-authenticate",
        "te", "trailers", "transfer-encoding", "upgrade"}


class StandinProxy:
    def __init__(self, banner: str | None = None):
        # banner: if set, a plain (non-proxy) GET / to the listener returns this
        # HTML, the way Burp serves its own "Burp Suite ..." page.
        self.banner = banner
        self.log: list[tuple[str, str]] = []        # forwarded requests: (method, absolute url)
        self.connects: list[str] = []               # accepted CONNECT targets (host:port)
        self.refused: list[tuple[str, str]] = []    # never forwarded: (method, target)
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(self))
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _note(self, bucket: list, item) -> None:
        with self._lock:
            bucket.append(item)

    def paths_for_port(self, port: int) -> list[tuple[str, str]]:
        """(method, path?query) of every forwarded request to 127.0.0.1/localhost:port."""
        out = []
        for m, u in list(self.log):
            p = urlsplit(u)
            if p.port == port:
                out.append((m, p.path + (f"?{p.query}" if p.query else "")))
        return out

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _make_handler(proxy: StandinProxy):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):  # quiet
            pass

        def _forward(self, url: str) -> None:
            u = urlsplit(url)
            host = (u.hostname or "").lower()
            if u.scheme != "http" or host not in LOOPBACK_HOSTS:
                proxy._note(proxy.refused, (self.command, url))
                self.send_error(502, "stand-in proxy only forwards plain http to loopback")
                return
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
            headers["Via"] = VIA
            headers["Connection"] = "close"
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            proxy._note(proxy.log, (self.command, url))
            conn = http.client.HTTPConnection(host, u.port or 80, timeout=15)
            try:
                conn.request(self.command, path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
            except OSError:
                self.send_error(502, "upstream failed")
                return
            finally:
                conn.close()
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in _HOP and k.lower() != "content-length":
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Via", VIA)
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            self.close_connection = True

        def _absolute(self) -> None:
            if proxy.banner is not None and self.command == "GET" and self.path == "/":
                body = proxy.banner.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if not self.path.startswith("http://"):
                proxy._note(proxy.refused, (self.command, self.path))
                self.send_error(400, "absolute-URI requests only")
                return
            self._forward(self.path)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _absolute

        def do_CONNECT(self):
            host, _, port = self.path.rpartition(":")
            host = host.strip("[]").lower()
            if host not in LOOPBACK_HOSTS or not port.isdigit():
                proxy._note(proxy.refused, ("CONNECT", self.path))
                self.send_error(403, "CONNECT only to loopback")
                return
            proxy._note(proxy.connects, self.path)
            self.send_response(200, "Connection established")
            self.end_headers()
            self.wfile.flush()
            # The tunnel must carry plain HTTP (the fixture is http): parse the
            # inner request and forward it like an absolute-URI one.
            first = self.rfile.peek(1)[:1] if hasattr(self.rfile, "peek") else b""
            if first == b"\x16":   # TLS ClientHello: not supported by this stand-in
                self.close_connection = True
                return
            self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline or not self.parse_request():
                self.close_connection = True
                return
            target_host = "127.0.0.1" if host == "127.0.0.1" else host
            netloc = f"[{target_host}]" if ":" in target_host else target_host
            self._forward(f"http://{netloc}:{port}{self.path}")
            self.close_connection = True

    return Handler
