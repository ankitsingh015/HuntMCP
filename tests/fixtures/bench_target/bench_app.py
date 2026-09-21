"""Constructed multi-vuln-class benchmark target (TEST FIXTURE ONLY).

See docs/superpowers/specs/2026-09-17-p2-bench-design.md for the full
design. Loopback-only (127.0.0.1, ephemeral port), zero outbound calls,
two behavior modes ("vulnerable"/"patched"). Holds an independent
in-process request log so a test can verify a claimed finding is backed
by real, differing requests rather than a tool's own narrative -- same
role as tests/fixtures/cem_target/cem_benchmark_app.py's request log.

Does NOT import bench_scenarios/bench_answer_key -- this app has no path
to its own expected answers, matching cem_benchmark_app.py's own
"safe by construction" property.
"""
from __future__ import annotations

import html
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOOPBACK = "127.0.0.1"

# Fake-but-recognizable content so a real tool's own output can be checked
# against something specific, not just "some text changed."
_BACKUP_FILE_CONTENT = "DB_PASSWORD=bench-fixture-fake-secret-not-real\n"
_MISCONFIG_BANNER = "build 2026.09-DEBUG-ENABLED"


class _State:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.lock = threading.Lock()
        self.request_log: list[dict] = []
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.execute("CREATE TABLE products (id INTEGER, name TEXT)")
        self.db.executemany(
            "INSERT INTO products VALUES (?, ?)",
            [(1, "PRODUCT-alpha"), (2, "PRODUCT-bravo"), (3, "PRODUCT-charlie")],
        )
        self.db.commit()
        # orders: id -> owner session token. Order 42 belongs to "owner-session".
        self.orders = {42: {"owner": "owner-session", "data": "ORDER-DETAIL-42-SECRET"}}

    def reset(self) -> None:
        with self.lock:
            self.request_log.clear()

    def orders_session_of(self, headers) -> str:
        cookie = _cookie_value(headers)
        return cookie.split("session=", 1)[-1] if "session=" in cookie else ""


def _cookie_value(headers) -> str:
    return headers.get("Cookie", "") or ""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a, **k) -> None:
        return

    def _send(self, status: int, body: str, headers: dict | None = None) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _record(self, path: str, qs: dict) -> None:
        st: _State = self.server.state  # type: ignore[attr-defined]
        with st.lock:
            st.request_log.append({
                "path": path, "query": qs,
                "headers": dict(self.headers.items()),
                "cookie": _cookie_value(self.headers),
            })

    def do_GET(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler's own naming convention
        st: _State = self.server.state  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        self._record(path, qs)

        if path == "/bench/decoy":
            self._send(200, "nothing interesting here")
            return

        if path == "/bench/products":
            raw_id = qs.get("id", ["1"])[0]
            if st.mode == "vulnerable":
                # Real, string-concatenated SQL injection -- genuinely
                # exploitable, not a toy check.
                query = f"SELECT id, name FROM products WHERE id = {raw_id}"
                try:
                    rows = st.db.execute(query).fetchall()
                except sqlite3.Error as e:
                    self._send(500, f"db error: {e}")
                    return
            else:
                # Extract only leading digits to prevent injection
                id_match = re.match(r'^(\d+)', raw_id)
                if id_match:
                    try:
                        id_val = int(id_match.group(1))
                        rows = st.db.execute(
                            "SELECT id, name FROM products WHERE id = ?", (id_val,)
                        ).fetchall()
                    except sqlite3.Error:
                        rows = []
                else:
                    rows = []
            self._send(200, "\n".join(f"{r[0]}: {r[1]}" for r in rows) or "no products")
            return

        if path == "/bench/search":
            term = qs.get("q", [""])[0]
            if st.mode == "vulnerable":
                body = f"<html><body>Results for: {term}</body></html>"
            else:
                body = f"<html><body>Results for: {html.escape(term)}</body></html>"
            self._send(200, body)
            return

        if path.startswith("/bench/orders/"):
            order_id_raw = path.rsplit("/", 1)[-1]
            try:
                order_id = int(order_id_raw)
            except ValueError:
                self._send(404, "not found")
                return
            order = st.orders.get(order_id)
            if order is None:
                self._send(404, "no such order")
                return
            session = st.orders_session_of(self.headers)
            if st.mode == "vulnerable" or session == order["owner"]:
                self._send(200, order["data"])
            else:
                self._send(403, "forbidden")
            return

        if path == "/backup.sql.bak":
            if st.mode == "vulnerable":
                self._send(200, _BACKUP_FILE_CONTENT)
            else:
                self._send(404, "not found")
            return

        if path == "/bench/status":
            headers = {"X-Bench-Debug-Panel": _MISCONFIG_BANNER} if st.mode == "vulnerable" else {}
            self._send(200, "status: ok", headers=headers)
            return

        if path == "/bench/login":
            next_url = qs.get("next", ["/bench/home"])[0]
            if st.mode == "vulnerable":
                location = next_url
            else:
                location = next_url if next_url.startswith("/") else "/bench/home"
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self._send(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        self._send(404, "not found")


def _make_server(mode: str) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((LOOPBACK, 0), _Handler)
    server.state = _State(mode)  # type: ignore[attr-defined]
    return server


class BenchApp:
    def __init__(self, mode: str) -> None:
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "BenchApp":
        self._server = _make_server(self.mode)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def reset(self) -> None:
        self._server.state.reset()  # type: ignore[attr-defined]

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address  # type: ignore[union-attr]
        return f"http://{LOOPBACK}:{port}"

    @property
    def request_log(self) -> list[dict]:
        return self._server.state.request_log  # type: ignore[attr-defined]
