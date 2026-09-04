"""Constructed benchmark target for CEM (TEST FIXTURE ONLY -- NOT CEM).

Neutral routes (/svc/alpha.. /svc/golf) so the CEM-facing scenario manifest leaks no
semantics. Two behavior modes (vulnerable/patched) for the mutation scenario (B2). An
independent in-process request log (B1) records what actually hit the target, so a test
can confirm CEM's claimed experiments against reality rather than CEM's own narrative.

Safe by construction: binds ONLY to 127.0.0.1 on an ephemeral port; zero outbound calls;
holds all state in-process; reset() clears it. Does NOT import scenarios/answer_key/
ground truth -- the target has no path to its own expected answers.
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOOPBACK = "127.0.0.1"
OWNER_ID = "42"  # /svc/golf owner; any other id is a "victim" object


class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.flaky_counter = 0
        self.cached_seen: set[str] = set()
        self.race_in_flight = 0
        self.request_log: list[dict] = []  # independent evidence trail (B1)

    def reset(self) -> None:
        with self.lock:
            self.flaky_counter = 0
            self.cached_seen.clear()
            self.race_in_flight = 0
            self.request_log.clear()


def _has_session(headers) -> bool:
    return "session=" in (headers.get("Cookie", "") or "")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a, **k) -> None:
        return

    def _send(self, status: int, body: str) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _record(self, path: str, qs: dict) -> None:
        st: _State = self.server.state  # type: ignore[attr-defined]
        with st.lock:
            st.request_log.append({
                "method": "GET",
                "path": path,
                "session": _has_session(self.headers),
                "x_access": self.headers.get("X-Access", ""),
                "x_role": self.headers.get("X-Role", ""),
                "flag": qs.get("flag", [""])[0],
                "trace": qs.get("trace", [""])[0],
            })

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        st: _State = self.server.state  # type: ignore[attr-defined]
        mode = self.server.mode  # type: ignore[attr-defined]
        self._record(path, qs)

        # alpha/{id}: session cookie NECESSARY; trace param IRRELEVANT.
        if path.startswith("/svc/alpha/"):
            return self._send(200, "DOC-SECRET-CONTENTS") if _has_session(self.headers) else self._send(401, "unauthorized")

        # bravo: X-Access header OR session cookie -> TWO independent paths.
        if path == "/svc/bravo":
            ok = self.headers.get("X-Access", "") == "grant" or _has_session(self.headers)
            return self._send(200, "REPORT-DATA") if ok else self._send(403, "forbidden")

        # charlie: X-Role admin AND flag=on together -> INTERACTION.
        if path == "/svc/charlie":
            ok = self.headers.get("X-Role", "") == "admin" and qs.get("flag", [""])[0] == "on"
            return self._send(200, "MERGED") if ok else self._send(403, "forbidden")

        # delta: alternates 200/403 -> non-constant baseline (nondeterminism).
        if path == "/svc/delta":
            with st.lock:
                st.flaky_counter += 1
                even = st.flaky_counter % 2 == 0
            return self._send(200 if even else 403, "ok" if even else "no")

        # echo/{key}: first hit 200, then 403 (cache/one-shot confounder).
        if path.startswith("/svc/echo/"):
            key = path[len("/svc/echo/"):]
            with st.lock:
                first = key not in st.cached_seen
                st.cached_seen.add(key)
            return self._send(200 if first else 403, "fresh" if first else "stale")

        # foxtrot: succeeds only under real concurrency (race).
        if path == "/svc/foxtrot":
            with st.lock:
                st.race_in_flight += 1
                peak = st.race_in_flight
            time.sleep(0.05)
            with st.lock:
                concurrent = st.race_in_flight >= 2
                st.race_in_flight -= 1
            return self._send(200, "RACE-WON") if (concurrent or peak >= 2) else self._send(409, "race-lost")

        # golf/{id}: IDOR, MODE-DEPENDENT (the mutation scenario, B2).
        #   no session -> 401; own id -> 200 both modes;
        #   other id -> vulnerable: 200 VICTIM-DOC ; patched: 403.
        if path.startswith("/svc/golf/"):
            obj = path[len("/svc/golf/"):]
            if not _has_session(self.headers):
                return self._send(401, "unauthorized")
            if obj == OWNER_ID:
                return self._send(200, "OWN-DOC")
            if mode == "vulnerable":
                return self._send(200, f"VICTIM-DOC-{obj}")
            return self._send(403, "forbidden")

        return self._send(404, "not found")


class CemBenchmarkServer:
    """Loopback-only benchmark target. mode in {'vulnerable','patched'} (B2)."""

    def __init__(self, mode: str = "vulnerable") -> None:
        if mode not in ("vulnerable", "patched"):
            raise ValueError("mode must be 'vulnerable' or 'patched'")
        self._httpd = ThreadingHTTPServer((LOOPBACK, 0), _Handler)
        self._httpd.state = _State()      # type: ignore[attr-defined]
        self._httpd.mode = mode           # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def mode(self) -> str:
        return self._httpd.mode  # type: ignore[attr-defined]

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{LOOPBACK}:{self.port}"

    def requests(self) -> list[dict]:
        """Independent evidence trail of what actually hit the target (B1)."""
        with self._httpd.state.lock:  # type: ignore[attr-defined]
            return list(self._httpd.state.request_log)  # type: ignore[attr-defined]

    def reset(self) -> None:
        self._httpd.state.reset()  # type: ignore[attr-defined]

    def start(self) -> "CemBenchmarkServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "CemBenchmarkServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
