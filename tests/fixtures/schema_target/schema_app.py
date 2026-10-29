"""Isolated JSON API fixture for P3-SCHEMA's schemathesis dependency
validation (TEST FIXTURE ONLY). See docs/superpowers/specs/
2026-10-10-p3-schema-fixture-design.md for the full design rationale.

Separate from tests/fixtures/bench_target/ (the protected P2-BENCH
benchmark, untouched by this file) and tests/fixtures/cem_target/ (CEM's
own causal-necessity fixture) -- a sibling fixture, same precedent as
tests/fixtures/injection_target/injection_app.py.

Serves a tiny JSON API plus its own OpenAPI 3.0.3 document at
/openapi.json (single source of truth -- the spec is generated from the
same module that implements the behavior it describes, so it can't
drift). One deliberate planted bug, vulnerable/patched pair: GET
/schema/items accepts a required, unconstrained integer page_size query
parameter; vulnerable mode divides by it with no validation
(ZeroDivisionError at page_size=0, caught and turned into a real HTTP 500
-- stdlib BaseHTTPRequestHandler does NOT do this automatically for an
uncaught exception, it just drops the connection, so the 500 must be
sent explicitly, same pattern bench_app.py's /bench/products
SQLite-error handling already uses); patched mode validates page_size >=
1 first and returns a declared 400 otherwise. GET /schema/health is an
unrelated, parameter-free negative control, identical in both modes.

Safe by construction: binds ONLY to 127.0.0.1 on an ephemeral port; zero
outbound calls; holds all state in-process.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOOPBACK = "127.0.0.1"

ITEMS = ["widget", "gadget", "gizmo"]

# The vulnerable mode's actual 500 is deliberately NOT declared here --
# per the design spec, an unexpected server error must stay undeclared
# so status_code_conformance correctly flags it as undocumented on top
# of not_a_server_error flagging the 5xx itself.
_OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "schema-target (TEST FIXTURE ONLY)", "version": "1.0"},
    "paths": {
        "/schema/health": {
            "get": {
                "operationId": "health",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"status": {"type": "string"}},
                                    "required": ["status"],
                                }
                            }
                        },
                    }
                },
            }
        },
        "/schema/items": {
            "get": {
                "operationId": "listItems",
                "parameters": [
                    {
                        "name": "page_size",
                        "in": "query",
                        "required": True,
                        # Deliberately no "minimum" -- this is the exact
                        # spec-under-constrains-input class schemathesis
                        # targets. "example": 0 makes the planted bug
                        # deterministic under schemathesis's "examples"
                        # phase (design spec Sec 2), independent of the
                        # fuzzing phase's random search budget.
                        "schema": {"type": "integer", "example": 0},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "items": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                        "page_count": {"type": "integer"},
                                    },
                                    "required": ["items", "page_count"],
                                }
                            }
                        },
                    },
                    "400": {
                        "description": "Bad Request",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"error": {"type": "string"}},
                                    "required": ["error"],
                                }
                            }
                        },
                    },
                },
            }
        },
    },
}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a, **k) -> None:
        return

    def _send(self, status: int, obj: dict) -> None:
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        mode = self.server.mode  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)

        if path == "/openapi.json":
            return self._send(200, _OPENAPI_SPEC)

        if path == "/schema/health":
            return self._send(200, {"status": "ok"})

        if path == "/schema/items":
            if "page_size" not in qs:
                return self._send(400, {"error": "page_size is required"})
            raw = qs["page_size"][0]
            try:
                page_size = int(raw)
            except ValueError:
                return self._send(400, {"error": "page_size must be an integer"})
            if mode == "vulnerable":
                try:
                    page_count = len(ITEMS) // page_size
                except ZeroDivisionError:
                    # Real 500: BaseHTTPRequestHandler does NOT turn an
                    # uncaught exception into a 500 response on its own
                    # -- it just drops the connection -- so this must be
                    # sent explicitly to be a realistic server error.
                    return self._send(500, {"error": "internal error"})
            else:
                if page_size < 1:
                    return self._send(400, {"error": "page_size must be >= 1"})
                page_count = len(ITEMS) // page_size
            return self._send(200, {"items": ITEMS, "page_count": page_count})

        return self._send(404, {"error": "not found"})


def _make_server(mode: str, bind: str = LOOPBACK, port: int = 0) -> ThreadingHTTPServer:
    """`bind`/`port` default to the loopback-only, ephemeral-port behavior
    every existing caller (SchemaTargetApp.start(), below) relies on as a
    deliberate security property. The only intended caller of a
    non-default `bind` is schema_sandboxed_app.py's container entrypoint
    (__main__ block below) -- that process runs inside its own throwaway,
    network-isolated container, so a 0.0.0.0 bind there is scoped by the
    container boundary, not a loopback-only host process. Mirrors
    tests/fixtures/bench_target/bench_app.py's own _make_server()
    exactly, same rationale."""
    srv = ThreadingHTTPServer((bind, port), _Handler)
    srv.mode = mode  # type: ignore[attr-defined]
    return srv


class SchemaTargetApp:
    """Loopback-only fixture. mode in {'vulnerable', 'patched'}."""

    def __init__(self, mode: str = "vulnerable") -> None:
        if mode not in ("vulnerable", "patched"):
            raise ValueError("mode must be 'vulnerable' or 'patched'")
        self._httpd = _make_server(mode)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        _, port = self._httpd.server_address
        return f"http://{LOOPBACK}:{port}"

    def start(self) -> "SchemaTargetApp":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> "SchemaTargetApp":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


if __name__ == "__main__":
    # Container entrypoint ONLY -- invoked by schema_sandboxed_app.py
    # inside schema_app's own throwaway, --internal (no host/internet
    # route) container, for schemathesis-mcp's real end-to-end test
    # (tests/test_schemathesis_mcp_fixture_e2e.py). Never invoked by
    # SchemaTargetApp (the host-thread, loopback-only path) -- that class
    # still calls _make_server() with its own unchanged defaults. Mirrors
    # tests/fixtures/bench_target/bench_app.py's own __main__ block.
    import os
    import sys

    _mode = sys.argv[1] if len(sys.argv) > 1 else "vulnerable"
    _bind = os.environ.get("SCHEMA_APP_BIND", LOOPBACK)
    _port = int(os.environ.get("SCHEMA_APP_PORT", "8000"))
    _make_server(_mode, bind=_bind, port=_port).serve_forever()
