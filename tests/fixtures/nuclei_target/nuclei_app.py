"""Isolated HTTP fixture for P3-FANOUT's nuclei-mcp end-to-end proof
(TEST FIXTURE ONLY). See tests/test_fanout_nuclei_e2e.py for the real
end-to-end test this backs, and tests/fixtures/schema_target/schema_app.py
for the sibling precedent this mirrors (P3-SCHEMA).

Serves three routes, all stdlib-only, zero outbound calls:

- GET /health -- unconditional 200, used only for the container-exec
  readiness probe (NucleiContainerStartupError / _wait_until_ready()),
  identical role to schema_app.py's own /schema/health.
- GET /panel -- unconditional 200 with a distinctive body marker every
  target in the batch can match on (nuclei_target_templates/
  fanout-test-panel.yaml) -- this is what proves "every target's result
  is accounted for, nothing silently dropped" in the real e2e test: a
  target that was never contacted, or whose job result was dropped,
  would show up with this marker ABSENT from its formatted output.
- GET /limited -- the rigged route. Returns 429 (with a body containing
  the literal text "rate limit", matching tool_resolver.py's own
  _RATE_LIMIT_PATTERNS) ONLY when the incoming Host header's hostname
  starts with the alias this fixture's own RIGGED_HOST_PREFIX constant
  names; every other Host gets a plain 404. This is what lets ONE
  container, aliased under several different hostnames on the same
  Podman network (see nuclei_sandboxed_app.py), stand in for "N real
  targets, exactly one of which is rigged to look rate-limited" without
  needing N separate containers -- the Host header is the only thing
  that differs between an ordinary target and the rigged one from this
  process's point of view, same as any real vhost-routed backend.

Safe by construction: this module is never bound to a real network
interface by itself -- nuclei_sandboxed_app.py's container entrypoint is
the only thing that ever binds it to 0.0.0.0, and only inside its own
throwaway, --internal (no host/internet route) Podman network.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOOPBACK = "127.0.0.1"

# Any Host header whose hostname (before an optional ":port") starts with
# this is treated as the rigged target for /limited -- see this module's
# own docstring. Must match nuclei_sandboxed_app.py's RIGGED_ALIAS exactly
# (that module defines the alias name the fixture publishes on the Podman
# network; this module only ever compares against the prefix).
RIGGED_HOST_PREFIX = "nuclei-rigged"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a, **k) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            return self._send(200, b'{"status": "ok"}', "application/json")

        if self.path == "/panel":
            return self._send(200, b"FANOUT-PANEL-MARKER")

        if self.path == "/limited":
            host_header = (self.headers.get("Host") or "").split(":")[0]
            if host_header.startswith(RIGGED_HOST_PREFIX):
                return self._send(
                    429,
                    b"429 Too Many Requests: rate limit exceeded, please slow down",
                )
            return self._send(404, b"not found")

        return self._send(404, b"not found")


def _make_server(bind: str = LOOPBACK, port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((bind, port), _Handler)


if __name__ == "__main__":
    # Container entrypoint ONLY -- invoked by nuclei_sandboxed_app.py inside
    # this fixture's own throwaway, --internal (no host/internet route)
    # container. Mirrors schema_app.py's own __main__ block exactly.
    import os

    _bind = os.environ.get("NUCLEI_APP_BIND", LOOPBACK)
    _port = int(os.environ.get("NUCLEI_APP_PORT", "8000"))
    _make_server(bind=_bind, port=_port).serve_forever()
