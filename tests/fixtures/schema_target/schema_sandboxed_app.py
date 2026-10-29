"""Container-based schema_app launcher for schemathesis-mcp's real
end-to-end test (tests/test_schemathesis_mcp_fixture_e2e.py).

Why this exists: the real schemathesis-mcp tool (run_schema_test ->
job_runtime.start_job() -> sandbox_runner.build_argv()) gives every
invocation its own isolated Podman network namespace with no
host-loopback reverse connectivity -- a sandboxed schemathesis process
cannot reach schema_app.py's host-thread, 127.0.0.1-bound
SchemaTargetApp at all (confirmed empirically: a real run against it
got "Connection refused", since 127.0.0.1 inside the sandboxed
container's own network namespace refers to the container itself, not
the host).

SandboxedSchemaApp runs schema_app.py inside its OWN throwaway container
instead, attached to a fresh, uniquely-named, --internal (no route to
the host or the internet) Podman network. The caller is responsible for
also setting sandbox_runner's HUNTMCP_BENCH_NETWORK to `.network_name`
(e.g. via monkeypatch.setenv, scoped to one test) before invoking
run_schema_test -- that is what makes the tool's OWN sandboxed container
join the same private network and reach `.base_url` by its alias. Never
exposes a host port; never reachable from the real network; the
mechanism lives entirely under tests/fixtures/schema_target/, never
imported by any production code path.

Mirrors tests/fixtures/bench_target/bench_sandboxed_app.py exactly, same
rationale, same pinned base image -- the only real differences are the
network-name prefix (huntmcp-schema-net- vs huntmcp-bench-net-, both
accepted by sandbox_runner._BENCH_NETWORK_PREFIXES) and the target
module/alias/health-check path.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "mcp-servers"))
import sandbox_runner  # noqa: E402 -- reuse remove_container()'s established best-effort force-remove semantics

_SCHEMA_APP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema_app.py")
# Same pinned digest as bench_sandboxed_app.py's own _IMAGE -- same
# reproducibility rationale (.claude/rules/benchmarks.md): schema_app.py
# is stdlib-only, so any current CPython 3.12 build behaves identically
# for it; reusing the already-reviewed, already-pulled digest avoids a
# second, redundant image pull for what is the same runtime requirement.
_IMAGE = "docker.io/library/python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
_CONTAINER_PORT = 8000
_ALIAS = "schema-target"


class SchemaContainerStartupError(RuntimeError):
    pass


class SandboxedSchemaApp:
    def __init__(self, mode: str) -> None:
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        self.network_name = f"huntmcp-schema-net-{uuid.uuid4().hex[:12]}"
        self.container_name = f"huntmcp-schema-app-{uuid.uuid4().hex[:12]}"
        self._network_created = False
        self._container_started = False

    def start(self, ready_timeout_s: float = 20.0) -> "SandboxedSchemaApp":
        subprocess.run(
            ["podman", "network", "create", "--internal", self.network_name],
            check=True, capture_output=True, text=True, timeout=15,
        )
        self._network_created = True
        try:
            subprocess.run(
                [
                    "podman", "run", "-d", "--rm",
                    "--name", self.container_name,
                    "--network", self.network_name,
                    "--network-alias", _ALIAS,
                    "--volume", f"{_SCHEMA_APP_PATH}:/schema_app.py:ro",
                    "--env", "SCHEMA_APP_BIND=0.0.0.0",
                    f"--env=SCHEMA_APP_PORT={_CONTAINER_PORT}",
                    _IMAGE, "python3", "/schema_app.py", self.mode,
                ],
                check=True, capture_output=True, text=True, timeout=60,
            )
            self._container_started = True
            self._wait_until_ready(ready_timeout_s)
        except Exception:
            self.stop()
            raise
        return self

    def _wait_until_ready(self, timeout_s: float) -> None:
        # The host has no route into an --internal network (that's the
        # point), so readiness is polled via `podman exec` INTO the
        # already-running schema_app container itself (reusing its
        # existing network namespace) rather than spinning up a brand-new
        # throwaway container per poll attempt -- same established
        # pattern as bench_sandboxed_app.py's own _wait_until_ready().
        deadline = time.time() + timeout_s
        last_err = ""
        while time.time() < deadline:
            try:
                probe = subprocess.run(
                    [
                        "podman", "exec", self.container_name, "python3", "-c",
                        "import urllib.request; "
                        f"urllib.request.urlopen('http://127.0.0.1:{_CONTAINER_PORT}/schema/health', timeout=3)",
                    ],
                    capture_output=True, text=True, timeout=5,
                )
            except subprocess.TimeoutExpired as e:
                last_err = f"probe timed out: {e}"
                time.sleep(0.5)
                continue
            if probe.returncode == 0:
                return
            last_err = probe.stderr.strip()
            time.sleep(0.5)
        raise SchemaContainerStartupError(
            f"schema_app container {self.container_name!r} on network "
            f"{self.network_name!r} did not become ready within {timeout_s}s: {last_err}"
        )

    @property
    def base_url(self) -> str:
        return f"http://{_ALIAS}:{_CONTAINER_PORT}"

    def stop(self) -> None:
        if self._container_started:
            sandbox_runner.remove_container(self.container_name)
            self._container_started = False
        if self._network_created:
            subprocess.run(["podman", "network", "rm", self.network_name],
                            capture_output=True, text=True, timeout=15)
            self._network_created = False
