"""Container-based bench_app launcher for P2-BENCH's real-tool
fixture-proof tests (Tasks 12-17 of
docs/superpowers/plans/2026-09-17-p2-bench-implementation.md).

Why this exists: the real Tier-2 MCP tool functions (sqlmap-mcp,
dalfox-mcp, ffuf-mcp, nuclei-mcp, curl via tool_resolver) always route
through job_runtime.start_job() -> sandbox_runner.build_argv(), which
gives every invocation its own isolated Podman network namespace with no
host-loopback reverse connectivity -- a sandboxed tool cannot reach
bench_app.py's host-thread, 127.0.0.1-bound BenchApp at all (confirmed
empirically, see the plan's 2026-09-22 networking-seam decision note).

SandboxedBenchApp runs bench_app.py inside its OWN throwaway container
instead, attached to a fresh, uniquely-named, --internal (no route to the
host or the internet) Podman network. The caller is responsible for also
setting sandbox_runner's HUNTMCP_BENCH_NETWORK to `.network_name` (e.g.
via monkeypatch.setenv, scoped to one test) before invoking a real MCP
tool function -- that is what makes the tool's OWN sandboxed container
join the same private network and reach `.base_url` by its alias. Never
exposes a host port; never reachable from the real network; the mechanism
lives entirely under tests/fixtures/bench_target/, never imported by any
production code path.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "mcp-servers"))
import sandbox_runner  # noqa: E402 -- reuse remove_container()'s established best-effort force-remove semantics

_BENCH_APP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_app.py")
# Pinned by digest, not the floating "3.12-slim" tag -- same reproducibility
# rationale as nuclei-mcp/templates_pin.py's TEMPLATES_PINNED_SHA: a
# benchmark's own evidence must be reproducible from recorded config
# (.claude/rules/benchmarks.md), and a floating tag can silently change
# out from under a later run. bench_app.py is stdlib-only, so any current
# CPython 3.12 build behaves identically for it; this pin is about
# reproducibility and availability (no surprise re-pull), not correctness.
# Bump deliberately (re-pull and update the digest) when wanted; never
# silently follow upstream's own "latest 3.12-slim" drift.
_IMAGE = "docker.io/library/python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
_CONTAINER_PORT = 8000
_ALIAS = "bench-target"


class BenchContainerStartupError(RuntimeError):
    pass


class SandboxedBenchApp:
    def __init__(self, mode: str) -> None:
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        self.network_name = f"huntmcp-bench-net-{uuid.uuid4().hex[:12]}"
        self.container_name = f"huntmcp-bench-app-{uuid.uuid4().hex[:12]}"
        self._network_created = False
        self._container_started = False

    def start(self, ready_timeout_s: float = 20.0) -> "SandboxedBenchApp":
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
                    "--volume", f"{_BENCH_APP_PATH}:/bench_app.py:ro",
                    "--env", "BENCH_APP_BIND=0.0.0.0",
                    f"--env=BENCH_APP_PORT={_CONTAINER_PORT}",
                    _IMAGE, "python3", "/bench_app.py", self.mode,
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
        # already-running bench_app container itself (reusing its
        # existing network namespace) rather than spinning up a brand-new
        # throwaway container per poll attempt (found in adversarial
        # review, 2026-09-23: the original probe-container approach paid
        # a full container-creation cost, image-layer setup included, on
        # every ~0.5s poll).
        deadline = time.time() + timeout_s
        last_err = ""
        while time.time() < deadline:
            try:
                probe = subprocess.run(
                    [
                        "podman", "exec", self.container_name, "python3", "-c",
                        "import urllib.request; "
                        f"urllib.request.urlopen('http://127.0.0.1:{_CONTAINER_PORT}/bench/status', timeout=3)",
                    ],
                    capture_output=True, text=True, timeout=5,
                )
            except subprocess.TimeoutExpired as e:
                # A hung probe must not escape as an uncaught exception
                # (found in adversarial review) -- treat it as one more
                # failed attempt so the remaining timeout budget still
                # gets used, exactly like a nonzero-returncode attempt.
                last_err = f"probe timed out: {e}"
                time.sleep(0.5)
                continue
            if probe.returncode == 0:
                return
            last_err = probe.stderr.strip()
            time.sleep(0.5)
        raise BenchContainerStartupError(
            f"bench_app container {self.container_name!r} on network "
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
