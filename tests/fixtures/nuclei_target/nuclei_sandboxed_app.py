"""Container-based nuclei_app launcher for nuclei-mcp's real end-to-end
P3-FANOUT test (tests/test_fanout_nuclei_e2e.py).

Why this exists: the real nuclei-mcp tool (scan_batch_with_templates() ->
fanout.start_batch() -> job_runtime.start_job() -> sandbox_runner.build_argv())
gives every invocation its own isolated Podman network namespace with no
host-loopback reverse connectivity -- a sandboxed nuclei process cannot
reach nuclei_app.py's host-thread, 127.0.0.1-bound fixture at all (same
gap SandboxedSchemaApp's own module docstring documents, confirmed
empirically there and not re-litigated here).

SandboxedNucleiApp runs nuclei_app.py inside its OWN throwaway container,
attached to a fresh, uniquely-named, --internal (no route to the host or
the internet) Podman network -- same mechanism as SandboxedSchemaApp /
SandboxedBenchApp. The caller is responsible for also setting
sandbox_runner's HUNTMCP_BENCH_NETWORK to `.network_name` (e.g. via
monkeypatch.setenv, scoped to one test) before invoking a real nuclei-mcp
tool function -- that is what makes the tool's OWN sandboxed container
join the same private network and reach any of `.aliases` by name.

Unlike SandboxedSchemaApp/SandboxedBenchApp (one fixed alias each), this
launcher publishes the SAME container under SEVERAL --network-alias names
at once -- Podman supports repeating that flag, and every alias resolves
(via the network's own embedded DNS) to the one container's IP. This is
what lets one tiny fixture stand in for "N distinct batch targets, one of
which is rigged to look rate-limited": nuclei_app.py's own /limited route
inspects the incoming Host header to decide whether THIS particular
alias is the rigged one (see nuclei_app.py's RIGGED_HOST_PREFIX) --
nuclei itself sends a Host header matching whichever URL the agent gave
it, so each alias genuinely behaves like its own independent target from
nuclei's point of view, without needing N separate containers.

Never exposes a host port; never reachable from the real network; the
mechanism lives entirely under tests/fixtures/nuclei_target/, never
imported by any production code path.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "mcp-servers"))
import sandbox_runner  # noqa: E402 -- reuse remove_container()'s established best-effort force-remove semantics

_NUCLEI_APP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nuclei_app.py")
# Same pinned digest as schema_sandboxed_app.py/bench_sandboxed_app.py's own
# _IMAGE -- same reproducibility rationale (.claude/rules/benchmarks.md):
# nuclei_app.py is stdlib-only, so any current CPython 3.12 build behaves
# identically for it; reusing the already-reviewed, already-pulled digest
# avoids a second, redundant image pull for the same runtime requirement.
_IMAGE = "docker.io/library/python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
_CONTAINER_PORT = 8000

# Default aliases this fixture publishes when a caller doesn't supply its
# own list -- one rigged (matches nuclei_app.RIGGED_HOST_PREFIX) plus two
# plain ones, enough for the real e2e test's "N targets, one rigged" batch
# without the test itself having to know the exact prefix convention.
RIGGED_ALIAS = "nuclei-rigged"
PLAIN_ALIASES = ("nuclei-plain-1", "nuclei-plain-2")
DEFAULT_ALIASES = (RIGGED_ALIAS, *PLAIN_ALIASES)


class NucleiContainerStartupError(RuntimeError):
    pass


class SandboxedNucleiApp:
    def __init__(self, aliases: tuple[str, ...] = DEFAULT_ALIASES) -> None:
        self.aliases = aliases
        self.network_name = f"huntmcp-schema-net-{uuid.uuid4().hex[:12]}"
        self.container_name = f"huntmcp-nuclei-app-{uuid.uuid4().hex[:12]}"
        self._network_created = False
        self._container_started = False

    def start(self, ready_timeout_s: float = 20.0) -> "SandboxedNucleiApp":
        subprocess.run(
            ["podman", "network", "create", "--internal", self.network_name],
            check=True, capture_output=True, text=True, timeout=15,
        )
        self._network_created = True
        try:
            alias_flags = []
            for alias in self.aliases:
                alias_flags += ["--network-alias", alias]
            subprocess.run(
                [
                    "podman", "run", "-d", "--rm",
                    "--name", self.container_name,
                    "--network", self.network_name,
                    *alias_flags,
                    "--volume", f"{_NUCLEI_APP_PATH}:/nuclei_app.py:ro",
                    "--env", "NUCLEI_APP_BIND=0.0.0.0",
                    f"--env=NUCLEI_APP_PORT={_CONTAINER_PORT}",
                    _IMAGE, "python3", "/nuclei_app.py",
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
        # Same "podman exec INTO the already-running container" readiness
        # pattern as SandboxedSchemaApp/SandboxedBenchApp's own
        # _wait_until_ready() -- the host has no route into an --internal
        # network, so a fresh throwaway probe container can't reach it
        # either; exec'ing into the target container itself reuses its own
        # network namespace instead.
        deadline = time.time() + timeout_s
        last_err = ""
        while time.time() < deadline:
            try:
                probe = subprocess.run(
                    [
                        "podman", "exec", self.container_name, "python3", "-c",
                        "import urllib.request; "
                        f"urllib.request.urlopen('http://127.0.0.1:{_CONTAINER_PORT}/health', timeout=3)",
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
        raise NucleiContainerStartupError(
            f"nuclei_app container {self.container_name!r} on network "
            f"{self.network_name!r} did not become ready within {timeout_s}s: {last_err}"
        )

    def target_url(self, alias: str) -> str:
        assert alias in self.aliases, f"{alias!r} is not one of this fixture's own aliases {self.aliases!r}"
        return f"http://{alias}:{_CONTAINER_PORT}"

    def stop(self) -> None:
        if self._container_started:
            sandbox_runner.remove_container(self.container_name)
            self._container_started = False
        if self._network_created:
            subprocess.run(["podman", "network", "rm", self.network_name],
                            capture_output=True, text=True, timeout=15)
            self._network_created = False
