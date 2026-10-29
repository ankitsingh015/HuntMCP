"""End-to-end: drives the actual new schemathesis-mcp server (not raw CLI,
unlike the earlier 2026-10-10 fixture-validation work) through the REAL
S5 sandbox against a containerized tests/fixtures/schema_target/
fixture.

Uses SandboxedSchemaApp (schema_sandboxed_app.py), not the host-thread
SchemaTargetApp -- found live: run_schema_test's sandboxed schemathesis
process runs in its own Podman network namespace with no host-loopback
reverse connectivity, so it cannot reach a 127.0.0.1-bound host-thread
fixture at all (got a real "Connection refused", confirmed via a direct
debug run before this file was written this way). See
schema_sandboxed_app.py's own module docstring for the full mechanism
(mirrors tests/fixtures/bench_target/bench_sandboxed_app.py's own
P2-BENCH precedent for this exact problem).

Requires BOTH podman and the actual rebuilt sandbox image (see this
tool's implementation plan, Task 3, Step 7) -- gating on the podman
BINARY alone was a real bug class already found and fixed in this repo's
P2-BENCH work; do not repeat it here."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "schema_target"))

import sandbox_runner  # noqa: E402
from schema_sandboxed_app import SandboxedSchemaApp  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "schemathesis_mcp_server_e2e", os.path.join(ROOT, "mcp-servers", "schemathesis-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def _podman_and_image_available() -> bool:
    if not shutil.which("podman"):
        return False
    result = subprocess.run(
        ["podman", "image", "exists", sandbox_runner.SANDBOX_IMAGE],
        capture_output=True, timeout=10,
    )
    return result.returncode == 0


requires_sandbox = pytest.mark.skipif(
    not _podman_and_image_available(),
    reason="podman/huntmcp-sandbox image (with schemathesis) not available -- "
           "run `podman build -t localhost/huntmcp-sandbox:2026-10-20 "
           "mcp-servers/sandbox/` first",
)


@pytest.fixture
def in_scope_engagement(tmp_path, monkeypatch):
    # "schema-target" is the container alias SandboxedSchemaApp's
    # --network-alias publishes on the shared --internal Podman network
    # (see schema_sandboxed_app.py); the sandboxed schemathesis process
    # resolves it via that network's own embedded DNS, never the host's.
    eng = tmp_path / "engagement.yaml"
    eng.write_text("target: schema-target\nin_scope:\n  - schema-target\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_SCHEMATHESIS_TMP", str(tmp_path / "tmp-schemathesis"))
    return tmp_path


@pytest.fixture
def sandboxed_vulnerable_fixture(monkeypatch):
    app = SandboxedSchemaApp(mode="vulnerable").start()
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", app.network_name)
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture
def sandboxed_patched_fixture(monkeypatch):
    app = SandboxedSchemaApp(mode="patched").start()
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", app.network_name)
    try:
        yield app
    finally:
        app.stop()


def _run_to_completion(url: str, target: str, timeout_s: int = 90) -> str:
    out = srv.run_schema_test(url, target, timeout=timeout_s)
    assert "job_id" in out, f"run_schema_test did not start a job: {out!r}"
    job_id = out.split('job_id="', 1)[1].split('"', 1)[0]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = srv.check_scan(job_id)
        if "Still running" not in result:
            return result
        time.sleep(2)
    pytest.fail(f"schemathesis job {job_id} did not finish within {timeout_s}s")


@requires_sandbox
def test_e2e_detects_real_planted_bug_on_vulnerable_fixture(in_scope_engagement, sandboxed_vulnerable_fixture):
    fixture = sandboxed_vulnerable_fixture
    out = _run_to_completion(f"{fixture.base_url}/openapi.json", fixture.base_url)

    assert "Falsifiers" in out
    falsifier_line = [l for l in out.splitlines() if l.startswith("Falsifiers")][-1]
    payload = json.loads(falsifier_line.split(":", 1)[1].strip())
    assert len(payload) >= 1, f"expected a real falsifier hit, got none. Full output:\n{out}"
    assert any("ServerError" in f.get("type", "") for f in payload)


@requires_sandbox
def test_e2e_stays_clean_on_patched_fixture(in_scope_engagement, sandboxed_patched_fixture):
    fixture = sandboxed_patched_fixture
    out = _run_to_completion(f"{fixture.base_url}/openapi.json", fixture.base_url)

    falsifier_line = [l for l in out.splitlines() if l.startswith("Falsifiers")][-1]
    payload = json.loads(falsifier_line.split(":", 1)[1].strip())
    assert payload == [], f"expected a clean run, got falsifiers. Full output:\n{out}"
