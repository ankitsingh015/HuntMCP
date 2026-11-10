"""End-to-end: drives the actual, UNMODIFIED nuclei-mcp server (not a mock
of job_runtime/work_registry, unlike every other P3-FANOUT test so far)
through the REAL S5 sandbox against a containerized
tests/fixtures/nuclei_target/ fixture.

Mirrors tests/test_schemathesis_mcp_fixture_e2e.py's own real-sandbox
pattern as closely as possible (same gating convention, same
HUNTMCP_BENCH_NETWORK mechanism, same "import the server module via
importlib.util.spec_from_file_location" trick) -- see that file's module
docstring for the full networking-seam rationale (a sandboxed process has
no host-loopback reverse connectivity, so the fixture has to run inside
its OWN throwaway, --internal Podman network and the tool's own sandboxed
container has to join it).

What this proves that no earlier P3-FANOUT test could (Tasks 1-5 all
mocked job_runtime/work_registry):

  (a) a real scan_batch_with_templates() batch run through the real
      sandboxed nuclei binary accounts for every target -- none silently
      dropped, even though the whole fanout machinery (bounded
      concurrency, dedupe, backoff) sits between the tool call and the
      real subprocess;
  (b) a real 429 response from one rigged target is actually classified
      as a block by tool_resolver.classify_block() (via job_runtime.
      poll_job()) and surfaced through check_batch()'s own
      block_prefix() -- not just a mocked `{"block": "rate_limit"}`
      dict handed to fanout directly;
  (c) that real block causes fanout._record_block() to actually persist
      a reduced effective cap to disk, readable via a fresh
      fanout._effective_cap("nuclei") call after the batch is done --
      proving the backoff state really survived past this one batch,
      not just within one in-memory test run.

Requires BOTH podman AND the actual rebuilt sandbox image AND a real,
populated nuclei-templates snapshot (templates_pin.templates_available())
-- gating on the podman binary alone was a real bug class already found
and fixed in this repo's P2-BENCH work; do not repeat it here.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import time
import uuid

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "nuclei-mcp"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "nuclei_target"))

import fanout  # noqa: E402
import sandbox_runner  # noqa: E402
import templates_pin  # noqa: E402
from nuclei_sandboxed_app import DEFAULT_ALIASES, PLAIN_ALIASES, RIGGED_ALIAS, SandboxedNucleiApp  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "nuclei_mcp_server_e2e", os.path.join(ROOT, "mcp-servers", "nuclei-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

_FIXTURE_TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "nuclei_target", "templates",
)

# Monkeypatched onto fanout.DEFAULT_CAPS for this test only -- small enough
# (with len(DEFAULT_ALIASES) == 3 real targets) that the batch genuinely
# cannot run everything at once, so the bounded-concurrency path is
# exercised for real rather than trivially satisfied by "cap >= target
# count".
_TEST_CAP = 2


def _podman_and_image_available() -> bool:
    if not shutil.which("podman"):
        return False
    result = subprocess.run(
        ["podman", "image", "exists", sandbox_runner.SANDBOX_IMAGE],
        capture_output=True, timeout=10,
    )
    return result.returncode == 0


requires_sandbox_and_templates = pytest.mark.skipif(
    not (_podman_and_image_available() and templates_pin.templates_available()),
    reason="podman/huntmcp-sandbox image, or the pinned nuclei-templates snapshot, "
           "not available -- run `podman build -t localhost/huntmcp-sandbox:2026-10-20 "
           "mcp-servers/sandbox/` and `scripts/fetch-nuclei-templates.sh` first",
)


@pytest.fixture
def in_scope_engagement(tmp_path, monkeypatch):
    # Every alias this fixture publishes (see nuclei_sandboxed_app.py) must
    # be explicitly in scope -- these hostnames resolve only inside the
    # throwaway --internal network, never on the real internet, but
    # _prepare()'s scope_guard.pin_hosts_or_error() call still runs the
    # normal in_scope check before (deliberately) skipping the DNS-pin step
    # itself for HUNTMCP_BENCH_NETWORK runs.
    in_scope = "\n".join(f"  - {alias}" for alias in DEFAULT_ALIASES)
    eng = tmp_path / "engagement.yaml"
    eng.write_text(f"target: nuclei-target\nin_scope:\n{in_scope}\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    # Full isolation from any real, on-disk engagement state -- a batch run
    # here must never dedupe against, or pollute, a genuine engagement's
    # own work-registry/backoff files (see this repo's own P3-FANOUT commit
    # "docs: note HUNTMCP_WORK_REGISTRY_PATH for test isolation").
    monkeypatch.setenv("HUNTMCP_WORK_REGISTRY_PATH", str(tmp_path / "work-registry.json"))
    monkeypatch.setenv("HUNTMCP_FANOUT_BACKOFF_PATH", str(tmp_path / "fanout-backoff.json"))
    return tmp_path


@pytest.fixture
def sandboxed_nuclei_fixture(monkeypatch):
    app = SandboxedNucleiApp().start()
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", app.network_name)
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture
def custom_templates_dir():
    # _resolve_templates_arg() only ever accepts a path that resolves
    # INSIDE templates_pin.TEMPLATES_DIR (that's the only directory
    # _prepare() bind-mounts into the sandbox) -- so this fixture's own
    # two tiny test-only templates have to live under there for the real
    # sandboxed nuclei process to ever see them. A fresh, uniquely-named
    # subdirectory keeps this test's files from colliding with anything
    # else that might read the pinned snapshot concurrently, and the
    # whole thing is removed again in the finally: below -- the pinned
    # snapshot itself (data/nuclei-templates/, gitignored, fetched by
    # scripts/fetch-nuclei-templates.sh) is never otherwise touched.
    rel_name = f"_p3_fanout_e2e_{uuid.uuid4().hex[:8]}"
    abs_dir = os.path.join(templates_pin.TEMPLATES_DIR, rel_name)
    os.makedirs(abs_dir)
    try:
        for fname in ("fanout-test-panel.yaml", "fanout-test-ratelimit.yaml"):
            shutil.copyfile(
                os.path.join(_FIXTURE_TEMPLATES_DIR, fname),
                os.path.join(abs_dir, fname),
            )
        yield rel_name
    finally:
        shutil.rmtree(abs_dir, ignore_errors=True)


@requires_sandbox_and_templates
def test_batch_concurrency_drops_after_a_simulated_rate_limit(
    in_scope_engagement, sandboxed_nuclei_fixture, custom_templates_dir, monkeypatch,
):
    monkeypatch.setattr(fanout, "DEFAULT_CAPS", {"nuclei": _TEST_CAP})

    fixture = sandboxed_nuclei_fixture
    target_urls = [fixture.target_url(alias) for alias in fixture.aliases]
    rigged_url = fixture.target_url(RIGGED_ALIAS)
    plain_urls = [fixture.target_url(a) for a in PLAIN_ALIASES]
    assert len(target_urls) > _TEST_CAP, "test needs more real targets than the cap to prove bounding"

    out = srv.scan_batch_with_templates(
        targets=",".join(target_urls), templates=custom_templates_dir, timeout=90,
    )
    assert 'batch_id="' in out, f"scan_batch_with_templates did not start a batch: {out!r}"
    batch_id = out.split('batch_id="', 1)[1].split('"', 1)[0]

    # Bounded concurrency, evidenced off the REAL live batch state (not a
    # mock): with 3 real targets and a cap of 2, the batch must not have
    # launched all 3 jobs at once, immediately after start_batch() returned.
    batch = srv._batches.get(batch_id)
    if batch is not None:  # may already be gone if everything somehow finished instantly
        assert len(batch.in_flight) <= _TEST_CAP
        assert len(batch.in_flight) + len(batch.pending) == len(target_urls)

    deadline = time.monotonic() + 90
    final_text = None
    while time.monotonic() < deadline:
        result = srv.check_batch(batch_id)
        if "Still running" not in result:
            final_text = result
            break
        time.sleep(2)
    if final_text is None:
        pytest.fail(f"nuclei batch {batch_id} did not finish within 90s")

    # (a) every target accounted for -- none silently dropped by the real
    # fanout/job_runtime/sandbox pipeline.
    for url in target_urls:
        assert url in final_text, f"target {url!r} missing from final batch result:\n{final_text}"
    assert "skipped -- already in progress elsewhere" not in final_text, final_text
    assert "BLOCKED by scope gate" not in final_text, final_text
    # Confirms the panel template genuinely ran (and matched) against
    # every single target, not just some -- real evidence nothing was
    # dropped or truncated mid-batch.
    assert final_text.count("fanout-test-panel") == len(target_urls), final_text

    # (b) the real 429 from the rigged target was actually classified as a
    # block by tool_resolver.classify_block() and surfaced via
    # job_runtime.block_prefix() -- only for the rigged target's own line.
    # block_prefix() output lands on its OWN line immediately before the
    # "  {target}: ..." line (see nuclei-mcp/server.py's _format_batch_entry:
    # f"  {job_runtime.block_prefix(entry)}{target}: {formatted}", and
    # block_prefix() itself ends with "\n") -- so the marker is checked
    # against that line plus the one right before it, not just the line
    # containing the target string itself.
    lines = final_text.splitlines()

    def _entry_block_context(target_url: str) -> str:
        idx = next(i for i, line in enumerate(lines) if target_url in line)
        return "\n".join(lines[max(0, idx - 1):idx + 1])

    assert "RATE_LIMIT BLOCK DETECTED" in _entry_block_context(rigged_url), final_text
    for plain_url in plain_urls:
        assert "BLOCK DETECTED" not in _entry_block_context(plain_url), final_text

    # (c) that real block persisted a reduced effective cap to disk --
    # readable via a fresh call, proving it survived past this one batch
    # (same persistent-backoff-file mechanism _record_block()/
    # _effective_cap() already have unit coverage for with mocks; this is
    # the real end-to-end proof that a genuine classify_block() result
    # actually reaches _record_block()).
    reduced_cap = fanout._effective_cap("nuclei")
    assert reduced_cap < _TEST_CAP, (
        f"expected nuclei's effective cap to be reduced below {_TEST_CAP} "
        f"after a real rate-limit block, got {reduced_cap}"
    )
    assert reduced_cap == max(1, _TEST_CAP // 2)
