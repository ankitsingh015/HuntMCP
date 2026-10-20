"""P3-SCHEMA fixture-validation: proves the newly-approved `schemathesis`
dependency can reliably detect a real, planted schema/property-robustness
violation on an isolated local JSON API fixture, and correctly stays
clean on the patched variant and an unrelated endpoint. See
docs/superpowers/specs/2026-10-10-p3-schema-fixture-design.md for the
full design rationale and the empirical research (exact CLI behavior,
phase/check selection) behind every choice below.

This is NOT the P3-SCHEMA mcp-server build: no job_runtime/sandbox, no
case_store writes, no CEM involvement. schemathesis is invoked directly
(unsandboxed, outside job_runtime/podman) via subprocess -- same category
of step as test_p2_inj_fixture_hunt.py's direct httpx/dalfox invocations
against tests/fixtures/injection_target/.

The vulnerable-mode HTTP 500 this fixture plants is a schema/property
ROBUSTNESS violation, not an automatically-confirmed security
vulnerability -- nothing here writes a finding or asserts security
impact; the assertions only check that schemathesis's own check
mechanism flags the violation class it exists to flag.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "schema_target"))

from schema_app import SchemaTargetApp  # noqa: E402


@pytest.fixture
def vulnerable_app():
    app = SchemaTargetApp(mode="vulnerable").start()
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture
def patched_app():
    app = SchemaTargetApp(mode="patched").start()
    try:
        yield app
    finally:
        app.stop()


def _get(url: str):
    """GET url, returning (status, json_body). Never raises on 4xx/5xx --
    urllib raises HTTPError for those, this normalizes both paths to one
    return shape so tests can assert on status without a try/except each."""
    try:
        with urllib.request.urlopen(url) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# --- Determinism safety net: plain HTTP, no schemathesis involved --------

def test_vulnerable_mode_page_size_zero_returns_500(vulnerable_app):
    status, body = _get(f"{vulnerable_app.base_url}/schema/items?page_size=0")
    assert status == 500
    assert body == {"error": "internal error"}


def test_patched_mode_page_size_zero_returns_400(patched_app):
    status, body = _get(f"{patched_app.base_url}/schema/items?page_size=0")
    assert status == 400
    assert body == {"error": "page_size must be >= 1"}


def test_health_endpoint_clean_in_both_modes(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        status, body = _get(f"{app.base_url}/schema/health")
        assert status == 200
        assert body == {"status": "ok"}


# --- Review Focus: edge cases on the fixture's one real input ------------

def test_non_integer_page_size_returns_400_in_both_modes(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        status, body = _get(f"{app.base_url}/schema/items?page_size=abc")
        assert status == 400
        assert body == {"error": "page_size must be an integer"}


def test_missing_page_size_returns_400_in_both_modes(vulnerable_app, patched_app):
    for app in (vulnerable_app, patched_app):
        status, body = _get(f"{app.base_url}/schema/items")
        assert status == 400
        assert body == {"error": "page_size is required"}


def test_negative_page_size_does_not_trigger_the_bug(vulnerable_app):
    # Pins the spec's explicit claim: only EXACTLY page_size=0 is the
    # deterministic trigger -- Python's floor division with a negative
    # divisor does not raise, so this must stay 200, not 500.
    status, body = _get(f"{vulnerable_app.base_url}/schema/items?page_size=-1")
    assert status == 200
    assert body["items"] == ["widget", "gadget", "gizmo"]


def test_schemathesis_available_check_rejects_wrong_version(monkeypatch):
    # Code review (audit pass): gating only on shutil.which("schemathesis")
    # presence -- not the exact pinned version -- means a stale/different
    # schemathesis resolvable on PATH would silently let these tests run
    # "successfully" against behavior never actually verified for that
    # version. Mirrors tests/test_p2_bench_fixture.py's own
    # _podman_and_image_available() precedent: binary-only checks in this
    # repo have caused real false-pass CI runs before (see its docstring).
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/schemathesis")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, stdout="schemathesis, version 3.19.7\n", stderr=""),
    )
    assert _schemathesis_available_and_correct_version() is False


def test_schemathesis_available_check_accepts_pinned_version(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/schemathesis")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 0, stdout=f"schemathesis, version {_PINNED_SCHEMATHESIS_VERSION}\n", stderr=""),
    )
    assert _schemathesis_available_and_correct_version() is True


def test_schemathesis_available_check_false_when_binary_missing(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert _schemathesis_available_and_correct_version() is False


# --- schemathesis integration: real CLI, real subprocess, real JSON report

# Narrow, verified-clean check set (design spec Sec 2) -- no auth-adjacent
# check (e.g. ignored_auth), preserving the schema/property-testing vs.
# VAL-AUTHZ authorization-differential boundary. "examples" phase only
# (not coverage/fuzzing/stateful): deterministic, driven by the OpenAPI
# document's own declared "example": 0 -- NOT a probabilistic claim about
# what Hypothesis's random search is likely to generate within some
# example budget. coverage was verified live to ALSO probe unimplemented
# HTTP verbs (e.g. TRACE), which stdlib's BaseHTTPRequestHandler answers
# with a real 501 -- a 5xx not_a_server_error correctly but IRRELEVANTLY
# flags, which would have broken the health-endpoint negative control.
_CHECKS = "not_a_server_error,status_code_conformance,response_schema_conformance"
_SCHEMATHESIS_TIMEOUT_S = 30

SCHEMATHESIS_BIN = shutil.which("schemathesis")
_PINNED_SCHEMATHESIS_VERSION = "4.30.1"


def _schemathesis_available_and_correct_version() -> bool:
    """Checks both binary presence AND an exact pinned-version match --
    mirrors tests/test_p2_bench_fixture.py's own
    _podman_and_image_available() precedent (code review, audit pass):
    that function's own docstring records a real CI incident where a
    binary-only check let a sandboxed podman run fail outright instead of
    skipping, "unlike every other real-tool test in this suite that's
    gated by the stronger, established check." A stale/different
    schemathesis resolvable on PATH would otherwise silently let these
    tests run "successfully" against behavior never actually verified for
    this repo's pinned 4.30.1 -- every empirical claim in the design spec
    (docs/superpowers/specs/2026-10-10-p3-schema-fixture-design.md Sec 2)
    was confirmed against that exact version, not "whatever schemathesis
    happens to be on PATH"."""
    binary = shutil.which("schemathesis")
    if binary is None:
        return False
    result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10, check=False)
    return _PINNED_SCHEMATHESIS_VERSION in result.stdout


requires_schemathesis = pytest.mark.skipif(
    not _schemathesis_available_and_correct_version(),
    reason=f"schemathesis not installed, or not the pinned version -- see "
           f".github/workflows/ci.yml for the pinned version this repo tests "
           f"against; install it locally (pip install "
           f"schemathesis=={_PINNED_SCHEMATHESIS_VERSION}) to run these.",
)


def _run_schemathesis(base_url: str, report_dir) -> dict:
    """Invoke the real schemathesis CLI (pinned 4.30.1 -- see
    .github/workflows/ci.yml) against `base_url`'s /openapi.json and
    return its structured JSON report as a dict, plus one extra key,
    "_exit_code" (the subprocess's own return code, not part of
    schemathesis's own report shape). Bounded subprocess timeout --
    _SCHEMATHESIS_TIMEOUT_S -- so a hung run can't block the suite."""
    result = subprocess.run(
        [
            SCHEMATHESIS_BIN, "run", f"{base_url}/openapi.json",
            "--checks", _CHECKS,
            "--phases", "examples",
            "--report", "json",
            "--report-dir", str(report_dir),
        ],
        capture_output=True, text=True, timeout=_SCHEMATHESIS_TIMEOUT_S, check=False,
        # schemathesis writes a .schemathesis/ example cache relative to
        # its own process CWD by default -- pin it to report_dir (already
        # a disposable tmp_path) so it never lands wherever the test
        # suite happens to be invoked from (e.g. an untracked, non-
        # gitignored directory at the repo root -- found in code review).
        cwd=str(report_dir),
    )
    report_files = [f for f in os.listdir(report_dir) if f.startswith("json-")]
    assert len(report_files) == 1, (
        f"expected exactly one schemathesis JSON report in {report_dir}, "
        f"found {report_files} -- stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    with open(os.path.join(report_dir, report_files[0])) as f:
        report = json.load(f)
    report["_exit_code"] = result.returncode
    return report


@requires_schemathesis
def test_schemathesis_examples_phase_flags_vulnerable_mode(vulnerable_app, tmp_path):
    report = _run_schemathesis(vulnerable_app.base_url, tmp_path)
    assert report["_exit_code"] != 0
    assert report["test_cases"]["with_failures"] >= 1
    server_error_failures = [
        f for f in report["failures"]
        if f["type"] == "ServerError" and "GET /schema/items" in f["operations"]
    ]
    assert server_error_failures, (
        f"expected a ServerError failure on GET /schema/items, "
        f"got: {report['failures']}"
    )


@requires_schemathesis
def test_schemathesis_examples_phase_clean_on_patched_mode(patched_app, tmp_path):
    report = _run_schemathesis(patched_app.base_url, tmp_path)
    assert report["_exit_code"] == 0
    assert report["test_cases"]["with_failures"] == 0
    assert report["failures"] == []


@requires_schemathesis
def test_run_schemathesis_does_not_leave_cache_in_cwd(vulnerable_app, tmp_path, monkeypatch):
    # schemathesis writes a .schemathesis/ example cache relative to its
    # own CWD by default -- without an explicit cwd=, that lands wherever
    # the TEST SUITE happens to be invoked from (e.g. the repo root),
    # an untracked, non-gitignored side effect, not this test's report_dir.
    other_cwd = tmp_path / "cwd"
    other_cwd.mkdir()
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    monkeypatch.chdir(other_cwd)
    _run_schemathesis(vulnerable_app.base_url, report_dir)
    assert not (other_cwd / ".schemathesis").exists()
