"""schemathesis-mcp: scope/outbound-policy enforcement and job-launch wiring
for run_schema_test(). Report-parsing (check_scan's real behavior) is covered
separately in tests/test_schemathesis_mcp_report_parsing.py (Task 4)."""
import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "schemathesis_mcp_server", os.path.join(ROOT, "mcp-servers", "schemathesis-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


@pytest.fixture
def in_scope_engagement(tmp_path, monkeypatch):
    eng = tmp_path / "engagement.yaml"
    eng.write_text("target: t.example\nin_scope:\n  - t.example\nout_of_scope: []\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    # Isolates run_schema_test's tempfile.mkdtemp(dir=_output_dir()) to a
    # pytest-managed tmp_path -- without this it falls back to the real
    # /tmp/huntmcp-schemathesis and leaves a real per-job directory behind
    # on every test call (job_runtime.start_job is mocked in these tests,
    # so check_scan's own cleanup is never reached to remove it).
    monkeypatch.setenv("HUNTMCP_SCHEMATHESIS_TMP", str(tmp_path / "tmp-schemathesis"))
    return tmp_path


def test_run_schema_test_refuses_empty_target(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "")
    assert "BLOCKED" in out or "Error" in out
    assert "target" in out.lower()


def test_run_schema_test_refuses_whitespace_only_target(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "   ")
    assert "BLOCKED" in out or "Error" in out


def test_run_schema_test_refuses_out_of_scope_target(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "https://evil.example/")
    assert "BLOCKED" in out
    assert "scope" in out.lower()


def test_run_schema_test_refuses_out_of_scope_url(in_scope_engagement):
    out = srv.run_schema_test("https://evil.example/openapi.json", "https://t.example/")
    assert "BLOCKED" in out
    assert "scope" in out.lower()


def test_run_schema_test_refuses_cloud_metadata_target(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "http://169.254.169.254/")
    assert "BLOCKED" in out
    assert "metadata" in out.lower() or "ssrf" in out.lower()


def test_run_schema_test_refuses_cloud_metadata_url(in_scope_engagement):
    out = srv.run_schema_test("http://169.254.169.254/openapi.json", "https://t.example/")
    assert "BLOCKED" in out
    assert "metadata" in out.lower() or "ssrf" in out.lower()


def test_run_schema_test_refused_call_never_starts_a_job(in_scope_engagement, monkeypatch):
    """A refused call must not reach job_runtime.start_job (no budget charged)."""
    called = []
    monkeypatch.setattr(srv.job_runtime, "start_job",
                        lambda *a, **k: called.append(a) or {"job_id": "x"})
    out = srv.run_schema_test("https://t.example/openapi.json", "https://evil.example/")
    assert "BLOCKED" in out
    assert called == []


def test_run_schema_test_launches_job_when_in_scope(in_scope_engagement, monkeypatch):
    captured = {}

    def fake_start_job(tool_name, args, max_wall_seconds, jobs, extra_mounts_rw=None, extra_hosts=None):
        captured["tool_name"] = tool_name
        captured["args"] = args
        captured["extra_mounts_rw"] = extra_mounts_rw
        captured["extra_hosts"] = extra_hosts
        return {"job_id": "job-1"}

    # "t.example" is RFC 2606 reserved -- never resolves. resolve_and_pin()
    # is fail-CLOSED on a resolution failure (see its own docstring: the
    # caller here launches an external process that resolves on its own,
    # later, so a transient failure here must refuse, not silently proceed
    # unpinned) -- so a real (unmocked) call would be refused before ever
    # reaching start_job. Mocked here to a fixed successful pin so this
    # test can focus on the job-launch wiring itself; the pinning behavior
    # has its own dedicated tests below.
    monkeypatch.setattr(srv.scope_guard, "resolve_and_pin", lambda host: ("93.184.216.34", None))
    monkeypatch.setattr(srv.job_runtime, "start_job", fake_start_job)
    out = srv.run_schema_test("https://t.example/openapi.json", "https://t.example/")

    assert "job-1" in out
    assert captured["tool_name"] == "schemathesis"
    assert "https://t.example/openapi.json" in captured["args"]
    assert "--url" in captured["args"]
    assert "https://t.example/" in captured["args"]
    assert "--base-url" not in captured["args"]
    assert captured["extra_mounts_rw"] is not None and len(captured["extra_mounts_rw"]) == 1
    assert captured["extra_hosts"] == {"t.example": "93.184.216.34"}


def test_run_schema_test_always_disables_redirects(in_scope_engagement, monkeypatch):
    """Security review finding: target's own HTTP responses could redirect
    generated requests to an arbitrary, unchecked host -- --max-redirects 0
    closes that vector, and it must never be something a caller can loosen
    (same safety-control posture as rate_limit)."""
    captured = {}

    def fake_start_job(tool_name, args, max_wall_seconds, jobs, extra_mounts_rw=None, extra_hosts=None):
        captured["args"] = args
        return {"job_id": "job-1"}

    monkeypatch.setattr(srv.scope_guard, "resolve_and_pin", lambda host: ("93.184.216.34", None))
    monkeypatch.setattr(srv.job_runtime, "start_job", fake_start_job)
    srv.run_schema_test("https://t.example/openapi.json", "https://t.example/")

    args = captured["args"]
    assert "--max-redirects" in args
    assert args[args.index("--max-redirects") + 1] == "0"


def test_run_schema_test_pins_a_resolvable_host(in_scope_engagement, monkeypatch):
    captured = {}

    def fake_start_job(tool_name, args, max_wall_seconds, jobs, extra_mounts_rw=None, extra_hosts=None):
        captured["extra_hosts"] = extra_hosts
        return {"job_id": "job-1"}

    def fake_resolve_and_pin(host):
        return "93.184.216.34", None

    monkeypatch.setattr(srv.job_runtime, "start_job", fake_start_job)
    monkeypatch.setattr(srv.scope_guard, "resolve_and_pin", fake_resolve_and_pin)
    srv.run_schema_test("https://t.example/openapi.json", "https://t.example/")

    assert captured["extra_hosts"] == {"t.example": "93.184.216.34"}


def test_run_schema_test_refuses_when_pinning_finds_a_blocked_ip(in_scope_engagement, monkeypatch):
    def fake_resolve_and_pin(host):
        return None, f"host {host!r} resolves to a link-local address -- refused (SSRF)"

    monkeypatch.setattr(srv.scope_guard, "resolve_and_pin", fake_resolve_and_pin)
    out = srv.run_schema_test("https://t.example/openapi.json", "https://t.example/")

    assert "BLOCKED" in out
    assert "SSRF" in out


def test_run_schema_test_rejects_stateful_phase(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "https://t.example/", phases="stateful")
    assert "Error" in out
    assert "stateful" in out.lower()


def test_run_schema_test_rejects_all_checks_shortcut(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "https://t.example/", checks="all")
    assert "Error" in out


def test_run_schema_test_rejects_unbounded_max_examples(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "https://t.example/", max_examples=1_000_000)
    assert "Error" in out
    assert "max_examples" in out


def test_run_schema_test_rejects_free_form_rate_limit(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "https://t.example/", rate_limit="100000/s")
    assert "Error" in out
    assert "rate_limit" in out


def test_run_schema_test_rejects_excessive_timeout(in_scope_engagement):
    out = srv.run_schema_test("https://t.example/openapi.json", "https://t.example/", timeout=999999)
    assert "Error" in out
    assert "timeout" in out


def test_run_schema_test_accepts_the_allowed_rate_limits(in_scope_engagement, monkeypatch):
    def fake_start_job(tool_name, args, max_wall_seconds, jobs, extra_mounts_rw=None, extra_hosts=None):
        return {"job_id": "job-1"}

    monkeypatch.setattr(srv.scope_guard, "resolve_and_pin", lambda host: ("93.184.216.34", None))
    monkeypatch.setattr(srv.job_runtime, "start_job", fake_start_job)
    for rl in ("auto", "10/s", "60/m"):
        out = srv.run_schema_test("https://t.example/openapi.json", "https://t.example/", rate_limit=rl)
        assert "job-1" in out, f"rate_limit={rl!r} should be permitted, got: {out}"


def test_list_scans_reports_no_scans_initially():
    assert "No schemathesis" in srv.list_scans()
