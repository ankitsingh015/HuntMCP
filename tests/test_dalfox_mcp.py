import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "dalfox_mcp_server", os.path.join(ROOT, "mcp-servers", "dalfox-mcp", "server.py")
)
dalfox_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dalfox_server)


FOUND_OUTPUT = (
    '{"vuln":"XSS","param":"q","evidence":"<script>alert(1)</script>",'
    '"severity":"high","type":"reflected","payload":"<script>alert(1)</script>"}\n'
)


def test_format_findings_reports_no_xss_for_scan_url_wording():
    out = dalfox_server._format_findings("https://target.com/", "", 0, "", verbose=True)
    assert out == "No XSS vulnerabilities found on https://target.com/."


def test_format_findings_reports_no_xss_for_scan_parameter_wording():
    out = dalfox_server._format_findings("q", "", 0, "", verbose=False)
    assert out == "No XSS found on parameter 'q'."


def test_format_findings_surfaces_crash_instead_of_silent_no_findings():
    # A crashed run with no parsed findings used to be silently reported
    # as "no XSS found" instead of surfacing the failure.
    out = dalfox_server._format_findings("https://target.com/", "", 1, "connection refused", verbose=True)
    assert "dalfox failed" in out
    assert "connection refused" in out


def test_format_findings_lists_verbose_details():
    out = dalfox_server._format_findings("https://target.com/", FOUND_OUTPUT, 0, "", verbose=True)
    assert "HIGH" in out
    assert "Parameter: q" in out
    assert "Evidence:" in out


def test_format_findings_compact_for_scan_parameter():
    out = dalfox_server._format_findings("q", FOUND_OUTPUT, 0, "", verbose=False)
    assert "XSS findings on parameter 'q'" in out
    assert "Parameter:" not in out  # compact form omits the per-line breakdown


def test_scan_url_then_check_scan_round_trip(monkeypatch):
    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-xss", "status": "running", "tool": "dalfox"},
    )
    start_msg = dalfox_server.scan_url("https://target.com/?q=1")
    assert "job-xss" in start_msg

    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FOUND_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = dalfox_server.check_scan("job-xss")
    assert "dalfox found 1 XSS issue(s) on https://target.com/?q=1" in out


def test_check_scan_surfaces_rate_limit_block(monkeypatch):
    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-block", "status": "running", "tool": "dalfox"},
    )
    dalfox_server.scan_url("https://target.com/?q=1")

    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "429 too many requests", "elapsed_s": 5.0, "block": "rate_limit",
        },
    )
    out = dalfox_server.check_scan("job-block")
    assert "RATE_LIMIT" in out
    assert "BLOCK DETECTED" in out


def test_check_scan_still_running_does_not_consume_target(monkeypatch):
    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-slow", "status": "running", "tool": "dalfox"},
    )
    dalfox_server.scan_url("https://target.com/")

    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {"status": "running", "job_id": job_id, "elapsed_s": 42.0},
    )
    out = dalfox_server.check_scan("job-slow")
    assert "running" in out.lower()
    assert "job-slow" in dalfox_server._targets  # not popped while still running
