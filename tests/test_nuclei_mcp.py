import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "nuclei_mcp_server", os.path.join(ROOT, "mcp-servers", "nuclei-mcp", "server.py")
)
nuclei_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nuclei_server)


FOUND_OUTPUT = (
    '{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium"},'
    '"matched-at":"https://target.com/admin","type":"http"}\n'
)


def test_format_findings_uses_the_no_findings_message_verbatim():
    out = nuclei_server._format_findings("target.com", "custom no-findings text", "", 0, "")
    assert out == "custom no-findings text"


def test_format_findings_surfaces_hard_failure_with_no_stdout():
    out = nuclei_server._format_findings("target.com", "no findings", "", 1, "connection timed out")
    assert "nuclei failed" in out
    assert "connection timed out" in out


def test_format_findings_lists_matches():
    out = nuclei_server._format_findings("target.com", "no findings", FOUND_OUTPUT, 0, "")
    assert "MEDIUM" in out
    assert "Exposed Admin Panel" in out
    assert "target.com" in out


def test_scan_target_then_check_scan_round_trip(monkeypatch):
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-nuc", "status": "running", "tool": "nuclei"},
    )
    start_msg = nuclei_server.scan_target("target.com")
    assert "job-nuc" in start_msg

    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FOUND_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nuclei_server.check_scan("job-nuc")
    assert "Exposed Admin Panel" in out


def test_scan_with_templates_no_findings_wording_differs_from_scan_target(monkeypatch):
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-tmpl", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_with_templates("target.com", "cves/2021")

    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nuclei_server.check_scan("job-tmpl")
    assert out == "No vulnerabilities found with the specified templates."


def test_check_scan_surfaces_waf_block(monkeypatch):
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-waf", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_target("target.com")

    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "403 Forbidden - request blocked by Cloudflare",
            "elapsed_s": 3.0, "block": "waf",
        },
    )
    out = nuclei_server.check_scan("job-waf")
    assert "WAF" in out
    assert "BLOCK DETECTED" in out


def test_check_scan_timeout_status_returns_error_and_cleans_up(monkeypatch):
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-to", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_target("target.com")

    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id,
            "error": "nuclei timed out after 300s and was killed -- partial output below, if any",
            "stdout": "", "stderr": "", "elapsed_s": 300.0,
        },
    )
    out = nuclei_server.check_scan("job-to")
    assert "timed out" in out
    assert "job-to" not in nuclei_server._targets
