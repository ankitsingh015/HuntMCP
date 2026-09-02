import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "subfinder_mcp_server", os.path.join(ROOT, "mcp-servers", "subfinder-mcp", "server.py")
)
subfinder_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(subfinder_server)


def test_format_findings_sorts_and_lists_subdomains():
    out = subfinder_server._format_findings("acme.com", "b.acme.com\na.acme.com\n", 0, "")
    assert "Found 2 subdomains for acme.com" in out
    assert out.index("a.acme.com") < out.index("b.acme.com")


def test_format_findings_no_subdomains():
    assert subfinder_server._format_findings("acme.com", "", 0, "") == "No subdomains found."


def test_format_findings_reports_failure():
    out = subfinder_server._format_findings("acme.com", "", 1, "api rate limited")
    assert "subfinder failed" in out


def test_run_subfinder_then_check_scan_round_trip(monkeypatch):
    monkeypatch.setattr(
        subfinder_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-sub", "status": "running", "tool": "subfinder"},
    )
    start_msg = subfinder_server.run_subfinder("acme.com")
    assert "job-sub" in start_msg
    assert subfinder_server._domains["job-sub"] == "acme.com"

    monkeypatch.setattr(
        subfinder_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "api.acme.com\n", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = subfinder_server.check_scan("job-sub")
    assert "api.acme.com" in out
    assert "job-sub" not in subfinder_server._domains


def test_check_scan_timeout_cleans_up_domains_entry(monkeypatch):
    monkeypatch.setattr(
        subfinder_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-sub-to", "status": "running", "tool": "subfinder"},
    )
    subfinder_server.run_subfinder("acme.com")

    monkeypatch.setattr(
        subfinder_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id,
            "error": "subfinder timed out after 120s and was killed -- partial output below, if any",
            "stdout": "", "stderr": "", "elapsed_s": 120.0,
        },
    )
    out = subfinder_server.check_scan("job-sub-to")
    assert "timed out" in out
    assert "job-sub-to" not in subfinder_server._domains
