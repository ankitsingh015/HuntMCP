"""C1a: invocation-level provenance, third concrete source. sqlmap-mcp's
check_scan() now appends {"class": "invocation", "tool": "sqlmap",
"target": url}. Unlike dalfox/nuclei, sqlmap-mcp's job metadata (_meta)
never tracked the real target url at all -- _start() gained a `target`
parameter, threaded through from test_injection()/test_with_data()'s own
`url` argument, which both already had.
"""
import importlib.util
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "sqlmap_mcp_server_invocation_provenance", os.path.join(ROOT, "mcp-servers", "sqlmap-mcp", "server.py"),
)
sqlmap_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sqlmap_server)

_JOB_ID_RE = re.compile(r'job_id="([^"]+)"')


def _extract_provenance_payload(result: str) -> dict:
    lines = [l for l in result.splitlines() if l.startswith("Provenance")]
    assert lines, f"no Provenance line found in: {result!r}"
    return json.loads(lines[-1].split(":", 1)[1].strip())


def test_check_scan_emits_invocation_provenance_for_test_injection(monkeypatch, tmp_path):
    monkeypatch.setattr(sqlmap_server, "_output_dir", lambda: str(tmp_path))
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-inj", "status": "running", "tool": "sqlmap"},
    )
    sqlmap_server.test_injection("https://target.com/x?id=1")
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = sqlmap_server.check_scan("job-inj")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "sqlmap", "target": "https://target.com/x?id=1"}


def test_check_scan_emits_invocation_provenance_for_test_with_data(monkeypatch, tmp_path):
    monkeypatch.setattr(sqlmap_server, "_output_dir", lambda: str(tmp_path))
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-data", "status": "running", "tool": "sqlmap"},
    )
    sqlmap_server.test_with_data("https://target.com/login", "user=x&pass=y")
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = sqlmap_server.check_scan("job-data")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "sqlmap", "target": "https://target.com/login"}


def test_check_scan_invocation_provenance_is_valid_case_store_provenance(monkeypatch, tmp_path):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import case_store

    monkeypatch.setattr(sqlmap_server, "_output_dir", lambda: str(tmp_path))
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-valid", "status": "running", "tool": "sqlmap"},
    )
    sqlmap_server.test_injection("https://target.com/x?id=1")
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = sqlmap_server.check_scan("job-valid")
    payload = _extract_provenance_payload(out)
    assert case_store._validate_provenance(payload) is None


def test_check_scan_timeout_has_no_provenance_line(monkeypatch, tmp_path):
    monkeypatch.setattr(sqlmap_server, "_output_dir", lambda: str(tmp_path))
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-timeout", "status": "running", "tool": "sqlmap"},
    )
    sqlmap_server.test_injection("https://target.com/x?id=1")
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id, "error": "sqlmap scan timed out",
            "stdout": "", "stderr": "", "elapsed_s": 300.0,
        },
    )
    out = sqlmap_server.check_scan("job-timeout")
    assert "Provenance" not in out
