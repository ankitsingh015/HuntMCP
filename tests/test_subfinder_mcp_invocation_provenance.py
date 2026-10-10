"""C1a: invocation-level provenance, seventh and last concrete source
for this round. subfinder-mcp's check_scan() now appends
{"class": "invocation", "tool": "subfinder", "target": domain}.
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "subfinder_mcp_server_invocation_provenance", os.path.join(ROOT, "mcp-servers", "subfinder-mcp", "server.py"),
)
subfinder_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(subfinder_server)


def _extract_provenance_payload(result: str) -> dict:
    lines = [l for l in result.splitlines() if l.startswith("Provenance")]
    assert lines, f"no Provenance line found in: {result!r}"
    return json.loads(lines[-1].split(":", 1)[1].strip())


def test_check_scan_emits_invocation_provenance(monkeypatch):
    monkeypatch.setattr(
        subfinder_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-sub", "status": "running", "tool": "subfinder"},
    )
    subfinder_server.run_subfinder("target.com")
    monkeypatch.setattr(
        subfinder_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = subfinder_server.check_scan("job-sub")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "subfinder", "target": "target.com"}


def test_check_scan_invocation_provenance_is_valid_case_store_provenance(monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import case_store

    monkeypatch.setattr(
        subfinder_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-valid", "status": "running", "tool": "subfinder"},
    )
    subfinder_server.run_subfinder("target.com")
    monkeypatch.setattr(
        subfinder_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = subfinder_server.check_scan("job-valid")
    payload = _extract_provenance_payload(out)
    assert case_store._validate_provenance(payload) is None


def test_check_scan_timeout_has_no_provenance_line(monkeypatch):
    monkeypatch.setattr(
        subfinder_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-timeout", "status": "running", "tool": "subfinder"},
    )
    subfinder_server.run_subfinder("target.com")
    monkeypatch.setattr(
        subfinder_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id, "error": "subfinder run timed out",
            "stdout": "", "stderr": "", "elapsed_s": 120.0,
        },
    )
    out = subfinder_server.check_scan("job-timeout")
    assert "Provenance" not in out
