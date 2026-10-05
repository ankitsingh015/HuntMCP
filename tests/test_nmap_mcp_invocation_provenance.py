"""C1a: invocation-level provenance, fifth concrete source. nmap-mcp's
check_scan() now appends {"class": "invocation", "tool": "nmap",
"target": target}. Code-review-worthy pre-existing detail: check_scan()
already did `_targets.pop(job_id, None)` but DISCARDED the popped value
(never assigned to a variable) -- this change is the first thing to
actually use it.
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "nmap_mcp_server_invocation_provenance", os.path.join(ROOT, "mcp-servers", "nmap-mcp", "server.py"),
)
nmap_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nmap_server)


def _extract_provenance_payload(result: str) -> dict:
    lines = [l for l in result.splitlines() if l.startswith("Provenance")]
    assert lines, f"no Provenance line found in: {result!r}"
    return json.loads(lines[-1].split(":", 1)[1].strip())


def test_check_scan_emits_invocation_provenance(monkeypatch):
    monkeypatch.setattr(
        nmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-ports", "status": "running", "tool": "nmap"},
    )
    nmap_server.scan_ports("target.com")
    monkeypatch.setattr(
        nmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nmap_server.check_scan("job-ports")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "nmap", "target": "target.com"}


def test_check_scan_invocation_provenance_is_valid_case_store_provenance(monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import case_store

    monkeypatch.setattr(
        nmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-valid", "status": "running", "tool": "nmap"},
    )
    nmap_server.scan_ports("target.com")
    monkeypatch.setattr(
        nmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nmap_server.check_scan("job-valid")
    payload = _extract_provenance_payload(out)
    assert case_store._validate_provenance(payload) is None


def test_check_scan_timeout_has_no_provenance_line(monkeypatch):
    monkeypatch.setattr(
        nmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-timeout", "status": "running", "tool": "nmap"},
    )
    nmap_server.scan_ports("target.com")
    monkeypatch.setattr(
        nmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id, "error": "nmap scan timed out",
            "stdout": "", "stderr": "", "elapsed_s": 300.0,
        },
    )
    out = nmap_server.check_scan("job-timeout")
    assert "Provenance" not in out
