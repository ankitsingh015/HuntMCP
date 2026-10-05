"""C1a: invocation-level provenance, second concrete source after
nuclei-mcp -- same "smallest useful increment" pattern, repeated per
tool. dalfox-mcp's check_scan() now appends
{"class": "invocation", "tool": "dalfox", "target": label} -- `label` is
whatever scan_url()/scan_parameter() already tracked as this job's
display identifier (the full URL for scan_url, just the parameter name
for scan_parameter), same value already shown in this tool's own
findings header, not a fabricated claim.
"""
import importlib.util
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "dalfox_mcp_server_invocation_provenance", os.path.join(ROOT, "mcp-servers", "dalfox-mcp", "server.py"),
)
dalfox_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dalfox_server)

_JOB_ID_RE = re.compile(r'job_id="([^"]+)"')

FOUND_OUTPUT = (
    '{"vuln":"XSS","param":"q","evidence":"x","severity":"high","type":"reflected","payload":"y"}\n'
)


def _extract_provenance_payload(result: str) -> dict:
    lines = [l for l in result.splitlines() if l.startswith("Provenance")]
    assert lines, f"no Provenance line found in: {result!r}"
    return json.loads(lines[-1].split(":", 1)[1].strip())


def test_check_scan_emits_invocation_provenance_for_scan_url(monkeypatch):
    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-url", "status": "running", "tool": "dalfox"},
    )
    dalfox_server.scan_url("https://target.com/")
    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FOUND_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = dalfox_server.check_scan("job-url")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "dalfox", "target": "https://target.com/"}


def test_check_scan_invocation_provenance_is_valid_case_store_provenance(monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import case_store

    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-valid", "status": "running", "tool": "dalfox"},
    )
    dalfox_server.scan_url("https://target.com/")
    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FOUND_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = dalfox_server.check_scan("job-valid")
    payload = _extract_provenance_payload(out)
    assert case_store._validate_provenance(payload) is None


def test_check_scan_timeout_has_no_provenance_line(monkeypatch):
    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-timeout", "status": "running", "tool": "dalfox"},
    )
    dalfox_server.scan_url("https://target.com/")
    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id, "error": "dalfox scan timed out",
            "stdout": "", "stderr": "", "elapsed_s": 180.0,
        },
    )
    out = dalfox_server.check_scan("job-timeout")
    assert "Provenance" not in out
