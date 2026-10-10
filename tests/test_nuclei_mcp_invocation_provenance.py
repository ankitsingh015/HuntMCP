"""C1a: the "invocation-level provenance for scanner-narrated output"
half of C1a's original scope -- distinct from (and until now, entirely
untouched by) the "wire-level provenance" work done elsewhere this
session. case_store._validate_provenance() has supported
{"class": "invocation", "tool": ...} since C1a's foundation, and
case-mcp/server.py's add_evidence() docstring has documented it since
then too ("for scanner-narrated output (nuclei/sqlmap/subfinder parse
stdout -- the real HTTP exchange happens inside the external binary's
own process, invisible here, so only 'which tool ran' is honestly
claimable)") -- but nothing actually produced one.

nuclei-mcp is the first concrete source, the same "smallest useful
increment, not a platform" scoping this session already applied to
oob-mcp (get_interaction_records only) and browser-mcp (render_dom
only, in its first round). dalfox-mcp/sqlmap-mcp/ffuf-mcp/nmap-mcp/
katana-mcp/subfinder-mcp remain unwired, recorded in the tracker.
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "nuclei-mcp"))
import templates_pin  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "nuclei_mcp_server_invocation_provenance", os.path.join(ROOT, "mcp-servers", "nuclei-mcp", "server.py"),
)
nuclei_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nuclei_server)

FOUND_OUTPUT = (
    '{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium"},'
    '"matched-at":"https://target.com/admin","type":"http"}\n'
)


def _extract_provenance_payload(result: str) -> dict:
    lines = [l for l in result.splitlines() if l.startswith("Provenance")]
    assert lines, f"no Provenance line found in: {result!r}"
    return json.loads(lines[-1].split(":", 1)[1].strip())


def test_check_scan_emits_invocation_provenance_line(monkeypatch):
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-found", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_target("target.com")
    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FOUND_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nuclei_server.check_scan("job-found")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "nuclei", "target": "target.com"}


def test_check_scan_invocation_provenance_is_valid_case_store_provenance(monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import case_store

    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-valid", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_target("target.com")
    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FOUND_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nuclei_server.check_scan("job-valid")
    payload = _extract_provenance_payload(out)

    assert case_store._validate_provenance(payload) is None


def test_check_scan_no_findings_still_emits_provenance(monkeypatch):
    """Harmless to include even with zero findings -- an agent simply
    won't call add_evidence() if there's nothing worth attaching."""
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-empty", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_target("target.com")
    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nuclei_server.check_scan("job-empty")
    assert "No vulnerabilities found" in out
    payload = _extract_provenance_payload(out)
    assert payload["tool"] == "nuclei"


def test_check_scan_timeout_has_no_provenance_line(monkeypatch):
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-timeout", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_target("target.com")
    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id, "error": "nuclei scan timed out after 300s",
            "stdout": "", "stderr": "", "elapsed_s": 300.0,
        },
    )
    out = nuclei_server.check_scan("job-timeout")
    assert "Provenance" not in out


def test_check_scan_still_running_has_no_provenance_line(monkeypatch):
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-running", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_target("target.com")
    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {"status": "running", "job_id": job_id, "elapsed_s": 10.0},
    )
    out = nuclei_server.check_scan("job-running")
    assert "Provenance" not in out
