"""C1a: invocation-level provenance, fourth concrete source. ffuf-mcp's
check_scan() now appends {"class": "invocation", "tool": "ffuf",
"target": url} -- fuzz_directory() always has a real base url;
fuzz_with_data() deliberately passes url=None to _start() (no single
"target" concept for a body-fuzzing run), so "target" is OMITTED from
the provenance dict entirely in that case rather than fabricating one --
case_store._validate_provenance() only requires "tool" for class
"invocation", so an absent "target" is still valid, honest provenance.
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "ffuf_mcp_server_invocation_provenance", os.path.join(ROOT, "mcp-servers", "ffuf-mcp", "server.py"),
)
ffuf_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ffuf_server)


def _extract_provenance_payload(result: str) -> dict:
    lines = [l for l in result.splitlines() if l.startswith("Provenance")]
    assert lines, f"no Provenance line found in: {result!r}"
    return json.loads(lines[-1].split(":", 1)[1].strip())


def test_check_scan_emits_invocation_provenance_for_fuzz_directory(monkeypatch):
    monkeypatch.setattr(ffuf_server, "_resolve_wordlist", lambda w: "/tmp/fake-wordlist.txt")
    monkeypatch.setattr(
        ffuf_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-dir", "status": "running", "tool": "ffuf"},
    )
    ffuf_server.fuzz_directory("https://target.com")
    monkeypatch.setattr(
        ffuf_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = ffuf_server.check_scan("job-dir")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "ffuf", "target": "https://target.com"}


def test_check_scan_fuzz_with_data_omits_target_rather_than_fabricating_one(monkeypatch):
    monkeypatch.setattr(ffuf_server, "_resolve_wordlist", lambda w: "/tmp/fake-wordlist.txt")
    monkeypatch.setattr(
        ffuf_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-data", "status": "running", "tool": "ffuf"},
    )
    ffuf_server.fuzz_with_data("https://target.com/login")
    monkeypatch.setattr(
        ffuf_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = ffuf_server.check_scan("job-data")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "ffuf"}
    assert "target" not in payload


def test_check_scan_invocation_provenance_is_valid_case_store_provenance(monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import case_store

    monkeypatch.setattr(ffuf_server, "_resolve_wordlist", lambda w: "/tmp/fake-wordlist.txt")
    monkeypatch.setattr(
        ffuf_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-valid", "status": "running", "tool": "ffuf"},
    )
    ffuf_server.fuzz_with_data("https://target.com/login")
    monkeypatch.setattr(
        ffuf_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = ffuf_server.check_scan("job-valid")
    payload = _extract_provenance_payload(out)
    assert case_store._validate_provenance(payload) is None


def test_check_scan_timeout_has_no_provenance_line(monkeypatch):
    monkeypatch.setattr(ffuf_server, "_resolve_wordlist", lambda w: "/tmp/fake-wordlist.txt")
    monkeypatch.setattr(
        ffuf_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-timeout", "status": "running", "tool": "ffuf"},
    )
    ffuf_server.fuzz_directory("https://target.com")
    monkeypatch.setattr(
        ffuf_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id, "error": "ffuf run timed out",
            "stdout": "", "stderr": "", "elapsed_s": 180.0,
        },
    )
    out = ffuf_server.check_scan("job-timeout")
    assert "Provenance" not in out
