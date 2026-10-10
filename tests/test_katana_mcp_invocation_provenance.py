"""C1a: invocation-level provenance, sixth concrete source. katana-mcp's
check_scan() now appends {"class": "invocation", "tool": "katana",
"target": url} -- crawl() always has a real url; crawl_with_filter()
deliberately passes url=None to _start() (its own header never names a
single url either, per this file's own pre-existing comment), so
"target" is OMITTED rather than fabricated, same as ffuf-mcp's
fuzz_with_data().
"""
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "katana_mcp_server_invocation_provenance", os.path.join(ROOT, "mcp-servers", "katana-mcp", "server.py"),
)
katana_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(katana_server)


def _extract_provenance_payload(result: str) -> dict:
    lines = [l for l in result.splitlines() if l.startswith("Provenance")]
    assert lines, f"no Provenance line found in: {result!r}"
    return json.loads(lines[-1].split(":", 1)[1].strip())


def test_check_scan_emits_invocation_provenance_for_crawl(monkeypatch):
    monkeypatch.setattr(
        katana_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-crawl", "status": "running", "tool": "katana"},
    )
    katana_server.crawl("https://target.com")
    monkeypatch.setattr(
        katana_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = katana_server.check_scan("job-crawl")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "katana", "target": "https://target.com"}


def test_check_scan_crawl_with_filter_omits_target_rather_than_fabricating_one(monkeypatch):
    monkeypatch.setattr(
        katana_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-filter", "status": "running", "tool": "katana"},
    )
    katana_server.crawl_with_filter("https://target.com", extensions="png,css")
    monkeypatch.setattr(
        katana_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = katana_server.check_scan("job-filter")

    payload = _extract_provenance_payload(out)
    assert payload == {"class": "invocation", "tool": "katana"}
    assert "target" not in payload


def test_check_scan_invocation_provenance_is_valid_case_store_provenance(monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import case_store

    monkeypatch.setattr(
        katana_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-valid", "status": "running", "tool": "katana"},
    )
    katana_server.crawl("https://target.com")
    monkeypatch.setattr(
        katana_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = katana_server.check_scan("job-valid")
    payload = _extract_provenance_payload(out)
    assert case_store._validate_provenance(payload) is None


def test_check_scan_timeout_has_no_provenance_line(monkeypatch):
    monkeypatch.setattr(
        katana_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-timeout", "status": "running", "tool": "katana"},
    )
    katana_server.crawl("https://target.com")
    monkeypatch.setattr(
        katana_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id, "error": "katana crawl timed out",
            "stdout": "", "stderr": "", "elapsed_s": 120.0,
        },
    )
    out = katana_server.check_scan("job-timeout")
    assert "Provenance" not in out
