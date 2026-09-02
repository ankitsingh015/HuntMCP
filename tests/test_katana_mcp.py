import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "katana_mcp_server", os.path.join(ROOT, "mcp-servers", "katana-mcp", "server.py")
)
katana_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(katana_server)


def test_format_findings_dedupes_and_counts():
    out = katana_server._format_findings(
        "https://target.com",
        "https://target.com/a\nhttps://target.com/a\nhttps://target.com/b\n",
        0, "",
    )
    assert "Discovered 2 endpoint(s) for https://target.com:" in out
    assert "https://target.com/a" in out
    assert "https://target.com/b" in out


def test_format_findings_no_url_uses_with_filter_wording():
    out = katana_server._format_findings(
        None, "https://target.com/a\n", 0, "",
    )
    assert "Discovered 1 endpoint(s) with filter:" in out


def test_format_findings_no_endpoints():
    out = katana_server._format_findings("https://target.com", "", 0, "")
    assert out == "No endpoints discovered."


def test_format_findings_reports_failure():
    out = katana_server._format_findings("https://target.com", "", 1, "refused")
    assert "katana failed" in out


def test_format_findings_url_with_braces_does_not_crash():
    # Regression: a url containing a literal "{"/"}" (a REST path
    # template like /users/{id}, plausible input here) used to collide
    # with the found_header's {n} placeholder when the header was built
    # as a stored template later run through .format(n=...) -- KeyError,
    # raised inside check_scan() after the job was already popped, so the
    # crawl's results were permanently lost. Building the header fresh
    # with an f-string (as this now does) never re-interprets a runtime
    # string's own "{"/"}" characters.
    out = katana_server._format_findings(
        "https://target.com/api/{id}/profile",
        "https://target.com/api/1/profile\n", 0, "",
    )
    assert "{id}" in out


def test_crawl_then_check_scan_round_trip(monkeypatch):
    monkeypatch.setattr(
        katana_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-crawl", "status": "running", "tool": "katana"},
    )
    start_msg = katana_server.crawl("https://target.com")
    assert "job-crawl" in start_msg

    monkeypatch.setattr(
        katana_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "https://target.com/api\n", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = katana_server.check_scan("job-crawl")
    assert "https://target.com/api" in out
    assert "job-crawl" not in katana_server._targets


def test_crawl_with_braces_in_url_does_not_crash_check_scan(monkeypatch):
    # End-to-end regression for the same bug via the real crawl()/
    # check_scan() path, not just _format_findings() directly.
    monkeypatch.setattr(
        katana_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-braces", "status": "running", "tool": "katana"},
    )
    katana_server.crawl("https://target.com/api/{id}/profile")

    monkeypatch.setattr(
        katana_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "https://target.com/api/1/profile\n", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = katana_server.check_scan("job-braces")  # must not raise
    assert "{id}" in out


def test_check_scan_timeout_cleans_up_targets(monkeypatch):
    monkeypatch.setattr(
        katana_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-crawl-to", "status": "running", "tool": "katana"},
    )
    katana_server.crawl("https://target.com")

    monkeypatch.setattr(
        katana_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id,
            "error": "katana timed out after 120s and was killed -- partial output below, if any",
            "stdout": "", "stderr": "", "elapsed_s": 120.0,
        },
    )
    out = katana_server.check_scan("job-crawl-to")
    assert "timed out" in out
    assert "job-crawl-to" not in katana_server._targets
