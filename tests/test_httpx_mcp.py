import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "httpx_mcp_server", os.path.join(ROOT, "mcp-servers", "httpx-mcp", "server.py")
)
httpx_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(httpx_server)


PROBE_JSON = (
    '{"url":"https://target.com","status_code":200,"title":"Home",'
    '"tech":["nginx"],"webserver":"nginx","content_length":1024}\n'
)


def test_format_probe_lists_hosts():
    out = httpx_server._format_probe(PROBE_JSON, 0, "")
    assert "Probed 1 host(s)" in out
    assert "https://target.com" in out
    assert "Status: 200" in out


def test_format_probe_reports_hard_failure():
    out = httpx_server._format_probe("", 1, "connection refused")
    assert "httpx failed" in out


def test_format_probe_no_live_hosts():
    assert httpx_server._format_probe("", 0, "banner") == "No live hosts found."


def test_probe_hosts_then_check_scan_cleans_up_input_file(monkeypatch, tmp_path):
    monkeypatch.setattr(
        httpx_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-probe", "status": "running", "tool": "httpx"},
    )
    httpx_server.probe_hosts("target.com")
    input_path = httpx_server._meta["job-probe"]["input_path"]
    assert os.path.isfile(input_path)

    monkeypatch.setattr(
        httpx_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": PROBE_JSON, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = httpx_server.check_scan("job-probe")
    assert "target.com" in out
    assert not os.path.isfile(input_path)  # cleaned up once collected
    assert "job-probe" not in httpx_server._meta


def test_screenshot_hosts_timeout_still_cleans_up_workdir(monkeypatch):
    monkeypatch.setattr(
        httpx_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-shot-to", "status": "running", "tool": "httpx"},
    )
    httpx_server.screenshot_hosts("target.com")
    meta = httpx_server._meta["job-shot-to"]
    input_path, work_dir = meta["input_path"], meta["work_dir"]
    assert os.path.isfile(input_path)
    assert os.path.isdir(work_dir)

    monkeypatch.setattr(
        httpx_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "timeout", "job_id": job_id,
            "error": "httpx timed out after 180s and was killed -- partial output below, if any",
            "stdout": "", "stderr": "", "elapsed_s": 180.0,
        },
    )
    out = httpx_server.check_scan("job-shot-to")
    assert "timed out" in out
    assert not os.path.isfile(input_path)
    assert not os.path.isdir(work_dir)
    assert "job-shot-to" not in httpx_server._meta
