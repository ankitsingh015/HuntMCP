import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "dalfox_mcp_server", os.path.join(ROOT, "mcp-servers", "dalfox-mcp", "server.py")
)
dalfox_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dalfox_server)


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    """"target.com" (this file's standard test target) is a REAL,
    resolvable domain -- without this, every scan_url()/scan_parameter()
    call does a real DNS lookup via the new scope_guard.pin_hosts_or_error()
    call in _start() (testing.md: avoid real external targets)."""
    monkeypatch.setattr(dalfox_server.scope_guard, "resolve_and_pin", lambda host: ("93.184.216.34", None))


FOUND_OUTPUT = (
    '{"vuln":"XSS","param":"q","evidence":"<script>alert(1)</script>",'
    '"severity":"high","type":"reflected","payload":"<script>alert(1)</script>"}\n'
)


def test_format_findings_reports_no_xss_for_scan_url_wording():
    out = dalfox_server._format_findings("https://target.com/", "", 0, "", verbose=True)
    assert out == "No XSS vulnerabilities found on https://target.com/."


def test_format_findings_reports_no_xss_for_scan_parameter_wording():
    out = dalfox_server._format_findings("q", "", 0, "", verbose=False)
    assert out == "No XSS found on parameter 'q'."


def test_format_findings_surfaces_crash_instead_of_silent_no_findings():
    # A crashed run with no parsed findings used to be silently reported
    # as "no XSS found" instead of surfacing the failure.
    out = dalfox_server._format_findings("https://target.com/", "", 1, "connection refused", verbose=True)
    assert "dalfox failed" in out
    assert "connection refused" in out


def test_format_findings_lists_verbose_details():
    out = dalfox_server._format_findings("https://target.com/", FOUND_OUTPUT, 0, "", verbose=True)
    assert "HIGH" in out
    assert "Parameter: q" in out
    assert "Evidence:" in out


def test_format_findings_compact_for_scan_parameter():
    out = dalfox_server._format_findings("q", FOUND_OUTPUT, 0, "", verbose=False)
    assert "XSS findings on parameter 'q'" in out
    assert "Parameter:" not in out  # compact form omits the per-line breakdown


def test_scan_url_and_scan_parameter_request_jsonl_not_pretty_json(monkeypatch):
    # Real bug found live via P2-BENCH's real-tool fixture-proof testing
    # (Task 13): dalfox's --format json is a PRETTY-PRINTED JSON ARRAY
    # ("[\n{...},\n{}]"), not one-JSON-object-per-line -- confirmed by
    # direct reproduction. _format_findings() parses stdout line-by-line
    # expecting each line to be its own complete JSON object (exactly
    # dalfox's --format jsonl output), so with --format json every line
    # ("[", "{...},", "{}]") fails json.loads() and is silently skipped,
    # meaning check_scan() reported "No XSS found" even when dalfox found
    # and verified a real XSS -- a false negative for every real scan,
    # not just this benchmark. This test file's own FOUND_OUTPUT mock is
    # already JSONL-shaped, which is exactly why this bug wasn't caught
    # by the existing unit tests above -- they never exercised the real
    # --format value passed to dalfox.
    captured = {}

    def _fake_start_job(tool, args, timeout, jobs, **kwargs):
        captured["args"] = args
        return {"job_id": "job-format", "status": "running", "tool": tool}

    monkeypatch.setattr(dalfox_server.job_runtime, "start_job", _fake_start_job)

    dalfox_server.scan_url("https://target.com/?q=1")
    assert "jsonl" in captured["args"]
    assert "json" not in captured["args"]  # exact-element check: "jsonl" != "json"

    dalfox_server.scan_parameter("https://target.com/?q=1", "q")
    assert "jsonl" in captured["args"]
    assert "json" not in captured["args"]


def test_scan_url_then_check_scan_round_trip(monkeypatch):
    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-xss", "status": "running", "tool": "dalfox"},
    )
    start_msg = dalfox_server.scan_url("https://target.com/?q=1")
    assert "job-xss" in start_msg

    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FOUND_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = dalfox_server.check_scan("job-xss")
    assert "dalfox found 1 XSS issue(s) on https://target.com/?q=1" in out


def test_check_scan_surfaces_rate_limit_block(monkeypatch):
    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-block", "status": "running", "tool": "dalfox"},
    )
    dalfox_server.scan_url("https://target.com/?q=1")

    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "429 too many requests", "elapsed_s": 5.0, "block": "rate_limit",
        },
    )
    out = dalfox_server.check_scan("job-block")
    assert "RATE_LIMIT" in out
    assert "BLOCK DETECTED" in out


def test_scan_url_refuses_when_pinning_finds_a_blocked_ip(monkeypatch):
    def fake_resolve_and_pin(host):
        return None, f"host {host!r} resolves to a link-local address -- refused (SSRF)"
    monkeypatch.setattr(dalfox_server.scope_guard, "resolve_and_pin", fake_resolve_and_pin)

    def _unreachable_start_job(*a, **k):
        raise AssertionError("scan_url must refuse before ever calling start_job")
    monkeypatch.setattr(dalfox_server.job_runtime, "start_job", _unreachable_start_job)

    out = dalfox_server.scan_url("https://target.com/?q=1")
    assert "BLOCKED" in out
    assert "SSRF" in out


def test_scan_parameter_pins_url_host_not_param_name(monkeypatch):
    """Regression: scan_parameter()'s _start() call used to pass `param`
    (e.g. "q") as the pinning target -- `param` is never a URL, so pinning
    it would have been meaningless. _start() now takes an explicit `url`
    param for this, separate from `label` (the display identifier)."""
    captured = {}

    def fake_start_job(tool, args, timeout, jobs, **kwargs):
        captured["extra_hosts"] = kwargs.get("extra_hosts")
        return {"job_id": "job-pin", "status": "running", "tool": tool}
    monkeypatch.setattr(dalfox_server.job_runtime, "start_job", fake_start_job)

    dalfox_server.scan_parameter("https://target.com/?q=1", "q")
    assert captured["extra_hosts"] == {"target.com": "93.184.216.34"}


def test_scan_url_appends_scan_header_when_configured(monkeypatch, tmp_path):
    path = tmp_path / "engagement.yaml"
    path.write_text(
        "target: target.com\nin_scope:\n  - target.com\n"
        "scan_header_name: X-Bug-Bounty\nscan_header_value: ankit015\n",
    )
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(path))
    captured = {}

    def fake_start_job(tool, args, timeout, jobs, **kwargs):
        captured["args"] = args
        return {"job_id": "job-hdr", "status": "running", "tool": tool}
    monkeypatch.setattr(dalfox_server.job_runtime, "start_job", fake_start_job)

    dalfox_server.scan_url("https://target.com/?q=1")
    args = captured["args"]
    assert args[args.index("-H") + 1] == "X-Bug-Bounty: ankit015"


def test_scan_url_omits_scan_header_when_nothing_configured(monkeypatch, tmp_path):
    path = tmp_path / "engagement.yaml"
    path.write_text("target: target.com\nin_scope:\n  - target.com\n")
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(path))
    captured = {}

    def fake_start_job(tool, args, timeout, jobs, **kwargs):
        captured["args"] = args
        return {"job_id": "job-nohdr", "status": "running", "tool": tool}
    monkeypatch.setattr(dalfox_server.job_runtime, "start_job", fake_start_job)

    dalfox_server.scan_url("https://target.com/?q=1")
    assert "-H" not in captured["args"]


def test_check_scan_still_running_does_not_consume_target(monkeypatch):
    monkeypatch.setattr(
        dalfox_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-slow", "status": "running", "tool": "dalfox"},
    )
    dalfox_server.scan_url("https://target.com/")

    monkeypatch.setattr(
        dalfox_server.job_runtime, "poll_job",
        lambda job_id, jobs: {"status": "running", "job_id": job_id, "elapsed_s": 42.0},
    )
    out = dalfox_server.check_scan("job-slow")
    assert "running" in out.lower()
    assert "job-slow" in dalfox_server._targets  # not popped while still running
