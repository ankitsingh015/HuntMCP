import importlib.util
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "bench_target"))

from bench_app import BenchApp


@pytest.fixture
def vulnerable_app():
    app = BenchApp(mode="vulnerable").start()
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture
def patched_app():
    app = BenchApp(mode="patched").start()
    try:
        yield app
    finally:
        app.stop()


def _podman_and_image_available() -> bool:
    """Mirrors tests/test_sandbox_runner.py's own _podman_and_image_available()
    exactly -- found live (CI run 2026-09-24) that checking only the podman
    BINARY isn't enough: CI has podman installed but never builds
    localhost/huntmcp-sandbox locally, so a real sandboxed podman run there
    tries to PULL that name as a registry image and fails outright (exit
    125) instead of skipping, unlike every other real-tool test in this
    suite that's gated by the stronger, established check."""
    if not shutil.which("podman"):
        return False
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import sandbox_runner
    result = subprocess.run(
        ["podman", "image", "exists", sandbox_runner.SANDBOX_IMAGE],
        capture_output=True, timeout=10,
    )
    return result.returncode == 0


requires_podman = pytest.mark.skipif(
    not _podman_and_image_available(),
    reason="podman not installed or huntmcp-sandbox image not built",
)


@pytest.fixture
def bench_env(tmp_path, monkeypatch):
    """Isolates every real-tool test's budget/audit ledgers under a fresh
    tmp_path -- consolidates what was previously two repeated
    monkeypatch.setenv() lines copy-pasted across 14 test functions (found
    in review, 2026-09-23), mirroring test_cem_benchmark.py's own
    `cem_env` fixture for the same purpose."""
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path


@pytest.fixture
def sandboxed_vulnerable_app(monkeypatch):
    """Container-based counterpart to `vulnerable_app`, for tests that
    drive a REAL Tier-2 MCP tool function (which always sandboxes via
    sandbox_runner.build_argv()) against the target -- see
    bench_sandboxed_app.py's module docstring for why the host-thread
    `vulnerable_app` fixture above is unreachable from inside that
    sandbox. Also sets HUNTMCP_BENCH_NETWORK for the duration of the test
    so the tool's OWN sandboxed container joins the same private network."""
    from bench_sandboxed_app import SandboxedBenchApp
    app = SandboxedBenchApp(mode="vulnerable").start()
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", app.network_name)
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture
def sandboxed_patched_app(monkeypatch):
    from bench_sandboxed_app import SandboxedBenchApp
    app = SandboxedBenchApp(mode="patched").start()
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", app.network_name)
    try:
        yield app
    finally:
        app.stop()


def test_app_binds_loopback_only_and_returns_a_base_url(vulnerable_app):
    assert vulnerable_app.base_url.startswith("http://127.0.0.1:")


def test_make_server_still_defaults_to_loopback_and_ephemeral_port():
    """Locks in BenchApp's existing, deliberate security property (spec
    principle 1: a target containing real, exploitable bugs must never be
    reachable beyond loopback) -- the new optional bind/port parameters
    (added for the container-based launcher Tasks 12-17 use, see
    bench_sandboxed_app.py) must be opt-in only, never change this
    fixture's own default behavior."""
    from bench_app import _make_server
    server = _make_server("vulnerable")
    try:
        host, port = server.server_address
        assert host == "127.0.0.1"
        assert port != 0
    finally:
        server.server_close()


def test_make_server_accepts_an_explicit_bind_and_port_for_the_container_launcher():
    # Uses 127.0.0.2, not 0.0.0.0 (found in adversarial review, 2026-09-23):
    # _make_server()'s own docstring says the only intended non-default-bind
    # caller is the container entrypoint, running inside an isolated,
    # network-namespaced container -- binding 0.0.0.0 directly in THIS
    # process (the host pytest run) would briefly open a socket on every
    # host interface for a fixture whose whole design contract (spec
    # principle 1) is "never reachable beyond loopback." 127.0.0.2 still
    # proves a non-default bind is honored (loopback covers all of
    # 127.0.0.0/8, never externally routable) without that exposure.
    from bench_app import _make_server
    server = _make_server("vulnerable", bind="127.0.0.2", port=0)
    try:
        host, port = server.server_address
        assert host == "127.0.0.2"
        assert port != 0
    finally:
        server.server_close()


def test_sqli_vulnerable_boolean_injection_returns_all_products(vulnerable_app):
    import urllib.request
    baseline = urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/products?id=1").read().decode()
    injected = urllib.request.urlopen(
        f"{vulnerable_app.base_url}/bench/products?id=1%20OR%201=1"
    ).read().decode()
    assert injected.count("PRODUCT-") > baseline.count("PRODUCT-")


def test_sqli_patched_boolean_injection_has_no_effect(patched_app):
    import urllib.request
    baseline = urllib.request.urlopen(f"{patched_app.base_url}/bench/products?id=1").read().decode()
    injected = urllib.request.urlopen(
        f"{patched_app.base_url}/bench/products?id=1%20OR%201=1"
    ).read().decode()
    assert injected.count("PRODUCT-") == baseline.count("PRODUCT-")


def test_request_log_records_the_path_and_query(vulnerable_app):
    import urllib.request
    urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/products?id=7")
    assert any(
        e["path"] == "/bench/products" and e["query"].get("id") == ["7"]
        for e in vulnerable_app.request_log
    )


def test_xss_vulnerable_reflects_script_tag_unescaped(vulnerable_app):
    import urllib.request
    body = urllib.request.urlopen(
        f"{vulnerable_app.base_url}/bench/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    ).read().decode()
    assert "<script>alert(1)</script>" in body


def test_xss_patched_escapes_the_script_tag(patched_app):
    import urllib.request
    body = urllib.request.urlopen(
        f"{patched_app.base_url}/bench/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    ).read().decode()
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_idor_vulnerable_attacker_session_sees_owners_order(vulnerable_app):
    import urllib.request
    req = urllib.request.Request(
        f"{vulnerable_app.base_url}/bench/orders/42", headers={"Cookie": "session=attacker-session"}
    )
    body = urllib.request.urlopen(req).read().decode()
    assert "ORDER-DETAIL-42-SECRET" in body


def test_idor_patched_attacker_session_is_refused(patched_app):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        f"{patched_app.base_url}/bench/orders/42", headers={"Cookie": "session=attacker-session"}
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 403


def test_idor_patched_owner_session_still_works(patched_app):
    import urllib.request
    req = urllib.request.Request(
        f"{patched_app.base_url}/bench/orders/42", headers={"Cookie": "session=owner-session"}
    )
    body = urllib.request.urlopen(req).read().decode()
    assert "ORDER-DETAIL-42-SECRET" in body


def test_backup_file_vulnerable_is_present(vulnerable_app):
    import urllib.request
    body = urllib.request.urlopen(f"{vulnerable_app.base_url}/backup.sql.bak").read().decode()
    assert "DB_PASSWORD=bench-fixture-fake-secret-not-real" in body


def test_backup_file_patched_is_absent(patched_app):
    import urllib.error
    import urllib.request
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{patched_app.base_url}/backup.sql.bak")
    assert exc.value.code == 404


def test_misconfig_vulnerable_banner_header_present(vulnerable_app):
    import urllib.request
    resp = urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/status")
    assert resp.headers.get("X-Bench-Debug-Panel") == "build 2026.09-DEBUG-ENABLED"


def test_misconfig_patched_banner_header_absent(patched_app):
    import urllib.request
    resp = urllib.request.urlopen(f"{patched_app.base_url}/bench/status")
    assert resp.headers.get("X-Bench-Debug-Panel") is None


def test_open_redirect_vulnerable_follows_any_next(vulnerable_app):
    import urllib.request
    import urllib.error
    class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        opener.open(f"{vulnerable_app.base_url}/bench/login?next=https://attacker.example/steal")
        assert False, "Expected HTTPError for redirect"
    except urllib.error.HTTPError as e:
        assert e.code == 302
        assert e.headers.get("Location") == "https://attacker.example/steal"


def test_open_redirect_patched_ignores_external_next(patched_app):
    import urllib.request
    import urllib.error
    class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        opener.open(f"{patched_app.base_url}/bench/login?next=https://attacker.example/steal")
        assert False, "Expected HTTPError for redirect"
    except urllib.error.HTTPError as e:
        assert e.code == 302
        assert e.headers.get("Location") == "/bench/home"


def test_harness_refuses_a_non_loopback_url():
    from bench_harness import ExternalTargetRefused, http_get
    with pytest.raises(ExternalTargetRefused):
        http_get("https://example.com")


def test_harness_reaches_the_real_loopback_target(vulnerable_app):
    from bench_harness import http_get
    status, body = http_get(f"{vulnerable_app.base_url}/bench/decoy")
    assert status == 200
    assert "nothing interesting" in body


# ---------------------------------------------------------------------------
# Networking-seam end-to-end proof (prerequisite for Tasks 12-17): the real
# production tool_resolver.run_tool() -> job_runtime -> sandbox_runner
# chain, with HUNTMCP_BENCH_NETWORK set, actually reaches a container-based
# bench_app and gets back real, differing evidence for a planted bug --
# not a mocked/bypassed path.
# ---------------------------------------------------------------------------

@requires_podman
def test_real_sandboxed_curl_reaches_the_container_based_bench_app_over_the_bench_network(
    sandboxed_vulnerable_app, bench_env,
):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import tool_resolver
    result = tool_resolver.run_tool(
        "curl", ["-s", f"{sandboxed_vulnerable_app.base_url}/bench/status"], timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "status: ok" in result.stdout


@requires_podman
def test_real_sandboxed_curl_gets_real_differing_evidence_for_the_planted_sqli(
    sandboxed_vulnerable_app, bench_env,
):
    """The networking seam's whole point: the sandboxed tool's OWN request
    must reach the REAL planted bug and get back REAL, differing evidence
    -- not a canned/mocked response. Mirrors the boolean-injection check
    test_sqli_vulnerable_boolean_injection_returns_all_products already
    proves against the host-thread fixture, but here through curl's own
    real sandboxed subprocess."""
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import tool_resolver
    base = sandboxed_vulnerable_app.base_url
    baseline = tool_resolver.run_tool("curl", ["-s", f"{base}/bench/products?id=1"], timeout=30)
    injected = tool_resolver.run_tool(
        "curl", ["-s", f"{base}/bench/products?id=1%20OR%201=1"], timeout=30,
    )
    assert baseline.returncode == 0 and injected.returncode == 0
    assert injected.stdout.count("PRODUCT-") > baseline.stdout.count("PRODUCT-")


# ---------------------------------------------------------------------------
# Tasks 12-17: real-tool fixture proofs -- each drives an actual, unmodified
# HuntMCP MCP tool function (loaded from its own server.py, exactly as
# test_cem_benchmark.py already does for case-mcp) against the
# container-based sandboxed_vulnerable_app/sandboxed_patched_app fixtures.
# ---------------------------------------------------------------------------

def _load_mcp_server(dashed_dir: str, module_name: str):
    # A real `python3 server.py` invocation gets its OWN directory
    # prepended to sys.path[0] automatically (CPython's interpreter-
    # startup behavior) -- importlib.util.spec_from_file_location() does
    # NOT do this. Most server.py files here only import shared
    # mcp-servers/ siblings (already handled by their own explicit
    # sys.path.insert), but idor-mcp/server.py imports idor_sweep.py, a
    # SAME-DIRECTORY sibling -- found live (Task 14) via a real
    # ModuleNotFoundError when loaded this way. Explicitly adding the
    # server's own directory here restores parity with real execution.
    server_dir = os.path.join(ROOT, "mcp-servers", dashed_dir)
    if server_dir not in sys.path:
        sys.path.insert(0, server_dir)
    spec = importlib.util.spec_from_file_location(
        module_name, os.path.join(server_dir, "server.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _poll_mcp_tool(check_scan_fn, start_result: str, timeout_s: int = 120) -> str:
    m = re.search(r'job_id="([^"]+)"', start_result)
    assert m, f"could not find job_id in: {start_result!r}"
    job_id = m.group(1)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        result = check_scan_fn(job_id)
        if "still running" not in result.lower():
            return result
        time.sleep(2)
    raise AssertionError(f"job {job_id} did not finish within {timeout_s}s")


def _requires_binary(binary_name: str):
    return pytest.mark.skipif(shutil.which(binary_name) is None, reason=f"{binary_name} not installed")


requires_sqlmap = _requires_binary("sqlmap")


@requires_podman
@requires_sqlmap
def test_real_sqlmap_confirms_sqli_in_vulnerable_mode(sandboxed_vulnerable_app, bench_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SQLMAP_TMP", str(bench_env / "sqlmap-tmp"))
    sqlmap_mcp = _load_mcp_server("sqlmap-mcp", "sqlmap_mcp_p2bench")
    started = sqlmap_mcp.test_injection(
        f"{sandboxed_vulnerable_app.base_url}/bench/products?id=1", level=1, risk=1, timeout=90,
    )
    result = _poll_mcp_tool(sqlmap_mcp.check_scan, started, timeout_s=90)
    assert "identified" in result.lower() or "injection point" in result.lower(), result


@requires_podman
@requires_sqlmap
def test_real_sqlmap_finds_nothing_in_patched_mode(sandboxed_patched_app, bench_env, monkeypatch):
    monkeypatch.setenv("HUNTMCP_SQLMAP_TMP", str(bench_env / "sqlmap-tmp"))
    sqlmap_mcp = _load_mcp_server("sqlmap-mcp", "sqlmap_mcp_p2bench_patched")
    started = sqlmap_mcp.test_injection(
        f"{sandboxed_patched_app.base_url}/bench/products?id=1", level=1, risk=1, timeout=90,
    )
    result = _poll_mcp_tool(sqlmap_mcp.check_scan, started, timeout_s=90)
    assert "no injection found" in result.lower(), result


requires_dalfox = _requires_binary("dalfox")


@requires_podman
@requires_dalfox
def test_real_dalfox_confirms_xss_in_vulnerable_mode(sandboxed_vulnerable_app, bench_env):
    dalfox_mcp = _load_mcp_server("dalfox-mcp", "dalfox_mcp_p2bench")
    started = dalfox_mcp.scan_parameter(
        f"{sandboxed_vulnerable_app.base_url}/bench/search?q=test", "q", timeout=90,
    )
    result = _poll_mcp_tool(dalfox_mcp.check_scan, started, timeout_s=90)
    assert "xss" in result.lower() and "no xss found" not in result.lower(), result


@requires_podman
@requires_dalfox
def test_real_dalfox_finds_nothing_in_patched_mode(sandboxed_patched_app, bench_env):
    dalfox_mcp = _load_mcp_server("dalfox-mcp", "dalfox_mcp_p2bench_patched")
    started = dalfox_mcp.scan_parameter(
        f"{sandboxed_patched_app.base_url}/bench/search?q=test", "q", timeout=90,
    )
    result = _poll_mcp_tool(dalfox_mcp.check_scan, started, timeout_s=90)
    assert "no xss found" in result.lower(), result


# idor-mcp is pure-stdlib urllib -- it never routes through
# tool_resolver.run_tool()/sandbox_runner (see idor-mcp/server.py's own
# module docstring), so it needs no sandboxed network seam; the
# host-thread vulnerable_app/patched_app fixtures are directly reachable.

def test_real_idor_mcp_confirms_leak_in_vulnerable_mode(vulnerable_app, bench_env):
    idor_mcp = _load_mcp_server("idor-mcp", "idor_mcp_p2bench")
    result = idor_mcp.sweep_idor(
        url=f"{vulnerable_app.base_url}/bench/orders/{{id}}",
        object_ids=["42"],
        owner_cookie_header="session=owner-session",
        other_cookie_header="session=attacker-session",
    )
    assert "LEAKED" in result, result


def test_real_idor_mcp_reports_protected_in_patched_mode(patched_app, bench_env):
    idor_mcp = _load_mcp_server("idor-mcp", "idor_mcp_p2bench_patched")
    result = idor_mcp.sweep_idor(
        url=f"{patched_app.base_url}/bench/orders/{{id}}",
        object_ids=["42"],
        owner_cookie_header="session=owner-session",
        other_cookie_header="session=attacker-session",
    )
    assert "PROTECTED" in result, result


requires_ffuf = _requires_binary("ffuf")
_P2BENCH_WORDLIST = "p2bench-backup-filenames.txt"  # under knowledge/wordlists/, ffuf-mcp's approved root


@requires_podman
@requires_ffuf
def test_real_ffuf_discovers_backup_file_in_vulnerable_mode(sandboxed_vulnerable_app, bench_env):
    ffuf_mcp = _load_mcp_server("ffuf-mcp", "ffuf_mcp_p2bench")
    started = ffuf_mcp.fuzz_directory(
        sandboxed_vulnerable_app.base_url, wordlist=_P2BENCH_WORDLIST, timeout=60,
    )
    result = _poll_mcp_tool(ffuf_mcp.check_scan, started, timeout_s=60)
    assert "backup.sql.bak" in result, result


@requires_podman
@requires_ffuf
def test_real_ffuf_finds_nothing_in_patched_mode(sandboxed_patched_app, bench_env):
    ffuf_mcp = _load_mcp_server("ffuf-mcp", "ffuf_mcp_p2bench_patched")
    started = ffuf_mcp.fuzz_directory(
        sandboxed_patched_app.base_url, wordlist=_P2BENCH_WORDLIST, timeout=60,
    )
    result = _poll_mcp_tool(ffuf_mcp.check_scan, started, timeout_s=60)
    assert "no directories found" in result.lower(), result


requires_nuclei = _requires_binary("nuclei")

_SOURCE_TEMPLATE = os.path.join(ROOT, "tests", "fixtures", "bench_target", "templates", "misconfig-banner.yaml")


@pytest.fixture
def bench_misconfig_template():
    """Copies the fixture template into templates_pin.TEMPLATES_DIR (the
    pinned, sandbox-mounted nuclei-templates root) under a leading-
    underscore subfolder reserved for bench-local content, then yields the
    RELATIVE path to pass as scan_with_templates()'s `templates=` argument
    -- nuclei-mcp's own _resolve_templates_arg() rejects any path outside
    that root (S5-follow-up hardening, see the plan's Task 16 notes).
    Skips if the pinned snapshot hasn't been fetched."""
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "nuclei-mcp"))
    import templates_pin
    if not templates_pin.templates_available():
        pytest.skip("nuclei-templates snapshot not fetched -- run scripts/fetch-nuclei-templates.sh")
    dest_dir = os.path.join(templates_pin.TEMPLATES_DIR, "_bench-fixtures")
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, "misconfig-banner.yaml")
    try:
        shutil.copyfile(_SOURCE_TEMPLATE, dest_path)
        yield "_bench-fixtures/misconfig-banner.yaml"
    finally:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        try:
            os.rmdir(dest_dir)
        except OSError:
            pass


@requires_podman
@requires_nuclei
def test_real_nuclei_confirms_misconfig_in_vulnerable_mode(
    sandboxed_vulnerable_app, bench_misconfig_template, bench_env,
):
    nuclei_mcp = _load_mcp_server("nuclei-mcp", "nuclei_mcp_p2bench")
    started = nuclei_mcp.scan_with_templates(
        sandboxed_vulnerable_app.base_url, bench_misconfig_template, timeout=60,
    )
    result = _poll_mcp_tool(nuclei_mcp.check_scan, started, timeout_s=60)
    assert "bench-debug-panel-exposed" in result.lower(), result


@requires_podman
@requires_nuclei
def test_real_nuclei_finds_nothing_in_patched_mode(
    sandboxed_patched_app, bench_misconfig_template, bench_env,
):
    nuclei_mcp = _load_mcp_server("nuclei-mcp", "nuclei_mcp_p2bench_patched")
    started = nuclei_mcp.scan_with_templates(
        sandboxed_patched_app.base_url, bench_misconfig_template, timeout=60,
    )
    result = _poll_mcp_tool(nuclei_mcp.check_scan, started, timeout_s=60)
    assert "no vulnerabilities found" in result.lower(), result


@requires_podman
def test_real_curl_confirms_open_redirect_in_vulnerable_mode(sandboxed_vulnerable_app, bench_env):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import tool_resolver
    result = tool_resolver.run_tool(
        "curl", ["-s", "-o", "/dev/null", "-D", "-",
                 f"{sandboxed_vulnerable_app.base_url}/bench/login?next=https://attacker.example/steal"],
        timeout=30,
    )
    assert "location: https://attacker.example/steal" in result.stdout.lower()


@requires_podman
def test_real_curl_shows_same_origin_redirect_in_patched_mode(sandboxed_patched_app, bench_env):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import tool_resolver
    result = tool_resolver.run_tool(
        "curl", ["-s", "-o", "/dev/null", "-D", "-",
                 f"{sandboxed_patched_app.base_url}/bench/login?next=https://attacker.example/steal"],
        timeout=30,
    )
    assert "location: https://attacker.example/steal" not in result.stdout.lower()
    assert "location: /bench/home" in result.stdout.lower()
