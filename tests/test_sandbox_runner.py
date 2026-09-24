"""S5 (IMPLEMENTATION-TASK-TRACKER.md) -- rootless per-run execution
boundary. Unit tests verify argv construction (mocked, no podman needed);
live tests (skipped if podman isn't installed) verify the real isolation
properties against the actual mcp-servers/sandbox/Dockerfile image."""

import os
import shutil
import subprocess

import pytest

import sandbox_runner


# ---------------------------------------------------------------------------
# Unit tests: argv construction (no podman required)
# ---------------------------------------------------------------------------

def test_unknown_tool_raises_before_any_subprocess_is_attempted():
    """The core allowlist guarantee: an unrecognized tool name must never
    be treated as an arbitrary path to execute inside the sandbox."""
    with pytest.raises(sandbox_runner.UnknownSandboxTool):
        sandbox_runner.build_argv("not-an-approved-tool", [], "/tmp/scratch", env={})


def test_every_approved_tool_maps_to_an_in_container_absolute_path():
    for tool_name, path in sandbox_runner._TOOL_MAP.items():
        assert path.startswith("/"), f"{tool_name} maps to a non-absolute path {path!r}"


def test_build_argv_uses_the_pinned_image():
    argv = sandbox_runner.build_argv("curl", ["https://example.com"], "/tmp/scratch", env={})
    assert sandbox_runner.SANDBOX_IMAGE in argv
    assert ":latest" not in sandbox_runner.SANDBOX_IMAGE


def test_build_argv_includes_isolation_flags():
    argv = sandbox_runner.build_argv("curl", ["https://example.com"], "/tmp/scratch", env={})
    for flag in ("--rm", "--read-only", "--cap-drop=ALL",
                 "--security-opt=no-new-privileges", "--pids-limit=50", "--memory=512m"):
        assert flag in argv, f"missing isolation flag {flag!r} in {argv}"


def test_build_argv_mounts_only_the_scratch_dir_by_default():
    argv = sandbox_runner.build_argv("curl", ["https://example.com"], "/tmp/my-scratch", env={})
    volume_flags = [a for a in argv if a.startswith("--volume=")]
    assert volume_flags == ["--volume=/tmp/my-scratch:/workspace:rw"]


def test_build_argv_env_flags_match_exactly_what_was_passed():
    argv = sandbox_runner.build_argv(
        "curl", ["https://example.com"], "/tmp/scratch",
        env={"PATH": "/usr/bin", "SSL_CERT_FILE": "/etc/ssl/custom.pem"},
    )
    assert "--env=PATH=/usr/bin" in argv
    assert "--env=SSL_CERT_FILE=/etc/ssl/custom.pem" in argv
    # HOME is always the container's own (see the next test) -- everything
    # else leaks through as explicitly passed, nothing more.
    env_flags = [a for a in argv if a.startswith("--env=") and not a.startswith("--env=HOME=")]
    assert len(env_flags) == 2


def test_build_argv_always_overrides_home_to_the_container_users_own():
    """Regression test found live: `env` (tool_resolver.minimal_subprocess_env())
    is the SAME dict also used for the outer podman-launching process,
    where HOME correctly means the real host user's home directory -- but
    forwarding that value INTO the container made ffuf silently fail to
    find its own $HOME/.config/ffuf/scraper (that host path doesn't exist
    inside the container) and fall back to printing usage/help, which
    looked exactly like an argv-parsing bug at first. The container's own
    HOME (CONTAINER_HOME, matching the Dockerfile's `useradd -m`) must
    always win, regardless of what HOME value the caller's env= carries."""
    argv = sandbox_runner.build_argv(
        "curl", [], "/tmp/scratch", env={"PATH": "/usr/bin", "HOME": "/home/someone-else"},
    )
    assert f"--env=HOME={sandbox_runner.CONTAINER_HOME}" in argv
    assert "--env=HOME=/home/someone-else" not in argv


def test_build_argv_never_passes_env_host():
    argv = sandbox_runner.build_argv("curl", [], "/tmp/scratch", env={"PATH": "/usr/bin"})
    assert "--env-host" not in argv


def test_build_argv_never_sets_a_network_flag_by_default(monkeypatch):
    """The core guarantee for every real hunt: with HUNTMCP_BENCH_NETWORK
    unset (true for every production launch config -- it's never set in
    opencode.jsonc), build_argv() must never add a --network flag at all,
    preserving today's default per-container isolated network exactly."""
    monkeypatch.delenv("HUNTMCP_BENCH_NETWORK", raising=False)
    argv = sandbox_runner.build_argv("curl", ["https://example.com"], "/tmp/scratch", env={})
    assert not any(a.startswith("--network") for a in argv)


def test_build_argv_joins_the_bench_network_only_when_the_env_var_is_set(monkeypatch):
    """P2-BENCH's real-tool fixture-proof tests (Tasks 12-17) are the only
    intended caller of this: a dedicated, --internal (no host/internet
    route), test-harness-owned Podman network so a sandboxed tool
    container can reach its own throwaway bench_app container. This is
    read directly from the process environment, never from a build_argv()
    parameter or any MCP tool argument -- there is no code path from an
    agent's tool-call input to this variable."""
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", "huntmcp-bench-net-deadbeef")
    argv = sandbox_runner.build_argv("curl", ["https://example.com"], "/tmp/scratch", env={})
    assert "--network=huntmcp-bench-net-deadbeef" in argv


def test_build_argv_rejects_a_bench_network_value_not_matching_the_expected_prefix(monkeypatch):
    """Defense in depth (found in adversarial review, 2026-09-23): the raw
    env-var value was previously spliced into --network=<value> with no
    validation at all -- a stray/typo'd/leftover-debug value of "host"
    would have silently granted every subsequent real Tier-2 tool call in
    that process full host networking, defeating S5 entirely. Only
    SandboxedBenchApp's own generated names (always prefixed
    huntmcp-bench-net-) are accepted; anything else, including Podman's
    own special values (host/none/bridge/container:x), is refused."""
    for dangerous in ("host", "none", "bridge", "container:evil", "huntmcp-sbx-not-a-real-bench-net"):
        monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", dangerous)
        with pytest.raises(sandbox_runner.UnsafeBenchNetwork):
            sandbox_runner.build_argv("curl", ["https://example.com"], "/tmp/scratch", env={})


def test_build_argv_ignores_an_empty_bench_network_value(monkeypatch):
    """An empty string is not a valid network name -- must behave exactly
    like unset, not produce a bare/broken --network= flag."""
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", "")
    argv = sandbox_runner.build_argv("curl", ["https://example.com"], "/tmp/scratch", env={})
    assert not any(a.startswith("--network") for a in argv)


def test_build_argv_never_leaks_the_bench_network_var_into_the_container_env(monkeypatch):
    """Adversarial check: HUNTMCP_BENCH_NETWORK controls the PODMAN
    NETWORK-JOIN flag only -- it must never also appear as one of the
    sandboxed process's own --env= flags. tool_resolver.minimal_subprocess_env()
    already excludes it (not in SUBPROCESS_ENV_ALLOWLIST), but this locks
    the guarantee in at build_argv() itself: even if a caller's `env=`
    dict is empty, the container never sees this variable."""
    monkeypatch.setenv("HUNTMCP_BENCH_NETWORK", "huntmcp-bench-net-deadbeef")
    argv = sandbox_runner.build_argv("curl", ["https://example.com"], "/tmp/scratch", env={})
    assert not any(a.startswith("--env=HUNTMCP_BENCH_NETWORK") for a in argv)


def test_build_argv_does_not_auto_mount_an_existing_path_from_args(tmp_path):
    """The core fix for a real security hole found in review: a path that
    merely APPEARS in `args` (as opposed to being explicitly passed via
    `extra_mounts=`/`cwd=`) must never be auto-mounted, even if it exists
    on the host -- ffuf-mcp's `wordlist` MCP parameter is agent-chosen and
    passed straight into args unvalidated; auto-mounting anything found
    there would let a prompt-injected agent get an arbitrary host path
    (e.g. under $HOME) silently bind-mounted and permission-widened with
    no explicit caller decision anywhere. Only scratch_dir (always) and
    explicit cwd/extra_mounts ever produce a --volume flag now."""
    existing_dir = tmp_path / "looks-legit"
    existing_dir.mkdir()
    argv = sandbox_runner.build_argv(
        "ffuf", ["-w", str(existing_dir), "-u", "https://example.com/FUZZ"],
        "/tmp/scratch", env={},
    )
    volume_flags = [a for a in argv if a.startswith("--volume=")]
    assert volume_flags == ["--volume=/tmp/scratch:/workspace:rw"]
    assert str(existing_dir) in argv  # the arg itself still passes through unmodified


def test_build_argv_mounts_an_explicit_rw_extra_mount(tmp_path):
    """The sqlmap-mcp case: --output-dir <tmpdir> is a real, specific,
    engagement-scoped directory sqlmap-mcp explicitly declares and reads
    files back from -- it must be visible inside the container at the
    SAME path, unmodified, mounted read-write (via extra_mounts_rw=) since
    sqlmap must WRITE its findings there."""
    out_dir = tmp_path / "sqlmap-out"
    out_dir.mkdir()
    argv = sandbox_runner.build_argv(
        "sqlmap", ["--output-dir", str(out_dir), "-u", "https://example.com"],
        "/tmp/scratch", env={}, extra_mounts_rw=[str(out_dir)],
    )
    assert f"--volume={out_dir}:{out_dir}:rw" in argv
    assert str(out_dir) in argv


def test_build_argv_mounts_an_explicit_file_extra_mount_read_only(tmp_path):
    """The httpx-mcp probe_hosts() case: -l <input_path> is a real file
    httpx only reads target domains from -- mounted read-only (via
    extra_mounts=) by default. Regression: an earlier version mounted
    this :rw unnecessarily, and a test run against it live actually
    deleted a real, git-tracked project file from the host -- read-only
    is the safer default whenever the sandboxed process doesn't need to
    write."""
    input_file = tmp_path / "domains.txt"
    input_file.write_text("example.com\n")
    argv = sandbox_runner.build_argv(
        "httpx", ["-l", str(input_file), "-silent"], "/tmp/scratch", env={},
        extra_mounts=[str(input_file)],
    )
    assert f"--volume={input_file}:{input_file}:ro" in argv
    assert f"--volume={input_file}:{input_file}:rw" not in argv


def test_build_argv_mounts_and_sets_workdir_for_explicit_cwd(tmp_path):
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    argv = sandbox_runner.build_argv(
        "httpx", ["-srd", str(work_dir)], "/tmp/scratch", env={}, cwd=str(work_dir),
    )
    assert f"--workdir={work_dir}" in argv
    assert f"--volume={work_dir}:{work_dir}:rw" in argv


def test_build_argv_refuses_a_dangerously_broad_explicit_mount():
    with pytest.raises(sandbox_runner.UnsafeSandboxMount):
        sandbox_runner.build_argv("curl", [], "/tmp/scratch", env={}, extra_mounts=["/etc"])


def test_build_argv_refuses_home_directory_as_explicit_mount():
    with pytest.raises(sandbox_runner.UnsafeSandboxMount):
        sandbox_runner.build_argv(
            "curl", [], "/tmp/scratch", env={}, extra_mounts=[os.path.expanduser("~")],
        )


def test_build_argv_allows_a_purpose_built_directory_deep_under_home_as_explicit_mount():
    """Regression test for a real bug found live: sqlmap-mcp's actual
    _output_dir() resolves to something like
    .../HuntMCP/data/engagements/<slug>/tmp-sqlmap/<job> -- a real,
    specific, purpose-built scratch directory that happens to live under
    both $HOME and the repo root. An earlier version of the deny-list
    check denied anything that was merely a PREFIX match against $HOME or
    the repo root, which blocked every single real sqlmap call on this
    completely ordinary, non-broad path. Only the exact directories
    themselves (mounted wholesale) should ever be denied -- a
    purpose-built subdirectory deep inside must be allowed."""
    scratch_under_home = os.path.join(sandbox_runner._REPO_ROOT, "data", ".huntmcp-test-scratch-regress")
    os.makedirs(scratch_under_home, exist_ok=True)
    try:
        argv = sandbox_runner.build_argv(
            "sqlmap", ["--output-dir", scratch_under_home], "/tmp/scratch", env={},
            extra_mounts_rw=[scratch_under_home],
        )
        assert f"--volume={scratch_under_home}:{scratch_under_home}:rw" in argv
    finally:
        shutil.rmtree(scratch_under_home, ignore_errors=True)


def test_build_argv_does_not_flag_an_ordinary_scratch_path_as_cwd():
    """Regression: an early version of the deny-list check used a bare
    `resolved.startswith(deny.rstrip("/") + "/")` for every deny entry,
    including "/" itself -- deny.rstrip("/") for "/" is "", so the check
    degenerated to `resolved.startswith("/")`, which matches EVERY
    absolute path and made the whole mount feature refuse everything."""
    scratch = sandbox_runner.new_scratch_dir()
    try:
        argv = sandbox_runner.build_argv("curl", [], "/tmp/unrelated-scratch", env={}, cwd=scratch)
        assert any(a.startswith(f"--volume={scratch}:") for a in argv)
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


def test_new_scratch_dir_creates_a_real_unique_directory():
    a = sandbox_runner.new_scratch_dir()
    b = sandbox_runner.new_scratch_dir()
    try:
        assert a != b
        assert os.path.isdir(a)
        assert os.path.isdir(b)
    finally:
        sandbox_runner.cleanup_scratch_dir(a)
        sandbox_runner.cleanup_scratch_dir(b)


def test_cleanup_scratch_dir_removes_it():
    d = sandbox_runner.new_scratch_dir()
    sandbox_runner.cleanup_scratch_dir(d)
    assert not os.path.exists(d)


def test_cleanup_scratch_dir_tolerates_already_missing():
    sandbox_runner.cleanup_scratch_dir("/tmp/definitely-does-not-exist-huntmcp-xyz")


def test_new_container_name_is_unique():
    a = sandbox_runner.new_container_name()
    b = sandbox_runner.new_container_name()
    assert a != b
    assert a.startswith("huntmcp-sbx-")


def test_remove_container_is_a_safe_noop_when_podman_missing(monkeypatch):
    def _raise(*a, **k):
        raise FileNotFoundError("no podman")

    monkeypatch.setattr(subprocess, "run", _raise)
    sandbox_runner.remove_container("does-not-exist")  # must not raise


def test_remove_container_tolerates_an_already_gone_container():
    # Never started, so `podman rm -f` on it is a normal not-found case --
    # must not raise.
    sandbox_runner.remove_container("huntmcp-sbx-definitely-never-existed")


# ---------------------------------------------------------------------------
# Live tests: real podman + the real mcp-servers/sandbox/Dockerfile image.
# Skipped entirely if podman isn't installed or the image hasn't been built
# -- see mcp-servers/sandbox/Dockerfile's own comment for the build command.
# ---------------------------------------------------------------------------

def _podman_and_image_available() -> bool:
    if not shutil.which("podman"):
        return False
    result = subprocess.run(
        ["podman", "image", "exists", sandbox_runner.SANDBOX_IMAGE],
        capture_output=True, timeout=10,
    )
    return result.returncode == 0


requires_sandbox_image = pytest.mark.skipif(
    not _podman_and_image_available(),
    reason="podman not installed or huntmcp-sandbox image not built",
)


@requires_sandbox_image
def test_live_sandboxed_curl_reaches_the_real_network():
    scratch = sandbox_runner.new_scratch_dir()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "https://example.com"], scratch,
            env={"PATH": "/usr/bin:/bin"},
        )
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0
        assert "Example Domain" in result.stdout
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


@requires_sandbox_image
def test_live_sandboxed_process_cannot_see_a_host_only_env_var():
    scratch = sandbox_runner.new_scratch_dir()
    try:
        # Deliberately NOT in the env= passed to build_argv -- simulates a
        # real credential sitting in this process's own os.environ that
        # must never reach the sandboxed tool.
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "file:///proc/self/environ"], scratch,
            env={"PATH": "/usr/bin:/bin"},
        )
        env = dict(os.environ)
        env["HUNTMCP_TEST_HOST_ONLY_SECRET"] = "must-never-appear-in-container"
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30, env=env)
        assert "must-never-appear-in-container" not in (result.stdout or "")
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


@requires_sandbox_image
def test_live_sandboxed_root_filesystem_is_read_only():
    scratch = sandbox_runner.new_scratch_dir()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "-o", "/etc/write-attempt", "https://example.com"],
            scratch, env={"PATH": "/usr/bin:/bin"},
        )
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        # curl's own exit code for "couldn't write output" -- confirms the
        # write was actually refused by the filesystem, not merely
        # unattempted for some unrelated reason.
        assert result.returncode != 0
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


@requires_sandbox_image
def test_live_sandboxed_scratch_dir_is_writable():
    scratch = sandbox_runner.new_scratch_dir()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "-o", "/workspace/output.txt", "https://example.com"],
            scratch, env={"PATH": "/usr/bin:/bin"},
        )
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0
        assert os.path.isfile(os.path.join(scratch, "output.txt"))
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


@requires_sandbox_image
def test_live_extra_mounts_read_only_actually_prevents_writes(tmp_path):
    """Regression test for a real, DEMONSTRATED data-loss incident during
    this feature's own testing: an early version mounted a caller-declared
    path :rw unconditionally, and a live test run against it deleted a
    real, git-tracked project wordlist file from the host (recovered via
    git checkout, but proved the risk is real). extra_mounts= must
    genuinely enforce read-only at the kernel/mount level, not just by
    convention -- an attempt to write through it must fail."""
    protected_file = tmp_path / "protected.txt"
    protected_file.write_text("do not modify me\n")
    scratch = sandbox_runner.new_scratch_dir()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "-o", str(protected_file), "https://example.com"],
            scratch, env={"PATH": "/usr/bin:/bin"}, extra_mounts=[str(protected_file)],
        )
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        assert result.returncode != 0  # curl's own write-error exit code
        assert protected_file.read_text() == "do not modify me\n"
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


@requires_sandbox_image
def test_live_container_is_removed_after_normal_completion():
    scratch = sandbox_runner.new_scratch_dir()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "https://example.com"], scratch, env={"PATH": "/usr/bin:/bin"},
        )
        subprocess.run(argv, capture_output=True, text=True, timeout=30)
        result = subprocess.run(
            ["podman", "ps", "-a", "-q", "--filter", "label=huntmcp-sandbox=1"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.stdout.strip() == ""
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


@requires_sandbox_image
def test_live_remove_container_does_not_touch_a_different_concurrent_container():
    """Regression test for a real concurrency bug found in review: an
    earlier version force-removed EVERY container sharing the generic
    huntmcp-sandbox=1 label, which would kill a completely different,
    healthy, still-running concurrent sandboxed call as collateral damage
    (plausible in HuntMCP's own multi-agent architecture -- recon-agent's
    httpx job can genuinely still be running while scan-agent's nuclei
    call finishes and cleans up). remove_container() must only ever touch
    the ONE container it's given by exact name."""
    scratch_a = sandbox_runner.new_scratch_dir()
    scratch_b = sandbox_runner.new_scratch_dir()
    name_a = sandbox_runner.new_container_name()
    name_b = sandbox_runner.new_container_name()
    proc_b = None
    try:
        # "a" is the one whose wrapper gets killed (its container survives,
        # orphaned, per the other live tests' own finding).
        argv_a = sandbox_runner.build_argv(
            "curl", ["-s", "--max-time", "30", "http://10.255.255.1/"],
            scratch_a, env={"PATH": "/usr/bin:/bin"}, container_name=name_a,
        )
        proc_a = subprocess.Popen(argv_a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # "b" simulates a different, unrelated, still-healthy concurrent run.
        argv_b = sandbox_runner.build_argv(
            "curl", ["-s", "--max-time", "30", "http://10.255.255.2/"],
            scratch_b, env={"PATH": "/usr/bin:/bin"}, container_name=name_b,
        )
        proc_b = subprocess.Popen(argv_b, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        import time
        time.sleep(1)
        proc_a.kill()
        proc_a.wait()

        sandbox_runner.remove_container(name_a)

        # "b" must still be alive and untouched.
        result = subprocess.run(
            ["podman", "ps", "-q", "--filter", f"name={name_b}"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.stdout.strip() != "", "concurrent container 'b' was wrongly removed"
    finally:
        if proc_b is not None:
            proc_b.kill()
            proc_b.wait()
        sandbox_runner.remove_container(name_a)
        sandbox_runner.remove_container(name_b)
        sandbox_runner.cleanup_scratch_dir(scratch_a)
        sandbox_runner.cleanup_scratch_dir(scratch_b)


@requires_sandbox_image
def test_live_remove_container_cleans_up_a_sigkilled_run_precisely():
    """Simulates the SIGKILL-orphan scenario job_runtime.py's timeout path
    can create: start a long-running sandboxed container under a KNOWN
    name, kill the wrapper hard (SIGKILL, uncatchable) rather than letting
    it exit gracefully, and verify remove_container(that_exact_name)
    cleans it up -- confirmed live elsewhere that the container survives
    the kill and shows status 'running' indefinitely, not 'exited', so
    only a precise, caller-tracked name (never a blind label sweep) can
    safely target exactly this one."""
    scratch = sandbox_runner.new_scratch_dir()
    name = sandbox_runner.new_container_name()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "--max-time", "30", "http://10.255.255.1/"],
            scratch, env={"PATH": "/usr/bin:/bin"}, container_name=name,
        )
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import time
        time.sleep(1)
        proc.kill()
        proc.wait()
        sandbox_runner.remove_container(name)
        result = subprocess.run(
            ["podman", "ps", "-a", "-q", "--filter", f"name={name}"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.stdout.strip() == ""
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)
