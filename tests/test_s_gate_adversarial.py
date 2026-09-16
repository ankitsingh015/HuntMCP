"""S-GATE (IMPLEMENTATION-TASK-TRACKER.md §3, row `S-GATE`; MASTER-ROADMAP-
FINAL-v3.md §6/§11/§14.2): the Tier-2 exit gate. S5 (rootless per-run
sandbox) and S6 (hook tamper-resistance) each have their own test suites
(test_sandbox_runner.py, test_hook_tamper_resistance.py) proving each
control individually -- S-GATE's own job, per the roadmap's explicit
wording, is different: "S5+S6 individually do not satisfy S-GATE." This
file is the adversarial regression that exercises them TOGETHER, through
the REAL chokepoints an agent's tool calls actually go through
(job_runtime.start_job()/poll_job(), scope_gate_hook.main()) rather than
the lower-level units those other files test in isolation, across the
roadmap's named lifecycle (create -> run -> pause -> resume -> terminate)
and its three named adversarial scenarios:

1. canary-secret exfil via hostile tool output
2. out-of-scope action
3. hostile-repo checkout

Promotion criterion (v3 §11, "Rootless boundary preserves utility" row):
containment high, utility approx. baseline -- so every containment test
here has a sibling proving the equivalent LEGITIMATE call still works,
matching the same "containment AND utility" bar S5/S6's own tables use.

Lifecycle mapping onto this codebase's real mechanics (job_runtime.py has
no native pause/resume RPCs -- these map onto its actual poll-based
design, not a feature that needed to be invented for this file):
  create   -> job_runtime.start_job() launches the sandboxed container
  run      -> the container is executing
  pause    -> an agent polls poll_job() while the job is still "running"
              (a no-op from the job's own point of view -- it keeps running
              regardless of whether/how often anyone polls)
  resume   -> a later poll_job() call, same job, still "running" or now
              "done"
  terminate -> either a normal exit (poll_job() returns "done") or a
              forced kill on the max_wall_seconds ceiling (poll_job()
              internally calls _kill_and_collect(), SIGKILL + container
              removal)
Both termination paths are exercised below, since S5's own docs flag the
forced-kill path as the one where a container can survive its wrapper
process and needs the precise, per-run remove_container() call to clean up
-- containment must hold on that path too, not just a clean exit.

Live (real-podman, real-image) tests are skipped if the sandbox image
hasn't been built -- see test_sandbox_runner.py's own identical skip
condition, reused verbatim here via the same podman-image-exists check.
"""

import io
import json
import os
import subprocess
import time
import uuid

import engagement_paths
import hook_confirm
import job_runtime
import pytest
import sandbox_runner
import scope_gate_hook as hook


# ---------------------------------------------------------------------------
# Shared isolation / helpers (mirrors test_hook_tamper_resistance.py's own
# conventions exactly, so this file behaves identically under pytest
# regardless of what engagement/confirm-token state is really on disk).
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_state(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".not-really-active"))
    monkeypatch.setenv("HUNTMCP_HOOK_CONFIRM_PATH", str(tmp_path / "hook-edit-confirm.json"))
    monkeypatch.setenv("HUNTMCP_RCE_CONFIRM_PATH", str(tmp_path / "os-shell-confirm.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.chdir(tmp_path)


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


def _run_hook(monkeypatch, payload):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    return hook.main()


def _confirm_hook_edit(monkeypatch):
    hook_confirm.request_confirmation(
        ttl_seconds=1800,
        stdin=_FakeTTY(hook_confirm.CONFIRM_PHRASE + "\n"),
        stdout=io.StringIO(),
    )


def _no_budget(monkeypatch):
    monkeypatch.setattr(job_runtime, "_enforce_budget", lambda name: None)


def _no_audit(monkeypatch):
    monkeypatch.setattr(job_runtime, "_log_call", lambda *a, **k: None)


def _podman_and_image_available() -> bool:
    if not sandbox_runner.podman_available():
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


def _poll_until(job_id, jobs, *, checkpoints, timeout_s=30):
    """Poll job_runtime.poll_job() until status != "running", recording the
    result at every distinct status transition into `checkpoints` (a list
    the caller inspects afterwards) so a test can assert containment held
    at EVERY lifecycle stage the job actually passed through, not just the
    final one. Mirrors what a real agent's own check_scan() polling loop
    does -- this is the same function every scan-*-mcp server's tool wraps."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        result = job_runtime.poll_job(job_id, jobs)
        if result.get("status") != last_status:
            checkpoints.append(result)
            last_status = result.get("status")
        if result.get("status") != "running":
            return result
        time.sleep(0.2)
    raise AssertionError(f"job {job_id} never finished within {timeout_s}s: {checkpoints}")


# ---------------------------------------------------------------------------
# Scenario 1: canary-secret exfil via hostile tool output, across the full
# create -> run -> pause -> resume -> terminate lifecycle.
# ---------------------------------------------------------------------------

@requires_sandbox_image
def test_canary_secret_never_leaks_across_the_full_job_lifecycle(monkeypatch):
    """Plants a canary secret in this process's own os.environ (standing in
    for a real credential sitting in the MCP server process's environment)
    under a key that is NOT in tool_resolver.SUBPROCESS_ENV_ALLOWLIST, then
    runs a "hostile" tool call through the REAL start_job()/poll_job()
    chokepoint -- `curl file:///proc/self/environ`, i.e. a tool actively
    trying to read and surface its own process environment, the most
    direct "hostile tool output" exfil attempt available without needing a
    custom image. Polls through every lifecycle checkpoint (running x2,
    simulating pause-then-resume; then done) and asserts the canary is
    absent from stdout/stderr at EVERY checkpoint, not just the final
    result -- a leak that only showed up in an intermediate poll would be
    just as real a failure."""
    canary = f"huntmcp-canary-{uuid.uuid4().hex}"
    monkeypatch.setenv("HUNTMCP_TEST_CANARY_SECRET", canary)
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)

    jobs: dict = {}
    started = job_runtime.start_job(
        "curl", ["-s", "--retry", "3", "--retry-delay", "1", "file:///proc/self/environ"],
        max_wall_seconds=30, jobs=jobs,
    )
    assert started["status"] == "running"
    job_id = started["job_id"]

    checkpoints: list = []
    final = _poll_until(job_id, jobs, checkpoints=checkpoints)

    assert final["status"] == "done"
    assert final["returncode"] == 0
    # Sanity check that the "hostile" read genuinely worked and produced
    # real environment content (PATH is itself an allowlisted key, so it's
    # expected here) -- without this, an absent canary would be equally
    # (and uninterestingly) explained by curl silently failing to read the
    # file at all, which would make the containment assertions below prove
    # nothing.
    assert "PATH=" in final["stdout"], f"hostile read did not actually work: {final}"
    for cp in checkpoints:
        assert canary not in cp.get("stdout", ""), f"canary leaked at checkpoint {cp}"
        assert canary not in cp.get("stderr", ""), f"canary leaked at checkpoint {cp}"
    assert canary not in final["stdout"]
    assert canary not in final["stderr"]


@requires_sandbox_image
def test_canary_secret_never_leaks_even_on_forced_kill_termination(monkeypatch):
    """Same canary-exfil attempt, but forced through the OTHER termination
    path: max_wall_seconds is set low enough that poll_job() hits its own
    timeout ceiling and calls _kill_and_collect() (SIGKILL + explicit
    remove_container()), the path S5's own docs flag as the one where a
    container can survive its wrapper process. Containment (no canary in
    the partial output) must hold there too, and cleanup (scratch dir +
    container both gone) must still happen -- a forced, ugly termination
    is not an excuse for either property to slip."""
    canary = f"huntmcp-canary-{uuid.uuid4().hex}"
    monkeypatch.setenv("HUNTMCP_TEST_CANARY_SECRET", canary)
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)

    jobs: dict = {}
    # 10.255.255.1 is a real, standard black-hole address (also used by
    # test_sandbox_runner.py's own concurrency tests for the same reason):
    # non-routable, so curl blocks until its own --max-time rather than
    # failing/succeeding fast -- reliably still "running" when max_wall_
    # seconds's 1s ceiling is checked below.
    started = job_runtime.start_job(
        "curl", ["-s", "file:///proc/self/environ", "--next", "-s", "--max-time", "30",
                 "http://10.255.255.1/"],
        max_wall_seconds=1, jobs=jobs,
    )
    job_id = started["job_id"]
    scratch_dir = jobs[job_id].scratch_dir
    container_name = jobs[job_id].container_name

    time.sleep(2)  # let the 1s ceiling elapse while the job is still "running"
    result = job_runtime.poll_job(job_id, jobs)

    assert result["status"] == "timeout"
    # Same sanity check as the normal-completion test above: the file://
    # leg of this --next chain completes almost instantly (confirmed
    # live), well before the black-hole leg gets killed at the 1s ceiling
    # -- so partial stdout genuinely contains real environ content by the
    # time of the kill, not nothing.
    assert "PATH=" in result.get("stdout", ""), f"hostile read did not actually work: {result}"
    assert canary not in result.get("stdout", "")
    assert canary not in result.get("stderr", "")
    assert not os.path.exists(scratch_dir), "scratch dir must be cleaned up even on forced kill"
    ps = subprocess.run(
        ["podman", "ps", "-a", "-q", "--filter", f"name={container_name}"],
        capture_output=True, text=True, timeout=10,
    )
    assert ps.stdout.strip() == "", "container must be removed even on forced kill"


@requires_sandbox_image
def test_legitimate_job_still_succeeds_across_the_same_lifecycle(monkeypatch):
    """Utility sibling of the two containment tests above (v3 §11
    promotion criterion: "containment high, utility approx. baseline" --
    every containment test needs one of these, or a 100%-effective
    containment control that also broke all legitimate use would trivially
    "pass"). A real, legitimate curl call through the exact same
    create->pause->resume->terminate lifecycle must still return real,
    correct output."""
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)

    jobs: dict = {}
    started = job_runtime.start_job("curl", ["-s", "https://example.com"], max_wall_seconds=30, jobs=jobs)
    job_id = started["job_id"]

    checkpoints: list = []
    final = _poll_until(job_id, jobs, checkpoints=checkpoints)

    assert final["status"] == "done"
    assert final["returncode"] == 0
    assert "Example Domain" in final["stdout"]


# ---------------------------------------------------------------------------
# Scenario 2: out-of-scope action.
# ---------------------------------------------------------------------------

def test_hook_blocks_out_of_scope_tier2_call_before_any_job_would_start(monkeypatch, tmp_path):
    """The primary containment property for this scenario: scope_gate_hook
    is a PreToolUse hook -- it runs and can refuse the call before
    job_runtime.start_job() is ever reached, so the sandboxed process never
    launches at all against an out-of-scope host."""
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "curl https://someothersite.com"}}
    assert _run_hook(monkeypatch, payload) == 2


def test_hook_allows_the_same_shaped_in_scope_call(monkeypatch, tmp_path):
    """Utility sibling: the identical call shape, in scope, must still be
    allowed -- proves the block above is a genuine scope decision, not an
    accidental blanket block on curl."""
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "curl https://realtarget-corp.com"}}
    assert _run_hook(monkeypatch, payload) == 0


@requires_sandbox_image
def test_sandbox_alone_provides_no_scope_enforcement_if_the_hook_is_bypassed(monkeypatch):
    """HONEST LIMIT, test-asserted rather than merely documented (matching
    every other acknowledged gap in this codebase): sandbox_runner.py's own
    module docstring states it provides "NO per-target network egress
    ACL" and that scope_gate_hook.py is "the sole enforcement point" for
    "may this call touch this host at all." This test proves that's true
    at the REAL job_runtime chokepoint, not just at the argv-construction
    level test_sandbox_runner.py already covers: a call that reaches
    start_job() WITHOUT first passing through the hook (simulating a
    hypothetical hook bypass/misconfiguration) still successfully reaches
    an arbitrary host. This is not a newly-found gap -- it is the
    documented S5 non-goal, verified here so nobody mistakes "sandboxed"
    for "scope-enforced" or silently assumes a second, redundant layer
    exists where none does. If this test ever starts FAILING (i.e. the
    sandboxed call stops reaching the network), that's a signal sandbox_
    runner grew network restrictions -- which would be a real, deliberate
    architecture change requiring the same explicit human decision S5's
    own "Non-goals" line already called out, not something to silently
    update this test to match."""
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)
    jobs: dict = {}
    # No engagement.yaml, no hook invocation anywhere in this test -- only
    # the sandbox chokepoint itself, deliberately.
    started = job_runtime.start_job("curl", ["-s", "-o", "/dev/null", "-w", "%{http_code}",
                                              "https://example.com"], max_wall_seconds=30, jobs=jobs)
    job_id = started["job_id"]
    checkpoints: list = []
    final = _poll_until(job_id, jobs, checkpoints=checkpoints)
    assert final["status"] == "done"
    assert final["stdout"].strip() == "200", (
        "expected the sandbox to reach the real network unrestricted -- if this "
        "assertion now fails, sandbox_runner gained network scope enforcement; "
        "see this test's own docstring before treating that as a bug fix here"
    )


def test_poll_job_takes_no_host_or_target_parameter():
    """Structural check backing the "pause/resume never re-touches scope"
    claim: poll_job()'s signature is (job_id, jobs) only -- polling an
    already-running job is a pure local status read (Popen.poll(), a
    non-blocking waitpid) with no code path that could contact a NEW host,
    in or out of scope, on a "pause" or "resume" step. The out-of-scope
    check only ever needs to fire once, at create time, via the hook --
    this is what makes that sufficient rather than a per-poll gap."""
    import inspect
    params = list(inspect.signature(job_runtime.poll_job).parameters)
    assert params == ["job_id", "jobs"]


# ---------------------------------------------------------------------------
# Scenario 3: hostile-repo checkout.
# ---------------------------------------------------------------------------

def _init_hostile_repo(tmp_path, backdoored_hook_contents: str) -> str:
    """Builds a REAL second git repository (not just a string shaped like
    a git command) containing a backdoored scope_gate_hook.py, standing in
    for a hostile fork/PR/clone an agent might be asked to pull in during
    an engagement. Returns its path."""
    hostile = tmp_path / "hostile-repo"
    hostile.mkdir()
    hooks_dir = hostile / "scripts" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "scope_gate_hook.py").write_text(backdoored_hook_contents)
    subprocess.run(["git", "init", "-q"], cwd=hostile, check=True)
    subprocess.run(["git", "config", "user.email", "hostile@example.com"], cwd=hostile, check=True)
    subprocess.run(["git", "config", "user.name", "hostile"], cwd=hostile, check=True)
    subprocess.run(["git", "add", "-A"], cwd=hostile, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "backdoored hook"], cwd=hostile, check=True)
    return str(hostile)


def test_bash_copy_of_a_hostile_repos_hook_over_the_real_one_is_blocked(monkeypatch, tmp_path):
    """The most direct "hostile-repo checkout" shape: an agent that has
    (legitimately, e.g. to review a PR, or maliciously via prompt
    injection) cloned a hostile repo now runs `cp` to bring its hook file
    into place over the real one. No confirm token on file -> blocked."""
    hostile_path = _init_hostile_repo(
        tmp_path, "# backdoored: always exit 0, disable every check\n"
    )
    command = f"cp {hostile_path}/scripts/hooks/scope_gate_hook.py scripts/hooks/scope_gate_hook.py"
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    assert _run_hook(monkeypatch, payload) == 2


def test_bash_copy_of_a_hostile_hook_is_allowed_once_a_human_confirms(monkeypatch, tmp_path):
    """Utility sibling: the escape hatch S6 deliberately provides (a real
    human running scripts/confirm-hook-edit.sh) must still work for this
    exact same call shape -- S-GATE is not supposed to make legitimate
    hook maintenance impossible, only ungated-by-a-human impossible."""
    hostile_path = _init_hostile_repo(tmp_path, "# a deliberate, human-reviewed hook change\n")
    _confirm_hook_edit(monkeypatch)
    command = f"cp {hostile_path}/scripts/hooks/scope_gate_hook.py scripts/hooks/scope_gate_hook.py"
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    assert _run_hook(monkeypatch, payload) == 0


def test_git_checkout_pathspec_from_a_real_hostile_remote_is_blocked(monkeypatch, tmp_path):
    """A more faithful "hostile-repo checkout" than a bare cp: fetches a
    REAL hostile remote into the (also real, git-init'd) working tree tmp_
    path represents, then attempts the exact git-checkout-pathspec shape
    S6's own adversarial self-review added coverage for -- restoring just
    the hook file from a hostile ref rather than the whole tree."""
    hostile_path = _init_hostile_repo(tmp_path, "# backdoored via git checkout pathspec\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "remote", "add", "hostile", hostile_path], cwd=tmp_path, check=True)
    subprocess.run(["git", "fetch", "-q", "hostile"], cwd=tmp_path, check=True)

    command = "git checkout hostile/master -- scripts/hooks/scope_gate_hook.py"
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    assert _run_hook(monkeypatch, payload) == 2


def test_edit_tool_writing_hostile_content_over_the_hook_is_blocked(monkeypatch):
    """The other real vector for "bringing hostile content in": not a
    shell copy at all, but the agent's own Edit tool being pointed at the
    protected file directly (e.g. an agent asked to "apply this patch from
    the PR" via Edit rather than a shell command)."""
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": "scripts/hooks/scope_gate_hook.py",
        "old_string": "def main() -> int:",
        "new_string": "def main() -> int:\n    return 0  # backdoored",
    }}
    assert _run_hook(monkeypatch, payload) == 2


@requires_sandbox_image
def test_sandboxed_execution_of_a_hostile_repo_has_no_mount_path_to_protected_files(tmp_path):
    """Combines S5+S6's containment guarantees from a different angle than
    the Bash/Edit tests above: even if a hostile repo's OWN code (not the
    outer agent's shell command) tried to reach out and overwrite the real
    hook from INSIDE a sandboxed run -- e.g. a malicious build script in a
    cloned repo an engagement's own tooling was pointed at -- it has no
    filesystem path back to do so. build_argv()'s mount list for a run
    whose cwd is the hostile repo's own clone contains ONLY that repo's
    scratch mount; none of the real protected paths appear anywhere in the
    produced argv, structurally, regardless of what the hostile content
    itself contains or attempts."""
    hostile_path = _init_hostile_repo(tmp_path, "# hostile build script\n")
    scratch = sandbox_runner.new_scratch_dir()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "https://example.com"], scratch,
            env={"PATH": "/usr/bin:/bin"}, cwd=hostile_path,
        )
        volume_flags = [a for a in argv if a.startswith("--volume=")]
        repo_root = sandbox_runner._REPO_ROOT
        protected_touching = [
            v for v in volume_flags
            if "scope_gate_hook" in v or "scope_guard" in v or ".claude" in v
            or v.startswith(f"--volume={repo_root}:")
        ]
        assert protected_touching == [], f"a hostile-repo run must never mount a protected path: {volume_flags}"
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


def test_sandbox_mount_validation_is_a_different_boundary_than_the_hook_protected_set(tmp_path):
    """Explicit, documentation-grade regression (not a claim that this is
    exploitable today -- audited at S5 time, no MCP-server call site ever
    passes a HuntMCP source path as an extra_mounts/cwd value): sandbox_
    runner.build_argv()'s own deny-list (_DENY_MOUNT_PREFIXES/_DENY_MOUNT_
    EXACT) protects against mounting broad SYSTEM paths or $HOME/repo-root
    WHOLESALE -- it does NOT know about, and does not reuse, scope_gate_
    hook.py's separate _PROTECTED_RELATIVE_PATHS set. A path like
    mcp-servers/scope_guard.py is therefore NOT refused by
    _validate_mount_path() the way it would be by the hook's own
    _protected_hit(). This is fine ONLY as long as it stays true that no
    call site ever passes such a path -- if a future MCP server's own code
    is changed to mount something under mcp-servers/ or scripts/hooks/
    (never an agent-facing parameter value, per _validate_mount_path()'s
    own docstring -- always this codebase's own call-site choice), that
    change needs the same scrutiny S5's own review gave every real mount
    call site, not an assumption that this deny-list would have caught it.
    This test is the canary for that: it must keep passing (i.e. this
    specific mount attempt keeps succeeding, since it's a mount VALIDATION
    test, not a call-site audit) precisely so nobody mistakes silence here
    for sandbox_runner enforcing the hook's protected-path list too."""
    target = os.path.join(sandbox_runner._REPO_ROOT, "mcp-servers", "scope_guard.py")
    scratch = sandbox_runner.new_scratch_dir()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "https://example.com"], scratch,
            env={"PATH": "/usr/bin:/bin"}, extra_mounts=[target],
        )
        assert f"--volume={target}:{target}:ro" in argv, (
            "sandbox_runner's mount validation does not consult the hook's "
            "protected-path set -- if this now raises UnsafeSandboxMount, "
            "someone unified the two deny-lists; update this test's own "
            "docstring to match, don't just delete the assertion"
        )
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch)


def test_documented_gap_bare_git_reset_hard_is_still_not_caught(monkeypatch, tmp_path):
    """S-GATE must not silently assume a gap the human explicitly decided
    to "document as accepted gap, defer" (IMPLEMENTATION-TASK-TRACKER.md
    S6 row, Vuln 5) is now closed. `git reset --hard <ref>` replaces the
    ENTIRE working tree with no per-file destination argument for
    _protected_hit() to inspect -- reproduced here against this repo's own
    real pre-S1 commit (50736b2, verified to predate every scope-gate/
    tamper-resistance file) so this stays an honest, live-verified
    regression rather than a stale claim. This must keep returning 0
    (NOT blocked) -- a change that makes it return 2 without an explicit,
    separate human-authorized task (per the tracker's own recorded
    decision and this project's Stop Conditions on "changing security
    boundaries") should be treated as scope creep on whatever task changed
    it, not quietly welcomed here."""
    payload = {"tool_name": "Bash", "tool_input": {"command": "git reset --hard 50736b2"}}
    assert _run_hook(monkeypatch, payload) == 0


# ---------------------------------------------------------------------------
# Combined: S5 AND S6 together, concurrently -- the specific bar the
# roadmap calls out as NOT met by either control individually.
# ---------------------------------------------------------------------------

@requires_sandbox_image
def test_hook_tamper_attempt_is_still_blocked_while_a_sandboxed_job_is_running(monkeypatch):
    """The flagship "S5 AND S6 together" test: while a real sandboxed job
    (S5) is actively running in the background, a SEPARATE, concurrent
    attempt to tamper with the hook (S6) must still be blocked -- proving
    the two controls compose rather than one somehow gating the other's
    availability (e.g. a naive global lock that let an in-flight scan
    starve out hook evaluation, or vice versa). This is the scenario the
    tracker's own line "S5+S6 individually do not satisfy S-GATE" is
    actually pointing at: individually-passing tests for each control
    don't prove they still both hold when exercised at the same time."""
    _no_budget(monkeypatch)
    _no_audit(monkeypatch)
    jobs: dict = {}
    started = job_runtime.start_job(
        "curl", ["-s", "--max-time", "10", "https://example.com"], max_wall_seconds=30, jobs=jobs,
    )
    job_id = started["job_id"]
    try:
        # Job is now running in its own container in the background --
        # attempt the tamper WHILE it's in flight, not before/after.
        assert job_runtime.poll_job(job_id, jobs)["status"] in ("running", "done")
        tamper_payload = {"tool_name": "Bash", "tool_input": {
            "command": "echo 'return 0' >> scripts/hooks/scope_gate_hook.py",
        }}
        assert _run_hook(monkeypatch, tamper_payload) == 2
    finally:
        # Drain the job so it doesn't leak past this test.
        _poll_until(job_id, jobs, checkpoints=[], timeout_s=30)
