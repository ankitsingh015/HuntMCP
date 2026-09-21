import importlib.util
import os
import re
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "nuclei-mcp"))
import sandbox_runner  # noqa: E402
import templates_pin  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "nuclei_mcp_server", os.path.join(ROOT, "mcp-servers", "nuclei-mcp", "server.py")
)
nuclei_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nuclei_server)


FOUND_OUTPUT = (
    '{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium"},'
    '"matched-at":"https://target.com/admin","type":"http"}\n'
)

# Extracts the job_id _start() actually put in a scan_target()/
# scan_with_templates() success message -- used by tests below that must
# prove check_scan() is being fed the REAL id start_job() returned, not a
# hardcoded string that would still "pass" even if scan_target() never
# reached start_job() at all (see test_check_scan_surfaces_waf_block's own
# comment for the regression this closes).
_JOB_ID_RE = re.compile(r'job_id="([^"]+)"')


def test_format_findings_uses_the_no_findings_message_verbatim():
    out = nuclei_server._format_findings("target.com", "custom no-findings text", "", 0, "")
    assert out == "custom no-findings text"


def test_format_findings_surfaces_hard_failure_with_no_stdout():
    out = nuclei_server._format_findings("target.com", "no findings", "", 1, "connection timed out")
    assert "nuclei failed" in out
    assert "connection timed out" in out


def test_format_findings_lists_matches():
    out = nuclei_server._format_findings("target.com", "no findings", FOUND_OUTPUT, 0, "")
    assert "MEDIUM" in out
    assert "Exposed Admin Panel" in out
    assert "target.com" in out


def test_scan_target_then_check_scan_round_trip(monkeypatch):
    # These three tests verify pure argument/message-construction logic
    # via a monkeypatched start_job -- they must not depend on whether
    # scripts/fetch-nuclei-templates.sh has actually been run on this
    # machine, the same portability gap _capture_start_job_args() itself
    # was fixed for (see its own docstring).
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-nuc", "status": "running", "tool": "nuclei"},
    )
    start_msg = nuclei_server.scan_target("target.com")
    assert "job-nuc" in start_msg

    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": FOUND_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nuclei_server.check_scan("job-nuc")
    assert "Exposed Admin Panel" in out


def test_scan_with_templates_no_findings_wording_differs_from_scan_target(monkeypatch):
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-tmpl", "status": "running", "tool": "nuclei"},
    )
    nuclei_server.scan_with_templates("target.com", "http/cves/2021")

    monkeypatch.setattr(
        nuclei_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": "", "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = nuclei_server.check_scan("job-tmpl")
    assert out == "No vulnerabilities found with the specified templates."


def test_check_scan_surfaces_waf_block(monkeypatch):
    """Regression test (code review, 2026-09-18): this test used to
    monkeypatch poll_job unconditionally -- ANY job_id string got the same
    canned WAF response back, so it kept "passing" even on a fresh clone
    where templates_pin.templates_available() is False and scan_target()
    returns the missing-snapshot error WITHOUT ever calling start_job(),
    silently testing nothing about scan_target() at all. Fixed by: (1)
    recording whether start_job() was actually called, (2) extracting the
    REAL job_id from scan_target()'s own return message rather than
    hardcoding one, and (3) recording which job_id poll_job() was actually
    asked about -- so this test can only pass by genuinely exercising
    scan_target() -> start_job() -> check_scan() -> poll_job() in order."""
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    start_calls = []

    def _fake_start_job(tool, args, timeout, jobs, **kwargs):
        start_calls.append((tool, args, kwargs))
        return {"job_id": "job-waf", "status": "running", "tool": tool}

    monkeypatch.setattr(nuclei_server.job_runtime, "start_job", _fake_start_job)
    start_msg = nuclei_server.scan_target("target.com")
    assert start_calls, "scan_target() must actually reach job_runtime.start_job()"
    job_id = _JOB_ID_RE.search(start_msg).group(1)

    poll_calls = []

    def _fake_poll_job(polled_job_id, jobs):
        poll_calls.append(polled_job_id)
        return {
            "status": "done", "job_id": polled_job_id, "returncode": 0,
            "stdout": "", "stderr": "403 Forbidden - request blocked by Cloudflare",
            "elapsed_s": 3.0, "block": "waf",
        }

    monkeypatch.setattr(nuclei_server.job_runtime, "poll_job", _fake_poll_job)
    out = nuclei_server.check_scan(job_id)
    assert poll_calls == [job_id]
    assert "WAF" in out
    assert "BLOCK DETECTED" in out


def test_scan_target_builds_args_with_jsonl_not_json(monkeypatch):
    """Regression test: nuclei v3 removed the old `-json` flag entirely
    (only `-jsonl` remains), which made every real scan_target()/
    scan_with_templates() call fail immediately with "flag provided but
    not defined: -json" -- reported live in a real engagement retrospective
    as the primary scan capability being completely dead. _format_findings
    already parses line-delimited JSON, so the fix is the flag name, not
    the parser."""
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    captured = {}

    def _fake_start_job(tool, args, timeout, jobs, **kwargs):
        captured["args"] = args
        return {"job_id": "job-flags", "status": "running", "tool": tool}

    monkeypatch.setattr(nuclei_server.job_runtime, "start_job", _fake_start_job)
    nuclei_server.scan_target("target.com")
    assert "-jsonl" in captured["args"]
    assert "-json" not in captured["args"]

    nuclei_server.scan_with_templates("target.com", "http/cves/2021")
    assert "-jsonl" in captured["args"]
    assert "-json" not in captured["args"]


def test_scan_target_flags_are_accepted_by_the_installed_nuclei_binary():
    """Live compatibility check (skipped if nuclei isn't installed): builds
    the same args scan_target() sends and runs them against a closed local
    port, so nuclei fails on connection refused rather than touching any
    real target -- but a flag-parsing failure ("flag provided but not
    defined") is caught immediately, which is exactly how the `-json`
    bug surfaced in practice."""
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return
    args = [nuclei_path, "-u", "http://127.0.0.1:1", "-severity", "medium,high,critical", "-silent", "-jsonl"]
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert "flag provided but not defined" not in result.stderr


def test_check_scan_timeout_status_returns_error_and_cleans_up(monkeypatch):
    """Same regression fix as test_check_scan_surfaces_waf_block above:
    poll_job used to be mocked unconditionally, so this test kept passing
    even if scan_target() never reached start_job() on a fresh clone --
    fixed the same way, by proving start_job() was really called and by
    driving check_scan() with the job_id scan_target() actually returned."""
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    start_calls = []

    def _fake_start_job(tool, args, timeout, jobs, **kwargs):
        start_calls.append((tool, args, kwargs))
        return {"job_id": "job-to", "status": "running", "tool": tool}

    monkeypatch.setattr(nuclei_server.job_runtime, "start_job", _fake_start_job)
    start_msg = nuclei_server.scan_target("target.com")
    assert start_calls, "scan_target() must actually reach job_runtime.start_job()"
    job_id = _JOB_ID_RE.search(start_msg).group(1)

    poll_calls = []

    def _fake_poll_job(polled_job_id, jobs):
        poll_calls.append(polled_job_id)
        return {
            "status": "timeout", "job_id": polled_job_id,
            "error": "nuclei timed out after 300s and was killed -- partial output below, if any",
            "stdout": "", "stderr": "", "elapsed_s": 300.0,
        }

    monkeypatch.setattr(nuclei_server.job_runtime, "poll_job", _fake_poll_job)
    out = nuclei_server.check_scan(job_id)
    assert poll_calls == [job_id]
    assert "timed out" in out
    assert job_id not in nuclei_server._targets


# ---------------------------------------------------------------------------
# Pinned nuclei-templates snapshot (S5 follow-up): CONTAINER_HOME=/tmp fixed
# subfinder/katana/ffuf/nuclei all being unable to write their startup
# config dirs, but left nuclei's REAL scans still broken -- nuclei's own
# template auto-download fills the 64MB /tmp tmpfs and dies with "no space
# left on device" (confirmed live against https://example.com, see
# templates_pin.py's own module docstring for the full incident). These
# tests verify the fix: a host-side pinned snapshot mounted read-only at a
# non-$HOME path via the existing extra_mounts= mechanism, with automatic
# template updates disabled.
# ---------------------------------------------------------------------------

def _capture_start_job_args(monkeypatch):
    """Shared helper for every argument-construction test below. These
    tests verify pure Python logic (flag/mount/path-resolution building),
    not real template content, so they must not depend on whether
    scripts/fetch-nuclei-templates.sh has actually been run on this
    machine -- adversarial review caught an earlier version of this
    helper NOT doing this: _start()'s templates_pin.templates_available()
    gate returns False on a fresh clone/CI (no fetch step), short-circuits
    before the monkeypatched start_job is ever called, and every test
    using this helper then failed with KeyError on captured["args"] for a
    reason entirely unrelated to the logic under test."""
    monkeypatch.setattr(templates_pin, "templates_available", lambda: True)
    captured = {}

    def _fake_start_job(tool, args, timeout, jobs, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"job_id": "job-tmpl-pin", "status": "running", "tool": tool}

    monkeypatch.setattr(nuclei_server.job_runtime, "start_job", _fake_start_job)
    return captured


def test_scan_target_disables_automatic_update_check(monkeypatch):
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_target("target.com")
    assert "-duc" in captured["args"]


def test_scan_target_points_at_the_pinned_templates_dir_for_a_full_sweep(monkeypatch):
    """Without an explicit -t, nuclei falls back to ITS OWN default
    template directory -- which is now empty (auto-update is disabled) --
    so a full-sweep scan_target() call must explicitly point at the
    pinned snapshot to have anything to run at all."""
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_target("target.com")
    args = captured["args"]
    assert "-t" in args
    assert args[args.index("-t") + 1] == templates_pin.TEMPLATES_DIR


def test_scan_target_mounts_the_pinned_templates_dir_read_only(monkeypatch):
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_target("target.com")
    assert captured["kwargs"].get("extra_mounts") == [templates_pin.TEMPLATES_DIR]
    # Read-only is the only mode start_job()/build_argv() offer via
    # extra_mounts= (extra_mounts_rw= is the separate, deliberate opt-in
    # for write access) -- a real scan never needs to write into its own
    # template set, so this must never be extra_mounts_rw=.
    assert captured["kwargs"].get("extra_mounts_rw") in (None, [])


def test_scan_with_templates_disables_automatic_update_check(monkeypatch):
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_with_templates("target.com", "http/exposed-panels")
    assert "-duc" in captured["args"]


def test_scan_with_templates_mounts_the_pinned_templates_dir_read_only(monkeypatch):
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_with_templates("target.com", "http/exposed-panels")
    assert captured["kwargs"].get("extra_mounts") == [templates_pin.TEMPLATES_DIR]


def test_scan_with_templates_resolves_a_relative_path_against_the_pinned_dir(monkeypatch):
    """`templates="http/exposed-panels"` (nuclei's own real layout at the
    pinned commit) must resolve against TEMPLATES_DIR -- nuclei's own
    default template directory is no longer populated (auto-update is
    disabled), so passing the relative value straight through to -t would
    silently fail to find it."""
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_with_templates("target.com", "http/exposed-panels")
    args = captured["args"]
    resolved = args[args.index("-t") + 1]
    assert resolved == os.path.join(templates_pin.TEMPLATES_DIR, "http/exposed-panels")


def test_scan_with_templates_resolves_each_entry_of_a_comma_separated_list(monkeypatch):
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_with_templates("target.com", "http/exposed-panels,http/cves/2021")
    args = captured["args"]
    resolved = args[args.index("-t") + 1]
    assert resolved == ",".join([
        os.path.join(templates_pin.TEMPLATES_DIR, "http/exposed-panels"),
        os.path.join(templates_pin.TEMPLATES_DIR, "http/cves/2021"),
    ])


def test_scan_with_templates_trailing_comma_does_not_expand_to_the_full_library(monkeypatch):
    """CONFIRMED finding #1: a trailing comma used to split into
    ["http/exposed-panels", ""], and os.path.join(TEMPLATES_DIR, "")
    resolves to TEMPLATES_DIR itself -- silently adding the ENTIRE pinned
    template library as a second -t entry. The empty entry must be
    dropped, never resolved to the template root."""
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_with_templates("target.com", "http/exposed-panels,")
    args = captured["args"]
    resolved = args[args.index("-t") + 1]
    assert resolved == os.path.join(templates_pin.TEMPLATES_DIR, "http/exposed-panels")
    # The specific bug: the bare template root must never appear as its
    # own resolved entry -- that's what "silently scans everything" means.
    assert templates_pin.TEMPLATES_DIR not in resolved.split(",")


def test_scan_with_templates_strips_whitespace_around_comma_separated_entries(monkeypatch):
    """CONFIRMED finding #4: "a, b" (a space after the comma -- the
    natural way to write a list) must resolve identically to "a,b". Before
    the fix, the un-stripped leading space was joined onto TEMPLATES_DIR
    verbatim, producing a path with an embedded space that doesn't exist
    on disk."""
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_with_templates("target.com", "http/exposed-panels, http/cves/2021")
    args = captured["args"]
    resolved = args[args.index("-t") + 1]
    assert resolved == ",".join([
        os.path.join(templates_pin.TEMPLATES_DIR, "http/exposed-panels"),
        os.path.join(templates_pin.TEMPLATES_DIR, "http/cves/2021"),
    ])


def test_scan_with_templates_rejects_an_all_empty_templates_argument(monkeypatch):
    """A templates argument that resolves to nothing at all (e.g. "" or a
    bare ",") must fail closed with a clear error before start_job() is
    ever called -- not silently produce an empty or malformed -t value."""
    called = {"start_job": False}
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: called.__setitem__("start_job", True),
    )
    out = nuclei_server.scan_with_templates("target.com", " , ")
    assert "Error" in out
    assert called["start_job"] is False


def test_scan_with_templates_accepts_an_absolute_path_inside_the_pinned_root(monkeypatch):
    """CONFIRMED-finding-#3 fix: an absolute path is only ever usable if it
    resolves inside the pinned, mounted TEMPLATES_DIR -- _start() only ever
    mounts TEMPLATES_DIR into the sandbox (never an arbitrary caller path),
    so an absolute path outside it could never actually be found by nuclei
    even though the old docstring claimed it worked. A path that already
    resolves inside the approved root is accepted -- passed through
    unmodified (realpath'd), not re-joined."""
    custom = os.path.join(templates_pin.TEMPLATES_DIR, "http", "exposed-panels")
    captured = _capture_start_job_args(monkeypatch)
    nuclei_server.scan_with_templates("target.com", custom)
    args = captured["args"]
    assert args[args.index("-t") + 1] == os.path.realpath(custom)


def test_scan_with_templates_rejects_an_absolute_path_outside_the_pinned_root(monkeypatch, tmp_path):
    """CONFIRMED-finding-#3 fix: an absolute path OUTSIDE the pinned,
    mounted template root must be rejected with a clear error rather than
    silently building a -t argument nuclei can never find inside the
    read-only sandbox (only TEMPLATES_DIR is ever mounted). Must fail
    closed BEFORE start_job() is called -- no budget/audit charge for a
    scan that can't run."""
    outside = str(tmp_path / "my-own-template.yaml")
    called = {"start_job": False}
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: called.__setitem__("start_job", True),
    )
    out = nuclei_server.scan_with_templates("target.com", outside)
    assert "Error" in out
    assert templates_pin.TEMPLATES_DIR in out
    assert called["start_job"] is False


def test_scan_with_templates_rejects_a_relative_path_that_traverses_outside_the_root(monkeypatch):
    """Adversarial-review finding on the finding-#3 fix: the containment
    check must apply symmetrically to relative entries too, not just
    absolute ones -- os.path.join(TEMPLATES_DIR, entry) does NOT collapse
    ".." components, so a relative entry like "../../../../etc/passwd"
    previously skipped the containment check entirely (it took the
    early "not absolute" branch) and was handed straight to nuclei as
    part of the sandboxed -t argument, silently defeating the whole
    "only the approved template root" guarantee for the one input class
    (leading "../" instead of a leading "/") the absolute-path check
    doesn't see. Must fail closed BEFORE start_job() is called."""
    called = {"start_job": False}
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: called.__setitem__("start_job", True),
    )
    out = nuclei_server.scan_with_templates("target.com", "../../../../etc/passwd")
    assert "Error" in out
    assert templates_pin.TEMPLATES_DIR in out
    assert called["start_job"] is False


def test_scan_target_fails_closed_when_templates_snapshot_is_missing(monkeypatch):
    """Must never silently let nuclei fall through to its own network
    auto-download -- that's the exact failure this fix replaces. A
    missing snapshot is a clear, actionable error, and start_job() must
    never be called (no budget/audit call for a scan that can't run)."""
    monkeypatch.setattr(templates_pin, "templates_available", lambda: False)
    called = {"start_job": False}
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: called.__setitem__("start_job", True),
    )
    out = nuclei_server.scan_target("target.com")
    assert "fetch-nuclei-templates.sh" in out
    assert called["start_job"] is False


def test_scan_with_templates_fails_closed_when_templates_snapshot_is_missing(monkeypatch):
    monkeypatch.setattr(templates_pin, "templates_available", lambda: False)
    called = {"start_job": False}
    monkeypatch.setattr(
        nuclei_server.job_runtime, "start_job",
        lambda *a, **k: called.__setitem__("start_job", True),
    )
    out = nuclei_server.scan_with_templates("target.com", "http/exposed-panels")
    assert "fetch-nuclei-templates.sh" in out
    assert called["start_job"] is False


_AGENTS_DIR = os.path.join(ROOT, ".opencode", "agents")
# Grabs the whole argument list first, then pulls the templates value out
# of it -- NOT a single regex requiring a literal `"` right after the
# first comma. Adversarial review caught that a stricter, double-quote-
# only, positional-only version silently produced zero matches (not a
# loud failure) for `scan_with_templates(url, 'http/exposures/')`
# (single quotes) or `scan_with_templates(url, templates="...")` (kwarg
# form) -- exactly the shape a future doc edit could plausibly use,
# reintroducing CONFIRMED finding #2's bug class with no test to catch
# it. `[^)]*` (not `.*?`) also matches embedded newlines, so a call
# wrapped across lines is still found.
_SCAN_WITH_TEMPLATES_CALL_RE = re.compile(r'scan_with_templates\(([^)]*)\)')
_TEMPLATES_KWARG_RE = re.compile(r'templates\s*=\s*[\'"]([^\'"]+)[\'"]')
_QUOTED_LITERAL_RE = re.compile(r'[\'"]([^\'"]+)[\'"]')


def _scan_with_templates_literal_paths():
    calls = []
    for fname in sorted(os.listdir(_AGENTS_DIR)):
        if not fname.endswith(".md"):
            continue
        with open(os.path.join(_AGENTS_DIR, fname)) as f:
            text = f.read()
        for call in _SCAN_WITH_TEMPLATES_CALL_RE.finditer(text):
            call_args = call.group(1)
            kwarg = _TEMPLATES_KWARG_RE.search(call_args)
            if kwarg:
                calls.append((fname, kwarg.group(1)))
                continue
            # Positional form: `target` is normally an unquoted variable
            # (e.g. `url`), so the templates value is whichever quoted
            # literal appears -- the last one, if `target` also happens
            # to be a quoted literal in some future doc example.
            quoted = _QUOTED_LITERAL_RE.findall(call_args)
            if quoted:
                calls.append((fname, quoted[-1]))
    return calls


def test_agent_docs_scan_with_templates_calls_match_the_pinned_template_layout():
    """CONFIRMED finding #2: scan-agent.md's --deep mode called
    scan_with_templates(url, "exposures/") -- a flat path that doesn't
    exist under the pinned snapshot's real, protocol-nested layout (the
    real directory is http/exposures/). Every literal, relative
    template-path argument used in agent docs must resolve to a real
    file/directory in the actual pinned snapshot on disk -- checked
    against the real snapshot, NOT a whitelist of "known" top-level dirs
    (an earlier version of this test used templates_pin._EXPECTED_SUBDIRS,
    a deliberately non-exhaustive sanity-check subset, as if it were a
    complete list -- that would have falsely failed a perfectly valid doc
    reference to any real category outside that subset, e.g. "file/" or
    "workflows/"). Skipped if the snapshot hasn't been fetched on this
    machine, same as the other pinned-snapshot tests below -- there's no
    layout to check a doc reference against without it."""
    calls = _scan_with_templates_literal_paths()
    assert calls, "expected at least one scan_with_templates(...) call in .opencode/agents/*.md"
    if not templates_pin.templates_available():
        pytest.skip("nuclei-templates snapshot not fetched -- run scripts/fetch-nuclei-templates.sh")
    for fname, literal in calls:
        for entry in literal.split(","):
            entry = entry.strip()
            if os.path.isabs(entry):
                continue
            resolved = os.path.join(templates_pin.TEMPLATES_DIR, entry.rstrip("/"))
            assert os.path.isdir(resolved) or os.path.isfile(resolved), (
                f"{fname}: scan_with_templates(..., {literal!r}) resolves to "
                f"{resolved!r}, which doesn't exist in the pinned snapshot -- likely "
                "stale after a template-layout change."
            )


def _podman_and_image_available() -> bool:
    if not shutil.which("podman"):
        return False
    result = subprocess.run(
        ["podman", "image", "exists", sandbox_runner.SANDBOX_IMAGE],
        capture_output=True, timeout=10,
    )
    return result.returncode == 0


requires_sandbox_and_templates = pytest.mark.skipif(
    not (_podman_and_image_available() and templates_pin.templates_available()),
    reason="podman/huntmcp-sandbox image not available, or templates snapshot not fetched",
)


@requires_sandbox_and_templates
def test_live_real_nuclei_scan_via_the_sandbox_loads_pinned_templates_without_enospc():
    """The actual regression this whole fix exists for: a REAL nuclei
    invocation (not -version) through the real sandbox, using exactly the
    args/mounts scan_target() builds, against a closed local port so it
    fails on connection-refused rather than touching any real target.
    Before this fix this died with "no space left on device" before ever
    reaching the target."""
    args = ["-u", "http://127.0.0.1:1", "-severity", "medium,high,critical",
            "-silent", "-jsonl", "-duc", "-t", templates_pin.TEMPLATES_DIR]
    scratch = sandbox_runner.new_scratch_dir()
    name = sandbox_runner.new_container_name()
    try:
        argv = sandbox_runner.build_argv(
            "nuclei", args, scratch, env={"PATH": "/usr/bin:/bin"},
            extra_mounts=[templates_pin.TEMPLATES_DIR], container_name=name,
        )
        result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        combined = result.stdout + result.stderr
        assert "no space left on device" not in combined
        assert "Could not create runner" not in combined
    finally:
        sandbox_runner.remove_container(name)
        sandbox_runner.cleanup_scratch_dir(scratch)


@requires_sandbox_and_templates
def test_live_pinned_templates_mount_is_genuinely_read_only():
    """Same class of regression test as
    test_sandbox_runner.py::test_live_extra_mounts_read_only_actually_prevents_writes
    -- a real scan must never be able to modify the pinned snapshot at the
    kernel/mount level, not merely by convention."""
    sample = os.path.join(templates_pin.TEMPLATES_DIR, "http", "exposed-panels")
    scratch = sandbox_runner.new_scratch_dir()
    name = sandbox_runner.new_container_name()
    try:
        argv = sandbox_runner.build_argv(
            "curl", ["-s", "-o", os.path.join(sample, "write-attempt.txt"), "https://example.com"],
            scratch, env={"PATH": "/usr/bin:/bin"},
            extra_mounts=[templates_pin.TEMPLATES_DIR], container_name=name,
        )
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        assert result.returncode != 0  # curl's own write-error exit code
        assert not os.path.exists(os.path.join(sample, "write-attempt.txt"))
    finally:
        sandbox_runner.remove_container(name)
        sandbox_runner.cleanup_scratch_dir(scratch)


@requires_sandbox_and_templates
def test_live_real_scan_does_not_modify_pinned_templates_host_state():
    """git state of the pinned checkout (the definitive record of exactly
    what a scan ran against) must be byte-identical before and after a
    real sandboxed scan -- proves both the read-only mount holds AND that
    nuclei made no local modification (e.g. a template-update rewrite)."""
    before_sha = subprocess.run(
        ["git", "-C", templates_pin.TEMPLATES_DIR, "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    before_status = subprocess.run(
        ["git", "-C", templates_pin.TEMPLATES_DIR, "status", "--porcelain"],
        capture_output=True, text=True, timeout=10,
    ).stdout

    args = ["-u", "http://127.0.0.1:1", "-severity", "medium,high,critical",
            "-silent", "-jsonl", "-duc", "-t", templates_pin.TEMPLATES_DIR]
    scratch = sandbox_runner.new_scratch_dir()
    name = sandbox_runner.new_container_name()
    try:
        argv = sandbox_runner.build_argv(
            "nuclei", args, scratch, env={"PATH": "/usr/bin:/bin"},
            extra_mounts=[templates_pin.TEMPLATES_DIR], container_name=name,
        )
        subprocess.run(argv, capture_output=True, text=True, timeout=60)
    finally:
        sandbox_runner.remove_container(name)
        sandbox_runner.cleanup_scratch_dir(scratch)

    after_sha = subprocess.run(
        ["git", "-C", templates_pin.TEMPLATES_DIR, "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    after_status = subprocess.run(
        ["git", "-C", templates_pin.TEMPLATES_DIR, "status", "--porcelain"],
        capture_output=True, text=True, timeout=10,
    ).stdout
    assert after_sha == before_sha
    assert after_status == before_status == ""
