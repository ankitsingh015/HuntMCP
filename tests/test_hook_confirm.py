"""S6 (Phase-S Tier-2): unit tests for mcp-servers/hook_confirm.py -- the
human-in-the-loop confirmation gate that lets a real maintenance session
edit a protected (hook-tamper-resistance) file, mirroring
tests/test_rce_confirm.py's structure and fakes for the analogous S4 module.

Unlike rce_confirm's os-shell token (single-use, target-bound), this token
is deliberately multi-use within a short TTL (~30 min) -- one human confirm
covers a bounded maintenance window on scope_gate_hook.py and its
dependencies, rather than requiring a fresh confirm before every single
protected-path write. See hook_confirm.py's own module docstring for why.
"""

import io
import json

import pytest

import hook_confirm


class _FakeTTY(io.StringIO):
    """Same fake used by test_rce_confirm.py -- reports itself as a real
    interactive terminal, the one thing an agent's own Bash/Edit tool call
    can never do."""

    def isatty(self):
        return True


@pytest.fixture
def token_path(tmp_path):
    return str(tmp_path / "hook-edit-confirm.json")


def test_request_confirmation_refuses_when_stdin_is_not_a_tty(token_path):
    stdin = io.StringIO(hook_confirm.CONFIRM_PHRASE + "\n")  # not a tty
    ok = hook_confirm.request_confirmation(stdin=stdin, stdout=io.StringIO(), path=token_path)
    assert ok is False
    assert not hook_confirm._token_exists(token_path)


def test_request_confirmation_writes_a_token_on_a_real_tty_with_matching_phrase(token_path):
    stdin = _FakeTTY(hook_confirm.CONFIRM_PHRASE + "\n")
    ok = hook_confirm.request_confirmation(stdin=stdin, stdout=io.StringIO(), path=token_path)
    assert ok is True
    with open(token_path) as f:
        token = json.load(f)
    assert "expires_at" in token


def test_request_confirmation_declines_on_mismatched_phrase(token_path):
    stdin = _FakeTTY("yes\n")
    ok = hook_confirm.request_confirmation(stdin=stdin, stdout=io.StringIO(), path=token_path)
    assert ok is False
    assert not hook_confirm._token_exists(token_path)


def test_check_valid_true_for_a_fresh_token(token_path):
    hook_confirm.request_confirmation(
        stdin=_FakeTTY(hook_confirm.CONFIRM_PHRASE + "\n"), stdout=io.StringIO(), path=token_path
    )
    assert hook_confirm.check_valid(path=token_path) is True


def test_check_valid_is_multi_use_not_consumed(token_path):
    """Core behavioral difference from rce_confirm's single-use token: one
    human confirm must authorize MULTIPLE protected-path writes within the
    TTL window, not just one -- otherwise every single Edit call during a
    real maintenance session would need its own fresh human confirm."""
    hook_confirm.request_confirmation(
        stdin=_FakeTTY(hook_confirm.CONFIRM_PHRASE + "\n"), stdout=io.StringIO(), path=token_path
    )
    assert hook_confirm.check_valid(path=token_path) is True
    assert hook_confirm.check_valid(path=token_path) is True
    assert hook_confirm.check_valid(path=token_path) is True


def test_check_valid_false_with_no_token_file(token_path):
    assert hook_confirm.check_valid(path=token_path) is False


def test_check_valid_false_once_expired(token_path):
    hook_confirm.request_confirmation(
        ttl_seconds=-1,  # already expired the instant it's written
        stdin=_FakeTTY(hook_confirm.CONFIRM_PHRASE + "\n"),
        stdout=io.StringIO(),
        path=token_path,
    )
    assert hook_confirm.check_valid(path=token_path) is False


def test_check_valid_false_on_malformed_token_file(token_path):
    with open(token_path, "w") as f:
        f.write("not valid json{{{")
    assert hook_confirm.check_valid(path=token_path) is False


def test_request_confirmation_creates_parent_directory(tmp_path):
    token_path = str(tmp_path / "nested" / "dir" / "hook-edit-confirm.json")
    ok = hook_confirm.request_confirmation(
        stdin=_FakeTTY(hook_confirm.CONFIRM_PHRASE + "\n"), stdout=io.StringIO(), path=token_path
    )
    assert ok is True
    assert hook_confirm._token_exists(token_path)


def test_token_path_not_engagement_scoped(monkeypatch, tmp_path):
    """Regression guard for a real design mistake caught during S6 planning:
    hook tamper-resistance is a repo/toolchain concern, not per-target hunt
    state -- unlike budget.json/os-shell-confirm.json, this token must NOT
    live under data/engagements/<active-slug>/, or pausing one engagement
    to work on another would silently relocate/invalidate a maintenance
    confirm that has nothing to do with either target."""
    import engagement_paths

    pointer = tmp_path / ".active-engagement"
    pointer.write_text("some-target-slug")
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(pointer))
    monkeypatch.delenv("HUNTMCP_HOOK_CONFIRM_PATH", raising=False)

    path = hook_confirm._token_path()
    assert "engagements" not in path
    assert "some-target-slug" not in path


def test_token_path_honors_env_override(monkeypatch):
    monkeypatch.setenv("HUNTMCP_HOOK_CONFIRM_PATH", "/tmp/custom-hook-confirm.json")
    assert hook_confirm._token_path() == "/tmp/custom-hook-confirm.json"
