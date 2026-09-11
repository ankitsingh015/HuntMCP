"""Tests for the session adapter (scripts/runner/session.py).

The real adapter shells out to `claude -p ... --output-format json` (each call is
a fresh process = a fresh session). These tests never invoke real Claude: argv
construction is asserted directly, and `run_session` is exercised with an injected
fake command runner that returns canned Claude JSON.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import session  # noqa: E402


def test_build_argv_uses_documented_headless_flags():
    ad = session.ClaudeCliSessionAdapter(claude_bin="claude")
    argv = ad.build_argv(prompt="do task C6", repo="/repo")
    assert argv[0] == "claude"
    assert "-p" in argv
    assert "do task C6" in argv
    assert "--output-format" in argv and "json" in argv
    # the repo is exposed to the session
    assert "--add-dir" in argv and "/repo" in argv


def test_build_argv_never_bypasses_permissions_by_default():
    ad = session.ClaudeCliSessionAdapter()
    argv = ad.build_argv(prompt="p", repo="/repo")
    assert "--dangerously-skip-permissions" not in argv
    assert "--allow-dangerously-skip-permissions" not in argv


def test_build_argv_includes_optional_model_and_permission_mode():
    ad = session.ClaudeCliSessionAdapter(model="claude-opus-5", permission_mode="plan")
    argv = ad.build_argv(prompt="p", repo="/repo", session_id="abc-123")
    assert "--model" in argv and "claude-opus-5" in argv
    assert "--permission-mode" in argv and "plan" in argv
    assert "--session-id" in argv and "abc-123" in argv


def test_build_argv_includes_effort_when_set():
    ad = session.ClaudeCliSessionAdapter(model="sonnet", effort="high")
    argv = ad.build_argv(prompt="p", repo="/repo")
    assert "--effort" in argv
    assert argv[argv.index("--effort") + 1] == "high"


def test_build_argv_omits_effort_when_unset():
    ad = session.ClaudeCliSessionAdapter()
    assert "--effort" not in ad.build_argv(prompt="p", repo="/repo")


def test_exact_argv_for_sonnet_high():
    # The precise command the autopilot will run per session (minus the prompt body).
    ad = session.ClaudeCliSessionAdapter(model="sonnet", effort="high")
    argv = ad.build_argv(prompt="do C6", repo="/repo")
    assert argv == [
        "claude", "-p", "do C6",
        "--output-format", "json",
        "--add-dir", "/repo",
        "--model", "sonnet",
        "--effort", "high",
    ]


def test_high_is_a_valid_effort_level():
    assert "high" in session.EFFORT_LEVELS


def test_child_env_carries_recursion_guard():
    ad = session.ClaudeCliSessionAdapter()
    env = ad.build_env({"PATH": "/bin"})
    assert env[session.RECURSION_GUARD_ENV] == "1"
    assert env["PATH"] == "/bin"  # base env preserved


def test_run_session_parses_success_json():
    captured = {}

    def fake_run(argv, cwd=None, env=None, timeout=None):
        captured["argv"] = argv
        captured["cwd"] = cwd
        captured["env"] = env
        payload = json.dumps(
            {"type": "result", "subtype": "success", "is_error": False,
             "session_id": "sess-1", "result": "done C6", "num_turns": 4}
        )
        return 0, payload, ""

    ad = session.ClaudeCliSessionAdapter(run=fake_run)
    res = ad.run_session(prompt="do C6", repo="/repo")
    assert res.session_id == "sess-1"
    assert res.is_error is False
    assert res.exit_reason == "completed"
    assert res.exit_code == 0
    assert captured["cwd"] == "/repo"
    assert captured["env"][session.RECURSION_GUARD_ENV] == "1"


def test_run_session_maps_max_turns_to_limit_reason():
    def fake_run(argv, cwd=None, env=None, timeout=None):
        payload = json.dumps(
            {"type": "result", "subtype": "error_max_turns", "is_error": True,
             "session_id": "sess-2", "result": ""}
        )
        return 0, payload, ""

    ad = session.ClaudeCliSessionAdapter(run=fake_run)
    res = ad.run_session(prompt="p", repo="/repo")
    assert res.is_error is True
    assert res.exit_reason == "limit"          # a context/turn-limit style exit
    assert res.session_id == "sess-2"


def test_run_session_handles_nonzero_exit_without_json():
    def fake_run(argv, cwd=None, env=None, timeout=None):
        return 1, "boom", "traceback"

    ad = session.ClaudeCliSessionAdapter(run=fake_run)
    res = ad.run_session(prompt="p", repo="/repo")
    assert res.exit_code == 1
    assert res.exit_reason == "process_error"
    assert res.is_error is True


# --- interactive adapter (primary mode: a real interactive `claude`, no -p) ---

def test_interactive_build_argv_is_not_headless():
    ad = session.InteractiveClaudeSessionAdapter(model="sonnet", effort="high")
    argv = ad.build_argv(prompt="seed", repo="/repo", session_id="11111111-1111-1111-1111-111111111111")
    # interactive = default mode -> NO -p, NO --output-format
    assert "-p" not in argv
    assert "--print" not in argv
    assert "--output-format" not in argv


def test_interactive_exact_argv_for_sonnet_high():
    ad = session.InteractiveClaudeSessionAdapter(model="sonnet", effort="high")
    argv = ad.build_argv(prompt="do C6", repo="/repo", session_id="abc")
    assert argv == [
        "claude",
        "--model", "sonnet",
        "--effort", "high",
        "--add-dir", "/repo",
        "--session-id", "abc",
        "do C6",                # seed prompt is the trailing positional
    ]


def test_interactive_never_bypasses_permissions():
    ad = session.InteractiveClaudeSessionAdapter(model="sonnet", effort="high")
    argv = ad.build_argv(prompt="p", repo="/repo", session_id="s")
    assert "--dangerously-skip-permissions" not in argv
    assert "--allow-dangerously-skip-permissions" not in argv


def test_interactive_run_session_assigns_uuid_and_maps_exit_code():
    seen = {}

    def fake_run(argv, cwd=None, env=None, timeout=None):
        seen["argv"] = argv
        seen["cwd"] = cwd
        seen["env"] = env
        return 0  # interactive runner returns an exit code, not (rc, out, err)

    ad = session.InteractiveClaudeSessionAdapter(run=fake_run)
    res = ad.run_session(prompt="p", repo="/repo")
    assert res.exit_code == 0
    assert res.exit_reason == "session_ended"
    assert res.is_error is False
    assert res.session_id  # a uuid was assigned and reported
    # the assigned id is threaded into the argv
    assert res.session_id in seen["argv"]
    assert seen["env"][session.RECURSION_GUARD_ENV] == "1"


def test_interactive_run_session_maps_nonzero_exit():
    ad = session.InteractiveClaudeSessionAdapter(run=lambda *a, **k: 1)
    res = ad.run_session(prompt="p", repo="/repo")
    assert res.exit_code == 1
    assert res.is_error is True
    assert res.exit_reason == "process_error"


def test_interactive_default_runner_inherits_stdio_and_returns_rc(tmp_path):
    # Prove the default (real) runner runs a child inheriting stdio and returns
    # its exit code -- using harmless /bin/true and /bin/false, never claude.
    ad = session.InteractiveClaudeSessionAdapter()
    assert ad._run(["true"], cwd=str(tmp_path), env=dict(os.environ)) == 0
    assert ad._run(["false"], cwd=str(tmp_path), env=dict(os.environ)) == 1


def test_run_session_never_logs_secrets_in_output_tail():
    # The adapter stores a bounded output tail; ensure it does not capture env.
    def fake_run(argv, cwd=None, env=None, timeout=None):
        return 0, json.dumps({"subtype": "success", "is_error": False, "session_id": "s", "result": "ok"}), ""

    ad = session.ClaudeCliSessionAdapter(run=fake_run)
    res = ad.run_session(prompt="p", repo="/repo")
    assert "ANTHROPIC_API_KEY" not in res.output_tail
