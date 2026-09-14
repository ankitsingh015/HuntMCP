"""S2 -- real PreToolUse dispatch verification.

Every other test in test_scope_gate_hook.py exercises scope_gate_hook.py by
importing it as a module and calling hook.main() in-process. That proves
the gate LOGIC is correct, but it can't catch the failure mode S2 exists
for: the hook registration itself going missing or broken (e.g. someone
edits .claude/settings.json and drops the PreToolUse entry, or the command
path drifts) while the Python logic underneath stays perfectly correct and
every in-process unit test keeps passing. This file drives the ACTUAL
dispatch contract instead:

1. Confirms .claude/settings.json really does register scope_gate_hook.py
   as a PreToolUse hook (catches a missing/broken registration directly).
2. Spawns `python3 scripts/hooks/scope_gate_hook.py` as a real subprocess,
   feeding it the exact stdin JSON / reading the exact exit code Claude
   Code's own PreToolUse dispatch uses (see the hook's own module
   docstring) -- not a mocked or imported call.

.opencode/plugin/scope-gate.ts is OpenCode's port of the same dispatch
contract; tests/test_scope_gate_plugin.mjs already drives IT end-to-end via
a real python3 subprocess (only Bun.spawn's transport is shimmed, not the
hook's logic) -- see that file's own header comment. Both are wired into
CI (see .github/workflows/ci.yml's scope-gate-dispatch job) so a broken
hook registration on either harness turns CI red.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK_SCRIPT = REPO_ROOT / "scripts" / "hooks" / "scope_gate_hook.py"
SETTINGS_PATH = REPO_ROOT / ".claude" / "settings.json"


def test_pretooluse_hook_is_registered_in_claude_settings():
    """Directly catches a missing/broken hook registration -- the exact
    failure mode S2 exists to detect. If a future edit to
    .claude/settings.json drops or mis-points the PreToolUse entry, this
    test fails even though scope_gate_hook.py's own logic is untouched and
    every other (in-process) test in this suite keeps passing."""
    data = json.loads(SETTINGS_PATH.read_text())
    pretooluse = data["hooks"]["PreToolUse"]
    commands = [
        h["command"]
        for matcher_entry in pretooluse
        for h in matcher_entry.get("hooks", [])
    ]
    assert any("scope_gate_hook.py" in cmd for cmd in commands), (
        "scripts/hooks/scope_gate_hook.py is no longer registered as a "
        "PreToolUse hook in .claude/settings.json"
    )
    # Must apply broadly ("*") -- a narrowed matcher (e.g. "Bash" only)
    # would silently stop gating Tier-2 MCP tool calls.
    assert any(
        m.get("matcher") == "*"
        for m in pretooluse
        if any("scope_gate_hook.py" in h["command"] for h in m.get("hooks", []))
    )


def _dispatch(payload: dict | None, raw_stdin: str | None = None, env_extra: dict | None = None):
    """Invoke the hook exactly as Claude Code's PreToolUse dispatch does:
    spawn `python3 scripts/hooks/scope_gate_hook.py`, write the JSON
    payload to its stdin, close stdin, read the real exit code and
    stderr. No monkeypatching, no in-process import -- a genuine
    subprocess boundary, same as the real harness and same as
    .opencode/plugin/scope-gate.ts's Bun.spawn call."""
    env = dict(os.environ)
    env.update(env_extra or {})
    stdin_text = raw_stdin if raw_stdin is not None else json.dumps(payload)
    proc = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=stdin_text,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=30,
        check=False,
    )
    return proc.returncode, proc.stderr


@pytest.fixture
def isolated_env(tmp_path):
    """Real subprocess isolation from whatever engagement is actually
    active on this machine (see test_scope_gate_hook.py's own
    _isolated_active_engagement fixture for why this matters -- same
    reasoning, just via env vars since this is a separate process rather
    than an in-process monkeypatch)."""
    return {
        "HUNTMCP_ACTIVE_POINTER": str(tmp_path / ".not-really-active"),
    }


def test_real_dispatch_allows_in_scope_target(tmp_path, isolated_env):
    engagement = tmp_path / "engagement.yaml"
    engagement.write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    env = {**isolated_env, "HUNTMCP_ENGAGEMENT_PATH": str(engagement)}
    payload = {"tool_name": "Bash", "tool_input": {"command": "nuclei -u realtarget-corp.com"}}
    code, _ = _dispatch(payload, env_extra=env)
    assert code == 0


def test_real_dispatch_blocks_out_of_scope_target(tmp_path, isolated_env):
    engagement = tmp_path / "engagement.yaml"
    engagement.write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    env = {**isolated_env, "HUNTMCP_ENGAGEMENT_PATH": str(engagement)}
    payload = {"tool_name": "Bash", "tool_input": {"command": "nuclei -u someothersite.com"}}
    code, err = _dispatch(payload, env_extra=env)
    assert code == 2
    assert "someothersite.com" in err


def test_real_dispatch_fails_closed_on_malformed_json(isolated_env):
    code, err = _dispatch(None, raw_stdin="not json", env_extra=isolated_env)
    assert code == 2
    assert "BLOCKED" in err


def test_real_dispatch_fails_closed_on_malformed_engagement_yaml(tmp_path, isolated_env):
    engagement = tmp_path / "engagement.yaml"
    engagement.write_text("target: [this is not: valid: yaml")
    env = {**isolated_env, "HUNTMCP_ENGAGEMENT_PATH": str(engagement)}
    payload = {"tool_name": "Bash", "tool_input": {"command": "nuclei -u realtarget-corp.com"}}
    code, err = _dispatch(payload, env_extra=env)
    assert code == 2
    assert "BLOCKED" in err


def test_real_dispatch_ignores_non_tier2_tool_even_with_no_engagement(tmp_path, isolated_env):
    """Regression: the fail-closed net must not broaden the gate beyond
    the target-touching boundary -- an ordinary Read call with no
    engagement.yaml anywhere must still pass straight through."""
    env = {**isolated_env, "HUNTMCP_ENGAGEMENT_PATH": str(tmp_path / "does-not-exist.yaml")}
    payload = {"tool_name": "Read", "tool_input": {"file_path": "/tmp/whatever.com"}}
    code, _ = _dispatch(payload, env_extra=env)
    assert code == 0


def test_real_dispatch_allows_plain_bash_with_no_engagement(tmp_path, isolated_env):
    env = {**isolated_env, "HUNTMCP_ENGAGEMENT_PATH": str(tmp_path / "does-not-exist.yaml")}
    payload = {"tool_name": "Bash", "tool_input": {"command": "git status"}}
    code, _ = _dispatch(payload, env_extra=env)
    assert code == 0
