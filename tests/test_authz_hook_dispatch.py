"""P3-VALAUTHZ: the REAL PreToolUse hook (spawned as a subprocess, exactly as Claude Code
dispatches it) gates the new idor-mcp `replay_authz_two_step` tool by its `url` argument.
authz_diff also checks scope in-process before every request; this proves the early filter
in front of it is actually wired for the new tool name, not just for sweep_idor."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK = REPO_ROOT / "scripts" / "hooks" / "scope_gate_hook.py"
TOOL = "mcp__idor-mcp__replay_authz_two_step"


def _dispatch(tool_input: dict, tmp_path):
    engagement = tmp_path / "engagement.yaml"
    engagement.write_text("target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n")
    env = dict(os.environ, HUNTMCP_ENGAGEMENT_PATH=str(engagement),
               HUNTMCP_ACTIVE_POINTER=str(tmp_path / ".not-active"))
    proc = subprocess.run([sys.executable, str(HOOK)], input=json.dumps({"tool_name": TOOL, "tool_input": tool_input}),
                          capture_output=True, text=True, cwd=str(REPO_ROOT), env=env, timeout=30, check=False)
    return proc.returncode, proc.stderr


def _args(host):
    return {"url": f"https://{host}/api/refs", "carried_path": "carts.0.ref",
            "step2_url_template": f"https://{host}/api/carts/{{carried}}/invoice"}


def test_in_scope_replay_is_allowed_by_the_real_hook(tmp_path):
    code, err = _dispatch(_args("realtarget-corp.com"), tmp_path)
    assert code == 0, err


def test_out_of_scope_replay_is_blocked_by_the_real_hook(tmp_path):
    code, err = _dispatch(_args("someothersite.com"), tmp_path)
    assert code == 2 and "someothersite.com" in err


@pytest.mark.parametrize("bad", ["", "not json"])
def test_hook_still_fails_closed_for_garbage_input(bad):
    proc = subprocess.run([sys.executable, str(HOOK)], input=bad, capture_output=True, text=True,
                          cwd=str(REPO_ROOT), timeout=30, check=False)
    assert proc.returncode == 2


@pytest.mark.parametrize("rel", ["mcp-servers/state_change_confirm.py", "scripts/confirm-state-change.sh"])
def test_the_state_change_confirmation_gate_is_tamper_protected_like_rce_confirm(rel, tmp_path):
    """An agent must not be able to Edit/Write the human-gate module or its wrapper script (S6)."""
    env = dict(os.environ, HUNTMCP_ACTIVE_POINTER=str(tmp_path / ".not-active"),
               HUNTMCP_HOOK_CONFIRM_PATH=str(tmp_path / "no-hook-confirm.json"))
    for tool, tool_input in (("Edit", {"file_path": rel, "old_string": "x", "new_string": "y"}),
                             ("Write", {"file_path": rel, "content": "x"})):
        proc = subprocess.run([sys.executable, str(HOOK)], input=json.dumps({"tool_name": tool, "tool_input": tool_input}),
                              capture_output=True, text=True, cwd=str(REPO_ROOT), env=env, timeout=30, check=False)
        assert proc.returncode == 2, f"{tool} on {rel} was not blocked: {proc.stderr}"
