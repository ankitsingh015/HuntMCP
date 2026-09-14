"""S4's own acceptance-gate table (MASTER-ROADMAP-FINAL-v3.md, table in
§10) lists "live prompt" as a distinct test type alongside "unit" -- this
file is that live test. It drives scripts/confirm-os-shell.sh attached to a
REAL pseudo-terminal (not a piped/mocked stdin) via the stdlib `pty` module,
proving the isatty() gate genuinely distinguishes a real human terminal from
an automated/piped call, and that the full interactive flow (prompt ->
typed confirm -> token written) works end-to-end through the actual script
an operator would run -- not just through rce_confirm.py's Python API
(covered separately, non-interactively, in tests/test_rce_confirm.py)."""

import json
import os
import pty
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "confirm-os-shell.sh")


def _run_over_pty(args, input_text, env, timeout=10):
    """Spawn `args` with its stdin/stdout attached to a real pty (so
    isatty() is genuinely True inside the child, unlike a subprocess pipe),
    write `input_text`, and return (exit_code, output_text)."""
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        args,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        cwd=REPO_ROOT,
        close_fds=True,
    )
    os.close(slave_fd)
    os.write(master_fd, input_text.encode())

    output = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    try:
        while True:
            chunk = os.read(master_fd, 4096)
            if not chunk:
                break
            output += chunk
    except OSError:
        pass
    os.close(master_fd)
    return proc.returncode, output.decode(errors="replace")


def test_confirm_os_shell_over_a_real_tty_writes_a_token(tmp_path):
    token_path = str(tmp_path / "os-shell-confirm.json")
    env = dict(os.environ)
    env["HUNTMCP_RCE_CONFIRM_PATH"] = token_path
    env["PYTHONPATH"] = os.path.join(REPO_ROOT, "mcp-servers")

    returncode, output = _run_over_pty(
        [SCRIPT, "example.com"], "example.com\n", env,
    )

    assert returncode == 0, output
    assert "About to authorize" in output
    with open(token_path) as f:
        token = json.load(f)
    assert token["target"] == "example.com"
    assert token["consumed"] is False


def test_confirm_os_shell_over_a_real_tty_declines_on_wrong_text(tmp_path):
    token_path = str(tmp_path / "os-shell-confirm.json")
    env = dict(os.environ)
    env["HUNTMCP_RCE_CONFIRM_PATH"] = token_path
    env["PYTHONPATH"] = os.path.join(REPO_ROOT, "mcp-servers")

    returncode, output = _run_over_pty(
        [SCRIPT, "example.com"], "wrong-target\n", env,
    )

    assert returncode == 1, output
    assert not os.path.isfile(token_path)


def test_confirm_os_shell_piped_non_tty_refuses():
    """The negative control this whole gate depends on: an agent's own
    Bash tool call has piped, non-interactive stdin -- confirm the script
    refuses outright in that shape, never falling through to "confirmed"
    just because the right text happened to be on stdin."""
    result = subprocess.run(
        [SCRIPT, "example.com"],
        input="example.com\n",
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": os.path.join(REPO_ROOT, "mcp-servers")},
        timeout=10,
    )
    assert result.returncode == 1
    assert "not an interactive terminal" in (result.stdout + result.stderr)
