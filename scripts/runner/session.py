"""Session adapter for the HuntMCP dev-runner supervisor.

A *session* is one fresh, separate-process Claude Code run. The real adapter
shells out to the documented headless CLI:

    claude -p "<prompt>" --output-format json --add-dir <repo> [--model ...] [--permission-mode ...]

Each invocation is its own OS process with no shared conversation context -- that
is precisely the "fresh session" the supervisor needs.

Safety: the adapter NEVER adds ``--dangerously-skip-permissions``. Running fully
unattended is the operator's explicit configuration choice (via ``--permission-mode``
or the repo's settings allowlist + scope-gate hook), not something this automation
turns on. The adapter also stamps a recursion-guard env var on the child so a
spawned session cannot start another autopilot.
"""
from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

# Set on every spawned session's environment. If a supervisor sees this already
# set at startup, it refuses to run (prevents session -> supervisor -> session ...).
RECURSION_GUARD_ENV = "HUNTMCP_AUTOPILOT_ACTIVE"

# Effort levels supported by `claude --effort <level>`, verified against the
# installed CLI (v2.1.260): `claude --effort __invalid__` reports
# "Valid values: low, medium, high, xhigh, max".
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")

# Command runner: (argv, cwd, env, timeout) -> (returncode, stdout, stderr).
Runner = Callable[..., tuple]

_MAX_OUTPUT_TAIL = 4000


@dataclass
class SessionResult:
    session_id: str | None
    exit_code: int
    exit_reason: str          # "completed" | "limit" | "error" | "process_error" | "timeout"
    is_error: bool
    output_tail: str = ""
    raw: dict | None = None


def _default_runner(argv, cwd=None, env=None, timeout=None) -> tuple:
    proc = subprocess.run(
        argv, cwd=cwd, env=env, timeout=timeout,
        capture_output=True, text=True, check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


# claude result subtypes -> our exit_reason vocabulary.
_SUBTYPE_TO_REASON = {
    "success": "completed",
    "error_max_turns": "limit",
    "error_max_tokens": "limit",
    "error_during_execution": "error",
}


class ClaudeCliSessionAdapter:
    def __init__(
        self,
        claude_bin: str = "claude",
        model: str | None = None,
        effort: str | None = None,
        permission_mode: str | None = None,
        output_format: str = "json",
        extra_args: list[str] | None = None,
        run: Runner | None = None,
    ):
        self.claude_bin = claude_bin
        self.model = model
        self.effort = effort
        self.permission_mode = permission_mode
        self.output_format = output_format
        self.extra_args = list(extra_args or [])
        self._run = run or _default_runner

    def build_argv(self, prompt: str, repo: str, session_id: str | None = None) -> list[str]:
        argv = [self.claude_bin, "-p", prompt, "--output-format", self.output_format, "--add-dir", repo]
        if self.model:
            argv += ["--model", self.model]
        if self.effort:
            argv += ["--effort", self.effort]
        if self.permission_mode:
            argv += ["--permission-mode", self.permission_mode]
        if session_id:
            argv += ["--session-id", session_id]
        argv += self.extra_args
        return argv

    def build_env(self, base_env: dict) -> dict:
        env = dict(base_env)
        env[RECURSION_GUARD_ENV] = "1"
        return env

    def run_session(
        self,
        prompt: str,
        repo: str,
        session_id: str | None = None,
        timeout: int | None = None,
        base_env: dict | None = None,
        group_ids: list[str] | None = None,
    ) -> SessionResult:
        import os

        argv = self.build_argv(prompt=prompt, repo=repo, session_id=session_id)
        env = self.build_env(base_env if base_env is not None else dict(os.environ))
        try:
            rc, out, err = self._run(argv, cwd=repo, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return SessionResult(
                session_id=session_id, exit_code=124, exit_reason="timeout", is_error=True,
                output_tail="(timed out)",
            )

        data = _parse_json_tail(out)
        if data is None:
            return SessionResult(
                session_id=session_id,
                exit_code=rc,
                exit_reason="process_error" if rc != 0 else "error",
                is_error=True,
                output_tail=_tail(out or err),
                raw=None,
            )

        subtype = data.get("subtype", "")
        is_error = bool(data.get("is_error", False))
        reason = _SUBTYPE_TO_REASON.get(subtype, "error" if is_error else "completed")
        return SessionResult(
            session_id=data.get("session_id", session_id),
            exit_code=rc,
            exit_reason=reason,
            is_error=is_error,
            output_tail=_tail(str(data.get("result", ""))),
            raw=data,
        )


# Interactive runner: (argv, cwd, env, timeout) -> returncode. Unlike the headless
# runner it does NOT capture output -- the child inherits the terminal so the user
# can interact with a normal Claude session.
InteractiveRunner = Callable[..., int]


def _interactive_runner(argv, cwd=None, env=None, timeout=None) -> int:
    # No capture_output: stdin/stdout/stderr are inherited from this process, so
    # the spawned `claude` is a normal interactive session on the user's terminal.
    proc = subprocess.run(argv, cwd=cwd, env=env, timeout=timeout, check=False)
    return proc.returncode


class InteractiveClaudeSessionAdapter:
    """Launch a NORMAL interactive Claude Code session (no ``-p``) per task group.

    The child inherits the terminal, so the user talks to Claude directly and
    Claude can ask questions. The supervisor sequences sessions: it waits for the
    interactive session to exit, then re-derives actual state from disk (it cannot
    observe the conversation without breaking interactivity) and launches the next
    fresh session. Never adds ``--dangerously-skip-permissions``.
    """

    def __init__(
        self,
        claude_bin: str = "claude",
        model: str | None = None,
        effort: str | None = None,
        permission_mode: str | None = None,
        extra_args: list[str] | None = None,
        run: InteractiveRunner | None = None,
    ):
        self.claude_bin = claude_bin
        self.model = model
        self.effort = effort
        self.permission_mode = permission_mode
        self.extra_args = list(extra_args or [])
        self._run = run or _interactive_runner

    def build_argv(self, prompt: str, repo: str, session_id: str) -> list[str]:
        argv = [self.claude_bin]
        if self.model:
            argv += ["--model", self.model]
        if self.effort:
            argv += ["--effort", self.effort]
        if self.permission_mode:
            argv += ["--permission-mode", self.permission_mode]
        argv += ["--add-dir", repo, "--session-id", session_id]
        argv += self.extra_args
        # the seed prompt is the trailing positional, matching `claude [options] [prompt]`
        argv += [prompt]
        return argv

    def build_env(self, base_env: dict) -> dict:
        env = dict(base_env)
        env[RECURSION_GUARD_ENV] = "1"
        return env

    def run_session(
        self,
        prompt: str,
        repo: str,
        session_id: str | None = None,
        timeout: int | None = None,
        base_env: dict | None = None,
        group_ids: list[str] | None = None,
    ) -> SessionResult:
        import os
        import uuid

        sid = session_id or str(uuid.uuid4())
        argv = self.build_argv(prompt=prompt, repo=repo, session_id=sid)
        env = self.build_env(base_env if base_env is not None else dict(os.environ))
        try:
            rc = self._run(argv, cwd=repo, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return SessionResult(session_id=sid, exit_code=124, exit_reason="timeout", is_error=True)
        return SessionResult(
            session_id=sid,
            exit_code=rc,
            exit_reason="session_ended" if rc == 0 else "process_error",
            is_error=rc != 0,
        )


def _parse_json_tail(out: str) -> dict | None:
    """Parse the last JSON object in `out` (claude prints one result object)."""
    if not out:
        return None
    out = out.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # fall back to the last line that parses as JSON
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return None


def _tail(text: str) -> str:
    text = text or ""
    return text[-_MAX_OUTPUT_TAIL:]
