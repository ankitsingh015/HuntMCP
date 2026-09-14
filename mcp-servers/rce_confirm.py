"""S4 (Phase-S Tier-1): human-in-the-loop confirmation gate for persistent-
RCE / state-changing actions -- today, specifically sqlmap's own
--os-shell/--os-pwn/--os-cmd/--os-bof flags, which escalate a confirmed SQLi
finding into actual OS-level command execution on the target. Nothing today
distinguishes that from an ordinary read-only injection test.

Why this can't just be a declarative "ask" permission entry: opencode.jsonc's
own comment records that a declarative bash permission ("ask" or "deny") was
empirically NOT enforced under `opencode run --auto` (see
scope_gate_hook.py's rm-block comment for the same finding) -- the only
structurally-unskippable enforcement point in this repo is the PreToolUse
hook itself (exit 2 blocks the call). But a hook process fired
non-interactively, as part of an agent's own tool call, has no real channel
to a human either -- it can only allow or block the call already in flight,
it cannot itself pop an interactive prompt and wait on someone. So "explicit
human confirm" here means a SEPARATE, human-run script
(scripts/confirm-os-shell.sh) that:

  1. Refuses to run at all unless its stdin is a genuine interactive TTY.
  2. Requires typing the exact target string back, not just an Enter-key
     confirm -- a deliberate second friction point against reflexively
     hitting Enter.
  3. On success, writes a single-use, time-limited confirmation token,
     bound to that target (check_and_consume() takes the target and
     refuses a token confirmed for a different one).

scope_gate_hook.py's own check then requires check_and_consume() to find
and consume that exact token before letting the Bash call through --
consuming it (not merely checking it) so a second --os-shell attempt needs
its own fresh confirm, matching the roadmap's "RCE requires explicit
confirm" acceptance gate (singular, per attempt).

HONEST LIMITS (code-review findings, CONFIRMED -- not fixed, by design out
of Tier-1's own scope; do not remove this section without addressing why):
this is a speed-bump against an ACCIDENTAL or NAIVE self-confirmation, not a
hard boundary against an agent that is itself actively trying to defeat it:

  - The isatty() check distinguishes "was this stdin piped" from "is this
    attached to a pty," not "is a human actually at the other end." An
    agent with ordinary Bash access can spawn its own pty (stdlib `pty`
    module: pty.openpty() + subprocess.Popen(stdin=slave_fd) + write the
    target string to the master fd -- exactly what this repo's own
    tests/test_confirm_os_shell_live.py does to drive the real script in
    tests) and satisfy this check without any human involved.
  - check_and_consume() does no cryptographic/provenance check on the
    token file -- it only checks shape (target/consumed/expires_at). An
    agent with Write/Edit access can fabricate a valid-looking token at
    the exact path this module resolves to and skip request_confirmation()
    entirely.
  Both require the agent to already be actively working AROUND its own
  safety rail using its own execution capability -- containing that is
  S6's job ("hook tamper-resistance -- bash file-writes above the
  boundary prevented"), not a hook-level heuristic's. Tier-1's own
  contract (see MASTER-ROADMAP-FINAL-v3.md's Security Floor section) is a
  floor against ordinary/unintended action, not a boundary that holds
  against a fully adversarial agent -- that hardening is explicitly S5/S6,
  same caveat already recorded for S3's .env-block and S1/rm-block.
"""

from __future__ import annotations

import json
import os
import sys
import time

import file_lock
from engagement_paths import resolve
from scope_guard import NoEngagementFile, load_engagement

# Long enough for a human to read the prompt, type the confirm phrase, and
# for the very next Bash call (the actual --os-shell invocation) to reach
# the hook; short enough that a stale token from an earlier, unrelated
# escalation can't silently authorize a much-later one.
DEFAULT_TTL_SECONDS = 900

_CONFIRM_FILENAME = "os-shell-confirm.json"


def _token_path(path: str | None = None) -> str:
    if path is not None:
        return path
    return resolve(
        _CONFIRM_FILENAME,
        override_env="HUNTMCP_RCE_CONFIRM_PATH",
        legacy_default=os.path.join("/tmp/huntmcp-rce-confirm", _CONFIRM_FILENAME),
    )


def _token_exists(path: str | None = None) -> bool:
    return os.path.isfile(_token_path(path))


def request_confirmation(target: str, ttl_seconds: int = DEFAULT_TTL_SECONDS,
                          stdin=None, stdout=None, path: str | None = None) -> bool:
    """Interactive, human-only confirmation flow for a persistent-RCE /
    state-changing action against `target`. Returns True once a fresh
    confirmation token has been written, False if stdin isn't a real
    terminal or the human declined/mistyped the confirm phrase."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    token_path = _token_path(path)

    isatty = getattr(stdin, "isatty", lambda: False)
    if not isatty():
        print(
            "Refusing to confirm: stdin is not an interactive terminal. "
            "This confirmation must come from a human typing into their "
            "own shell, not from an automated/piped call.",
            file=stdout,
        )
        return False

    print(
        f"About to authorize a persistent OS-shell / state-changing action "
        f"against {target!r}.\n"
        f"Type the target exactly ({target!r}) to confirm, or anything else "
        f"to decline: ",
        file=stdout,
    )
    try:
        typed = stdin.readline().strip()
    except (OSError, ValueError):
        return False

    if typed != target:
        print("Confirmation text did not match -- declined.", file=stdout)
        return False

    token = {
        "target": target,
        "expires_at": time.time() + ttl_seconds,
        "consumed": False,
    }
    parent = os.path.dirname(token_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with file_lock.locked(token_path), open(token_path, "w") as f:
        json.dump(token, f)
    print(f"Confirmed. Valid once, within {ttl_seconds}s.", file=stdout)
    return True


def check_and_consume(target: str, path: str | None = None) -> bool:
    """Called from the PreToolUse hook, non-interactively. True only if a
    fresh, unconsumed, unexpired confirmation token exists AND was
    confirmed for this exact `target` -- and consumes it (marks it used)
    as a side effect, so a second --os-shell attempt needs its own fresh
    human confirm. A target mismatch returns False WITHOUT consuming the
    token, so the correct target can still redeem it afterwards -- a wrong-
    target attempt (typo, stale engagement pointer, hallucinated host)
    shouldn't burn the human's one confirmation for the right one."""
    token_path = _token_path(path)
    with file_lock.locked(token_path):
        if not os.path.isfile(token_path):
            return False
        try:
            with open(token_path) as f:
                token = json.load(f)
        except (json.JSONDecodeError, OSError):
            return False

        if token.get("consumed"):
            return False
        if token.get("target") != target:
            return False
        if time.time() > token.get("expires_at", 0):
            return False

        token["consumed"] = True
        with open(token_path, "w") as f:
            json.dump(token, f)
        return True


def _cli() -> bool:
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target:
        # Use engagement.yaml's own `target:` field, not the active
        # pointer's slug -- check_and_consume() (called from the hook with
        # the SAME engagement.target) compares against this exact string,
        # so the two sides must agree on which spelling of "the target"
        # they mean.
        try:
            target = load_engagement().target
        except (NoEngagementFile, RuntimeError):
            print(
                "No active engagement and no target given. Usage: "
                "scripts/confirm-os-shell.sh <target>",
                file=sys.stderr,
            )
            return False
    return request_confirmation(target)


if __name__ == "__main__":
    sys.exit(0 if _cli() else 1)
