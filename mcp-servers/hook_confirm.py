"""S6 (Phase-S Tier-2): human-in-the-loop confirmation gate for editing a
hook-tamper-resistance protected file (scope_gate_hook.py itself and the
modules/config it depends on to enforce S1-S5 -- see
scope_gate_hook.py's own _PROTECTED_RELATIVE_PATHS for the exact list).

Why this exists: without it, an agent with ordinary Edit/Write/Bash access
could simply overwrite scope_gate_hook.py (or drop its registration from
.claude/settings.json) to silently neutralize every prior Tier-1/Tier-2
control mid-session -- the exact gap named "hook neutralizable mid-session"
in MASTER-ROADMAP-FINAL-v3.md's Phase-S Tier-2 spec.

Same "separate, human-run script" shape as mcp-servers/rce_confirm.py (S4)
and for the same reason recorded in that module's own docstring: a
PreToolUse hook fired non-interactively, as part of the very tool call it's
evaluating, has no channel to a human -- it can only allow or block a call
already in flight. So "explicit human confirm" here means
scripts/confirm-hook-edit.sh, run by a human directly in their own
terminal, refusing outright unless its stdin is a genuine tty.

DELIBERATE DIFFERENCE FROM rce_confirm.py's TOKEN: that token is single-use
and target-bound (each --os-shell ATTEMPT is its own distinct dangerous
action). This token is multi-use within a short TTL (default 30 minutes,
not consumed by check_valid()) -- a real maintenance session touching
scope_gate_hook.py legitimately needs several Edit passes (this exact S6
implementation session is the motivating example), and requiring a fresh
interactive human confirm before every single one of them would make
ordinary maintenance impractical without meaningfully raising the bar
against an autonomous/silent tamper attempt, which still needs a live human
typing the confirm phrase at least once per ~30-minute window.

NOT engagement-scoped (unlike budget.json/os-shell-confirm.json, which
correctly live under data/engagements/<active-slug>/ via
engagement_paths.resolve()): hook tamper-resistance is a repo/toolchain
concern, not per-target hunt state. Routing it through engagement_paths
would mean pausing one engagement to work on another silently relocates or
invalidates a maintenance confirm that has nothing to do with either
target -- a real design mistake caught and rejected during S6 planning, see
tests/test_hook_confirm.py::test_token_path_not_engagement_scoped.

HONEST LIMIT (same class as rce_confirm.py's own documented gap, not
closed here either): check_valid() does no cryptographic/provenance check
on the token file itself, only shape + expiry -- it can only tell "a
plausible-looking token exists," not "a human genuinely typed the confirm
phrase." What closes that gap here, unlike os-shell-confirm.json which
remained openly forgeable at S4 time, is that THIS token's own path is
itself one of scope_gate_hook.py's protected paths (see
_PROTECTED_RELATIVE_PATHS): an agent's own Edit/Write/Bash call to
fabricate a token file still has to pass the same protected-path check
this module exists to gate, closing the exact bypass rce_confirm.py's own
docstring named as "S6's job." A sufficiently determined adversarial agent
could still spawn its own pty against confirm-hook-edit.sh (the same
documented isatty() limit rce_confirm.py carries) -- that is a Tier-1/2
floor-not-boundary limit, not something this module claims to close.
"""

from __future__ import annotations

import json
import os
import sys
import time

import file_lock

DEFAULT_TTL_SECONDS = 1800  # 30 minutes -- long enough for a real maintenance
# session's multiple edit/test cycles, short enough that a forgotten confirm
# from hours ago can't silently authorize a much later, unrelated tamper.

CONFIRM_PHRASE = "CONFIRM HOOK EDIT"

_CONFIRM_FILENAME = "hook-edit-confirm.json"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_TOKEN_PATH = os.path.join(_REPO_ROOT, "data", _CONFIRM_FILENAME)


def _token_path(path: str | None = None) -> str:
    if path is not None:
        return path
    override = os.getenv("HUNTMCP_HOOK_CONFIRM_PATH")
    if override:
        return override
    return _DEFAULT_TOKEN_PATH


def _token_exists(path: str | None = None) -> bool:
    return os.path.isfile(_token_path(path))


def request_confirmation(ttl_seconds: int = DEFAULT_TTL_SECONDS,
                          stdin=None, stdout=None, path: str | None = None) -> bool:
    """Interactive, human-only confirmation flow authorizing protected-path
    writes for `ttl_seconds`. Returns True once a fresh token has been
    written, False if stdin isn't a real terminal or the human
    declined/mistyped the confirm phrase."""
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
        "About to authorize edits to HuntMCP's hook-tamper-resistance "
        "boundary (scope_gate_hook.py and the files it depends on to "
        f"enforce scope/secrets/RCE-confirm controls) for the next "
        f"{ttl_seconds}s.\n"
        f"Type exactly {CONFIRM_PHRASE!r} to confirm, or anything else to "
        "decline: ",
        file=stdout,
    )
    try:
        typed = stdin.readline().strip()
    except (OSError, ValueError):
        return False

    if typed != CONFIRM_PHRASE:
        print("Confirmation text did not match -- declined.", file=stdout)
        return False

    token = {
        "expires_at": time.time() + ttl_seconds,
        "confirmed_at": time.time(),
    }
    parent = os.path.dirname(token_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with file_lock.locked(token_path), open(token_path, "w") as f:
        json.dump(token, f)
    print(f"Confirmed. Valid for {ttl_seconds}s, any number of protected-path writes.", file=stdout)
    return True


def check_valid(path: str | None = None) -> bool:
    """Called from the PreToolUse hook, non-interactively. True iff a
    fresh, unexpired confirmation token exists. Deliberately NON-consuming
    (unlike rce_confirm.check_and_consume()) -- see module docstring for
    why this token is multi-use within its TTL rather than single-use."""
    token_path = _token_path(path)
    with file_lock.locked(token_path):
        if not os.path.isfile(token_path):
            return False
        try:
            with open(token_path) as f:
                token = json.load(f)
        except (json.JSONDecodeError, OSError):
            return False
        return time.time() <= token.get("expires_at", 0)


def _cli() -> bool:
    return request_confirmation()


if __name__ == "__main__":
    sys.exit(0 if _cli() else 1)
