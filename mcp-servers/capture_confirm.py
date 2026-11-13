"""Human TTY confirmation gate for session capture (#128).

The agent cannot complete a capture on its own: finish_capture refuses unless
a FRESH confirmation token exists that matches the open capture's fingerprint,
and that token can only be written by write_confirmation(), which refuses when
stdin is not a TTY. The operator runs scripts/confirm-capture.sh in their OWN
terminal after logging in -- same human-gate footing as
scripts/confirm-state-change.sh / state_change_confirm.py.

No secret is involved here: the token holds only the engagement slug, the
identity label, the fingerprint, and a timestamp.
"""

from __future__ import annotations

import json
import os
import sys
import time

import engagement_paths

CONFIRM_TTL_S = 600  # a confirmation older than this no longer authorizes a finish


def confirmation_token_path(slug: str, label: str) -> str:
    return engagement_paths.resolve(f"secrets/capture-confirm-{label}.json")


def write_confirmation(slug: str, label: str, fingerprint: str) -> None:
    """Write the fingerprint-bound confirmation token (0600). Refuses with
    SystemExit when stdin is not a TTY -- an agent cannot satisfy this gate."""
    if not sys.stdin.isatty():
        raise SystemExit(
            "confirm-capture must be run by a HUMAN in a real terminal "
            "(stdin is not a TTY) -- an agent cannot satisfy this gate."
        )
    path = confirmation_token_path(slug, label)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"slug": slug, "label": label, "fingerprint": fingerprint, "ts": time.time()}, f)
    os.chmod(path, 0o600)


def verify_confirmation(slug: str, label: str, fingerprint: str, ttl_s: int = CONFIRM_TTL_S) -> bool:
    """True only if a token exists, matches fingerprint, and is within ttl_s."""
    path = confirmation_token_path(slug, label)
    if not os.path.isfile(path):
        return False
    try:
        with open(path) as f:
            tok = json.load(f)
    except Exception:
        return False
    if tok.get("fingerprint") != fingerprint:
        return False
    if (time.time() - float(tok.get("ts", 0))) > ttl_s:
        return False
    return True


def _main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: confirm-capture.sh <slug> <label> <fingerprint>", file=sys.stderr)
        return 2
    slug, label, fingerprint = argv
    try:
        import session_capture

        note = session_capture.roster_entry(label).get("note", "")
    except Exception:
        note = ""
    print(
        "About to confirm a session capture:\n"
        f"  identity:    {label}  ({note})\n"
        f"  engagement:  {slug}\n"
        f"  fingerprint: {fingerprint}\n"
        "The fingerprint binds the exact login URL the agent opened. Confirm only if "
        "this is YOUR designated test account and you just logged in."
    )
    ans = input("Type 'yes' to confirm: ").strip().lower()
    if ans != "yes":
        print("Aborted -- no confirmation written.")
        return 1
    write_confirmation(slug, label, fingerprint)
    print("Confirmed. You can now let the agent call finish_capture.")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
