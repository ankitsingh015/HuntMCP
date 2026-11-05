"""P3-VALAUTHZ: human gate for state-changing replay steps.

authz_diff only sends a non-GET/HEAD/OPTIONS step when a valid approval object is passed in.
For the MCP tool that approval must NOT be something the calling agent can write itself, so it
comes from a token a HUMAN created by running scripts/confirm-state-change.sh in their own terminal.
Reuses rce_confirm's mechanism (interactive-TTY-only, type-the-target-back, single-use,
time-limited) with its own token file, bound to host[:port] AND the exact set of methods, so
confirming POST for one host cannot authorize DELETE or another host.

HONEST LIMITS (inherited from rce_confirm, see its docstring -- not fixed here by design): an agent
that spawns its own pty or writes the token file directly can defeat the isatty check; containing
that is the hook tamper-resistance job (S6), not this module's. This is a floor against accidental or
naive self-approval.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import tempfile
import time

import engagement_paths
import rce_confirm

CONFIRM_FILENAME = "state-change-confirm.json"
APPROVABLE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


# Used only when no engagement is active: a per-user directory that must be private to this user
# (a shared, predictable /tmp path would let another local user plant a token or a symlink).
LEGACY_DIR = os.path.join(tempfile.gettempdir(), f"huntmcp-state-change-confirm-{os.getuid()}")


def _engagement_slug_dir() -> str | None:
    slug = engagement_paths.get_active_target()
    return os.path.join(engagement_paths.ENGAGEMENTS_ROOT, slug) if slug else None


def _ensure_private_dir(path: str) -> None:
    """Create `path` 0700 if missing; refuse (RuntimeError) a symlink, a non-directory, a directory
    owned by someone else, or one that is group/world accessible."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or st.st_mode & 0o077):
        raise RuntimeError(f"refusing token directory {path!r}: not a private directory owned by this user")


def token_path() -> str:
    override = os.getenv("HUNTMCP_STATE_CHANGE_CONFIRM_PATH")  # trusted (env), used by tests/manual setups
    if override:
        return override
    base = _engagement_slug_dir()
    if base is None:
        _ensure_private_dir(LEGACY_DIR)
        base = LEGACY_DIR
    return os.path.join(base, CONFIRM_FILENAME)


def _methods(methods) -> list[str]:
    return sorted({str(m).strip().upper() for m in methods})


_FINGERPRINT_RE = re.compile(r"[0-9a-f]{32}")  # 128 bits: a birthday collision is out of reach


def target_string(host: str, methods, fingerprint: str = "") -> str:
    """host|METHODS or host|METHODS|fingerprint. The fingerprint (authz_diff.workflow_fingerprint) pins
    the confirmation to the exact step URLs, methods and body hash the tool printed, so the agent
    cannot reuse a confirmation for a different path or body on the same host."""
    base = f"{host.strip().lower()}|{','.join(_methods(methods))}"
    return f"{base}|{fingerprint}" if fingerprint else base


def _pending_path(fingerprint: str) -> str:
    return os.path.join(os.path.dirname(token_path()), f"state-change-pending-{fingerprint}.json")


def write_pending(host: str, methods, fingerprint: str, summary: str) -> None:
    """Called by the TOOL with a summary it built from the real workflow (not agent text), so the
    human's confirm prompt can show what will actually be sent. Best effort: a failure only means
    the prompt warns that it cannot show the details."""
    if not _FINGERPRINT_RE.fullmatch(fingerprint):
        return
    try:
        path = _pending_path(fingerprint)
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        _prune_pending(directory)
        with open(path, "w") as f:
            json.dump({"host": host.strip().lower(), "methods": _methods(methods), "summary": summary}, f)
    except (OSError, RuntimeError):
        pass


# A pending summary is only useful while a confirmation could still be given and used.
PENDING_TTL_SECONDS = 6 * 3600


def _prune_pending(directory: str) -> None:
    """Best effort: drop pending-request files older than PENDING_TTL_SECONDS."""
    cutoff = time.time() - PENDING_TTL_SECONDS
    for name in os.listdir(directory):
        if name.startswith("state-change-pending-") and name.endswith(".json"):
            full = os.path.join(directory, name)
            try:
                if os.lstat(full).st_mtime < cutoff:
                    os.unlink(full)
            except OSError:
                pass


def _drop_pending(fingerprint: str) -> None:
    try:
        os.unlink(_pending_path(fingerprint))
    except (OSError, RuntimeError):
        pass


# The most the confirm prompt will show. The tool refuses (ERROR) a workflow whose summary is longer,
# and the prompt itself marks any overflow instead of cutting it silently: the human must never be
# asked to confirm something they could not read in full.
PROMPT_SUMMARY_LIMIT = 2000


def _printable(text: str) -> str:
    """No escape sequences / newlines from agent-influenced text reach the human's terminal."""
    clean = "".join(c if c.isprintable() else "?" for c in text)
    if len(clean) > PROMPT_SUMMARY_LIMIT:
        return clean[:PROMPT_SUMMARY_LIMIT] + " [TRUNCATED -- DO NOT CONFIRM]"
    return clean


def _show_pending(host: str, wanted: list[str], fingerprint: str, out) -> None:
    summary = None
    try:
        with open(_pending_path(fingerprint)) as f:
            data = json.load(f)
        if data.get("host") == host.strip().lower() and data.get("methods") == wanted \
                and isinstance(data.get("summary"), str):
            summary = data["summary"]
    except (OSError, RuntimeError, ValueError, AttributeError):
        summary = None
    if summary is None:
        print("WARNING: no matching pending request found for this fingerprint -- this prompt cannot show "
              "you what it would authorize. Only confirm if you can verify it independently.", file=out)
    else:
        print(f"This confirmation covers exactly (as written by the tool from the real workflow):\n  "
              f"{_printable(summary)}", file=out)


def request_confirmation(host: str, methods, fingerprint: str = "", stdin=None, stdout=None) -> bool:
    """Human-only: writes a token iff stdin is a real TTY and the exact target string is typed back."""
    wanted = _methods(methods)
    if not wanted or not set(wanted) <= APPROVABLE_METHODS:
        print(f"Refusing: methods must be a non-empty subset of {sorted(APPROVABLE_METHODS)}.",
              file=stdout or sys.stdout)
        return False
    if fingerprint and not _FINGERPRINT_RE.fullmatch(fingerprint):
        print("Refusing: the fingerprint must be 32 lowercase hex characters (copy it from the tool's message).",
              file=stdout or sys.stdout)
        return False
    try:
        path = token_path()
    except RuntimeError as e:
        print(f"Refusing: {e}", file=stdout or sys.stdout)
        return False
    if fingerprint:
        _show_pending(host, wanted, fingerprint, stdout or sys.stdout)
    return rce_confirm.request_confirmation(target_string(host, wanted, fingerprint), stdin=stdin,
                                            stdout=stdout, path=path)


def consume_approval(host: str, methods, fingerprint: str = "") -> dict | None:
    """The approval object authz_diff/cem_engine expect, iff a fresh token for exactly this
    host+methods(+workflow fingerprint) exists (and consumes it); else None."""
    wanted = _methods(methods)
    try:
        path = token_path()
    except RuntimeError:
        return None  # an unsafe token directory never yields an approval
    if not wanted or not rce_confirm.check_and_consume(target_string(host, wanted, fingerprint), path=path):
        return None
    if fingerprint and _FINGERPRINT_RE.fullmatch(fingerprint):
        _drop_pending(fingerprint)  # the confirmation is spent; its summary has no further use
    return {"methods": wanted, "reason": "human-confirmed via scripts/confirm-state-change.sh",
            "authorized_by": "human (interactive TTY confirmation)"}


def _cli() -> bool:
    if len(sys.argv) < 3:
        print("Usage: scripts/confirm-state-change.sh <host[:port]> <METHOD[,METHOD...]> [fingerprint]",
              file=sys.stderr)
        return False
    return request_confirmation(sys.argv[1], sys.argv[2].split(","), sys.argv[3] if len(sys.argv) > 3 else "")


if __name__ == "__main__":
    sys.exit(0 if _cli() else 1)
