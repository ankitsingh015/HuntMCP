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

import audit_log
import engagement_paths
import rce_confirm
from scope_guard import NoEngagementFile, load_engagement

CONFIRM_FILENAME = "state-change-confirm.json"
APPROVABLE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# #132: a narrower authorization class the human grants ONCE per engagement
# (engagement.yaml `preauthorized_classes`) for a bounded, lower-blast-radius
# pattern. A request matching a pre-authorized class may fire with a SINGLE
# terminal confirmation instead of the two-step register-then-confirm flow --
# only the fingerprint register round trip is removed, never the human TTY
# keystroke, the single-use token, or the audit entry. The dict key is the
# class id; its value is the human-readable scope the confirm prompt shows so
# the human knows exactly what they pre-authorized. Only ids defined HERE can
# ever be fast-pathed, even if engagement.yaml lists an unknown one.
PREAUTHORIZABLE_CLASSES: dict[str, str] = {
    "own-account-credential-replay": (
        "Replay a short-lived, externally-issued credential against ANOTHER "
        "account the researcher already owns (both identities captured/on file "
        "as researcher-owned), reversible by its own disconnect/revoke call, "
        "creating no new resource in another tenant's data."
    ),
}


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


def target_string(host: str, methods, fingerprint: str = "", preauth_class: str = "") -> str:
    """host|METHODS, host|METHODS|fingerprint, or host|METHODS|preauth:<class>.

    The fingerprint (authz_diff.workflow_fingerprint) pins the confirmation to
    the exact step URLs, methods and body hash the tool printed, so the agent
    cannot reuse a confirmation for a different path or body on the same host.

    preauth_class (#132) binds a fast-path confirmation to a specific
    pre-authorized class instead -- a class-bound token can never satisfy a
    fingerprint consume, a plain host+methods consume, or a different class.
    fingerprint and preauth_class are mutually exclusive; preauth_class wins
    if both are somehow passed (the caller passes exactly one)."""
    base = f"{host.strip().lower()}|{','.join(_methods(methods))}"
    if preauth_class:
        return f"{base}|preauth:{preauth_class}"
    return f"{base}|{fingerprint}" if fingerprint else base


def preauthorized_classes() -> set[str]:
    """The set of fast-path classes the human listed in engagement.yaml's
    `preauthorized_classes` AND that this module actually defines -- an
    engagement.yaml entry for an unknown class id is ignored, never honored.
    Empty when there is no engagement, it can't be read, or none are listed."""
    try:
        eng = load_engagement()
    except (NoEngagementFile, RuntimeError):
        return set()
    listed = getattr(eng, "preauthorized_classes", None) or []
    return {str(c).strip() for c in listed} & set(PREAUTHORIZABLE_CLASSES)


def fast_path_allowed(class_id: str) -> bool:
    """True iff `class_id` is a known preauthorizable class AND the active
    engagement pre-authorized it. This is the ONLY switch that lets the
    single-confirmation fast path exist for a request; everything else keeps
    the full fingerprint gate. It does NOT remove the human TTY keystroke --
    see request_confirmation()/consume_approval()."""
    return class_id in PREAUTHORIZABLE_CLASSES and class_id in preauthorized_classes()


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


def request_confirmation(host: str, methods, fingerprint: str = "", preauth_class: str = "",
                         stdin=None, stdout=None) -> bool:
    """Human-only: writes a token iff stdin is a real TTY and the exact target string is typed back.

    With preauth_class set (#132), this is the fast path: it is REFUSED unless
    the engagement pre-authorized that class (fast_path_allowed), and it skips
    the fingerprint register round trip -- but it still requires the human TTY
    keystroke and still writes a single-use token, class-bound."""
    out = stdout or sys.stdout
    wanted = _methods(methods)
    if not wanted or not set(wanted) <= APPROVABLE_METHODS:
        print(f"Refusing: methods must be a non-empty subset of {sorted(APPROVABLE_METHODS)}.", file=out)
        return False
    if preauth_class:
        if not fast_path_allowed(preauth_class):
            print(f"Refusing fast path: class {preauth_class!r} is not pre-authorized for this engagement. "
                  "The human must list it in engagement.yaml `preauthorized_classes` at engagement start, "
                  "and it must be a class this build defines "
                  f"({sorted(PREAUTHORIZABLE_CLASSES)}). Use the full fingerprint confirmation instead.",
                  file=out)
            return False
    elif fingerprint and not _FINGERPRINT_RE.fullmatch(fingerprint):
        print("Refusing: the fingerprint must be 32 lowercase hex characters (copy it from the tool's message).",
              file=out)
        return False
    try:
        path = token_path()
    except RuntimeError as e:
        print(f"Refusing: {e}", file=out)
        return False
    if preauth_class:
        print(f"Fast path for pre-authorized class {preauth_class!r} -- this covers EXACTLY:\n  "
              f"{_printable(PREAUTHORIZABLE_CLASSES[preauth_class])}\nConfirm only if this specific "
              "replay stays within that class (own accounts, reversible).", file=out)
    elif fingerprint:
        _show_pending(host, wanted, fingerprint, out)
    return rce_confirm.request_confirmation(target_string(host, wanted, fingerprint, preauth_class),
                                            stdin=stdin, stdout=stdout, path=path)


def consume_approval(host: str, methods, fingerprint: str = "", preauth_class: str = "") -> dict | None:
    """The approval object authz_diff/cem_engine expect, iff a fresh token for exactly this
    host+methods(+workflow fingerprint, or +preauth class) exists (and consumes it); else None.

    A preauth_class consume (#132) is refused outright unless the class is
    still pre-authorized for this engagement -- defense in depth even if a
    class-bound token somehow existed -- and writes a full audit entry so the
    fast path is never off the engagement's own audit trail."""
    wanted = _methods(methods)
    if preauth_class and not fast_path_allowed(preauth_class):
        return None
    try:
        path = token_path()
    except RuntimeError:
        return None  # an unsafe token directory never yields an approval
    if not wanted or not rce_confirm.check_and_consume(target_string(host, wanted, fingerprint, preauth_class), path=path):
        return None
    if fingerprint and _FINGERPRINT_RE.fullmatch(fingerprint):
        _drop_pending(fingerprint)  # the confirmation is spent; its summary has no further use
    approval = {"methods": wanted, "reason": "human-confirmed via scripts/confirm-state-change.sh",
                "authorized_by": "human (interactive TTY confirmation)"}
    if preauth_class:
        approval["preauth_class"] = preauth_class
        # Still on the engagement's audit trail -- the whole point of #132 is
        # that the fast path is faster, not quieter.
        try:
            audit_log.log_call("state-change-confirm:fast-path",
                               [host.strip().lower(), ",".join(wanted), f"preauth:{preauth_class}"],
                               returncode=0, duration_ms=0.0, block=None)
        except (OSError, RuntimeError):
            pass
    return approval


def _cli() -> bool:
    argv = sys.argv[1:]
    preauth_class = ""
    if "--class" in argv:
        i = argv.index("--class")
        if i + 1 >= len(argv):
            print("Usage: --class needs a value, e.g. --class own-account-credential-replay",
                  file=sys.stderr)
            return False
        preauth_class = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if len(argv) < 2:
        print("Usage: scripts/confirm-state-change.sh <host[:port]> <METHOD[,METHOD...]> "
              "[fingerprint | --class <id>]", file=sys.stderr)
        return False
    fingerprint = argv[2] if len(argv) > 2 and not preauth_class else ""
    return request_confirmation(argv[0], argv[1].split(","), fingerprint=fingerprint,
                                preauth_class=preauth_class)


if __name__ == "__main__":
    sys.exit(0 if _cli() else 1)
