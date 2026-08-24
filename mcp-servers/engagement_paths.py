"""Per-target engagement state resolution -- lets HuntBrain run multiple
targets without one target's paused state getting mixed with another's.

Why this exists: engagement.yaml/budget.json/work-registry.json/
findings-seen.json/audit.jsonl were originally single flat files (repo
root / data/), reset by deleting them at the start of "a fresh
engagement." That's fine for exactly one target at a time, but pausing a
hunt on target A to start target B -- then coming back to A later -- would
silently reset or overwrite A's scope, budget, and dedup state with B's.

Fix: every guard module resolves its state file against the CURRENTLY
ACTIVE target's own directory under data/engagements/<slug>/ instead of a
shared flat path. Switching targets never touches another target's files;
resuming a paused target is just switching back, with its state exactly as
the engagement left it.

Active target is tracked via a small pointer file (data/.active-engagement,
gitignored), not an environment variable -- env vars exported inside one
Bash tool call do not persist into the next call in this harness, but a
file on disk does.

Explicit HUNTMCP_*_PATH overrides (already used by tests and for advanced
use) always win over auto-resolution -- see resolve()'s override_env param,
used by every caller in scope_guard.py/budget_guard.py/work_registry.py/
dedupe_check.py/audit_log.py.

CLI usage (what HuntBrain runs via Bash at Phase 0):
    python3 mcp-servers/engagement_paths.py check <target>
        -> run BEFORE `set`, in the SAME chat session. If a different
           target is currently active and hasn't been marked complete,
           prints a warning and exits 3 -- the conversational signal that
           this chat is already mid-hunt on another target, so HuntBrain
           should ask the user whether to continue here anyway or start a
           fresh chat session for the new target (state isolation via
           per-target directories doesn't by itself stop one CHAT from
           narrating two targets at once; this check is what does).
           Exits 0 ("ok") when there's no conflict -- no active target yet,
           the active target IS this target (a resume), or the active
           target is already marked complete.
    python3 mcp-servers/engagement_paths.py set <target>
        -> creates data/engagements/<slug>/ if needed, points the active
           pointer at it, prints the slug. Idempotent -- calling this again
           for a target that already has a directory (a resume, not a
           fresh start) does NOT touch its existing budget/work-registry/
           findings-seen/engagement.yaml; it only switches the pointer.
    python3 mcp-servers/engagement_paths.py complete
        -> marks the CURRENTLY active target's directory complete (Phase 6
           write-back). Lets a later `check` on a different target proceed
           without a warning, since this target's hunt is genuinely done.
    python3 mcp-servers/engagement_paths.py current
        -> prints the active slug and its directory, or "none" if unset
    python3 mcp-servers/engagement_paths.py list
        -> JSON array of every known engagement directory with its target
           name (from engagement.yaml, if present), Tier-2 call count
           (from budget.json, if present), and whether it's marked complete
           -- a quick "what's paused vs. finished" view
"""

from __future__ import annotations

import json
import os
import re
import sys

ACTIVE_POINTER = os.getenv("HUNTMCP_ACTIVE_POINTER", "data/.active-engagement")
ENGAGEMENTS_ROOT = os.getenv("HUNTMCP_ENGAGEMENTS_ROOT", "data/engagements")


def slugify(target: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", target.strip().lower()).strip("-")
    return slug or "unnamed-target"


def get_active_target(pointer_path: str = ACTIVE_POINTER) -> str | None:
    if not os.path.isfile(pointer_path):
        return None
    with open(pointer_path) as f:
        slug = f.read().strip()
    return slug or None


def set_active_target(target: str, pointer_path: str = ACTIVE_POINTER,
                       engagements_root: str = ENGAGEMENTS_ROOT) -> str:
    """Point the active pointer at target's directory, creating it if new.
    Never touches files already inside an existing target directory --
    switching back to a paused target is always safe."""
    slug = slugify(target)
    os.makedirs(os.path.dirname(pointer_path) or ".", exist_ok=True)
    with open(pointer_path, "w") as f:
        f.write(slug)
    os.makedirs(os.path.join(engagements_root, slug), exist_ok=True)
    return slug


def resolve(filename: str, override_env: str | None = None,
            pointer_path: str = ACTIVE_POINTER,
            engagements_root: str = ENGAGEMENTS_ROOT,
            legacy_default: str | None = None) -> str:
    """Resolve filename to its actual on-disk path for the active target.

    Priority: an explicit HUNTMCP_*_PATH env var (override_env) always wins
    -- this is what tests and advanced manual use rely on. Otherwise, if a
    target is currently active, resolve inside its per-target directory.
    Otherwise fall back to legacy_default (or, if not given, the bare
    filename) -- so a single-target workflow that never calls `set` behaves
    exactly as it did before this module existed."""
    if override_env:
        override = os.getenv(override_env)
        if override:
            return override
    slug = get_active_target(pointer_path)
    if slug:
        return os.path.join(engagements_root, slug, filename)
    return legacy_default if legacy_default is not None else filename


def _complete_marker(slug: str, engagements_root: str = ENGAGEMENTS_ROOT) -> str:
    return os.path.join(engagements_root, slug, ".complete")


def is_complete(slug: str, engagements_root: str = ENGAGEMENTS_ROOT) -> bool:
    return os.path.isfile(_complete_marker(slug, engagements_root))


def mark_complete(pointer_path: str = ACTIVE_POINTER,
                   engagements_root: str = ENGAGEMENTS_ROOT) -> str | None:
    """Mark the currently active target's directory complete. Returns the
    slug marked, or None if no target is active."""
    slug = get_active_target(pointer_path)
    if not slug:
        return None
    with open(_complete_marker(slug, engagements_root), "w") as f:
        f.write("")
    return slug


def check_conflict(target: str, pointer_path: str = ACTIVE_POINTER,
                    engagements_root: str = ENGAGEMENTS_ROOT) -> str | None:
    """Returns a warning message if starting `target` would conflict with
    an already-active, not-yet-complete DIFFERENT target in this same chat
    session -- None if there's no conflict (nothing active, this target IS
    the active one, or the active one is already marked complete)."""
    new_slug = slugify(target)
    active_slug = get_active_target(pointer_path)
    if not active_slug or active_slug == new_slug:
        return None
    if is_complete(active_slug, engagements_root):
        return None
    return (
        f"This chat is already mid-hunt on {active_slug!r} (not yet marked "
        f"complete). Starting {new_slug!r} here would narrate two targets "
        "in one conversation -- recommend continuing this chat with the "
        f"existing target, or opening a NEW chat session for {new_slug!r} "
        "instead. Their on-disk state is already isolated either way; this "
        "is about keeping the conversation itself to one target per chat."
    )


def list_engagements(engagements_root: str = ENGAGEMENTS_ROOT) -> list[dict]:
    if not os.path.isdir(engagements_root):
        return []
    out = []
    for slug in sorted(os.listdir(engagements_root)):
        d = os.path.join(engagements_root, slug)
        if not os.path.isdir(d):
            continue
        entry = {"slug": slug, "target": None, "tier2_calls": None,
                  "complete": is_complete(slug, engagements_root)}
        eng_path = os.path.join(d, "engagement.yaml")
        if os.path.isfile(eng_path):
            try:
                import yaml
                with open(eng_path) as f:
                    data = yaml.safe_load(f) or {}
                entry["target"] = data.get("target")
            except Exception:
                pass
        budget_path = os.path.join(d, "budget.json")
        if os.path.isfile(budget_path):
            try:
                with open(budget_path) as f:
                    entry["tier2_calls"] = json.load(f).get("calls")
            except Exception:
                pass
        out.append(entry)
    return out


def _cli() -> None:
    if len(sys.argv) < 2:
        print("usage: engagement_paths.py <check|set|complete|current|list> ...", file=sys.stderr)
        sys.exit(2)

    cmd = sys.argv[1]
    if cmd == "check":
        if len(sys.argv) < 3:
            print("usage: engagement_paths.py check <target>", file=sys.stderr)
            sys.exit(2)
        warning = check_conflict(sys.argv[2])
        if warning:
            print(warning, file=sys.stderr)
            sys.exit(3)
        print("ok")
    elif cmd == "set":
        if len(sys.argv) < 3:
            print("usage: engagement_paths.py set <target>", file=sys.stderr)
            sys.exit(2)
        slug = set_active_target(sys.argv[2])
        print(slug)
    elif cmd == "complete":
        slug = mark_complete()
        if slug:
            print(f"marked {slug} complete")
        else:
            print("no active target to mark complete", file=sys.stderr)
            sys.exit(1)
    elif cmd == "current":
        slug = get_active_target()
        if slug:
            print(f"{slug} ({os.path.join(ENGAGEMENTS_ROOT, slug)})")
        else:
            print("none")
    elif cmd == "list":
        print(json.dumps(list_engagements(), indent=2))
    else:
        print(f"unknown command {cmd!r}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    _cli()
