"""Cross-process advisory locking for the small per-engagement JSON state
files (budget.json, work-registry.json, findings-seen.json) that
budget_guard.py/work_registry.py/dedupe_check.py each read-modify-write on
every Tier-2 tool call.

Without this, two concurrent MCP server processes touching the same file
race: both read the old state, both write back, and one write clobbers the
other -- a classic lost-update bug. It also protects reads: _save() isn't
atomic (a plain open+write, not write-to-temp-then-rename), so a read
happening mid-write can see a torn/partial JSON file and fail to parse.

flock() is advisory and POSIX-only, which is fine -- this project targets
Linux dev/CI boxes only (see CLAUDE.md). It blocks until the lock is free
rather than raising, so callers don't need their own retry loop.
"""

from __future__ import annotations

import contextlib
import fcntl
import os


@contextlib.contextmanager
def locked(path: str):
    """Hold an exclusive lock associated with `path` for the duration of
    the `with` block. Wrap an entire load-mutate-save (or load-only)
    critical section in this so concurrent callers serialize instead of
    racing. Locks on a sidecar `<path>.lock` file rather than `path`
    itself, so it doesn't interfere with how the wrapped code opens/reads/
    writes the real file."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    lock_path = path + ".lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
