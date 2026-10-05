"""No-finding engagement close-out record.

Why this exists: with zero findings, the close-out was previously an
ad-hoc, free-form human summary -- coverage, refuted-hypothesis reasoning,
and remaining surfaces were not preserved structurally, so "no finding"
lost its WHY, and a future engagement had to re-derive what was already
refuted from scratch instead of loading it.

Same offline, read-only, evidence-cited pattern as this repo's other P2
signal modules (postmortem.py/coverage_signal.py/negative_knowledge.py):
case_store.resolve_db_path() + isfile() pre-check, case_export() only,
every free-text field redacted, no case_store WRITE function ever called
by build_close_out() itself. Composes coverage_signal.compute_coverage()
rather than re-deriving the same signal -- the one genuinely new piece
those existing modules don't already surface is REFUTED hypotheses' own
observation/hypothesis/note text: postmortem.py deliberately excludes
terminal states (it reports what's still STALLED/hanging, not what was
already resolved negative).

save_close_out()/load_close_out() are the one write/read-from-disk pair
this module performs -- writing the close-out record itself to a file
(not a case_store mutation), same category as report-agent's own
report-writing. was_already_refuted() is the actual "avoid re-testing a
closed path" check a later session runs against a loaded record: a
simple case-insensitive substring match against already-REFUTED
hypothesis text -- a heuristic prompt to look closer, not a semantic
guarantee.
"""

from __future__ import annotations

import json
import os
import sys

try:
    import case_store
    import coverage_signal
    import engagement_paths
    import file_lock
    from redact import redact_text
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import case_store
    import coverage_signal
    import engagement_paths
    import file_lock
    from redact import redact_text


def build_close_out(db_path: str | None = None) -> dict:
    """Read-only. Returns {"error": ...} if there's no case.db yet to
    close out (same not-found convention as coverage_signal.py/
    postmortem.py), else {"refuted_hypotheses": [...], "coverage": {...}}."""
    resolved_db_path = case_store.resolve_db_path(db_path)
    if not os.path.isfile(resolved_db_path):
        return {"error": f"no case.db found at {resolved_db_path!r} -- nothing to close out yet"}

    raw = json.loads(case_store.case_export(db_path=resolved_db_path))

    refuted = []
    for h in raw["hypotheses"]:
        if h["status"] != "REFUTED":
            continue
        refuted.append({
            "id": h["id"],
            "observation": redact_text(h["observation"]),
            "hypothesis": redact_text(h["hypothesis"]),
            "reason": redact_text(h.get("note") or ""),
        })

    return {
        "refuted_hypotheses": refuted,
        "coverage": coverage_signal.compute_coverage(db_path=resolved_db_path),
    }


def save_close_out(record: dict, path: str | None = None) -> str:
    """SECURITY/correctness: close-out.json is the same per-engagement
    JSON state-file shape file_lock.py's own docstring exists for (budget.
    json/work-registry.json/findings-seen.json/scan-escalation.json all
    lock this exact read-modify-write shape) -- a code-review finding
    caught this module using plain open() with no locking, unlike its
    scan_escalation.py sibling built in the same batch, which already had
    the identical gap found and fixed in an earlier review pass."""
    if path is None:
        path = engagement_paths.resolve("close-out.json", override_env="HUNTMCP_CLOSE_OUT_PATH")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with file_lock.locked(path), open(path, "w") as f:
        json.dump(record, f, indent=2)
    return path


def load_close_out(path: str | None = None) -> dict | None:
    """Locked even though read-only (see save_close_out()'s own comment)
    -- a plain open+write isn't atomic, so an unlocked read can observe a
    torn/partial JSON file mid-write. The isfile() check is inside the
    lock too, closing a TOCTOU gap between checking existence and opening
    the file."""
    if path is None:
        path = engagement_paths.resolve("close-out.json", override_env="HUNTMCP_CLOSE_OUT_PATH")
    with file_lock.locked(path):
        if not os.path.isfile(path):
            return None
        with open(path) as f:
            return json.load(f)


def was_already_refuted(text: str, loaded_close_out: dict) -> dict | None:
    """Does `text` (an endpoint, a hypothesis phrase, a technique name)
    appear in any already-REFUTED hypothesis's observation/hypothesis/
    reason text? Returns the matching refuted-hypothesis record (so the
    caller can read WHY it was refuted before deciding whether to
    re-test), or None. Case-insensitive substring match -- a prompt to
    look closer before spending budget re-testing, not a guarantee the
    two are the same underlying test."""
    needle = text.lower()
    for entry in loaded_close_out.get("refuted_hypotheses", []):
        haystack = f"{entry['observation']} {entry['hypothesis']} {entry['reason']}".lower()
        if needle in haystack:
            return entry
    return None
