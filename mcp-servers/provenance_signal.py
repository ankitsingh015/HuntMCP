"""C1a (part 2/3) -- provenance coverage signal: an offline, read-only
report of what fraction of stored evidence carries real provenance
metadata (MASTER-ROADMAP-FINAL-v3.md §8's "wire" vs "invocation" tiers),
evidence-cited by row id, so the roadmap's own acceptance/exit criterion
("provenance verified on stored findings") is checkable instead of a
documentation-only claim -- same reasoning P2-COV's coverage_signal.py
already established for "coverage."

Reads ONLY via case_store.case_export() (already a read-only export) --
no new query surface. Never creates a case.db on a stale/absent path
(case_store.resolve_db_path() + isfile() pre-check, same TOCTOU-safe
pattern as postmortem.py/coverage_signal.py).
"""

from __future__ import annotations

import json
import os
import sys

try:
    import case_store
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import case_store


def compute_provenance_coverage(db_path: str | None = None) -> dict:
    """Returns {"totals": {"wire": N, "invocation": N, "none": N},
    "by_finding": {"<finding_id>": {"wire": [evidence_id, ...],
    "invocation": [...], "none": [...]}}}. Evidence linked only to a
    hypothesis (no finding_id) counts in `totals` but is deliberately
    excluded from `by_finding` -- attributing it to some finding it isn't
    actually linked to would be a false claim, not a coverage signal."""
    resolved_db_path = case_store.resolve_db_path(db_path)
    if not os.path.isfile(resolved_db_path):
        return {"error": f"no case.db found at {resolved_db_path!r} -- nothing to analyze yet"}

    raw = json.loads(case_store.case_export(db_path=resolved_db_path))

    totals = {"wire": 0, "invocation": 0, "none": 0}
    by_finding: dict[str, dict[str, list[int]]] = {}
    for ev in raw["evidence"]:
        provenance_json = ev.get("provenance_json")
        cls = json.loads(provenance_json)["class"] if provenance_json else "none"
        totals[cls] += 1

        finding_id = ev["finding_id"]
        if finding_id is None:
            continue
        entry = by_finding.setdefault(str(finding_id), {"wire": [], "invocation": [], "none": []})
        entry[cls].append(ev["id"])

    return {"totals": totals, "by_finding": by_finding}
