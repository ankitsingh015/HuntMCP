"""P2-COV -- minimal coverage instrument (Xalgorix H3 "core"): an offline,
read-only signal reporting which (endpoint, vuln_class) pairs an engagement
has actually tested, evidence-cited against real case_store finding rows.

MASTER-ROADMAP-FINAL-v3.md P2-COV: "Minimal coverage instrument (H3 core) --
produce the coverage signal used in P2/P3. Why: metric must exist before it
is a decision signal." Deliberately the SMALLER of two H3-named items in the
roadmap, not the full P4-COVMATRIX: FINAL-MASTER-ROADMAP-REVIEW.md's own
F-M-6/F-H-4 findings explicitly called out that "coverage" was used in P2/P3
acceptance criteria before its instrument existed, and that the fix is "a
minimal Phase-2 coverage signal DISTINCT FROM the Phase-4 H3 matrix" -- this
module is that minimal signal, not a redefinition of the full matrix.

Honest limit, not silently overclaimed (same standard as every other P2
module in this repo): this reports TESTED surface only -- which
(endpoint, vuln_class) pairs have at least one case_store finding -- not a
true coverage RATIO against the target's total attack surface. There is no
independently-discovered-endpoint inventory in this codebase yet to divide
by, and building one here would silently absorb P4-COVMATRIX's own stated
job (endpoint x class x role, WITH an anti-gaming clause so an agent can't
inflate its own score by only counting a small, self-chosen surface as "the
total"). Until that lands, "coverage" from this module means "what we
tried," not "what fraction of what exists."

Why read-only, not an agent: matches P2-TEL/P2-E1's own established pattern
for offline P2 signal modules. Reads ONLY via case_store.case_export()
(already a read-only export -- no new query surface added), never calls a
case_store WRITE function, never imports tool_resolver/job_runtime/
scope_guard/budget_guard -- test_coverage_signal.py's own
test_coverage_module_has_no_write_or_tool_calls proves this structurally
(grepping the module's own source, docstring excluded), and
test_compute_coverage_never_mutates_the_case_store proves it at runtime
(case_export() byte-for-byte unchanged before/after a real call).
"""

from __future__ import annotations

import json
import os
import sys

try:
    import case_store
    from redact import redact_text
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import case_store
    from redact import redact_text


def compute_coverage(db_path: str | None = None) -> dict:
    """Offline, read-only coverage signal over one engagement's case_store.

    Reads ONLY via case_store.case_export() -- issues no writes. Checks
    os.path.isfile() first via case_store.resolve_db_path() (same pattern
    as postmortem.run_postmortem()) so a standalone/stale-path call never
    accidentally materializes an empty case.db from nothing. Returns
    {"error": ...} instead, matching case_store.py's own not-found
    convention, if there's genuinely nothing to read yet."""
    resolved_db_path = case_store.resolve_db_path(db_path)
    if not os.path.isfile(resolved_db_path):
        return {"error": f"no case.db found at {resolved_db_path!r} -- nothing to analyze yet"}

    raw = json.loads(case_store.case_export(db_path=resolved_db_path))

    endpoints_tested: set[str] = set()
    vuln_classes_tested: set[str] = set()
    pairs_tested: set[tuple[str, str]] = set()
    by_status: dict[str, int] = {}
    coverage_matrix = []

    for f in raw["findings"]:
        endpoint = f["endpoint"]
        vuln_class = f["vuln_class"]
        status = f["status"]
        endpoints_tested.add(endpoint)
        vuln_classes_tested.add(vuln_class)
        pairs_tested.add((endpoint, vuln_class))
        by_status[status] = by_status.get(status, 0) + 1
        coverage_matrix.append({
            "endpoint": redact_text(endpoint),
            "vuln_class": redact_text(vuln_class),
            "finding_id": f["id"],
            "status": status,
        })

    return {
        "pairs_tested": len(pairs_tested),
        "endpoints_tested": len(endpoints_tested),
        "vuln_classes_tested": len(vuln_classes_tested),
        "by_status": by_status,
        "coverage_matrix": coverage_matrix,
    }
