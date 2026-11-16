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
import re
import sys

try:
    import case_store
    from redact import redact_text
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import case_store
    from redact import redact_text

# P4-COVMATRIX role source. case_store has NO role column -- the one structured
# role tag the data model records today is authz_diff.emit_finding()'s finding
# `parameter`, written as "<carried_path>@<identity>" (identity names match
# authz_diff._MATRIX_NAME_RE, i.e. [A-Za-z0-9_-]{1,32}). We parse that trailing
# "@<identity>" rather than import authz_diff, so this offline reader stays
# dependency-light and never triggers that module's own import side effects.
# Honest, documented limitation (same standard as P2-COV's own boundary note):
# this is the ONLY role signal in the current schema, so every finding that is
# not an authz-matrix row is "unroled" (sentinel below). A richer, first-class
# role inventory would need a schema change -- deliberately out of scope for a
# read-only/additive P4 item. A `parameter` that happens to end in
# "@<short-token>" for an unrelated reason would be read as a role; no in-repo
# producer does that, and this is an advisory signal, so that edge is accepted,
# not guarded, rather than coupling to one vuln_class's naming.
UNROLED = "-"
_ROLE_SUFFIX_RE = re.compile(r"^.+@(?P<role>[A-Za-z0-9_-]{1,32})$")


def _role_from_parameter(parameter: str | None) -> str:
    """The identity tag from a "<carried_path>@<identity>" finding parameter,
    or the UNROLED sentinel when the parameter carries no such tag."""
    m = _ROLE_SUFFIX_RE.match(parameter or "")
    return m.group("role") if m else UNROLED


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


def compute_coverage_matrix(db_path: str | None = None) -> dict:
    """P4-COVMATRIX (MASTER-ROADMAP-FINAL-v3.md §4/§5(P4), H3): the full
    endpoint x vuln_class x role coverage matrix, WITH an anti-gaming clause.
    Offline, read-only, additive -- reads ONLY via case_export (no writes, no
    new table/column/migration), same TOCTOU-safe resolve-then-isfile pattern
    as compute_coverage above.

    This EXTENDS P2-COV's compute_coverage, it does not replace it:
      * adds the ROLE axis (see _role_from_parameter / UNROLED), so each cell
        is an (endpoint, vuln_class, role) triple, not just a pair; and
      * upgrades the "covered" predicate from P2-COV's "a finding exists"
        (tested surface) to an EVIDENCE-BACKED one.

    Anti-gaming clause (the point of this task; .claude/rules/benchmarks.md:
    "a cost/efficiency improvement is not valid if it reduces required
    security quality"; a non-gameable coverage metric). A cell is `covered`
    iff at least one of its findings has >= 1 linked evidence row -- a
    content-addressed captured artifact, the same bar case_store itself uses
    to gate CONFIRMED ("no evidence = no confirmed finding"). WHY evidence and
    not a bare finding: if "covered" meant "a finding exists for the triple,"
    an agent could inflate the metric to anything by spamming empty finding
    declarations across triples with zero real testing. Requiring an evidence
    row means moving the covered count takes an actual captured artifact per
    triple -- real work -- not a self-asserted status flag or an incrementable
    counter. A logged experiment is surfaced per cell as context
    (`experiment_count`) but is deliberately NOT sufficient for covered: an
    experiment row is a logged intent-to-run with no retained artifact, a
    weaker and more trivially-forgeable signal than captured evidence. Cells
    with finding(s) but no evidence are `covered=False` and counted in
    `uncovered` -- a coverage CLAIM not yet backed by evidence is surfaced
    transparently, never silently counted as coverage.

    Returns {"error": ...} (without creating a case.db) when none exists yet.
    Otherwise:
      cells        -- one per observed (endpoint, vuln_class, role) triple
                      (a triple with >= 1 finding), each:
                        {endpoint, vuln_class, role, covered,
                         evidence_count, experiment_count, finding_count,
                         finding_ids, by_status}
                      endpoint/vuln_class/role redacted; sorted by raw triple.
      covered      -- count of cells with covered True
      uncovered    -- count of cells with covered False
      endpoints    -- distinct endpoints observed
      vuln_classes -- distinct vuln_classes observed
      roles        -- sorted distinct roles observed (UNROLED included)
      role_gaps    -- H3 role-coverage view, the partial-coverage signal: for
                      each (endpoint, vuln_class) pair that is covered for at
                      least one named role, the OTHER named roles (UNROLED
                      excluded) observed in this engagement that are NOT
                      covered for this pair -- i.e. "you covered this
                      endpoint+class for some roles but not this one." Pairs
                      covered for no role at all are omitted: those are simply
                      fully-uncovered cells (already in `cells`/`uncovered`),
                      not a per-role gap -- listing every role for them would
                      be noise. Bounded by the roles actually observed (no
                      fabricated universe / false denominator). [] when no
                      named role is covered anywhere.
    """
    resolved_db_path = case_store.resolve_db_path(db_path)
    if not os.path.isfile(resolved_db_path):
        return {"error": f"no case.db found at {resolved_db_path!r} -- nothing to analyze yet"}

    raw = json.loads(case_store.case_export(db_path=resolved_db_path))

    # Evidence / experiment rows backing each finding (finding_id may be None
    # when a row is linked only to a hypothesis -- those back no finding cell).
    evidence_by_finding: dict[int, int] = {}
    for e in raw["evidence"]:
        fid = e.get("finding_id")
        if fid is not None:
            evidence_by_finding[fid] = evidence_by_finding.get(fid, 0) + 1
    experiment_by_finding: dict[int, int] = {}
    for x in raw["experiments"]:
        fid = x.get("finding_id")
        if fid is not None:
            experiment_by_finding[fid] = experiment_by_finding.get(fid, 0) + 1

    # Group findings into (endpoint, vuln_class, role) cells, keyed on RAW
    # values so grouping/sorting never depend on redaction.
    cells: dict[tuple[str, str, str], dict] = {}
    for f in raw["findings"]:
        endpoint = f["endpoint"]
        vuln_class = f["vuln_class"]
        role = _role_from_parameter(f.get("parameter"))
        key = (endpoint, vuln_class, role)
        cell = cells.setdefault(key, {
            "finding_ids": [], "evidence_count": 0, "experiment_count": 0, "by_status": {},
        })
        cell["finding_ids"].append(f["id"])
        cell["evidence_count"] += evidence_by_finding.get(f["id"], 0)
        cell["experiment_count"] += experiment_by_finding.get(f["id"], 0)
        cell["by_status"][f["status"]] = cell["by_status"].get(f["status"], 0) + 1

    out_cells = []
    endpoints: set[str] = set()
    vuln_classes: set[str] = set()
    roles: set[str] = set()
    covered_pair_roles: dict[tuple[str, str], set[str]] = {}
    for (endpoint, vuln_class, role) in sorted(cells):
        cell = cells[(endpoint, vuln_class, role)]
        covered = cell["evidence_count"] > 0
        endpoints.add(endpoint)
        vuln_classes.add(vuln_class)
        roles.add(role)
        if covered and role != UNROLED:
            covered_pair_roles.setdefault((endpoint, vuln_class), set()).add(role)
        out_cells.append({
            "endpoint": redact_text(endpoint),
            "vuln_class": redact_text(vuln_class),
            "role": redact_text(role),
            "covered": covered,
            "evidence_count": cell["evidence_count"],
            "experiment_count": cell["experiment_count"],
            "finding_count": len(cell["finding_ids"]),
            "finding_ids": sorted(cell["finding_ids"]),
            "by_status": cell["by_status"],
        })

    named_roles = {r for r in roles if r != UNROLED}
    role_gaps = []
    for (endpoint, vuln_class) in sorted(covered_pair_roles):
        uncovered = sorted(named_roles - covered_pair_roles[(endpoint, vuln_class)])
        if uncovered:
            role_gaps.append({
                "endpoint": redact_text(endpoint),
                "vuln_class": redact_text(vuln_class),
                "uncovered_roles": [redact_text(r) for r in uncovered],
            })

    covered_n = sum(1 for c in out_cells if c["covered"])
    return {
        "cells": out_cells,
        "covered": covered_n,
        "uncovered": len(out_cells) - covered_n,
        "endpoints": len(endpoints),
        "vuln_classes": len(vuln_classes),
        "roles": sorted(roles),
        "role_gaps": role_gaps,
    }
