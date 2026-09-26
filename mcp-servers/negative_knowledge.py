"""P2-NK (part 1/2) -- negative-knowledge signal: an offline, read-only
report of which (tool, vuln_class) pairs an engagement's own recorded
experiments have shown to be effective vs ineffective, evidence-cited
against real case_store rows.

MASTER-ROADMAP-PROPOSAL.md P2-N1 ("Structured, actionable negative
knowledge", Opp-4/UU-4): "(technique/tool, context-signature) -> outcome
tally; hints-not-skips." MASTER-ROADMAP-FINAL-v3.md §11-A states the
absolute invariant this module is built around: "allocation/dedupe/
negative-knowledge never hard-block a not-yet-confirmed novel test" (hints,
never skips) -- this module has NO mechanism capable of preventing a tool
call. It only returns advisory data for something else to read; nothing
here can gate, block, or skip anything (enforced structurally by
test_negative_knowledge.py's own grep of this module's source).

Grounded in data that actually flows in this codebase today, not the
proposal's original source list verbatim (lessons_store.py turned out to be
free-text markdown, not a structured store -- exactly the gap the proposal
itself was trying to close; audit_log.jsonl tracks PROCESS-level outcome
(did the tool crash), not technique EFFECTIVENESS against a target). The
real, already-populated signal is case_store.experiments joined to the
finding_id it ran against: an experiment linked to a finding that reached
CONFIRMED/IMPACT_PROVEN was effective; linked to a finding marked
FALSE_POSITIVE was ineffective. An experiment with no finding_id (pure
recon) or a finding still in flight (DISCOVERED/SUSPECTED/VALIDATING/
INCONCLUSIVE -- not yet resolved either way) is excluded from the tally
entirely, not counted as ineffective -- the same in-flight-vs-abandoned
caution postmortem.py's own STALLED_HYPOTHESIS_STATUSES design already
established: counting an unresolved investigation as a failure would
falsely deprioritize a technique that just hasn't finished being tried yet.

Honest v1 boundary, not silently overclaimed: this is a WITHIN-ENGAGEMENT
signal only (case_store.db is per-engagement). The proposal's fuller
ambition -- informing a FUTURE, different hunt via a cross-engagement store
with TTL/target-stack-version context -- would need its own persistent,
global store (like tool_gaps.py's data/tool-gaps.jsonl) and is a real,
larger increment left for a later task, not built here.
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

INEFFECTIVE_FINDING_STATUS = "FALSE_POSITIVE"

# case-mcp/server.py's own docstring: "DISCOVERED -> SUSPECTED -> VALIDATING
# -> CONFIRMED -> IMPACT_PROVEN -> REPORTED, or off to
# FALSE_POSITIVE/DUPLICATE/INCONCLUSIVE at any point." REPORTED is the
# TERMINAL success state, reached only after CONFIRMED/IMPACT_PROVEN -- NOT
# an in-flight status (code-review finding, 2026-09-25: an earlier version
# checked only case_store.EVIDENCE_GATED_STATUSES, which excludes REPORTED,
# so a finding that progressed past IMPACT_PROVEN silently lost its
# effective data point). DUPLICATE is deliberately NOT included here even
# though it's also a terminal/resolved status -- unlike REPORTED it can be
# reached "at any point," including before real validation, so it doesn't
# prove the technique found something real the way passing through
# CONFIRMED/IMPACT_PROVEN does; it stays excluded from the tally, same as
# the genuinely in-flight statuses.
EFFECTIVE_FINDING_STATUSES = case_store.EVIDENCE_GATED_STATUSES | {"REPORTED"}


def compute_negative_knowledge(db_path: str | None = None) -> dict:
    """Offline, read-only (same pattern as postmortem.py/coverage_signal.py:
    case_store.resolve_db_path() + isfile() pre-check, then case_export()
    with the already-resolved path -- never re-resolves independently, so
    this has no TOCTOU window on a mid-call engagement switch). Returns
    {"tally": {"<tool>::<vuln_class>": {...}}, "hints": [...]}. `hints` lists
    every key whose effective_count is 0 and ineffective_count > 0 -- a
    technique that has NEVER worked against this vuln_class in this
    engagement so far. Advisory only: nothing reads `hints` to block
    anything today; it exists for a future consumer (e.g. a Skill Router)
    to weight against, never to gate."""
    resolved_db_path = case_store.resolve_db_path(db_path)
    if not os.path.isfile(resolved_db_path):
        return {"error": f"no case.db found at {resolved_db_path!r} -- nothing to analyze yet"}

    raw = json.loads(case_store.case_export(db_path=resolved_db_path))
    findings_by_id = {f["id"]: f for f in raw["findings"]}

    tally: dict[str, dict] = {}
    for exp in raw["experiments"]:
        finding_id = exp["finding_id"]
        if finding_id is None:
            continue
        finding = findings_by_id.get(finding_id)
        if finding is None:
            continue

        status = finding["status"]
        if status in EFFECTIVE_FINDING_STATUSES:
            effective, ineffective = 1, 0
        elif status == INEFFECTIVE_FINDING_STATUS:
            effective, ineffective = 0, 1
        else:
            continue  # in-flight -- not yet resolved either way, excluded

        # redact before use -- vuln_class is agent-supplied free text
        # (case-mcp/server.py's create_finding() takes it as a plain str,
        # no enum enforcement), same defense-in-depth as postmortem.py/
        # coverage_signal.py's own redaction of this exact field.
        tool = redact_text(exp["tool"])
        vuln_class = redact_text(finding["vuln_class"])
        key = f"{tool}::{vuln_class}"
        entry = tally.setdefault(key, {
            "tool": tool, "vuln_class": vuln_class, "effective_count": 0, "ineffective_count": 0,
        })
        entry["effective_count"] += effective
        entry["ineffective_count"] += ineffective

    hints = sorted(k for k, v in tally.items() if v["effective_count"] == 0 and v["ineffective_count"] > 0)
    return {"tally": tally, "hints": hints}
