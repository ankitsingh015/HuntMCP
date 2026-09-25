"""P2-E1 -- hunt postmortem / self-evaluation: an offline, read-only,
analysis-only report over one engagement's already-recorded case_store +
audit_log state.

MASTER-ROADMAP-FINAL-v3.md Sec5(P2)/Sec15, IMPLEMENTATION-TASK-TRACKER.md P2-E1:
"analysis-only, read-only, no tools, no auto-retry, no self-modification,
no policy mutation; offline post-hunt analyzer; evidence-cited (cites
audit_log/case_store); planted-fixture precision/recall; independent
verification vs raw stores; redaction verified."

Why read-only, not an agent: this module NEVER calls any case_store WRITE
function (log_hypothesis/update_hypothesis/add_evidence/log_experiment/
create_finding/update_finding_status/score_finding_confidence/
group_root_cause/cem_define/cem_record_trial/cem_record_verdict/
cem_mark_incomplete), never calls dedupe_check's check_and_record (which
writes findings-seen.json), never imports tool_resolver/job_runtime/
scope_guard/budget_guard, and issues zero subprocess/network calls --
test_postmortem.py::test_run_postmortem_never_mutates_the_case_store
proves this at runtime (case_store.case_export() is byte-for-byte
unchanged before/after a run_postmortem() call, not just "we didn't call
the functions we know about"), and
test_postmortem_module_has_no_write_or_tool_calls proves it structurally
(grepping this module's own source for every case_store write function
name and every subprocess/tool-dispatch module name).

What it reports: hypotheses and findings that never reached a terminal
state (STALLED -- the "what got left hanging" signal a human wrap-up
review actually wants), evidence/experiment/root-cause totals, and
P2-TEL's own telemetry.audit_log_totals() for cost -- everything
evidence-cited by the real case_store id it came from, never free prose
with no way to trace it back to a row. Every free-text field
(observation/hypothesis/vuln_class/endpoint/parameter) is passed through
redact.redact_text() before being included in the report, so a hunter's
own accidentally-logged secret in a hypothesis note doesn't leak a second
time through the postmortem's own output.

Deliberately minimal -- this is the P2 floor, not the full self-evaluation
system. Extended (not rebuilt) by P4-PM+ (e.g. missed_chain_opportunities);
that task's job, not this one's.
"""

from __future__ import annotations

import json
import os
import sys

try:
    import case_store
    import telemetry
    from redact import redact_text
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import case_store
    import telemetry
    from redact import redact_text

# Hypotheses/findings NOT in one of these sets are still "in flight" by
# case_store.py's own status vocabulary (HYPOTHESIS_STATUSES/
# FINDING_STATUSES) -- i.e. never reached a resolved/terminal state.
# SUPPORTED is deliberately included (code-review finding): a hypothesis
# with some supporting evidence that never advanced to CONFIRMED/REFUTED/
# INCONCLUSIVE is arguably the MOST bounty-relevant kind of hanging thread
# (partial signal, never followed through), not less stalled than NEW.
STALLED_HYPOTHESIS_STATUSES = {"NEW", "TESTING", "SUPPORTED"}
UNRESOLVED_FINDING_STATUSES = {"DISCOVERED", "SUSPECTED", "VALIDATING", "INCONCLUSIVE"}

# Honest limit (code-review finding, not fixed here -- deliberately out of
# this task's minimal P2 scope, matching the roadmap's own "narrower
# postmortem; never grant action" framing): this module has no signal for
# whether the ENGAGEMENT itself has concluded. A finding legitimately still
# VALIDATING because the hunt is ongoing is indistinguishable here from one
# genuinely abandoned mid-hunt -- both show up in `unresolved_findings`.
# Run this at the END of an engagement for the "stalled/unresolved" lists
# to mean "missed," not "still in progress." P4-PM+ (which extends this
# module, not rebuilds it) is the natural place to add that distinction if
# a reliable engagement-completion signal becomes available.


def _redact(value: str) -> str:
    return redact_text(value) if isinstance(value, str) else value


def run_postmortem(db_path: str | None = None, audit_log_path: str | None = None) -> dict:
    """Offline, read-only postmortem over one engagement. Reads ONLY via
    case_store.case_export() (already a read-only export -- no new query
    surface added here) and telemetry.audit_log_totals() (already
    read-only, P2-TEL) -- issues no writes, no tool calls, no retries.

    Checks os.path.isfile() BEFORE calling case_export() (round-2 security
    review, CONFIRMED live): case_store._get_conn() unconditionally runs
    os.makedirs()/CREATE TABLE IF NOT EXISTS regardless of read-vs-write
    intent, so calling case_export() against a path with no case.db yet
    would silently materialize a fresh, empty one from nothing -- directly
    contradicting this module's own "issues no writes" claim for exactly
    the standalone/speculative/stale-path call this module is meant to
    support. Returns {"error": ...} instead, matching case_store.py's own
    not-found convention, without ever opening a connection.

    Passes the ALREADY-resolved path to case_export() below, not the
    original (possibly None) db_path (code-review finding, 2026-09-25):
    calling case_export(db_path=db_path) with db_path still None would
    let it re-resolve the active engagement independently inside its own
    _get_conn() -- a second, separate resolution that could disagree with
    the one just isfile()-checked above if the active engagement were
    switched by another process in between. Passing resolved_db_path
    through makes both checks agree by construction."""
    resolved_db_path = case_store.resolve_db_path(db_path)
    if not os.path.isfile(resolved_db_path):
        return {"error": f"no case.db found at {resolved_db_path!r} -- nothing to analyze yet"}

    raw = json.loads(case_store.case_export(db_path=resolved_db_path))

    hypothesis_counts: dict[str, int] = {}
    stalled_hypotheses = []
    for h in raw["hypotheses"]:
        hypothesis_counts[h["status"]] = hypothesis_counts.get(h["status"], 0) + 1
        if h["status"] in STALLED_HYPOTHESIS_STATUSES:
            stalled_hypotheses.append({
                "id": h["id"],
                "status": h["status"],
                "observation": _redact(h["observation"]),
                "hypothesis": _redact(h["hypothesis"]),
            })

    finding_counts: dict[str, int] = {}
    unresolved_findings = []
    for f in raw["findings"]:
        finding_counts[f["status"]] = finding_counts.get(f["status"], 0) + 1
        if f["status"] in UNRESOLVED_FINDING_STATUSES:
            unresolved_findings.append({
                "id": f["id"],
                "status": f["status"],
                "vuln_class": _redact(f["vuln_class"]),
                "endpoint": _redact(f["endpoint"]),
                "parameter": _redact(f["parameter"]),
            })

    return {
        "hypothesis_counts": hypothesis_counts,
        "finding_counts": finding_counts,
        "stalled_hypotheses": stalled_hypotheses,
        "unresolved_findings": unresolved_findings,
        "evidence_total": len(raw["evidence"]),
        "experiment_total": len(raw["experiments"]),
        "root_cause_total": len(raw["root_causes"]),
        "telemetry": telemetry.audit_log_totals(audit_log_path),
    }
