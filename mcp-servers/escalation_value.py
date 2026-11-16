"""P4-ESCALATE -- human escalation as an INFORMATION-VALUE mechanism, not an
approval-fatigue machine.

MASTER-ROADMAP-FINAL-v3.md section 5 (Phase 4) and IMPLEMENTATION-TASK-TRACKER.md
(P4-ESCALATE, dep P2-TEL): the point is to spend a human's LIMITED attention on
high-value decisions -- rank candidate human escalations by their information /
decision value so a person is interrupted when it is genuinely worth it, and
low-value ones can be batched or deferred. This directly reduces approval
fatigue instead of manufacturing it.

The never-suppress invariant (section 11-A), the reason this module is written
the way it is
------------------------------------------------------------------------------
This layer is ADVISORY and ADDITIVE only. It may say "this is high information
value, surface it" or "this is low value, it can wait / batch it" -- but it can
NEVER turn a mandatory human-in-the-loop control into "skip the human". Section
11-A's absolute invariants that bear on this module:

  * human-review-before-submit is preserved (hackerone-mcp has no submit tool by
    design; a finding is never auto-submitted), and
  * allocation/dedupe/negative-knowledge "never hard-block a not-yet-confirmed
    novel test" (hints, never skips).

So the guarantee here is structural, not a promise in prose:

  * A candidate marked `required=True` -- any safety-, authorization-, scope-,
    state-change-, or human-review-before-submit-bearing checkpoint -- is ALWAYS
    assigned `recommendation = "surface_now"` and ranked first. Its information-
    value score is NEVER consulted for its recommendation. There is literally no
    code path in `rank_escalations()` that assigns "batch" or "defer" to a
    required candidate (`test_rank_*` assert this across the whole 0..100 score
    range). The info-value score therefore only ever ADDS prioritization on top
    of mandatory checkpoints; it can never subtract one away.

  * This module has NO mechanism to run, gate, skip, defer, or hard-block a
    TEST. It ranks human-DECISION escalations only. It never writes case state,
    never calls a tool, never touches tool_resolver/job_runtime/scope_guard/
    budget_guard (`test_module_has_no_write_or_tool_calls` asserts this
    structurally). The §11-A "never hard-block a novel test" invariant is
    untouched because there is nothing here capable of blocking a test.

What counts as a candidate escalation (derived from real case state only)
------------------------------------------------------------------------
Offline, read-only, over the current `case.db`, same precedent as
negative_knowledge.py / coverage_signal.py / causal_signature.py
(resolve_db_path() + isfile() pre-check + case_export(), no independent
re-resolution, no TOCTOU window). No fabrication: only findings already in the
store become escalations.

  REQUIRED (always surfaced, never scored away):
    * `review_before_submit` -- a finding at CONFIRMED or IMPACT_PROVEN that has
      not yet reached REPORTED. It is validated/reproduced and a candidate to be
      written up and submitted; the human-review-before-submit control means a
      person MUST review the draft before it is submitted. The info-value layer
      must never tell the agent to skip that review, so these are required.
      (A REPORTED finding already passed that checkpoint; a DISMISSED one --
      FALSE_POSITIVE/DUPLICATE -- has no pending decision.)

  DISCRETIONARY (scored; may be batched/deferred):
    * `decision` -- an in-flight finding (SUSPECTED / VALIDATING / INCONCLUSIVE)
      where asking a human is a genuine judgment call, not mandatory. A fresh,
      untouched DISCOVERED finding is excluded: there is no human decision
      pending on it yet.

Information-value scoring (explicit, justified, REAL signals only)
-----------------------------------------------------------------
case_store.py's own module docstring warns against "confidence theater" -- a
formula over invented numbers. Every input below is a real, already-recorded
signal, and the per-component breakdown is returned so a human can see WHY
something was prioritized (not a black box):

  * ambiguity (status) -- INCONCLUSIVE means the agent genuinely could not
    decide, the case most worth a human's judgement; VALIDATING / SUSPECTED are
    progressively less ambiguous. (CONFIRMED/IMPACT_PROVEN are not ambiguous, so
    a required finding scores 0 here -- which is exactly why the end-to-end
    safety test can prove a required finding surfaces despite a 0 score.)
  * stakes (confidence_score) -- the finding's own evidence-based confidence
    (case_store.score_finding_confidence(), a signal-sum, not an LLM self-
    rating), scaled -- a more-developed finding is a higher-stakes decision.
  * effort_exhausted (experiment_count, via P2-TEL) -- "would a cheap experiment
    resolve this instead of a human?" Few experiments run so far => a cheap
    experiment might still resolve it => LOWER value for interrupting a human now
    (let the agent try first -> batch/defer). Many already run => cheap options
    exhausted => HIGHER value (the human is now the cheapest way forward). The
    count comes from telemetry.finding_telemetry() (P2-TEL, this task's stated
    base/dependency) rather than re-querying experiments here, reusing that
    existing read-only aggregate.

The three bounded components sum and clamp to 0..100; thresholds then map the
score to surface_now / batch / defer (for DISCRETIONARY candidates only).
"""

from __future__ import annotations

import json
import os
import sys

try:
    import case_store
    import telemetry
    from redact import redact_text
except ImportError:  # pragma: no cover - import shim mirrors sibling modules
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import case_store
    import telemetry
    from redact import redact_text

# Recommendation vocabulary (advisory -- never an action).
SURFACE = "surface_now"
BATCH = "batch"
DEFER = "defer"

# Discretionary-score thresholds. Required candidates never reach these -- they
# bypass scoring entirely (see rank_escalations).
SURFACE_THRESHOLD = 50
BATCH_THRESHOLD = 25

# Finding statuses that are a REQUIRED human-review-before-submit checkpoint:
# validated/reproduced, not yet submitted. REPORTED is excluded (review already
# happened); FALSE_POSITIVE/DUPLICATE are dismissed (no pending decision).
REQUIRED_REVIEW_STATUSES = ("CONFIRMED", "IMPACT_PROVEN")

# In-flight statuses where escalating to a human is a discretionary judgment
# call. DISCOVERED is excluded (untouched -- nothing to decide yet).
DISCRETIONARY_STATUSES = ("SUSPECTED", "VALIDATING", "INCONCLUSIVE")

# Ambiguity weight by status: INCONCLUSIVE (agent could not decide) is the case
# most worth a human's judgement. Required-review statuses map to 0 -- a
# required finding's surfacing never depends on its score.
_AMBIGUITY = {"INCONCLUSIVE": 40, "VALIDATING": 15, "SUSPECTED": 10}

# experiment_count is capped before weighting so one noisy finding with hundreds
# of logged experiments can't dominate the ranking; 6 * 5 = 30 max, matching the
# other two components' bounded contribution.
_EFFORT_CAP = 6
_EFFORT_WEIGHT = 5
_STAKES_WEIGHT = 0.3  # confidence_score (0..100) -> up to 30


def _info_value(status: str, confidence_score: int, experiment_count: int) -> dict:
    """Compute the bounded information-value score and its auditable breakdown
    from real recorded signals. Pure: no I/O. Returns the component dict with a
    clamped 0..100 `value`."""
    ambiguity = _AMBIGUITY.get(status, 0)
    stakes = round(max(0, min(100, int(confidence_score or 0))) * _STAKES_WEIGHT)
    effort_exhausted = min(max(0, experiment_count), _EFFORT_CAP) * _EFFORT_WEIGHT
    value = max(0, min(100, ambiguity + stakes + effort_exhausted))
    return {
        "value": value,
        "ambiguity": ambiguity,
        "stakes": stakes,
        "effort_exhausted": effort_exhausted,
        "experiment_count": experiment_count,
    }


def rank_escalations(candidates: list[dict]) -> dict:
    """Assign an advisory recommendation to each candidate escalation and rank
    them. THE safety-critical function.

    A candidate marked `required=True` is ALWAYS `surface_now`, no matter its
    `info_value` -- its score is never consulted. Only `required=False`
    (discretionary) candidates are mapped by score to surface_now / batch /
    defer. There is deliberately no branch that assigns batch/defer to a
    required candidate, so a mandatory human checkpoint can never be suppressed
    (`test_rank_*`).

    Returns {"escalations": [ranked...], "surface_now": [...], "batch": [...],
    "defer": [...]} where the three buckets partition `escalations`. Required
    candidates are ranked first; within required and within discretionary,
    higher info_value first, finding_id as a stable tie-break.
    """
    ranked: list[dict] = []
    for raw in candidates:
        c = dict(raw)
        if c.get("required"):
            # NEVER scored away: a required/safety-bearing checkpoint is always
            # surfaced regardless of information value.
            c["recommendation"] = SURFACE
        else:
            value = int(c.get("info_value") or 0)
            if value >= SURFACE_THRESHOLD:
                c["recommendation"] = SURFACE
            elif value >= BATCH_THRESHOLD:
                c["recommendation"] = BATCH
            else:
                c["recommendation"] = DEFER
        ranked.append(c)

    ranked.sort(key=lambda c: (
        0 if c.get("required") else 1,
        -int(c.get("info_value") or 0),
        int(c.get("finding_id") or 0),
    ))

    buckets: dict[str, list[dict]] = {SURFACE: [], BATCH: [], DEFER: []}
    for c in ranked:
        buckets[c["recommendation"]].append(c)
    return {
        "escalations": ranked,
        "surface_now": buckets[SURFACE],
        "batch": buckets[BATCH],
        "defer": buckets[DEFER],
    }


def _candidate_for_finding(finding: dict, resolved_db_path: str) -> dict | None:
    """Build one escalation candidate from a finding row, or None if the finding
    is not a pending escalation. Read-only."""
    status = finding["status"]
    required = status in REQUIRED_REVIEW_STATUSES
    discretionary = status in DISCRETIONARY_STATUSES
    if not (required or discretionary):
        return None

    # P2-TEL: reuse the existing read-only per-finding aggregate for the effort
    # signal instead of re-querying experiments here.
    tel = telemetry.finding_telemetry(finding["id"], db_path=resolved_db_path)
    experiment_count = 0 if "error" in tel else int(tel.get("experiment_count") or 0)

    breakdown = _info_value(status, finding.get("confidence_score", 0), experiment_count)

    # endpoint / vuln_class are agent-supplied free text (create_finding takes
    # them as plain str, no enum enforcement) -- redact before surfacing, same
    # defense-in-depth as negative_knowledge.py / coverage_signal.py.
    candidate = {
        "finding_id": finding["id"],
        "kind": "review_before_submit" if required else "decision",
        "required": required,
        "status": status,
        "vuln_class": redact_text(finding["vuln_class"]),
        "endpoint": redact_text(finding["endpoint"]),
        "info_value": breakdown["value"],
        "info_value_breakdown": {k: breakdown[k] for k in
                                 ("ambiguity", "stakes", "effort_exhausted", "experiment_count")},
    }
    if required:
        candidate["reason"] = (
            f"{status} finding -- mandatory human-review-before-submit checkpoint; "
            "always surfaced, never scored away."
        )
    else:
        candidate["reason"] = (
            f"{status} finding -- discretionary human decision; ranked by information value "
            f"({breakdown['value']}/100)."
        )
    return candidate


def compute_escalation_value(db_path: str | None = None) -> dict:
    """Offline, read-only information-value ranking of the current case's
    candidate human escalations.

    Derives candidates from finding state (no new store/table/write-path), scores
    the discretionary ones, and hands everything to rank_escalations() -- which
    guarantees any required checkpoint is always surfaced. Advisory only: it
    recommends, it never acts, suppresses, or blocks anything.

    Returns rank_escalations()'s shape, or {"error": ...} when no case.db exists
    yet (and never creates one -- same not-found convention as the sibling
    analysis modules).
    """
    resolved_db_path = case_store.resolve_db_path(db_path)
    if not os.path.isfile(resolved_db_path):
        return {"error": f"no case.db found at {resolved_db_path!r} -- nothing to analyze yet"}

    raw = json.loads(case_store.case_export(db_path=resolved_db_path))
    candidates = []
    for finding in raw["findings"]:
        candidate = _candidate_for_finding(finding, resolved_db_path)
        if candidate is not None:
            candidates.append(candidate)
    return rank_escalations(candidates)
