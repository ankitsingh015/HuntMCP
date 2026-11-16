"""Arm-agnostic LONG-HORIZON scoring contract (TEST-ONLY).

Consumes a normalized trajectory -- an ordered list[ObservedStep] plus a
{scenario_id -> ScenarioConclusion} map -- and the evaluator-only answer key, and
produces per-dimension outcomes.  ANY arm (HuntMCP's real pipeline, a future
frontier-only baseline, the golden reference arm in lh_harness) just needs to emit
this shape; this module never changes for a new arm.

Oracle independence is the core property: whether a claimed finding is REAL is
decided from the simulator's own independent event log + the explicit oracle
signature in the blind scenario index -- never from the arm's self-reported
verdict.  A `finding` verdict whose cited event does not actually exhibit the
planted leak earns no credit (an `unbacked_claim`).

Scoring vocabulary (per scenario outcome):
  hit                -- a planted finding correctly found AND backed by real evidence
  miss               -- a planted finding concluded absent
  inconclusive       -- the arm honestly declined to conclude (its own bucket)
  unbacked_claim     -- `finding` claimed but not backed by the event log
  correct_no_finding -- a genuinely-secure scenario correctly concluded "no finding"
  false_positive     -- a finding claimed on a genuinely-secure scenario

`inconclusive` is NEVER a miss and NEVER a false positive; a correct no-finding is
NEVER a miss.  False-causal-conclusion rate (FCCR) counts only `necessary` claims
on conditions whose ground truth is not necessary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple

import lh_answer_key as AK
import lh_scenarios as SC


class ObservedStep(NamedTuple):
    scenario: str
    epoch: int
    identity: str
    action: str
    event_ref: int          # index into the simulator's independent event log
    sig: str = ""


class HypRecord(NamedTuple):
    hyp_id: str
    status: str             # open | inconclusive | refuted | confirmed | resurrected
    at_step: int            # event-log index at which the arm set this status


@dataclass(frozen=True)
class ScenarioConclusion:
    verdict: str                                   # finding | no_finding | inconclusive
    condition_verdicts: dict = field(default_factory=dict)
    evidence_refs: dict = field(default_factory=dict)   # {"leak": idx} / {"baseline","perturbed"}
    hypotheses: tuple = ()                         # tuple[HypRecord]
    detected_change: bool = False
    recovered: bool = False


@dataclass(frozen=True)
class LhReport:
    per_scenario: dict
    per_dimension: dict
    hits: int
    misses: int
    inconclusive: int
    correct_no_finding: int
    false_positives: int
    unbacked_claims: int
    fccr: float
    fccr_numerator: int
    fccr_denominator: int
    version: str
    seed: int
    request_count: int


# --------------------------------------------------------------------------- #
# Oracle-independent helpers (read the SIMULATOR's own log, not the arm's claim)
# --------------------------------------------------------------------------- #
def _event(target, idx):
    if not isinstance(idx, int) or idx < 0 or idx >= len(target.events):
        return None
    return target.events[idx]


def _event_shows_leak(target, scenario: str, idx) -> bool:
    ev = _event(target, idx)
    if ev is None or ev["scenario"] != scenario:
        return False
    oracle = SC.SCENARIOS[scenario]["oracle"]["body_contains"]
    return oracle in ev["body"]


def _leak_ref(concl: ScenarioConclusion):
    refs = concl.evidence_refs
    return refs.get("leak", refs.get("perturbed"))


# --------------------------------------------------------------------------- #
# Kind-specific "is this finding genuinely backed?" predicates
# --------------------------------------------------------------------------- #
def _backed_point_finding(target, sid, concl) -> bool:
    return _event_shows_leak(target, sid, _leak_ref(concl))


def _backed_target_change(target, sid, concl) -> bool:
    idx = _leak_ref(concl)
    ev = _event(target, idx)
    return bool(concl.detected_change) and _event_shows_leak(target, sid, idx) and ev["epoch"] >= 1


def _backed_resurrection(target, sid, concl) -> bool:
    idx = _leak_ref(concl)
    if not _event_shows_leak(target, sid, idx):
        return False
    exp = AK.EXPECTED[sid]
    for h in concl.hypotheses:
        if (h.hyp_id == exp["hypothesis_id"] and h.status in ("resurrected", "confirmed")
                and h.at_step >= idx):
            return True
    return False


def _backed_recovery(target, sid, concl) -> bool:
    idx = _leak_ref(concl)
    if not (concl.recovered and _event_shows_leak(target, sid, idx)):
        return False
    fail_status = AK.EXPECTED[sid]["transient_failure_status"]
    # a transient failure on this scenario must PRECEDE the backed leak event
    return any(e["scenario"] == sid and e["status"] == fail_status and e["idx"] < idx
               for e in target.events)


_BACKERS = {
    "point_finding": _backed_point_finding,
    "target_change": _backed_target_change,
    "resurrection": _backed_resurrection,
    "recovery": _backed_recovery,
}


# --------------------------------------------------------------------------- #
def evaluate(target, steps: list, conclusions: dict) -> LhReport:
    """Deterministic given (target event log, conclusions)."""
    per_scenario: dict = {}
    per_dimension: dict = {}
    hits = misses = inconclusive = correct_no_finding = false_positives = unbacked = 0
    fccr_num = fccr_den = 0

    for sid, concl in conclusions.items():
        exp = AK.EXPECTED[sid]
        kind = exp["kind"]
        verdict = concl.verdict

        if kind == "no_finding":
            if verdict == "no_finding":
                outcome = "correct_no_finding"; correct_no_finding += 1
            elif verdict == "finding":
                outcome = "false_positive"; false_positives += 1
            else:
                outcome = "inconclusive"; inconclusive += 1
        else:
            if verdict == "finding":
                if _BACKERS[kind](target, sid, concl):
                    outcome = "hit"; hits += 1
                else:
                    outcome = "unbacked_claim"; unbacked += 1
            elif verdict == "no_finding":
                outcome = "miss"; misses += 1
            else:
                outcome = "inconclusive"; inconclusive += 1

        # FCCR: a `necessary` claim on a not-necessary condition (inconclusive never counts)
        for (sc, cond) in AK.MUST_NOT_BE_NECESSARY:
            if sc == sid:
                fccr_den += 1
                if concl.condition_verdicts.get(cond) == "necessary":
                    fccr_num += 1

        per_scenario[sid] = {"outcome": outcome, "verdict": verdict,
                             "dimension": AK.DIMENSION[sid]}
        per_dimension[AK.DIMENSION[sid]] = {"scenario": sid, "outcome": outcome}

    fccr = (fccr_num / fccr_den) if fccr_den else 0.0
    return LhReport(
        per_scenario=per_scenario, per_dimension=per_dimension,
        hits=hits, misses=misses, inconclusive=inconclusive,
        correct_no_finding=correct_no_finding, false_positives=false_positives,
        unbacked_claims=unbacked, fccr=fccr, fccr_numerator=fccr_num,
        fccr_denominator=fccr_den, version=SC.LH_BENCH_VERSION, seed=getattr(target, "seed", 0),
        request_count=len(target.events),
    )


def verify_evidence_trail(target, scenario: str, concl: ScenarioConclusion) -> tuple[bool, str]:
    """Cross-check that a claimed finding's baseline/perturbed events are REAL and
    actually differ in the dimension that matters (identity/epoch/action/args),
    per the simulator's independent log -- not the arm's own narrative."""
    refs = concl.evidence_refs
    if "baseline" not in refs or "perturbed" not in refs:
        return False, f"no baseline/perturbed evidence refs for {scenario!r}"
    base = _event(target, refs["baseline"])
    pert = _event(target, refs["perturbed"])
    if base is None or pert is None:
        return False, "evidence refs point outside the recorded event log"
    pivot_base = (base["identity"], base["epoch"], base["action"], tuple(sorted(base["args"].items())))
    pivot_pert = (pert["identity"], pert["epoch"], pert["action"], tuple(sorted(pert["args"].items())))
    if pivot_base == pivot_pert:
        return False, f"baseline and perturbed requests are identical -- unbacked claim ({scenario!r})"
    return True, f"evidence trail OK for {scenario!r}: {pivot_base} vs {pivot_pert}"


def reproducibility(reports: list) -> tuple[bool, str]:
    if not reports:
        return False, "no reports"
    def key(r):
        return (r.hits, r.misses, r.inconclusive, r.correct_no_finding,
                r.false_positives, r.unbacked_claims, r.fccr_numerator, r.fccr_denominator)
    first = key(reports[0])
    for r in reports[1:]:
        if key(r) != first:
            return False, "non-reproducible across runs"
    return True, f"reproducible across {len(reports)} runs"
