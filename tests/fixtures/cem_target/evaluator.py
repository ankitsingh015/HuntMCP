"""Independent evaluator (TEST-ONLY). Consumes CEM's EXTERNALLY EMITTED conclusion plus
the evaluator-only answer key and produces measured results. It is NOT imported by CEM
production code, and it never feeds the answer key back into CEM.

`CemConclusion` is the OUTPUT CONTRACT the future CEM must emit (provisional; the real CEM
must conform). The evaluator is deterministic given fixed inputs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import answer_key as AK


@dataclass(frozen=True)
class CaseConclusion:
    """What CEM emits per case (externally observable result, not internals)."""
    verdicts: dict = field(default_factory=dict)          # condition -> verdict
    determinism_status: str | None = None                 # e.g. "STABLE"/"NONDETERMINISTIC"
    minimal_sets: tuple = ()                               # tuple of tuples
    finding_reproduced: bool = True                        # False = capability absent
    evidence_refs: dict = field(default_factory=dict)      # condition -> {"baseline": idx, "perturbed": idx}


@dataclass(frozen=True)
class EvalReport:
    per_case: dict
    coverage: float           # fraction of scored conditions classified correctly
    fccr: float               # false-causal-conclusion rate
    fccr_numerator: int
    fccr_denominator: int
    discovered: int
    missed: int
    false_positives: int      # necessary asserted where truth is not-necessary (non-race/flaky conds)


def _expected_for(case_id: str, mode: str) -> dict | None:
    if case_id in AK.EXPECTED:
        return dict(AK.EXPECTED[case_id])
    if case_id in AK.EXPECTED_BY_MODE:
        return dict(AK.EXPECTED_BY_MODE[case_id][mode])
    return None


def evaluate(conclusions: dict, mode: str = "vulnerable") -> EvalReport:
    """conclusions: case_id -> CaseConclusion. Deterministic."""
    per_case = {}
    scored = correct = 0
    fccr_num = fccr_den = 0
    discovered = missed = fps = 0

    for case_id, concl in conclusions.items():
        exp = _expected_for(case_id, mode)
        if exp is None:
            per_case[case_id] = {"error": "no answer-key entry"}
            continue

        # capability-absent (patched mutation): CEM must NOT emit any `necessary`.
        if exp.get("capability_absent"):
            emitted_necessary = [c for c, v in concl.verdicts.items() if v == "necessary"]
            ok = (not concl.finding_reproduced) and not emitted_necessary
            per_case[case_id] = {"capability_absent_expected": True, "ok": ok,
                                 "emitted_necessary": emitted_necessary}
            if not ok:
                missed += 0  # not a missed finding; it's a false reproduction
                fps += len(emitted_necessary)
                fccr_num += len(emitted_necessary)
                fccr_den += 1
            else:
                discovered += 1  # correctly recognized the fix
            continue

        exp_verdicts = exp.get("verdicts", {})
        case_correct = 0
        for cond, exp_v in exp_verdicts.items():
            scored += 1
            got = concl.verdicts.get(cond)
            if got == exp_v:
                correct += 1
                case_correct += 1
            # FCCR: emitting `necessary` where truth is not-necessary
            if exp_v in ("apparently_not_necessary", "inconclusive", "probabilistic", "interacting") and got == "necessary":
                if exp_v != "interacting":  # interacting conds legitimately appear in minimal sets
                    fps += 1

        # FCCR denominator/numerator from must-not-be-necessary cases + apparently-not conds
        if case_id in AK.MUST_NOT_BE_NECESSARY_CASES:
            fccr_den += len(exp_verdicts)
            fccr_num += sum(1 for c in exp_verdicts if concl.verdicts.get(c) == "necessary")
        for (ci, cond) in AK.APPARENTLY_NOT_NECESSARY_CONDITIONS:
            if ci == case_id:
                fccr_den += 1
                if concl.verdicts.get(cond) == "necessary":
                    fccr_num += 1

        # discovered vs missed: a "necessary" or complete minimal set present == discovered finding
        found = any(v == "necessary" for v in concl.verdicts.values()) or bool(concl.minimal_sets)
        if case_id not in AK.MUST_NOT_BE_NECESSARY_CASES:
            if found:
                discovered += 1
            else:
                missed += 1

        per_case[case_id] = {"scored": len(exp_verdicts), "correct": case_correct,
                             "verdicts_expected": exp_verdicts, "verdicts_got": dict(concl.verdicts)}

    coverage = (correct / scored) if scored else 0.0
    fccr = (fccr_num / fccr_den) if fccr_den else 0.0
    return EvalReport(per_case=per_case, coverage=coverage, fccr=fccr,
                      fccr_numerator=fccr_num, fccr_denominator=fccr_den,
                      discovered=discovered, missed=missed, false_positives=fps)


def verify_evidence_trail(concl: CaseConclusion, request_log: list[dict], condition: str) -> tuple[bool, str]:
    """B1: confirm CEM's claimed intervention on `condition` is backed by REAL requests --
    a baseline and a perturbed request that actually differ in exactly that condition,
    according to the target's independent request log (not CEM's own narrative)."""
    refs = concl.evidence_refs.get(condition)
    if not refs or "baseline" not in refs or "perturbed" not in refs:
        return False, f"no evidence refs for {condition!r}"
    try:
        base = request_log[refs["baseline"]]
        pert = request_log[refs["perturbed"]]
    except (IndexError, KeyError):
        return False, "evidence refs point outside the recorded request log"
    field_map = {"session_cookie": "session", "x_access_header": "x_access",
                 "role_admin": "x_role", "flag_on": "flag", "trace_param": "trace",
                 "target_object_id": "path"}
    key = field_map.get(condition)
    if key is None:
        return False, f"unknown condition {condition!r}"
    if base.get(key) == pert.get(key):
        return False, f"baseline and perturbed requests do NOT differ in {condition!r} (unbacked claim)"
    return True, f"evidence trail OK for {condition!r}: baseline {base.get(key)!r} vs perturbed {pert.get(key)!r}"


def reproducibility(reports: list[EvalReport]) -> tuple[bool, str]:
    """Deterministic-repeat check: identical coverage+fccr across repeated runs."""
    if not reports:
        return False, "no reports"
    first = (round(reports[0].coverage, 6), reports[0].fccr_numerator, reports[0].fccr_denominator)
    for r in reports[1:]:
        if (round(r.coverage, 6), r.fccr_numerator, r.fccr_denominator) != first:
            return False, "non-reproducible across runs"
    return True, f"reproducible across {len(reports)} runs"
