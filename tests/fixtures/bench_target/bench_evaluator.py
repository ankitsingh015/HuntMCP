"""Arm-agnostic scoring (TEST-ONLY). Consumes a normalized
list[ObservedFinding] -- any arm (HuntMCP's real pipeline today, a future
frontier-only baseline) just needs to produce this shape; this function
never changes for a new arm. See
docs/superpowers/specs/2026-09-17-p2-bench-design.md sections 6-7.

Matching is by PATH ONLY (query string ignored) against bench_scenarios's
endpoints -- never by anything an arm was told in advance, since nothing
is told in advance (a real hunt only ever sees the target's base URL).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlsplit

import bench_answer_key as AK
import bench_scenarios as SC


class ObservedFinding(NamedTuple):
    """`evidence` defaults to None, not {} -- a NamedTuple field default is
    evaluated once at class-definition time and shared by every instance
    that omits the field (the same class of bug as a mutable default
    argument on a function, and NamedTuple's own immutability does NOT
    protect against in-place mutation of that shared default). Found in
    task review (empirically confirmed): omitting `evidence` on two
    separate ObservedFinding instances made them share ONE dict object,
    so mutating one's `.evidence` in place silently corrupted the other's
    too, for the lifetime of the process. `evaluate()` itself never reads
    `.evidence` today, but this is the shared interface every future arm-
    adapter reports through -- the fix must land before anything starts
    populating it."""
    location: str
    confirmed: bool
    tool: str = ""
    evidence: dict | None = None

    def evidence_or_empty(self) -> dict:
        return self.evidence if self.evidence is not None else {}


@dataclass(frozen=True)
class BenchReport:
    coverage: float
    yield_: int
    false_positives: int
    novel_findings: int
    cost: dict = field(default_factory=dict)
    per_case: dict = field(default_factory=dict)


def _path_of(location: str) -> str:
    return urlsplit(location).path or location


def _case_id_for_path(path: str) -> str | None:
    """Exact match for a flat route (e.g. /bench/products), OR a
    path-prefix match for a parameterized route (e.g. bench_scenarios'
    case_idor endpoint "/bench/orders" must match a real observed
    location like "/bench/orders/42" -- the scenario entry names the
    general route, not one specific instance)."""
    for case_id, spec in SC.SCENARIOS.items():
        endpoint = spec["endpoint"]
        if path == endpoint or path.startswith(endpoint + "/"):
            return case_id
    return None


def evaluate(observed: list[ObservedFinding], mode: str, cost: dict | None = None) -> BenchReport:
    total_cases = len(SC.SCENARIOS)
    yield_ = 0
    false_positives = 0
    novel_findings = 0
    per_case: dict = {}
    correctly_confirmed: set[str] = set()

    for finding in observed:
        if not finding.confirmed:
            continue
        case_id = _case_id_for_path(_path_of(finding.location))
        if case_id is None:
            novel_findings += 1
            continue
        expected = AK.EXPECTED_BY_MODE[case_id][mode]["confirmed"]
        if expected:
            yield_ += 1
            correctly_confirmed.add(case_id)
        else:
            false_positives += 1
        per_case[case_id] = {"expected_confirmed": expected, "reported_confirmed": True, "tool": finding.tool}

    coverage = len(correctly_confirmed) / total_cases if total_cases else 0.0
    return BenchReport(
        coverage=coverage, yield_=yield_, false_positives=false_positives,
        novel_findings=novel_findings, cost=dict(cost or {}), per_case=per_case,
    )


def reproducibility(reports: list[BenchReport]) -> tuple[bool, str]:
    if not reports:
        return False, "no reports"
    first = (round(reports[0].coverage, 6), reports[0].yield_, reports[0].false_positives, reports[0].novel_findings)
    for r in reports[1:]:
        if (round(r.coverage, 6), r.yield_, r.false_positives, r.novel_findings) != first:
            return False, "non-reproducible across runs"
    return True, f"reproducible across {len(reports)} runs"


def verify_evidence_trail(request_log: list[dict], case_id: str, evidence: dict) -> tuple[bool, str]:
    """B1-style cross-check (mirrors cem_target/evaluator.py's
    verify_evidence_trail): confirm a claimed finding is backed by two
    REAL requests that actually differ in the field that matters for this
    case, per the target's own independent request log -- not a tool's
    own narrative."""
    if "baseline" not in evidence or "perturbed" not in evidence:
        return False, f"no evidence refs for {case_id!r}"
    try:
        base = request_log[evidence["baseline"]]
        pert = request_log[evidence["perturbed"]]
    except (IndexError, KeyError):
        return False, "evidence refs point outside the recorded request log"
    key = "cookie" if case_id == "case_idor" else "path"
    if base.get(key) == pert.get(key):
        return False, f"baseline and perturbed requests do NOT differ ({key!r}) -- unbacked claim"
    return True, f"evidence trail OK for {case_id!r}: {base.get(key)!r} vs {pert.get(key)!r}"
