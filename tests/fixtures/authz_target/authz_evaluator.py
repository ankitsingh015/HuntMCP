"""Arm-agnostic scoring for the P3-VALAUTHZ range (TEST-ONLY). Consumes a
normalized list[ObservedFinding]; matching is by PATH PREFIX only against
authz_scenarios' endpoints. Ground truth comes solely from authz_answer_key,
never from anything a tool reported."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlsplit

import authz_answer_key as AK
import authz_scenarios as SC


class ObservedFinding(NamedTuple):
    location: str
    confirmed: bool
    tool: str = ""
    identity: str = ""  # for identity-matrix cases: which identity the finding is about


@dataclass(frozen=True)
class AuthzReport:
    true_positives: int
    false_positives: int
    false_negatives: int
    unmatched_confirmed: int
    per_case: dict = field(default_factory=dict)


def _case_id_for_path(path: str) -> str | None:
    for case_id, spec in SC.SCENARIOS.items():
        endpoint = spec["endpoint"]
        if path == endpoint or path.startswith(endpoint + "/"):
            return case_id
    return None


def evaluate(observed: list[ObservedFinding], mode: str) -> AuthzReport:
    """Case-level scoring, except cases whose answer key lists per-identity expectations: those
    are scored per (case, identity) unit, and a confirmed identity the key does not list is a FP."""
    reported: set = set()
    unmatched = 0
    for finding in observed:
        if not finding.confirmed:
            continue
        case_id = _case_id_for_path(urlsplit(finding.location).path)
        if case_id is None:
            unmatched += 1
        elif "identities" in AK.EXPECTED_BY_MODE[case_id][mode]:
            reported.add((case_id, finding.identity))
        else:
            reported.add(case_id)

    tp = fp = fn = 0
    per_case: dict = {}
    for case_id, by_mode in AK.EXPECTED_BY_MODE.items():
        expected_mode = by_mode[mode]
        if "identities" in expected_mode:
            units = dict(expected_mode["identities"])
            for unit in reported:
                if isinstance(unit, tuple) and unit[0] == case_id and unit[1] not in units:
                    units[unit[1]] = False  # an identity the key does not list can only be a false positive
            rows = {}
            for ident, expected in units.items():
                got = (case_id, ident) in reported
                tp += expected and got
                fp += got and not expected
                fn += expected and not got
                rows[ident] = {"expected_confirmed": expected, "reported_confirmed": got}
            per_case[case_id] = rows
            continue
        expected = expected_mode["confirmed"]
        got = case_id in reported
        tp += expected and got
        fp += got and not expected
        fn += expected and not got
        per_case[case_id] = {"expected_confirmed": expected, "reported_confirmed": got}
    return AuthzReport(tp, fp, fn, unmatched, per_case)
