"""EVALUATOR-ONLY answer key. Never imported by CEM production code or fed into CEM inputs.

Keyed by the SAME neutral case ids as scenarios.py so the evaluator can join CEM's emitted
conclusion to the expected outcome without CEM ever seeing this file. For the mutation
scenario (case_07) the expected outcome depends on the target MODE.

Verdict vocabulary: necessary | apparently_not_necessary | inconclusive | interacting |
probabilistic. `capability_absent` means the finding does not reproduce at all (patched).
"""
from __future__ import annotations

from types import MappingProxyType

# Human-readable meaning kept here (evaluator side) ONLY -- the leak that must not reach CEM.
MEANING = MappingProxyType({
    "case_01": "auth necessary; trace irrelevant",
    "case_02": "two independent access paths",
    "case_03": "interaction (both needed)",
    "case_04": "nondeterministic (flaky)",
    "case_05": "cache/one-shot confounder",
    "case_06": "race / TOCTOU",
    "case_07": "IDOR; mode-dependent",
})

# Mode-independent cases.
EXPECTED = MappingProxyType({
    "case_01": MappingProxyType({
        "verdicts": MappingProxyType({"session_cookie": "necessary", "trace_param": "apparently_not_necessary"}),
        "minimal_sets": (("session_cookie",),),
    }),
    "case_02": MappingProxyType({
        "verdicts": MappingProxyType({"x_access_header": "interacting", "session_cookie": "interacting"}),
        "minimal_sets": (("x_access_header",), ("session_cookie",)),
    }),
    "case_03": MappingProxyType({
        "verdicts": MappingProxyType({"role_admin": "interacting", "flag_on": "interacting"}),
        "minimal_sets": (("role_admin", "flag_on"),),
    }),
    "case_04": MappingProxyType({
        "verdicts": MappingProxyType({"probe_header": "inconclusive"}),
        "determinism_status": "NONDETERMINISTIC",
    }),
    "case_05": MappingProxyType({
        "verdicts": MappingProxyType({"probe_header": "inconclusive"}),
    }),
    "case_06": MappingProxyType({
        "verdicts": MappingProxyType({"probe_header": "probabilistic"}),
    }),
})

# Mode-dependent expectations for the mutation scenario.
EXPECTED_BY_MODE = MappingProxyType({
    "case_07": MappingProxyType({
        "vulnerable": MappingProxyType({
            "verdicts": MappingProxyType({"session_cookie": "necessary", "target_object_id": "necessary"}),
            "minimal_sets": (("session_cookie", "target_object_id"),),
        }),
        "patched": MappingProxyType({
            "capability_absent": True,  # baseline oracle never fires -> CEM must NOT emit necessity
        }),
    }),
})

# A `necessary` verdict on any condition of these cases is a FALSE causal conclusion (FCCR).
MUST_NOT_BE_NECESSARY_CASES = frozenset({"case_04", "case_05", "case_06"})
# Conditions expected NOT necessary (also FCCR denominator).
APPARENTLY_NOT_NECESSARY_CONDITIONS = frozenset({("case_01", "trace_param")})
