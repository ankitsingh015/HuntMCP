"""EVALUATOR-ONLY answer key for the long-horizon benchmark.

Never imported by any mcp-servers/* production code and never fed back into the
simulator (blindness + oracle independence are asserted in tests/test_lh_benchmark.py).
Keyed by the SAME opaque scenario ids as lh_scenarios.py so the evaluator can join
an arm's emitted conclusion to the planted ground truth without the arm ever seeing
this file.

Every expected label here describes REAL, observable lh_target.py behaviour -- the
benchmark self-tests prove each one actually fires at build time, so the ground
truth is genuinely planted, not fabricated.

Causal vocabulary (same discipline as the CEM benchmark): a condition is
`necessary` when removing it flips the oracle, `apparently_not_necessary` when it
never affects the oracle.  Claiming `necessary` for an `apparently_not_necessary`
condition is a FALSE causal conclusion (counted in FCCR).  `inconclusive` is honest
uncertainty and is NEVER a false causal conclusion.
"""
from __future__ import annotations

from types import MappingProxyType

# scenario id -> the long-horizon dimension it exercises (the mapping the blind
# index must never reveal).
DIMENSION = MappingProxyType({
    "lh_s_alpha": "sustained_investigation",
    "lh_s_bravo": "multi_identity",
    "lh_s_charlie": "business_logic",
    "lh_s_delta": "target_change",
    "lh_s_echo": "hypothesis_resurrection",
    "lh_s_foxtrot": "recovery",
    "lh_s_golf": "correct_no_finding",
})
DIMENSIONS = tuple(sorted(set(DIMENSION.values())))

# Human-readable meaning kept on the evaluator side ONLY.
MEANING = MappingProxyType({
    "lh_s_alpha": "leak reachable only after probe->enumerate->access(id)",
    "lh_s_bravo": "cross-identity read of alice's doc leaks (horizontal authz)",
    "lh_s_charlie": "replaying the coupon drives checkout below zero (logic abuse)",
    "lh_s_delta": "secure in epoch 0, debug regression leaks in epoch 1",
    "lh_s_echo": "OOB callback only lands in epoch 1 -> resurrect the dormant hypothesis",
    "lh_s_foxtrot": "first scan 503s; the key leaks only after a retry (recovery)",
    "lh_s_golf": "decoy shaped like bravo but access control holds -> correct no-finding",
})

EXPECTED = MappingProxyType({
    "lh_s_alpha": MappingProxyType({
        "kind": "point_finding", "planted": True, "vuln_class": "broken_access_control",
        "condition_verdicts": MappingProxyType({
            "enumerated_id": "necessary", "probe_recon": "apparently_not_necessary"}),
        "minimal_sets": (("enumerated_id",),),
    }),
    "lh_s_bravo": MappingProxyType({
        "kind": "point_finding", "planted": True, "vuln_class": "idor",
        "condition_verdicts": MappingProxyType({
            "identity_not_owner": "necessary", "extra_header": "apparently_not_necessary"}),
        "minimal_sets": (("identity_not_owner",),),
    }),
    "lh_s_charlie": MappingProxyType({
        "kind": "point_finding", "planted": True, "vuln_class": "business_logic",
        "condition_verdicts": MappingProxyType({
            "coupon_replay": "necessary", "checkout": "necessary"}),
        "minimal_sets": (("coupon_replay", "checkout"),),
    }),
    "lh_s_delta": MappingProxyType({
        "kind": "target_change", "planted": True, "vuln_class": "information_disclosure",
        "finding_epoch": 1,
    }),
    "lh_s_echo": MappingProxyType({
        "kind": "resurrection", "planted": True, "vuln_class": "ssrf_oob",
        "hypothesis_id": "echo_oob", "initial_status": "inconclusive", "evidence_epoch": 1,
    }),
    "lh_s_foxtrot": MappingProxyType({
        "kind": "recovery", "planted": True, "vuln_class": "secret_exposure",
        "transient_failure_status": 503,
    }),
    "lh_s_golf": MappingProxyType({
        "kind": "no_finding", "planted": False, "vuln_class": None,
    }),
})

# (scenario, condition) pairs whose ground truth is NOT necessary -- the FCCR
# denominator.  A `necessary` claim on any of these is a false causal conclusion;
# an `inconclusive` claim is not.
MUST_NOT_BE_NECESSARY = frozenset({
    ("lh_s_alpha", "probe_recon"),
    ("lh_s_bravo", "extra_header"),
})
