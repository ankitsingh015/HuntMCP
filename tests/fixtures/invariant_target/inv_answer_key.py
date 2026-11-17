"""EVALUATOR-ONLY answer key for the P4-M0 shallow-invariant-probe metric.

Independent ground truth for ONE question only: for each long-horizon
benchmark scenario (lh_target.py), is it an invariant-model-mineable
violation that the shallow prototype's two heuristic templates
(ownership / one-time-use) are SUPPOSED to surface, and would a
class-driven scanner independently catch it?

Blindness/independence (same discipline as bench_answer_key.py /
lh_answer_key.py, enforced in tests/test_invariant_probe.py):
  * NEVER imported by any mcp-servers/* production code -- the probe
    (mcp-servers/invariant_probe.py) must reach its verdict from the
    observed corpus alone, never from this file.
  * Describes REAL, observable lh_target.py behaviour (the measurement
    test drives the simulator and the scores are computed against this
    key). It does NOT import lh_answer_key.py, lh_target.py, or the
    probe -- it is hand-authored ground truth, SHA-256 integrity-locked.

Field meanings (per opaque lh scenario id):
  in_family   -- True iff this is an ownership- or one-time-use-invariant
                 violation the shallow miner targets. These are the ones
                 it SHOULD surface (recall denominator). A candidate on
                 any `in_family: False` scenario is a FALSE invariant
                 (the "confident false invariant / garbage-in-for-CEM"
                 failure mode P4-M0 exists to measure) -- precision guard.
  family      -- which template should fire ("ownership"/"one_time_use"),
                 or None when it is out of family / correctly secured.
  class_scannable -- True iff a class-driven scanner/skill in this repo
                 already targets this bug's class (idor-mcp, secrets, ...).
                 False == maps to NO single vuln class, so class scanning
                 structurally MISSES it -> the differential value of the
                 invariant model (UU research Opp-1 benchmark).
"""
from __future__ import annotations

from types import MappingProxyType

INV_GROUND_TRUTH = MappingProxyType({
    # ownership invariant broken: bob reads alice's doc-1 and it leaks (idor).
    # idor-mcp already targets this class -> class scanning also catches it.
    "lh_s_bravo": MappingProxyType({
        "in_family": True, "family": "ownership", "class_scannable": True,
    }),
    # one-time-use invariant broken: replaying add_coupon drives checkout
    # below zero (business logic). No vuln-class scanner targets this ->
    # class scanning structurally misses it (the differential value).
    "lh_s_charlie": MappingProxyType({
        "in_family": True, "family": "one_time_use", "class_scannable": False,
    }),
    # correctly-secured decoy, shaped like bravo: a non-owner gets 403.
    # A candidate here would be a false ownership invariant.
    "lh_s_golf": MappingProxyType({
        "in_family": False, "family": None, "class_scannable": False,
    }),
    # recovery dimension (transient 503 then success). Replayed `scan` but the
    # first response is 5xx, not accumulation -- a one_time_use candidate here
    # would be a false invariant (precision guard vs the replay heuristic).
    "lh_s_foxtrot": MappingProxyType({
        "in_family": False, "family": None, "class_scannable": True,
    }),
    # other long-horizon dimensions -- real planted bugs, but NOT ownership/
    # one-time-use invariant surfaces for the shallow miner. It must stay
    # silent on them; a candidate here is a false invariant.
    "lh_s_alpha": MappingProxyType({
        "in_family": False, "family": None, "class_scannable": True,
    }),
    "lh_s_delta": MappingProxyType({
        "in_family": False, "family": None, "class_scannable": True,
    }),
    "lh_s_echo": MappingProxyType({
        "in_family": False, "family": None, "class_scannable": True,
    }),
    # THE canonical T1 precision decoy (inv_decoys.py): a legitimately public /
    # shared resource that returns 2xx + identical content to >=2 identities
    # with NO denial anywhere. in_family is False at the PROBE stage: the
    # high-recall probe is EXPECTED to flag it (it cannot be distinguished from
    # an IDOR leak on {identity,resource,status,body} alone), so a probe
    # candidate here is a probe-stage false positive that the frozen CEM
    # counterfactual MUST reject (dropping the identity still returns the same
    # content => identity not necessary). `cem_must_reject` records exactly that
    # pipeline-stage obligation.
    "pub_shared": MappingProxyType({
        "in_family": False, "family": None, "class_scannable": False,
        "cem_must_reject": True,
    }),
    # P4-M1 deeper templates.
    # vertical-privilege differential (T3): a low-priv identity succeeds at a
    # privileged op another is denied. in_family for the T3 detector (the probe
    # SHOULD surface it); class-less (no vuln-class scanner targets it). It is a
    # DISCOVERED lead, NOT a CEM-confirmable necessity claim -- so it is
    # deliberately absent from CEM_MUST_REJECT (nothing false to confirm) and the
    # pipeline gate never asserts a `necessary` verdict for it.
    "lh_s_hotel": MappingProxyType({
        "in_family": True, "family": "vertical_privilege", "class_scannable": False,
    }),
    # client-controlled privilege PARAMETER (T4) genuinely escalates -> the param
    # IS necessary for the leak, CEM confirms it. class-less differential value.
    "lh_s_india": MappingProxyType({
        "in_family": True, "family": "state_gated_param", "class_scannable": False,
    }),
    # T4 PRECISION decoy: a role param the server ignores. The high-recall probe
    # flags it (role varies across identities), so in_family is False at the
    # PROBE stage and the frozen CEM counterfactual MUST reject it (dropping role
    # returns identical content => role not necessary). A CONFIRMED-necessary
    # verdict here is a confirmed false invariant.
    "lh_s_kilo": MappingProxyType({
        "in_family": False, "family": None, "class_scannable": False,
        "cem_must_reject": True,
    }),
})

# Resources the probe is ALLOWED to flag (high recall) but whose candidate the
# frozen CEM counterfactual must then REJECT -- the pipeline-stage precision
# obligation.  A CONFIRMED-necessary verdict on any of these is a confirmed
# false invariant (the pipeline-stage failure the gate exists to prevent).
CEM_MUST_REJECT = frozenset(
    s for s, v in INV_GROUND_TRUTH.items() if v.get("cem_must_reject"))

# Convenience projections for the evaluator (derived, not independent truth).
IN_FAMILY = frozenset(s for s, v in INV_GROUND_TRUTH.items() if v["in_family"])
MUST_NOT_FLAG = frozenset(s for s, v in INV_GROUND_TRUTH.items() if not v["in_family"])
CLASS_LESS_IN_FAMILY = frozenset(
    s for s, v in INV_GROUND_TRUTH.items()
    if v["in_family"] and not v["class_scannable"]
)
