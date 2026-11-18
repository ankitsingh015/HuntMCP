"""P4-BM LIVE ARM (TEST-ONLY): HuntMCP's real pipeline as a benchmark arm.

`real_pipeline_trajectory(target)` drives the long-horizon simulator while using
the REAL HuntMCP modules for the dimensions that need a long-horizon capability:
  * bravo / charlie -- real `invariant_probe.mine_invariants` DETECTS the broken
    ownership / one-time-use invariant from the observed corpus (the P4-M1
    capability), which is what makes the arm pursue and confirm them;
  * echo -- real `case_store.find_resurrectable_hypotheses` (P4-RESURRECT)
    revives the dormant OOB hypothesis once deferred evidence lands.
It is an ARM: it concludes only from the simulator's observable behaviour and
the blind scenario index -- never the evaluator-only ground truth (blindness,
asserted by a test that greps this module for that import).

`baseline_trajectory(target)` is a naive single-pass arm: no invariant mining,
no cross-run memory / resurrection, no retry, no epoch re-check. It legitimately
MISSES exactly the dimensions those capabilities exist for, so
`evaluate_arm(real) vs evaluate_arm(baseline)` is a real, measured uplift.

Honest limit: this drives the real DETERMINISTIC modules, not the LLM agents
(non-deterministic, un-hermetic -- can't be a CI arm). Whether a live LLM run
calls these tools well is observed in a real engagement, not asserted here.
"""
from __future__ import annotations

import time

import case_store
import invariant_probe
from lh_evaluator import HypRecord, ObservedStep, ScenarioConclusion

_OWNER = "alice"
_ATTACKER = "bob"


def _do(target, steps, scenario, epoch, identity, action, args=None):
    idx = len(target.events)
    resp = target.act(scenario, epoch, identity, action, args)
    steps.append(ObservedStep(scenario, epoch, identity, action, idx, resp.sig))
    return idx, resp


def _exchange(idx, identity, resource, action, resp, session=None):
    return {"identity": identity, "resource": resource, "action": action, "args": {},
            "status": resp.status, "body": resp.body, "session": session, "_idx": idx}


# --------------------------------------------------------------------------- #
# The real-pipeline arm                                                       #
# --------------------------------------------------------------------------- #
def real_pipeline_trajectory(target, db_path: str | None = None):
    """Return (steps, conclusions). Uses an isolated case.db (via db_path or the
    HUNTMCP_CASE_DB_PATH env the caller set)."""
    steps: list = []
    concl: dict = {}

    # --- alpha: sustained multi-step recon -> access the enumerated id --------
    _do(target, steps, "lh_s_alpha", 0, _OWNER, "probe")
    _, enum = _do(target, steps, "lh_s_alpha", 0, _OWNER, "enumerate")
    leak, _ = _do(target, steps, "lh_s_alpha", 0, _OWNER, "access", {"id": enum.body.strip()})
    concl["lh_s_alpha"] = ScenarioConclusion(verdict="finding", evidence_refs={"leak": leak})

    # --- bravo: cross-identity read; REAL invariant_probe confirms ownership --
    o_idx, o_resp = _do(target, steps, "lh_s_bravo", 0, _OWNER, "read", {"id": "doc-1"})
    a_idx, a_resp = _do(target, steps, "lh_s_bravo", 0, _ATTACKER, "read", {"id": "doc-1"})
    corpus = [_exchange(o_idx, _OWNER, "lh_s_bravo", "read", o_resp),
              _exchange(a_idx, _ATTACKER, "lh_s_bravo", "read", a_resp)]
    mined = {c["invariant"] for c in invariant_probe.mine_invariants(corpus)}
    if "ownership" in mined:  # the real P4-M1 detection drives the conclusion
        concl["lh_s_bravo"] = ScenarioConclusion(
            verdict="finding", evidence_refs={"leak": a_idx},
            condition_verdicts={"identity_not_owner": "necessary"})

    # --- charlie: replay the coupon; REAL one-time-use detection drives it ----
    c_events = []
    for _ in range(3):
        i, r = _do(target, steps, "lh_s_charlie", 0, _OWNER, "add_coupon")
        c_events.append((i, r))
    leak, _ = _do(target, steps, "lh_s_charlie", 0, _OWNER, "checkout")
    c_corpus = [_exchange(i, _OWNER, "lh_s_charlie", "add_coupon", r, session="s1")
                for i, r in c_events]
    mined = {c["invariant"] for c in invariant_probe.mine_invariants(c_corpus)}
    if "one_time_use" in mined:
        concl["lh_s_charlie"] = ScenarioConclusion(
            verdict="finding", evidence_refs={"leak": leak})

    # --- delta: re-check across epochs (long-horizon) -> notice the regression -
    _do(target, steps, "lh_s_delta", 0, _OWNER, "read")              # epoch 0: secure
    leak, _ = _do(target, steps, "lh_s_delta", 1, _OWNER, "read")    # epoch 1: regression
    concl["lh_s_delta"] = ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": leak}, detected_change=True)

    # --- echo: dormant OOB hypothesis resurrected by REAL case_store ----------
    _do(target, steps, "lh_s_echo", 0, _OWNER, "probe")
    _do(target, steps, "lh_s_echo", 0, _OWNER, "callback")          # epoch 0: no interaction
    h = case_store.log_hypothesis("submitted an OOB payload on lh_s_echo",
                                  "the OOB callback may fire later", db_path=db_path)
    case_store.update_hypothesis(h["id"], "INCONCLUSIVE", db_path=db_path)
    time.sleep(1.1)  # cross the 1s resolution boundary so new evidence is strictly newer
    leak, _ = _do(target, steps, "lh_s_echo", 1, _OWNER, "callback")  # epoch 1: it fired
    case_store.add_evidence("callback", "ECHO-OOB interaction received (dns+http)",
                            hypothesis_id=h["id"], db_path=db_path)
    resurrectable = {c["hypothesis_id"]
                     for c in case_store.find_resurrectable_hypotheses(db_path=db_path)}
    if h["id"] in resurrectable:
        case_store.update_hypothesis(h["id"], "CONFIRMED", db_path=db_path)
        concl["lh_s_echo"] = ScenarioConclusion(
            verdict="finding", evidence_refs={"leak": leak},
            hypotheses=(HypRecord("echo_oob", "resurrected", leak),))

    # --- foxtrot: recover from the injected transient failure -----------------
    _do(target, steps, "lh_s_foxtrot", 0, _OWNER, "scan")          # 503 (transient)
    leak, _ = _do(target, steps, "lh_s_foxtrot", 0, _OWNER, "scan")  # retry -> leak
    concl["lh_s_foxtrot"] = ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": leak}, recovered=True)

    # --- golf: correctly secured -> no finding --------------------------------
    _do(target, steps, "lh_s_golf", 0, _OWNER, "read")
    _do(target, steps, "lh_s_golf", 0, _ATTACKER, "read")          # denied
    concl["lh_s_golf"] = ScenarioConclusion(verdict="no_finding")

    return steps, concl


# --------------------------------------------------------------------------- #
# The naive baseline arm                                                      #
# --------------------------------------------------------------------------- #
def baseline_trajectory(target):
    """Single-pass, no invariant mining, no memory/resurrection, no retry, no
    epoch re-check. It catches the basic class-scannable dimensions and MISSES
    the ones that need a long-horizon capability."""
    steps: list = []
    concl: dict = {}

    # alpha: basic enumerate+access works.
    _do(target, steps, "lh_s_alpha", 0, _OWNER, "probe")
    _, enum = _do(target, steps, "lh_s_alpha", 0, _OWNER, "enumerate")
    leak, _ = _do(target, steps, "lh_s_alpha", 0, _OWNER, "access", {"id": enum.body.strip()})
    concl["lh_s_alpha"] = ScenarioConclusion(verdict="finding", evidence_refs={"leak": leak})

    # bravo: a 2-identity read diff is class-scannable (idor) -> caught.
    _do(target, steps, "lh_s_bravo", 0, _OWNER, "read", {"id": "doc-1"})
    a_idx, _ = _do(target, steps, "lh_s_bravo", 0, _ATTACKER, "read", {"id": "doc-1"})
    concl["lh_s_bravo"] = ScenarioConclusion(verdict="finding", evidence_refs={"leak": a_idx})

    # charlie: single pass (one coupon) -> no credit -> MISS.
    _do(target, steps, "lh_s_charlie", 0, _OWNER, "add_coupon")
    _do(target, steps, "lh_s_charlie", 0, _OWNER, "checkout")
    concl["lh_s_charlie"] = ScenarioConclusion(verdict="no_finding")

    # delta: single epoch only -> never sees the regression -> MISS.
    _do(target, steps, "lh_s_delta", 0, _OWNER, "read")
    concl["lh_s_delta"] = ScenarioConclusion(verdict="no_finding")

    # echo: no resurrection -> the early probe is inconclusive and stays so -> MISS.
    _do(target, steps, "lh_s_echo", 0, _OWNER, "probe")
    _do(target, steps, "lh_s_echo", 0, _OWNER, "callback")
    concl["lh_s_echo"] = ScenarioConclusion(verdict="no_finding")

    # foxtrot: no retry -> gives up on the transient 503 -> MISS.
    _do(target, steps, "lh_s_foxtrot", 0, _OWNER, "scan")
    concl["lh_s_foxtrot"] = ScenarioConclusion(verdict="no_finding")

    # golf: correctly secured -> no finding (a correct no-finding, not a miss).
    _do(target, steps, "lh_s_golf", 0, _OWNER, "read")
    _do(target, steps, "lh_s_golf", 0, _ATTACKER, "read")
    concl["lh_s_golf"] = ScenarioConclusion(verdict="no_finding")

    return steps, concl
