"""Long-horizon benchmark driver (TEST-ONLY): a GOLDEN reference arm and the
reproducibility record.

`golden_trajectory(target)` is the oracle/reference arm -- a CORRECT long-horizon
run that drives the real simulator through every dimension (sustained multi-step
investigation, cross-identity access, business-logic abuse, noticing a target
change across epochs, resurrecting a dormant hypothesis when deferred evidence
lands, recovering from an injected failure, and correctly concluding "no finding"
on the decoy).  It exists to PROVE the benchmark scores a correct run well and
reproducibly; it is NOT an arm under measurement.  A real arm (HuntMCP's pipeline)
is wired in later as the consumer step -- it just has to emit the same contract.

The simulator is in-process and hermetic (no network/filesystem/randomness), so
this is loopback-only by construction.
"""
from __future__ import annotations

import lh_scenarios as SC
from lh_evaluator import HypRecord, ObservedStep, ScenarioConclusion, reproducibility


def _do(target, steps, scenario, epoch, identity, action, args=None):
    """Drive one real simulator action, append the arm's self-report step, and
    return (event_index, Response)."""
    idx = len(target.events)
    resp = target.act(scenario, epoch, identity, action, args)
    steps.append(ObservedStep(scenario, epoch, identity, action, idx, resp.sig))
    return idx, resp


def golden_trajectory(target):
    """Return (steps, conclusions) for a correct run over all seven scenarios."""
    steps: list = []
    concl: dict = {}

    # --- sustained investigation: probe -> enumerate -> access(the id) ---------
    _do(target, steps, "lh_s_alpha", 0, "alice", "probe")
    _, enum = _do(target, steps, "lh_s_alpha", 0, "alice", "enumerate")
    leak, _ = _do(target, steps, "lh_s_alpha", 0, "alice", "access", {"id": enum.body.strip()})
    concl["lh_s_alpha"] = ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": leak},
        condition_verdicts={"enumerated_id": "necessary",
                            "probe_recon": "apparently_not_necessary"})

    # --- multi-identity: baseline owner read, then cross-identity leak ---------
    base, _ = _do(target, steps, "lh_s_bravo", 0, "alice", "read", {"id": "doc-1"})
    leak, _ = _do(target, steps, "lh_s_bravo", 0, "bob", "read", {"id": "doc-1"})
    concl["lh_s_bravo"] = ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": leak, "baseline": base, "perturbed": leak},
        condition_verdicts={"identity_not_owner": "necessary",
                            "extra_header": "apparently_not_necessary"})

    # --- business logic: replay the coupon, then checkout goes negative --------
    _do(target, steps, "lh_s_charlie", 0, "alice", "add_coupon")
    _do(target, steps, "lh_s_charlie", 0, "alice", "add_coupon")
    leak, _ = _do(target, steps, "lh_s_charlie", 0, "alice", "checkout")
    concl["lh_s_charlie"] = ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": leak},
        condition_verdicts={"coupon_replay": "necessary", "checkout": "necessary"})

    # --- target change: secure in epoch 0, regressed in epoch 1 ----------------
    base, _ = _do(target, steps, "lh_s_delta", 0, "alice", "read")
    leak, _ = _do(target, steps, "lh_s_delta", 1, "alice", "read")
    concl["lh_s_delta"] = ScenarioConclusion(
        verdict="finding", detected_change=True,
        evidence_refs={"leak": leak, "baseline": base, "perturbed": leak})

    # --- hypothesis resurrection: dormant in epoch 0, lands in epoch 1 ---------
    _do(target, steps, "lh_s_echo", 0, "alice", "probe")
    cb0, _ = _do(target, steps, "lh_s_echo", 0, "alice", "callback")   # 204 -> inconclusive
    cb1, _ = _do(target, steps, "lh_s_echo", 1, "alice", "callback")   # leak -> resurrect
    concl["lh_s_echo"] = ScenarioConclusion(
        verdict="finding", evidence_refs={"leak": cb1},
        hypotheses=(HypRecord("echo_oob", "inconclusive", cb0),
                    HypRecord("echo_oob", "resurrected", cb1)))

    # --- recovery: first scan 503s, retry recovers the key ---------------------
    _do(target, steps, "lh_s_foxtrot", 0, "alice", "scan")            # 503
    leak, _ = _do(target, steps, "lh_s_foxtrot", 0, "alice", "scan")  # recovered leak
    concl["lh_s_foxtrot"] = ScenarioConclusion(
        verdict="finding", recovered=True, evidence_refs={"leak": leak})

    # --- correct no-finding: the decoy is actually secured ---------------------
    _do(target, steps, "lh_s_golf", 0, "bob", "read", {"id": "doc-1"})
    concl["lh_s_golf"] = ScenarioConclusion(verdict="no_finding")

    return steps, concl


def reproducibility_record(reports: list) -> dict:
    """Emit the benchmark metadata required by .claude/rules/benchmarks.md so a
    result is reproducible from recorded evidence."""
    if not reports:
        raise ValueError("no reports to record")
    rep = reports[0]
    ok, _ = reproducibility(reports)
    return {
        "benchmark_version": rep.version,
        "seed": rep.seed,
        "target_mode": SC.TARGET_MODE,
        "scenario_count": len(rep.per_scenario),
        "request_count": rep.request_count,
        "verdicts": {sid: d["outcome"] for sid, d in rep.per_scenario.items()},
        "dimensions": {dim: d["outcome"] for dim, d in rep.per_dimension.items()},
        "fccr": rep.fccr,
        "fccr_numerator": rep.fccr_numerator,
        "fccr_denominator": rep.fccr_denominator,
        "runs": len(reports),
        "reproducible": ok,
    }
