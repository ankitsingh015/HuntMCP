"""P4-M0 -- shallow invariant-model PROTOTYPE -> GO/NO-GO.

The invariant model (UU research Opp-1; MASTER-ROADMAP-FINAL-v3.md
decision matrix "Invariant model (UU-1)" + section 5 Phase-4) passively mines a
hunt's observed request/response corpus into an
actor->action->object->state-transition->invariant model and hands the
*candidate broken invariants* to CEM as hypotheses to falsify -- never
asserted facts (the failure mode the whole gate exists to measure is a
shallow miner emitting "confident false invariants", i.e. garbage-in for
CEM).

These tests pin the two shallow heuristic templates, prove each surfaced
candidate is expressible as a CEM-provable hypothesis through the EXISTING
case_store path (no new store), keep the probe blind to the evaluator-only
answer key, and compute the measured GO/NO-GO signal against independent,
integrity-locked ground truth.

Substrate (built-on, not duplicated):
  * corpus = the P4-BM long-horizon simulator tests/fixtures/lh_target/lh_target.py,
    driven OBSERVABLY (an "arm" only ever sees the simulator's behaviour +
    the blind index), exactly like a real 2-account engagement.
  * ground truth = tests/fixtures/invariant_target/inv_answer_key.py
    (evaluator-only, SHA-256 locked) -- never imported by the probe.
"""
from __future__ import annotations

import os
import pathlib
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "lh_target"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "invariant_target"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "bench_target"))

import bench_integrity  # noqa: E402
import case_store  # noqa: E402
import inv_answer_key as AK  # noqa: E402  -- EVALUATOR-ONLY (test side)
import inv_decoys  # noqa: E402  -- blind precision-decoy target (test side)
import invariant_probe  # noqa: E402  -- the prototype under test
from lh_target import LhTarget  # noqa: E402

_INV_KEY = os.path.join(ROOT, "tests", "fixtures", "invariant_target", "inv_answer_key.py")


# --------------------------------------------------------------------------- #
# Corpus builder: drive the lh simulator observably into the probe's input    #
# shape {identity, resource, action, args, status, body}. resource == the     #
# opaque scenario id (a real hunt's URL path maps 1:1 to a scenario anyway).  #
# --------------------------------------------------------------------------- #
def _exchange(ex_id, resource, resp):
    return {
        "identity": ex_id[0], "resource": resource, "action": ex_id[1],
        "args": ex_id[2], "status": resp.status, "body": resp.body,
    }


def _drive(scenario, steps, epoch=0):
    """steps: list of (identity, action, args). Fresh simulator per scenario."""
    t = LhTarget()
    out = []
    for identity, action, args in steps:
        resp = t.act(scenario, epoch, identity, action, args or {})
        out.append(_exchange((identity, action, args or {}), scenario, resp))
    return out


def build_corpus():
    """A small, deterministic multi-identity corpus exercising every lh
    dimension the shallow miner could react to."""
    corpus = []
    # ownership family: bravo leaks to a non-owner; golf (decoy) does not.
    corpus += _drive("lh_s_bravo", [("alice", "read", {}), ("bob", "read", {})])
    corpus += _drive("lh_s_golf", [("alice", "read", {}), ("bob", "read", {})])
    # one-time-use family: charlie accumulates a coupon then over-credits.
    corpus += _drive("lh_s_charlie", [
        ("alice", "add_coupon", {}), ("alice", "add_coupon", {}),
        ("alice", "add_coupon", {}), ("alice", "checkout", {})])
    # recovery decoy: foxtrot replays `scan` but the first response is 503.
    corpus += _drive("lh_s_foxtrot", [("alice", "scan", {}), ("alice", "scan", {})])
    # other dimensions the 2 templates must stay silent on.
    corpus += _drive("lh_s_alpha", [
        ("alice", "probe", {}), ("alice", "enumerate", {}),
        ("alice", "access", {"id": "obj-7"})])
    corpus += _drive("lh_s_delta", [("alice", "read", {})], epoch=0)
    corpus += _drive("lh_s_delta", [("alice", "read", {})], epoch=1)
    corpus += _drive("lh_s_echo", [("alice", "probe", {}), ("alice", "callback", {})])
    # P4-M1 T3 vertical-privilege (hotel): anon denied, low-priv bob succeeds at
    # a privileged non-read op -> the probe stages it as a DISCOVERED lead.
    corpus += _drive("lh_s_hotel", [("anon", "export", {}), ("bob", "export", {})])
    # P4-M1 T4 privilege parameter (india): role varies across identities; the
    # rows carry the REAL captured request so the candidate is real-request
    # mapped and CEM can drop the `role` query param.
    for ident, role in [("alice", "user"), ("bob", "admin")]:
        r = LhTarget().act("lh_s_india", 0, ident, "read", {"role": role})
        ex = _exchange((ident, "read", {"role": role}), "lh_s_india", r)
        ex["base_request"] = {
            "method": "GET",
            "url": f"https://{invariant_probe._HOST}/lh_s_india?role={role}",
            "headers": {}, "body": None}
        corpus.append(ex)
    return corpus


def _resources_flagged(candidates):
    return {c["resource"] for c in candidates}


# --------------------------------------------------------------------------- #
# Template 1: ownership / horizontal authz                                    #
# --------------------------------------------------------------------------- #
def test_ownership_template_flags_bravo_not_golf():
    """bravo: two identities both read the same singular object successfully
    -> candidate ownership-invariant violation. golf: the non-owner is denied
    (403) -> the invariant holds -> NO candidate (precision on the decoy)."""
    cands = invariant_probe.mine_invariants(build_corpus())
    own = [c for c in cands if c["invariant"] == "ownership"]
    flagged = {c["resource"] for c in own}
    assert "lh_s_bravo" in flagged
    assert "lh_s_golf" not in flagged


# --------------------------------------------------------------------------- #
# Template 2: one-time-use / replay                                           #
# --------------------------------------------------------------------------- #
def test_one_time_use_template_flags_charlie_not_foxtrot():
    """charlie: the same action replayed with identical args, all 2xx, bodies
    accumulate -> candidate one-time-use violation. foxtrot: `scan` is replayed
    too, but its first response is 503 (transient failure + recovery), NOT state
    accumulation -> NO candidate (precision guard against the replay heuristic)."""
    cands = invariant_probe.mine_invariants(build_corpus())
    otu = [c for c in cands if c["invariant"] == "one_time_use"]
    flagged = {c["resource"] for c in otu}
    assert "lh_s_charlie" in flagged
    assert "lh_s_foxtrot" not in flagged


def test_miner_is_silent_on_out_of_family_dimensions():
    """alpha (sustained), delta (target-change), echo (resurrection) are real
    planted bugs but NOT ownership/one-time-use surfaces for the 2 shallow
    templates. A candidate on any of them would be a false invariant."""
    flagged = _resources_flagged(invariant_probe.mine_invariants(build_corpus()))
    assert flagged.isdisjoint({"lh_s_alpha", "lh_s_delta", "lh_s_echo"})


# --------------------------------------------------------------------------- #
# The hard constraint: an invariant must remain a CEM-provable hypothesis,    #
# expressed through the EXISTING case_store path -- no new store/table.       #
# --------------------------------------------------------------------------- #
def test_every_candidate_is_expressible_as_a_cem_provable_hypothesis(tmp_path):
    db = str(tmp_path / "case.db")
    cands = invariant_probe.mine_invariants(build_corpus())
    assert cands, "expected at least one candidate to express"
    for c in cands:
        res = invariant_probe.to_cem_hypothesis(c, db_path=db)
        assert "error" not in res, res
        # the candidate is linked to a real hypothesis row (to falsify, not assert).
        finding = case_store.get_finding(res["finding_id"], db_path=db)
        assert finding and finding["hypothesis_id"] == res["hypothesis_id"]
        # CEM state is actually defined for the finding (==> CEM-provable).
        state = case_store.cem_load_state(res["finding_id"], db_path=db)
        assert "error" not in state, state
        assert state["conditions"], "a CEM-provable invariant needs >=1 candidate condition"
        assert state["meta"]["success_signature"], "CEM needs the caller-supplied oracle"
        assert res["condition_ids"]


def test_expressing_a_candidate_adds_no_new_table(tmp_path):
    """'invariants remain CEM-provable hypotheses ... no new store' -- the probe
    must reuse case_store's existing schema, not invent a parallel truth-store."""
    db = str(tmp_path / "case.db")
    case_store._get_conn(db).close()  # materialize the stock schema
    before = _table_set(db)
    cand = invariant_probe.mine_invariants(build_corpus())[0]
    invariant_probe.to_cem_hypothesis(cand, db_path=db)
    assert _table_set(db) == before


def _table_set(db):
    conn = case_store._get_conn(db)
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Blindness / integrity (benchmarks.md)                                       #
# --------------------------------------------------------------------------- #
def test_probe_has_no_import_path_to_any_answer_key():
    """The prototype's success signal must not be auto-derived from ground
    truth: mcp-servers/invariant_probe.py must not import the evaluator-only
    answer key(s)."""
    src = pathlib.Path(ROOT, "mcp-servers", "invariant_probe.py").read_text()
    for needle in ("inv_answer_key", "lh_answer_key", "lh_evaluator", "bench_answer_key"):
        assert f"import {needle}" not in src
        assert f"from {needle}" not in src


def test_inv_answer_key_is_integrity_locked():
    ok, msg = bench_integrity.verify(_INV_KEY)
    assert ok, msg


# --------------------------------------------------------------------------- #
# The deliverable: the measured GO/NO-GO signal with numbers.                 #
# --------------------------------------------------------------------------- #
def test_measured_go_no_go_signal(tmp_path):
    """Pre-registered GO criterion (final decision is the human's), grounded in
    MASTER-ROADMAP-FINAL-v3.md section 5(P4):
      GO iff  (a) >=1 class-less invariant violation surfaced that class
                  scanning structurally misses  (differential value), AND
              (b) 0 false invariants on secured / out-of-family decoys
                  ('false positives a quality risk'), AND
              (c) every surfaced candidate is CEM-provable.
    """
    db = str(tmp_path / "case.db")
    cands = invariant_probe.mine_invariants(build_corpus())
    flagged = _resources_flagged(cands)

    surfaced_in_family = flagged & AK.IN_FAMILY
    false_invariants = flagged & AK.MUST_NOT_FLAG
    class_less_surfaced = flagged & AK.CLASS_LESS_IN_FAMILY

    cem_provable = all(
        "error" not in invariant_probe.to_cem_hypothesis(c, db_path=db) for c in cands)

    recall = len(surfaced_in_family) / len(AK.IN_FAMILY)
    precision = len(surfaced_in_family) / len(flagged) if flagged else 0.0

    # (a) differential value over class scanning, (b) zero false invariants,
    # (c) CEM-provable.
    assert len(class_less_surfaced) >= 1, (
        "NO-GO: surfaced no class-less invariant violation that class scanning misses")
    assert len(false_invariants) == 0, f"NO-GO: false invariants on {false_invariants}"
    assert cem_provable, "NO-GO: a candidate was not CEM-provable"
    # the full in-family set was recovered with perfect precision on this corpus.
    assert recall == 1.0 and precision == 1.0


# =========================================================================== #
# UPGRADE: high-recall probe + negative-control confidence, and the 4         #
# code-review fixes.  (The PIPELINE-measured GO/NO-GO lives in                 #
# tests/test_invariant_probe_pipeline.py.)                                    #
# =========================================================================== #
def _cand_for(resource, candidates):
    return next((c for c in candidates if c["resource"] == resource), None)


def test_high_recall_flags_public_shared_decoy_but_marks_it_low_confidence():
    """The canonical T1 false positive: a public/shared resource (2xx+content to
    >=2 identities, NO denial).  The probe must STILL flag it (high recall, so
    CEM can gate it) but annotate LOW confidence via the negative control."""
    corpus = inv_decoys.observe(inv_decoys.PUB_SHARED, ["alice", "bob"])
    cand = _cand_for(inv_decoys.PUB_SHARED, invariant_probe.mine_invariants(corpus))
    assert cand is not None, "high-recall probe must not silently drop the public case"
    assert cand["confidence"] == "low"
    assert cand["negative_control"]["denial_seen"] is False
    assert cand["negative_control"]["content_relation"] == "identical"


def test_denial_elsewhere_on_resource_raises_ownership_confidence():
    """Negative control: a 4xx denial seen for SOME identity on the resource is
    evidence it is per-owner protected -> higher confidence a 2xx cross-identity
    read is a real violation (reuses the denial signal, not reinvented)."""
    corpus = [
        {"identity": "alice", "resource": "r1", "action": "read", "args": {},
         "status": 200, "body": "owner view of object r1"},
        {"identity": "bob", "resource": "r1", "action": "read", "args": {},
         "status": 200, "body": "SECRET object r1 leaked"},
        {"identity": "carol", "resource": "r1", "action": "read", "args": {},
         "status": 403, "body": "forbidden"},
    ]
    cand = _cand_for("r1", invariant_probe.mine_invariants(corpus))
    assert cand is not None
    assert cand["negative_control"]["denial_seen"] is True
    assert cand["confidence"] == "high"


def test_malformed_corpus_row_is_skipped_not_raised():
    """Fix (i): a partial/malformed row must degrade (skip the row) rather than
    abort the whole mine -- the repo's capture-failure-never-aborts convention."""
    good = build_corpus()
    corpus = [{"identity": "x"}, {"resource": "y", "status": "nope"}, None] + good
    cands = invariant_probe.mine_invariants(corpus)  # must not raise
    flagged = _resources_flagged(cands)
    assert "lh_s_bravo" in flagged and "lh_s_charlie" in flagged


def test_row_missing_args_key_does_not_crash_one_time_use():
    """Fix (i) completeness: 'args' is NOT in _REQUIRED_KEYS, yet one_time_use
    reads r['args'] -- a row carrying the 5 required keys but no 'args' must
    still degrade (be grouped with args={}), never KeyError out of the mine."""
    corpus = [
        {"identity": "a", "resource": "cart", "action": "apply",
         "status": 200, "body": "applied: 1"},
        {"identity": "a", "resource": "cart", "action": "apply",
         "status": 200, "body": "applied: 2"},
    ]
    invariant_probe.mine_invariants(corpus)  # must not raise


def test_row_with_unhashable_resource_is_skipped_not_raised():
    """Fix (ii) completeness: a non-str (unhashable) resource/action must be
    rejected by _valid_row so the groupby key never raises 'unhashable type'
    out of the whole mine."""
    good = build_corpus()
    corpus = [{"identity": "a", "resource": ["x", 1], "action": "read",
               "args": {}, "status": 200, "body": "b"}] + good
    cands = invariant_probe.mine_invariants(corpus)  # must not raise
    assert "lh_s_bravo" in _resources_flagged(cands)


def test_replays_in_different_sessions_are_not_counted_as_accumulation():
    """Fix (ii): two legitimate re-reads/replays in DIFFERENT sessions (or
    epochs) are not in-session accumulation and must not be flagged one_time_use;
    the same replays within ONE session still are."""
    # differing bodies (would look like accumulation) but DIFFERENT sessions:
    # must NOT be flagged -- these are two independent legitimate actions.
    diff_session = [
        {"identity": "a", "resource": "cart", "action": "apply", "args": {},
         "status": 200, "body": "applied: 1", "session": "s1"},
        {"identity": "a", "resource": "cart", "action": "apply", "args": {},
         "status": 200, "body": "applied: 1 (new cart)", "session": "s2"},
    ]
    assert not [c for c in invariant_probe.mine_invariants(diff_session)
                if c["invariant"] == "one_time_use"]
    # the same two differing responses WITHIN one session = real accumulation.
    same_session = [{**r, "session": "s1"} for r in diff_session]
    assert [c for c in invariant_probe.mine_invariants(same_session)
            if c["invariant"] == "one_time_use"]


def test_all_qualifying_replay_groups_are_emitted():
    """Fix (iii): emit ALL qualifying replay groups on a resource, not only the
    first -- two different identities each accumulating state are two candidates."""
    corpus = []
    for ident in ("a", "b"):
        corpus += [
            {"identity": ident, "resource": "coupons", "action": "add", "args": {},
             "status": 200, "body": f"{ident}: 1"},
            {"identity": ident, "resource": "coupons", "action": "add", "args": {},
             "status": 200, "body": f"{ident}: 2"},
        ]
    otu = [c for c in invariant_probe.mine_invariants(corpus)
           if c["invariant"] == "one_time_use" and c["resource"] == "coupons"]
    assert {c["cem_spec"]["base_request"].get("identity",
            c.get("identity")) for c in otu} or len(otu) == 2
    assert len(otu) == 2


def test_cem_spec_uses_frozen_pipeline_drop_perturbation():
    """'CEM-provable' must mean RUNNABLE by the frozen Phase-1 pipeline, which
    only supports perturbation {"drop": true} on a header/query-param named by
    the condition.  The base_request must be a GET whose URL carries that param."""
    from urllib.parse import parse_qsl, urlsplit
    for c in invariant_probe.mine_invariants(build_corpus()):
        spec = c["cem_spec"]
        assert spec["base_request"]["method"] == "GET"
        params = dict(parse_qsl(urlsplit(spec["base_request"]["url"]).query))
        for cond in spec["conditions"]:
            assert cond["perturbation"] == {"drop": True}
            assert cond["name"] in params, (cond["name"], params)
