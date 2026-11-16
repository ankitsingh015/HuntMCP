"""P4-INFOGAIN -- information-gain experiment ORDERING (hints, never skips).

MASTER-ROADMAP-FINAL-v3.md decision matrix "Info-gain experiment selection
(UU-3)" (GATED; "orders, never hard-blocks a novel test") and section 11-A
absolute security invariant: "allocation/dedupe/negative-knowledge never
hard-block a not-yet-confirmed novel test (hints, never skips)".

These tests pin the ordering model and, above all, the load-bearing guardrail:
the module ORDERS candidate experiments by expected information-gain-per-cost
but NEVER removes a candidate and NEVER penalizes a novel (no-history) test for
lacking a track record -- a novel test is scored with an optimistic prior
(optimism-under-uncertainty) so it is never ranked below a known low-yield test
purely for being new.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import info_gain  # noqa: E402  -- module under test


# --------------------------------------------------------------------------- #
# Ordering model                                                              #
# --------------------------------------------------------------------------- #
def test_orders_by_info_gain_per_cost():
    history = {"sqli": {"trials": 10, "hits": 8}, "xss": {"trials": 10, "hits": 1}}
    cands = [{"id": "a", "vuln_class": "xss", "cost": 1.0},
             {"id": "b", "vuln_class": "sqli", "cost": 1.0}]
    out = info_gain.order_experiments(cands, history)
    assert [c["id"] for c in out] == ["b", "a"]


def test_higher_cost_lowers_rank_for_equal_gain():
    history = {"sqli": {"trials": 10, "hits": 5}}
    cands = [{"id": "pricey", "vuln_class": "sqli", "cost": 5.0},
             {"id": "cheap", "vuln_class": "sqli", "cost": 1.0}]
    out = info_gain.order_experiments(cands, history)
    assert [c["id"] for c in out] == ["cheap", "pricey"]


# --------------------------------------------------------------------------- #
# The load-bearing guardrail: HINTS, NEVER SKIPS; novelty is never penalized  #
# --------------------------------------------------------------------------- #
def test_returns_all_candidates_never_drops_any():
    history = {"sqli": {"trials": 5, "hits": 5}}
    cands = [{"id": str(i), "vuln_class": "sqli", "cost": 1.0} for i in range(5)]
    out = info_gain.order_experiments(cands, history)
    assert sorted(c["id"] for c in out) == sorted(c["id"] for c in cands)
    assert len(out) == len(cands)


def test_novel_test_is_never_ranked_below_a_known_low_yield_test():
    """§11-A: a not-yet-confirmed novel test must never be hard-blocked and must
    never be penalized for lacking history. A known LOW-yield class vs a novel
    class at equal cost -> the novel one must rank first (optimism)."""
    history = {"xss": {"trials": 20, "hits": 1}}  # known, very low yield
    cands = [{"id": "known_low", "vuln_class": "xss", "cost": 1.0},
             {"id": "novel", "vuln_class": "brand_new_class", "cost": 1.0}]
    out = info_gain.order_experiments(cands, history)
    assert out[0]["id"] == "novel"
    assert out[0]["_novel"] is True


def test_novel_gets_optimistic_prior_equal_to_best_known_not_zero():
    history = {"sqli": {"trials": 10, "hits": 9}, "xss": {"trials": 10, "hits": 1}}
    out = info_gain.order_experiments(
        [{"id": "n", "vuln_class": "never_seen", "cost": 1.0}], history)
    best_known = (9 + 1.0) / (10 + 2.0)  # Laplace-smoothed max known gain
    assert out[0]["_info_gain"] == round(best_known, 6)
    assert out[0]["_info_gain"] > 0.0
    assert out[0]["_novel"] is True


def test_missing_key_is_treated_as_novel():
    out = info_gain.order_experiments(
        [{"id": "a", "cost": 1.0}], {"sqli": {"trials": 9, "hits": 9}})
    assert out[0]["_novel"] is True


def test_no_history_all_novel_preserves_stable_order():
    cands = [{"id": "a", "vuln_class": "x", "cost": 1.0},
             {"id": "b", "vuln_class": "y", "cost": 1.0}]
    out = info_gain.order_experiments(cands, {})
    assert [c["id"] for c in out] == ["a", "b"]  # stable; nothing penalized
    assert all(c["_novel"] for c in out)


def test_ordering_is_deterministic_stable_tie_break():
    history = {"sqli": {"trials": 10, "hits": 5}}
    cands = [{"id": "a", "vuln_class": "sqli", "cost": 1.0},
             {"id": "b", "vuln_class": "sqli", "cost": 1.0},
             {"id": "c", "vuln_class": "sqli", "cost": 1.0}]
    assert ([c["id"] for c in info_gain.order_experiments(cands, history)]
            == [c["id"] for c in info_gain.order_experiments(cands, history)]
            == ["a", "b", "c"])


# --------------------------------------------------------------------------- #
# Robustness / edges                                                          #
# --------------------------------------------------------------------------- #
def test_empty_input_returns_empty():
    assert info_gain.order_experiments([], {"a": {"trials": 1, "hits": 1}}) == []


def test_nonpositive_cost_is_clamped_not_crash():
    history = {"sqli": {"trials": 4, "hits": 2}}
    out = info_gain.order_experiments(
        [{"id": "z", "vuln_class": "sqli", "cost": 0}], history)  # no ZeroDivisionError
    assert out and out[0]["id"] == "z"


def test_does_not_mutate_input_candidates():
    cands = [{"id": "a", "vuln_class": "sqli", "cost": 1.0}]
    info_gain.order_experiments(cands, {"sqli": {"trials": 2, "hits": 1}})
    assert cands == [{"id": "a", "vuln_class": "sqli", "cost": 1.0}]  # annotations only on the copy


# --------------------------------------------------------------------------- #
# History from case_store (offline, read-only, fail-safe toward exploration)  #
# --------------------------------------------------------------------------- #
def test_build_history_from_case_store(tmp_path):
    import case_store
    db = str(tmp_path / "case.db")
    case_store.create_finding(vuln_class="sqli", endpoint="/a", parameter="p", db_path=db)
    case_store.create_finding(vuln_class="sqli", endpoint="/b", parameter="q", db_path=db)
    case_store.create_finding(vuln_class="xss", endpoint="/c", parameter="r", db_path=db)
    hist = info_gain.build_history_from_case_store(db)
    assert hist["sqli"]["trials"] == 2
    assert hist["xss"]["trials"] == 1
    assert hist["sqli"]["hits"] == 0  # none CONFIRMED yet


def test_build_history_counts_all_success_statuses_as_hits(tmp_path):
    """A 'hit' = a test of this class paid off, i.e. reached ANY successful
    terminal status (CONFIRMED/IMPACT_PROVEN/REPORTED), not only CONFIRMED --
    otherwise a class whose findings were escalated to IMPACT_PROVEN/REPORTED
    would read as zero-yield and be mis-ranked."""
    import case_store
    db = str(tmp_path / "case.db")
    for status in ("CONFIRMED", "IMPACT_PROVEN", "REPORTED", "DISCOVERED"):
        f = case_store.create_finding(vuln_class="sqli", endpoint="/" + status,
                                      parameter="p", db_path=db)
        conn = case_store._get_conn(db)  # set status directly; we test the READER
        try:
            conn.execute("UPDATE findings SET status=? WHERE id=?", (status, f["id"]))
            conn.commit()
        finally:
            conn.close()
    hist = info_gain.build_history_from_case_store(db)
    assert hist["sqli"]["trials"] == 4
    assert hist["sqli"]["hits"] == 3  # the 3 success statuses, not DISCOVERED


def test_explicit_zero_trials_entry_is_known_not_novel():
    """Intended semantics: an ABSENT class is novel (optimistic prior); an
    EXPLICIT {trials:0,hits:0} entry is 'seen, no data yet' -> known, gain 0.5."""
    history = {"seen": {"trials": 0, "hits": 0}}
    out = info_gain.order_experiments(
        [{"id": "seen", "vuln_class": "seen", "cost": 1.0},
         {"id": "absent", "vuln_class": "never", "cost": 1.0}], history)
    by_id = {c["id"]: c for c in out}
    assert by_id["seen"]["_novel"] is False and by_id["seen"]["_info_gain"] == 0.5
    assert by_id["absent"]["_novel"] is True


def test_build_history_degrades_to_empty_on_error():
    """Fail-safe toward exploration: if history can't be read, everything is
    novel -> optimism -> nothing penalized (never hard-block a novel test)."""
    assert info_gain.build_history_from_case_store("/no/such/dir/nope.db") == {}
