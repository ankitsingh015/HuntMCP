"""Evaluator self-tests for the P3-VALAUTHZ range (TEST-ONLY)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "authz_target"))

from authz_evaluator import ObservedFinding, evaluate  # noqa: E402

BASE = "http://127.0.0.1:1"
CARTS = f"{BASE}/authz/carts/ck-7f3a91/invoice"
ORDERS = f"{BASE}/authz/orders/42"
REPORTS = f"{BASE}/authz/reports/rp-31c4e2"
DRAFTS = f"{BASE}/authz/drafts/dr-0001-a"
RECEIPTS = f"{BASE}/authz/receipts/re-0002-a"
CATALOG = f"{BASE}/authz/catalog/sku-100"
PROFILES = f"{BASE}/authz/profiles/pr-a11ce0"


def _f(location, confirmed=True):
    return ObservedFinding(location=location, confirmed=confirmed, tool="t")


def test_perfect_vulnerable_run_scores_full_recall_zero_fp():
    r = evaluate([_f(CARTS), _f(ORDERS), _f(REPORTS), _f(DRAFTS)], "vulnerable")
    assert (r.true_positives, r.false_positives, r.false_negatives) == (4, 0, 3)  # the 3 matrix units unreported


def test_missing_the_multistep_case_is_a_false_negative_not_a_fp():
    r = evaluate([_f(ORDERS), _f(REPORTS), _f(DRAFTS)], "vulnerable")
    assert (r.true_positives, r.false_positives, r.false_negatives) == (3, 0, 4)
    assert r.per_case["case_authz_01"]["reported_confirmed"] is False


def test_confirming_a_look_alike_is_a_false_positive():
    r = evaluate([_f(CARTS), _f(ORDERS), _f(REPORTS), _f(CATALOG)], "vulnerable")
    assert r.false_positives == 1
    r = evaluate([_f(PROFILES)], "vulnerable")
    assert r.false_positives == 1


def test_any_confirmation_in_patched_mode_is_a_false_positive():
    r = evaluate([_f(CARTS)], "patched")
    assert (r.true_positives, r.false_positives) == (0, 1)


def test_patched_run_with_nothing_confirmed_is_clean():
    r = evaluate([_f(CARTS, confirmed=False)], "patched")
    assert (r.true_positives, r.false_positives, r.false_negatives) == (0, 0, 0)


def test_duplicate_confirmations_of_one_case_count_once():
    r = evaluate([_f(CARTS), _f(CARTS + "?x=1")], "vulnerable")
    assert r.true_positives == 1


def test_confirmation_outside_every_scenario_is_counted_separately_not_silently_dropped():
    r = evaluate([_f(f"{BASE}/other/thing")], "vulnerable")
    assert r.unmatched_confirmed == 1 and r.false_positives == 0


def test_report_and_statement_paths_are_scored_as_a_true_positive_and_a_false_positive():
    r = evaluate([_f(f"{BASE}/authz/reports/rp-31c4e2"), _f(f"{BASE}/authz/statements/st-6be2f0")], "vulnerable")
    assert (r.true_positives, r.false_positives, r.false_negatives) == (1, 1, 6)


def test_a_confirmed_receipt_is_a_false_positive_and_a_confirmed_draft_a_true_positive():
    r = evaluate([_f(DRAFTS), _f(RECEIPTS)], "vulnerable")
    assert (r.true_positives, r.false_positives) == (1, 1)


# --- per-identity scoring for the matrix cases --------------------------------------

LEDGER = f"{BASE}/authz/ledger/lg-5d11aa"
TEAMDOC = f"{BASE}/authz/teamdocs/td-90c3b2"


def _fi(location, identity, confirmed=True):
    return ObservedFinding(location=location, confirmed=confirmed, tool="t", identity=identity)


def test_matrix_findings_are_scored_per_identity():
    ok = [_fi(LEDGER, "bobby"), _fi(LEDGER, "carol"), _fi(TEAMDOC, "carol")]
    base = [_f(CARTS), _f(ORDERS), _f(REPORTS), _f(DRAFTS)]
    r = evaluate(base + ok, "vulnerable")
    assert (r.true_positives, r.false_positives, r.false_negatives) == (7, 0, 0)


def test_reporting_the_admin_or_the_same_tenant_user_is_a_false_positive():
    r = evaluate([_fi(LEDGER, "root"), _fi(TEAMDOC, "bobby")], "vulnerable")
    assert r.false_positives == 2


def test_missing_one_identity_is_a_false_negative_not_a_fp():
    r = evaluate([_fi(LEDGER, "bobby")], "vulnerable")
    assert r.false_positives == 0 and r.true_positives == 1 and r.false_negatives == 6


def test_an_unknown_identity_on_a_matrix_case_counts_as_a_false_positive():
    assert evaluate([_fi(LEDGER, "mallory")], "vulnerable").false_positives == 1


def test_any_matrix_confirmation_in_patched_mode_is_a_false_positive():
    assert evaluate([_fi(LEDGER, "carol")], "patched").false_positives == 1
