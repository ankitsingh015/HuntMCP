import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "bench_target"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "cem_target"))

import bench_integrity


def test_verify_fails_when_no_lock_file_exists(tmp_path):
    target = tmp_path / "some_file.py"
    target.write_text("x = 1\n")
    ok, msg = bench_integrity.verify(str(target))
    assert ok is False
    assert "integrity lock missing" in msg


def test_update_then_verify_succeeds(tmp_path):
    target = tmp_path / "some_file.py"
    target.write_text("x = 1\n")
    bench_integrity.update(str(target))
    ok, msg = bench_integrity.verify(str(target))
    assert ok is True
    assert "integrity OK" in msg


def test_verify_fails_after_the_file_changes_post_lock(tmp_path):
    target = tmp_path / "some_file.py"
    target.write_text("x = 1\n")
    bench_integrity.update(str(target))
    target.write_text("x = 2\n")  # tampered, no re-lock
    ok, msg = bench_integrity.verify(str(target))
    assert ok is False
    assert "INTEGRITY FAILURE" in msg


# === NEW TESTS: bench_scenarios and bench_answer_key ===

import bench_scenarios
import bench_answer_key


def test_scenarios_covers_all_six_cases():
    assert set(bench_scenarios.SCENARIOS) == {
        "case_sqli", "case_xss", "case_idor", "case_backup_file", "case_misconfig", "case_open_redirect",
    }


def test_scenarios_never_leaks_a_forbidden_answer_field():
    import json
    blob = json.dumps({k: dict(v) for k, v in bench_scenarios.SCENARIOS.items()})
    for field in bench_scenarios.FORBIDDEN_ANSWER_FIELDS:
        assert field not in blob, f"{field!r} leaked into the blind scenario manifest"


def test_answer_key_has_an_entry_for_every_scenario_case():
    assert set(bench_answer_key.EXPECTED_BY_MODE) == set(bench_scenarios.SCENARIOS)


def test_answer_key_expects_confirmed_true_in_vulnerable_and_false_in_patched():
    for case_id, by_mode in bench_answer_key.EXPECTED_BY_MODE.items():
        assert by_mode["vulnerable"]["confirmed"] is True, case_id
        assert by_mode["patched"]["confirmed"] is False, case_id


def test_bench_scenarios_and_answer_key_integrity_locks_hold():
    import os

    import bench_integrity
    fixture_dir = os.path.dirname(bench_scenarios.__file__)
    for name in ("bench_scenarios.py", "bench_answer_key.py"):
        ok, msg = bench_integrity.verify(os.path.join(fixture_dir, name))
        assert ok, msg


# === NEW TESTS: bench_evaluator ===

from bench_evaluator import ObservedFinding, evaluate, reproducibility


def test_evaluate_scores_a_correct_confirmation_as_coverage_and_yield():
    observed = [ObservedFinding(location="/bench/products", confirmed=True, tool="sqlmap")]
    report = evaluate(observed, mode="vulnerable")
    assert report.yield_ == 1
    assert report.coverage == 1 / 6
    assert report.false_positives == 0
    assert report.novel_findings == 0


def test_evaluate_counts_a_patched_mode_confirmation_as_a_false_positive():
    observed = [ObservedFinding(location="/bench/products", confirmed=True, tool="sqlmap")]
    report = evaluate(observed, mode="patched")
    assert report.false_positives == 1
    assert report.yield_ == 0


def test_evaluate_buckets_an_unmatched_confirmation_as_novel_never_as_a_false_positive():
    observed = [ObservedFinding(location="/bench/totally-unplanted-endpoint", confirmed=True, tool="curl")]
    report = evaluate(observed, mode="vulnerable")
    assert report.novel_findings == 1
    assert report.false_positives == 0
    assert report.coverage == 0.0


def test_evaluate_ignores_query_string_when_matching_path():
    observed = [ObservedFinding(location="/bench/products?id=99", confirmed=True, tool="sqlmap")]
    report = evaluate(observed, mode="vulnerable")
    assert report.yield_ == 1


def test_evaluate_matches_a_parameterized_idor_path_to_its_general_route():
    """Regression for a pre-flight-scan finding: bench_scenarios' case_idor
    endpoint is the general route "/bench/orders" (no id) -- a real
    observed IDOR finding's location carries the specific object id (e.g.
    "/bench/orders/42"), which must still match case_idor, not be bucketed
    as a novel finding."""
    observed = [ObservedFinding(location="/bench/orders/42", confirmed=True, tool="idor-mcp")]
    report = evaluate(observed, mode="vulnerable")
    assert report.yield_ == 1
    assert report.novel_findings == 0


def test_reproducibility_true_across_identical_reports():
    observed = [ObservedFinding(location="/bench/products", confirmed=True, tool="sqlmap")]
    r1 = evaluate(observed, mode="vulnerable")
    r2 = evaluate(observed, mode="vulnerable")
    ok, msg = reproducibility([r1, r2])
    assert ok, msg


def test_reproducibility_false_across_differing_reports():
    r1 = evaluate([ObservedFinding(location="/bench/products", confirmed=True)], mode="vulnerable")
    r2 = evaluate([], mode="vulnerable")
    ok, msg = reproducibility([r1, r2])
    assert not ok


def test_observed_finding_evidence_default_is_not_shared_between_instances():
    """Regression: NamedTuple field defaults are evaluated once at class-
    definition time and shared by every instance that omits the field.
    This test verifies the fix for the mutable-default aliasing bug where
    omitting `evidence` on two separate instances made them share ONE dict
    object (e.g. a.evidence is b.evidence == True), so mutating one's
    `.evidence` in place silently corrupted the other's."""
    a = ObservedFinding(location="/bench/products", confirmed=True)
    b = ObservedFinding(location="/bench/search", confirmed=True)
    assert a.evidence_or_empty() is not b.evidence_or_empty()


# === NEW TESTS: verify_evidence_trail ===

def test_verify_evidence_trail_confirms_two_differing_idor_requests():
    from bench_evaluator import verify_evidence_trail
    request_log = [
        {"path": "/bench/orders/42", "cookie": "session=owner-session"},
        {"path": "/bench/orders/42", "cookie": "session=attacker-session"},
    ]
    ok, msg = verify_evidence_trail(request_log, "case_idor", {"baseline": 0, "perturbed": 1})
    assert ok, msg


def test_verify_evidence_trail_rejects_identical_baseline_and_perturbed():
    from bench_evaluator import verify_evidence_trail
    request_log = [
        {"path": "/bench/orders/42", "cookie": "session=owner-session"},
        {"path": "/bench/orders/42", "cookie": "session=owner-session"},
    ]
    ok, msg = verify_evidence_trail(request_log, "case_idor", {"baseline": 0, "perturbed": 1})
    assert not ok


def test_bench_and_cem_fixtures_coexist_in_one_pytest_session():
    """Regression for the module-cache collision risk named in the spec:
    both fixture packages' identically-shaped-but-differently-named
    modules must not cross-contaminate."""
    import bench_scenarios
    import scenarios as cem_scenarios  # tests/fixtures/cem_target's own bare-named module

    assert "case_sqli" in bench_scenarios.SCENARIOS
    assert "case_sqli" not in cem_scenarios.SCENARIOS
    assert "case_01" in cem_scenarios.SCENARIOS
    assert "case_01" not in bench_scenarios.SCENARIOS
