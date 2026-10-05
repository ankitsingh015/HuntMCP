import os

import case_store
import coverage_signal


def _db(tmp_path):
    return str(tmp_path / "case.db")


# ---- basic pair coverage -------------------------------------------------

def test_compute_coverage_reports_a_single_tested_pair(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)
    report = coverage_signal.compute_coverage(db_path=db)
    assert report["pairs_tested"] == 1
    assert report["endpoints_tested"] == 1
    assert report["vuln_classes_tested"] == 1
    assert report["coverage_matrix"] == [
        {"endpoint": "/api/x", "vuln_class": "SQLi", "finding_id": f["id"], "status": "DISCOVERED"}
    ]


def test_compute_coverage_counts_distinct_endpoints_and_classes_not_findings(tmp_path):
    db = _db(tmp_path)
    # two different vuln classes on the SAME endpoint -- 1 endpoint, 2 classes, 2 pairs
    case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.create_finding("XSS", "/api/x", db_path=db)
    report = coverage_signal.compute_coverage(db_path=db)
    assert report["endpoints_tested"] == 1
    assert report["vuln_classes_tested"] == 2
    assert report["pairs_tested"] == 2


def test_compute_coverage_same_endpoint_and_class_twice_is_one_pair(tmp_path):
    db = _db(tmp_path)
    # a re-tested (endpoint, vuln_class) pair (e.g. re-confirmed after a fix) is
    # still ONE pair in the coverage signal, not two -- coverage measures WHICH
    # surface was touched, not how many times.
    case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.create_finding("SQLi", "/api/x", db_path=db)
    report = coverage_signal.compute_coverage(db_path=db)
    assert report["pairs_tested"] == 1
    assert len(report["coverage_matrix"]) == 2  # both individual findings still cited


def test_compute_coverage_empty_case_store(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)  # a real case.db, but no findings yet
    report = coverage_signal.compute_coverage(db_path=db)
    assert report["pairs_tested"] == 0
    assert report["endpoints_tested"] == 0
    assert report["vuln_classes_tested"] == 0
    assert report["coverage_matrix"] == []


def test_compute_coverage_never_creates_a_case_db_when_none_exists(tmp_path):
    db = _db(tmp_path)
    assert not os.path.exists(db)
    report = coverage_signal.compute_coverage(db_path=db)
    assert "error" in report
    assert not os.path.exists(db), "compute_coverage() must not create a case.db that didn't exist"


# ---- status breakdown -----------------------------------------------------

def test_compute_coverage_by_status_breakdown(tmp_path):
    db = _db(tmp_path)
    f1 = case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.create_finding("XSS", "/api/y", db_path=db)  # stays DISCOVERED
    case_store.update_finding_status(f1["id"], "SUSPECTED", db_path=db)
    report = coverage_signal.compute_coverage(db_path=db)
    assert report["by_status"] == {"DISCOVERED": 1, "SUSPECTED": 1}


# ---- redaction --------------------------------------------------------------

def test_compute_coverage_redacts_endpoint_and_vuln_class(tmp_path):
    db = _db(tmp_path)
    case_store.create_finding("SQLi", "/api/x?token=sk-live-abcdef1234567890abcdef1234567890", db_path=db)
    report = coverage_signal.compute_coverage(db_path=db)
    endpoint = report["coverage_matrix"][0]["endpoint"]
    assert "sk-live-abcdef1234567890abcdef1234567890" not in endpoint


# ---- read-only enforcement --------------------------------------------------

def test_compute_coverage_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    case_store.create_finding("SQLi", "/api/x", db_path=db)
    before = case_store.case_export(db_path=db)
    coverage_signal.compute_coverage(db_path=db)
    after = case_store.case_export(db_path=db)
    assert before == after


def test_coverage_module_has_no_write_or_tool_calls():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "mcp-servers", "coverage_signal.py")
    with open(path) as f:
        lines = f.readlines()
    # Strip the module docstring (a triple-quoted block at the top) so prose
    # describing what this module does NOT do doesn't trigger its own check.
    src = "".join(lines)
    if src.lstrip().startswith('"""'):
        first = src.index('"""')
        second = src.index('"""', first + 3)
        src = src[second + 3:]

    write_fns = [
        "log_hypothesis(", "update_hypothesis(", "add_evidence(", "log_experiment(",
        "create_finding(", "update_finding_status(", "score_finding_confidence(",
        "group_root_cause(", "cem_define(", "cem_record_trial(", "cem_record_verdict(",
        "cem_mark_incomplete(",
    ]
    tool_modules = ["tool_resolver", "job_runtime", "subprocess", "Popen", "scope_guard", "budget_guard"]
    for name in write_fns + tool_modules:
        assert name not in src, f"coverage.py must not reference {name!r}"
