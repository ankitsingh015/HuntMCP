import os

import case_store
import provenance_signal


def _db(tmp_path):
    return str(tmp_path / "case.db")


def test_compute_provenance_coverage_counts_by_class(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    case_store.add_evidence("callback", "hit", finding_id=f["id"],
                             provenance={"class": "wire", "method": "DNS", "url": "x.oast.fun"}, db_path=db)
    case_store.add_evidence("response", "output", finding_id=f["id"],
                             provenance={"class": "invocation", "tool": "nuclei"}, db_path=db)
    case_store.add_evidence("metadata", "agent note", finding_id=f["id"], db_path=db)

    report = provenance_signal.compute_provenance_coverage(db_path=db)

    assert report["totals"] == {"wire": 1, "invocation": 1, "none": 1}


def test_compute_provenance_coverage_per_finding_breakdown_is_evidence_cited(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    ev = case_store.add_evidence("callback", "hit", finding_id=f["id"],
                                  provenance={"class": "wire", "method": "DNS", "url": "x.oast.fun"}, db_path=db)

    report = provenance_signal.compute_provenance_coverage(db_path=db)

    entry = report["by_finding"][str(f["id"])]
    assert entry["wire"] == [ev["id"]]
    assert entry["invocation"] == []
    assert entry["none"] == []


def test_compute_provenance_coverage_ignores_evidence_linked_only_to_a_hypothesis(tmp_path):
    """A finding-level report shouldn't silently attribute hypothesis-only
    evidence to some finding it isn't actually linked to."""
    db = _db(tmp_path)
    h = case_store.log_hypothesis("obs", "hyp", db_path=db)
    case_store.add_evidence("metadata", "x", hypothesis_id=h["id"], db_path=db)

    report = provenance_signal.compute_provenance_coverage(db_path=db)

    assert report["by_finding"] == {}
    assert report["totals"] == {"wire": 0, "invocation": 0, "none": 1}


def test_compute_provenance_coverage_empty_case_store(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)
    report = provenance_signal.compute_provenance_coverage(db_path=db)
    assert report["totals"] == {"wire": 0, "invocation": 0, "none": 0}
    assert report["by_finding"] == {}


def test_compute_provenance_coverage_never_creates_a_case_db_when_none_exists(tmp_path):
    db = _db(tmp_path)
    assert not os.path.exists(db)
    report = provenance_signal.compute_provenance_coverage(db_path=db)
    assert "error" in report
    assert not os.path.exists(db)


def test_compute_provenance_coverage_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    case_store.add_evidence("callback", "hit", finding_id=f["id"], db_path=db)
    before = case_store.case_export(db_path=db)
    provenance_signal.compute_provenance_coverage(db_path=db)
    after = case_store.case_export(db_path=db)
    assert before == after


def test_provenance_signal_module_has_no_write_or_tool_calls():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "mcp-servers", "provenance_signal.py")
    with open(path) as f:
        src = f.read()
    if src.lstrip().startswith('"""'):
        first = src.index('"""')
        second = src.index('"""', first + 3)
        src = src[second + 3:]
    src = "\n".join(line.split("#", 1)[0] for line in src.splitlines())

    forbidden = [
        "log_hypothesis(", "update_hypothesis(", "add_evidence(", "log_experiment(",
        "create_finding(", "update_finding_status(", "score_finding_confidence(",
        "group_root_cause(", "cem_define(", "cem_record_trial(", "cem_record_verdict(",
        "cem_mark_incomplete(", "tool_resolver", "job_runtime", "subprocess", "Popen",
        "scope_guard", "budget_guard",
    ]
    for name in forbidden:
        assert name not in src, f"provenance_signal.py must not reference {name!r}"
