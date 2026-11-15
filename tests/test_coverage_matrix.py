"""P4-COVMATRIX -- full endpoint x vuln_class x role coverage matrix with an
anti-gaming clause. Extends P2-COV (coverage_signal.compute_coverage): adds the
ROLE dimension and an evidence-backed "covered" predicate an agent cannot
inflate by merely declaring findings.

Role source note (asserted by these tests): case_store has no role column; the
one structured role tag the data model records is authz_diff.emit_finding()'s
`<carried_path>@<identity>` finding parameter. compute_coverage_matrix() derives
role from that convention, with a sentinel "-" for unroled findings.
"""

import os

import case_store
import coverage_signal


def _db(tmp_path):
    return str(tmp_path / "case.db")


def _covered_cell(report, endpoint, vuln_class, role):
    for c in report["cells"]:
        if c["endpoint"] == endpoint and c["vuln_class"] == vuln_class and c["role"] == role:
            return c
    return None


# ---- role dimension -------------------------------------------------------

def test_matrix_derives_role_from_authz_parameter_convention(tmp_path):
    db = _db(tmp_path)
    # authz matrix findings tag the identity as <carried_path>@<identity>
    f = case_store.create_finding("IDOR_MULTISTEP", "/api/order", parameter="/order/id@attacker", db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=f["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    cell = _covered_cell(report, "/api/order", "IDOR_MULTISTEP", "attacker")
    assert cell is not None
    assert cell["covered"] is True
    assert cell["evidence_count"] == 1
    assert "attacker" in report["roles"]


def test_matrix_unroled_finding_uses_sentinel_role(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)  # no @identity in parameter
    case_store.add_evidence("request", "req", finding_id=f["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    cell = _covered_cell(report, "/api/x", "SQLi", "-")
    assert cell is not None
    assert cell["covered"] is True


def test_matrix_distinct_roles_same_endpoint_and_class(tmp_path):
    db = _db(tmp_path)
    fa = case_store.create_finding("IDOR_MULTISTEP", "/api/order", parameter="/order/id@admin", db_path=db)
    fg = case_store.create_finding("IDOR_MULTISTEP", "/api/order", parameter="/order/id@guest", db_path=db)
    case_store.add_evidence("metadata", "pa", finding_id=fa["id"], db_path=db)
    case_store.add_evidence("metadata", "pg", finding_id=fg["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    assert sorted(report["roles"]) == ["admin", "guest"]
    assert report["covered"] == 2
    assert _covered_cell(report, "/api/order", "IDOR_MULTISTEP", "admin")["covered"] is True
    assert _covered_cell(report, "/api/order", "IDOR_MULTISTEP", "guest")["covered"] is True


# ---- ANTI-GAMING: evidence-backed predicate -------------------------------

def test_asserting_a_finding_without_evidence_is_not_covered(tmp_path):
    """Core anti-gaming property: declaring a finding (create_finding) with NO
    evidence must NOT mark its cell covered -- a cell is covered only on real,
    evidence-backed activity, never on self-assertion."""
    db = _db(tmp_path)
    case_store.create_finding("SQLi", "/api/x", parameter="/id@admin", db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    cell = _covered_cell(report, "/api/x", "SQLi", "admin")
    assert cell is not None
    assert cell["covered"] is False
    assert cell["evidence_count"] == 0
    assert report["covered"] == 0
    assert report["uncovered"] == 1


def test_spamming_bare_findings_does_not_inflate_covered_count(tmp_path):
    """An agent that spams create_finding() across many triples with zero
    evidence cannot move the covered count -- inflation attempt is visible as
    uncovered, not hidden as covered."""
    db = _db(tmp_path)
    for i in range(10):
        case_store.create_finding("SQLi", f"/api/{i}", parameter="/id@admin", db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    assert report["covered"] == 0
    assert report["uncovered"] == 10


def test_experiment_alone_does_not_make_a_cell_covered(tmp_path):
    """A logged experiment is surfaced as context but is NOT sufficient for
    covered: only a content-addressed evidence row counts (same bar case_store
    uses to gate CONFIRMED)."""
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", parameter="/id@admin", db_path=db)
    case_store.log_experiment("sqlmap", "payload", "/api/x", finding_id=f["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    cell = _covered_cell(report, "/api/x", "SQLi", "admin")
    assert cell["covered"] is False
    assert cell["experiment_count"] == 1
    assert cell["evidence_count"] == 0


def test_evidence_linked_only_to_a_hypothesis_does_not_cover_a_finding_cell(tmp_path):
    db = _db(tmp_path)
    h = case_store.log_hypothesis("obs", "hyp", db_path=db)
    case_store.create_finding("SQLi", "/api/x", parameter="/id@admin", db_path=db)
    case_store.add_evidence("request", "req", hypothesis_id=h["id"], db_path=db)  # not finding-linked
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    cell = _covered_cell(report, "/api/x", "SQLi", "admin")
    assert cell["covered"] is False


def test_evidence_aggregates_across_findings_of_the_same_triple(tmp_path):
    db = _db(tmp_path)
    f1 = case_store.create_finding("IDOR_MULTISTEP", "/api/order", parameter="/order/id@admin", db_path=db)
    case_store.create_finding("IDOR_MULTISTEP", "/api/order", parameter="/order/id@admin", db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=f1["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    cell = _covered_cell(report, "/api/order", "IDOR_MULTISTEP", "admin")
    assert cell["covered"] is True
    assert cell["finding_count"] == 2
    assert cell["evidence_count"] == 1


# ---- role-gap (H3) view ---------------------------------------------------

def test_role_gaps_flag_named_roles_covered_elsewhere_but_not_here(tmp_path):
    db = _db(tmp_path)
    # /api/x IDOR covered for admin; guest is a real identity covered on /api/y.
    fx = case_store.create_finding("IDOR_MULTISTEP", "/api/x", parameter="/id@admin", db_path=db)
    fy = case_store.create_finding("IDOR_MULTISTEP", "/api/y", parameter="/id@guest", db_path=db)
    case_store.add_evidence("metadata", "px", finding_id=fx["id"], db_path=db)
    case_store.add_evidence("metadata", "py", finding_id=fy["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    gaps = {(g["endpoint"], g["vuln_class"]): g["uncovered_roles"] for g in report["role_gaps"]}
    assert "guest" in gaps[("/api/x", "IDOR_MULTISTEP")]
    assert "admin" in gaps[("/api/y", "IDOR_MULTISTEP")]


def test_role_gaps_omit_pairs_covered_for_no_role(tmp_path):
    """A pair covered for zero roles (only asserted/uncovered) is NOT a per-role
    gap -- it is a fully-uncovered cell already visible in `cells`. Listing every
    role for it would be noise, so role_gaps omits it."""
    db = _db(tmp_path)
    # /api/x SQLi only ASSERTED for admin (no evidence); /api/y covered for guest.
    case_store.create_finding("SQLi", "/api/x", parameter="/id@admin", db_path=db)
    fy = case_store.create_finding("IDOR_MULTISTEP", "/api/y", parameter="/id@guest", db_path=db)
    case_store.add_evidence("metadata", "py", finding_id=fy["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    gap_pairs = {(g["endpoint"], g["vuln_class"]) for g in report["role_gaps"]}
    assert ("/api/x", "SQLi") not in gap_pairs  # covered for no role -> omitted
    assert ("/api/y", "IDOR_MULTISTEP") in gap_pairs  # covered for guest, admin is a gap


def test_role_gaps_empty_when_no_named_roles(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.add_evidence("request", "r", finding_id=f["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    assert report["role_gaps"] == []


# ---- status breakdown -----------------------------------------------------

def test_matrix_by_status_breakdown_per_cell(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", parameter="/id@admin", db_path=db)
    case_store.add_evidence("request", "r", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "SUSPECTED", db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    cell = _covered_cell(report, "/api/x", "SQLi", "admin")
    assert cell["by_status"] == {"SUSPECTED": 1}


# ---- redaction ------------------------------------------------------------

def test_matrix_redacts_endpoint_and_vuln_class(tmp_path):
    db = _db(tmp_path)
    secret = "sk-live-abcdef1234567890abcdef1234567890"  # gitleaks:allow
    f = case_store.create_finding("SQLi", f"/api/x?token={secret}", db_path=db)
    case_store.add_evidence("request", "r", finding_id=f["id"], db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    assert all(secret not in c["endpoint"] for c in report["cells"])


# ---- empty / no-db --------------------------------------------------------

def test_matrix_empty_case_store(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    assert report["cells"] == []
    assert report["covered"] == 0
    assert report["uncovered"] == 0
    assert report["roles"] == []
    assert report["role_gaps"] == []


def test_matrix_never_creates_a_case_db_when_none_exists(tmp_path):
    db = _db(tmp_path)
    assert not os.path.exists(db)
    report = coverage_signal.compute_coverage_matrix(db_path=db)
    assert "error" in report
    assert not os.path.exists(db)


# ---- read-only enforcement ------------------------------------------------

def test_matrix_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", parameter="/id@admin", db_path=db)
    case_store.add_evidence("request", "r", finding_id=f["id"], db_path=db)
    before = case_store.case_export(db_path=db)
    coverage_signal.compute_coverage_matrix(db_path=db)
    after = case_store.case_export(db_path=db)
    assert before == after
