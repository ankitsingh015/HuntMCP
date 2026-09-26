import os

import case_store
import negative_knowledge


def _db(tmp_path):
    return str(tmp_path / "case.db")


def _experiment_for(tool, target, db_path, finding_id=None):
    return case_store.log_experiment(tool, "id=1", target, result="ran", finding_id=finding_id, db_path=db_path)


# ---- basic tally ------------------------------------------------------------

def test_compute_negative_knowledge_counts_a_confirmed_finding_as_effective(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    _experiment_for("sqlmap", "https://x", db, finding_id=f["id"])

    report = negative_knowledge.compute_negative_knowledge(db_path=db)

    assert report["tally"] == {
        "sqlmap::SQLi": {"tool": "sqlmap", "vuln_class": "SQLi", "effective_count": 1, "ineffective_count": 0}
    }


def test_compute_negative_knowledge_counts_a_false_positive_as_ineffective(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("XSS", "/api/y", db_path=db)
    case_store.update_finding_status(f["id"], "FALSE_POSITIVE", db_path=db)
    _experiment_for("dalfox", "https://y", db, finding_id=f["id"])

    report = negative_knowledge.compute_negative_knowledge(db_path=db)

    assert report["tally"]["dalfox::XSS"]["ineffective_count"] == 1
    assert report["tally"]["dalfox::XSS"]["effective_count"] == 0


def test_compute_negative_knowledge_excludes_in_flight_findings_from_the_tally(tmp_path):
    """A finding still DISCOVERED/SUSPECTED/VALIDATING/INCONCLUSIVE is
    "in flight," not resolved either way -- counting it as ineffective would
    falsely deprioritize a technique that just hasn't finished being
    investigated yet (same in-flight-vs-abandoned caution as P2-E1's own
    postmortem module)."""
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/z", db_path=db)  # stays DISCOVERED
    _experiment_for("curl", "https://z", db, finding_id=f["id"])

    report = negative_knowledge.compute_negative_knowledge(db_path=db)

    assert report["tally"] == {}


def test_compute_negative_knowledge_excludes_experiments_with_no_finding_id(tmp_path):
    db = _db(tmp_path)
    _experiment_for("subfinder", "example.com", db, finding_id=None)  # pure recon, no vuln class

    report = negative_knowledge.compute_negative_knowledge(db_path=db)

    assert report["tally"] == {}


def test_compute_negative_knowledge_hint_flags_only_all_ineffective_pairs(tmp_path):
    db = _db(tmp_path)
    effective_f = case_store.create_finding("SQLi", "/api/a", db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=effective_f["id"], db_path=db)
    case_store.update_finding_status(effective_f["id"], "CONFIRMED", db_path=db)
    _experiment_for("sqlmap", "https://a", db, finding_id=effective_f["id"])

    ineffective_f = case_store.create_finding("XSS", "/api/b", db_path=db)
    case_store.update_finding_status(ineffective_f["id"], "FALSE_POSITIVE", db_path=db)
    _experiment_for("dalfox", "https://b", db, finding_id=ineffective_f["id"])

    report = negative_knowledge.compute_negative_knowledge(db_path=db)

    assert report["hints"] == ["dalfox::XSS"]  # sqlmap::SQLi is NOT a hint -- it worked


def test_compute_negative_knowledge_counts_reported_as_effective_not_in_flight(tmp_path):
    """Code-review finding (2026-09-25): REPORTED is the TERMINAL, fully-
    resolved success state of the lifecycle (DISCOVERED -> SUSPECTED ->
    VALIDATING -> CONFIRMED -> IMPACT_PROVEN -> REPORTED, per
    case-mcp/server.py's own docstring), not an in-flight status -- a
    finding that reached REPORTED necessarily passed through CONFIRMED/
    IMPACT_PROVEN first. Treating it as excluded/in-flight would silently
    drop the one effective data point for a (tool, vuln_class) pair once
    its finding progresses past IMPACT_PROVEN, potentially flipping a
    hint for a technique that actually worked."""
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    case_store.update_finding_status(f["id"], "IMPACT_PROVEN", db_path=db)
    case_store.update_finding_status(f["id"], "REPORTED", db_path=db)
    _experiment_for("sqlmap", "https://x", db, finding_id=f["id"])

    report = negative_knowledge.compute_negative_knowledge(db_path=db)

    assert report["tally"]["sqlmap::SQLi"]["effective_count"] == 1
    assert report["hints"] == []


def test_compute_negative_knowledge_treats_duplicate_as_excluded_not_ineffective(tmp_path):
    """DUPLICATE can happen at ANY point in the lifecycle (case-mcp/
    server.py: "off to FALSE_POSITIVE/DUPLICATE/INCONCLUSIVE at any
    point"), including before real validation -- unlike FALSE_POSITIVE it
    doesn't prove the technique found nothing real, so it's excluded from
    the tally rather than counted as a negative data point."""
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.update_finding_status(f["id"], "DUPLICATE", db_path=db)
    _experiment_for("sqlmap", "https://x", db, finding_id=f["id"])

    report = negative_knowledge.compute_negative_knowledge(db_path=db)

    assert report["tally"] == {}


def test_compute_negative_knowledge_empty_case_store(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)
    report = negative_knowledge.compute_negative_knowledge(db_path=db)
    assert report["tally"] == {}
    assert report["hints"] == []


def test_compute_negative_knowledge_never_creates_a_case_db_when_none_exists(tmp_path):
    db = _db(tmp_path)
    assert not os.path.exists(db)
    report = negative_knowledge.compute_negative_knowledge(db_path=db)
    assert "error" in report
    assert not os.path.exists(db)


# ---- never a hard block -------------------------------------------------------

def test_negative_knowledge_module_never_blocks_or_skips_anything():
    """Absolute invariant (MASTER-ROADMAP-FINAL-v3.md §11-A): "allocation/
    dedupe/negative-knowledge never hard-block a not-yet-confirmed novel
    test." This module must have no mechanism capable of preventing a tool
    call -- hints only, never gates. Structural proof, same technique as
    postmortem.py's/coverage_signal.py's own no-write/no-tool-call checks."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "mcp-servers", "negative_knowledge.py")
    with open(path) as f:
        src = f.read()
    if src.lstrip().startswith('"""'):
        first = src.index('"""')
        second = src.index('"""', first + 3)
        src = src[second + 3:]
    # Also strip inline "# ..." comments -- this module's own explanatory
    # comments legitimately mention case_store function names in prose
    # (e.g. "case-mcp/server.py's create_finding()") without ever calling
    # them; a naive substring scan over comment text would false-positive
    # on that prose. Cheap line-based strip, not a full tokenizer -- same
    # "good enough for this structural check" honesty as elsewhere in this
    # repo (a "#" inside a string literal would be clipped too, but none of
    # this module's real code contains one).
    src = "\n".join(line.split("#", 1)[0] for line in src.splitlines())

    forbidden = [
        "log_hypothesis(", "update_hypothesis(", "add_evidence(", "log_experiment(",
        "create_finding(", "update_finding_status(", "score_finding_confidence(",
        "group_root_cause(", "cem_define(", "cem_record_trial(", "cem_record_verdict(",
        "cem_mark_incomplete(", "tool_resolver", "job_runtime", "subprocess", "Popen",
        "scope_guard", "budget_guard", "raise PermissionError", "sys.exit(",
    ]
    for name in forbidden:
        assert name not in src, f"negative_knowledge.py must not reference {name!r}"


# ---- read-only ---------------------------------------------------------------

def test_compute_negative_knowledge_redacts_vuln_class(tmp_path):
    """Defense-in-depth consistency (security review): vuln_class is
    agent-supplied free text (case-mcp/server.py's create_finding() takes
    it as a plain str, no enum enforcement) -- postmortem.py and
    coverage_signal.py both redact it before returning it in a report;
    this module should too. redact_text() is shape-based for a bare string
    with no surrounding key=value context (see redact.py's own _JWT_RE/
    _CARD_CANDIDATE_RE) -- a JWT-shaped value is what it actually catches
    here, not an arbitrary "looks like a secret" string."""
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    db = _db(tmp_path)
    f = case_store.create_finding(fake_jwt, "/api/x", db_path=db)
    case_store.add_evidence("metadata", "proof", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    _experiment_for("sqlmap", "https://x", db, finding_id=f["id"])

    report = negative_knowledge.compute_negative_knowledge(db_path=db)

    tally_key = next(iter(report["tally"]))
    assert fake_jwt not in tally_key
    assert fake_jwt not in report["tally"][tally_key]["vuln_class"]


def test_compute_negative_knowledge_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)
    _experiment_for("sqlmap", "https://x", db, finding_id=f["id"])
    before = case_store.case_export(db_path=db)
    negative_knowledge.compute_negative_knowledge(db_path=db)
    after = case_store.case_export(db_path=db)
    assert before == after
