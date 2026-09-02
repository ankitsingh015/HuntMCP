import os

import case_store


def _db(tmp_path):
    return str(tmp_path / "case.db")


# ---- Hypotheses -------------------------------------------------------------

def test_log_hypothesis_starts_at_new(tmp_path):
    db = _db(tmp_path)
    h = case_store.log_hypothesis("param reflected unescaped", "reflected XSS", db_path=db)
    assert h["status"] == "NEW"
    assert isinstance(h["id"], int)


def test_update_hypothesis_transitions_status(tmp_path):
    db = _db(tmp_path)
    h = case_store.log_hypothesis("obs", "hyp", db_path=db)
    result = case_store.update_hypothesis(h["id"], "TESTING", db_path=db)
    assert result["status"] == "TESTING"


def test_update_hypothesis_rejects_invalid_status(tmp_path):
    db = _db(tmp_path)
    h = case_store.log_hypothesis("obs", "hyp", db_path=db)
    result = case_store.update_hypothesis(h["id"], "MAYBE", db_path=db)
    assert "error" in result


def test_update_hypothesis_rejects_unknown_id(tmp_path):
    db = _db(tmp_path)
    result = case_store.update_hypothesis(999, "TESTING", db_path=db)
    assert "error" in result


# ---- Evidence: content-addressing -------------------------------------------

def test_add_evidence_creates_content_addressed_file(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    ev = case_store.add_evidence("callback", "DNS callback received", finding_id=f["id"], db_path=db)
    assert "hash" in ev
    ev_path = os.path.join(os.path.dirname(db), "evidence", ev["hash"])
    assert os.path.isfile(ev_path)
    with open(ev_path) as fh:
        assert fh.read() == "DNS callback received"


def test_add_evidence_same_content_twice_dedupes_to_one_file(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    ev1 = case_store.add_evidence("callback", "identical content", finding_id=f["id"], db_path=db)
    ev2 = case_store.add_evidence("callback", "identical content", finding_id=f["id"], db_path=db)
    assert ev1["hash"] == ev2["hash"]
    ev_dir = os.path.join(os.path.dirname(db), "evidence")
    assert len(os.listdir(ev_dir)) == 1


def test_add_evidence_rejects_invalid_type(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.add_evidence("smell", "x", finding_id=f["id"], db_path=db)
    assert "error" in result


def test_add_evidence_requires_a_link(tmp_path):
    db = _db(tmp_path)
    result = case_store.add_evidence("metadata", "orphan evidence", db_path=db)
    assert "error" in result


# ---- Cross-engagement FK mismatch: clear error, not a raw sqlite crash -------
#
# Regression for a live incident: an agent working on target B (whose
# hypothesis/finding ids are real) got a raw, uncaught
# sqlite3.IntegrityError: FOREIGN KEY constraint failed when the active
# engagement pointer still resolved to target A's case.db -- the id was
# real, just real in a DIFFERENT engagement's database. These prove the
# pre-check returns a clean, actionable {"error": ...} dict instead.

def test_add_evidence_rejects_unknown_hypothesis_id(tmp_path):
    db = _db(tmp_path)
    result = case_store.add_evidence("metadata", "x", hypothesis_id=999, db_path=db)
    assert "error" in result
    assert "999" in result["error"]


def test_add_evidence_rejects_unknown_finding_id(tmp_path):
    db = _db(tmp_path)
    result = case_store.add_evidence("metadata", "x", finding_id=999, db_path=db)
    assert "error" in result
    assert "999" in result["error"]


def test_log_experiment_rejects_unknown_hypothesis_id(tmp_path):
    db = _db(tmp_path)
    result = case_store.log_experiment("dig", "dig TXT example.com", "example.com", hypothesis_id=999, db_path=db)
    assert "error" in result
    assert "999" in result["error"]


def test_create_finding_rejects_unknown_hypothesis_id(tmp_path):
    db = _db(tmp_path)
    result = case_store.create_finding("SSRF", "/api/fetch", hypothesis_id=999, db_path=db)
    assert "error" in result
    assert "999" in result["error"]


def test_cross_engagement_hypothesis_id_gives_clean_error_not_a_crash(tmp_path):
    # Exactly the real incident: hypothesis id 3 is real, just in a
    # DIFFERENT engagement's case.db than the one currently active.
    db_a = str(tmp_path / "hellomatik-com-case.db")
    db_b = str(tmp_path / "iisc-ac-in-case.db")
    for i in range(3):
        case_store.log_hypothesis(f"obs {i}", f"hyp {i}", db_path=db_b)
    # db_a has zero hypotheses -- id 3 only exists in db_b.
    result = case_store.log_experiment(
        "dig", "dig TXT iisc.ac.in", "iisc.ac.in", hypothesis_id=3, db_path=db_a,
    )
    assert "error" in result
    assert "3" in result["error"]


def test_group_root_cause_rejects_unknown_finding_id_with_clear_message(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.group_root_cause([f["id"], 999], "shared root cause", db_path=db)
    assert "error" in result
    assert "999" in result["error"]


# ---- Findings: the evidence gate ---------------------------------------------

def test_confirmed_transition_blocked_without_evidence(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user/2", db_path=db)
    result = case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    assert "error" in result


def test_impact_proven_transition_blocked_without_evidence(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user/2", db_path=db)
    result = case_store.update_finding_status(f["id"], "IMPACT_PROVEN", db_path=db)
    assert "error" in result


def test_confirmed_transition_succeeds_with_evidence(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user/2", db_path=db)
    case_store.add_evidence("response", "200 OK, other user's data returned", finding_id=f["id"], db_path=db)
    result = case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    assert result["status"] == "CONFIRMED"


def test_non_gated_transition_does_not_need_evidence(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user/2", db_path=db)
    result = case_store.update_finding_status(f["id"], "SUSPECTED", db_path=db)
    assert result["status"] == "SUSPECTED"


def test_update_finding_status_rejects_invalid_status(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user/2", db_path=db)
    result = case_store.update_finding_status(f["id"], "PROBABLY", db_path=db)
    assert "error" in result


# ---- Confidence scoring -------------------------------------------------------

def test_confidence_scoring_bands():
    assert case_store._band_for_score(0) == "LOW"
    assert case_store._band_for_score(30) == "MEDIUM"
    assert case_store._band_for_score(31) == "MEDIUM"
    assert case_store._band_for_score(60) == "HIGH"
    assert case_store._band_for_score(80) == "CONFIRMED"
    assert case_store._band_for_score(100) == "CONFIRMED"


def test_score_finding_confidence_sums_and_bands(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.score_finding_confidence(
        f["id"], {"endpoint_confirmed": 15, "oob_confirmation": 20, "reproduction": 25}, db_path=db
    )
    assert result["confidence_score"] == 60
    assert result["confidence_band"] == "HIGH"


def test_score_finding_confidence_clamps_to_100(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.score_finding_confidence(f["id"], {"a": 60, "b": 60}, db_path=db)
    assert result["confidence_score"] == 100
    assert result["confidence_band"] == "CONFIRMED"


def test_score_finding_confidence_rejects_non_numeric_signal(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.score_finding_confidence(f["id"], {"reproduction": "yes"}, db_path=db)
    assert "error" in result


# ---- Experiments: dedup ---------------------------------------------------------

def test_check_experiment_exists_false_before_logging(tmp_path):
    db = _db(tmp_path)
    assert case_store.check_experiment_exists("sqlmap-mcp", "id=1' OR '1'='1", "target.com", db_path=db) is False


def test_check_experiment_exists_true_after_logging(tmp_path):
    db = _db(tmp_path)
    case_store.log_experiment("sqlmap-mcp", "id=1' OR '1'='1", "target.com", db_path=db)
    assert case_store.check_experiment_exists("sqlmap-mcp", "id=1' OR '1'='1", "target.com", db_path=db) is True


def test_check_experiment_exists_distinguishes_input(tmp_path):
    db = _db(tmp_path)
    case_store.log_experiment("sqlmap-mcp", "id=1' OR '1'='1", "target.com", db_path=db)
    assert case_store.check_experiment_exists("sqlmap-mcp", "id=2' OR '1'='1", "target.com", db_path=db) is False


# ---- Root cause -------------------------------------------------------------

def test_group_root_cause_requires_at_least_two_findings(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user", db_path=db)
    result = case_store.group_root_cause([f["id"]], "single finding", db_path=db)
    assert "error" in result


def test_group_root_cause_rejects_unknown_finding_id(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user", db_path=db)
    result = case_store.group_root_cause([f["id"], 9999], "desc", db_path=db)
    assert "error" in result


def test_group_root_cause_links_all_findings(tmp_path):
    db = _db(tmp_path)
    f1 = case_store.create_finding("IDOR", "/api/user", db_path=db)
    f2 = case_store.create_finding("IDOR", "/api/orders", db_path=db)
    result = case_store.group_root_cause([f1["id"], f2["id"]], "broken authz middleware", db_path=db)
    assert result["grouped_findings"] == [f1["id"], f2["id"]]


def test_suggest_root_cause_flags_shared_signature(tmp_path):
    db = _db(tmp_path)
    case_store.create_finding("IDOR", "/api/user?id=1", db_path=db)
    case_store.create_finding("IDOR", "/api/user?id=2", db_path=db)
    result = case_store.suggest_root_cause(db_path=db)
    assert "idor|/api/user" in result


def test_suggest_root_cause_ignores_already_grouped(tmp_path):
    db = _db(tmp_path)
    f1 = case_store.create_finding("IDOR", "/api/user", db_path=db)
    f2 = case_store.create_finding("IDOR", "/api/user", db_path=db)
    case_store.group_root_cause([f1["id"], f2["id"]], "desc", db_path=db)
    result = case_store.suggest_root_cause(db_path=db)
    assert "No ungrouped findings" in result


# ---- Next best action -------------------------------------------------------

def test_suggest_next_action_prioritizes_testing_hypothesis(tmp_path):
    db = _db(tmp_path)
    h = case_store.log_hypothesis("obs", "a fresh idea", db_path=db)
    case_store.update_hypothesis(h["id"], "TESTING", db_path=db)
    case_store.create_finding("XSS", "/search", db_path=db)  # a fresh, lower-priority finding
    result = case_store.suggest_next_action(db_path=db)
    assert f"hypothesis #{h['id']}" in result


def test_suggest_next_action_falls_back_to_fresh_finding(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("XSS", "/search", db_path=db)
    result = case_store.suggest_next_action(db_path=db)
    assert f"finding #{f['id']}" in result


def test_suggest_next_action_empty_case(tmp_path):
    db = _db(tmp_path)
    result = case_store.suggest_next_action(db_path=db)
    assert "nothing queued" in result.lower()


# ---- Summary / export --------------------------------------------------------

def test_case_summary_counts(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)
    f = case_store.create_finding("XSS", "/search", db_path=db)
    case_store.add_evidence("response", "reflected payload", finding_id=f["id"], db_path=db)
    summary = case_store.case_summary(db_path=db)
    assert "NEW=1" in summary
    assert "DISCOVERED=1" in summary
    assert "Evidence rows: 1" in summary


def test_case_export_round_trips_all_tables(tmp_path):
    import json

    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)
    f = case_store.create_finding("XSS", "/search", db_path=db)
    case_store.add_evidence("response", "payload", finding_id=f["id"], db_path=db)
    case_store.log_experiment("dalfox-mcp", "<script>", "target.com", finding_id=f["id"], db_path=db)

    exported = json.loads(case_store.case_export(db_path=db))
    assert len(exported["hypotheses"]) == 1
    assert len(exported["findings"]) == 1
    assert len(exported["evidence"]) == 1
    assert len(exported["experiments"]) == 1
