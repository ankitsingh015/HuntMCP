import json
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


def test_resolve_db_path_returns_explicit_path_unchanged(tmp_path):
    db = _db(tmp_path)
    assert case_store.resolve_db_path(db) == db


def test_resolve_db_path_never_creates_the_file(tmp_path):
    db = _db(tmp_path)
    assert not os.path.exists(db)
    case_store.resolve_db_path(db)
    assert not os.path.exists(db)


def test_list_experiments_returns_only_that_findings_rows(tmp_path):
    db = _db(tmp_path)
    f1 = case_store.create_finding("SQLi", "/api/x", db_path=db)
    f2 = case_store.create_finding("XSS", "/api/y", db_path=db)
    case_store.log_experiment("sqlmap", "id=1", "https://x", cost=3, finding_id=f1["id"], db_path=db)
    case_store.log_experiment("dalfox", "q=<script>", "https://y", cost=1, finding_id=f2["id"], db_path=db)
    rows = case_store.list_experiments(f1["id"], db_path=db)
    assert len(rows) == 1
    assert rows[0]["tool"] == "sqlmap"
    assert rows[0]["cost"] == 3


def test_list_experiments_empty_for_finding_with_none(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/z", db_path=db)
    assert case_store.list_experiments(f["id"], db_path=db) == []


def test_count_cem_trials_none_when_cem_never_defined(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    assert case_store.count_cem_trials(f["id"], db_path=db) is None


def test_count_cem_trials_zero_when_defined_but_no_trials_yet(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    case_store.cem_define(
        f["id"], {"method": "GET", "url": "https://x"}, {"status": 200},
        [{"name": "c1", "category": "header", "perturbation": {"x": "y"}}],
        db_path=db,
    )
    assert case_store.count_cem_trials(f["id"], db_path=db) == 0


def test_count_cem_trials_counts_real_trial_rows(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    case_store.cem_define(
        f["id"], {"method": "GET", "url": "https://x"}, {"status": 200},
        [{"name": "c1", "category": "header", "perturbation": {"x": "y"}}],
        db_path=db,
    )
    case_store.cem_record_trial(f["id"], "baseline", 0, True, db_path=db)
    case_store.cem_record_trial(f["id"], "perturbed", 0, True, db_path=db)
    assert case_store.count_cem_trials(f["id"], db_path=db) == 2


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


# ---- C1a: evidence provenance binding ---------------------------------------

def test_add_evidence_with_no_provenance_stores_none(tmp_path):
    """Backward-compatible default -- pre-C1a callers (and every one of
    this file's own tests above) never pass provenance, and the row must
    honestly record "no provenance," not a fabricated default."""
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    ev = case_store.add_evidence("callback", "raw hit", finding_id=f["id"], db_path=db)
    row = case_store.get_evidence(ev["id"], db_path=db)
    assert row["provenance"] is None


def test_add_evidence_stores_wire_level_provenance(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    prov = {"class": "wire", "captured_by": "oob-mcp", "method": "DNS",
            "url": "abc123.oast.fun", "remote_address": "203.0.113.5"}
    ev = case_store.add_evidence("callback", "raw hit", finding_id=f["id"],
                                  provenance=prov, db_path=db)
    row = case_store.get_evidence(ev["id"], db_path=db)
    assert row["provenance"]["class"] == "wire"
    assert row["provenance"]["method"] == "DNS"
    assert row["provenance"]["remote_address"] == "203.0.113.5"


def test_add_evidence_stores_invocation_level_provenance(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("XSS", "/api/x", db_path=db)
    prov = {"class": "invocation", "captured_by": "tool_resolver", "tool": "dalfox"}
    ev = case_store.add_evidence("response", "reflected payload", finding_id=f["id"],
                                  provenance=prov, db_path=db)
    row = case_store.get_evidence(ev["id"], db_path=db)
    assert row["provenance"]["class"] == "invocation"
    assert row["provenance"]["tool"] == "dalfox"


def test_add_evidence_rejects_provenance_with_unknown_class(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.add_evidence("callback", "x", finding_id=f["id"],
                                      provenance={"class": "vibes"}, db_path=db)
    assert "error" in result


def test_add_evidence_rejects_wire_provenance_missing_method_or_url(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.add_evidence("callback", "x", finding_id=f["id"],
                                      provenance={"class": "wire", "url": "https://x"}, db_path=db)
    assert "error" in result


def test_add_evidence_rejects_invocation_provenance_missing_tool(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.add_evidence("callback", "x", finding_id=f["id"],
                                      provenance={"class": "invocation"}, db_path=db)
    assert "error" in result


def test_add_evidence_rejects_provenance_that_is_not_a_dict(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    result = case_store.add_evidence("callback", "x", finding_id=f["id"],
                                      provenance="not a dict", db_path=db)
    assert "error" in result


def test_add_evidence_redacts_secret_shaped_provenance_values(tmp_path):
    """Defense-in-depth, same as evidence content's own SHA-256-addressed
    storage isn't a redaction mechanism -- provenance is bookkeeping
    metadata (method/url/tool), not the evidence substance itself, so it's
    safe and correct to redact it the way audit_log.log_call() already
    redacts its own args."""
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    ev = case_store.add_evidence("request", "x", finding_id=f["id"],
                                  provenance={"class": "wire", "method": "GET", "url": jwt},
                                  db_path=db)
    row = case_store.get_evidence(ev["id"], db_path=db)
    assert jwt not in row["provenance"]["url"]


def test_add_evidence_redacts_secret_shaped_values_nested_under_a_header_dict(tmp_path):
    """Code-review finding (2 independent agents converged on this):
    _redact_provenance()'s original one-level-deep implementation
    (`{k: redact_text(v) if isinstance(v, str) else v ...}`) never
    recursed into a nested dict, so a real secret sitting under
    provenance["headers"]["Authorization"] (the realistic shape a wire-
    level capture would actually produce) passed through completely
    unredacted -- even though this exact codebase already fixed the
    identical bug class for CEM's own evidence bundling
    (cem_engine._redact_recursive(), whose own docstring documents two
    prior retrospective-audit fixes for precisely this). Must reuse that
    hardened recursive redactor, not a second, weaker one-level copy."""
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    ev = case_store.add_evidence(
        "request", "x", finding_id=f["id"],
        provenance={"class": "wire", "method": "GET", "url": "https://x",
                    "headers": {"Authorization": "Bearer opaque-real-secret-token-value"}},
        db_path=db,
    )
    row = case_store.get_evidence(ev["id"], db_path=db)
    assert "opaque-real-secret-token-value" not in json.dumps(row["provenance"])


def test_add_evidence_old_rows_from_before_this_column_existed_still_readable(tmp_path):
    """Real migration correctness, not just a fresh-db assumption: a
    case.db created before C1a (no provenance_json column) must not break
    when _init_schema() adds the column via ALTER TABLE, and pre-existing
    rows must read back with provenance=None, not crash."""
    db = _db(tmp_path)
    # Simulate a pre-C1a db: create the OLD schema by hand, no provenance_json.
    conn = case_store.sqlite3.connect(db)
    conn.execute("""
        CREATE TABLE evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hypothesis_id INTEGER, finding_id INTEGER, type TEXT NOT NULL,
            content_hash TEXT NOT NULL, content_ref TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute(
        "INSERT INTO evidence (finding_id, type, content_hash, content_ref) VALUES (1, 'metadata', 'h', 'r')"
    )
    conn.commit()
    conn.close()

    row = case_store.get_evidence(1, db_path=db)
    assert row["provenance"] is None


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


def test_get_finding_returns_the_row_or_none(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/orders/{id}", db_path=db)
    row = case_store.get_finding(f["id"], db_path=db)
    assert row is not None
    assert row["id"] == f["id"]
    assert row["vuln_class"] == "IDOR"
    assert row["status"] == "DISCOVERED"
    assert case_store.get_finding(999, db_path=db) is None


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


def test_impact_proven_transition_blocked_without_prior_confirmed(tmp_path):
    """Regression test (engagement-retrospective finding): CONFIRMED and
    IMPACT_PROVEN were both evidence-gated independently, so a finding
    could jump straight from DISCOVERED to IMPACT_PROVEN with one generic
    evidence row, skipping CONFIRMED entirely -- conflating "reproduction"
    (CONFIRMED) with "exploitability/impact demonstrated" (IMPACT_PROVEN),
    the exact distinction this two-state split exists to preserve (see
    case_store.py's own module docstring on cem_meta/cem_conditions).
    IMPACT_PROVEN must only be reachable from a finding already CONFIRMED."""
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user/2", db_path=db)
    case_store.add_evidence("response", "200 OK, other user's data returned", finding_id=f["id"], db_path=db)
    result = case_store.update_finding_status(f["id"], "IMPACT_PROVEN", db_path=db)
    assert "error" in result
    assert "CONFIRMED" in result["error"]


def test_impact_proven_transition_succeeds_after_confirmed(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/user/2", db_path=db)
    case_store.add_evidence("response", "200 OK, other user's data returned", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    result = case_store.update_finding_status(f["id"], "IMPACT_PROVEN", db_path=db)
    assert result["status"] == "IMPACT_PROVEN"


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


def test_find_similar_experiments_recognizes_same_test_with_different_oob_host(tmp_path):
    """Regression test reported live in an engagement retrospective: a
    second SSRF confirmation used a different OOB callback host than the
    first, so check_experiment_exists() (still exact-string, unchanged --
    see test above) correctly says False, but find_similar_experiments()
    should recognize it as the same underlying test."""
    db = _db(tmp_path)
    case_store.log_experiment(
        "curl", "https://target.com/fetch?url=http://abc123def456ghi789.oast.fun/", "target.com", db_path=db,
    )
    assert case_store.check_experiment_exists(
        "curl", "https://target.com/fetch?url=http://xyz987wvu654tsr321.oast.fun/", "target.com", db_path=db,
    ) is False
    similar = case_store.find_similar_experiments(
        "curl", "https://target.com/fetch?url=http://xyz987wvu654tsr321.oast.fun/", "target.com", db_path=db,
    )
    assert len(similar) == 1


def test_find_similar_experiments_does_not_collapse_distinct_payload_values(tmp_path):
    """The normalization must stay narrow -- two genuinely different SQLi
    payload values are NOT "similar", same distinction
    test_check_experiment_exists_distinguishes_input already protects."""
    db = _db(tmp_path)
    case_store.log_experiment("sqlmap-mcp", "id=1' OR '1'='1", "target.com", db_path=db)
    similar = case_store.find_similar_experiments("sqlmap-mcp", "id=2' OR '1'='1", "target.com", db_path=db)
    assert similar == []


def test_find_similar_experiments_empty_when_none_logged(tmp_path):
    db = _db(tmp_path)
    assert case_store.find_similar_experiments("curl", "https://target.com/x", "target.com", db_path=db) == []


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
