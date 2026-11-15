import json
import os
import sqlite3

import case_store
import postmortem


def _db(tmp_path):
    return str(tmp_path / "case.db")


# ---- basic counting / evidence-citation --------------------------------------

def test_run_postmortem_counts_hypotheses_and_findings_by_status(tmp_path):
    db = _db(tmp_path)
    h1 = case_store.log_hypothesis("obs1", "hyp1", db_path=db)
    case_store.update_hypothesis(h1["id"], "CONFIRMED", db_path=db)
    case_store.log_hypothesis("obs2", "hyp2", db_path=db)  # stays NEW
    case_store.create_finding("SQLi", "/api/x", db_path=db)  # stays DISCOVERED

    report = postmortem.run_postmortem(db_path=db)
    assert report["hypothesis_counts"] == {"CONFIRMED": 1, "NEW": 1}
    assert report["finding_counts"] == {"DISCOVERED": 1}


def test_run_postmortem_includes_telemetry(tmp_path):
    db = _db(tmp_path)
    audit = str(tmp_path / "audit.jsonl")
    case_store.log_hypothesis("obs", "hyp", db_path=db)  # a real case.db must exist to analyze
    report = postmortem.run_postmortem(db_path=db, audit_log_path=audit)
    assert report["telemetry"] == {"tool_calls": 0, "wall_clock_ms": 0.0, "by_tool": {}}


def test_run_postmortem_evidence_ids_trace_back_to_real_rows(tmp_path):
    db = _db(tmp_path)
    h = case_store.log_hypothesis("obs", "hyp", db_path=db)  # stays NEW -- stalled
    report = postmortem.run_postmortem(db_path=db)
    assert report["stalled_hypotheses"] == [
        {"id": h["id"], "status": "NEW", "observation": "obs", "hypothesis": "hyp"}
    ]


# ---- planted-fixture precision/recall -----------------------------------------

def test_run_postmortem_planted_fixture_recall_and_precision(tmp_path):
    """Plants a known-ground-truth mini engagement covering EVERY status in
    case_store.HYPOTHESIS_STATUSES/FINDING_STATUSES (not just a couple),
    split into a planted-stalled/unresolved set and a planted-NOT set.
    Asserts run_postmortem() recovers EXACTLY the planted set -- 100% recall
    (nothing planted-stalled is missed) and 100% precision (nothing else is
    wrongly flagged) -- against the FULL status vocabulary, not a subset."""
    db = _db(tmp_path)

    assert case_store.HYPOTHESIS_STATUSES == {
        "NEW", "TESTING", "SUPPORTED", "REFUTED", "INCONCLUSIVE", "CONFIRMED",
    }, "test's planted set must cover every status -- update this test if case_store's vocabulary changes"
    assert case_store.FINDING_STATUSES == {
        "DISCOVERED", "SUSPECTED", "VALIDATING", "CONFIRMED", "IMPACT_PROVEN",
        "REPORTED", "FALSE_POSITIVE", "DUPLICATE", "INCONCLUSIVE",
    }, "test's planted set must cover every status -- update this test if case_store's vocabulary changes"

    planted_stalled_ids = set()
    for status in ("NEW", "TESTING", "SUPPORTED"):
        h = case_store.log_hypothesis(f"obs-{status}", f"hyp-{status}", db_path=db)
        if status != "NEW":
            case_store.update_hypothesis(h["id"], status, db_path=db)
        planted_stalled_ids.add(h["id"])
    for status in ("REFUTED", "INCONCLUSIVE", "CONFIRMED"):
        h = case_store.log_hypothesis(f"obs-{status}", f"hyp-{status}", db_path=db)
        case_store.update_hypothesis(h["id"], status, db_path=db)

    planted_unresolved_ids = set()
    for status in ("DISCOVERED", "SUSPECTED", "VALIDATING", "INCONCLUSIVE"):
        f = case_store.create_finding("SQLi", f"/api/{status}", db_path=db)
        if status != "DISCOVERED":
            case_store.update_finding_status(f["id"], status, db_path=db)
        planted_unresolved_ids.add(f["id"])
    for status in ("CONFIRMED", "IMPACT_PROVEN", "REPORTED", "FALSE_POSITIVE", "DUPLICATE"):
        f = case_store.create_finding("SQLi", f"/api/{status}", db_path=db)
        if status in ("CONFIRMED", "IMPACT_PROVEN", "REPORTED"):
            case_store.add_evidence("response", "proof", finding_id=f["id"], db_path=db)
            case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
            if status != "CONFIRMED":
                case_store.update_finding_status(f["id"], status, db_path=db)
        else:
            case_store.update_finding_status(f["id"], status, db_path=db)

    report = postmortem.run_postmortem(db_path=db)

    reported_stalled_ids = {h["id"] for h in report["stalled_hypotheses"]}
    assert reported_stalled_ids == planted_stalled_ids  # recall == precision == 1.0

    reported_unresolved_ids = {f["id"] for f in report["unresolved_findings"]}
    assert reported_unresolved_ids == planted_unresolved_ids  # recall == precision == 1.0


# ---- redaction ------------------------------------------------------------------

def test_run_postmortem_redacts_secrets_in_hypothesis_free_text(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis(
        "leaked token=sk_live_abc123 in response", "auth bypass", db_path=db,
    )
    report = postmortem.run_postmortem(db_path=db)
    observation = report["stalled_hypotheses"][0]["observation"]
    assert "sk_live_abc123" not in observation
    assert "[REDACTED:" in observation


def test_run_postmortem_redacts_secrets_in_finding_fields(tmp_path):
    db = _db(tmp_path)
    case_store.create_finding("SSRF", "/api/fetch?api_key=sk_live_zzz999", db_path=db)
    report = postmortem.run_postmortem(db_path=db)
    endpoint = report["unresolved_findings"][0]["endpoint"]
    assert "sk_live_zzz999" not in endpoint
    assert "[REDACTED:" in endpoint


# ---- read-only proof --------------------------------------------------------------

def test_run_postmortem_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    h = case_store.log_hypothesis("obs", "hyp", db_path=db)
    case_store.create_finding("SQLi", "/api/x", db_path=db)
    before = case_store.case_export(db_path=db)

    postmortem.run_postmortem(db_path=db)

    after = case_store.case_export(db_path=db)
    assert before == after
    # sanity: the hypothesis really is still there, untouched, not just an
    # empty-vs-empty vacuous comparison
    assert f'"id": {h["id"]}' in after


def test_run_postmortem_never_creates_a_case_db_when_none_exists(tmp_path):
    """Round-2 security review, CONFIRMED live by direct reproduction:
    case_store._get_conn() unconditionally os.makedirs()/CREATE TABLE IF
    NOT EXISTS regardless of read-vs-write intent, so calling case_export()
    against a path with no case.db yet would silently materialize a fresh,
    empty one from nothing -- directly contradicting this module's own
    "issues no writes" claim for exactly the standalone/stale-path call
    this module exists to support (run after/between engagements)."""
    db = _db(tmp_path)
    assert not os.path.exists(db)

    report = postmortem.run_postmortem(db_path=db)

    assert "error" in report
    assert not os.path.exists(db), "run_postmortem() must not create a case.db that didn't exist"


def test_run_postmortem_passes_its_own_resolved_path_to_case_export_when_db_path_is_none(monkeypatch, tmp_path):
    """Correctness finding (independent code review, 2026-09-25): with
    db_path=None, run_postmortem() resolved the active-engagement path once
    via case_store.resolve_db_path() to do its isfile() pre-check, then
    called case_store.case_export(db_path=db_path) with the ORIGINAL
    (still-None) db_path -- letting case_export()'s own internal
    _get_conn() re-resolve the active engagement independently a second
    time. If the active-engagement pointer were switched by another
    process in between (this codebase treats that as a real scenario
    elsewhere, e.g. engagement_paths' own conflict/mismatch handling),
    the isfile() check would validate engagement A's case.db while
    case_export() opened -- and, on a stale/absent path, silently
    auto-created -- engagement B's, directly contradicting this module's
    own "issues no writes" guarantee. Fixed: pass the ALREADY-resolved
    path through, so both calls agree by construction rather than by
    hoping nothing switches active engagement in between. Proven here by
    forcing resolve_db_path() to report a fixed "active engagement" path
    and asserting case_export() actually receives that resolved value
    (not None) -- None would mean it's still re-resolving independently."""
    real_db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=real_db)  # a real case.db to analyze

    monkeypatch.setattr(case_store, "resolve_db_path", lambda db_path=None: real_db)

    captured = {}
    real_case_export = case_store.case_export

    def _capturing_case_export(db_path=None):
        captured["db_path"] = db_path
        return real_case_export(db_path=db_path)

    monkeypatch.setattr(case_store, "case_export", _capturing_case_export)

    postmortem.run_postmortem(db_path=None)

    assert captured["db_path"] == real_db, (
        "run_postmortem(db_path=None) must pass its own already-resolved path "
        "to case_export(), not None -- None means case_export() re-resolves "
        "the active engagement independently, reopening the TOCTOU window"
    )


def test_postmortem_module_has_no_write_or_tool_calls():
    """Structural proof (not just a docstring claim) that postmortem.py
    never calls a case_store WRITE function, never calls
    dedupe_check.check_and_record(), and never touches a tool-dispatch
    module -- P2-E1's own acceptance bar: 'no tools, no auto-retry, no
    self-modification, no policy mutation'."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "mcp-servers", "postmortem.py")) as f:
        full_src = f.read()
    # Scan CODE only, not the module docstring's own prose describing what
    # it doesn't do (which necessarily names these same forbidden strings).
    _, _, src = full_src.partition('"""')
    _, _, src = src.partition('"""')

    forbidden_write_calls = [
        "log_hypothesis(", "update_hypothesis(", "add_evidence(", "log_experiment(",
        "create_finding(", "update_finding_status(", "score_finding_confidence(",
        "group_root_cause(", "cem_define(", "cem_record_trial(", "cem_record_verdict(",
        "cem_mark_incomplete(", "check_and_record(",
    ]
    for call in forbidden_write_calls:
        assert call not in src, f"postmortem.py must not call case_store write function {call!r}"

    forbidden_modules = ["tool_resolver", "job_runtime", "subprocess", "Popen", "scope_guard", "budget_guard"]
    for module in forbidden_modules:
        assert module not in src, f"postmortem.py must not reference {module!r} (tool/policy surface)"


# ---- independent cross-check vs raw store --------------------------------------

def test_run_postmortem_finding_counts_match_raw_sqlite_query(tmp_path):
    db = _db(tmp_path)
    case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.create_finding("XSS", "/api/y", db_path=db)
    f3 = case_store.create_finding("IDOR", "/api/z", db_path=db)
    case_store.add_evidence("response", "proof", finding_id=f3["id"], db_path=db)
    case_store.update_finding_status(f3["id"], "CONFIRMED", db_path=db)

    report = postmortem.run_postmortem(db_path=db)

    conn = sqlite3.connect(db)
    try:
        raw_total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        raw_confirmed = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE status = 'CONFIRMED'"
        ).fetchone()[0]
    finally:
        conn.close()

    assert sum(report["finding_counts"].values()) == raw_total
    assert report["finding_counts"]["CONFIRMED"] == raw_confirmed


# ---- P4-PM+: missed_chain_opportunities ---------------------------------------
# Extends P2-E1 (same module, same read-only/offline/evidence-cited contract).
# "Missed" = a chainer-mcp chain template whose required finding classes are
# ALL covered by CONFIRMED/IMPACT_PROVEN/REPORTED findings, yet no hypothesis
# or experiment text in the case store ever mentions that chain (by template
# key or display name) -- i.e. the chain existed on paper and was never tried.

import importlib.util

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "chainer_mcp_server_for_postmortem_test",
    os.path.join(_ROOT, "mcp-servers", "chainer-mcp", "server.py"),
)
chainer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chainer)


def _confirmed(db, vuln_class, endpoint="/x", status="CONFIRMED"):
    f = case_store.create_finding(vuln_class, endpoint, db_path=db)
    case_store.add_evidence("response", f"proof-{vuln_class}-{endpoint}", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    if status != "CONFIRMED":
        case_store.update_finding_status(f["id"], status, db_path=db)
    return f["id"]


def _keys(report):
    return {o["chain_key"] for o in report}


def test_missed_chain_reported_with_finding_ids_when_never_attempted(tmp_path):
    db = _db(tmp_path)
    idor = _confirmed(db, "IDOR", "/api/user/1")
    xss = _confirmed(db, "XSS", "/search")

    out = postmortem.missed_chain_opportunities(db_path=db)

    by_key = {o["chain_key"]: o for o in out}
    assert "idor_xss_ato" in by_key
    opp = by_key["idor_xss_ato"]
    assert opp["chain_name"] == chainer.CHAIN_TEMPLATES["idor_xss_ato"]["name"]
    assert opp["severity"] == chainer.CHAIN_TEMPLATES["idor_xss_ato"]["severity_multiplier"]
    assert opp["required_classes"] == ["IDOR", "XSS"]
    assert opp["finding_ids"] == {"IDOR": [idor], "XSS": [xss]}


def test_missed_chain_needs_every_required_class(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "IDOR")
    assert "idor_xss_ato" not in _keys(postmortem.missed_chain_opportunities(db_path=db))


def test_missed_chain_ignores_template_with_empty_required_findings(tmp_path, monkeypatch):
    """A template with no required findings must NOT be vacuously flagged as
    missed (all(... for r in []) is True). Guard it; the real one still fires."""
    db = _db(tmp_path)
    _confirmed(db, "SSRF", "/fetch")
    monkeypatch.setattr(postmortem, "_load_chain_templates", lambda: {
        "empty_reqs": {"name": "Empty Requirements Chain",
                       "severity_multiplier": 3.0, "required_findings": []},
        "ssrf_internal_portscan": {"name": "SSRF Internal Port Scan",
                                   "severity_multiplier": 2.0, "required_findings": ["SSRF"]},
    })
    keys = _keys(postmortem.missed_chain_opportunities(db_path=db))
    assert "empty_reqs" not in keys            # guarded: not vacuously flagged
    assert "ssrf_internal_portscan" in keys    # a real single-class chain still reported


def test_missed_chain_ignores_findings_that_are_not_confirmed(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "IDOR")
    case_store.create_finding("XSS", "/s", db_path=db)  # DISCOVERED only
    fp = case_store.create_finding("XSS", "/t", db_path=db)
    case_store.update_finding_status(fp["id"], "FALSE_POSITIVE", db_path=db)
    assert "idor_xss_ato" not in _keys(postmortem.missed_chain_opportunities(db_path=db))


def test_missed_chain_counts_impact_proven_and_reported_findings(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "IDOR", status="IMPACT_PROVEN")
    _confirmed(db, "XSS", status="REPORTED")
    assert "idor_xss_ato" in _keys(postmortem.missed_chain_opportunities(db_path=db))


def test_missed_chain_class_match_is_case_insensitive_and_multiword(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "sql injection")
    _confirmed(db, "xss")
    assert "sqli_xss_stored" in _keys(postmortem.missed_chain_opportunities(db_path=db))


def test_missed_chain_lists_all_findings_of_a_class_sorted(tmp_path):
    db = _db(tmp_path)
    a = _confirmed(db, "XSS", "/a")
    b = _confirmed(db, "XSS", "/b")
    i = _confirmed(db, "IDOR")
    opp = {o["chain_key"]: o for o in postmortem.missed_chain_opportunities(db_path=db)}["idor_xss_ato"]
    assert opp["finding_ids"] == {"IDOR": [i], "XSS": [a, b]}


def test_attempted_chain_mentioned_in_hypothesis_by_key_is_not_reported(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "IDOR")
    _confirmed(db, "XSS")
    case_store.log_hypothesis("saw both", "try idor_xss_ato to steal a victim session", db_path=db)
    assert "idor_xss_ato" not in _keys(postmortem.missed_chain_opportunities(db_path=db))


def test_attempted_chain_mentioned_in_hypothesis_note_is_not_reported(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "IDOR")
    _confirmed(db, "XSS")
    h = case_store.log_hypothesis("o", "h", db_path=db)
    case_store.update_hypothesis(h["id"], "REFUTED", note="idor_xss_ato blocked by HttpOnly", db_path=db)
    assert "idor_xss_ato" not in _keys(postmortem.missed_chain_opportunities(db_path=db))


def test_attempted_chain_mentioned_in_experiment_by_display_name_is_not_reported(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "IDOR")
    _confirmed(db, "XSS")
    name = chainer.CHAIN_TEMPLATES["idor_xss_ato"]["name"].lower()
    case_store.log_experiment("manual", f"replayed {name} against staging", "t", db_path=db)
    assert "idor_xss_ato" not in _keys(postmortem.missed_chain_opportunities(db_path=db))


def test_attempting_one_chain_does_not_suppress_another(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "SSRF")
    case_store.log_hypothesis("o", "try ssrf_cloud_creds via metadata", db_path=db)
    keys = _keys(postmortem.missed_chain_opportunities(db_path=db))
    assert "ssrf_cloud_creds" not in keys
    assert "ssrf_internal_portscan" in keys


def test_missed_chain_planted_fixture_recall_and_precision(tmp_path):
    """Hand-derived ground truth (NOT computed from the code under test):
    with confirmed {SSRF, XSS, IDOR}, the only templates whose required
    classes are all present are ssrf_cloud_creds, ssrf_internal_portscan and
    idor_xss_ato. Two are 'attempted' via text; exactly the remaining one
    must be reported, and none of the others (cors/proto-pollution/sqli_xss
    all need a class that is absent)."""
    db = _db(tmp_path)
    for c in ("SSRF", "XSS", "IDOR"):
        _confirmed(db, c)
    case_store.log_hypothesis("o", "ssrf_cloud_creds worth a try", db_path=db)
    case_store.log_experiment("manual", "ssrf_internal_portscan sweep", "t", db_path=db)
    assert _keys(postmortem.missed_chain_opportunities(db_path=db)) == {"idor_xss_ato"}


def test_missed_chain_agrees_with_chainer_analyze_chains_on_matching_rule(tmp_path):
    """Independent cross-check: with nothing attempted, the reported keys
    must equal the set chainer-mcp's own analyze_chains() says is possible."""
    db = _db(tmp_path)
    classes = ["SSRF", "XSS", "IDOR", "SQL Injection", "LFI"]
    for c in classes:
        _confirmed(db, c)
    reported = _keys(postmortem.missed_chain_opportunities(db_path=db))
    out = chainer.analyze_chains(json.dumps([{"vulnerability_class": c} for c in classes]))
    expected = {k for k in chainer.CHAIN_TEMPLATES if f"Key: {k}" in out}
    assert expected  # non-vacuous
    assert reported == expected


def test_missed_chain_output_carries_no_free_text_from_the_store(tmp_path):
    db = _db(tmp_path)
    secret = "AKIAIOSFODNN7EXAMPLE"  # gitleaks:allow
    _confirmed(db, "IDOR", f"/api/{secret}")
    _confirmed(db, "XSS", f"/s?k={secret}")
    out = postmortem.missed_chain_opportunities(db_path=db)
    assert out
    assert secret not in json.dumps(out)


def test_missed_chain_no_case_db_returns_error_and_creates_nothing(tmp_path):
    db = _db(tmp_path)
    out = postmortem.missed_chain_opportunities(db_path=db)
    assert isinstance(out, dict) and "error" in out
    assert not os.path.exists(db)


def test_missed_chain_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "IDOR")
    _confirmed(db, "XSS")
    before = case_store.case_export(db_path=db)
    postmortem.missed_chain_opportunities(db_path=db)
    assert case_store.case_export(db_path=db) == before


def test_run_postmortem_includes_missed_chain_opportunities(tmp_path):
    db = _db(tmp_path)
    _confirmed(db, "IDOR")
    _confirmed(db, "XSS")
    report = postmortem.run_postmortem(db_path=db)
    assert "idor_xss_ato" in _keys(report["missed_chain_opportunities"])


def test_run_postmortem_survives_chain_template_load_failure(tmp_path, monkeypatch):
    """The postmortem's always-produces-a-report property must hold even if
    chainer-mcp's templates cannot be loaded: the rest of the report is
    intact and only the chain section degrades to an error marker."""
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)

    def boom():
        raise RuntimeError("chainer unavailable")

    monkeypatch.setattr(postmortem, "_load_chain_templates", boom)
    report = postmortem.run_postmortem(db_path=db)
    assert report["hypothesis_counts"] == {"NEW": 1}
    assert "error" in report["missed_chain_opportunities"]
