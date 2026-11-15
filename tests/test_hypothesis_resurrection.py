"""P4-RESURRECT: case_store.find_resurrectable_hypotheses() -- an additive,
read-only, advisory query surfacing dormant (INCONCLUSIVE/REFUTED)
hypotheses that have gained NEW positive evidence since they were last
touched, plus the case-mcp tool wrapper over it.

Machine-checkable predicate under test (see the function's docstring):
  a hypothesis is resurrectable iff its status is INCONCLUSIVE or REFUTED
  AND at least one trigger is strictly newer than its updated_at:
    - new_evidence:          an evidence row linked directly to it
    - new_finding_evidence:  an evidence row linked to a finding that
                             points at it (finding not FALSE_POSITIVE/DUPLICATE)
    - finding_advanced:      a finding that points at it reached
                             CONFIRMED/IMPACT_PROVEN/REPORTED

Timestamps are forced with direct SQL on an isolated temp case.db so the
tests are deterministic (datetime('now') has 1-second resolution).
"""

import importlib.util
import json
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

import case_store

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_resurrection", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

T_OLD = "2026-01-01 00:00:00"
T_MID = "2026-01-02 00:00:00"
T_NEW = "2026-01-03 00:00:00"


def _db(tmp_path):
    return str(tmp_path / "case.db")


def _set(db, sql, params=()):
    conn = sqlite3.connect(db)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def _hyp(db, status="INCONCLUSIVE", at=T_MID, text="idor on /api/x"):
    h = case_store.log_hypothesis("obs " + text, text, db_path=db)
    case_store.update_hypothesis(h["id"], status, note="parked", db_path=db)
    _set(db, "UPDATE hypotheses SET updated_at = ?, created_at = ? WHERE id = ?", (at, T_OLD, h["id"]))
    return h["id"]


def _evidence(db, hypothesis_id=None, finding_id=None, at=T_NEW):
    e = case_store.add_evidence("metadata", f"proof-{hypothesis_id}-{finding_id}-{at}",
                                hypothesis_id=hypothesis_id, finding_id=finding_id, db_path=db)
    _set(db, "UPDATE evidence SET created_at = ? WHERE id = ?", (at, e["id"]))
    return e["id"]


def _finding(db, hypothesis_id, status="DISCOVERED", at=T_NEW):
    f = case_store.create_finding("IDOR", "/api/x", hypothesis_id=hypothesis_id, db_path=db)
    if status != "DISCOVERED":
        if status in case_store.EVIDENCE_GATED_STATUSES | {"REPORTED"}:
            _evidence(db, finding_id=f["id"], at=T_OLD)  # old evidence: must not itself trigger
            r = case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
            assert "error" not in r
            if status != "CONFIRMED":
                assert "error" not in case_store.update_finding_status(f["id"], status, db_path=db)
        else:
            assert "error" not in case_store.update_finding_status(f["id"], status, db_path=db)
    _set(db, "UPDATE findings SET updated_at = ? WHERE id = ?", (at, f["id"]))
    return f["id"]


def _ids(result):
    return [r["hypothesis_id"] for r in result]


# ---- predicate: positive triggers -------------------------------------------

def test_inconclusive_hypothesis_with_newer_direct_evidence_is_resurrectable(tmp_path):
    db = _db(tmp_path)
    h = _hyp(db)
    e = _evidence(db, hypothesis_id=h, at=T_NEW)

    result = case_store.find_resurrectable_hypotheses(db_path=db)

    assert _ids(result) == [h]
    row = result[0]
    assert row["status"] == "INCONCLUSIVE"
    assert row["hypothesis"] == "idor on /api/x"
    assert {"kind": "new_evidence", "id": e, "at": T_NEW} in row["reasons"]


def test_refuted_hypothesis_with_newer_evidence_is_resurrectable(tmp_path):
    db = _db(tmp_path)
    h = _hyp(db, status="REFUTED")
    _evidence(db, hypothesis_id=h)

    assert _ids(case_store.find_resurrectable_hypotheses(db_path=db)) == [h]


def test_evidence_on_a_linked_finding_makes_hypothesis_resurrectable(tmp_path):
    db = _db(tmp_path)
    h = _hyp(db)
    f = _finding(db, h, at=T_OLD)
    e = _evidence(db, finding_id=f, at=T_NEW)

    result = case_store.find_resurrectable_hypotheses(db_path=db)

    assert _ids(result) == [h]
    assert {"kind": "new_finding_evidence", "id": e, "at": T_NEW} in result[0]["reasons"]


def test_linked_finding_that_reached_confirmed_after_park_is_resurrectable(tmp_path):
    db = _db(tmp_path)
    h = _hyp(db)
    f = _finding(db, h, status="CONFIRMED", at=T_NEW)

    result = case_store.find_resurrectable_hypotheses(db_path=db)

    assert _ids(result) == [h]
    assert {"kind": "finding_advanced", "id": f, "at": T_NEW} in result[0]["reasons"]


def test_reported_and_impact_proven_findings_count_as_advanced(tmp_path):
    db = _db(tmp_path)
    h1 = _hyp(db, text="a")
    h2 = _hyp(db, text="b")
    _finding(db, h1, status="IMPACT_PROVEN")
    _finding(db, h2, status="REPORTED")

    assert sorted(_ids(case_store.find_resurrectable_hypotheses(db_path=db))) == sorted([h1, h2])


# ---- predicate: negatives (must NOT resurrect) -------------------------------

def test_evidence_older_than_the_park_does_not_resurrect(tmp_path):
    db = _db(tmp_path)
    h = _hyp(db, at=T_MID)
    _evidence(db, hypothesis_id=h, at=T_OLD)

    assert case_store.find_resurrectable_hypotheses(db_path=db) == []


def test_evidence_at_the_exact_park_timestamp_does_not_resurrect(tmp_path):
    """Strictly-newer only: evidence logged in the same second the
    hypothesis was parked is treated as part of the same investigation."""
    db = _db(tmp_path)
    h = _hyp(db, at=T_MID)
    _evidence(db, hypothesis_id=h, at=T_MID)

    assert case_store.find_resurrectable_hypotheses(db_path=db) == []


def test_live_and_resolved_hypotheses_are_never_candidates(tmp_path):
    db = _db(tmp_path)
    for status in ("NEW", "TESTING", "SUPPORTED", "CONFIRMED"):
        h = _hyp(db, status=status, text=status)
        _evidence(db, hypothesis_id=h)

    assert case_store.find_resurrectable_hypotheses(db_path=db) == []


def test_false_positive_and_duplicate_findings_do_not_resurrect(tmp_path):
    db = _db(tmp_path)
    h = _hyp(db)
    fp = _finding(db, h, status="FALSE_POSITIVE", at=T_NEW)
    dup = _finding(db, h, status="DUPLICATE", at=T_NEW)
    _evidence(db, finding_id=fp, at=T_NEW)  # evidence on a dismissed finding: no signal
    _evidence(db, finding_id=dup, at=T_NEW)

    assert case_store.find_resurrectable_hypotheses(db_path=db) == []


def test_in_flight_finding_without_new_evidence_does_not_resurrect(tmp_path):
    db = _db(tmp_path)
    h = _hyp(db)
    _finding(db, h, status="SUSPECTED", at=T_NEW)

    assert case_store.find_resurrectable_hypotheses(db_path=db) == []


def test_evidence_for_an_unrelated_hypothesis_does_not_leak(tmp_path):
    db = _db(tmp_path)
    parked = _hyp(db, text="parked")
    other = _hyp(db, status="TESTING", text="other")
    _evidence(db, hypothesis_id=other)

    assert parked not in _ids(case_store.find_resurrectable_hypotheses(db_path=db))


def test_re_parking_acknowledges_the_trigger(tmp_path):
    """No new store needed to dismiss a candidate: re-saving the hypothesis
    (update_hypothesis) bumps updated_at past the evidence."""
    db = _db(tmp_path)
    h = _hyp(db)
    _evidence(db, hypothesis_id=h, at=T_NEW)
    assert _ids(case_store.find_resurrectable_hypotheses(db_path=db)) == [h]

    case_store.update_hypothesis(h, "INCONCLUSIVE", note="reviewed new evidence, still parked", db_path=db)
    _set(db, "UPDATE hypotheses SET updated_at = '2026-02-01 00:00:00' WHERE id = ?", (h,))

    assert case_store.find_resurrectable_hypotheses(db_path=db) == []


# ---- shape / determinism ----------------------------------------------------

def test_multiple_reasons_are_all_listed_and_results_ordered_by_id(tmp_path):
    db = _db(tmp_path)
    h1 = _hyp(db, text="first")
    h2 = _hyp(db, text="second")
    _evidence(db, hypothesis_id=h2, at=T_NEW)
    _evidence(db, hypothesis_id=h1, at=T_NEW)
    _finding(db, h1, status="CONFIRMED", at=T_NEW)

    result = case_store.find_resurrectable_hypotheses(db_path=db)

    assert _ids(result) == [h1, h2]
    assert {r["kind"] for r in result[0]["reasons"]} >= {"new_evidence", "finding_advanced"}


def test_empty_and_missing_case_db(tmp_path):
    db = _db(tmp_path)
    assert not os.path.exists(db)
    assert case_store.find_resurrectable_hypotheses(db_path=db) == []
    assert not os.path.exists(db)  # a read-only query must not materialize a case.db

    case_store.log_hypothesis("o", "h", db_path=db)
    assert case_store.find_resurrectable_hypotheses(db_path=db) == []


# ---- read-only / advisory ----------------------------------------------------

def test_query_never_mutates_the_case_store(tmp_path):
    db = _db(tmp_path)
    h = _hyp(db)
    _evidence(db, hypothesis_id=h)
    before = case_store.case_export(db_path=db)

    case_store.find_resurrectable_hypotheses(db_path=db)

    assert case_store.case_export(db_path=db) == before


def test_resurrection_query_has_no_write_or_blocking_mechanism():
    """MASTER-ROADMAP-FINAL-v3.md §11-A: advisory only. Structural check on
    the function body: SELECT-only, no status writes, no raise/exit."""
    import inspect
    src = inspect.getsource(case_store.find_resurrectable_hypotheses)
    body = src.split('"""', 2)[-1]  # drop the docstring
    for name in ("INSERT", "UPDATE", "DELETE", "commit(", "update_hypothesis(", "update_finding_status(",
                 "log_hypothesis(", "raise ", "sys.exit(", "subprocess"):
        assert name not in body, f"find_resurrectable_hypotheses must not contain {name!r}"


# ---- case-mcp tool wrapper ---------------------------------------------------

def test_case_mcp_tool_returns_json_with_candidates(tmp_path, monkeypatch):
    db = _db(tmp_path)
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", db)
    h = _hyp(db)
    _evidence(db, hypothesis_id=h)

    out = json.loads(srv.find_resurrectable_hypotheses())

    assert out["advisory"] is True
    assert [c["hypothesis_id"] for c in out["candidates"]] == [h]


def test_case_mcp_tool_redacts_free_text_and_is_empty_safe(tmp_path, monkeypatch):
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"  # gitleaks:allow -- fabricated example JWT, fixture for the redaction assertion below
    db = _db(tmp_path)
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", db)
    assert json.loads(srv.find_resurrectable_hypotheses())["candidates"] == []

    h = _hyp(db, text=fake_jwt)
    _evidence(db, hypothesis_id=h)

    raw = srv.find_resurrectable_hypotheses()
    assert fake_jwt not in raw
    assert len(json.loads(raw)["candidates"]) == 1


def test_case_mcp_tool_does_not_touch_scope_or_budget(tmp_path, monkeypatch):
    """Offline DB read: must not be a Tier-2 (target-touching) tool."""
    import inspect
    src = inspect.getsource(srv.find_resurrectable_hypotheses)
    assert "_enforce_budget" not in src and "scope" not in src.lower().replace("scoped", "")
