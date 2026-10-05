import json
import os

import case_store
import close_out
import coverage_signal
import file_lock


def _db(tmp_path):
    return str(tmp_path / "case.db")


def test_build_close_out_reports_error_when_no_case_db(tmp_path):
    db = _db(tmp_path)
    result = close_out.build_close_out(db_path=db)
    assert "error" in result


def test_build_close_out_includes_refuted_hypotheses_with_reason(tmp_path):
    """The one genuinely new piece coverage_signal.py/postmortem.py don't
    already surface: postmortem.py deliberately excludes terminal states
    (REFUTED is resolved, not "stalled"/hanging) -- this is what preserves
    the actual WHY behind a negative result instead of it being lost in a
    free-form human summary."""
    db = _db(tmp_path)
    h = case_store.log_hypothesis("client-side route guard present", "admin panel unauth accessible", db_path=db)
    case_store.update_hypothesis(
        h["id"], "REFUTED", note="server returns 403 on every admin path regardless of client guard", db_path=db,
    )
    result = close_out.build_close_out(db_path=db)
    assert "error" not in result
    assert len(result["refuted_hypotheses"]) == 1
    entry = result["refuted_hypotheses"][0]
    assert entry["id"] == h["id"]
    assert "admin panel" in entry["hypothesis"]
    assert "403" in entry["reason"]


def test_build_close_out_excludes_non_refuted_hypotheses(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "still testing this one", db_path=db)
    h2 = case_store.log_hypothesis("obs2", "confirmed this one", db_path=db)
    case_store.update_hypothesis(h2["id"], "CONFIRMED", db_path=db)
    result = close_out.build_close_out(db_path=db)
    assert result["refuted_hypotheses"] == []


def test_build_close_out_includes_coverage_signal(tmp_path):
    """Composes coverage_signal.py's own already-tested output rather than
    re-deriving it -- reuse, not a parallel computation."""
    db = _db(tmp_path)
    f = case_store.create_finding("IDOR", "/api/orders/{id}", db_path=db)
    case_store.add_evidence("response", "leaked another user's order", finding_id=f["id"], db_path=db)
    case_store.update_finding_status(f["id"], "CONFIRMED", db_path=db)
    result = close_out.build_close_out(db_path=db)
    expected_coverage = coverage_signal.compute_coverage(db_path=db)
    assert result["coverage"] == expected_coverage


def test_build_close_out_redacts_free_text_fields(tmp_path):
    db = _db(tmp_path)
    h = case_store.log_hypothesis(
        "obs", "admin login accepts password=Sup3rSecret2026", db_path=db,
    )
    case_store.update_hypothesis(h["id"], "REFUTED", note="password=Sup3rSecret2026 also rejected", db_path=db)
    result = close_out.build_close_out(db_path=db)
    dumped = json.dumps(result)
    assert "Sup3rSecret2026" not in dumped


def test_build_close_out_never_writes_to_case_store(tmp_path):
    db = _db(tmp_path)
    case_store.log_hypothesis("obs", "hyp", db_path=db)
    before = case_store.case_export(db_path=db)
    close_out.build_close_out(db_path=db)
    after = case_store.case_export(db_path=db)
    assert before == after


# ------------------------------------------------------ save / load / reuse

def test_save_close_out_takes_the_file_lock(tmp_path, monkeypatch):
    """Code-review finding: close-out.json is the identical per-engagement
    JSON state file shape file_lock.py's own docstring exists for
    (budget.json/work-registry.json/findings-seen.json/scan-escalation.json
    all wrap their read-modify-write in file_lock.locked() for exactly this
    reason -- "_save() is a plain open+write, not an atomic write-then-
    rename, so a read happening mid-write can see a torn/partial JSON file
    and fail to parse"), but save_close_out()/load_close_out() used plain
    open() with no locking at all."""
    p = str(tmp_path / "close-out.json")
    calls = []
    real_locked = file_lock.locked

    def _tracking_locked(path):
        calls.append(path)
        return real_locked(path)

    monkeypatch.setattr(close_out.file_lock, "locked", _tracking_locked)
    close_out.save_close_out({"refuted_hypotheses": [], "coverage": {}}, path=p)
    assert calls == [p], "save_close_out() did not take file_lock.locked()"


def test_load_close_out_takes_the_file_lock(tmp_path, monkeypatch):
    p = str(tmp_path / "close-out.json")
    close_out.save_close_out({"refuted_hypotheses": [], "coverage": {}}, path=p)

    calls = []
    real_locked = file_lock.locked

    def _tracking_locked(path):
        calls.append(path)
        return real_locked(path)

    monkeypatch.setattr(close_out.file_lock, "locked", _tracking_locked)
    close_out.load_close_out(path=p)
    assert calls == [p], "load_close_out() did not take file_lock.locked()"


def test_save_and_load_round_trips(tmp_path):
    p = str(tmp_path / "close-out.json")
    record = {"refuted_hypotheses": [{"id": 1, "observation": "o", "hypothesis": "h", "reason": "r"}],
              "coverage": {"pairs_tested": 0}}
    written_path = close_out.save_close_out(record, path=p)
    assert written_path == p
    loaded = close_out.load_close_out(path=p)
    assert loaded == record


def test_load_close_out_returns_none_when_absent(tmp_path):
    assert close_out.load_close_out(path=str(tmp_path / "nope.json")) is None


def test_a_later_session_avoids_re_testing_an_already_refuted_path(tmp_path):
    """End-to-end validation of the actual ask: build a close-out record
    from one "session" (a case.db), save it, then -- simulating a LATER
    session loading it fresh -- confirm was_already_refuted() correctly
    flags a path that was already tested and refuted, surfacing the
    original reason instead of silently re-deriving it from scratch."""
    db = _db(tmp_path)
    h = case_store.log_hypothesis(
        "webhook URL parameter accepts arbitrary hosts",
        "SSRF via webhook callback URL is exploitable",
        db_path=db,
    )
    case_store.update_hypothesis(
        h["id"], "REFUTED",
        note="outbound requests are proxied through an egress allowlist; non-allowlisted hosts time out",
        db_path=db,
    )
    record = close_out.build_close_out(db_path=db)
    close_out_path = str(tmp_path / "close-out.json")
    close_out.save_close_out(record, path=close_out_path)

    # New session: only the close-out file is loaded, not the case.db.
    loaded = close_out.load_close_out(path=close_out_path)
    match = close_out.was_already_refuted("SSRF via webhook callback", loaded)
    assert match is not None
    assert "egress allowlist" in match["reason"]

    no_match = close_out.was_already_refuted("completely unrelated open redirect check", loaded)
    assert no_match is None
