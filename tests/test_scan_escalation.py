import file_lock
import scan_escalation


def test_first_throttled_attempt_does_not_yet_escalate(tmp_path):
    p = str(tmp_path / "scan-escalation.json")
    result = scan_escalation.record_scan_attempt("target.com", "throttled_after_bypass", path=p)
    assert result["consecutive_throttled"] == 1
    assert result["should_escalate_to_browser"] is False


def test_reaching_the_threshold_triggers_escalation(tmp_path):
    """Regression test reported live in an engagement retrospective: a
    CDN/bot-management platform defeated full automated scan-template
    coverage even after an initial hard block was bypassed via a
    request-header change -- a single manual request succeeded where the
    same automated scanner, using the same bypass, still could not
    complete. A browser-automation tool was already available but no
    playbook step routed to it automatically. This tracks consecutive
    throttled/incomplete runs on the SAME host (after an otherwise-
    successful bypass) and signals escalation at the threshold."""
    p = str(tmp_path / "scan-escalation.json")
    for _ in range(scan_escalation.ESCALATION_THRESHOLD - 1):
        result = scan_escalation.record_scan_attempt("target.com", "throttled_after_bypass", path=p)
        assert result["should_escalate_to_browser"] is False
    result = scan_escalation.record_scan_attempt("target.com", "throttled_after_bypass", path=p)
    assert result["consecutive_throttled"] == scan_escalation.ESCALATION_THRESHOLD
    assert result["should_escalate_to_browser"] is True


def test_a_completed_scan_resets_the_consecutive_count(tmp_path):
    p = str(tmp_path / "scan-escalation.json")
    scan_escalation.record_scan_attempt("target.com", "throttled_after_bypass", path=p)
    scan_escalation.record_scan_attempt("target.com", "throttled_after_bypass", path=p)
    result = scan_escalation.record_scan_attempt("target.com", "completed", path=p)
    assert result["consecutive_throttled"] == 0
    assert result["should_escalate_to_browser"] is False


def test_hosts_are_tracked_independently(tmp_path):
    p = str(tmp_path / "scan-escalation.json")
    for _ in range(scan_escalation.ESCALATION_THRESHOLD):
        scan_escalation.record_scan_attempt("target-a.com", "throttled_after_bypass", path=p)
    result_b = scan_escalation.record_scan_attempt("target-b.com", "throttled_after_bypass", path=p)
    assert result_b["consecutive_throttled"] == 1
    assert result_b["should_escalate_to_browser"] is False


def test_should_escalate_reads_back_current_state_without_recording(tmp_path):
    p = str(tmp_path / "scan-escalation.json")
    for _ in range(scan_escalation.ESCALATION_THRESHOLD):
        scan_escalation.record_scan_attempt("target.com", "throttled_after_bypass", path=p)
    assert scan_escalation.should_escalate_to_browser("target.com", path=p) is True
    assert scan_escalation.should_escalate_to_browser("never-scanned.com", path=p) is False
    # Read-only -- calling should_escalate_to_browser again must not itself
    # mutate the counter.
    assert scan_escalation.should_escalate_to_browser("target.com", path=p) is True


def test_should_escalate_takes_the_file_lock_before_reading(tmp_path, monkeypatch):
    """Code-review finding: every sibling guard module in this repo
    (budget_guard.check_budget(), work_registry.list_active_work(),
    dedupe_check) wraps even READ-ONLY access in file_lock.locked(),
    because _save() here is a plain open+write, not an atomic
    write-then-rename -- file_lock.py's own docstring names exactly this
    failure mode: "a read happening mid-write can see a torn/partial JSON
    file and fail to parse." record_scan_attempt() already takes the lock;
    should_escalate_to_browser() must too, for the same reason."""
    p = str(tmp_path / "scan-escalation.json")
    scan_escalation.record_scan_attempt("target.com", "throttled_after_bypass", path=p)

    calls = []
    real_locked = file_lock.locked

    def _tracking_locked(path):
        calls.append(path)
        return real_locked(path)

    monkeypatch.setattr(scan_escalation.file_lock, "locked", _tracking_locked)
    scan_escalation.should_escalate_to_browser("target.com", path=p)

    assert calls == [p], "should_escalate_to_browser() did not take file_lock.locked() before reading"


def test_record_scan_attempt_rejects_invalid_outcome(tmp_path):
    p = str(tmp_path / "scan-escalation.json")
    result = scan_escalation.record_scan_attempt("target.com", "vibes", path=p)
    assert "error" in result
