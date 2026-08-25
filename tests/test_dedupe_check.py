import threading
import time

import dedupe_check


def test_first_finding_is_not_a_duplicate(tmp_path):
    p = str(tmp_path / "findings-seen.json")
    result = dedupe_check.check_and_record("XSS", "https://example.com/search", "q", path=p)
    assert result["duplicate"] is False
    assert "fingerprint" in result


def test_same_finding_again_is_flagged_duplicate(tmp_path):
    p = str(tmp_path / "findings-seen.json")
    dedupe_check.check_and_record("XSS", "https://example.com/search", "q", path=p)
    result = dedupe_check.check_and_record("XSS", "https://example.com/search", "q", path=p)
    assert result["duplicate"] is True
    assert "first_seen_as" in result


def test_different_parameter_is_not_a_duplicate(tmp_path):
    p = str(tmp_path / "findings-seen.json")
    dedupe_check.check_and_record("XSS", "https://example.com/search", "q", path=p)
    result = dedupe_check.check_and_record("XSS", "https://example.com/search", "sort", path=p)
    assert result["duplicate"] is False


def test_different_vuln_class_same_endpoint_is_not_a_duplicate(tmp_path):
    p = str(tmp_path / "findings-seen.json")
    dedupe_check.check_and_record("XSS", "https://example.com/search", "q", path=p)
    result = dedupe_check.check_and_record("SQLi", "https://example.com/search", "q", path=p)
    assert result["duplicate"] is False


def test_case_insensitive_fingerprint():
    fp1 = dedupe_check._fingerprint("XSS", "https://Example.com/Search", "Q")
    fp2 = dedupe_check._fingerprint("xss", "https://example.com/search", "q")
    assert fp1 == fp2


def test_no_parameter_still_works(tmp_path):
    p = str(tmp_path / "findings-seen.json")
    result = dedupe_check.check_and_record("SSRF", "https://example.com/fetch", path=p)
    assert result["duplicate"] is False
    dup = dedupe_check.check_and_record("SSRF", "https://example.com/fetch", path=p)
    assert dup["duplicate"] is True


def test_concurrent_same_finding_only_one_wins(monkeypatch, tmp_path):
    """Regression test for the TOCTOU race: check_and_record() used to
    check-then-save with no locking, so two concurrent submissions of the
    exact same finding could both read "not seen yet" and both record it
    as new -- exploit-agent would write up the same bug twice. Widen the
    race window artificially so this fails reliably without file_lock."""
    p = str(tmp_path / "findings-seen.json")
    orig_load = dedupe_check._load

    def slow_load(path):
        state = orig_load(path)
        time.sleep(0.01)
        return state

    monkeypatch.setattr(dedupe_check, "_load", slow_load)

    n = 20
    results: list[dict] = []
    lock = threading.Lock()

    def _record():
        result = dedupe_check.check_and_record("XSS", "https://example.com/search", "q", path=p)
        with lock:
            results.append(result)

    threads = [threading.Thread(target=_record) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    non_duplicates = [r for r in results if not r["duplicate"]]
    assert len(non_duplicates) == 1
