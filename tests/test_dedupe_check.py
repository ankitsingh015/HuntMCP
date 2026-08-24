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
