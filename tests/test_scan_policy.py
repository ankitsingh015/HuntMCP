import pytest

import scan_policy


def _write_engagement(tmp_path, extra_yaml=""):
    p = tmp_path / "engagement.yaml"
    p.write_text(
        "target: example.com\nin_scope:\n  - example.com\n" + extra_yaml,
    )
    return str(p)


def test_load_scan_policy_defaults_to_full_when_absent(tmp_path):
    """Backward-compatible default: an engagement.yaml written before this
    field existed (or one that simply doesn't restrict scanning) must
    behave exactly as scan-agent's current scanner-first default already
    does -- "full", no cap."""
    path = _write_engagement(tmp_path)
    policy = scan_policy.load_scan_policy(path)
    assert policy["scan_policy"] == "full"
    assert policy["scanner_volume_cap"] is None


@pytest.mark.parametrize("value", ["manual", "bounded", "full"])
def test_load_scan_policy_reads_each_valid_value(tmp_path, value):
    path = _write_engagement(tmp_path, f"scan_policy: {value}\n")
    policy = scan_policy.load_scan_policy(path)
    assert policy["scan_policy"] == value


def test_load_scan_policy_reads_scanner_volume_cap(tmp_path):
    path = _write_engagement(tmp_path, "scan_policy: bounded\nscanner_volume_cap: 50\n")
    policy = scan_policy.load_scan_policy(path)
    assert policy["scan_policy"] == "bounded"
    assert policy["scanner_volume_cap"] == 50


def test_load_scan_policy_rejects_invalid_value(tmp_path):
    """Fail loud, not silently-default -- a typo'd policy value (e.g.
    "manaul") must not silently fall back to "full" and let bulk scanning
    proceed on a program that explicitly restricted it."""
    path = _write_engagement(tmp_path, "scan_policy: manaul\n")
    policy = scan_policy.load_scan_policy(path)
    assert "error" in policy


def test_load_scan_policy_missing_file_defaults_to_full(tmp_path):
    policy = scan_policy.load_scan_policy(str(tmp_path / "nope.yaml"))
    assert policy["scan_policy"] == "full"


def test_load_scan_policy_fails_loud_when_pyyaml_unavailable(tmp_path, monkeypatch):
    """SECURITY regression (code-review finding): a missing PyYAML module
    used to be treated identically to "no engagement.yaml file" -- both
    silently returned the unrestricted DEFAULT_POLICY. That conflates
    "nothing to restrict" with "cannot determine whether something
    restricts" -- a program's explicit scan_policy: manual would silently
    read back as unrestricted "full" if yaml ever failed to import in
    whatever environment this is invoked from, contradicting this
    function's own "fail loud, not silently default to full" stated
    behavior for the invalid-value case. Must error instead, consistent
    with scope_guard.py's own convention for the identical yaml-missing
    case."""
    path = _write_engagement(tmp_path, "scan_policy: manual\n")
    monkeypatch.setattr(scan_policy, "yaml", None)
    policy = scan_policy.load_scan_policy(path)
    assert "error" in policy


def test_should_run_bulk_scanner_true_for_full():
    assert scan_policy.should_run_bulk_scanner({"scan_policy": "full", "scanner_volume_cap": None}) is True


def test_should_run_bulk_scanner_false_for_manual():
    """Regression test reported live in an engagement retrospective: under
    a no-high-volume-scan program policy, the orchestrator had to manually
    notice the conflict and rewrite the scan task into a fixed-path manual
    check -- policy was prose-only, not consumed by the scan specialist
    itself."""
    assert scan_policy.should_run_bulk_scanner({"scan_policy": "manual", "scanner_volume_cap": None}) is False


def test_should_run_bulk_scanner_true_for_bounded_under_cap():
    policy = {"scan_policy": "bounded", "scanner_volume_cap": 50}
    assert scan_policy.should_run_bulk_scanner(policy, calls_so_far=10) is True


def test_should_run_bulk_scanner_false_for_bounded_at_cap():
    policy = {"scan_policy": "bounded", "scanner_volume_cap": 50}
    assert scan_policy.should_run_bulk_scanner(policy, calls_so_far=50) is False
