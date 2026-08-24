import json

import audit_log


def test_log_call_writes_one_json_line(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit_log.log_call("nuclei", ["-u", "https://example.com"], 0, 123.4, None, path=str(p))
    lines = p.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["tool"] == "nuclei"
    assert entry["args"] == ["-u", "https://example.com"]
    assert entry["returncode"] == 0
    assert entry["duration_ms"] == 123.4
    assert entry["block"] is None
    assert "ts" in entry


def test_log_call_appends_across_calls(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit_log.log_call("subfinder", ["-d", "example.com"], 0, 50.0, None, path=str(p))
    audit_log.log_call("nuclei", ["-u", "https://example.com"], 1, 200.0, "waf", path=str(p))
    lines = p.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["block"] == "waf"


def test_log_call_creates_parent_dir(tmp_path):
    p = tmp_path / "nested" / "audit.jsonl"
    audit_log.log_call("ffuf", [], 0, 1.0, None, path=str(p))
    assert p.exists()
