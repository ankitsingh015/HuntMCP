import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "memory_db", os.path.join(ROOT, "mcp-servers", "memory-mcp", "db.py")
)
memory_db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(memory_db)


def _use_tmp_db(monkeypatch, tmp_path):
    monkeypatch.setattr(memory_db, "MEMORY_DIR", str(tmp_path))
    monkeypatch.setattr(memory_db, "MEMORY_DB", str(tmp_path / "memory.db"))


def test_save_hunt_with_dict_findings(monkeypatch, tmp_path):
    _use_tmp_db(monkeypatch, tmp_path)
    result = memory_db.save_hunt(
        target="example.com",
        findings=[{"finding": "Reflected XSS on /search", "vuln_class": "XSS", "confidence": "HIGH"}],
    )
    assert "Saved hunt" in result
    recalled = memory_db.recall("example.com")
    assert "Reflected XSS on /search" in recalled
    assert "HIGH" in recalled


def test_save_hunt_with_plain_string_findings(monkeypatch, tmp_path):
    """Regression test: orchestrator can call save() with findings as a list
    of plain strings rather than {finding, vuln_class, confidence} objects --
    this previously crashed with 'str' object has no attribute 'get'
    (reported live in a real engagement retrospective)."""
    _use_tmp_db(monkeypatch, tmp_path)
    result = memory_db.save_hunt(
        target="example.com",
        findings=["IDOR on /api/user/{id}", "Open redirect on /login?next="],
    )
    assert "Saved hunt" in result
    recalled = memory_db.recall("example.com")
    assert "IDOR on /api/user/{id}" in recalled
    assert "Open redirect on /login?next=" in recalled


def test_save_hunt_with_mixed_findings_shapes(monkeypatch, tmp_path):
    _use_tmp_db(monkeypatch, tmp_path)
    result = memory_db.save_hunt(
        target="example.com",
        findings=[
            {"finding": "SSRF via webhook URL", "vuln_class": "SSRF", "confidence": "MEDIUM"},
            "Missing rate limit on /api/login",
        ],
    )
    assert "Saved hunt" in result
    recalled = memory_db.recall("example.com")
    assert "SSRF via webhook URL" in recalled
    assert "Missing rate limit on /api/login" in recalled
