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


def test_save_hunt_with_dict_chains(monkeypatch, tmp_path):
    """Regression test: chains was assumed to always be a list of plain
    strings -- a dict-shaped chain entry (the same {field: ...} object shape
    findings/tech_stack accept) previously crashed with
    sqlite3.ProgrammingError: Error binding parameter 2 (dict not supported)
    (reported live in a real engagement retrospective, same root cause class
    already fixed for `findings` above)."""
    _use_tmp_db(monkeypatch, tmp_path)
    result = memory_db.save_hunt(
        target="example.com",
        chains=[{"description": "IDOR -> account takeover via password reset"}],
    )
    assert "Saved hunt" in result
    recalled = memory_db.recall("example.com")
    assert "IDOR -> account takeover via password reset" in recalled


def test_save_hunt_with_mixed_chains_shapes(monkeypatch, tmp_path):
    _use_tmp_db(monkeypatch, tmp_path)
    result = memory_db.save_hunt(
        target="example.com",
        chains=[
            {"description": "SSRF -> cloud metadata -> IAM credential theft"},
            "Open redirect -> OAuth token exfiltration",
        ],
    )
    assert "Saved hunt" in result
    recalled = memory_db.recall("example.com")
    assert "SSRF -> cloud metadata -> IAM credential theft" in recalled
    assert "Open redirect -> OAuth token exfiltration" in recalled


def test_save_hunt_with_dict_tech_stack(monkeypatch, tmp_path):
    """Regression test: tech_stack/subdomains are stored as a JSON list
    regardless of item shape, but recall()/search_by_tech() previously
    assumed every item was already a plain string and called
    ', '.join(tech) directly -- a dict-shaped tech_stack entry (e.g.
    {"name": "nginx", "version": "1.18"}) crashed with TypeError: sequence
    item 0: expected str instance, dict found."""
    _use_tmp_db(monkeypatch, tmp_path)
    result = memory_db.save_hunt(
        target="example.com",
        tech_stack=[{"name": "nginx", "version": "1.18"}, "React"],
    )
    assert "Saved hunt" in result
    recalled = memory_db.recall("example.com")
    assert "nginx" in recalled
    assert "React" in recalled


def test_save_hunt_with_dict_subdomains(monkeypatch, tmp_path):
    _use_tmp_db(monkeypatch, tmp_path)
    result = memory_db.save_hunt(
        target="example.com",
        subdomains=[{"host": "api.example.com"}, "app.example.com"],
    )
    assert "Saved hunt" in result
    recalled = memory_db.recall("example.com")
    assert "api.example.com" in recalled
    assert "app.example.com" in recalled


def test_search_by_tech_with_dict_tech_stack(monkeypatch, tmp_path):
    """search_by_tech() also joins tech_stack into display text -- must
    survive dict-shaped entries the same way recall() does."""
    _use_tmp_db(monkeypatch, tmp_path)
    memory_db.save_hunt(
        target="example.com",
        tech_stack=[{"name": "nginx", "version": "1.18"}],
    )
    result = memory_db.search_by_tech(["nginx"])
    assert "example.com" in result
    assert "nginx" in result
