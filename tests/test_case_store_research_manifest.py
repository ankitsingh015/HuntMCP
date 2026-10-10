"""C1b: case_store persistence for research-run manifests -- lets a
manifest captured at the start of a run be retrieved later (e.g. by
report-agent, to attach to a Triager-Proof Bundle for the eventual
triager-acceptance A/B)."""

import sqlite3

import case_store


def _db(tmp_path):
    return str(tmp_path / "case.db")


def test_save_research_manifest_returns_an_id(tmp_path):
    db = _db(tmp_path)
    result = case_store.save_research_manifest("example.com", {"target": "example.com"}, db_path=db)
    assert "error" not in result
    assert result["id"] >= 1
    assert result["target"] == "example.com"


def test_get_latest_research_manifest_round_trips_the_dict(tmp_path):
    db = _db(tmp_path)
    manifest = {"target": "example.com", "tool_versions": {"nmap": {"version": "7.94SVN"}}}
    case_store.save_research_manifest("example.com", manifest, db_path=db)

    fetched = case_store.get_latest_research_manifest("example.com", db_path=db)
    assert fetched["target"] == "example.com"
    assert fetched["manifest"] == manifest
    assert "created_at" in fetched


def test_get_latest_research_manifest_returns_none_when_absent(tmp_path):
    db = _db(tmp_path)
    assert case_store.get_latest_research_manifest("example.com", db_path=db) is None


def test_get_latest_research_manifest_returns_the_most_recent_one(tmp_path):
    db = _db(tmp_path)
    case_store.save_research_manifest("example.com", {"run": 1}, db_path=db)
    case_store.save_research_manifest("example.com", {"run": 2}, db_path=db)

    fetched = case_store.get_latest_research_manifest("example.com", db_path=db)
    assert fetched["manifest"] == {"run": 2}


def test_research_manifests_are_isolated_per_target(tmp_path):
    db = _db(tmp_path)
    case_store.save_research_manifest("a.com", {"run": "a"}, db_path=db)
    case_store.save_research_manifest("b.com", {"run": "b"}, db_path=db)

    assert case_store.get_latest_research_manifest("a.com", db_path=db)["manifest"] == {"run": "a"}
    assert case_store.get_latest_research_manifest("b.com", db_path=db)["manifest"] == {"run": "b"}


def test_research_manifests_table_created_on_a_preexisting_db(tmp_path):
    """A case.db from an engagement paused before C1b existed (literally
    missing the research_manifests table, not just a fresh db that
    happens to already have it via the current schema) must gain the new
    table on next open -- the same guarantee C1a's provenance_json ALTER
    TABLE already established for evidence. A prior draft of this test
    built its "pre-existing" db with the CURRENT (post-C1b) create_finding,
    which already includes the table, so it couldn't actually have failed
    even without the fix; this builds a genuinely old-schema db by hand."""
    db = _db(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, vuln_class TEXT)")
    conn.commit()
    conn.close()

    result = case_store.save_research_manifest("example.com", {"ok": True}, db_path=db)
    assert "error" not in result

    fetched = case_store.get_latest_research_manifest("example.com", db_path=db)
    assert fetched["manifest"] == {"ok": True}
