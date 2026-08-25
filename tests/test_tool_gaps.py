import tool_gaps


def test_record_gap_returns_id(tmp_path):
    p = str(tmp_path / "gaps.jsonl")
    gap_id = tool_gaps.record_gap("ssti-vendor-x", "no matching skill", path=p)
    assert len(gap_id) == 8


def test_record_gap_defaults_to_open_status(tmp_path):
    p = str(tmp_path / "gaps.jsonl")
    tool_gaps.record_gap("technique-a", "context", path=p)
    gaps = tool_gaps.list_gaps(status="open", path=p)
    assert len(gaps) == 1
    assert gaps[0]["status"] == "open"
    assert gaps[0]["technique"] == "technique-a"


def test_list_gaps_filters_by_status(tmp_path):
    p = str(tmp_path / "gaps.jsonl")
    gap_id = tool_gaps.record_gap("technique-a", "context", path=p)
    tool_gaps.record_gap("technique-b", "context2", path=p)
    tool_gaps.resolve_gap(gap_id, resolved_by="human", path=p)

    open_gaps = tool_gaps.list_gaps(status="open", path=p)
    resolved_gaps = tool_gaps.list_gaps(status="resolved", path=p)
    all_gaps = tool_gaps.list_gaps(status="all", path=p)

    assert len(open_gaps) == 1
    assert open_gaps[0]["technique"] == "technique-b"
    assert len(resolved_gaps) == 1
    assert resolved_gaps[0]["technique"] == "technique-a"
    assert len(all_gaps) == 2


def test_resolve_gap_sets_resolved_fields(tmp_path):
    p = str(tmp_path / "gaps.jsonl")
    gap_id = tool_gaps.record_gap("technique-a", "context", path=p)
    ok = tool_gaps.resolve_gap(gap_id, resolved_by="ankit", path=p)
    assert ok is True
    resolved = tool_gaps.list_gaps(status="resolved", path=p)
    assert resolved[0]["resolved_by"] == "ankit"
    assert resolved[0]["resolved_at"] is not None


def test_resolve_gap_unknown_id_returns_false(tmp_path):
    p = str(tmp_path / "gaps.jsonl")
    assert tool_gaps.resolve_gap("nonexistent", path=p) is False


def test_gap_counts_by_technique_groups_correctly(tmp_path):
    p = str(tmp_path / "gaps.jsonl")
    tool_gaps.record_gap("technique-a", "ctx1", path=p)
    tool_gaps.record_gap("technique-a", "ctx2", path=p)
    tool_gaps.record_gap("technique-b", "ctx3", path=p)
    counts = tool_gaps.gap_counts_by_technique(status="open", path=p)
    assert counts == {"technique-a": 2, "technique-b": 1}


def test_gap_counts_excludes_resolved_by_default(tmp_path):
    p = str(tmp_path / "gaps.jsonl")
    gap_id = tool_gaps.record_gap("technique-a", "ctx1", path=p)
    tool_gaps.record_gap("technique-a", "ctx2", path=p)
    tool_gaps.resolve_gap(gap_id, path=p)
    counts = tool_gaps.gap_counts_by_technique(status="open", path=p)
    assert counts == {"technique-a": 1}


def test_list_gaps_empty_when_no_file(tmp_path):
    p = str(tmp_path / "nonexistent.jsonl")
    assert tool_gaps.list_gaps(path=p) == []


def test_record_gap_stores_suggested_tool_name(tmp_path):
    p = str(tmp_path / "gaps.jsonl")
    tool_gaps.record_gap("technique-a", "ctx", suggested_tool_name="new-mcp-server", path=p)
    gaps = tool_gaps.list_gaps(path=p)
    assert gaps[0]["suggested_tool_name"] == "new-mcp-server"
