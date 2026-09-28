import scope_expansion


def test_record_candidate_returns_id(tmp_path):
    p = str(tmp_path / "scope-expansion.jsonl")
    cand_id = scope_expansion.record_candidate(
        "cdn-edge-7.example-corp.net",
        "shares the in-scope TLS cert (same SAN list) as app.example.com",
        "app.example.com",
        path=p,
    )
    assert len(cand_id) == 8


def test_record_candidate_defaults_to_pending_status(tmp_path):
    p = str(tmp_path / "scope-expansion.jsonl")
    scope_expansion.record_candidate("host-a.example.net", "evidence", "app.example.com", path=p)
    candidates = scope_expansion.list_candidates(status="pending", path=p)
    assert len(candidates) == 1
    assert candidates[0]["status"] == "pending"
    assert candidates[0]["host"] == "host-a.example.net"
    assert candidates[0]["related_in_scope_host"] == "app.example.com"


def test_list_candidates_filters_by_status(tmp_path):
    p = str(tmp_path / "scope-expansion.jsonl")
    cand_id = scope_expansion.record_candidate("host-a.example.net", "evidence", "app.example.com", path=p)
    scope_expansion.record_candidate("host-b.example.net", "evidence2", "app.example.com", path=p)
    scope_expansion.decide_candidate(cand_id, "approved", decided_by="human", path=p)

    pending = scope_expansion.list_candidates(status="pending", path=p)
    approved = scope_expansion.list_candidates(status="approved", path=p)
    all_candidates = scope_expansion.list_candidates(status="all", path=p)

    assert len(pending) == 1
    assert pending[0]["host"] == "host-b.example.net"
    assert len(approved) == 1
    assert approved[0]["host"] == "host-a.example.net"
    assert len(all_candidates) == 2


def test_decide_candidate_sets_decision_fields(tmp_path):
    p = str(tmp_path / "scope-expansion.jsonl")
    cand_id = scope_expansion.record_candidate("host-a.example.net", "evidence", "app.example.com", path=p)
    ok = scope_expansion.decide_candidate(cand_id, "rejected", decided_by="ankit", path=p)
    assert ok is True
    rejected = scope_expansion.list_candidates(status="rejected", path=p)
    assert len(rejected) == 1
    assert rejected[0]["decided_by"] == "ankit"
    assert rejected[0]["decided_at"] is not None


def test_decide_candidate_rejects_invalid_decision(tmp_path):
    p = str(tmp_path / "scope-expansion.jsonl")
    cand_id = scope_expansion.record_candidate("host-a.example.net", "evidence", "app.example.com", path=p)
    ok = scope_expansion.decide_candidate(cand_id, "maybe", path=p)
    assert ok is False
    # still pending -- an invalid decision must not silently mutate state
    assert scope_expansion.list_candidates(status="pending", path=p)[0]["id"] == cand_id


def test_decide_candidate_returns_false_for_unknown_id(tmp_path):
    p = str(tmp_path / "scope-expansion.jsonl")
    assert scope_expansion.decide_candidate("nosuchid", "approved", path=p) is False


def test_recording_never_touches_the_real_engagement_scope_file(tmp_path, monkeypatch):
    """Recording/deciding a candidate is pure bookkeeping -- it must never
    write to engagement.yaml itself. Approving a candidate still requires
    the human operator to add it to in_scope by hand (same "policy
    judgment stays human" principle as scope_guard.detect_scope_conflicts()
    -- see this module's own docstring)."""
    p = str(tmp_path / "scope-expansion.jsonl")
    engagement_file = tmp_path / "engagement.yaml"
    engagement_file.write_text("target: app.example.com\nin_scope: [app.example.com]\n")
    before = engagement_file.read_text()
    cand_id = scope_expansion.record_candidate("host-a.example.net", "evidence", "app.example.com", path=p)
    scope_expansion.decide_candidate(cand_id, "approved", path=p)
    assert engagement_file.read_text() == before
