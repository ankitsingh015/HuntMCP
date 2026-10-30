"""P3-ADAPTER: case-mcp's ingest_schemathesis_falsifiers tool converts
schemathesis-mcp's "Falsifiers (for case-mcp/P3-ADAPTER): <json>" contract
into the SAME DISCOVERED-finding + hypothesis pipeline every other scanner
feeds (create_finding/log_hypothesis) -- it must never touch CEM state or
bypass the CONFIRMED gate; that stays exploit-agent's job via the normal
re-run/evidence/update_finding_status flow."""

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))

_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_ingest_falsifiers", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"),
)
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))


def _one_failure(**overrides):
    f = {
        "type": "response_schema_conformance",
        "title": "Response violates schema",
        "severity": "HIGH",
        "count": 3,
        "operations": ["GET /api/users/{id}"],
    }
    f.update(overrides)
    return f


def test_ingest_creates_one_finding_per_operation(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    failures = [_one_failure(operations=["GET /api/users/{id}", "POST /api/users"])]
    result = json.loads(srv.ingest_schemathesis_falsifiers(json.dumps(failures)))

    assert "error" not in result
    assert len(result["created"]) == 2
    endpoints = {c["endpoint"] for c in result["created"]}
    assert endpoints == {"GET /api/users/{id}", "POST /api/users"}

    for c in result["created"]:
        finding = srv.case_store.get_finding(c["finding_id"])
        assert finding["status"] == "DISCOVERED"
        assert finding["hypothesis_id"] == c["hypothesis_id"]
        assert finding["vuln_class"] == "SCHEMA_RESPONSE_SCHEMA_CONFORMANCE"


def test_ingest_handles_multiple_failures(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    failures = [
        _one_failure(type="not_a_server_error", operations=["GET /api/foo"]),
        _one_failure(type="negative_data_rejection", operations=["POST /api/bar"]),
    ]
    result = json.loads(srv.ingest_schemathesis_falsifiers(json.dumps(failures)))
    assert len(result["created"]) == 2
    vuln_classes = {c["vuln_class"] for c in result["created"]}
    assert vuln_classes == {"SCHEMA_NOT_A_SERVER_ERROR", "SCHEMA_NEGATIVE_DATA_REJECTION"}


def test_ingest_never_creates_cem_state(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    failures = [_one_failure()]
    result = json.loads(srv.ingest_schemathesis_falsifiers(json.dumps(failures)))
    finding_id = result["created"][0]["finding_id"]
    # No cem_define was ever called -- CEM entry stays gated on the normal
    # CONFIRMED flow, never auto-unlocked by ingestion.
    state = srv.case_store.cem_load_state(finding_id)
    assert "error" in state


def test_ingest_rejects_malformed_json(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    result = json.loads(srv.ingest_schemathesis_falsifiers("{not json"))
    assert "error" in result


def test_ingest_rejects_non_list_json(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    result = json.loads(srv.ingest_schemathesis_falsifiers(json.dumps({"type": "x"})))
    assert "error" in result


def test_ingest_skips_failure_with_no_operations(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    failures = [_one_failure(operations=[])]
    result = json.loads(srv.ingest_schemathesis_falsifiers(json.dumps(failures)))
    assert result["created"] == []
    assert len(result["skipped"]) == 1


def test_ingest_skips_failure_with_non_list_operations(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    # A string "operations" value is truthy, so a naive `if not operations`
    # check alone would miss this -- it must be rejected for not being a
    # list, not silently iterated character-by-character.
    failures = [_one_failure(operations="abc")]
    result = json.loads(srv.ingest_schemathesis_falsifiers(json.dumps(failures)))
    assert result["created"] == []
    assert len(result["skipped"]) == 1


def test_ingest_skips_failure_missing_type(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    failures = [{"title": "no type here", "operations": ["GET /x"]}]
    result = json.loads(srv.ingest_schemathesis_falsifiers(json.dumps(failures)))
    assert result["created"] == []
    assert len(result["skipped"]) == 1


def test_ingest_empty_list_is_a_noop(tmp_path, monkeypatch):
    _isolated(tmp_path, monkeypatch)
    result = json.loads(srv.ingest_schemathesis_falsifiers(json.dumps([])))
    assert result == {"created": [], "skipped": []}
