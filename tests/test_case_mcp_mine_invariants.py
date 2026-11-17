"""P4-M1 Task 5 -- read-only `mine_invariants` case-mcp tool.

Builds the observed-exchange corpus (invariant_corpus), mines invariant
candidates (invariant_probe), and STAGES each survivor as a DISCOVERED finding
via the existing to_cem_hypothesis path. It has no `url` param, makes no target
request, never runs CEM counterfactuals, and never advances finding status --
the normal CONFIRMED gate + run_cem_pipeline flow still owns that.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os

import case_store
import engagement_paths
import invariant_corpus
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_mine", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


def _real_corpus():
    def _row(tok, res="/orders/42"):
        url = f"https://app.example.com{res}"
        return {"identity": invariant_corpus.identity_label({"Authorization": tok}),
                "resource": res, "action": "read", "args": {}, "status": 200,
                "body": "", "session": None,
                "base_request": {"method": "GET", "url": url,
                                 "headers": {"Authorization": tok}, "body": None}}
    return [_row("Bearer alice"), _row("Bearer bob")]


def test_mine_invariants_has_no_url_param():
    params = inspect.signature(srv.mine_invariants).parameters
    assert "url" not in params


def test_mine_invariants_stages_discovered_findings_from_corpus(monkeypatch):
    monkeypatch.setattr(invariant_corpus, "build_corpus", lambda *a, **k: _real_corpus())
    out = json.loads(srv.mine_invariants(target="app.example.com"))
    assert out["count"] >= 1
    staged = out["staged"][0]
    assert staged["invariant"] == "ownership"
    assert staged["condition_names"] == ["Authorization"]
    assert case_store.get_finding(staged["finding_id"])["status"] == "DISCOVERED"


def test_mine_invariants_never_runs_cem_or_advances_status(monkeypatch):
    monkeypatch.setattr(invariant_corpus, "build_corpus", lambda *a, **k: _real_corpus())
    out = json.loads(srv.mine_invariants(target="app.example.com"))
    fid = out["staged"][0]["finding_id"]
    assert case_store.get_finding(fid)["status"] == "DISCOVERED"   # not advanced
    assert case_store.count_cem_trials(fid) == 0                   # no counterfactual ran


def test_mine_invariants_empty_corpus_is_noop(monkeypatch):
    monkeypatch.setattr(invariant_corpus, "build_corpus", lambda *a, **k: [])
    out = json.loads(srv.mine_invariants(target="app.example.com"))
    assert out == {"staged": [], "count": 0}
