"""P4-BM wiring: read-only `order_experiments` case-mcp tool (exposes P4-INFOGAIN).

Orders candidate experiments by expected info-gain-per-cost so the agent runs
the highest-yield tests first -- HINTS, NEVER SKIPS: every candidate is returned
and a novel (no-history) class is never ranked below a known low-yield one.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os

import engagement_paths
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "case_mcp_server_order", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".no-active"))
    monkeypatch.setenv("HUNTMCP_CASE_DB_PATH", str(tmp_path / "case.db"))


def test_order_experiments_returns_all_candidates_never_skips():
    cands = [{"vuln_class": "xss"}, {"vuln_class": "idor"}, {"vuln_class": "business_logic"}]
    out = json.loads(srv.order_experiments(json.dumps(cands)))
    assert out["count"] == 3
    assert {c["vuln_class"] for c in out["ordered"]} == {"xss", "idor", "business_logic"}


def test_order_experiments_ranks_novel_above_a_known_low_yield_class():
    # a known class with a poor track record (3 tried, 0 confirmed) must NOT
    # outrank a brand-new class purely because the novel one lacks history
    # (optimism-under-uncertainty / §11-A never-penalize-a-novel-test).
    import case_store
    for _ in range(3):
        case_store.create_finding(vuln_class="xss", endpoint="/x")  # DISCOVERED = a trial, no hit
    cands = [{"vuln_class": "xss", "cost": 1.0}, {"vuln_class": "never_seen_before", "cost": 1.0}]
    out = json.loads(srv.order_experiments(json.dumps(cands)))
    order = [c["vuln_class"] for c in out["ordered"]]
    assert order.index("never_seen_before") <= order.index("xss")


def test_order_experiments_has_no_url_param():
    assert "url" not in inspect.signature(srv.order_experiments).parameters


def test_order_experiments_rejects_malformed_input():
    assert "error" in json.loads(srv.order_experiments("{not json"))
    assert "error" in json.loads(srv.order_experiments(json.dumps({"not": "a list"})))
