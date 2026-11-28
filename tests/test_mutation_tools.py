"""Spec 3a, Task 9: plan_mutations / run_mutations / check_mutations /
list_mutation_runs, teardown cleanup of mutation state, agent wiring."""

import asyncio
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import server  # noqa: E402
import ui_walk_replay as R  # noqa: E402
import ui_walk_store  # noqa: E402

AGENTS = os.path.join(ROOT, ".claude", "agents")


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_UI_WALK_DIR", str(tmp_path / "ui-walk"))
    server._UI_JOBS.clear()


def _tools():
    return {t.name: t for t in asyncio.run(server.app.list_tools())}


def test_tools_registered_and_params():
    t = _tools()
    for name in ("plan_mutations", "run_mutations", "check_mutations", "list_mutation_runs"):
        assert name in t, name
    assert {"walk_id", "request_filter", "max_requests"} <= set(t["plan_mutations"].inputSchema["properties"])
    assert {"plan_id", "session_file", "variants", "extra_variants", "drop_variants", "upstream_proxy",
            "bearer_token"} <= set(t["run_mutations"].inputSchema["properties"])
    assert "url" not in t["run_mutations"].inputSchema["properties"]
    doc = t["run_mutations"].description
    assert "grant" in doc and "lead" in doc.lower() and "restore" in doc.lower()


def test_plan_mutations_unknown_walk():
    out = server.plan_mutations("nosuchwalk")
    assert out.startswith("Error") and "start_ui_walk" in out


def test_plan_mutations_lists_reasons_quarantined(tmp_path):
    rep = {"schema": 1, "walk_id": "w1", "session_file_realpath": None, "self_ids": [],
           "entries": [{"replay_id": "r1", "method": "GET", "url": "http://127.0.0.1:9/api/x?promo=A1",
                        "headers": {}, "body": None, "body_truncated": False, "withheld_fields": [],
                        "source": "get-sent", "page": None, "control_signature": None, "response_keys": []}]}
    R.save_replay(rep)
    out = server.plan_mutations("w1")
    assert "plan_id=p" in out and "UNTRUSTED-DATA-BEGIN" in out
    assert out.splitlines()[-1].startswith("Provenance (for case-mcp add_evidence):")


def test_run_mutations_requires_existing_plan():
    out = server.run_mutations("pdoesnotexist")
    assert out.startswith("Error") and not server._UI_JOBS


def test_run_mutations_rejects_remote_proxy():
    out = server.run_mutations("pabc", upstream_proxy="http://10.0.0.1:8080")
    assert "upstream_proxy refused" in out and not server._UI_JOBS


def _fake_done(monkeypatch, res):
    monkeypatch.setattr(server.job_runtime, "poll_thread_job",
                        lambda job_id, jobs: {"status": "done", "job_id": job_id,
                                              "value": {"kind": "mutations", "result": res, "path": "/tmp/m.json"}})


def _res(**kw):
    r = {"run_id": "m1", "plan_id": "p1", "walk_id": "w1", "status": "complete", "error": None, "sent": 12,
         "results": [{"route": "http://127.0.0.1:9/api/v3/profile", "sent": True, "why_not": None},
                     {"route": "http://127.0.0.1:9/api/v3/profile", "sent": False, "why_not": "needs grant"}],
         "candidates": [{"type": "mass-assignment-candidate", "reason": "the added field persisted",
                         "persisted": True, "change": [{"op": "add_param", "location": "json", "field": "role"}],
                         "evidence": {"excerpt": "<b>target text</b>"}, "replay_id": "r1", "variant_id": "v1"}],
         "created_ids": [], "restore_failures": [], "blocked_hosts": [], "honest_limits": ["a limit"],
         "burp_mirror": {"active": False}}
    r.update(kw)
    return r


def test_check_mutations_restore_failed_first_and_provenance_last(monkeypatch):
    _fake_done(monkeypatch, _res(status="restore_failed",
                                 restore_failures=[{"route": "http://127.0.0.1:9/api/v3/profile", "field": "role",
                                                    "why": "read-back still differs after restore"}]))
    out = server.check_mutations("job1")
    lines = out.splitlines()
    assert lines[0].startswith("RESTORE FAILED:") and "role" in lines[0]
    assert lines[-1].startswith("Provenance (for case-mcp add_evidence):")
    assert "mass-assignment-candidate=1" in out and "needs grant" in out


def test_output_quarantines_target_text(monkeypatch):
    _fake_done(monkeypatch, _res())
    out = server.check_mutations("job1")
    i = out.index("<b>target text</b>")
    assert out.rfind("UNTRUSTED-DATA-BEGIN", 0, i) != -1 and out.find("UNTRUSTED-DATA-END", i) != -1
    assert "NOT confirmed" in out


def test_check_mutations_running(monkeypatch):
    monkeypatch.setattr(server.job_runtime, "poll_thread_job",
                        lambda job_id, jobs: {"status": "running", "job_id": job_id, "elapsed_s": 2.0})
    assert "running" in server.check_mutations("job1")


def test_list_mutation_runs_empty():
    assert "No" in server.list_mutation_runs()


def test_teardown_cleanup_deletes_replay_stores(monkeypatch):
    import ui_walk_teardown

    R.save_replay({"walk_id": "w9", "entries": [], "self_ids": []})
    assert ui_walk_teardown.cleanup_mutation_state() == {"replay_stores_deleted": 1}
    assert R.load_replay("w9") is None


def test_mutation_created_objects_are_cleanup_canaries():
    ui_walk_store.register_canary("mut-m1-1", {"token": "mut-m1-1", "kind": "mutation-created"})
    ui_walk_store.register_created_id("mut-m1-1", "77")
    assert "mut-m1-1" in ui_walk_store.load_cleanup_canaries()
    assert ui_walk_store.load_created_ids()["77"] == "mut-m1-1"


def _read(name):
    with open(os.path.join(AGENTS, name)) as fh:
        return fh.read()


def test_agent_prompts_mention_plan_and_run_mutations():
    ex = _read("exploit-agent.md")
    for s in ("plan_mutations", "run_mutations", "check_mutations", "extra_variants",
              "mass-assignment-candidate", "param-removal-bypass-candidate", "hpp-candidate",
              "type-juggling-candidate", "numeric-edge-candidate"):
        assert s in ex, s
    hb = _read("huntbrain.md")
    assert "plan_mutations" in hb and "run_mutations" in hb
    names = _tools()
    for s in ("plan_mutations", "run_mutations", "check_mutations"):
        assert s in names


def test_check_mutations_reports_left_null_keys(monkeypatch):
    _fake_done(monkeypatch, _res(left_null_keys=[{"route": "http://127.0.0.1:9/api/v3/profile", "field": "admin"}]))
    out = server.check_mutations("job1")
    line = next(ln for ln in out.splitlines() if ln.startswith("LEFT AS NULL:"))
    assert "admin" in line and out.index("LEFT AS NULL") < out.index("UNTRUSTED-DATA-BEGIN")


# -- spec 3b, Task 10 ----------------------------------------------------------
def test_plan_output_lists_xform_variants_and_quarantines():
    rep = {"schema": 1, "walk_id": "w3b", "session_file_realpath": None, "self_ids": [],
           "entries": [{"replay_id": "r1", "method": "GET", "url": "http://127.0.0.1:9/api/v4/admin",
                        "headers": {}, "body": None, "body_truncated": False, "withheld_fields": [],
                        "source": "get-sent", "page": None, "control_signature": None, "response_keys": [],
                        "response_meta": {"status": 403, "content_type": "application/json",
                                          "cache_signals": [], "proxy_signals": []}}]}
    R.save_replay(rep)
    out = server.plan_mutations("w3b")
    assert "header X-Forwarded-For: 127.0.0.1" in out and "path /api/v4/admin/" in out
    assert "method HEAD" in out and "UNTRUSTED-DATA-BEGIN" in out
    assert out.splitlines()[-1].startswith("Provenance (for case-mcp add_evidence):")


def test_run_mutations_docstring_names_3b_ops():
    doc = _tools()["run_mutations"].description
    for s in ("set_header", "remove_header", "content_type", "graphql_batch", "hmcb", "race"):
        assert s in doc, s
    pdoc = _tools()["plan_mutations"].description
    for s in ("routing", "cache", "GraphQL", "race"):
        assert s in pdoc, s


def test_check_mutations_shows_3b_candidate_types(monkeypatch):
    res = {"run_id": "m9", "plan_id": "p9", "walk_id": "w9", "status": "complete", "sent": 3, "results": [],
           "candidates": [{"type": t} for t in ("header-authz-bypass-candidate", "cache-poisoning-candidate",
                                                 "race-candidate")], "created_ids": [], "restore_failures": [],
           "honest_limits": [], "burp_mirror": {"active": False}}
    monkeypatch.setattr(server.job_runtime, "poll_thread_job",
                        lambda jid, jobs: {"status": "done", "value": {"kind": "mutations", "result": res,
                                                                       "path": None}})
    out = server.check_mutations("job1")
    for t in ("header-authz-bypass-candidate", "cache-poisoning-candidate", "race-candidate"):
        assert t in out


def test_agent_prompts_mention_3b_candidates_and_ops():
    ex = open(os.path.join(AGENTS, "exploit-agent.md")).read()
    for s in ("header-authz-bypass-candidate", "method-override-candidate", "content-type-confusion-candidate",
              "json-parser-differential-candidate", "path-normalization-candidate", "cache-poisoning-candidate",
              "cache-deception-candidate", "graphql-batching-candidate", "race-candidate", "set_header",
              "graphql_batch", "hmcb"):
        assert s in ex, s
    hb = open(os.path.join(AGENTS, "huntbrain.md")).read()
    assert "request-level" in hb
