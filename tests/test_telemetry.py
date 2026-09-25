import json
import os

import audit_log
import case_store
import telemetry


def _db(tmp_path):
    return str(tmp_path / "case.db")


def _audit(tmp_path):
    return str(tmp_path / "audit.jsonl")


# ---- audit_log_totals -------------------------------------------------------

def test_audit_log_totals_missing_file_returns_zeros(tmp_path):
    totals = telemetry.audit_log_totals(audit_log_path=_audit(tmp_path))
    assert totals == {"tool_calls": 0, "wall_clock_ms": 0.0, "by_tool": {}}


def test_audit_log_totals_counts_calls_and_sums_duration(tmp_path):
    p = _audit(tmp_path)
    audit_log.log_call("nuclei", ["-u", "https://x"], 0, 100.0, None, path=p)
    audit_log.log_call("httpx", ["-u", "https://x"], 0, 50.5, None, path=p)
    totals = telemetry.audit_log_totals(audit_log_path=p)
    assert totals["tool_calls"] == 2
    assert totals["wall_clock_ms"] == 150.5
    assert totals["by_tool"] == {"nuclei": 1, "httpx": 1}


def test_audit_log_totals_ignores_malformed_lines(tmp_path):
    p = _audit(tmp_path)
    with open(p, "w") as f:
        f.write("not json\n")
        f.write(json.dumps({"tool": "nmap", "duration_ms": 10.0}) + "\n")
    totals = telemetry.audit_log_totals(audit_log_path=p)
    assert totals["tool_calls"] == 1
    assert totals["by_tool"] == {"nmap": 1}


def test_audit_log_totals_ignores_a_line_with_a_non_string_tool(tmp_path):
    """A non-string "tool" (e.g. a JSON list) is truthy and would otherwise
    reach `by_tool[tool] = ...` and raise TypeError: unhashable type,
    crashing this offline aggregate (round-2 review finding, independently
    confirmed twice)."""
    p = _audit(tmp_path)
    with open(p, "w") as f:
        f.write(json.dumps({"tool": ["nuclei", "httpx"], "duration_ms": 1.0}) + "\n")
        f.write(json.dumps({"tool": "nmap", "duration_ms": 10.0}) + "\n")
    totals = telemetry.audit_log_totals(audit_log_path=p)
    assert totals["tool_calls"] == 1
    assert totals["by_tool"] == {"nmap": 1}


def test_audit_log_totals_survives_a_wrongly_typed_duration_ms(tmp_path):
    """A validly-JSON but non-numeric duration_ms (hand-edited/corrupted
    line) must not raise -- found via code review: this used to be an
    uncaught ValueError that propagated straight through postmortem.py's
    run_postmortem(), breaking its always-produces-a-report contract."""
    p = _audit(tmp_path)
    with open(p, "w") as f:
        f.write(json.dumps({"tool": "nmap", "duration_ms": "not-a-number"}) + "\n")
        f.write(json.dumps({"tool": "httpx", "duration_ms": 25.0}) + "\n")
    totals = telemetry.audit_log_totals(audit_log_path=p)
    assert totals["tool_calls"] == 2  # both calls still counted
    assert totals["wall_clock_ms"] == 25.0  # the bad one contributes 0, not a crash
    assert totals["by_tool"] == {"nmap": 1, "httpx": 1}


def test_audit_log_totals_treats_a_boolean_duration_ms_as_malformed(tmp_path):
    """bool is a subclass of int in Python -- float(True) == 1.0 would
    otherwise silently succeed instead of being treated as the malformed
    value it is (round-2 review finding)."""
    p = _audit(tmp_path)
    with open(p, "w") as f:
        f.write(json.dumps({"tool": "nuclei", "duration_ms": True}) + "\n")
    totals = telemetry.audit_log_totals(audit_log_path=p)
    assert totals["tool_calls"] == 1
    assert totals["wall_clock_ms"] == 0.0


def test_audit_log_totals_ignores_a_json_line_that_isnt_an_object(tmp_path):
    p = _audit(tmp_path)
    with open(p, "w") as f:
        f.write(json.dumps([1, 2, 3]) + "\n")
        f.write(json.dumps({"tool": "nuclei", "duration_ms": 5.0}) + "\n")
    totals = telemetry.audit_log_totals(audit_log_path=p)
    assert totals["tool_calls"] == 1
    assert totals["by_tool"] == {"nuclei": 1}


# ---- to_bench_cost -----------------------------------------------------------

def test_to_bench_cost_shape(tmp_path):
    p = _audit(tmp_path)
    audit_log.log_call("sqlmap", ["-u", "https://x"], 0, 2000.0, None, path=p)
    cost = telemetry.to_bench_cost(audit_log_path=p)
    assert cost == {"tool_calls": 1.0, "wall_clock_s": 2.0, "requests": 1.0}


# ---- finding_telemetry --------------------------------------------------------

def test_finding_telemetry_missing_finding_returns_error(tmp_path):
    result = telemetry.finding_telemetry(999, db_path=_db(tmp_path))
    assert "error" in result


def test_finding_telemetry_sums_experiment_cost_and_counts(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=db)
    case_store.log_experiment("sqlmap", "id=1", "https://x", cost=3, finding_id=f["id"], db_path=db)
    case_store.log_experiment("sqlmap", "id=2", "https://x", cost=2, finding_id=f["id"], db_path=db)
    tel = telemetry.finding_telemetry(f["id"], db_path=db)
    assert tel["finding_id"] == f["id"]
    assert tel["experiment_count"] == 2
    assert tel["experiment_cost_total"] == 5
    assert tel["http_requests"] is None  # never run through CEM -- "not measured", not "zero"
    assert tel["token_yield"] is None


def test_finding_telemetry_counts_cem_trials_as_http_requests(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("SSRF", "/api/fetch", db_path=db)
    case_store.cem_define(
        f["id"], {"method": "GET", "url": "https://x"}, {"status": 200},
        [{"name": "c1", "category": "header", "perturbation": {"x": "y"}}],
        db_path=db,
    )
    case_store.cem_record_trial(f["id"], "baseline", 0, True, db_path=db)
    case_store.cem_record_trial(f["id"], "perturbed", 0, True, db_path=db)
    tel = telemetry.finding_telemetry(f["id"], db_path=db)
    assert tel["http_requests"] == 2


def test_finding_telemetry_accepts_caller_supplied_token_yield(tmp_path):
    db = _db(tmp_path)
    f = case_store.create_finding("XSS", "/x", db_path=db)
    tel = telemetry.finding_telemetry(f["id"], db_path=db, token_yield=1234.0)
    assert tel["token_yield"] == 1234.0


def test_finding_telemetry_resolves_db_path_once_not_per_call(monkeypatch, tmp_path):
    """Correctness finding (independent code review, 2026-09-25):
    finding_telemetry(db_path=None) called get_finding()/list_experiments()/
    count_cem_trials() each passing the ORIGINAL (still-None) db_path,
    letting each one independently re-resolve the active engagement inside
    its own case_store._get_conn() call. If the active engagement were
    switched mid-call, the three reads could silently land against two
    different engagements' case.db files for the same numeric finding_id --
    a real (if narrow) data-integrity risk, not just wrong-file-not-found.
    Fixed: resolve db_path once at the top of finding_telemetry() and pass
    the resolved value to all three case_store calls, so they agree by
    construction. Proven here by forcing resolve_db_path() to report a
    fixed path and asserting all three downstream calls receive it
    (not None, which would mean each still re-resolves independently)."""
    real_db = _db(tmp_path)
    f = case_store.create_finding("SQLi", "/api/x", db_path=real_db)

    monkeypatch.setattr(case_store, "resolve_db_path", lambda db_path=None: real_db)

    captured = {"get_finding": "unset", "list_experiments": "unset", "count_cem_trials": "unset"}
    real_get_finding = case_store.get_finding
    real_list_experiments = case_store.list_experiments
    real_count_cem_trials = case_store.count_cem_trials

    def _capturing_get_finding(finding_id, db_path=None):
        captured["get_finding"] = db_path
        return real_get_finding(finding_id, db_path=db_path)

    def _capturing_list_experiments(finding_id, db_path=None):
        captured["list_experiments"] = db_path
        return real_list_experiments(finding_id, db_path=db_path)

    def _capturing_count_cem_trials(finding_id, db_path=None):
        captured["count_cem_trials"] = db_path
        return real_count_cem_trials(finding_id, db_path=db_path)

    monkeypatch.setattr(case_store, "get_finding", _capturing_get_finding)
    monkeypatch.setattr(case_store, "list_experiments", _capturing_list_experiments)
    monkeypatch.setattr(case_store, "count_cem_trials", _capturing_count_cem_trials)

    telemetry.finding_telemetry(f["id"], db_path=None)

    assert captured == {
        "get_finding": real_db,
        "list_experiments": real_db,
        "count_cem_trials": real_db,
    }, "finding_telemetry(db_path=None) must resolve once and reuse the result -- None means each call still re-resolves independently"


# ---- P2-TEL acceptance: zero hot-path cost ------------------------------------

def test_telemetry_not_wired_into_hot_path_chokepoints():
    """P2-TEL is explicitly offline/passive (IMPLEMENTATION-TASK-TRACKER.md:
    "0 hot-path cost"). Structural proof, not just a docstring claim: neither
    real subprocess chokepoint imports or calls into this module."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for fname in ("tool_resolver.py", "job_runtime.py"):
        path = os.path.join(repo_root, "mcp-servers", fname)
        with open(path) as f:
            assert "telemetry" not in f.read(), f"{fname} must not reference telemetry.py (hot-path coupling)"
