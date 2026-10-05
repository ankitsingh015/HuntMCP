import json
import os

import capability_utilization


def _audit_log(tmp_path, entries):
    path = str(tmp_path / "audit.jsonl")
    with open(path, "w") as f:
        f.writelines(json.dumps(e) + "\n" for e in entries)
    return path


def test_compute_utilization_reports_call_count_per_known_tool(tmp_path):
    path = _audit_log(tmp_path, [
        {"tool": "nuclei", "duration_ms": 100},
        {"tool": "nuclei", "duration_ms": 50},
        {"tool": "sqlmap", "duration_ms": 200},
    ])
    report = capability_utilization.compute_utilization(audit_log_path=path)
    assert report["by_tool"]["nuclei"] == 2
    assert report["by_tool"]["sqlmap"] == 1


def test_compute_utilization_includes_never_called_known_tools_at_zero(tmp_path):
    path = _audit_log(tmp_path, [{"tool": "nuclei", "duration_ms": 1}])
    report = capability_utilization.compute_utilization(audit_log_path=path)
    assert report["by_tool"]["dalfox"] == 0
    assert "dalfox" in report["never_used"]
    assert "nuclei" not in report["never_used"]


def test_compute_utilization_known_tools_matches_sandbox_runner_tool_map(tmp_path):
    """Reuses sandbox_runner._TOOL_MAP as the canonical known-tool inventory
    rather than a separately hand-maintained list, so the two never drift."""
    path = _audit_log(tmp_path, [])
    report = capability_utilization.compute_utilization(audit_log_path=path)
    import sandbox_runner
    assert set(report["by_tool"].keys()) == set(sandbox_runner._TOOL_MAP.keys())


def test_compute_utilization_ignores_a_tool_not_in_the_known_inventory(tmp_path):
    """A call for a tool name outside _TOOL_MAP (e.g. a future addition not
    yet registered there) is reported separately, not silently dropped and
    not silently added to the known-tool inventory either."""
    path = _audit_log(tmp_path, [{"tool": "some-future-tool", "duration_ms": 5}])
    report = capability_utilization.compute_utilization(audit_log_path=path)
    assert "some-future-tool" not in report["by_tool"]
    assert report["unregistered_tools_seen"] == {"some-future-tool": 1}


def test_compute_utilization_missing_audit_log_reports_all_known_tools_never_used(tmp_path):
    path = str(tmp_path / "does-not-exist.jsonl")
    report = capability_utilization.compute_utilization(audit_log_path=path)
    assert all(count == 0 for count in report["by_tool"].values())
    assert set(report["never_used"]) == set(report["by_tool"].keys())


def test_capability_utilization_module_is_offline_read_only():
    """Same structural no-write/no-tool-call proof as every other P2 signal
    module in this repo -- this must never call a tool or mutate state."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "mcp-servers", "capability_utilization.py")
    with open(path) as f:
        src = f.read()
    if src.lstrip().startswith('"""'):
        first = src.index('"""')
        second = src.index('"""', first + 3)
        src = src[second + 3:]
    forbidden = ["tool_resolver", "job_runtime", "subprocess", "Popen", "scope_guard", "budget_guard"]
    for name in forbidden:
        assert name not in src, f"capability_utilization.py must not reference {name!r}"
