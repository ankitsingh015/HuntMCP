"""Regression test for watch-mcp's scope-check exemption gap.

Bug found live (2026-09-01, MCP full-coverage testing pass): _scope_error()
called load_engagement() directly without first checking is_safe_test_host(),
unlike every other Tier-2 tool (scope_gate_hook.py's check_scope flow) --
watch-mcp was the only tool that couldn't be used against example.com/
localhost/etc. without a real engagement.yaml on disk.
"""
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "watch_mcp_server", os.path.join(ROOT, "mcp-servers", "watch-mcp", "server.py"),
)
watch_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(watch_server)


def test_safe_test_host_exempt_even_with_no_engagement_file(monkeypatch, tmp_path):
    # No engagement.yaml anywhere reachable -- point HUNTMCP_ENGAGEMENT_PATH
    # at a path that can never exist, so this test can't accidentally pass
    # by reading a real engagement.yaml lying around in the repo/cwd.
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(tmp_path / "nope.yaml"))
    assert watch_server._scope_error("example.com") is None
    assert watch_server._scope_error("localhost") is None
    assert watch_server._scope_error("127.0.0.1") is None


def test_real_target_still_blocked_with_no_engagement_file(monkeypatch, tmp_path):
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(tmp_path / "nope.yaml"))
    err = watch_server._scope_error("realtarget-corp.com")
    assert err is not None
    assert "BLOCKED" in err


def test_real_target_allowed_when_in_scope(monkeypatch, tmp_path):
    eng_path = tmp_path / "engagement.yaml"
    eng_path.write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng_path))
    assert watch_server._scope_error("realtarget-corp.com") is None


def test_real_target_blocked_when_out_of_scope(monkeypatch, tmp_path):
    eng_path = tmp_path / "engagement.yaml"
    eng_path.write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    monkeypatch.setenv("HUNTMCP_ENGAGEMENT_PATH", str(eng_path))
    err = watch_server._scope_error("someothersite.com")
    assert err is not None
    assert "BLOCKED" in err
