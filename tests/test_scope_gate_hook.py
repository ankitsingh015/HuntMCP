import io
import json

import pytest
import scope_gate_hook as hook


def test_safe_test_host_recognized():
    assert hook._is_safe_test_host("example.com") is True
    assert hook._is_safe_test_host("localhost") is True
    assert hook._is_safe_test_host("127.0.0.1") is True
    assert hook._is_safe_test_host("evil-target.com") is False


def test_safe_test_host_private_ip_ranges():
    assert hook._is_safe_test_host("192.168.1.1") is True
    assert hook._is_safe_test_host("10.0.0.5") is True
    assert hook._is_safe_test_host("8.8.8.8") is False


def test_extract_hosts_from_bash_ignores_non_tier2_binary():
    assert hook._extract_hosts_from_bash("go install github.com/foo/bar@latest") == []


def test_extract_hosts_from_bash_flags_tier2_binary():
    hosts = hook._extract_hosts_from_bash("subfinder -d realtarget-corp.com -silent")
    assert "realtarget-corp.com" in hosts


def test_extract_hosts_from_bash_exempts_safe_hosts():
    assert hook._extract_hosts_from_bash("subfinder -d example.com") == []


def test_extract_hosts_from_tool_input_known_keys():
    hosts = hook._extract_hosts_from_tool_input({"domains": "realtarget-corp.com,example.com"})
    assert hosts == ["realtarget-corp.com"]


def test_extract_hosts_from_tool_input_ignores_unknown_keys():
    assert hook._extract_hosts_from_tool_input({"keyword": "apache.example.com"}) == []


def test_mcp_server_name_parses_correctly():
    assert hook._mcp_server_name("mcp__httpx-mcp__screenshot_hosts") == "httpx-mcp"
    assert hook._mcp_server_name("Bash") == ""


def _run_main(monkeypatch, payload):
    # scope_guard.DEFAULT_PATH is bound from HUNTMCP_ENGAGEMENT_PATH once at
    # import time (same pattern as budget_guard.MAX_CALLS), so it can't be
    # overridden per-test via env var after the fact -- tests that need a
    # real engagement.yaml instead chdir into a tmp_path containing one at
    # the literal default relative name, which open() resolves at call time.
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    return hook.main()


def test_main_allows_plain_bash(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no engagement.yaml here -- must not matter for a plain command
    assert _run_main(monkeypatch, {"tool_name": "Bash", "tool_input": {"command": "git status"}}) == 0


def test_main_allows_safe_host_with_no_engagement(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    payload = {"tool_name": "Bash", "tool_input": {"command": "subfinder -d example.com"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_real_target_with_no_engagement(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    payload = {"tool_name": "Bash", "tool_input": {"command": "subfinder -d realtarget-corp.com"}}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_in_scope_target(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "nuclei -u realtarget-corp.com"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_blocks_out_of_scope_target(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "nuclei -u someothersite.com"}}
    assert _run_main(monkeypatch, payload) == 2


def test_main_exempts_non_tier2_mcp_server(monkeypatch):
    payload = {"tool_name": "mcp__writeup-mcp__fetch_cves", "tool_input": {"keyword": "apache"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_gates_tier2_mcp_server(monkeypatch):
    payload = {"tool_name": "mcp__httpx-mcp__screenshot_hosts", "tool_input": {"domains": "realtarget-corp.com"}}
    assert _run_main(monkeypatch, payload) == 2


def test_main_fails_open_on_malformed_json(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert hook.main() == 0


@pytest.mark.parametrize("tool_name", ["Read", "Write", "Grep"])
def test_main_ignores_non_bash_non_mcp_tools(monkeypatch, tool_name):
    payload = {"tool_name": tool_name, "tool_input": {"file_path": "/tmp/whatever.com"}}
    assert _run_main(monkeypatch, payload) == 0
