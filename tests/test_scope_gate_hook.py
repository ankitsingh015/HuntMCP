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


def test_extract_hosts_from_bash_flags_raw_curl():
    """Regression: curl had no dedicated MCP wrapper, so it was previously
    invisible to this hook entirely -- the exact bypass path an external
    curl-heavy skill library's procedures would have exploited by
    construction (see the recon-skills content review)."""
    hosts = hook._extract_hosts_from_bash("curl https://realtarget-corp.com/api")
    assert "realtarget-corp.com" in hosts


def test_extract_hosts_from_bash_flags_raw_wget():
    hosts = hook._extract_hosts_from_bash("wget https://realtarget-corp.com/file")
    assert "realtarget-corp.com" in hosts


def test_extract_hosts_from_bash_flags_curl_rl_wrapper():
    """Regression: scripts/curl-rl.sh (the 429-retry curl wrapper) must
    get identical scope treatment to raw curl -- calling it instead of
    curl must never be a way to silently skip host extraction just
    because the binary name changed."""
    hosts = hook._extract_hosts_from_bash("scripts/curl-rl.sh https://realtarget-corp.com/api")
    assert "realtarget-corp.com" in hosts


def test_extract_hosts_from_bash_curl_exempts_dev_infra():
    assert hook._extract_hosts_from_bash(
        "curl -sL https://raw.githubusercontent.com/foo/bar/main/README.md"
    ) == []


def test_extract_hosts_from_bash_curl_does_not_flag_url_path_as_a_second_host():
    """Regression: a blanket hostname regex over the whole command matches
    'file.txt' inside a URL path as if it were a second hostname. Real URL
    parsing (urlsplit) must be used so only the actual host is extracted."""
    hosts = hook._extract_hosts_from_bash(
        "curl -sL https://realtarget-corp.com/downloads/wordlist.txt"
    )
    assert hosts == ["realtarget-corp.com"]


def test_extract_hosts_from_bash_curl_does_not_flag_output_filename():
    """Regression: curl -o results.json / -d @payload.json are the single
    most common curl invocation shapes -- the bare-hostname fallback scan
    must not treat a file argument as a second host to scope-check."""
    hosts = hook._extract_hosts_from_bash("curl -o results.json https://realtarget-corp.com/data")
    assert hosts == ["realtarget-corp.com"]

    hosts = hook._extract_hosts_from_bash("curl -d @payload.json https://realtarget-corp.com/submit")
    assert hosts == ["realtarget-corp.com"]


def test_extract_hosts_from_bash_curl_exempts_attacker_origin_placeholder():
    """Regression: a CORS/CSRF PoC's -H 'Origin: https://evil.com' names the
    attacker's own probe origin, not a live target -- evil.com must not be
    treated as a second host requiring engagement.yaml scope."""
    hosts = hook._extract_hosts_from_bash(
        'curl https://realtarget-corp.com/api -H "Origin: https://evil.com"'
    )
    assert hosts == ["realtarget-corp.com"]


def test_mcp_server_name_parses_correctly():
    assert hook._mcp_server_name("mcp__httpx-mcp__screenshot_hosts") == "httpx-mcp"
    assert hook._mcp_server_name("Bash") == ""


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf scratch-test-dir/foo.txt",
        "rm foo",
        "rm",
        "/bin/rm -f x",
        "sudo rm -rf /tmp/x",
        "curl https://example.com && rm -rf data/",
        "rm -rf x; ls",
        "echo hi | rm -f x",
        "$(rm -rf x)",
    ],
)
def test_is_rm_command_detects_rm(command):
    assert hook._is_rm_command(command) is True


@pytest.mark.parametrize(
    "command",
    [
        "cat rm.log",
        "rmdir foo",
        "ls -la",
        "mv foo bar",
        'echo "do not rm this"',
        # Regression: a bare ')' from unrelated command text (e.g. a Python
        # tuple literal passed via python3 -c) must not be treated as a
        # sub-command boundary -- that would put whatever follows it into
        # its own piece and false-positive-block on an unrelated later "rm".
        "python3 -c \"print(('rm -rf x', True))\"",
        # Regression: a lone backtick from markdown inline code in a PR
        # body/commit message (e.g. `gh pr create --body "$(cat <<'EOF'
        # ... `rm -f file.txt` ... EOF)"`) must not be treated as opening a
        # command substitution -- caught this live 2026-08-26 writing this
        # very PR's own body text.
        "gh pr create --body \"See `rm -f scratch-file.txt` in the docs\"",
    ],
)
def test_is_rm_command_ignores_non_rm(command):
    assert hook._is_rm_command(command) is False


def _run_main(monkeypatch, payload):
    # scope_guard.DEFAULT_PATH is bound from HUNTMCP_ENGAGEMENT_PATH once at
    # import time (same pattern as budget_guard.MAX_CALLS), so it can't be
    # overridden per-test via env var after the fact -- tests that need a
    # real engagement.yaml instead chdir into a tmp_path containing one at
    # the literal default relative name, which open() resolves at call time.
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    return hook.main()


def test_main_blocks_rm_with_no_engagement_and_no_scope_check(monkeypatch, tmp_path):
    """rm is a blanket "never run, never ask" rule, not a scope rule -- must
    block even with no engagement.yaml and no in-scope host anywhere in the
    command, unlike every other Tier-2 check in this file which requires a
    real-looking target host to trigger at all."""
    monkeypatch.chdir(tmp_path)
    payload = {"tool_name": "Bash", "tool_input": {"command": "rm -rf scratch-test-dir/foo.txt"}}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_rm_even_with_in_scope_engagement(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "rm -rf data/engagements/realtarget-corp"}}
    assert _run_main(monkeypatch, payload) == 2


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


def test_main_blocks_raw_curl_to_out_of_scope_target(monkeypatch, tmp_path):
    """End-to-end regression for the curl bypass: previously invisible to
    this hook entirely (curl was not a Tier-2 binary), a plain curl at an
    unauthorized host must now be blocked exactly like the wrapped tools."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "curl https://someothersite.com/api"}}
    assert _run_main(monkeypatch, payload) == 2


def test_main_blocks_curl_rl_wrapper_to_out_of_scope_target(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "scripts/curl-rl.sh https://someothersite.com/api"}}
    assert _run_main(monkeypatch, payload) == 2


def test_main_curl_rl_wrapper_in_scope_enforces_budget_and_logs_audit(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    budget_calls = []
    monkeypatch.setattr(hook, "_enforce_budget", lambda name: budget_calls.append(name))
    audit_calls = []
    monkeypatch.setattr(
        hook, "_log_call",
        lambda tool, args, returncode, duration_ms, block: audit_calls.append(
            (tool, args, returncode, duration_ms, block)
        ),
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "scripts/curl-rl.sh -s https://realtarget-corp.com/api"}}
    assert _run_main(monkeypatch, payload) == 0
    assert budget_calls == ["curl-rl.sh"]
    assert audit_calls == [("curl-rl.sh", ["-s", "https://realtarget-corp.com/api"], None, 0.0, None)]


def test_main_allows_raw_curl_to_in_scope_target(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    # audit_log.LOG_PATH's no-active-engagement fallback is anchored to
    # __file__, not cwd, so it survives monkeypatch.chdir(tmp_path) -- must
    # be stubbed explicitly here or this test would append a real line to
    # the repo's own data/audit.jsonl on every test run.
    monkeypatch.setattr(hook, "_enforce_budget", lambda name: None)
    monkeypatch.setattr(hook, "_log_call", lambda *a, **k: None)
    payload = {"tool_name": "Bash", "tool_input": {"command": "curl https://realtarget-corp.com/api"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_curl_in_scope_enforces_budget_and_logs_audit(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    budget_calls = []
    monkeypatch.setattr(hook, "_enforce_budget", lambda name: budget_calls.append(name))
    audit_calls = []
    monkeypatch.setattr(
        hook, "_log_call",
        lambda tool, args, returncode, duration_ms, block: audit_calls.append(
            (tool, args, returncode, duration_ms, block)
        ),
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "curl -s https://realtarget-corp.com/api"}}
    assert _run_main(monkeypatch, payload) == 0
    assert budget_calls == ["curl"]
    assert audit_calls == [("curl", ["-s", "https://realtarget-corp.com/api"], None, 0.0, None)]


def test_main_curl_budget_exceeded_blocks(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )

    def _raise(name):
        raise hook.BudgetExceeded("500/500 Tier-2 calls used")

    monkeypatch.setattr(hook, "_enforce_budget", _raise)
    logged = []
    monkeypatch.setattr(hook, "_log_call", lambda *a, **k: logged.append(a))
    payload = {"tool_name": "Bash", "tool_input": {"command": "curl https://realtarget-corp.com/api"}}
    assert _run_main(monkeypatch, payload) == 2
    assert logged == []  # budget block happens before the audit-log call


def test_main_nmap_in_scope_does_not_double_count_budget_or_audit(monkeypatch, tmp_path):
    """Regression: nmap/nuclei/etc. already get budgeted/audited exactly
    once via their own MCP server's tool_resolver.run_tool() call -- the
    hook must not also call budget_guard/audit_log for them, or every raw-
    Bash invocation of a wrapped tool would double-count against the shared
    Tier-2 budget."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    called = []
    monkeypatch.setattr(hook, "_enforce_budget", lambda name: called.append(("budget", name)))
    monkeypatch.setattr(hook, "_log_call", lambda *a, **k: called.append(("audit", a)))
    payload = {"tool_name": "Bash", "tool_input": {"command": "nmap -p 80 realtarget-corp.com"}}
    assert _run_main(monkeypatch, payload) == 0
    assert called == []


def test_main_curl_dev_infra_host_does_not_call_budget_or_audit(monkeypatch, tmp_path):
    """A curl with no real, non-exempt host (dev-infra allowlist) has empty
    candidates and returns before ever reaching the budget/audit insertion
    point -- ordinary package-fetching curls must never count against the
    Tier-2 budget or appear in the audit trail."""
    monkeypatch.chdir(tmp_path)
    called = []
    monkeypatch.setattr(hook, "_enforce_budget", lambda name: called.append(("budget", name)))
    monkeypatch.setattr(hook, "_log_call", lambda *a, **k: called.append(("audit", a)))
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": "curl -sL https://raw.githubusercontent.com/foo/bar/main/README.md"},
    }
    assert _run_main(monkeypatch, payload) == 0
    assert called == []


def test_main_exempts_non_tier2_mcp_server(monkeypatch):
    payload = {"tool_name": "mcp__writeup-mcp__fetch_cves", "tool_input": {"keyword": "apache"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_gates_tier2_mcp_server(monkeypatch):
    payload = {"tool_name": "mcp__httpx-mcp__screenshot_hosts", "tool_input": {"domains": "realtarget-corp.com"}}
    assert _run_main(monkeypatch, payload) == 2


@pytest.mark.parametrize("tool_name", ["WebFetch", "webfetch"])
def test_main_never_gates_webfetch_regardless_of_scope_or_host(monkeypatch, tmp_path, tool_name):
    """Regression: WebFetch was briefly scope-gated the same way as Bash's
    curl/wget (2026-08-29), then reverted the same day -- its real use in
    this agent system is read-only research (CVE pages, writeups, vendor
    docs), and gating it identically to curl blocked any research URL that
    wasn't the target itself or on the dev-infra allowlist as "not in
    scope," which isn't a meaningful authorization boundary for reading a
    public webpage. WebFetch must never be blocked by this hook, with or
    without an engagement.yaml, in scope or out."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": tool_name, "tool_input": {"url": "https://someothersite.com/page"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_never_gates_webfetch_with_no_engagement_at_all(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no engagement.yaml -- must not matter for WebFetch
    payload = {"tool_name": "WebFetch", "tool_input": {"url": "https://someothersite.com/page"}}
    assert _run_main(monkeypatch, payload) == 0


def test_main_fails_open_on_malformed_json(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert hook.main() == 0


@pytest.mark.parametrize("tool_name", ["Read", "Write", "Grep"])
def test_main_ignores_non_bash_non_mcp_tools(monkeypatch, tool_name):
    payload = {"tool_name": tool_name, "tool_input": {"file_path": "/tmp/whatever.com"}}
    assert _run_main(monkeypatch, payload) == 0
