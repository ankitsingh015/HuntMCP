import io
import json

import engagement_paths
import pytest
import scope_gate_hook as hook


@pytest.fixture(autouse=True)
def _isolated_active_engagement(monkeypatch, tmp_path):
    """Every test in this file must be isolated from whatever real
    engagement (if any) is actually active in this repo right now.
    scope_guard/budget_guard/audit_log/etc. correctly follow WHICHEVER
    engagement is currently active (by design -- confirmed live: a real
    active engagement correctly overrides a test's own chdir()'d
    engagement.yaml, exactly as intended). That means a stale
    data/.active-engagement pointer left behind by a real audit would
    otherwise silently make every "in scope" test below see the wrong
    engagement instead of the one it writes into its own tmp_path --
    this is exactly what caused this file's 5 hardest-to-diagnose
    failures (2026-08-31): they looked like "no engagement.yaml found"
    but were actually "found the WRONG one, frozen in from whatever was
    active when this module first imported." Point ACTIVE_POINTER at a
    path inside this test's own tmp_path that deliberately never has a
    file written to it, so every test here starts from a guaranteed
    "no active engagement" regardless of real repo state."""
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(tmp_path / ".not-really-active"))


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


@pytest.mark.parametrize(
    "command",
    [
        "cat .env",
        "cat ./.env",
        "head -5 .env",
        "cat /home/ankit/HuntMCP/.env",
        "grep TOKEN .env",
        "less .env",
        "curl https://example.com && cat .env",
        "cat .env; ls",
        "echo hi | cat .env",
        # Regressions (code-review findings, CONFIRMED) -- found live,
        # none require adversarial cleverness:
        "echo $(cat .env)",  # ordinary command substitution, not evasion
        "echo $(head -c 100 .env)",
        "cp .env /tmp/x",  # stages exfiltration without an interpreter
        "mv .env /tmp/x",
        "sudo env cat .env",  # doubled sudo/env prefix
    ],
)
def test_reads_env_file_detects_direct_reads(command):
    assert hook._reads_env_file(command) is True


@pytest.mark.parametrize(
    "command",
    [
        "cat .env.example",  # documented, no real secrets, must stay readable
        "cat .envrc",  # a different tool's file, not this repo's secrets
        "cat keys.env",  # a differently-named file, not the real .env
        "ls -la",
        "echo hello",
        'echo "the file is called .env"',  # a string mentioning it, not a read
        "cp keys.env /tmp/x",  # differently-named file through a now-gated command
        "cp .env.example /tmp/x",  # documented file, no real secrets
        "mv notes.txt archive/",
    ],
)
def test_reads_env_file_ignores_non_matches(command):
    assert hook._reads_env_file(command) is False


def test_reads_env_file_ignores_prose_mentioning_env_in_a_heredoc():
    """Regression: found live writing this very fix's own commit message.
    git commit -m "$(cat <<'EOF' ... EOF)" is a common pattern in this
    repo's own workflow (see .claude/skills instructions for git commits);
    _CHAIN_SPLIT_RE splits on newlines, so a heredoc's multi-line PROSE
    BODY gets torn into one piece per line -- a documentation line that
    merely mentions ".env" as a word (not an actual file read) must not
    trip this, the same way _is_rm_command's own first-word-only check
    already protects against prose mentioning "rm"."""
    command = (
        "git commit -m \"$(cat <<'EOF'\n"
        "fix: scope secrets out of untrusted execution\n"
        "\n"
        "dotenv_loader.load_dotenv_if_present() dumped every key in .env into\n"
        "the process environment. Replaced with get_secret(), which falls\n"
        "back to .env only for the one requested key.\n"
        "EOF\n"
        ")\""
    )
    assert hook._reads_env_file(command) is False


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


def test_main_blocks_env_file_read_with_no_engagement_and_no_scope_check(monkeypatch, tmp_path, capsys):
    """S3 (secrets scoped out of untrusted execution): reading .env
    directly is a blanket 'never run, never ask' rule, same category as
    the rm-block above -- must block even with no engagement.yaml and no
    in-scope host anywhere in the command."""
    monkeypatch.chdir(tmp_path)
    payload = {"tool_name": "Bash", "tool_input": {"command": "cat .env"}}
    assert _run_main(monkeypatch, payload) == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_main_blocks_env_file_read_even_with_in_scope_engagement(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )
    payload = {"tool_name": "Bash", "tool_input": {"command": "cat .env"}}
    assert _run_main(monkeypatch, payload) == 2


def test_main_allows_reading_env_example_file(monkeypatch, tmp_path):
    """Regression: .env.example is documented, contains no real secrets,
    and is referenced by name elsewhere in this codebase -- must stay
    readable, not swept up by the .env block."""
    monkeypatch.chdir(tmp_path)
    payload = {"tool_name": "Bash", "tool_input": {"command": "cat .env.example"}}
    assert _run_main(monkeypatch, payload) == 0


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


def test_main_gates_obscura_mcp(monkeypatch):
    # Regression: obscura-mcp touches the live target the same way
    # browser-mcp/playwright-mcp already do (browser_navigate(url) etc.),
    # so it must get the identical structural scope-gate, not just the
    # documented-convention one.
    payload = {"tool_name": "mcp__obscura-mcp__browser_navigate", "tool_input": {"url": "https://realtarget-corp.com"}}
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


def test_main_fails_closed_on_malformed_json(monkeypatch, capsys):
    """S1 (fail-closed): malformed stdin means this hook cannot determine
    which tool call it's guarding -- it might be a Tier-2 target-touching
    call this hook exists to block. Contract change from the prior
    fail-open behavior (see MASTER-ROADMAP-FINAL-v3.md / IMPLEMENTATION-
    TASK-TRACKER.md S1): 'internal error blocks the gated call, not the
    session' -- this blocks only the one tool call the hook was invoked
    for (exit 2, with a clear stderr reason), it does not crash or hang
    the session. In real operation Claude Code/OpenCode always construct
    this payload themselves as well-formed JSON, so this path is not
    expected to fire on ordinary Read/Edit/git-status traffic -- it exists
    for the tamper/corruption/hook-invocation-bug case, where failing
    closed is the safe default."""
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert hook.main() == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_main_fails_closed_on_malformed_engagement_yaml(monkeypatch, tmp_path, capsys):
    """S1 (fail-closed): engagement.yaml exists but is not valid YAML --
    load_engagement() raises yaml.YAMLError, which is neither
    NoEngagementFile nor RuntimeError. This must not propagate as an
    uncaught exception (which would fail open on this harness's exit-code
    contract, since only exit 2 is recognized as a block) -- it must
    deterministically block the Tier-2 call that triggered it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text("target: [this is not: valid: yaml")
    payload = {"tool_name": "Bash", "tool_input": {"command": "nuclei -u realtarget-corp.com"}}
    assert _run_main(monkeypatch, payload) == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_main_fails_closed_on_unexpected_error_during_scope_check(monkeypatch, tmp_path, capsys):
    """S1 (fail-closed): any unexpected exception raised while evaluating
    an already-identified Tier-2 candidate (here, is_in_scope itself)
    must block that call, not silently let it through via an uncaught
    exception."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagement.yaml").write_text(
        "target: realtarget-corp.com\nin_scope:\n  - realtarget-corp.com\nout_of_scope: []\n"
    )

    def _boom(host, engagement):
        raise ValueError("simulated internal scope-check failure")

    monkeypatch.setattr(hook, "is_in_scope", _boom)
    payload = {"tool_name": "Bash", "tool_input": {"command": "nuclei -u realtarget-corp.com"}}
    assert _run_main(monkeypatch, payload) == 2
    assert "BLOCKED" in capsys.readouterr().err


@pytest.mark.parametrize("tool_name", ["Read", "Write", "Grep"])
def test_main_ignores_non_bash_non_mcp_tools(monkeypatch, tool_name):
    payload = {"tool_name": tool_name, "tool_input": {"file_path": "/tmp/whatever.com"}}
    assert _run_main(monkeypatch, payload) == 0


# S1 follow-up (code-review finding, CONFIRMED): the malformed-JSON fix above
# only covers JSON that fails to *parse*. Syntactically valid JSON with the
# wrong *shape* (a bare `null`/list/string at the top level, a non-string
# tool_name, a non-dict tool_input, a non-string command on a Bash call)
# reached past the new try/except entirely and crashed with an uncaught
# AttributeError/TypeError -- exit code 1, which both real callers
# (.claude/settings.json's PreToolUse dispatch and .opencode/plugin/
# scope-gate.ts) treat as an implicit allow. Verified live before this fix:
# `echo 'null' | python3 scripts/hooks/scope_gate_hook.py` exited 1 with an
# unhandled traceback. These tests close that gap without widening the gate
# to non-Tier2 tools -- a malformed tool_input on a definitely-non-Tier2
# tool_name (see test_main_ignores_malformed_tool_input_on_non_tier2_tool
# below) must still pass straight through, since tool_input is never even
# inspected until tool_name is confirmed to be Bash or mcp__*.


@pytest.mark.parametrize("raw_stdin", ["null", "[1, 2, 3]", '"just a string"', "42"])
def test_main_fails_closed_on_non_object_json_payload(monkeypatch, capsys, raw_stdin):
    monkeypatch.setattr("sys.stdin", io.StringIO(raw_stdin))
    assert hook.main() == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_main_fails_closed_on_non_string_tool_name(monkeypatch, capsys):
    payload = {"tool_name": None, "tool_input": {"command": "curl https://realtarget-corp.com"}}
    assert _run_main(monkeypatch, payload) == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_main_fails_closed_on_non_dict_tool_input_for_bash(monkeypatch, capsys):
    payload = {"tool_name": "Bash", "tool_input": "not-a-dict"}
    assert _run_main(monkeypatch, payload) == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_main_fails_closed_on_non_dict_tool_input_for_tier2_mcp(monkeypatch, capsys):
    payload = {"tool_name": "mcp__httpx-mcp__screenshot_hosts", "tool_input": ["not", "a", "dict"]}
    assert _run_main(monkeypatch, payload) == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_main_fails_closed_on_non_string_command_for_bash(monkeypatch, capsys):
    """Regression for the exact crash found live: {"command": 123} used to
    raise TypeError inside _is_rm_command's regex .split() call, uncaught,
    exit code 1 -- defeating both the rm-block and the scope gate for this
    call shape."""
    payload = {"tool_name": "Bash", "tool_input": {"command": 123}}
    assert _run_main(monkeypatch, payload) == 2
    assert "BLOCKED" in capsys.readouterr().err


@pytest.mark.parametrize("tool_name", ["Read", "Write", "Grep", "WebFetch"])
def test_main_ignores_malformed_tool_input_on_non_tier2_tool(monkeypatch, tool_name):
    """Narrow-boundary regression: tool_name is checked BEFORE tool_input is
    ever inspected, so a definitely-non-Tier2 tool with a garbage tool_input
    shape must still pass straight through -- the fail-closed net for
    payload shape must not widen the gate to tools this hook never gated."""
    payload = {"tool_name": tool_name, "tool_input": "totally-not-a-dict"}
    assert _run_main(monkeypatch, payload) == 0
