import json
import os

from tool_resolver import classify_block, resolve_tool, run_tool


def test_classify_block_none_on_clean_output():
    assert classify_block("200 OK, 3 endpoints found") is None


def test_classify_block_none_on_empty():
    assert classify_block("") is None
    assert classify_block(None) is None


def test_classify_block_rate_limit_status_code():
    assert classify_block("HTTP/1.1 429 Too Many Requests") == "rate_limit"


def test_classify_block_rate_limit_text():
    assert classify_block("error: rate limit exceeded, slow down") == "rate_limit"


def test_classify_block_rate_limit_retry_after_header():
    """Regression: a real engagement's API rate-limiter signaled via a
    Retry-After-shaped response rather than the literal string "429" or
    "rate limit" -- must still classify as rate_limit, not fall through
    to None."""
    assert classify_block("HTTP/1.1 200 OK\nRetry-After: 30") == "rate_limit"


def test_classify_block_rate_limit_try_again_later():
    assert classify_block('{"error": "try again later"}') == "rate_limit"


def test_classify_block_rate_limit_try_again_in_n():
    assert classify_block('{"error": "try again in 30 seconds"}') == "rate_limit"


def test_classify_block_waf_cloudflare():
    assert classify_block("403 Forbidden - cloudflare ray id: abc123") == "waf"


def test_classify_block_waf_generic_block_page():
    assert classify_block("Request blocked by security policy") == "waf"


def test_classify_block_403_alone_is_not_automatically_waf():
    # a bare 403 with no block-page signature shouldn't be misclassified --
    # only 403 co-occurring with forbidden/blocked text counts
    assert classify_block("HTTP 403") is None


def test_resolve_tool_finds_something_on_path():
    # python3 is guaranteed present in the test environment
    resolved = resolve_tool("python3")
    assert resolved.endswith("python3")


def test_resolve_tool_falls_back_to_bare_name_when_not_found():
    resolved = resolve_tool("definitely-not-a-real-binary-xyz123")
    assert resolved == "definitely-not-a-real-binary-xyz123"


# ---------------------------------------------------------------------------
# S3: run_tool()'s subprocess must not inherit arbitrary secrets sitting in
# this process's own os.environ -- none of subfinder/httpx/nuclei/curl/etc.
# need any HuntMCP credential to do their job, and subprocess.run() inherits
# the FULL parent environment by default unless env= is passed explicitly.
# ---------------------------------------------------------------------------

def _dump_env_result(monkeypatch, extra_env: dict[str, str] | None = None):
    monkeypatch.setattr("tool_resolver._enforce_budget", lambda name: None)
    monkeypatch.setattr("tool_resolver._log_call", lambda *a, **k: None)
    for k, v in (extra_env or {}).items():
        monkeypatch.setenv(k, v)
    result = run_tool(
        "python3",
        ["-c", "import json, os, sys; json.dump(dict(os.environ), sys.stdout)"],
        retry_on_rate_limit=False,
    )
    assert result.returncode == 0
    return json.loads(result.stdout)


def test_run_tool_subprocess_does_not_inherit_secret_env_vars(monkeypatch):
    """The core guarantee: a credential present in THIS process's os.environ
    (e.g. because some earlier code called dotenv_loader.get_secret() and
    happened to be inspecting it, or a real key is exported in the
    operator's shell) must not silently flow into an external tool binary
    that never asked for it."""
    child_env = _dump_env_result(monkeypatch, {"HUNTMCP_TEST_FAKE_SECRET": "super-secret-value"})
    assert "HUNTMCP_TEST_FAKE_SECRET" not in child_env


def test_run_tool_subprocess_still_has_path():
    """Sanity check that the environment scrub isn't so aggressive the
    child can't function -- PATH must survive, or resolve_tool()'s own
    binary resolution and the tool's own internal exec calls would break."""
    result = run_tool(
        "python3",
        ["-c", "import os, sys; sys.stdout.write(os.environ.get('PATH', ''))"],
        retry_on_rate_limit=False,
    )
    assert result.stdout.strip() != ""


def test_run_tool_respects_explicit_env_override(monkeypatch):
    """A caller that explicitly passes env= (e.g. a future tool-specific
    need) must still be able to -- the new default must use setdefault,
    not clobber an explicit override, matching every other kwarg this
    function already defaults (capture_output, text, stdin)."""
    monkeypatch.setattr("tool_resolver._enforce_budget", lambda name: None)
    monkeypatch.setattr("tool_resolver._log_call", lambda *a, **k: None)
    result = run_tool(
        "python3",
        ["-c", "import os, sys; sys.stdout.write(os.environ.get('HUNTMCP_EXPLICIT_OVERRIDE', 'MISSING'))"],
        retry_on_rate_limit=False,
        env={"HUNTMCP_EXPLICIT_OVERRIDE": "present", "PATH": os.environ["PATH"]},
    )
    assert result.stdout.strip() == "present"
