from tool_resolver import classify_block, resolve_tool


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
