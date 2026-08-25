import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "waf_bypass_mcp_server", os.path.join(ROOT, "mcp-servers", "waf-bypass-mcp", "server.py")
)
waf_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(waf_server)


def test_percent_encode_all():
    # Every character gets encoded, not just special ones -- that's what
    # "encode all" means (distinct from a normal URL-encode that leaves
    # alphanumerics alone).
    assert waf_server._percent_encode_all("' OR 1=1") == "%27%20%4F%52%20%31%3D%31"


def test_double_percent_encode():
    once = waf_server._percent_encode_all("<")
    twice = waf_server._double_percent_encode("<")
    assert once == "%3C"
    assert twice == "%253C"


def test_html_entity_encode_hex_and_decimal():
    assert waf_server._html_entity_encode("<", hex_form=True) == "&#x3c;"
    assert waf_server._html_entity_encode("<", hex_form=False) == "&#60;"


def test_overlong_utf8_only_documented_chars():
    out = waf_server._overlong_utf8("/admin/../x")
    # ".." is two dots, each replaced independently.
    assert out == "%c0%afadmin%c0%af%c0%ae%c0%ae%c0%afx"


def test_whitespace_variants_empty_when_no_space():
    assert waf_server._whitespace_variants("noSpacesHere") == {}


def test_whitespace_variants_replaces_every_space():
    variants = waf_server._whitespace_variants("UNION SELECT")
    assert variants["whitespace -> %09 (tab)"] == "UNION%09SELECT"
    assert variants["whitespace -> /**/ (SQL comment)"] == "UNION/**/SELECT"


def test_mixed_case_keywords_only_matches_whole_words():
    # "OR" must not match inside "FORMULA", "AND" must not match inside
    # "SANDBOX" -- this was a real bug caught before landing: the first
    # draft used re.escape(kw) with no \b word boundaries.
    out = waf_server._mixed_case_keywords("formula and sandbox")
    assert "formula" in out
    assert "sandbox" in out
    # "and" (the real standalone keyword) should have been mixed-case.
    assert " and " not in out


def test_mixed_case_keywords_mutates_real_keyword():
    out = waf_server._mixed_case_keywords("1 OR 1=1")
    assert out != "1 OR 1=1"
    assert out.upper() == "1 OR 1=1"


def test_sql_comment_split_only_matches_whole_words():
    out = waf_server._sql_comment_split("formula and sandbox")
    # "formula"/"sandbox" must survive untouched; only the standalone "and"
    # in between gets a comment spliced into it.
    assert out == "formula a/**/nd sandbox"


def test_sql_comment_split_inserts_comment_mid_keyword():
    out = waf_server._sql_comment_split("UNION SELECT")
    assert "/**/" in out
    assert out.replace("/**/", "") == "UNION SELECT"


def test_js_hex_escape():
    assert waf_server._js_hex_escape("<a>") == "\\x3c\\x61\\x3e"


def test_js_hex_escape_non_bmp_uses_codepoint_form():
    # \uXXXX is only valid JS syntax for exactly 4 hex digits (the BMP). A
    # codepoint above 0xFFFF (e.g. an emoji) used to emit ὠ0 (5
    # digits) -- not valid JS. Must use the \u{...} codepoint form instead.
    out = waf_server._js_hex_escape("\U0001F600")
    assert out == "\\u{1f600}"
    assert "\\u1f600" not in out


def test_detect_context_sql():
    assert waf_server._detect_context("' UNION SELECT username,password FROM users--") == "sql"


def test_detect_context_does_not_false_positive_on_substring():
    # "california" contains "or" as a substring ("calif-OR-nia") -- must
    # not be misdetected as SQL context.
    assert waf_server._detect_context("search=california") == "generic"


def test_detect_context_xss_marker_word_boundary():
    # "onload"/"onclick" embedded inside an unrelated longer word (no word
    # boundary around them) must not trigger a false-positive XSS-context
    # detection on a SQL-only payload. (A LIKE '%onload%' pattern is a
    # different case -- "onload" there genuinely is a bounded standalone
    # word since '%' isn't a word character, so it's not something word-
    # boundary matching fixes or should fix.)
    assert waf_server._detect_context("SELECT * FROM sales WHERE region='salonload'") == "sql"
    assert waf_server._detect_context("1; SELECT pg_sleep(5) -- econclick") == "sql"


def test_detect_context_xss():
    assert waf_server._detect_context("<script>alert(1)</script>") == "xss"


def test_detect_context_both():
    assert waf_server._detect_context("' UNION SELECT '<script>alert(1)</script>'--") == "both"


def test_mutate_payload_empty_input():
    assert "Error" in waf_server.mutate_payload("")


def test_mutate_payload_unknown_context():
    assert "Error" in waf_server.mutate_payload("test", context="not-a-real-context")


def test_mutate_payload_includes_generic_encodings():
    out = waf_server.mutate_payload("<script>alert(1)</script>", context="xss")
    assert "percent-encode all" in out
    assert "JS hex-escape" in out


def test_mutate_payload_sql_context_includes_sql_mutations():
    out = waf_server.mutate_payload("' OR 1=1--", context="sql")
    assert "SQL mixed-case keywords" in out
    assert "SQL inline-comment split" in out
    assert "JS hex-escape" not in out
