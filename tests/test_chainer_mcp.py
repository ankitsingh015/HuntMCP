import importlib.util
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# server.py is a same-named module in every mcp-servers/*-mcp/ directory --
# load it by explicit file path under a unique module name so it can't
# collide with another test file's `import server`.
_spec = importlib.util.spec_from_file_location(
    "chainer_mcp_server", os.path.join(ROOT, "mcp-servers", "chainer-mcp", "server.py")
)
chainer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chainer)


def _findings(*classes):
    return json.dumps([{"vulnerability_class": c, "endpoint": "/x"} for c in classes])


def test_analyze_chains_matches_multi_word_template():
    # sqli_xss_stored requires ["SQL Injection", "XSS"] -- both multi-word/
    # mixed-case in CHAIN_TEMPLATES. This used to never match because the
    # comparison diffed the raw (mixed-case) required set against an
    # uppercased finding set.
    out = chainer.analyze_chains(_findings("SQL Injection", "XSS"))
    assert "sqli_xss_stored" in out
    assert "No multi-step chains possible" not in out


def test_analyze_chains_matches_single_word_template():
    out = chainer.analyze_chains(_findings("IDOR", "XSS"))
    assert "idor_xss_ato" in out


def test_analyze_chains_no_match_reports_individual_findings():
    # CSRF alone doesn't appear in any template's required_findings.
    out = chainer.analyze_chains(_findings("CSRF"))
    assert "No multi-step chains possible" in out
    assert "CSRF" in out


def test_plan_chain_no_missing_findings_when_present():
    out = chainer.plan_chain("graphql_batching_idor", _findings("GraphQL", "IDOR"))
    assert "All required findings present" in out
    assert "Missing required finding" not in out


def test_plan_chain_reports_missing_in_original_casing():
    out = chainer.plan_chain("subdomain_takeover_xss", _findings("XSS"))
    assert "Missing required finding" in out
    assert "Subdomain Takeover" in out


def test_suggest_next_tool_sql_injection_branch_reachable():
    out = chainer.suggest_next_tool(_findings("SQL Injection"))
    assert "database schema" in out.lower()
