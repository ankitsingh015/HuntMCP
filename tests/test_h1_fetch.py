"""Offline unit tests for writeup-mcp's h1_fetch module.

No network: fetch_report() is not exercised here -- only the pure parsing /
markdown-building / idempotence helpers, using a captured report fixture.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(__file__)
MOD = os.path.join(HERE, "..", "mcp-servers", "writeup-mcp", "h1_fetch.py")

spec = importlib.util.spec_from_file_location("h1_fetch", MOD)
h1 = importlib.util.module_from_spec(spec)
sys.modules["h1_fetch"] = h1
spec.loader.exec_module(h1)


def _report(visibility_body: str, **kw):
    d = {
        "id": 526325,
        "title": "Stored XSS in Wiki pages",
        "vulnerability_information": visibility_body,
        "weakness": {"id": 62, "name": "Cross-site Scripting (XSS) - Stored"},
        "team": {"handle": "gitlab", "profile": {"name": "GitLab"}},
        "bounty_amount": "3500.0",
        "vote_count": 629,
        "severity_rating": "high",
        "cve_ids": ["CVE-2019-5467"],
        "summaries": [{"category": "team", "content": "team summary text"}],
    }
    d.update(kw)
    return d


def test_report_id_parsing():
    assert h1.report_id("510152") == 510152
    assert h1.report_id("https://hackerone.com/reports/488147") == 488147
    assert h1.report_id("https://hackerone.com/reports/510152.json") == 510152
    assert h1.report_id("not-a-report") is None


def test_full_body_is_used():
    fname, md, quality = h1.report_to_markdown(_report("### Summary\nThe real body"))
    assert quality == "full"
    assert "The real body" in md
    assert "team summary text" not in md
    assert fname.startswith("h1-cross-site-scripting-xss-store-526325-")
    assert fname.endswith(".md")


def test_summary_fallback_when_no_content():
    _fname, md, quality = h1.report_to_markdown(_report(""))
    assert quality == "summary-only"
    assert "team summary text" in md


def test_frontmatter_fields():
    _, md, _ = h1.report_to_markdown(_report("body"))
    assert "url: \"https://hackerone.com/reports/526325\"" in md
    assert "bounty: 3500" in md
    assert 'content_quality: "full"' in md
    assert "CVE-2019-5467" in md


def test_metadata_only_when_truly_empty():
    d = _report("", summaries=[])
    _, md, quality = h1.report_to_markdown(d)
    assert quality == "summary-only"
    assert "no public content" in md


def test_slug_is_filesystem_safe():
    s = h1._slug("Cross-site Scripting (XSS) - Stored / ../etc")
    assert "/" not in s and " " not in s and ".." not in s
