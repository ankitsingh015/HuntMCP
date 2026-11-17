"""Offline unit tests for writeup-mcp's hexbrain_fetch module.

No network: the pure parsing / markdown-building / sync helpers are exercised
with injected fakes, mirroring test_h1_fetch.py.
"""
import importlib.util
import os
import sys

import yaml

HERE = os.path.dirname(__file__)
MOD = os.path.join(HERE, "..", "mcp-servers", "writeup-mcp", "hexbrain_fetch.py")

spec = importlib.util.spec_from_file_location("hexbrain_fetch", MOD)
hb = importlib.util.module_from_spec(spec)
sys.modules["hexbrain_fetch"] = hb
spec.loader.exec_module(hb)


# --- Task 1: report-id listing ------------------------------------------

def test_list_report_ids_extracts_from_sitemap():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://hexbrainai.com/report/341876</loc></url>"
        "<url><loc>https://hexbrainai.com/report/1067443</loc></url>"
        "<url><loc>https://hexbrainai.com/about</loc></url>"
        "</urlset>"
    )
    assert hb.list_report_ids(xml) == [341876, 1067443]


def test_list_report_ids_ignores_garbage():
    assert hb.list_report_ids("<<<not xml at all >>> /report/ nope") == []


def test_list_report_ids_matches_hackerone_reports_plural():
    # the Atom feed may link to hackerone.com/reports/<id> (plural) instead of
    # HexBrain's /report/<id> -- both must be extracted
    xml = "<feed><entry><link href='https://hackerone.com/reports/341876'/></entry></feed>"
    assert hb.list_report_ids(xml) == [341876]


def test_to_writeup_md_escapes_url():
    # a malformed Original value with a quote must not corrupt the YAML
    raw = '# T\n\n- Original: https://x/"evil\n- Class: XSS\n\n## S\n\nbody\n'
    _fname, text = hb.to_writeup_md(raw, 5)
    fm = yaml.safe_load(text.split("---\n", 2)[1])  # must parse, not raise
    assert fm["url"] == 'https://x/"evil'


# --- Task 2: map one HexBrain .md to our writeup frontmatter -------------

_RAW = """# SSRF in Exchange leads to ROOT access in all instances

- Report: #341876
- Original: https://hackerone.com/reports/341876
- Program: Shopify
- Weakness: Server-Side Request Forgery (SSRF)
- Class: Server-Side Request Forgery
- Severity: medium
- Disclosed: 2018-05-23

## Summary

The screenshot service fetched attacker-controlled URLs.
"""


def test_to_writeup_md_maps_header():
    fname, text = hb.to_writeup_md(_RAW, 341876)
    assert text.startswith("---\n")
    assert "title: " in text
    assert 'url: "https://hackerone.com/reports/341876"' in text
    assert 'vuln_class: "Server-Side Request Forgery"' in text
    assert 'program: "Shopify"' in text
    assert fname.startswith("hexbrain-") and "341876" in fname
    # body preserved after frontmatter
    assert "screenshot service fetched" in text


def test_to_writeup_md_missing_class_falls_back():
    raw = "# Some bug\n\n- Program: Acme\n\n## Summary\n\nbody\n"
    fname, text = hb.to_writeup_md(raw, 999)
    assert 'vuln_class: "unknown"' in text
    assert 'url: "https://hackerone.com/reports/999"' in text


def test_to_writeup_md_caps_body():
    raw = "# T\n\n- Class: XSS\n\n## Summary\n\n" + ("A" * 5000)
    fname, text = hb.to_writeup_md(raw, 1, max_body=100)
    # body portion (after the closing frontmatter fence) is capped
    body = text.split("---\n\n", 1)[1]
    assert len(body) <= 120  # 100 cap + small slack for a trailing newline


# --- Task 3: resumable, throttled sync driver ---------------------------

def _fake_raw(rid):
    return f"# Report {rid}\n\n- Class: XSS\n\n## Summary\n\nbody {rid}\n"


def test_sync_writes_and_is_idempotent(tmp_path):
    wd = str(tmp_path)
    res = hb.sync([1, 2], wd, fetch=_fake_raw, sleep_s=0)
    assert res["written"] == 2 and res["skipped"] == 0 and res["failed"] == 0
    files = sorted(p.name for p in tmp_path.glob("hexbrain-*.md"))
    assert len(files) == 2
    # rerun -> all skipped, no duplicates
    res2 = hb.sync([1, 2], wd, fetch=_fake_raw, sleep_s=0)
    assert res2["skipped"] == 2 and res2["written"] == 0
    assert len(list(tmp_path.glob("hexbrain-*.md"))) == 2


def test_sync_skips_failed(tmp_path):
    wd = str(tmp_path)

    def fetch(rid):
        return None if rid == 2 else _fake_raw(rid)

    res = hb.sync([1, 2], wd, fetch=fetch, sleep_s=0)
    assert res["written"] == 1 and res["failed"] == 1
    done = (tmp_path / ".hexbrain-done.txt").read_text()
    assert "1" in done.split() and "2" not in done.split()


# --- supersede dedup (cross-source) -------------------------------------

def test_existing_other_sources_finds_h1_not_hexbrain(tmp_path):
    (tmp_path / "h1-xss-5-old.md").write_text("x")
    (tmp_path / "hexbrain-xss-5-new.md").write_text("x")
    others = hb._existing_other_sources(str(tmp_path), 5)
    names = [os.path.basename(p) for p in others]
    assert names == ["h1-xss-5-old.md"]


def test_existing_other_sources_ignores_non_h1_user_files(tmp_path):
    # a hand-added writeup that happens to contain -5- must NOT be superseded
    (tmp_path / "custom-notes-5-analysis.md").write_text("mine")
    (tmp_path / "command-injection-example-5.md").write_text("mine")
    assert hb._existing_other_sources(str(tmp_path), 5) == []


def test_sync_supersede_removes_h1_and_clears_chunks(tmp_path):
    wd = str(tmp_path)
    (tmp_path / "h1-access-791-old.md").write_text("old h1 body")
    deleted = []
    hb.sync([791], wd, fetch=_fake_raw, sleep_s=0, supersede=True,
            chunk_deleter=lambda url: deleted.append(url))
    # old h1 file gone, new hexbrain file written
    assert not (tmp_path / "h1-access-791-old.md").exists()
    assert list(tmp_path.glob("hexbrain-*-791-*.md"))
    # chunks cleared for that report's url
    assert deleted == ["https://hackerone.com/reports/791"]


def test_sync_no_supersede_leaves_h1(tmp_path):
    wd = str(tmp_path)
    (tmp_path / "h1-access-791-old.md").write_text("old")
    hb.sync([791], wd, fetch=_fake_raw, sleep_s=0)  # supersede default off
    assert (tmp_path / "h1-access-791-old.md").exists()


# --- Task 4: embed path --------------------------------------------------

def test_embed_flag_calls_embedder(tmp_path, monkeypatch):
    wd = str(tmp_path)
    calls = []
    monkeypatch.setattr(hb, "_embedder", lambda: (lambda path: calls.append(path)))
    # first run: 2 written -> 2 embeds
    hb.sync([1, 2], wd, fetch=_fake_raw, sleep_s=0, embed=True)
    assert len(calls) == 2
    # rerun: both skipped -> no new embeds
    hb.sync([1, 2], wd, fetch=_fake_raw, sleep_s=0, embed=True)
    assert len(calls) == 2
