"""#164 wiring: the page-first rules are actually in the agents that run the
engagement, and every browser-mcp tool they name really exists."""

import asyncio
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "browser-mcp"))

import server  # noqa: E402

AGENTS = os.path.join(ROOT, ".claude", "agents")
CANDIDATE_TYPES = ("stored-xss", "reflected-render", "broken-delete", "delete-leftover",
                   "delete-idor-candidate", "cancel-without-revoke-candidate", "logout-session-survives",
                   "account-deleted-session-survives", "reregistration-candidate")


def _read(name):
    with open(os.path.join(AGENTS, name)) as fh:
        return fh.read()


def _tool_names():
    return {t.name for t in asyncio.run(server.app.list_tools())}


def test_recon_agent_must_walk_before_recon_is_done():
    t = _read("recon-agent.md")
    assert "start_ui_walk" in t and "check_ui_walk" in t
    assert "not complete while an app with UI has no walk" in t
    assert "AUTH LOST" in t


def test_scan_agent_tests_walk_inventory_first():
    t = _read("scan-agent.md")
    assert "UI-walk inventory" in t and "FIRST" in t


def test_exploit_agent_handles_every_candidate_type():
    t = _read("exploit-agent.md")
    for ct in CANDIDATE_TYPES:
        assert f"`{ct}`" in t, ct
    assert "run_teardown" in t and "never on your own initiative" in t
    assert "never\ncreate or edit that file yourself" in t or "never create or edit that file yourself" in t


def test_huntbrain_never_creates_grant_or_runs_teardown():
    t = _read("huntbrain.md")
    assert "you never create or edit it" in t
    assert "NEVER run by you" in t and "run_teardown" in t


def test_report_agent_offers_teardown_after_triage():
    t = _read("report-agent.md")
    assert "run_teardown" in t and "triage" in t and "Never run it yourself" in t


def test_every_browser_mcp_tool_named_in_agents_exists():
    names = _tool_names()
    mentioned = set()
    for f in os.listdir(AGENTS):
        if f.endswith(".md"):
            mentioned |= set(re.findall(r"\b(start_ui_walk|check_ui_walk|list_ui_walks|run_teardown)\b", _read(f)))
    assert mentioned and mentioned <= names
