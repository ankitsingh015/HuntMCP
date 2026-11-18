import json
import os
import shutil
import subprocess

import mcp_connectivity

# Real captured output shape (ANSI-stripped) from `claude mcp list` -- each
# server is one line "<name>: <command-or-url> - <symbol> <status>". The
# "burp" failed line is a SYNTHETIC fixture (best-effort reconstruction of the
# documented failure shape -- reproducing a real failed MCP connection locally
# would mean breaking a real server registration, not done here) modeled on
# the same line shape the real connected lines use.
_SYNTHETIC_OUTPUT = """Checking MCP server health…

writeup-mcp: ${CLAUDE_PROJECT_DIR}/scripts/venv-python.sh ${CLAUDE_PROJECT_DIR}/mcp-servers/writeup-mcp/server.py - \x1b[32m✔ Connected\x1b[0m
case-mcp: ${CLAUDE_PROJECT_DIR}/scripts/venv-python.sh ${CLAUDE_PROJECT_DIR}/mcp-servers/case-mcp/server.py - \x1b[32m✔ Connected\x1b[0m
burp: java -jar /home/x/.BurpSuite/mcp-proxy/mcp-proxy-all.jar --sse-url http://localhost:9876 - \x1b[31m✗ Failed to connect\x1b[0m
"""


def test_parse_mcp_list_output_finds_connected_servers():
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    assert statuses["writeup-mcp"] == "connected"
    assert statuses["case-mcp"] == "connected"


def test_parse_mcp_list_output_finds_non_connected_servers():
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    assert statuses["burp"] == "failed to connect"


def test_parse_mcp_list_output_strips_ansi_codes_cleanly():
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    for name, status in statuses.items():
        assert "\x1b" not in name
        assert "\x1b" not in status


def test_parse_mcp_list_output_captures_any_non_connected_status():
    """Any status that is not "✔ Connected" must be captured as a non-connected
    entry (not dropped), so a server mid-handshake/OAuth/timeout is still
    surfaced rather than silently vanishing and inflating the healthy count."""
    raw = (
        "some-server: /x/server.py - \x1b[33m◐ Connecting…\x1b[0m\n"
        "writeup-mcp: /x/writeup.py - \x1b[32m✔ Connected\x1b[0m\n"
    )
    statuses = mcp_connectivity.parse_mcp_list_output(raw)
    assert statuses["writeup-mcp"] == "connected"
    assert statuses["some-server"] != "connected"
    summary = mcp_connectivity.summarize_for_agent_context(statuses)
    assert "some-server" in summary


def test_parse_mcp_list_output_skips_header_and_blank_lines():
    """The `claude mcp list` header ("Checking MCP server health…") and blank
    lines have no " - " status and must not be parsed as servers."""
    raw = "Checking MCP server health…\n\nwriteup-mcp: /x/w.py - \x1b[32m✔ Connected\x1b[0m\n"
    statuses = mcp_connectivity.parse_mcp_list_output(raw)
    assert statuses == {"writeup-mcp": "connected"}


def test_parse_mcp_list_output_handles_connector_names_with_spaces():
    """Remote connectors print as "claude.ai Google Drive: <url> - ✔ Connected";
    the name is everything before the first ': ' (spaces allowed)."""
    raw = "claude.ai Google Drive: https://drivemcp.googleapis.com/mcp/v1 - \x1b[32m✔ Connected\x1b[0m\n"
    statuses = mcp_connectivity.parse_mcp_list_output(raw)
    assert statuses == {"claude.ai Google Drive": "connected"}


def test_find_disconnected_servers_reports_only_non_connected():
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    disconnected = mcp_connectivity.find_disconnected(statuses)
    assert disconnected == {"burp": "failed to connect"}


def test_find_disconnected_servers_empty_when_all_connected():
    statuses = {"a-mcp": "connected", "b-mcp": "connected"}
    assert mcp_connectivity.find_disconnected(statuses) == {}


def test_summarize_for_agent_context_names_every_disconnected_server():
    """The actual fix for the reported gap: "only visible via host-level
    connection diagnostics, not communicated to the agent that had declared it
    as an available tool" -- this produces the one-line summary meant to be
    surfaced directly in an agent's own opening context."""
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    summary = mcp_connectivity.summarize_for_agent_context(statuses)
    assert "burp" in summary
    assert "failed" in summary
    assert "writeup-mcp" not in summary  # only the PROBLEM servers are named


def test_summarize_for_agent_context_all_healthy():
    statuses = {"a-mcp": "connected", "b-mcp": "connected"}
    summary = mcp_connectivity.summarize_for_agent_context(statuses)
    assert "all" in summary.lower()
    assert "connected" in summary.lower()


# --------------------------------------- persistence + fallback (issue #134)

def test_fallback_for_known_server_returns_documented_chain():
    fb = mcp_connectivity.fallback_for("burp")
    assert fb is not None
    assert "oob-mcp" in fb  # Collaborator -> oob-mcp is the documented path


def test_fallback_for_unknown_server_is_none():
    assert mcp_connectivity.fallback_for("totally-unknown-mcp") is None


def test_save_and_load_health_snapshot_roundtrip(tmp_path):
    path = str(tmp_path / "mcp-health.json")
    statuses = {"writeup-mcp": "connected", "burp": "failed to connect", "case-mcp": "connected"}
    snap = mcp_connectivity.save_health_snapshot(statuses, path=path)
    assert os.path.isfile(path)
    assert snap["disconnected"] == {"burp": "failed to connect"}
    assert snap["total"] == 3
    assert snap["checked_at"]
    assert "burp" in snap["fallbacks"]
    loaded = mcp_connectivity.load_health_snapshot(path=path)
    assert loaded["disconnected"] == {"burp": "failed to connect"}


def test_unavailable_servers_reads_snapshot(tmp_path):
    path = str(tmp_path / "mcp-health.json")
    mcp_connectivity.save_health_snapshot(
        {"a-mcp": "connected", "burp": "failed to connect"}, path=path
    )
    assert mcp_connectivity.unavailable_servers(path=path) == {"burp": "failed to connect"}


def test_unavailable_servers_empty_when_all_connected(tmp_path):
    path = str(tmp_path / "mcp-health.json")
    mcp_connectivity.save_health_snapshot(
        {"a-mcp": "connected", "b-mcp": "connected"}, path=path
    )
    assert mcp_connectivity.unavailable_servers(path=path) == {}


def test_unavailable_servers_empty_when_no_snapshot(tmp_path):
    assert mcp_connectivity.unavailable_servers(path=str(tmp_path / "nope.json")) == {}


def test_snapshot_checked_flag_distinguishes_could_not_check_from_all_healthy(tmp_path):
    # {} statuses means collect_live_statuses() could not check (claude binary
    # missing / command failed) -- must NOT read back the same as a real "all
    # connected" result.
    could_not = mcp_connectivity.save_health_snapshot({}, path=str(tmp_path / "a.json"))
    all_healthy = mcp_connectivity.save_health_snapshot(
        {"x-mcp": "connected"}, path=str(tmp_path / "b.json")
    )
    assert could_not["checked"] is False
    assert all_healthy["checked"] is True


def test_save_health_snapshot_resolves_per_engagement_when_no_path(tmp_path, monkeypatch):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    monkeypatch.setattr("engagement_paths.ACTIVE_POINTER", pointer)
    monkeypatch.setattr("engagement_paths.ENGAGEMENTS_ROOT", root)
    import engagement_paths
    engagement_paths.set_active_target("target-x.com", pointer, root)
    mcp_connectivity.save_health_snapshot({"burp": "failed to connect"})
    expected = os.path.join(root, "target-x-com", "mcp-health.json")
    assert os.path.isfile(expected)
    with open(expected) as f:
        assert json.load(f)["disconnected"] == {"burp": "failed to connect"}


def test_collect_live_statuses_empty_when_claude_missing(monkeypatch):
    monkeypatch.setattr(mcp_connectivity.shutil, "which", lambda _: None)
    assert mcp_connectivity.collect_live_statuses() == {}


def test_collect_live_statuses_parses_subprocess_output(monkeypatch):
    monkeypatch.setattr(mcp_connectivity.shutil, "which", lambda _: "/usr/bin/claude")

    class _R:
        returncode = 0
        stdout = (
            "writeup-mcp: /x/w.py - \x1b[32m✔ Connected\x1b[0m\n"
            "burp: /x/burp - \x1b[31m✗ Failed to connect\x1b[0m\n"
        )

    monkeypatch.setattr(mcp_connectivity.subprocess, "run", lambda *a, **k: _R())
    statuses = mcp_connectivity.collect_live_statuses()
    assert statuses == {"writeup-mcp": "connected", "burp": "failed to connect"}


# ------------------------------------------------- live integration (gated)

def test_live_mcp_list_reports_every_registered_server_connected():
    """Live compatibility check (skipped if the claude binary isn't installed):
    runs the real `claude mcp list` and confirms nothing in THIS repo's own
    registered server set is silently disconnected."""
    if not shutil.which("claude"):
        return
    try:
        result = subprocess.run(["claude", "mcp", "list"], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return
    if result.returncode != 0:
        return
    statuses = mcp_connectivity.parse_mcp_list_output(result.stdout)
    assert statuses, "parsed zero servers from real `claude mcp list` output -- parser is out of sync with real format"
    disconnected = mcp_connectivity.find_disconnected(statuses)
    assert disconnected == {}, f"servers not connected: {disconnected}"
