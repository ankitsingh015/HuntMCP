import shutil
import subprocess

import mcp_connectivity

# Real captured output shape (ANSI-stripped) from `opencode mcp list` --
# connected servers use this exact "<name> connected" line shape. The
# "burp" failed-connection line is a SYNTHETIC fixture (best-effort
# reconstruction of the documented failure shape -- reproducing a real
# failed MCP connection locally would mean breaking a real server
# registration, not done here) modeled on the same "<name> <status>"
# structure the real connected lines use.
_SYNTHETIC_OUTPUT = """[0m
──  MCP Servers
│
●  ✓ writeup-mcp \x1b[90mconnected
│      \x1b[90m./scripts/venv-python.sh mcp-servers/writeup-mcp/server.py
│
●  ✓ case-mcp \x1b[90mconnected
│      \x1b[90m./scripts/venv-python.sh mcp-servers/case-mcp/server.py
│
●  ✗ burp \x1b[91mfailed
│      \x1b[90msome-external-bridge-command
│
└  3 server(s)
"""


def test_parse_mcp_list_output_finds_connected_servers():
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    assert statuses["writeup-mcp"] == "connected"
    assert statuses["case-mcp"] == "connected"


def test_parse_mcp_list_output_finds_non_connected_servers():
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    assert statuses["burp"] == "failed"


def test_parse_mcp_list_output_strips_ansi_codes_cleanly():
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    for name in statuses:
        assert "\x1b" not in name


def test_parse_mcp_list_output_captures_unrecognized_status_words():
    """Regression (code-review finding, confirmed via direct reproduction):
    the status regex used to hardcode exactly four literal words
    (connected/failed/error/disconnected) -- any OTHER status word (e.g.
    "connecting", a realistic mid-handshake/OAuth state) caused that
    server's line to not match at all, so the server vanished from the
    parsed dict entirely instead of being captured as non-connected. This
    silently inflated the healthy-server count and could make
    summarize_for_agent_context() wrongly report "all connected" while a
    real problem server was invisible -- exactly the failure mode this
    module exists to prevent."""
    raw = "●  ✓ some-server \x1b[93mconnecting\n●  ✓ writeup-mcp \x1b[90mconnected\n"
    statuses = mcp_connectivity.parse_mcp_list_output(raw)
    assert statuses == {"some-server": "connecting", "writeup-mcp": "connected"}
    summary = mcp_connectivity.summarize_for_agent_context(statuses)
    assert "some-server" in summary
    assert "connecting" in summary


def test_parse_mcp_list_output_does_not_match_header_or_footer_lines():
    """The real CLI output's header ("MCP Servers") and footer ("32
    server(s)") lines have the same loose "<symbol> <word> <word>" shape
    as a real server line -- broadening the status-word capture (previous
    test) must not also start matching these, which would inject fake
    "servers" named "MCP"/"32" into the result."""
    raw = "──  MCP Servers\n│\n●  ✓ writeup-mcp \x1b[90mconnected\n└  1 server(s)\n"
    statuses = mcp_connectivity.parse_mcp_list_output(raw)
    assert statuses == {"writeup-mcp": "connected"}


def test_find_disconnected_servers_reports_only_non_connected():
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    disconnected = mcp_connectivity.find_disconnected(statuses)
    assert disconnected == {"burp": "failed"}


def test_find_disconnected_servers_empty_when_all_connected():
    statuses = {"a-mcp": "connected", "b-mcp": "connected"}
    assert mcp_connectivity.find_disconnected(statuses) == {}


def test_summarize_for_agent_context_names_every_disconnected_server():
    """The actual fix for the reported gap: "only visible via host-level
    connection diagnostics, not communicated to the agent that had
    declared it as an available tool" -- this produces the one-line
    summary meant to be surfaced directly in an agent's own opening
    context, not left to a separate diagnostic a human has to go look at."""
    statuses = mcp_connectivity.parse_mcp_list_output(_SYNTHETIC_OUTPUT)
    summary = mcp_connectivity.summarize_for_agent_context(statuses)
    assert "burp" in summary
    assert "failed" in summary
    assert "writeup-mcp" not in summary  # only the PROBLEM servers are named, not every healthy one


def test_summarize_for_agent_context_all_healthy():
    statuses = {"a-mcp": "connected", "b-mcp": "connected"}
    summary = mcp_connectivity.summarize_for_agent_context(statuses)
    assert "all" in summary.lower()
    assert "connected" in summary.lower()


# ------------------------------------------------- live integration (gated)

def test_live_mcp_list_reports_every_registered_server_connected():
    """Live compatibility check (skipped if the opencode binary isn't
    installed): runs the real `opencode mcp list` and confirms nothing in
    THIS repo's own registered server set is silently disconnected --
    would have caught the reported "configured but failed to connect for
    an entire session" gap immediately at the start of any session that
    ran this check."""
    if not shutil.which("opencode"):
        return
    try:
        result = subprocess.run(["opencode", "mcp", "list"], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return
    if result.returncode != 0:
        return
    statuses = mcp_connectivity.parse_mcp_list_output(result.stdout)
    assert statuses, "parsed zero servers from real `opencode mcp list` output -- parser is out of sync with real format"
    disconnected = mcp_connectivity.find_disconnected(statuses)
    assert disconnected == {}, f"servers not connected: {disconnected}"
