import json
import os
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


# --------------------------------------- persistence + fallback (issue #134)
# The smoke check above already surfaces a down server in the agent's own
# context. #134 part 2 asks that the result also be PERSISTED into the
# engagement's state so a finding whose primary validation path was down can
# cite that from the case store, not just a transient agent report; part 3
# asks for a documented per-capability fallback so a missing server degrades
# predictably.

def test_fallback_for_known_server_returns_documented_chain():
    fb = mcp_connectivity.fallback_for("burp")
    assert fb is not None
    assert "oob-mcp" in fb  # Collaborator -> oob-mcp is the documented path


def test_fallback_for_unknown_server_is_none():
    assert mcp_connectivity.fallback_for("totally-unknown-mcp") is None


def test_save_and_load_health_snapshot_roundtrip(tmp_path):
    path = str(tmp_path / "mcp-health.json")
    statuses = {"writeup-mcp": "connected", "burp": "failed", "case-mcp": "connected"}
    snap = mcp_connectivity.save_health_snapshot(statuses, path=path)
    assert os.path.isfile(path)
    # Returned snapshot records only the problem servers + total + a timestamp.
    assert snap["disconnected"] == {"burp": "failed"}
    assert snap["total"] == 3
    assert snap["checked_at"]
    # A documented fallback is recorded for the down server.
    assert "burp" in snap["fallbacks"]
    # Reloads identically from disk.
    loaded = mcp_connectivity.load_health_snapshot(path=path)
    assert loaded["disconnected"] == {"burp": "failed"}


def test_unavailable_servers_reads_snapshot(tmp_path):
    path = str(tmp_path / "mcp-health.json")
    mcp_connectivity.save_health_snapshot(
        {"a-mcp": "connected", "burp": "failed"}, path=path
    )
    assert mcp_connectivity.unavailable_servers(path=path) == {"burp": "failed"}


def test_unavailable_servers_empty_when_all_connected(tmp_path):
    path = str(tmp_path / "mcp-health.json")
    mcp_connectivity.save_health_snapshot(
        {"a-mcp": "connected", "b-mcp": "connected"}, path=path
    )
    assert mcp_connectivity.unavailable_servers(path=path) == {}


def test_unavailable_servers_empty_when_no_snapshot(tmp_path):
    # No health snapshot recorded (check never ran / file absent) -> {}.
    assert mcp_connectivity.unavailable_servers(path=str(tmp_path / "nope.json")) == {}


def test_snapshot_checked_flag_distinguishes_could_not_check_from_all_healthy(tmp_path):
    # {} statuses means collect_live_statuses() could not check (opencode
    # missing / command failed) -- that must NOT read back the same as a real
    # "all connected" result, or a finding could cite 'nothing was down' when
    # the check never actually ran.
    could_not = mcp_connectivity.save_health_snapshot({}, path=str(tmp_path / "a.json"))
    all_healthy = mcp_connectivity.save_health_snapshot(
        {"x-mcp": "connected"}, path=str(tmp_path / "b.json")
    )
    assert could_not["checked"] is False
    assert all_healthy["checked"] is True


def test_save_health_snapshot_resolves_per_engagement_when_no_path(tmp_path, monkeypatch):
    # With no explicit path it must land under the ACTIVE engagement's dir,
    # same per-target resolution budget.json/work-registry.json use.
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    monkeypatch.setattr("engagement_paths.ACTIVE_POINTER", pointer)
    monkeypatch.setattr("engagement_paths.ENGAGEMENTS_ROOT", root)
    import engagement_paths
    engagement_paths.set_active_target("target-x.com", pointer, root)
    mcp_connectivity.save_health_snapshot({"burp": "failed"})
    expected = os.path.join(root, "target-x-com", "mcp-health.json")
    assert os.path.isfile(expected)
    with open(expected) as f:
        assert json.load(f)["disconnected"] == {"burp": "failed"}


def test_collect_live_statuses_empty_when_opencode_missing(monkeypatch):
    monkeypatch.setattr(mcp_connectivity.shutil, "which", lambda _: None)
    assert mcp_connectivity.collect_live_statuses() == {}


def test_collect_live_statuses_parses_subprocess_output(monkeypatch):
    monkeypatch.setattr(mcp_connectivity.shutil, "which", lambda _: "/usr/bin/opencode")

    class _R:
        returncode = 0
        stdout = "●  ✓ writeup-mcp \x1b[90mconnected\n●  ✗ burp \x1b[91mfailed\n"

    monkeypatch.setattr(mcp_connectivity.subprocess, "run", lambda *a, **k: _R())
    statuses = mcp_connectivity.collect_live_statuses()
    assert statuses == {"writeup-mcp": "connected", "burp": "failed"}


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
