import importlib.util
import os
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "sqlmap_mcp_server", os.path.join(ROOT, "mcp-servers", "sqlmap-mcp", "server.py")
)
sqlmap_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sqlmap_server)

import engagement_paths


@dataclass
class _FakeResult:
    stdout: str
    stderr: str = ""
    returncode: int = 0


SQLMAP_OUTPUT = """\
sqlmap identified the following injection point(s):
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
"""


def test_injection_type_not_truncated_to_one_char(monkeypatch, tmp_path):
    # sqlmap prints Type:/Title:/Payload: on separate lines, never combined
    # on one line -- the old lazy-quantifier-plus-optional-groups regex
    # captured just the first character ("b") of the type instead of the
    # full "boolean-based blind" string.
    monkeypatch.setattr(sqlmap_server, "run_tool", lambda *a, **k: _FakeResult(stdout=SQLMAP_OUTPUT))
    # No active engagement in this test's isolated cwd, so _output_dir()
    # falls back to its legacy /tmp path -- point that fallback at tmp_path
    # instead, so the test doesn't touch the real /tmp/huntmcp-sqlmap.
    fake_out_dir = tmp_path / "sqlmap-out"
    fake_out_dir.mkdir()
    monkeypatch.setattr(sqlmap_server, "_output_dir", lambda: str(fake_out_dir))
    out = sqlmap_server.test_injection("https://example.com/?id=1")
    assert "Type: boolean-based blind" in out
    assert "Type: b\n" not in out


def test_output_dir_scopes_under_active_engagement(monkeypatch, tmp_path):
    # The real bug this closes: sqlmap-mcp used to hardcode OUTPUT_DIR =
    # "/tmp/huntmcp-sqlmap" -- one flat, unscoped dir shared across every
    # target ever hunted from this machine, instead of the same per-target
    # data/engagements/<slug>/ isolation every other Tier-2 tool already
    # gets via engagement_paths.py. Confirm _output_dir() now resolves
    # under the ACTIVE target's own directory.
    #
    # ACTIVE_POINTER/ENGAGEMENTS_ROOT are now repo-root-anchored absolute
    # paths (not cwd-relative -- that used to silently break whenever a
    # caller's cwd wasn't the repo root, confirmed live on 2026-08-31), and
    # every function that uses them re-reads the module attribute at call
    # time rather than binding it into a parameter default at definition
    # time -- so monkeypatching the module attributes directly here (the
    # obvious approach) actually takes effect, and does so without ever
    # touching the real repo's data/ directory the way a chdir()-based
    # trick or an unpatched default well would.
    pointer = tmp_path / ".active-engagement"
    root = tmp_path / "engagements"
    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(pointer))
    monkeypatch.setattr(engagement_paths, "ENGAGEMENTS_ROOT", str(root))
    engagement_paths.set_active_target("acme.com")

    out_dir = sqlmap_server._output_dir()
    assert out_dir == os.path.join(str(root), "acme-com", "tmp-sqlmap")
    assert os.path.isdir(out_dir)
