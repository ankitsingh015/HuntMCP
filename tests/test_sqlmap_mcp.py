import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "sqlmap_mcp_server", os.path.join(ROOT, "mcp-servers", "sqlmap-mcp", "server.py")
)
sqlmap_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sqlmap_server)

import engagement_paths


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
    #
    # test_injection() now only *starts* a background job (see
    # mcp-servers/job_runtime.py) -- fake start_job()/poll_job() rather
    # than run_tool(), which sqlmap-mcp no longer calls directly.
    # No active engagement in this test's isolated cwd, so _output_dir()
    # falls back to its legacy /tmp path -- point that fallback at tmp_path
    # instead, so the test doesn't touch the real /tmp/huntmcp-sqlmap.
    fake_out_dir = tmp_path / "sqlmap-out"
    fake_out_dir.mkdir()
    monkeypatch.setattr(sqlmap_server, "_output_dir", lambda: str(fake_out_dir))
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-1", "status": "running", "tool": "sqlmap"},
    )
    start_msg = sqlmap_server.test_injection("https://example.com/?id=1")
    assert "job-1" in start_msg

    monkeypatch.setattr(
        sqlmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": SQLMAP_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    out = sqlmap_server.check_scan("job-1")
    assert "Type: boolean-based blind" in out
    assert "Type: b\n" not in out


def test_check_scan_actually_removes_the_scratch_tmpdir_from_disk(monkeypatch, tmp_path):
    # test_injection()'s scratch --output-dir used to be a
    # `with tempfile.TemporaryDirectory(...)` context manager, guaranteed
    # cleaned up on scope exit. The backgrounded version creates it with
    # mkdtemp() and removes it manually in check_scan() instead -- confirm
    # that actually happens on disk, not just that the formatted text
    # looks right (which wouldn't catch a dropped/reordered rmtree()).
    fake_out_dir = tmp_path / "sqlmap-out"
    fake_out_dir.mkdir()
    monkeypatch.setattr(sqlmap_server, "_output_dir", lambda: str(fake_out_dir))
    monkeypatch.setattr(
        sqlmap_server.job_runtime, "start_job",
        lambda *a, **k: {"job_id": "job-cleanup", "status": "running", "tool": "sqlmap"},
    )
    sqlmap_server.test_injection("https://example.com/?id=1")
    tmpdir = sqlmap_server._meta["job-cleanup"]["tmpdir"]
    assert os.path.isdir(tmpdir)

    monkeypatch.setattr(
        sqlmap_server.job_runtime, "poll_job",
        lambda job_id, jobs: {
            "status": "done", "job_id": job_id, "returncode": 0,
            "stdout": SQLMAP_OUTPUT, "stderr": "", "elapsed_s": 1.0, "block": None,
        },
    )
    sqlmap_server.check_scan("job-cleanup")
    assert not os.path.isdir(tmpdir)
    assert "job-cleanup" not in sqlmap_server._meta


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
