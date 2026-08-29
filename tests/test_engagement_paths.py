import json
import os
import subprocess
import sys

import engagement_paths

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENGAGEMENT_PATHS_CLI = os.path.join(_REPO_ROOT, "mcp-servers", "engagement_paths.py")


def test_slugify_normalizes_target():
    assert engagement_paths.slugify("Example.com") == "example-com"
    assert engagement_paths.slugify("  api.Target.io  ") == "api-target-io"
    assert engagement_paths.slugify("***") == "unnamed-target"


def test_get_active_target_none_when_no_pointer(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    assert engagement_paths.get_active_target(pointer) is None


def test_set_active_target_creates_dir_and_pointer(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    slug = engagement_paths.set_active_target("example.com", pointer, root)
    assert slug == "example-com"
    assert os.path.isfile(pointer)
    assert os.path.isdir(os.path.join(root, "example-com"))
    assert engagement_paths.get_active_target(pointer) == "example-com"


def test_switching_target_does_not_touch_other_targets_files(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")

    engagement_paths.set_active_target("target-a.com", pointer, root)
    a_budget = engagement_paths.resolve("budget.json", pointer_path=pointer, engagements_root=root)
    os.makedirs(os.path.dirname(a_budget), exist_ok=True)
    with open(a_budget, "w") as f:
        json.dump({"calls": 42}, f)

    engagement_paths.set_active_target("target-b.com", pointer, root)
    b_budget = engagement_paths.resolve("budget.json", pointer_path=pointer, engagements_root=root)
    assert b_budget != a_budget
    assert not os.path.isfile(b_budget)

    # resuming target-a later is just switching the pointer back --
    # its budget.json is untouched by anything that happened on target-b
    engagement_paths.set_active_target("target-a.com", pointer, root)
    resumed_budget = engagement_paths.resolve("budget.json", pointer_path=pointer, engagements_root=root)
    assert resumed_budget == a_budget
    with open(resumed_budget) as f:
        assert json.load(f)["calls"] == 42


def test_resolve_falls_back_to_legacy_when_no_active_target(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    assert engagement_paths.resolve("budget.json", pointer_path=pointer) == "budget.json"
    assert engagement_paths.resolve(
        "budget.json", pointer_path=pointer, legacy_default="/some/legacy/path.json"
    ) == "/some/legacy/path.json"


def test_resolve_env_override_wins_over_active_target(tmp_path, monkeypatch):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("example.com", pointer, root)
    monkeypatch.setenv("HUNTMCP_TEST_OVERRIDE", "/explicit/override.json")
    resolved = engagement_paths.resolve(
        "budget.json", override_env="HUNTMCP_TEST_OVERRIDE",
        pointer_path=pointer, engagements_root=root,
    )
    assert resolved == "/explicit/override.json"


def test_list_engagements_empty_when_no_root(tmp_path):
    root = str(tmp_path / "nope")
    assert engagement_paths.list_engagements(root) == []


def test_check_conflict_none_when_nothing_active(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    assert engagement_paths.check_conflict("example.com", pointer_path=pointer) is None


def test_check_conflict_none_when_same_target(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("example.com", pointer, root)
    assert engagement_paths.check_conflict(
        "example.com", pointer_path=pointer, engagements_root=root
    ) is None


def test_check_conflict_warns_on_different_incomplete_target(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("target-a.com", pointer, root)
    warning = engagement_paths.check_conflict(
        "target-b.com", pointer_path=pointer, engagements_root=root
    )
    assert warning is not None
    assert "target-a-com" in warning
    assert "target-b-com" in warning


def test_check_conflict_none_when_active_target_marked_complete(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("target-a.com", pointer, root)
    engagement_paths.mark_complete(pointer, root)
    warning = engagement_paths.check_conflict(
        "target-b.com", pointer_path=pointer, engagements_root=root
    )
    assert warning is None


def test_mark_complete_returns_none_when_nothing_active(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    assert engagement_paths.mark_complete(pointer, root) is None


def test_is_complete_false_until_marked(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("example.com", pointer, root)
    assert engagement_paths.is_complete("example-com", root) is False
    engagement_paths.mark_complete(pointer, root)
    assert engagement_paths.is_complete("example-com", root) is True


def test_list_engagements_includes_complete_flag(tmp_path):
    root = str(tmp_path / "engagements")
    pointer = str(tmp_path / ".active-engagement")
    engagement_paths.set_active_target("example.com", pointer, root)
    result = engagement_paths.list_engagements(root)
    assert result[0]["complete"] is False
    engagement_paths.mark_complete(pointer, root)
    result = engagement_paths.list_engagements(root)
    assert result[0]["complete"] is True


def test_list_engagements_reports_target_and_calls(tmp_path):
    root = str(tmp_path / "engagements")
    slug_dir = os.path.join(root, "example-com")
    os.makedirs(slug_dir)
    with open(os.path.join(slug_dir, "engagement.yaml"), "w") as f:
        f.write("target: example.com\nin_scope:\n  - example.com\n")
    with open(os.path.join(slug_dir, "budget.json"), "w") as f:
        json.dump({"calls": 7}, f)

    result = engagement_paths.list_engagements(root)
    assert len(result) == 1
    assert result[0]["slug"] == "example-com"
    assert result[0]["target"] == "example.com"
    assert result[0]["tier2_calls"] == 7


def test_resolve_dir_creates_and_scopes_under_active_target(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("example.com", pointer, root)

    downloads = engagement_paths.resolve_dir(
        "downloads", pointer_path=pointer, engagements_root=root
    )
    assert downloads == os.path.join(root, "example-com", "downloads")
    assert os.path.isdir(downloads)


def test_resolve_dir_falls_back_to_legacy_when_no_active_target(tmp_path):
    pointer = str(tmp_path / ".active-engagement")
    legacy = str(tmp_path / "legacy-downloads")
    result = engagement_paths.resolve_dir(
        "downloads", pointer_path=pointer, legacy_default=legacy
    )
    assert result == legacy
    assert os.path.isdir(legacy)


def _run_cli(args, env_extra, cwd):
    env = {**os.environ, **env_extra}
    return subprocess.run(
        [sys.executable, _ENGAGEMENT_PATHS_CLI, *args],
        cwd=cwd, env=env, capture_output=True, text=True, check=True,
    )


def test_format_session_commands_empty_when_no_engagements(tmp_path):
    root = str(tmp_path / "engagements")
    assert engagement_paths.format_session_commands(root) == "No engagements yet -- nothing to copy."


def test_format_session_commands_prints_one_ready_line_per_engagement(tmp_path):
    root = str(tmp_path / "engagements")
    for slug, target, calls, complete in [
        ("target-a-com", "target-a.com", 12, False),
        ("target-b-com", "target-b.com", 54, True),
    ]:
        d = os.path.join(root, slug)
        os.makedirs(d)
        with open(os.path.join(d, "engagement.yaml"), "w") as f:
            f.write(f"target: {target}\nin_scope:\n  - {target}\n")
        with open(os.path.join(d, "budget.json"), "w") as f:
            json.dump({"calls": calls}, f)
        if complete:
            open(os.path.join(d, ".complete"), "w").close()

    output = engagement_paths.format_session_commands(root, active_slug="target-a-com")
    lines = output.splitlines()
    assert len(lines) == 2
    assert 'source scripts/new-target-session.sh "target-a.com"' in lines[0]
    assert "12 Tier-2 calls" in lines[0]
    assert "open" in lines[0]
    assert "(this terminal's active target)" in lines[0]
    assert 'source scripts/new-target-session.sh "target-b.com"' in lines[1]
    assert "54 Tier-2 calls" in lines[1]
    assert "COMPLETE" in lines[1]
    assert "(this terminal's active target)" not in lines[1]


def test_format_session_commands_falls_back_to_slug_when_no_engagement_yaml(tmp_path):
    root = str(tmp_path / "engagements")
    os.makedirs(os.path.join(root, "mystery-target"))
    output = engagement_paths.format_session_commands(root)
    assert 'source scripts/new-target-session.sh "mystery-target"' in output


def test_active_pointer_env_var_isolates_concurrent_sessions(tmp_path):
    """Regression for scripts/new-target-session.sh's whole premise: two
    real, separate processes (as two concurrent opencode/claude sessions
    actually are) each pointed at their own HUNTMCP_ACTIVE_POINTER must
    never see or overwrite each other's active target, even though both
    share the exact same data/engagements/ root underneath. Runs the
    actual CLI as a subprocess (not just calling the Python function
    in-process) because ACTIVE_POINTER's env-var default is itself bound
    at import time -- the real guarantee only holds if each session is a
    genuinely separate process, which this test exercises for real."""
    # engagement_paths.py resolves its own relative default paths against
    # the process's cwd, so both subprocesses share one cwd (tmp_path) --
    # same as two concurrent sessions both running from the same repo
    # checkout, isolated only by which HUNTMCP_ACTIVE_POINTER each sees.
    pointer_a = "data/.active-engagement-a"
    pointer_b = "data/.active-engagement-b"

    _run_cli(["set", "company-a.com"], {"HUNTMCP_ACTIVE_POINTER": pointer_a}, cwd=tmp_path)
    _run_cli(["set", "company-b.com"], {"HUNTMCP_ACTIVE_POINTER": pointer_b}, cwd=tmp_path)

    current_a = _run_cli(["current"], {"HUNTMCP_ACTIVE_POINTER": pointer_a}, cwd=tmp_path)
    current_b = _run_cli(["current"], {"HUNTMCP_ACTIVE_POINTER": pointer_b}, cwd=tmp_path)

    assert "company-a-com" in current_a.stdout
    assert "company-b-com" in current_b.stdout
    assert "company-b-com" not in current_a.stdout
    assert "company-a-com" not in current_b.stdout


def test_resolve_dir_env_override_wins_over_active_target(tmp_path, monkeypatch):
    pointer = str(tmp_path / ".active-engagement")
    root = str(tmp_path / "engagements")
    engagement_paths.set_active_target("example.com", pointer, root)

    override_dir = str(tmp_path / "override-downloads")
    monkeypatch.setenv("HUNTMCP_TEST_DOWNLOADS_DIR", override_dir)
    result = engagement_paths.resolve_dir(
        "downloads", override_env="HUNTMCP_TEST_DOWNLOADS_DIR",
        pointer_path=pointer, engagements_root=root,
    )
    assert result == override_dir
    assert result != os.path.join(root, "example-com", "downloads")
    assert os.path.isdir(override_dir)
