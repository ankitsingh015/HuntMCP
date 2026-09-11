"""Tests for the dev-runner worktree-safety module (scripts/runner/worktree.py).

Pure assessment logic is tested with synthetic inputs; the git reader is tested
against a throwaway temp repository created under tmp_path. No test touches the
real HuntMCP repository or its git history, and the reader must never mutate the
repo it inspects.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from runner import worktree  # noqa: E402


def _info(branch="feature", dirty=False, changes=None, worktrees=None, toplevel="/repo"):
    return worktree.WorktreeInfo(
        branch=branch,
        toplevel=toplevel,
        common_dir="/repo/.git",
        dirty=dirty,
        changes=changes or [],
        worktrees=worktrees or [(toplevel, branch)],
    )


# --- pure assessment ---

def test_matching_branch_is_ok():
    chk = worktree.assess(_info(branch="feature"), expected_branch="feature")
    assert chk.ok is True
    assert chk.stop_codes == []


def test_no_expected_branch_is_ok():
    chk = worktree.assess(_info(branch="anything"), expected_branch=None)
    assert chk.ok is True


def test_branch_mismatch_stops():
    chk = worktree.assess(_info(branch="main"), expected_branch="feature")
    assert chk.ok is False
    assert "WORKTREE_BRANCH_MISMATCH" in chk.stop_codes
    assert "main" in chk.reason and "feature" in chk.reason


def test_expected_branch_living_in_another_worktree_stops():
    info = _info(
        branch="main",
        toplevel="/repo",
        worktrees=[("/repo", "main"), ("/repo/.wt/feature", "feature")],
    )
    chk = worktree.assess(info, expected_branch="feature")
    assert chk.ok is False
    assert "WORKTREE_MISMATCH" in chk.stop_codes
    # must name where the work actually lives so a human can act.
    assert "/repo/.wt/feature" in chk.reason


def test_dirty_tree_warns_but_is_ok_by_default():
    chk = worktree.assess(_info(dirty=True, changes=[" M foo.py"]), expected_branch="feature")
    assert chk.ok is True
    assert any("uncommitted" in w.lower() for w in chk.warnings)


def test_dirty_tree_stops_when_clean_required():
    chk = worktree.assess(
        _info(dirty=True, changes=[" M foo.py"]),
        expected_branch="feature",
        require_clean=True,
    )
    assert chk.ok is False
    assert "UNCOMMITTED_CHANGES" in chk.stop_codes


# --- git reader (integration against a temp repo) ---

def _run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def _make_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    _run(["git", "init", "-b", "work"], path)
    _run(["git", "config", "user.email", "t@example.com"], path)
    _run(["git", "config", "user.name", "Tester"], path)
    (path / "a.txt").write_text("hello\n", encoding="utf-8")
    _run(["git", "add", "."], path)
    _run(["git", "commit", "-m", "init"], path)
    return path


def test_git_context_reads_branch_and_clean_state(tmp_path):
    repo = _make_repo(tmp_path / "repo")
    info = worktree.git_context(str(repo))
    assert info.branch == "work"
    assert info.dirty is False
    assert info.changes == []


def test_git_context_detects_dirty(tmp_path):
    repo = _make_repo(tmp_path / "repo")
    (repo / "a.txt").write_text("changed\n", encoding="utf-8")
    info = worktree.git_context(str(repo))
    assert info.dirty is True
    assert any("a.txt" in c for c in info.changes)


def test_git_context_lists_linked_worktrees(tmp_path):
    repo = _make_repo(tmp_path / "repo")
    wt = tmp_path / "linked"
    _run(["git", "worktree", "add", "-b", "side", str(wt)], repo)
    info = worktree.git_context(str(repo))
    branches = {b for _, b in info.worktrees}
    assert "work" in branches
    assert "side" in branches


def test_git_context_preserves_slashes_in_worktree_branch_names(tmp_path):
    # Real branches contain slashes (e.g. "claude/phase1-cem"); the worktree
    # listing must keep the full name, not truncate at the last slash.
    repo = _make_repo(tmp_path / "repo")
    wt = tmp_path / "linked"
    _run(["git", "worktree", "add", "-b", "claude/phase1-cem", str(wt)], repo)
    info = worktree.git_context(str(repo))
    branches = {b for _, b in info.worktrees}
    assert "claude/phase1-cem" in branches


def test_git_context_does_not_mutate_repo(tmp_path):
    repo = _make_repo(tmp_path / "repo")
    before = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True
    ).stdout
    worktree.git_context(str(repo))
    after = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True
    ).stdout
    assert before == after == ""
