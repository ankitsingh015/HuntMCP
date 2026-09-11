"""Worktree-safety module for the HuntMCP dev-runner.

Reads git state (branch, cleanliness, linked worktrees) with **read-only**
commands and assesses whether it is safe to execute the selected task here. It
never mutates the repository: it will not copy, reset, stash, merge, switch
branches, or overwrite anything. When the expected work lives on another branch
or in another worktree, it STOPs and reports where -- it does not move the work.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


@dataclass
class WorktreeInfo:
    branch: str
    toplevel: str
    common_dir: str
    dirty: bool
    changes: list[str] = field(default_factory=list)
    worktrees: list[tuple[str, str]] = field(default_factory=list)  # (path, branch)


@dataclass
class WorktreeCheck:
    ok: bool
    stop_codes: list[str] = field(default_factory=list)
    reason: str = ""
    warnings: list[str] = field(default_factory=list)


def _git(repo_dir: str, *args: str) -> str:
    """Run a read-only git command and return stdout (empty on failure)."""
    proc = subprocess.run(
        ["git", "-C", repo_dir, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def _parse_worktree_porcelain(text: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    cur_path: str | None = None
    cur_branch = ""
    for line in text.splitlines():
        if line.startswith("worktree "):
            if cur_path is not None:
                result.append((cur_path, cur_branch))
            cur_path = line[len("worktree "):].strip()
            cur_branch = ""
        elif line.startswith("branch "):
            ref = line[len("branch "):].strip()
            # Strip only the refs/heads/ prefix -- branch names may contain
            # slashes (e.g. "claude/phase1-cem"), so never truncate on them.
            if ref.startswith("refs/heads/"):
                cur_branch = ref[len("refs/heads/"):]
            else:
                cur_branch = ref
        elif line.startswith("detached"):
            cur_branch = "(detached)"
    if cur_path is not None:
        result.append((cur_path, cur_branch))
    return result


def git_context(repo_dir: str = ".") -> WorktreeInfo:
    branch = _git(repo_dir, "rev-parse", "--abbrev-ref", "HEAD").strip()
    toplevel = _git(repo_dir, "rev-parse", "--show-toplevel").strip()
    common_dir = _git(repo_dir, "rev-parse", "--git-common-dir").strip()
    porcelain = _git(repo_dir, "status", "--porcelain")
    changes = [ln for ln in porcelain.splitlines() if ln.strip()]
    worktrees = _parse_worktree_porcelain(_git(repo_dir, "worktree", "list", "--porcelain"))
    return WorktreeInfo(
        branch=branch,
        toplevel=toplevel,
        common_dir=common_dir,
        dirty=bool(changes),
        changes=changes,
        worktrees=worktrees,
    )


def assess(
    info: WorktreeInfo,
    expected_branch: str | None = None,
    require_clean: bool = False,
) -> WorktreeCheck:
    stop_codes: list[str] = []
    warnings: list[str] = []
    reasons: list[str] = []

    if expected_branch and info.branch != expected_branch:
        # Does the expected work actually live in another worktree?
        elsewhere = [
            path for path, br in info.worktrees if br == expected_branch and path != info.toplevel
        ]
        if elsewhere:
            stop_codes.append("WORKTREE_MISMATCH")
            reasons.append(
                f"The task's expected branch '{expected_branch}' is checked out in another "
                f"worktree ({', '.join(elsewhere)}), not here ('{info.branch}' at {info.toplevel}). "
                "The runner will not copy/merge work across worktrees -- switch to that worktree "
                "manually or reconcile intentionally."
            )
        else:
            stop_codes.append("WORKTREE_BRANCH_MISMATCH")
            reasons.append(
                f"Current branch is '{info.branch}' but the task expects '{expected_branch}'. "
                "Refusing to switch branches automatically."
            )

    if info.dirty:
        summary = f"{len(info.changes)} uncommitted change(s) in the working tree"
        if require_clean:
            stop_codes.append("UNCOMMITTED_CHANGES")
            reasons.append(
                summary + "; a clean tree is required before starting this task. "
                "The runner will not stash or discard them."
            )
        else:
            warnings.append(summary + " (review before committing).")

    return WorktreeCheck(
        ok=not stop_codes,
        stop_codes=stop_codes,
        reason=" ".join(reasons),
        warnings=warnings,
    )
