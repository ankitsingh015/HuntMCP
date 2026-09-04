# Git and Worktree Rules

## Worktree awareness
Before modifying code:
- run `git status`;
- identify the current branch;
- inspect `git worktree list` when worktrees are present.

Never assume the current directory is the main repository.

## Isolation
Do not modify another worktree unless explicitly instructed.

Do not use one worktree's state as a substitute for another worktree's state.

## Existing user changes
Protect unrelated user changes.

Never run destructive cleanup commands such as `git clean -fd`, `git reset --hard`, or broad deletion commands without explicit authorization.

## Branch discipline
Keep changes on the intended branch/worktree.

Do not silently merge, rebase, cherry-pick, reset, or delete branches.

## Commits
Create commits only when the task/workflow calls for them.

Before committing:
- inspect the diff;
- ensure unrelated changes are excluded;
- run required tests;
- verify no secrets are included.

## Pushes
Do not force-push.

Do not push unrelated work.

Follow the repository's existing Git/push rules.

## Checkpoints
For long tasks, checkpoint meaningful completed groups.

A checkpoint should include:
- implementation state;
- tests run;
- verification result;
- remaining work;
- relevant execution-plan state.

## Worktree cleanup
Do not remove a worktree until its branch/work has been verified as safely merged or intentionally discarded.

Never delete a worktree to hide unfinished or failing work.
