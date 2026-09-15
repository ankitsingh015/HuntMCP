# Git and Worktree Rules

## IMPORTANT GIT WORKFLOW RULE

For this repository, use exactly ONE physical git worktree:

`/home/ankit/HuntMCP`

NEVER create, use, or switch to a separate git worktree.

Do not run:
- `git worktree add`
- `git worktree move`
- `git worktree prune`
- or any equivalent operation that creates/manages another checkout.

Do not use Claude-generated or OpenCode-generated worktrees.

Branches are allowed, but ALL branches/tasks must use the same physical worktree:

`/home/ankit/HuntMCP`

Preferred pattern:

```
main
→ git switch -c <task-branch>
→ work
→ commit
→ wait for explicit human approval
→ merge/cherry-pick
→ verify
→ delete branch only when explicitly instructed.
```

Before starting ANY task:

1. Confirm `pwd` is `/home/ankit/HuntMCP`.
2. Confirm the current branch.
3. Confirm `git worktree list`.
4. If the current physical worktree is not `/home/ankit/HuntMCP`, STOP and report it.
5. If already on an unrelated branch, do not switch silently; report it.

Parallel work is allowed, but MUST NOT create multiple physical git worktrees.

This also applies to tool- or skill-driven worktree creation (for example, an `EnterWorktree`-style native tool or the Superpowers `using-git-worktrees` skill). For HuntMCP, decline such mechanisms and continue in `/home/ankit/HuntMCP` on the appropriate branch instead.

Do not silently:
- create a worktree
- switch to a worktree
- switch branches
- merge
- rebase
- force-push
- delete branches
- reset or clean user changes.

This rule is permanent for HuntMCP and exists specifically to prevent filesystem/state fragmentation across AI sessions.

## Existing user changes

Protect unrelated user changes.

Never run destructive cleanup commands such as `git clean -fd`, `git reset --hard`, or broad deletion commands without explicit authorization.

## Branch discipline

Keep changes on the intended branch, within the single physical worktree above.

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

## Branch cleanup

Do not delete a branch until its work has been verified as safely merged or intentionally discarded, and only when explicitly instructed.
