#!/usr/bin/env bash
# hunt-runner.sh -- entrypoint for the controlled, resumable HuntMCP dev-runner.
#
# The runner reads the persistent project plan (PHASE1-EXECUTION-PLAN.md +
# ROADMAP.md), determines the single next actionable task, generates the minimum
# execution context for it, and STOPs (asking for a human decision) at any
# ambiguity or safety boundary. It is READ-ONLY except for the `checkpoint`
# command, which writes a runner-owned JSON cache -- never the plan itself.
#
# Usage:
#   bash scripts/hunt-runner.sh status        # phase, counts, next action
#   bash scripts/hunt-runner.sh next           # just the next task / decision
#   bash scripts/hunt-runner.sh dry-run        # safe preview of the next task
#   bash scripts/hunt-runner.sh context        # generated task context
#   bash scripts/hunt-runner.sh check          # worktree safety only
#   bash scripts/hunt-runner.sh verify         # run mechanical checks + gate
#   bash scripts/hunt-runner.sh checkpoint     # write the resumable state cache
#
# Extra flags pass straight through, e.g.:
#   bash scripts/hunt-runner.sh dry-run --expected-branch claude/phase1-cem-implementation-6e1693
#   bash scripts/hunt-runner.sh status --plan /path/to/PHASE1-EXECUTION-PLAN.md --json
#
# Exit codes: 0 = OK / actionable / done, 2 = STOP (human decision required).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="$REPO_ROOT/scripts"

# Resolve a venv Python the same way scripts/venv-python.sh does, so this works
# from any worktree (where .venv is gitignored and may live only in the main
# checkout).
candidates=()
if [ -n "${CLAUDE_PROJECT_DIR:-}" ]; then
  candidates+=("$CLAUDE_PROJECT_DIR/.venv/bin/python")
fi
candidates+=("$REPO_ROOT/.venv/bin/python")
if git_common_dir=$(git -C "$REPO_ROOT" rev-parse --git-common-dir 2>/dev/null); then
  main_root="$(cd "$(dirname "$git_common_dir")" && pwd)"
  candidates+=("$main_root/.venv/bin/python")
fi
PY=""
for cand in "${candidates[@]}"; do
  if [ -x "$cand" ]; then PY="$cand"; break; fi
done
[ -n "$PY" ] || PY="python3"

export PYTHONPATH="$SCRIPTS_DIR${PYTHONPATH:+:$PYTHONPATH}"

# No arguments -> let argparse print its usage/error.
if [ "$#" -eq 0 ]; then
  exec "$PY" -m runner.cli
fi

# Default --repo to this worktree's root unless the caller already passed one,
# so the runner resolves the plan/roadmap correctly regardless of cwd. The flag
# is inserted right after the subcommand (argv[1]).
have_repo=0
for arg in "$@"; do
  if [ "$arg" = "--repo" ]; then have_repo=1; break; fi
done

subcmd="$1"; shift
if [ "$have_repo" -eq 1 ]; then
  exec "$PY" -m runner.cli "$subcmd" "$@"
else
  exec "$PY" -m runner.cli "$subcmd" --repo "$REPO_ROOT" "$@"
fi
