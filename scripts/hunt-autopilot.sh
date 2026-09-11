#!/usr/bin/env bash
# hunt-autopilot.sh -- outer supervisor for autonomous, cross-session HuntMCP work.
#
# Runs OUTSIDE any Claude session (a normal shell). It loops:
#     read persisted state -> select one coherent task group
#       -> start a FRESH `claude -p` session to execute it
#       -> independently re-verify + checkpoint
#       -> start the next fresh session ... until done / STOP / a safety limit.
#
# It never bypasses Claude Code permissions (no --dangerously-skip-permissions),
# never performs git writes, never crosses worktrees, and STOPs on any human
# decision. See .claude/dev-runner.md for the full contract.
#
# Usage (from the repo/worktree root):
#     ./scripts/hunt-autopilot.sh --dry-run          # plan only, NO session runs
#     ./scripts/hunt-autopilot.sh                     # run, safe defaults
#     ./scripts/hunt-autopilot.sh --max-sessions 5 --max-group-size 2 \
#         --expected-branch claude/phase1-cem-implementation-6e1693
#
# Exit codes: 0 = done / dry-run, 2 = stopped (needs a human).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="$REPO_ROOT/scripts"

# Shell-level recursion guard: if we are already inside an autopilot-launched
# session, refuse to start another supervisor.
if [ "${HUNTMCP_AUTOPILOT_ACTIVE:-}" = "1" ]; then
  echo "REFUSING: HUNTMCP_AUTOPILOT_ACTIVE=1 -- already inside an autopilot session." >&2
  echo "The supervisor must be run from a normal shell, not from within a Claude session." >&2
  exit 2
fi

# Resolve a venv Python the same way scripts/venv-python.sh does (worktree-safe).
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

# Default --repo to this worktree root unless the caller passed one.
have_repo=0
for arg in "$@"; do
  if [ "$arg" = "--repo" ]; then have_repo=1; break; fi
done

export PYTHONPATH="$SCRIPTS_DIR${PYTHONPATH:+:$PYTHONPATH}"
if [ "$have_repo" -eq 1 ]; then
  exec "$PY" -m runner.supervisor "$@"
else
  exec "$PY" -m runner.supervisor --repo "$REPO_ROOT" "$@"
fi
