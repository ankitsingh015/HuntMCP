#!/usr/bin/env bash
# venv-python.sh -- resolve the right venv Python interpreter and exec it.
#
# Why this exists: .mcp.json/opencode.jsonc used to hardcode
# "${CLAUDE_PROJECT_DIR:-.}/.venv/bin/python" directly. .venv/ is gitignored
# (never shared across git worktrees), and CLAUDE_PROJECT_DIR is not always
# set in every harness session -- when it's empty, that path falls back to
# "./.venv/bin/python" relative to cwd, which silently doesn't exist in any
# secondary worktree (only the main checkout has a real .venv). Every MCP
# server then fails to start, with no clear error surfaced to the caller.
#
# Fix: this script is a real, git-tracked file present in every worktree
# (unlike .venv itself), so .mcp.json/opencode.jsonc point at THIS instead
# of the venv directly. It tries, in order:
#   1. $CLAUDE_PROJECT_DIR/.venv/bin/python, if that env var is set
#   2. ./.venv/bin/python relative to this script's own repo root (covers
#      the common case: running from the main worktree, or a worktree that
#      got its own venv created deliberately)
#   3. the MAIN worktree's .venv, found via `git rev-parse --git-common-dir`
#      -- this always points at the primary .git dir shared by every
#      worktree, so this resolves correctly no matter which worktree we're
#      actually running from
#   4. system python3, as a last resort (so a missing venv degrades to
#      "wrong interpreter, maybe missing deps" rather than "nothing starts")
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

candidates=()
if [ -n "${CLAUDE_PROJECT_DIR:-}" ]; then
  candidates+=("$CLAUDE_PROJECT_DIR/.venv/bin/python")
fi
candidates+=("$HERE/.venv/bin/python")

if git_common_dir=$(git -C "$HERE" rev-parse --git-common-dir 2>/dev/null); then
  main_root="$(cd "$(dirname "$git_common_dir")" && pwd)"
  candidates+=("$main_root/.venv/bin/python")
fi

for py in "${candidates[@]}"; do
  if [ -x "$py" ]; then
    exec "$py" "$@"
  fi
done

exec python3 "$@"
