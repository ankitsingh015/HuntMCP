#!/usr/bin/env bash
# Isolates one terminal's engagement session so multiple opencode/claude
# sessions can hunt DIFFERENT targets at the SAME TIME without one
# session's "active engagement" pointer stomping another's.
#
# Per-target STATE was already isolated (data/engagements/<slug>/
# engagement.yaml, budget.json, work-registry.json, findings-seen.json,
# downloads/ -- see mcp-servers/engagement_paths.py's own module
# docstring). What was NOT isolated: which target is "active" right now
# was tracked by a single shared file, data/.active-engagement, read/
# written by every session on this machine. Two people (or two chat
# sessions) hunting two different targets at once would each overwrite
# that same pointer -- session A calls `switch-engagement.sh set
# company-a.com`, session B then calls `set company-b.com`, and session
# A's NEXT tool call would silently start reading/writing company-b's
# budget/scope/dedup state instead of its own, even though company-a's
# files themselves were never touched.
#
# Fix: engagement_paths.py already supports HUNTMCP_ACTIVE_POINTER as an
# env var override (ACTIVE_POINTER = os.getenv(...)) -- it just wasn't
# wired into an easy workflow. An env var set on the actual opencode/
# claude PROCESS itself (not inside one of its own Bash tool calls -- see
# engagement_paths.py's docstring on why a file, not an env var, is used
# for WITHIN-session persistence) is inherited by every subprocess that
# process spawns for its entire lifetime, so pointing each session's
# HUNTMCP_ACTIVE_POINTER at its own file before launching it gives each
# session a private "active target" that no other session can see or
# overwrite, while still sharing the exact same per-target data/
# directories underneath (so the isolation added here is purely about the
# pointer, not a second copy of the data).
#
# USAGE -- must be SOURCED (not executed) so the export reaches the shell
# you go on to launch opencode/claude from:
#   source scripts/new-target-session.sh <target>
#   opencode run "HuntMCP audit <target>"
# A second, completely separate terminal doing the same for a different
# target runs fully in parallel -- neither can see or touch the other's
# active-target pointer, and `switch-engagement.sh current`/`list` inside
# each session only ever reports its own.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "This script must be SOURCED, not executed, so its 'export' reaches your shell:" >&2
  echo "  source ${BASH_SOURCE[0]} <target>" >&2
  exit 1
fi

if [[ -z "${1:-}" ]]; then
  echo "usage: source ${BASH_SOURCE[0]} <target>" >&2
  return 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SLUG="$(python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR/../mcp-servers')
import engagement_paths
print(engagement_paths.slugify(sys.argv[1]))
" "$1")"

export HUNTMCP_ACTIVE_POINTER="data/.active-engagement-${SLUG}"
python3 "$SCRIPT_DIR/../mcp-servers/engagement_paths.py" set "$1" >&2

echo "HUNTMCP_ACTIVE_POINTER=${HUNTMCP_ACTIVE_POINTER} exported in THIS shell." >&2
echo "Launch opencode/claude from this same terminal now -- it (and every Bash" >&2
echo "tool call it makes) will hunt '$1' without any other session's" >&2
echo "switch-engagement.sh affecting it, or being affected by it." >&2
