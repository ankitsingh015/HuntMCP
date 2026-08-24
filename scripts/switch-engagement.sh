#!/usr/bin/env bash
# Thin wrapper so HuntBrain can switch/establish the active per-target
# engagement as a plain command -- this is what makes multi-target hunting
# safe: state for a target not currently active is never touched.
# Usage:
#   scripts/switch-engagement.sh set <target>   -> prints the target's slug
#   scripts/switch-engagement.sh current        -> prints the active slug+dir
#   scripts/switch-engagement.sh list           -> JSON, every known engagement
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/engagement_paths.py" "$@"
