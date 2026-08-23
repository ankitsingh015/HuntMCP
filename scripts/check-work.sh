#!/usr/bin/env bash
# Thin wrapper so HuntBrain can check/record specialist-agent work as a
# plain command, without depending on its own conversation context (which
# can get compacted mid-engagement) to remember what's already running.
# Usage:
#   scripts/check-work.sh start <agent> <host> [task]   -> prints work_id
#   scripts/check-work.sh complete <work_id> [outcome]
#   scripts/check-work.sh active [host]                 -> JSON, check before spawning
#   scripts/check-work.sh all                           -> JSON, full history
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/work_registry.py" "$@"
