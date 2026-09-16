#!/usr/bin/env bash
# Thin wrapper so a HUMAN -- never an agent, see mcp-servers/hook_confirm.py's
# own isatty() refusal -- can explicitly authorize a maintenance window of
# edits to scope_gate_hook.py and its hook-tamper-resistance dependencies
# before scope_gate_hook.py's own PreToolUse check will let an Edit/Write/
# Bash write to one of those protected paths through.
# Must be run directly in your own terminal, not piped or backgrounded --
# it refuses immediately if stdin isn't a real TTY.
# Usage: scripts/confirm-hook-edit.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/hook_confirm.py"
