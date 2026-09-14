#!/usr/bin/env bash
# Thin wrapper so a HUMAN -- never an agent, see mcp-servers/rce_confirm.py's
# own isatty() refusal -- can explicitly authorize a persistent OS-shell /
# state-changing sqlmap action (--os-shell/--os-pwn/--os-cmd/--os-bof)
# before scope_gate_hook.py's PreToolUse check will let that command run.
# Must be run directly in your own terminal, not piped or backgrounded --
# it refuses immediately if stdin isn't a real TTY.
# Usage: scripts/confirm-os-shell.sh [target]
#   target defaults to the currently active engagement (see
#   `scripts/switch-engagement.sh current`) if omitted.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/rce_confirm.py" "$@"
