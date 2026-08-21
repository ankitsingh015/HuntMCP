#!/usr/bin/env bash
# Thin wrapper so agents can call the scope gate as a plain command.
# Usage: scripts/check-scope.sh <host-or-url>
# Exit 0 = in scope, proceed. Exit non-zero = STOP, do not run the tool call
# that would have followed.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/scope_guard.py" "$@"
