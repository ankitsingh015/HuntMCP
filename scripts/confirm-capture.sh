#!/usr/bin/env bash
# Thin wrapper so a HUMAN -- never an agent, see mcp-servers/capture_confirm.py's
# isatty() refusal -- can confirm ONE session capture after logging in by hand
# in the window session_capture.start_capture opened. Run it directly in your
# own terminal; it refuses if stdin is not a TTY.
# Usage: scripts/confirm-capture.sh <slug> <label> <fingerprint>
#   The fingerprint is printed by start_capture and binds the exact login URL
#   the agent opened. finish_capture then refuses unless this fresh, matching
#   confirmation exists.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/capture_confirm.py" "$@"
