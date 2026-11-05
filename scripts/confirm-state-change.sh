#!/usr/bin/env bash
# Thin wrapper so a HUMAN -- never an agent, see mcp-servers/rce_confirm.py's isatty() refusal --
# can authorize ONE state-changing P3-VALAUTHZ replay (replay_authz_two_step with a POST/PUT/PATCH/
# DELETE step) against one host. Run it directly in your own terminal; it refuses if stdin is not a TTY.
# Usage: scripts/confirm-state-change.sh <host[:port]> <METHOD[,METHOD...]> [fingerprint]
#   e.g. scripts/confirm-state-change.sh api.target.com POST <32-hex fingerprint>
#   The tool's BLOCKED message prints the exact command, including the fingerprint of the exact
#   URLs / methods / body hash / accounts it will send; this prompt then shows what the tool wrote
#   for that fingerprint -- read it before you type the confirmation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/state_change_confirm.py" "$@"
