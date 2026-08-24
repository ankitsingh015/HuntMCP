#!/usr/bin/env bash
# Thin wrapper so exploit-agent can call the finding-level dedup check as a
# plain command, right before finalizing a CONFIRMED verdict.
# Usage: scripts/check-dedupe.sh <vuln_class> <endpoint> [parameter]
# Exit 0 = new finding, recorded. Exit 1 = duplicate this engagement.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/dedupe_check.py" "$@"
