#!/usr/bin/env bash
# Thin wrapper for recording/reviewing tool gaps -- techniques with no
# matching MCP tool/skill hit during an engagement. See
# mcp-servers/tool_gaps.py's module docstring for the full design (this is
# capture only, not autonomous tool-authoring).
# Usage:
#   scripts/tool-gaps.sh record <technique> <context> [suggested_tool_name]
#   scripts/tool-gaps.sh list [--status open|resolved|all]
#   scripts/tool-gaps.sh resolve <gap_id> [resolved_by]
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/tool_gaps.py" "$@"
