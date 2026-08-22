#!/usr/bin/env bash
# Pick a model provider (explicit override or automatic fallback chain, see
# mcp-servers/model_gateway.py) and apply it to opencode.jsonc so the next
# `opencode run` actually uses it. Run this before opencode, not instead of
# it -- it only patches config, it doesn't launch anything itself.
#
# Usage:
#   scripts/select-model.sh              # apply the global default
#   scripts/select-model.sh exploit      # preview what agent role "exploit"
#                                         # would get (role overrides don't
#                                         # patch opencode.jsonc -- OpenCode
#                                         # has one global model, not
#                                         # per-agent; use HUNTMCP_MODEL_*
#                                         # only for a future API-runner
#                                         # harness that reads per-role)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" != "" ]; then
  echo "Preview only for role '$1' -- opencode.jsonc has one global model, not per-agent:"
  exec python3 "$SCRIPT_DIR/../mcp-servers/model_gateway.py" "$1"
fi

exec python3 "$SCRIPT_DIR/../mcp-servers/model_gateway.py" --apply
