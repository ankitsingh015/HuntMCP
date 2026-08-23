#!/usr/bin/env bash
# Thin wrapper so HuntBrain can poll the budget circuit-breaker's status as
# a plain command, without waiting for a stderr warning to show up mid-run.
# Usage: scripts/check-budget.sh
# Prints {"calls", "max_calls", "pct_used", "band", "exceeded", "by_tool"} as JSON.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/../mcp-servers/budget_guard.py"
