#!/usr/bin/env bash
# Thin wrapper for manually checking/refreshing the aggregated bounty-scope
# cache -- Tier 1 only, never touches a target. Complements the cron job
# from setup-bounty-scope-watch.sh for an on-demand check.
# Usage:
#   scripts/check-new-bounty-scope.sh                    -> refresh + list new (last 24h)
#   scripts/check-new-bounty-scope.sh since <hours>       -> list new in a custom window
#   scripts/check-new-bounty-scope.sh lookup <domain>     -> check one domain against the cache
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PYTHON="${PROJECT_DIR}/.venv/bin/python"
if [ ! -f "$PYTHON" ]; then
    PYTHON="python3"
fi

cmd="${1:-}"

if [ "$cmd" = "lookup" ]; then
    domain="${2:?usage: check-new-bounty-scope.sh lookup <domain>}"
    "$PYTHON" -c "
import sys
sys.path.insert(0, '${PROJECT_DIR}/mcp-servers')
import bounty_scope
matches = bounty_scope.lookup_domain('$domain')
if not matches:
    print(f'{\"$domain\"!r} not found in cached bounty-program scope.')
else:
    for m in matches:
        print(f\"[{m['platform']}] {m['program']} (eligible: {m['eligible_for_bounty']}) -- {m['program_url']}\")
"
    exit 0
fi

if [ "$cmd" = "since" ]; then
    hours="${2:-24}"
else
    hours=24
fi

"$PYTHON" -c "
import sys
sys.path.insert(0, '${PROJECT_DIR}/mcp-servers')
import bounty_scope
result = bounty_scope.refresh()
print(f'refresh: {result}')
events = bounty_scope.list_new_scope(since_hours=$hours)
if not events:
    print(f'No newly-added scope in the last ${hours}h.')
else:
    print(f'{len(events)} newly-added scope entries in the last ${hours}h:')
    for e in events:
        print(f\"  [{e['platform']}] {e['domain']} -- {e['program']} (seen {e['ts']})\")
"
