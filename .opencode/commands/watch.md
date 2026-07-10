---
description: Start, stop, or check continuous monitoring of a target. Tracks subdomains, endpoints, and alerts on changes.
---

# Watch Command — Continuous Monitoring

Watch a target for changes over time. Detects new subdomains, new endpoints, and changes in live hosts.

## Usage

```
/watch start <target> [--interval 6]    Start watching a target (default check every 6h)
/watch stop <target>                     Stop watching a target
/watch list                              List all watched targets
/watch check <target>                    Manually trigger a change check
/watch history <target>                  Show watch events for a target
```

## How it works

1. First run captures a snapshot (subdomains via subfinder, endpoints via katana).
2. Subsequent checks diff against the last snapshot.
3. New subdomains are probed with httpx to check if they're live.
4. All changes are logged to the watch database.
5. Critical changes (new live subdomains) are flagged with higher severity.

## Cron Setup

For automatic periodic checks, run:

```bash
./scripts/setup-watch.sh
```

This adds a cron entry that checks all active watched targets every 6 hours (configurable per target).

## Example

```bash
/openwatch start example.com --interval 6
# → Started watching example.com (interval: 6h)

# Check manually
/openwatch check example.com
# → Changes detected: 2 new subdomains, 5 new endpoints

# View history
/openwatch history example.com
# → Shows all watch events chronologically
```
