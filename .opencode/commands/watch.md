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

`start`/`check` run in the background (subfinder->httpx->katana chained
together can take longer than one MCP call is safely allowed to block) and
come back with a `job_id` immediately rather than the final result -- poll
`check_status(job_id)` every ~10-15s until it reports done. Running
`start`/`check` again for a target that already has a job in flight reuses
that job instead of starting a second, racing one.

## Cron Setup

For automatic periodic checks, run:

```bash
./scripts/setup-watch.sh
```

This adds a cron entry that checks all active watched targets every 6 hours (configurable per target).

## Example

```bash
/openwatch start example.com --interval 6
# → Started watching example.com (interval: 6h). Initial snapshot running
#   in background (job_id="..."). Poll check_status("...") until it
#   reports status=done.

# Poll until the snapshot is ready
/openwatch check_status <job_id>
# → Snapshot captured for example.com: 12 subdomain(s), 40 endpoint(s).

# Check manually
/openwatch check example.com
# → Started change check for example.com (job_id="..."). Poll
#   check_status("...") until it reports status=done.
/openwatch check_status <job_id>
# → Changes detected on example.com (2 event(s)): 2 new subdomains

# View history
/openwatch history example.com
# → Shows all watch events chronologically
```
