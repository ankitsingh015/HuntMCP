"""Structured audit log (Phase 2.8 backlog) -- every Tier-2 tool call,
one JSON line, so a real engagement can be reviewed after the fact.

Wired into tool_resolver.run_tool()'s shared chokepoint, same pattern as
budget_guard.py. Appends to data/audit.jsonl (gitignored -- real target
names/args are exactly what shouldn't be in git).
"""

from __future__ import annotations

import json
import os
import time

LOG_PATH = os.getenv(
    "HUNTMCP_AUDIT_LOG",
    os.path.join(os.path.dirname(__file__), "..", "data", "audit.jsonl"),
)


def log_call(tool: str, args: list[str], returncode: int | None,
             duration_ms: float, block: str | None) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": tool,
        "args": args,
        "returncode": returncode,
        "duration_ms": round(duration_ms, 1),
        "block": block,
    }
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
