"""Structured audit log (Phase 2.8 backlog) -- every Tier-2 tool call,
one JSON line, so a real engagement can be reviewed after the fact.

Wired into tool_resolver.run_tool()'s shared chokepoint, same pattern as
budget_guard.py. Appends to data/audit.jsonl (gitignored -- real target
names/args are exactly what shouldn't be in git).
"""

from __future__ import annotations

import json
import os
import sys
import time

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

_LEGACY_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "audit.jsonl")
LOG_PATH = engagement_paths.resolve(
    "audit.jsonl", override_env="HUNTMCP_AUDIT_LOG", legacy_default=_LEGACY_LOG_PATH,
)


def log_call(tool: str, args: list[str], returncode: int | None,
             duration_ms: float, block: str | None, path: str = LOG_PATH) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": tool,
        "args": args,
        "returncode": returncode,
        "duration_ms": round(duration_ms, 1),
        "block": block,
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
