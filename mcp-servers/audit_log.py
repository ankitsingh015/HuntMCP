"""Structured audit log (Phase 2.8 backlog) -- every Tier-2 tool call,
one JSON line, so a real engagement can be reviewed after the fact.

Wired into tool_resolver.run_tool()'s shared chokepoint, same pattern as
budget_guard.py. Appends to data/audit.jsonl (gitignored -- real target
names/args are exactly what shouldn't be in git, on top of which this
file can outlive the conversation it came from and get reviewed/shared
later, unlike args that only ever flow through an agent's own context).

Every arg is passed through redact.redact_text() before it's written --
a caller passing a raw URL (the common case: idor-mcp/browser-mcp/curl-rl.sh
log the exact url they hit) with a token/api_key/password in its query
string, or a Cookie/Authorization header line captured as an arg, gets
redacted here at the one shared chokepoint rather than needing every
caller to remember to redact its own args first. See redact.py's own
module docstring for why this is name/shape-based, never entropy-based --
the object ids this log is often USED to review (which id did that IDOR
sweep test?) are exactly the high-entropy-looking values that must survive
untouched.
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

try:
    from redact import redact_text
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from redact import redact_text

_LEGACY_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "audit.jsonl")
LOG_PATH = engagement_paths.resolve(
    "audit.jsonl", override_env="HUNTMCP_AUDIT_LOG", legacy_default=_LEGACY_LOG_PATH,
)


def log_call(tool: str, args: list[str], returncode: int | None,
             duration_ms: float, block: str | None, path: str = LOG_PATH) -> None:
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tool": tool,
        "args": [redact_text(a) for a in args],
        "returncode": returncode,
        "duration_ms": round(duration_ms, 1),
        "block": block,
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
