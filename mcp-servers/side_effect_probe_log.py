"""Side-effecting-endpoint probe log -- a post-engagement check for
whether any probe against an endpoint with a real-world human side effect
(it creates a human-visible artifact: a support ticket, an email to a real
person, a public comment) may have actually succeeded.

Why this exists: an agent's hard constraint is "never send a request that
can succeed" against such an endpoint, but the success/failure boundary is
often unknown in advance -- reported live in an engagement retrospective:
one probe the backend apparently treated as acceptable (the request timed
out instead of returning a clean validation error) may have created a real
artifact with a disposable, unroutable contact address. The agent honestly
reported the anomaly and did not repeat it, but there was no structured
place to record "this specific probe's outcome was uncertain" for a human
to review afterward -- it was narrative only.

This module is the record-keeping half of that fix (see also
.claude/agents/exploit-agent.md's own guidance on using a provably-invalid
required field as defense in depth on every such probe). Every probe
against a side-effecting endpoint gets one row: the endpoint, which field
was set to a value that should be impossible to accept, the response
status, and an explicit `response_indicates_rejection` judgment call
(True = a clean validation error, matching what was expected; False =
uncertain -- a timeout, an unexpected status, or anything else that isn't
a confirmed clean rejection). list_probes(status="uncertain") is the
actual post-engagement check: every row where success could not be ruled
out, in one place, instead of buried in a transcript.

State is per-engagement, reset alongside engagement.yaml/budget.json.

CLI usage:
    python3 mcp-servers/side_effect_probe_log.py record <endpoint> <provably_invalid_field> \\
        <response_status|none> <rejected|uncertain> [note]
        -> prints the probe id
    python3 mcp-servers/side_effect_probe_log.py list [--status rejected|uncertain|all]
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

DEFAULT_PATH = engagement_paths.resolve("side-effect-probes.jsonl", override_env="HUNTMCP_SIDE_EFFECT_PROBES_PATH")


def _resolve_path(path: str | None) -> str:
    if path is not None:
        return path
    return engagement_paths.resolve("side-effect-probes.jsonl", override_env="HUNTMCP_SIDE_EFFECT_PROBES_PATH")


def _load(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
    return entries


def _append(entry: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def record_probe(endpoint: str, provably_invalid_field: str, response_status: int | None,
                  response_indicates_rejection: bool, note: str = "", path: str | None = None) -> str:
    """Returns the probe id."""
    path = _resolve_path(path)
    probe_id = uuid.uuid4().hex[:8]
    entry = {
        "id": probe_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "endpoint": endpoint,
        "provably_invalid_field": provably_invalid_field,
        "response_status": response_status,
        "response_indicates_rejection": response_indicates_rejection,
        "note": note,
    }
    _append(entry, path)
    return probe_id


def list_probes(status: str = "all", path: str | None = None) -> list[dict]:
    """status: "rejected" (response_indicates_rejection True), "uncertain"
    (False -- the actual post-engagement review list), or "all"."""
    path = _resolve_path(path)
    entries = _load(path)
    if status == "all":
        return entries
    if status == "rejected":
        return [e for e in entries if e.get("response_indicates_rejection") is True]
    if status == "uncertain":
        return [e for e in entries if e.get("response_indicates_rejection") is False]
    return []


def _cli() -> None:
    if len(sys.argv) < 2:
        print("usage: side_effect_probe_log.py <record|list> ...", file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "record":
        if len(sys.argv) < 6:
            print("usage: side_effect_probe_log.py record <endpoint> <provably_invalid_field> "
                  "<response_status|none> <rejected|uncertain> [note]", file=sys.stderr)
            sys.exit(2)
        endpoint, field, status_raw, verdict = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
        response_status = None if status_raw.lower() == "none" else int(status_raw)
        rejected = verdict == "rejected"
        note = sys.argv[6] if len(sys.argv) > 6 else ""
        print(record_probe(endpoint, field, response_status, rejected, note))
    elif cmd == "list":
        status = "all"
        if len(sys.argv) > 2 and sys.argv[2] == "--status" and len(sys.argv) > 3:
            status = sys.argv[3]
        print(json.dumps(list_probes(status=status), indent=2))
    else:
        print(f"unknown command {cmd!r}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    _cli()
