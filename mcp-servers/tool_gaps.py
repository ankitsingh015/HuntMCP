"""Tool-gap capture -- the bounded first step toward ARCHITECTURE.md's
"self-expanding toolkit" mechanic (an agent authoring new MCP servers/
skills when it hits a technique gap with no matching tool).

Deliberately NOT full autonomous tool-authoring: an agent that writes new
code and then runs that same code against a live target, unsupervised, is
a meaningfully bigger and riskier feature than what this builds. This is
the safe, useful slice of that idea -- gaps get captured in a structured,
queryable place instead of silently dropped (which is what happened
before this existed, per huntbrain.md's Phase 6 item 17: "note it for a
follow-up tool-building pass... rather than silently dropping the gap" had
no actual mechanism behind the word "note"). Building the actual new tool
or skill for a captured gap is still a normal human-in-the-loop coding
task -- ask Claude Code to build it in a regular session, same as
everything else in mcp-servers/ and .claude/skills/ was built. Whatever
gets built that way should then be checked with
mcp-servers/content_scanner.py before being trusted, same as any other
new skill/tool content.

Recording is deliberately cheap and low-friction (no LLM call, just a
JSONL append) so agents actually do it instead of skipping it under time
pressure. list_gaps()'s grouping by technique is the actual signal worth
watching: a gap noted once might be a one-off; the same technique
recurring across engagements is real evidence a tool is worth building --
which is also why this file is deliberately GLOBAL (data/tool-gaps.jsonl),
not per-target like engagement.yaml/budget.json. Siloing gaps inside each
target's own data/engagements/<slug>/ directory (mcp-servers/
engagement_paths.py's pattern for state that must never mix across
targets) would defeat the actual point here: recurrence is only visible
if every engagement's gaps land in the same place.

CLI usage (what huntbrain.md's Phase 6 runs when it hits a gap):
    python3 mcp-servers/tool_gaps.py record <technique> <context> [suggested_tool_name]
        -> prints the gap id
    python3 mcp-servers/tool_gaps.py list [--status open|resolved|all]
        -> human-readable list, grouped by technique with counts
    python3 mcp-servers/tool_gaps.py resolve <gap_id> [resolved_by]
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid

DEFAULT_PATH = os.getenv(
    "HUNTMCP_TOOL_GAPS_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "tool-gaps.jsonl"),
)


def _load(path: str = DEFAULT_PATH) -> list[dict]:
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


def _append(entry: dict, path: str = DEFAULT_PATH) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _rewrite(entries: list[dict], path: str = DEFAULT_PATH) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.writelines(json.dumps(e) + "\n" for e in entries)


def record_gap(technique: str, context: str, suggested_tool_name: str = "",
               path: str = DEFAULT_PATH) -> str:
    """Record a technique that had no matching MCP tool/skill during an
    engagement. Returns the gap id."""
    gap_id = uuid.uuid4().hex[:8]
    entry = {
        "id": gap_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "technique": technique,
        "context": context,
        "suggested_tool_name": suggested_tool_name,
        "status": "open",
        "resolved_by": None,
        "resolved_at": None,
    }
    _append(entry, path)
    return gap_id


def list_gaps(status: str = "open", path: str = DEFAULT_PATH) -> list[dict]:
    entries = _load(path)
    if status == "all":
        return entries
    return [e for e in entries if e.get("status") == status]


def gap_counts_by_technique(status: str = "open", path: str = DEFAULT_PATH) -> dict[str, int]:
    """The actual signal worth watching -- a technique recurring across
    multiple gap reports is real evidence a tool is worth building, not
    just a one-off engagement quirk."""
    counts: dict[str, int] = {}
    for e in list_gaps(status=status, path=path):
        counts[e["technique"]] = counts.get(e["technique"], 0) + 1
    return counts


def resolve_gap(gap_id: str, resolved_by: str = "", path: str = DEFAULT_PATH) -> bool:
    entries = _load(path)
    found = False
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for e in entries:
        if e.get("id") == gap_id:
            e["status"] = "resolved"
            e["resolved_by"] = resolved_by
            e["resolved_at"] = now
            found = True
    if found:
        _rewrite(entries, path)
    return found


def _cli() -> None:
    if len(sys.argv) < 2:
        print("usage: tool_gaps.py <record|list|resolve> ...", file=sys.stderr)
        sys.exit(2)

    cmd = sys.argv[1]
    if cmd == "record":
        if len(sys.argv) < 4:
            print("usage: tool_gaps.py record <technique> <context> [suggested_tool_name]", file=sys.stderr)
            sys.exit(2)
        technique, context = sys.argv[2], sys.argv[3]
        suggested = sys.argv[4] if len(sys.argv) > 4 else ""
        gap_id = record_gap(technique, context, suggested)
        print(gap_id)
    elif cmd == "list":
        status = "open"
        if len(sys.argv) > 2 and sys.argv[2] == "--status" and len(sys.argv) > 3:
            status = sys.argv[3]
        entries = list_gaps(status=status)
        if not entries:
            print(f"No {status} tool gaps recorded.")
            return
        counts = gap_counts_by_technique(status=status)
        print(f"{len(entries)} {status} gap(s), by technique:")
        for technique, count in sorted(counts.items(), key=lambda kv: -kv[1]):
            flag = "  <- recurring, worth building" if count >= 2 else ""
            print(f"  {technique}: {count}{flag}")
        print()
        for e in entries:
            print(f"  [{e['id']}] {e['technique']} -- {e['context']} (seen {e['ts']})")
    elif cmd == "resolve":
        if len(sys.argv) < 3:
            print("usage: tool_gaps.py resolve <gap_id> [resolved_by]", file=sys.stderr)
            sys.exit(2)
        gap_id = sys.argv[2]
        resolved_by = sys.argv[3] if len(sys.argv) > 3 else ""
        if not resolve_gap(gap_id, resolved_by):
            print(f"BLOCKED: no such gap id {gap_id!r}", file=sys.stderr)
            sys.exit(1)
        print(f"resolved {gap_id}")
    else:
        print(f"unknown command {cmd!r}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    _cli()
