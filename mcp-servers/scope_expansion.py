"""Candidate scope-expansion registry: pure bookkeeping for out-of-scope
hosts an agent notices are plausibly related to an in-scope host (e.g.
sharing the same TLS certificate/SAN list, a linked subdomain discovered
during recon), paired with a human approve/reject decision.

Deliberately NOT an auto-expansion mechanism -- recording or even
"approving" a candidate here never touches engagement.yaml itself, the same
"policy judgment stays human" principle scope_guard.detect_scope_conflicts()
already established for scope diagnostics. Approving a candidate still
requires the human operator to add it to engagement.yaml's in_scope by hand;
this registry only tracks the discovery + decision trail so a candidate
never gets silently investigated then forgotten, without ever letting a
tool call widen scope on its own.

Global, not per-engagement (same reasoning as tool_gaps.py): a candidate
recorded during one engagement is meaningless once that engagement ends, so
this could reasonably be per-engagement too, but keeping one shared,
append-only log across the whole toolkit's history means a human reviewing
"what expansion candidates have ever come up" doesn't need to hunt across
every past engagement's own directory -- and, like tool_gaps.py, nothing
here is ever auto-actioned, so cross-engagement visibility carries none of
the cross-target state-isolation risk engagement_paths.py exists to prevent
for actually-enforced state (scope, budget, dedup).

CLI usage:
    python3 mcp-servers/scope_expansion.py record <host> <evidence> <related_in_scope_host>
        -> prints the candidate id
    python3 mcp-servers/scope_expansion.py list [--status pending|approved|rejected|all]
    python3 mcp-servers/scope_expansion.py decide <candidate_id> approved|rejected [decided_by]
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid

DEFAULT_PATH = os.getenv(
    "HUNTMCP_SCOPE_EXPANSION_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "scope-expansion.jsonl"),
)

DECISIONS = {"approved", "rejected"}


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


def record_candidate(host: str, evidence: str, related_in_scope_host: str,
                      path: str = DEFAULT_PATH) -> str:
    """Record a host noticed as plausibly related to an already-in-scope
    host, with a free-text note on WHY (e.g. "shares the in-scope TLS cert
    (same SAN list) as app.example.com"). Returns the candidate id. Pure
    bookkeeping -- does not touch engagement.yaml, does not affect
    is_in_scope()'s enforcement in any way."""
    cand_id = uuid.uuid4().hex[:8]
    entry = {
        "id": cand_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": host,
        "evidence": evidence,
        "related_in_scope_host": related_in_scope_host,
        "status": "pending",
        "decided_by": None,
        "decided_at": None,
    }
    _append(entry, path)
    return cand_id


def list_candidates(status: str = "pending", path: str = DEFAULT_PATH) -> list[dict]:
    entries = _load(path)
    if status == "all":
        return entries
    return [e for e in entries if e.get("status") == status]


def decide_candidate(candidate_id: str, decision: str, decided_by: str = "",
                      path: str = DEFAULT_PATH) -> bool:
    """Record a human decision (approved/rejected) on a candidate. Returns
    False, without mutating anything, for an unknown id or an invalid
    decision -- an invalid decision must not silently leave the candidate
    in some other unintended state. Approving does NOT add the host to
    engagement.yaml; the human operator still does that by hand."""
    if decision not in DECISIONS:
        return False
    entries = _load(path)
    found = False
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for e in entries:
        if e.get("id") == candidate_id:
            e["status"] = decision
            e["decided_by"] = decided_by
            e["decided_at"] = now
            found = True
    if found:
        _rewrite(entries, path)
    return found


def _cli() -> None:
    if len(sys.argv) < 2:
        print("usage: python3 mcp-servers/scope_expansion.py record|list|decide ...", file=sys.stderr)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "record" and len(sys.argv) >= 5:
        print(record_candidate(sys.argv[2], sys.argv[3], sys.argv[4]))
    elif cmd == "list":
        status = "pending"
        if "--status" in sys.argv:
            status = sys.argv[sys.argv.index("--status") + 1]
        for e in list_candidates(status=status):
            print(f"{e['id']}  [{e['status']}]  {e['host']}  (related to {e['related_in_scope_host']})")
    elif cmd == "decide" and len(sys.argv) >= 4:
        decided_by = sys.argv[4] if len(sys.argv) >= 5 else ""
        ok = decide_candidate(sys.argv[2], sys.argv[3], decided_by=decided_by)
        print("ok" if ok else "not found or invalid decision")
        sys.exit(0 if ok else 1)
    else:
        print("usage: python3 mcp-servers/scope_expansion.py record <host> <evidence> <related_in_scope_host>"
              " | list [--status pending|approved|rejected|all] | decide <id> approved|rejected [decided_by]",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _cli()
