"""Read-by-path/label access to captured identities (#128).

A small reader over the per-engagement `secrets/identities.json` +
`secrets/sessions/<label>.json` that `session_capture.finish_capture` writes.
It exists so downstream, server-side tools can consume a captured identity by
LABEL/PATH -- never by the agent pasting raw cookie/bearer values back through
the transcript.

This slice provides the reader; wiring idor-mcp / ws-rpc-mcp to call it (so
they accept an `identity_label` instead of inline `cookie_header`/
`bearer_token`) is a deliberate follow-up, not done here. `browser-mcp` tools
already consume by `session_file=` path, so they need no change.

These functions return secret-bearing material (a Cookie header, an
Authorization header, a session_file path) and are for IN-PROCESS use only;
nothing here is an MCP tool, and no secret value is ever returned to the agent.
"""

from __future__ import annotations

import json
import os

import engagement_paths


def _identities_path(slug: str | None = None) -> str:
    return engagement_paths.resolve("secrets/identities.json")


def _load_entry(label: str, slug: str | None = None) -> dict | None:
    path = _identities_path(slug)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        data = json.load(f) or {}
    entry = data.get(label)
    return entry if isinstance(entry, dict) else None


def get_headers(label: str, slug: str | None = None) -> dict:
    """In-process: assemble {"Cookie": ..., "Authorization": ...} for label
    from identities.json. Empty keys are omitted; {} when the identity or file
    is absent. Never returned to the agent."""
    entry = _load_entry(label, slug)
    if entry is None:
        return {}
    headers: dict[str, str] = {}
    cookies = entry.get("cookies") or []
    cookie_header = "; ".join(
        f"{c['name']}={c['value']}" for c in cookies if c.get("name")
    )
    if cookie_header:
        headers["Cookie"] = cookie_header
    authorization = entry.get("authorization")
    if authorization:
        headers["Authorization"] = authorization
    return headers


def get_session_file(label: str, slug: str | None = None) -> str | None:
    """Path to the per-identity filtered Playwright storage_state file for
    label, or None if it has not been captured. Consumed by browser-mcp tools
    as `session_file=`."""
    path = engagement_paths.resolve(f"secrets/sessions/{label}.json")
    return path if os.path.isfile(path) else None
