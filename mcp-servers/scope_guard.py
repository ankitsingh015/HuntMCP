"""Scope gate — validated once per engagement, checked cheaply on every call.

Design: HuntBrain writes engagement.yaml ONCE at the start of an engagement,
after the user hands over program/scope details. Every Tier-2 (execution-
capable) agent then calls this before touching a target — a plain string/
suffix match against the already-parsed in-scope list, no LLM call, no
re-analysis. This is what actually blocks an out-of-scope request; it costs
nothing to run on every single call.

CLI usage (what agents actually run via Bash before a Tier-2 action):
    python3 mcp-servers/scope_guard.py <host-or-url>
    exit 0  -> in scope, proceed
    exit 1  -> NOT in scope (or no engagement.yaml at all) — stop, do not run
               the tool call that would have followed
"""

from __future__ import annotations

import fnmatch
import os
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_PATH = os.getenv("HUNTMCP_ENGAGEMENT_PATH", "engagement.yaml")


@dataclass
class Engagement:
    target: str
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    program_url: str = ""
    authorized_on: str = ""


class NoEngagementFile(Exception):
    pass


def load_engagement(path: str = DEFAULT_PATH) -> Engagement:
    if not os.path.isfile(path):
        raise NoEngagementFile(
            f"No engagement file at {path!r}. HuntBrain must write this once at "
            "Phase 0 (target, in_scope, out_of_scope, program_url, authorized_on) "
            "before any Tier-2 agent runs. See engagement.yaml.example."
        )
    if yaml is None:
        raise RuntimeError("PyYAML not installed. pip install pyyaml")
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return Engagement(
        target=data.get("target", ""),
        in_scope=data.get("in_scope", []) or [],
        out_of_scope=data.get("out_of_scope", []) or [],
        program_url=data.get("program_url", ""),
        authorized_on=data.get("authorized_on", ""),
    )


def _host_of(target: str) -> str:
    """Accept a bare host, a host:port, or a full URL and return just the host."""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split(":")[0].split("/")[0]


def _matches(host: str, pattern: str) -> bool:
    # supports exact host, "*.example.com" wildcard subdomain patterns
    return fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(host, pattern.lstrip("*."))


def is_in_scope(target: str, engagement: Engagement) -> bool:
    host = _host_of(target)
    for pattern in engagement.out_of_scope:
        if _matches(host, pattern):
            return False
    return any(_matches(host, pattern) for pattern in engagement.in_scope)


def _cli() -> None:
    if len(sys.argv) != 2:
        print("usage: python3 mcp-servers/scope_guard.py <host-or-url>", file=sys.stderr)
        sys.exit(2)

    target = sys.argv[1]
    try:
        engagement = load_engagement()
    except (NoEngagementFile, RuntimeError) as e:
        print(f"BLOCKED: {e}", file=sys.stderr)
        sys.exit(1)

    if is_in_scope(target, engagement):
        print(f"IN SCOPE: {target} (engagement: {engagement.target})")
        sys.exit(0)
    else:
        print(
            f"BLOCKED: {target} is NOT in the in_scope list for this engagement "
            f"({engagement.target}). Refusing to proceed — do not work around this.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    _cli()
