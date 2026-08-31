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
import ipaddress
import os
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None

try:
    import engagement_paths
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths

# Snapshot only, for introspection/backward-compat (e.g. printing the
# resolved path in a log line) -- load_engagement() below re-resolves this
# fresh on every call instead of using this frozen value; see its comment.
DEFAULT_PATH = engagement_paths.resolve("engagement.yaml", override_env="HUNTMCP_ENGAGEMENT_PATH")

# Hosts/patterns that never need an engagement.yaml at all, on either the
# real enforcement path (scripts/hooks/scope_gate_hook.py's PreToolUse hook)
# or this module's own CLI (scripts/check-scope.sh, which agents are
# instructed to run before touching any host). These two paths used to
# diverge -- the hook was lenient about them, this CLI was not, which meant
# an agent following its own instructions ("run check-scope.sh first") would
# self-block on a totally safe host (example.com, localhost, a github.com
# curl) the moment ANY engagement.yaml existed for a different target,
# something the actual enforcement never required. Fixed 2026-08-29 by
# making this the one shared source of truth both paths check.
SAFE_TEST_HOSTS = {
    "example.com", "example.org", "example.net", "localhost", "0.0.0.0",
}

# Deliberately NOT included above: evil.com/attacker.com/malicious.com.
# scope_gate_hook.py's own command-text host EXTRACTION filters those out
# separately (a CORS/CSRF PoC's `-H "Origin: https://evil.com"` is a header
# VALUE describing the attacker's origin, not a live target being
# contacted) -- but that's a narrower, different claim than "this host
# needs no authorization at all." Someone could genuinely own evil.com and
# put it in in_scope/out_of_scope; is_safe_test_host() answering True for
# it would make is_in_scope() ignore that entirely. Keep the two concerns
# separate: is_safe_test_host() is for "not really a target," the
# attacker-placeholder list is for "not really what this command is
# contacting" -- see scope_gate_hook.py's _ATTACKER_PLACEHOLDER_HOSTS.

# Ordinary development/package infrastructure a Tier-2 curl/wget or an
# agent's own tooling legitimately touches regardless of which target is
# currently engaged -- fetching a package, a docs page, a GitHub raw file.
# Not an allowlist for testing against someone's actual product.
DEV_INFRA_HOSTS = {
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "api.github.com", "codeload.github.com",
    "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "nodejs.org",
    "golang.org", "proxy.golang.org", "go.dev",
    "deb.debian.org", "archive.ubuntu.com", "security.ubuntu.com",
    "opencode.ai", "docs.anthropic.com", "modelcontextprotocol.io",
}

# A bare hostname-shaped regex can't distinguish a real domain from a
# filename with an extension (results.json, wordlist.txt) -- see
# scope_gate_hook.py's own comment on this for the full rationale. Kept here
# too since is_safe_test_host() is the shared authority both callers use.
NON_TLD_FILE_EXTENSIONS = {
    "txt", "json", "py", "md", "yaml", "yml", "csv", "html", "htm", "xml",
    "sh", "js", "ts", "log", "pdf", "zip", "tar", "gz", "cfg", "conf", "ini",
    "png", "jpg", "jpeg", "gif", "svg", "css", "sql", "db", "bak", "out",
}


def is_safe_test_host(host: str) -> bool:
    """True for a host that never needs an engagement.yaml or an explicit
    in_scope entry -- test/placeholder domains, private/loopback IPs, and
    well-known dev/package infrastructure. This is about "is this host even
    a live-target-shaped thing," not "is it authorized" -- a real target
    still goes through the normal in_scope/out_of_scope check."""
    host = host.lower().strip(".")
    if host in SAFE_TEST_HOSTS or host in DEV_INFRA_HOSTS:
        return True
    if host.rsplit(".", 1)[-1] in NON_TLD_FILE_EXTENSIONS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


@dataclass
class Engagement:
    target: str
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    program_url: str = ""
    authorized_on: str = ""


class NoEngagementFile(Exception):
    pass


def load_engagement(path: str | None = None) -> Engagement:
    # `path: str | None = None`, re-resolved fresh here on every call when
    # not given explicitly -- NOT `path: str = DEFAULT_PATH`. DEFAULT_PATH
    # is computed once at import time; binding it as a literal parameter
    # default freezes every future call onto whatever active-engagement
    # pointer existed at THAT moment (a stale one left in the real repo by
    # an earlier real audit, in the worst case -- confirmed live, this
    # silently pinned every scope check to the wrong engagement.yaml for
    # an entire process lifetime with no way to override it after the
    # fact) and never picks up a later `switch-engagement.sh` mid-session.
    # Re-resolving here instead makes every call reflect whichever
    # engagement is ACTUALLY active right now.
    if path is None:
        path = engagement_paths.resolve("engagement.yaml", override_env="HUNTMCP_ENGAGEMENT_PATH")
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
    if is_safe_test_host(host):
        return True
    for pattern in engagement.out_of_scope:
        if _matches(host, pattern):
            return False
    return any(_matches(host, pattern) for pattern in engagement.in_scope)


def _cli() -> None:
    if len(sys.argv) != 2:
        print("usage: python3 mcp-servers/scope_guard.py <host-or-url>", file=sys.stderr)
        sys.exit(2)

    target = sys.argv[1]

    # Check this BEFORE requiring an engagement.yaml to exist at all --
    # agents are told to run this script before touching any host, and a
    # safe/dev-infra host shouldn't need an active engagement (for THIS or
    # any target) just to pass. This used to fail here unconditionally,
    # which made an agent following its own instructions self-block on
    # example.com/github.com the moment any unrelated engagement existed.
    if is_safe_test_host(_host_of(target)):
        print(f"IN SCOPE: {target} (safe/dev-infra test host, no engagement required)")
        sys.exit(0)

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
