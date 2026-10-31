"""P3-H4 — scan-identification headers (target-only, correct destination
boundary).

Bug-bounty programs commonly require an identifying header (e.g.
`X-Bug-Bounty: <handle>`) on every request so the program's access
logs/WAF/SOC can attribute and allow-list our traffic (Xalgorix-derived
lesson M1/H4, MASTER-ROADMAP-FINAL-v3.md §4/§5(P3)). The whole point of
this module is the destination boundary: the header is read from
engagement.yaml's own target scope and is only ever handed back for a URL
that engagement actually authorizes -- never for an LLM/provider call, a
notification channel, a third-party platform API, or any other
target-unrelated request. Callers (http_probe.fetch, each scanner MCP
server) only ever see this module for target-facing requests in the
first place, but get_scan_headers()/get_scan_header_args() re-check scope
themselves rather than trusting that -- defense in depth, same spirit as
http_probe.fetch()'s own resolved_ip_policy_error() SSRF check.

Deliberately a SEPARATE module reading engagement.yaml directly, rather
than a change to scope_guard.py's own Engagement dataclass -- same
reasoning as scan_policy.py: this is a target-attribution header, not a
scope-authorization boundary change, so it needs no
scripts/confirm-hook-edit.sh confirmation and can never accidentally
touch scope enforcement itself. It does call scope_guard.load_engagement()
and scope_guard.is_in_scope() (calling, not editing) to decide whether a
given URL matches the active engagement's target.
"""

from __future__ import annotations

import os
import re

try:
    import yaml
except ImportError:
    yaml = None

try:
    import engagement_paths
    import scope_guard
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import engagement_paths
    import scope_guard

# RFC 7230 token chars -- what's legal in an HTTP header *name*.
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# Header-injection guard: a value containing CR/LF/NUL could split the
# request into a second, attacker-shaped header or request.
_CONTROL_CHARS_RE = re.compile(r"[\r\n\x00]")


def load_scan_header(path: str | None = None) -> dict:
    """Reads `scan_header_name`/`scan_header_value` directly from
    engagement.yaml. Returns {} (no header configured -- identical to
    pre-H4 behavior) when the file or either field is absent. Returns
    {"error": ...} for a present-but-invalid configuration -- fail loud,
    same convention as scan_policy.load_scan_policy()."""
    if path is None:
        path = engagement_paths.resolve("engagement.yaml", override_env="HUNTMCP_ENGAGEMENT_PATH")
    if not os.path.isfile(path):
        return {}
    if yaml is None:
        return {"error": "PyYAML not installed; cannot determine scan_header configuration"}
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        return {"error": f"malformed engagement.yaml at {path!r}: {e}"}

    name = data.get("scan_header_name")
    value = data.get("scan_header_value")
    if name is None and value is None:
        return {}
    if name is None or value is None:
        return {"error": "engagement.yaml sets only one of scan_header_name/scan_header_value "
                          "-- both are required together"}
    if not isinstance(name, str) or not isinstance(value, str):
        return {"error": f"scan_header_name/scan_header_value must both be strings, got "
                          f"{type(name).__name__}/{type(value).__name__}"}
    if not _TOKEN_RE.match(name):
        return {"error": f"invalid scan_header_name {name!r}: must be a valid HTTP header token"}
    if _CONTROL_CHARS_RE.search(name) or _CONTROL_CHARS_RE.search(value):
        return {"error": "scan_header_name/scan_header_value must not contain CR/LF/NUL"}
    return {"name": name, "value": value}


def get_scan_headers(url: str, path: str | None = None) -> dict[str, str]:
    """The identification header to attach to a request to `url`, or {} if
    none is configured, the configuration is invalid, or `url`'s host is
    not the active engagement's authorized target -- the P3-H4
    destination-boundary check itself."""
    header = load_scan_header(path)
    if not header or "error" in header:
        return {}
    try:
        engagement = scope_guard.load_engagement(path)
    except scope_guard.NoEngagementFile:
        return {}
    try:
        in_scope = scope_guard.is_in_scope(url, engagement)
    except ValueError:
        # A malformed URL (e.g. an unbalanced IPv6 literal like
        # "http://[::1") makes is_in_scope()'s internal urlparse() raise --
        # degrade to "no header" here, same as http_probe.fetch()'s own
        # established convention of never raising on an unparseable URL.
        return {}
    if not in_scope:
        return {}
    return {header["name"]: header["value"]}


def get_scan_header_args(url: str, path: str | None = None, *, flag: str = "-H") -> list[str]:
    """`[flag, "Name: Value"]` for a command-line scanner invocation
    against `url` (httpx/nuclei/katana/ffuf/dalfox all accept `-H`;
    sqlmap-mcp passes flag="--header"), or [] if no header is configured
    or `url` is out of the active engagement's scope."""
    headers = get_scan_headers(url, path)
    if not headers:
        return []
    (name, value), = headers.items()
    return [flag, f"{name}: {value}"]


def get_scan_header_args_for_hosts(hosts: list[str], path: str | None = None, *,
                                    flag: str = "-H") -> list[str]:
    """Batch variant for a tool invocation that targets several hosts at
    once (httpx-mcp's probe_hosts/screenshot_hosts) -- one CLI `-H` flag
    is shared across the whole batch, so the header is only ever returned
    if EVERY host in `hosts` is in scope; [] (never a partial attach) if
    any single one isn't, or if `hosts` is empty."""
    if not hosts:
        return []
    header = load_scan_header(path)
    if not header or "error" in header:
        return []
    # Load the config and the engagement once for the whole batch -- the
    # in-scope answer is the same file/parse result for every host in a
    # single call, so there's nothing host-dependent about re-reading it
    # (a batch here is routinely 50-500+ domains straight from
    # subfinder-mcp's output).
    try:
        engagement = scope_guard.load_engagement(path)
    except scope_guard.NoEngagementFile:
        return []
    for host in hosts:
        try:
            if not scope_guard.is_in_scope(host, engagement):
                return []
        except ValueError:
            return []
    return [flag, f"{header['name']}: {header['value']}"]
