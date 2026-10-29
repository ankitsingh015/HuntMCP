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
import socket
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlsplit

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
    # Disposable/temp-mail API hosts -- supporting infrastructure for the
    # standard VDP practice of provisioning a throwaway inbox to complete an
    # app's own public signup (identical category to interactsh OOB: these are
    # NOT bug-bounty targets, they are external services used to receive
    # verification mail). Listed explicitly by HuntBrain's engagement brief.
    "api.mail.tm", "mail.tm", "www.1secmail.com", "1secmail.com",
    "api.1secmail.com", "www.mailinator.com", "mailinator.com",
    "api.guerrillamail.com", "guerrillamail.com", "inboxes.com",
    # mail.tm currently serves the mailbox domain "uberip.com" (dynamic over
    # time) -- mailbox domains are the addresses themselves, same supporting-
    # infrastructure category. Also 1secmail/mailinator mailbox domains.
    "uberip.com", "guerrillamail.net",
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

    # A broad out_of_scope wildcard (e.g. "*.example.com", meant to express
    # "no sibling hosts of the same root domain") used to silently shadow an
    # explicit, specific in_scope literal (e.g. "app.example.com") -- the
    # guard checked out_of_scope first with no awareness of in_scope at all,
    # so a self-contradictory-looking-but-actually-fine engagement file
    # (a program that scopes specific hosts under a domain it otherwise
    # excludes) blocked hosts the operator explicitly authorized, with no
    # indication why. Reported live, independently, in two engagements.
    # Fix: an EXACT in_scope literal wins over a WILDCARD out_of_scope
    # match on the same host -- this is unambiguous (the operator spelled
    # this exact host out by name) and strictly more precise, not looser:
    # an exact out_of_scope literal (a genuine, deliberate exclusion of
    # this precise host) still wins over everything, same as before.
    exact_in_scope = host in engagement.in_scope
    for pattern in engagement.out_of_scope:
        if _matches(host, pattern):
            if exact_in_scope and "*" in pattern:
                continue
            return False
    return any(_matches(host, pattern) for pattern in engagement.in_scope)


_OUTBOUND_ALLOWED_SCHEMES = ("http", "https")
_OUTBOUND_METADATA_HOSTS = frozenset({"metadata", "metadata.google.internal", "metadata.goog"})
_OUTBOUND_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Shared by outbound_policy_error() (checking a literal IP already in
    the URL) and resolved_ip_policy_error() (checking what a hostname
    actually resolved to) -- one classification, not two hand-copies that
    could drift out of sync with each other."""
    mapped = getattr(ip, "ipv4_mapped", None)
    return (ip.is_link_local or (mapped is not None and mapped.is_link_local)
            or str(ip) in _OUTBOUND_METADATA_IPS or (mapped is not None and str(mapped) in _OUTBOUND_METADATA_IPS))


def outbound_policy_error(url: str) -> str | None:
    """Generic outbound-request policy check, applied IN ADDITION to
    is_in_scope() -- is_in_scope()'s own is_safe_test_host fast-path treats
    loopback/RFC1918/link-local addresses as automatically in-scope before
    out_of_scope is even consulted (correct for this benchmark's own
    "needs no engagement.yaml" local test-host posture), so on its own it
    cannot keep a request off a cloud instance-metadata endpoint or a
    non-HTTP scheme. Originally built as a case-mcp-local CEM helper (despite
    its CEM-prefixed name, it was already generic, not CEM-specific) --
    relocated here so every caller shares one
    implementation instead of each hand-copying it.

    Returns None if the URL is a permissible outbound destination, else a
    refusal reason. Rejects: any scheme other than http/https (blocks
    file:/ftp:/gopher:/data:), the cloud instance-metadata IPs/hostnames,
    and any link-local address (169.254.0.0/16, fe80::/10). Deliberately
    does NOT reject ordinary loopback/RFC1918 -- callers that need scope
    enforcement on top of this still call is_in_scope() separately.

    IMPORTANT LIMIT, found during a security review of the P3-SCHEMA task
    that relocated this function here: this only ever inspects the LITERAL
    host string in the URL. It cannot catch a hostname whose DNS record
    resolves to a metadata/link-local address (DNS rebinding), nor an
    alternate numeric encoding of a metadata IP (e.g. decimal "2852039166"
    or octal "0251.0376.0251.0376" for 169.254.169.254) that Python's own
    strict ipaddress.ip_address() rejects but a real resolver (glibc
    getaddrinfo) still resolves to the real address -- both verified live
    against this exact function. This function is therefore a cheap EARLY
    filter only, not the real enforcement boundary; the real boundary is
    resolved_ip_policy_error(), called inside http_probe.fetch() right
    before the real connection, which checks what the host ACTUALLY
    resolves to rather than the literal string."""
    try:
        parts = urlsplit(url)
    except ValueError as e:
        return f"unparseable URL ({e})"
    if parts.scheme.lower() not in _OUTBOUND_ALLOWED_SCHEMES:
        return (f"scheme {parts.scheme.lower()!r} is not permitted -- "
                "only http/https (no file/ftp/gopher/data)")
    host = (parts.hostname or "").lower()
    if not host:
        return "URL has no host"
    if host in _OUTBOUND_METADATA_HOSTS or host in _OUTBOUND_METADATA_IPS:
        return f"host {host!r} is a cloud instance-metadata endpoint -- refused (SSRF)"
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None and _is_blocked_ip(ip):
        return (f"host {host!r} resolves to a link-local / instance-metadata address "
                "(169.254.0.0/16, fe80::/10, or a v4-mapped form) -- refused (SSRF)")
    return None


def _resolved_addresses(host: str) -> list[str] | None:
    """Shared by resolved_ip_policy_error() and resolve_and_pin() -- one
    resolution loop, not two hand-copies that could drift in how they
    parse a getaddrinfo() result (the exact drift this helper's sibling,
    _is_blocked_ip(), was already factored out to avoid one level down).
    Returns the raw IP strings (IPv6 zone ids stripped), or None if
    resolution itself failed for any reason."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    return [info[4][0].split("%", 1)[0] for info in infos]


def resolved_ip_policy_error(host: str) -> str | None:
    """The real SSRF enforcement boundary outbound_policy_error() itself
    cannot be (see its own docstring): resolves `host` via the OS resolver
    (socket.getaddrinfo, the same resolver the real connection will use)
    and checks EVERY resolved address against the identical denylist
    outbound_policy_error() applies to a literal IP -- so a hostname that
    DNS-rebinds to a metadata/link-local address, or a numeric encoding
    that only the OS resolver (not Python's strict ipaddress module)
    recognizes, is caught here instead of slipping through as "not a
    literal IP, therefore permitted."

    Returns None if resolution fails for any reason (the caller's own real
    connection attempt will surface that failure naturally -- this is a
    SSRF-deny check, not a reachability check, so a resolution error here
    is never treated as a refusal) or if every resolved address is
    permitted. Returns a refusal reason string if ANY resolved address is
    link-local/instance-metadata. Intended to be called immediately before
    the real connection (see http_probe.fetch()), not as a standalone
    cacheable decision -- resolving once here and connecting somewhere
    else later would reopen the exact TOCTOU gap this exists to close.
    (Contrast resolve_and_pin() below, whose caller's real connection does
    NOT happen right after this check -- a resolution failure there must
    NOT be treated the same permissive way; see its own docstring.)"""
    raw_ips = _resolved_addresses(host)
    if raw_ips is None:
        return None
    for raw_ip in raw_ips:
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            return (f"host {host!r} resolves to {raw_ip!r}, a link-local / "
                    "instance-metadata address -- refused (SSRF)")
    return None


def resolve_and_pin(host: str) -> tuple[str | None, str | None]:
    """For a caller whose real requests are made by an EXTERNAL process it
    does not control (e.g. schemathesis-mcp's sandboxed `schemathesis` CLI,
    which never goes through http_probe.fetch() and so never benefits from
    resolved_ip_policy_error()'s own per-connection check): resolves `host`
    ONCE, checks it the same way resolved_ip_policy_error() does, and
    returns an IP the caller can PIN (e.g. via a container's `--add-host`)
    for the whole lifetime of that external process -- not just the
    instant of this call.

    This closes the DNS-rebinding gap more completely than a one-time
    pre-flight check alone would: resolving again later (if the caller
    doesn't pin and instead just re-checks before each of many requests)
    still has a TOCTOU window between each check and that request's own
    real connection. Pinning removes the window entirely for that
    process's lifetime, because the pinned entry -- not a fresh DNS
    lookup -- is what the external process's own resolver will return for
    every subsequent request to that exact hostname, verified live:
    `podman run --add-host=host:ip ...` makes the container's own
    resolution of `host` return `ip` regardless of what real DNS says
    (also verified live: this is correct for an IPv6 `ip` too, with no
    bracket needed -- podman's own `--add-host` parser splits on the
    FIRST colon only).

    Only inspects/pins the FIRST resolved address, deliberately -- unlike
    resolved_ip_policy_error()'s "scan every address" contract, this
    function's own caller only ever connects to the ONE address it pins
    (every other resolved address becomes structurally unreachable via
    this hostname once pinned), so there is nothing gained by scanning
    further ones; only the address actually used needs checking.

    Returns `(ip, None)` on success -- `ip` is the first permitted
    resolved address, suitable for `--add-host=host:ip`. Returns
    `(None, error)` if resolution fails for ANY reason, INCLUDING a
    transient one, or if the first resolved address is link-local/
    instance-metadata, or if resolution produced no usable address at all.

    Deliberately NOT the same "resolution failure is never a refusal"
    convention resolved_ip_policy_error() uses: that convention is safe
    there only because that function's caller makes its own real
    connection attempt immediately afterward, so a resolution failure
    there surfaces naturally with no protection lost either way. This
    function's caller does NOT connect itself -- it launches an external
    process that resolves and connects on its own, later. If resolution
    merely transiently failed HERE, silently proceeding unpinned would let
    that later, unprotected resolution succeed with zero SSRF defense --
    exactly the TOCTOU window this function exists to close. The caller
    MUST refuse the whole operation whenever this returns a non-None
    error; it must never launch unpinned."""
    raw_ips = _resolved_addresses(host)
    if not raw_ips:
        return None, (f"could not resolve {host!r} to pin it -- refusing to run "
                       "unpinned rather than let the sandboxed process's own, "
                       "later, unprotected resolution decide where this goes")
    for raw_ip in raw_ips:
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            return None, (f"host {host!r} resolves to {raw_ip!r}, a link-local / "
                          "instance-metadata address -- refused (SSRF)")
        return raw_ip, None
    return None, f"host {host!r} resolved to no usable address -- refusing to run unpinned"


def pin_hosts_or_error(*urls: str) -> tuple[dict[str, str], str | None]:
    """Shared convention for EVERY job_runtime-based scanner server whose
    real HTTP traffic is generated by an external subprocess it does not
    otherwise control (sqlmap, nuclei, dalfox, ffuf, schemathesis -- every
    one of them shells out to a binary that resolves and connects on its
    own, never through http_probe.fetch()'s per-connection check). First
    built as schemathesis-mcp's own one-off `_hosts_to_pin_or_error`;
    promoted here after a security review's altitude pass pointed out the
    identical gap already existed, unpatched, in the 4 servers above --
    one shared, documented, reusable call site rather than a 5th
    (or 6th, or Nth) hand-copy that a future scanner server could just as
    easily skip or get subtly wrong.

    Extracts and dedupes the hostname of every url in `urls` via
    `_host_of()` -- NOT a bare `urlsplit(u).hostname` -- deliberately:
    several of this function's own real callers (e.g. nuclei-mcp's
    `scan_target(target, ...)`) pass a BARE hostname with no scheme (e.g.
    "target.com", confirmed against this repo's own existing tests), and
    `urlsplit("target.com").hostname` is `None` (no "//" means the whole
    string is parsed as a path, not a netloc) -- that would have made this
    function a silent no-op for exactly the callers that most need it.
    `_host_of()` already handles "bare host, host:port, or full URL"
    uniformly (it's what `is_in_scope()` itself uses), so reusing it here
    keeps "what counts as the host of this value" consistent with the
    scope decision already made on the same value, not a second,
    independently-drifting notion of it.

    Resolves and pins each via resolve_and_pin() (fail-closed -- see its
    own docstring), and returns an `extra_hosts` dict ready for
    job_runtime.start_job()'s own `extra_hosts` param. Every caller MUST
    pass the returned dict through to start_job (or refuse the whole
    operation on a non-None error) -- computing it and then not pinning it
    would defeat the whole point.

    Returns `(extra_hosts, None)` on success (extra_hosts may be `{}` if
    none of `urls` had an extractable host -- callers should treat that
    the same as "nothing to pin", not as a refusal). Returns `({}, error)`
    if any host should refuse the whole operation (resolution failure,
    link-local/instance-metadata resolution, or no usable address).

    Skips pinning entirely (returns `({}, None)`) when the process
    environment sets HUNTMCP_BENCH_NETWORK -- the SAME escape hatch
    sandbox_runner.build_argv() itself already documents for this exact
    variable: set ONLY by P2-BENCH's own real-tool fixture-proof tests
    (tests/test_p2_bench_fixture.py), never by any production launch
    config, and with no code path from an agent's own tool-call input to
    it (found live: without this, every real-tool benchmark test started
    failing, because the sandboxed container's target, e.g.
    "bench-target", is a name resolvable ONLY via that throwaway,
    --internal/no-host-route podman network's own embedded DNS, from
    INSIDE a container joined to it -- never from this host-side process,
    so resolve_and_pin() would always, correctly, fail to resolve it here
    and (now fail-closed) refuse every such run). Skipping pinning in
    this one recognized case is not a new weakening: DNS-rebinding/SSRF
    protection doesn't meaningfully apply to a network with no real
    external route in the first place."""
    if os.environ.get("HUNTMCP_BENCH_NETWORK"):
        return {}, None
    hosts: set[str] = set()
    for u in urls:
        host = _host_of(u) if isinstance(u, str) else ""
        if host:
            hosts.add(host)
    extra_hosts: dict[str, str] = {}
    for host in hosts:
        ip, error = resolve_and_pin(host)
        if error:
            return {}, error
        if ip:
            extra_hosts[host] = ip
    return extra_hosts, None


def detect_scope_conflicts(engagement: Engagement) -> list[str]:
    """Load-time-only diagnostic: surface engagement.yaml entries that LOOK
    self-contradictory, even though is_in_scope()'s runtime precedence
    already resolves them correctly (see is_in_scope()'s own comment on the
    exact-in_scope-literal-beats-wildcard-out_of_scope fix). Returns
    human-readable warning strings, or an empty list if nothing looks
    contradictory. Purely informational -- never raises, never changes
    enforcement -- so an operator understands *why* a host was allowed or
    blocked instead of being surprised by an engagement file that reads as
    self-contradictory (reported live, independently, across engagement
    retrospectives: debugging time spent re-deriving precedence from
    source before realizing the file itself, not the guard, was the
    problem)."""
    warnings: list[str] = []
    for in_host in engagement.in_scope:
        if "*" in in_host:
            continue  # only an EXACT in_scope literal can be shadowed/won
        for out_pattern in engagement.out_of_scope:
            if not _matches(in_host, out_pattern):
                continue
            if "*" in out_pattern:
                warnings.append(
                    f"in_scope host {in_host!r} matches out_of_scope wildcard "
                    f"{out_pattern!r} -- the exact in_scope literal wins (see "
                    f"is_in_scope()), so {in_host!r} IS authorized. If that's "
                    f"not what you intended, narrow or remove the wildcard."
                )
            elif out_pattern == in_host:
                warnings.append(
                    f"{in_host!r} appears in BOTH in_scope and out_of_scope "
                    f"as an exact literal -- the exact out_of_scope entry "
                    f"wins (see is_in_scope()), so {in_host!r} is NOT "
                    f"authorized despite also being listed in in_scope."
                )
    return warnings


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

    # Surfaced here (the explicit "run this before touching a target"
    # checkpoint), not inside load_engagement() itself -- the hook's own
    # PreToolUse enforcement path calls load_engagement() fresh on every
    # single Tier-2 call, and printing this on every call would spam
    # stderr instead of informing anyone. This CLI is the natural one-time
    # "engagement load" checkpoint an operator/agent actually sees.
    for warning in detect_scope_conflicts(engagement):
        print(f"WARNING: {warning}", file=sys.stderr)

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
