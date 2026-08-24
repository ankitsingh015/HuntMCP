"""Target discovery, both halves: unlisted (security.txt) and listed
(aggregated bounty-platform scope) (Phase 2.10-adjacent).

**Unlisted half** -- not every real, in-scope-for-testing target is listed
on HackerOne/Bugcrowd -- a company can publish its own vulnerability
disclosure policy via a security.txt file (RFC 9116) at its domain root
without ever appearing on a bounty platform. Those targets are both
explicitly authorized (the whole point of security.txt is "here's how/
whether you may report what you find") and less competed-over than an
already-listed H1 program, which is the actual, legitimate version of
"less visible target" -- unlike testing a domain with no published policy
at all and hoping for the best afterward, which this project does not do
(see ARCHITECTURE.md's Scope & Authorization section).

Fetching a domain's own published security.txt is not a Tier-2 action --
it's reading a file the domain owner explicitly publishes for exactly this
purpose (RFC 9116's entire point is machine discovery), the same way
reading a README is not "testing" a repo. It is NOT scope-gated and does
NOT imply the domain is now in scope for active testing -- only that it
has SOME disclosure channel. Read the actual policy text/URL before ever
treating a domain as authorized for anything beyond "I may email them a
report."

Workflow: check_security_txt(domain) to inspect one domain, then
add_candidate(domain, notes) to store it (only if it validated) in a local
DB for later triage -- list_candidates() to review what's accumulated.
Nothing here spawns a hunt automatically; a human still decides what to do
with an entry.

**Listed half** (`bounty_scope.py`) -- the complementary case: a domain
that IS already covered by a published program on HackerOne, Bugcrowd,
Intigriti, Federacy, or YesWeHack, sourced from arkadiyt/bounty-targets-data
(no credentials needed, unlike hackerone-mcp's sync_program_scope, which
needs a live H1 account and only covers H1 -- keep both, this is a
complement, not a replacement). refresh_bounty_scope() pulls the latest
aggregated data and logs any newly-added scope; lookup_bounty_scope(domain)
checks a specific domain against the cache; list_new_bounty_scope() reads
back what's newly appeared -- the cheap, safe-to-run-often half of
continuous scope discovery. Same rule applies here as above: none of this
spawns a hunt or implies active testing is authorized on its own -- it only
surfaces that a published program covers the domain; engagement.yaml is
still the sole enforced scope boundary before any Tier-2 action.
"""

from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import bounty_scope
import db
from mcp.server.fastmcp import FastMCP

app = FastMCP("target-discovery-mcp")

CANDIDATE_PATHS = ["/.well-known/security.txt", "/security.txt"]


def _fetch(domain: str) -> tuple[str, str] | tuple[None, None]:
    """Try RFC 9116's preferred path, then the legacy root fallback.
    Returns (raw_text, source_path) or (None, None) if neither exists."""
    for path in CANDIDATE_PATHS:
        url = f"https://{domain}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "HuntMCP-target-discovery/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    return resp.read().decode(errors="replace"), url
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
            continue
    return None, None


def _parse(raw: str) -> dict:
    fields: dict[str, list[str]] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        fields.setdefault(key, []).append(value)
    return fields


def _is_expired(expires_value: str) -> bool | None:
    """RFC 9116 Expires is ISO 8601. Returns True/False, or None if
    unparseable (treated as suspicious, not trusted)."""
    try:
        cleaned = expires_value.strip().replace("Z", "+00:00").replace("z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt < datetime.now(UTC)
    except ValueError:
        return None


@app.tool()
def check_security_txt(domain: str) -> str:
    """Fetch and parse a domain's security.txt (RFC 9116) if it publishes
    one. Read-only -- fetches a file the domain explicitly publishes for
    this exact purpose, not a Tier-2 action, not scope-gated. Reports
    whether it's present, valid (has Contact, has a non-expired Expires
    field per RFC), and its key fields."""
    domain = re.sub(r"^https?://", "", domain).strip().rstrip("/")
    raw, source = _fetch(domain)
    if raw is None:
        return f"No security.txt found for {domain!r} (checked {', '.join(CANDIDATE_PATHS)})."

    fields = _parse(raw)
    contacts = fields.get("contact", [])
    policy = fields.get("policy", [""])[0]
    expires = fields.get("expires", [""])[0]

    problems = []
    if not contacts:
        problems.append("no Contact field (required by RFC 9116)")
    if not expires:
        problems.append("no Expires field (required by RFC 9116)")
    else:
        expired = _is_expired(expires)
        if expired is None:
            problems.append(f"Expires field unparseable: {expires!r}")
        elif expired:
            problems.append(f"Expires {expires} is in the past -- do not trust this file")

    status = "VALID" if not problems else "INVALID/STALE"
    lines = [
        f"security.txt found at {source} -- {status}",
        f"  Contact: {', '.join(contacts) or '(none)'}",
        f"  Policy: {policy or '(none)'}",
        f"  Expires: {expires or '(none)'}",
    ]
    if problems:
        lines.append("  Problems: " + "; ".join(problems))
    return "\n".join(lines)


@app.tool()
def add_candidate(domain: str, notes: str = "") -> str:
    """Validate a domain's security.txt and, only if valid, store it as a
    candidate target in the local DB (data/candidate-targets.db,
    gitignored) for later human triage. Does not start any testing --
    this only builds a catalog to review, same as HackerOne/Bugcrowd's own
    program directories, just for domains that aren't listed there."""
    domain = re.sub(r"^https?://", "", domain).strip().rstrip("/")
    raw, source = _fetch(domain)
    if raw is None:
        return f"Not added: no security.txt found for {domain!r}."

    fields = _parse(raw)
    contacts = fields.get("contact", [])
    policy = fields.get("policy", [""])[0]
    expires = fields.get("expires", [""])[0]

    valid = bool(contacts) and bool(expires) and _is_expired(expires) is False
    db.upsert_candidate(
        domain=domain,
        contact="; ".join(contacts),
        policy_url=policy,
        expires=expires,
        validated=valid,
        notes=notes,
    )

    if valid:
        return f"Added {domain!r} as a validated candidate (source: {source})."
    return (
        f"Added {domain!r} but marked NOT validated (missing/expired Contact or "
        f"Expires field) -- review manually before treating this as a real "
        f"disclosure channel."
    )


@app.tool()
def list_candidates(validated_only: bool = True) -> str:
    """List stored candidate targets. validated_only=True (default) shows
    only ones whose security.txt passed validation."""
    rows = db.list_candidates(validated_only=validated_only)
    if not rows:
        return "No candidate targets stored yet." if validated_only else (
            "No candidate targets stored yet (validated or not)."
        )
    lines = [f"{len(rows)} candidate target(s):"]
    for r in rows:
        mark = "✓" if r["validated"] else "✗"
        lines.append(
            f"  [{mark}] {r['domain']} -- contact: {r['contact'] or '(none)'} "
            f"-- policy: {r['policy_url'] or '(none)'} -- notes: {r['notes'] or '(none)'}"
        )
    return "\n".join(lines)


@app.tool()
def refresh_bounty_scope(force: bool = False) -> str:
    """Refresh the local cache of aggregated bounty-program scope from
    arkadiyt/bounty-targets-data (HackerOne/Bugcrowd/Intigriti/Federacy/
    YesWeHack, no credentials needed). Skips the download if the cache is
    still fresh (<20 min old) unless force=True -- the upstream source
    itself only updates every 30 min, so calling this often is cheap and
    safe. Logs any newly-added or newly-removed (domain, platform, program)
    pairs -- see list_new_bounty_scope() to read that log."""
    result = bounty_scope.refresh(force=force)
    if not result.get("refreshed"):
        return f"Not refreshed: {result.get('reason', 'unknown')} (cached domains: {result.get('domains', 0)})"
    lines = [
        f"Refreshed -- {result['domains']} domains across cached platforms.",
        f"  {result['added']} newly added, {result['removed']} newly removed since last refresh.",
    ]
    if result.get("failed_platforms"):
        lines.append(f"  Failed to fetch: {', '.join(result['failed_platforms'])} (kept prior cached data for those)")
    return "\n".join(lines)


@app.tool()
def lookup_bounty_scope(domain: str) -> str:
    """Check whether a domain is already covered by a published bounty
    program on any of the 5 aggregated platforms -- the Phase 0
    auto-discovery use case: a target the user names may already have a
    known, structured scope you don't have to ask them to paste. Matches
    exact domains and wildcard subdomain patterns. Reads the local cache
    only -- call refresh_bounty_scope() first if it might be stale."""
    matches = bounty_scope.lookup_domain(domain)
    if not matches:
        return f"{domain!r} not found in any cached bounty-program scope (may be unlisted, or cache needs a refresh)."
    lines = [f"{len(matches)} match(es) for {domain!r}:"]
    for m in matches:
        bounty = "bounty-eligible" if m["eligible_for_bounty"] else "NOT bounty-eligible"
        sev = f", max severity {m['max_severity']}" if m.get("max_severity") else ""
        lines.append(
            f"  [{m['platform']}] {m['program']} ({bounty}{sev}) -- {m['program_url']}"
        )
    return "\n".join(lines)


@app.tool()
def list_new_bounty_scope(since_hours: int = 24) -> str:
    """List (domain, platform, program) pairs newly added to any cached
    platform's published scope within the last since_hours -- the cheap
    half of continuous scope discovery (see ARCHITECTURE.md's "Continuous
    bounty-scope discovery" section). This only reads the diff log built by
    refresh_bounty_scope() calls; it does not itself touch any target."""
    events = bounty_scope.list_new_scope(since_hours=since_hours)
    if not events:
        return f"No newly-added scope in the last {since_hours}h."
    lines = [f"{len(events)} newly-added scope entr{'y' if len(events)==1 else 'ies'} in the last {since_hours}h:"]
    for e in events:
        lines.append(f"  [{e['platform']}] {e['domain']} -- {e['program']} (seen {e['ts']})")
    return "\n".join(lines)


if __name__ == "__main__":
    print("target-discovery-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
