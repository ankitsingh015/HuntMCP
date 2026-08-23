"""HackerOne read-only MCP (Phase 2.8 backlog).

Read-only by design, on purpose, with no exceptions: pulls a program's
structured scope so it doesn't have to be hand-transcribed into
engagement.yaml, and checks the authenticated hunter's OWN accessible
reports on a program for likely self-duplicates before writing one up.
There is no submit/create-report call in this file and there must never be
one -- report-agent's local-markdown-draft-only design
(.claude/agents/report-agent.md's "Never submit" section) is the actual
submission boundary; this server only ever reduces manual scope-copying
and duplicate-report risk upstream of that.

Honest scope of "duplicate check": HackerOne's API does not expose other
hunters' private/pending reports to you -- that's a deliberate privacy
boundary, not a gap in this implementation. What IS achievable and
implemented here is a self-duplicate check: did *I* already report
something matching this keyword on this program. That's still useful (a
solo hunter re-discovering their own old finding is a real, avoidable
mistake) but it is not, and cannot be, a check against the whole program's
duplicate landscape.

IMPORTANT -- unlike every other MCP server in this repo, this one has NOT
been functionally tested against a live HackerOne account (no test API
credentials were available while building it). Endpoint paths and response
shapes follow HackerOne's official v1 API docs (api.hackerone.com/docs/v1)
as understood at the time this was written, but verify against a real
account/token before relying on it -- if H1 has changed a field name or
path since, this needs a real-account test pass to catch it, the same way
every other tool in this repo got one.

Auth: HACKERONE_API_USERNAME + HACKERONE_API_TOKEN (HTTP Basic Auth, both
generated from your own H1 account -- Settings -> API Token). Never commit
these; set them in your shell environment or an untracked .env.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from mcp.server.fastmcp import FastMCP

app = FastMCP("hackerone-mcp")

API_BASE = "https://api.hackerone.com/v1"


class HackerOneAuthError(Exception):
    pass


def _auth_header() -> str:
    username = os.getenv("HACKERONE_API_USERNAME")
    token = os.getenv("HACKERONE_API_TOKEN")
    if not username or not token:
        raise HackerOneAuthError(
            "HACKERONE_API_USERNAME and HACKERONE_API_TOKEN must both be set. "
            "Generate an API token from your HackerOne account: Settings -> API Token."
        )
    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    return f"Basic {creds}"


def _get(path: str, params: dict | None = None) -> dict:
    url = f"{API_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url,
        headers={"Authorization": _auth_header(), "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HackerOne API error {e.code}: {body[:500]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"HackerOne API unreachable: {e.reason}") from e


@app.tool()
def sync_program_scope(handle: str) -> str:
    """Pull a program's structured scope from the HackerOne API and format
    it as an engagement.yaml-ready snippet. Does NOT write engagement.yaml
    itself -- HuntBrain still owns that file, written once at Phase 0; this
    only saves hand-transcribing the scope page. `handle` is the program's
    URL slug (the part after hackerone.com/, e.g. "example-program")."""
    try:
        data = _get(f"/hackers/programs/{handle}/structured_scopes")
    except HackerOneAuthError as e:
        return f"Error: {e}"
    except RuntimeError as e:
        return f"Error: {e}"

    scopes = data.get("data", [])
    if not scopes:
        return f"No structured scopes returned for program {handle!r} (empty or not accessible)."

    in_scope, out_of_scope = [], []
    for item in scopes:
        attrs = item.get("attributes", {})
        identifier = attrs.get("asset_identifier")
        if not identifier:
            continue
        if attrs.get("eligible_for_submission"):
            in_scope.append(identifier)
        else:
            out_of_scope.append(identifier)

    lines = [
        f"# Structured scope for {handle!r} -- review before pasting into engagement.yaml",
        f"target: {handle}",
        "in_scope:",
    ]
    lines += [f"  - {i}" for i in in_scope] or ["  # (none marked eligible_for_submission)"]
    lines.append("out_of_scope:")
    lines += [f"  - {o}" for o in out_of_scope] or ["  # (none)"]
    lines.append(f'program_url: "https://hackerone.com/{handle}"')

    return "\n".join(lines)


@app.tool()
def check_my_duplicates(handle: str, keyword: str) -> str:
    """Self-duplicate check: search YOUR OWN accessible reports on a
    program for ones matching `keyword` (e.g. a vuln class + endpoint
    fragment), before writing up a new finding. This can only see reports
    you have access to (your own submissions, or ones on a program you're
    a team member of) -- HackerOne does not expose other hunters' private
    reports through any API, by design, so this is not and cannot be a
    full program-wide duplicate check."""
    try:
        data = _get(
            "/reports",
            params={"filter[program][]": handle, "filter[keyword]": keyword},
        )
    except HackerOneAuthError as e:
        return f"Error: {e}"
    except RuntimeError as e:
        return f"Error: {e}"

    reports = data.get("data", [])
    if not reports:
        return (
            f"No matching reports of yours found for {keyword!r} on {handle!r} "
            "(does not rule out another hunter having already reported this -- "
            "HackerOne does not expose that to you)."
        )

    lines = [f"{len(reports)} of your own report(s) matched {keyword!r} on {handle!r}:"]
    for r in reports:
        attrs = r.get("attributes", {})
        lines.append(
            f"  #{r.get('id', '?')} [{attrs.get('state', '?')}] {attrs.get('title', '(no title)')}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print("hackerone-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
