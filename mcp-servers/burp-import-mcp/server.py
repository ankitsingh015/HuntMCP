"""Burp Suite HTTP-history import.

Seeds recon/exploit-agent with authenticated traffic a human hunter
already captured manually through Burp's proxy -- session cookies, auth
headers, and real endpoint shapes that automated recon tools (subfinder,
katana) can't discover on their own since they don't know how to log in.

Tier 1 (file-only, like secrets-mcp/lessons-mcp): reads a local export
file the user already saved from their own Burp Suite session and never
sends anything to the live target itself, so this isn't scope-gated --
same reasoning as oob-mcp's generate_payload_url().
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db as burp_db  # noqa: E402
from parser import parse_burp_xml_file  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("burp-import-mcp")


@app.tool()
def import_history(export_path: str, target: str) -> str:
    """Import a Burp Suite HTTP-history export for `target` (Proxy or
    Target tab > right-click a request/selection > "Save selected items"
    > XML format). Seeds recon/exploit-agent with the endpoints a human
    hunter already explored manually while authenticated -- something
    automated recon can't do on its own since it doesn't know how to log
    in. `export_path` must be a local XML file already saved from Burp;
    this tool never talks to the live target."""
    if not export_path.strip():
        return "Error: export_path is required."
    if not os.path.isfile(export_path):
        return f"Error: {export_path!r} not found."
    if not target.strip():
        return "Error: target is required (which engagement this traffic belongs to)."

    try:
        entries = parse_burp_xml_file(export_path)
    except ValueError as e:
        return f"Error: {e}"

    if not entries:
        return f"No <item> entries found in {export_path!r} -- is this a Burp XML export (Save selected items > XML)?"

    result = burp_db.import_entries(target, entries, source_file=os.path.basename(export_path))
    return (
        f"Imported {result['imported']} new endpoint(s), updated {result['updated']} "
        f"existing one(s) ({result['total']} total in export) for {target!r}. "
        f"{result['authenticated']} carry a session cookie or Authorization header -- "
        f"call list_endpoints(target={target!r}, authenticated_only=True) to see them."
    )


@app.tool()
def list_endpoints(target: str = "", authenticated_only: bool = False, limit: int = 50) -> str:
    """List imported Burp endpoints, optionally filtered to one target
    and/or to only the ones carrying a session cookie or Authorization
    header -- the ones actually worth seeding into recon/exploit-agent,
    since everything else is traffic automated recon would've found
    anyway."""
    rows = burp_db.list_endpoints(target=target, authenticated_only=authenticated_only, limit=limit)
    if not rows:
        return "No imported endpoints match that filter."
    lines = [f"{len(rows)} imported endpoint(s):"]
    for r in rows:
        auth_marker = " [AUTH]" if (r["has_cookie"] or r["has_auth_header"]) else ""
        lines.append(f"  #{r['id']} [{r['method']}] {r['url']} -> {r['status']}{auth_marker}")
    return "\n".join(lines)


@app.tool()
def get_endpoint_detail(endpoint_id: int) -> str:
    """Full detail (including headers) for one imported endpoint by id --
    use this to get the exact cookies/auth header to replay against the
    target yourself with sqlmap/dalfox/ffuf/curl."""
    row = burp_db.get_endpoint(endpoint_id)
    if not row:
        return f"No imported endpoint with id={endpoint_id}."
    headers = json.loads(row["headers_json"])
    lines = [
        f"#{row['id']} [{row['method']}] {row['url']}",
        f"  Host: {row['host']}  Status: {row['status']}  Mimetype: {row['mimetype']}",
        f"  Imported from: {row['source_file']} at {row['imported_at']}",
        "  Headers:",
    ]
    for k, v in headers.items():
        lines.append(f"    {k}: {v}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("burp-import-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
