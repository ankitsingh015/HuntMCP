import json
import os
import sys
from mcp.server.fastmcp import FastMCP

from db import save_hunt, recall, search_by_tech, list_targets, delete_hunt

app = FastMCP("memory-mcp")


@app.tool()
def save(target: str, data_json: str) -> str:
    """Upsert this target's hunt record -- safe to call repeatedly across
    an engagement (Phase 1-2, Phase 3, and a final call at Phase 6), each
    call merges in whatever's new. data_json is a JSON object with any of:
    findings (list), chains (list), tech_stack (list of strings),
    subdomains (list of strings), bounty_estimate (string),
    summary (string) -- all optional, omit what you don't have yet."""
    try:
        data = json.loads(data_json)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"
    return save_hunt(
        target=target,
        findings=data.get("findings"),
        chains=data.get("chains"),
        tech_stack=data.get("tech_stack"),
        subdomains=data.get("subdomains"),
        bounty_estimate=data.get("bounty_estimate", ""),
        summary=data.get("summary", ""),
    )


@app.tool()
def recall_hunt(target: str) -> str:
    """Look up this target's saved hunt history (tech stack, past findings,
    when it was last hunted) -- call this at Phase 0.5 of every engagement,
    before any live testing, to check "have we hunted this before." Returns
    a not-found message if this exact target was never saved."""
    return recall(target)


@app.tool()
def search(tech_list_json: str) -> str:
    """Find past hunts that used any of the given technologies -- useful for
    "what worked against Laravel before" even on a target you've never
    personally hunted. tech_list_json is a JSON array of strings, e.g.
    '["nginx", "Laravel"]' (match is case-insensitive substring, not exact)."""
    try:
        techs = json.loads(tech_list_json)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"
    if not isinstance(techs, list):
        return "tech_list_json must be a JSON array of strings"
    return search_by_tech(techs)


@app.tool()
def targets() -> str:
    """List every target with a saved hunt record, with finding count and
    last-hunted date for each. No arguments."""
    return list_targets()


@app.tool()
def delete(target: str) -> str:
    """Permanently remove this target's saved hunt record. Rarely needed --
    normally save() upserts instead of accumulating stale entries."""
    return delete_hunt(target)


if __name__ == "__main__":
    print(f"Memory MCP starting...", file=sys.stderr)
    print(f"  DB: {os.path.join(os.path.dirname(__file__), '../../data/memory.db')}", file=sys.stderr)
    app.run(transport="stdio")
