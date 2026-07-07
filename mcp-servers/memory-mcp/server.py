import json
import os
import sys
from mcp.server.fastmcp import FastMCP

from db import save_hunt, recall, search_by_tech, list_targets, delete_hunt

app = FastMCP("memory-mcp")


@app.tool()
def save(target: str, data_json: str) -> str:
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
    return recall(target)


@app.tool()
def search(tech_list_json: str) -> str:
    try:
        techs = json.loads(tech_list_json)
    except json.JSONDecodeError as e:
        return f"Invalid JSON: {e}"
    if not isinstance(techs, list):
        return "tech_list_json must be a JSON array of strings"
    return search_by_tech(techs)


@app.tool()
def targets() -> str:
    return list_targets()


@app.tool()
def delete(target: str) -> str:
    return delete_hunt(target)


if __name__ == "__main__":
    print(f"Memory MCP starting...", file=sys.stderr)
    print(f"  DB: {os.path.join(os.path.dirname(__file__), '../../data/memory.db')}", file=sys.stderr)
    app.run(transport="stdio")
