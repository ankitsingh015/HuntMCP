import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("subfinder-mcp")


@app.tool()
def run_subfinder(domain: str, sources: str = "", threads: int = 10, timeout: int = 120) -> str:
    args = ["-d", domain, "-silent", "-t", str(threads)]
    if sources:
        args.extend(["-sources", sources])

    try:
        result = run_tool("subfinder", args, timeout=timeout)
    except FileNotFoundError:
        return f"Error: subfinder not found. Install with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    except subprocess.TimeoutExpired:
        return f"Error: subfinder timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

    if result.returncode != 0:
        return f"subfinder failed (exit {result.returncode}): {result.stderr.strip()}"

    subdomains = [s.strip() for s in result.stdout.splitlines() if s.strip()]
    if not subdomains:
        return "No subdomains found."

    lines = [f"Found {len(subdomains)} subdomains for {domain}:", ""]
    for s in sorted(subdomains):
        lines.append(f"  {s}")
    return "\n".join(lines)


@app.tool()
def list_sources() -> str:
    try:
        result = run_tool("subfinder", ["-list"], timeout=15)
    except FileNotFoundError:
        return "Error: subfinder not found."
    except Exception as e:
        return f"Error: {e}"
    return result.stdout.strip() or "No sources listed."


if __name__ == "__main__":
    print("subfinder-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
