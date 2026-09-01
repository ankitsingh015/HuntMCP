import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("katana-mcp")


@app.tool()
def crawl(url: str, depth: int = 2, delay: int = 0, timeout: int = 120) -> str:
    """Crawl `url` with katana and return every discovered endpoint URL
    (deduplicated, sorted). `depth` is how many link-hops deep to follow
    (default 2). `delay` adds seconds between requests (0 = no delay)."""
    args = [
        "-u", url,
        "-d", str(depth),
        "-silent",
        "-o", "-",
    ]
    if delay > 0:
        args.extend(["-delay", str(delay)])

    try:
        result = run_tool("katana", args, timeout=timeout)
    except FileNotFoundError:
        return "Error: katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest"
    except subprocess.TimeoutExpired:
        return f"Error: katana timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

    if result.returncode != 0:
        return f"katana failed (exit {result.returncode}): {result.stderr.strip()}"

    endpoints = [e.strip() for e in result.stdout.splitlines() if e.strip()]
    if not endpoints:
        return "No endpoints discovered."

    lines = [f"Discovered {len(endpoints)} endpoint(s) for {url}:", ""]
    for ep in sorted(set(endpoints)):
        lines.append(f"  {ep}")
    return "\n".join(lines)


@app.tool()
def crawl_with_filter(url: str, depth: int = 2, extensions: str = "") -> str:
    """Like crawl(), but `extensions` is an EXCLUDE list (katana's -ef
    flag), not an include filter -- e.g. extensions="png,css,js" drops
    those from the results, it doesn't restrict to only them. Comma-
    separated, no leading dots (e.g. "png,css" not ".png,.css")."""
    args = [
        "-u", url,
        "-d", str(depth),
        "-silent",
        "-o", "-",
    ]
    if extensions:
        args.extend(["-ef", extensions])

    try:
        result = run_tool("katana", args, timeout=120)
    except FileNotFoundError:
        return "Error: katana not found."
    except subprocess.TimeoutExpired:
        return "Error: katana timed out"
    except Exception as e:
        return f"Error: {e}"

    if result.returncode != 0:
        return f"katana failed (exit {result.returncode}): {result.stderr.strip()}"

    endpoints = [e.strip() for e in result.stdout.splitlines() if e.strip()]
    if not endpoints:
        return "No endpoints discovered."

    lines = [f"Discovered {len(endpoints)} endpoint(s) with filter:", ""]
    for ep in sorted(set(endpoints)):
        lines.append(f"  {ep}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("katana-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
