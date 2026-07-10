import subprocess
import sys
from mcp.server.fastmcp import FastMCP

app = FastMCP("katana-mcp")


@app.tool()
def crawl(url: str, depth: int = 2, delay: int = 0, timeout: int = 120) -> str:
    cmd = [
        "katana", "-u", url,
        "-d", str(depth),
        "-silent",
        "-o", "-",
    ]
    if delay > 0:
        cmd.extend(["-delay", str(delay)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
    cmd = [
        "katana", "-u", url,
        "-d", str(depth),
        "-silent",
        "-o", "-",
    ]
    if extensions:
        cmd.extend(["-ef", extensions])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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
