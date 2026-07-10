import json
import shlex
import subprocess
import sys
from mcp.server.fastmcp import FastMCP

app = FastMCP("subfinder-mcp")


@app.tool()
def run_subfinder(domain: str, sources: str = "", threads: int = 10, timeout: int = 120) -> str:
    cmd = ["subfinder", "-d", domain, "-silent", "-t", str(threads)]
    if sources:
        cmd.extend(["-sources", sources])
    cmd_str = shlex.join(cmd)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout,
        )
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
    cmd = ["subfinder", "-list"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return "Error: subfinder not found."
    except Exception as e:
        return f"Error: {e}"
    return result.stdout.strip() or "No sources listed."


if __name__ == "__main__":
    print("subfinder-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
