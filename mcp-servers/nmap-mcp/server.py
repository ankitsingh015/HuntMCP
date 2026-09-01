import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("nmap-mcp")


def _parse_nmap_grepable(raw: str) -> list[dict]:
    hosts = []
    for line in raw.splitlines():
        if not line.startswith("Host:"):
            continue
        host = {}
        m = re.search(r"Host:\s+(\S+)", line)
        host["host"] = m.group(1) if m else "?"
        m = re.search(r"Status:\s+(\w+)", line)
        host["status"] = m.group(1) if m else "?"
        m = re.search(r"Ports:\s+(.+)", line)
        if m:
            ports = []
            for part in m.group(1).split(","):
                part = part.strip()
                # nmap -oG's port field is
                # port/state/protocol/owner/service/rpc_info/version -- group
                # 5 is the service name, group 7 is the version string. This
                # used to read group(7) (version) as the service name.
                pm = re.match(
                    r"(\d+)/(open|filtered|closed)/(tcp|udp)/([^/]*)/([^/]*)/([^/]*)/(.*)",
                    part,
                )
                if pm:
                    ports.append({
                        "port": int(pm.group(1)),
                        "state": pm.group(2),
                        "proto": pm.group(3),
                        "service": pm.group(5).strip() if pm.group(5) else "unknown",
                    })
            host["ports"] = ports
        hosts.append(host)
    return hosts


@app.tool()
def scan_ports(target: str, top_ports: int = 1000, timeout: int = 300) -> str:
    """Fast nmap scan of the `top_ports` (default 1000) most common ports
    on `target` -- no service-version detection, just open/closed state.
    Use scan_deep() for -sV service fingerprinting on a specific range."""
    args = ["-T4", "--top-ports", str(top_ports), "-oG", "-", target]
    try:
        result = run_tool("nmap", args, timeout=timeout)
    except FileNotFoundError:
        return "Error: nmap not found. Install with: apt install nmap"
    except subprocess.TimeoutExpired:
        return f"Error: nmap timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

    if result.returncode != 0:
        return f"nmap failed (exit {result.returncode}): {result.stderr.strip()}"

    hosts = _parse_nmap_grepable(result.stdout)
    if not hosts:
        return "No hosts found."

    lines = []
    for h in hosts:
        lines.append(f"Host: {h['host']} ({h['status']})")
        for p in h.get("ports", []):
            lines.append(f"  {p['port']}/{p['proto']}  {p['state']}  {p['service']}")
        lines.append("")
    return "\n".join(lines)


@app.tool()
def scan_deep(target: str, ports: str = "1-10000", timeout: int = 600) -> str:
    """Deeper nmap scan with -sV service/version detection on `ports`
    (default "1-10000" -- an nmap-style range or comma list, e.g.
    "80,443,8080"). Slower than scan_ports(); narrow `ports` to what
    scan_ports() already found open when possible."""
    args = ["-T4", "-p", ports, "-sV", "-oG", "-", target]
    try:
        result = run_tool("nmap", args, timeout=timeout)
    except FileNotFoundError:
        return "Error: nmap not found."
    except subprocess.TimeoutExpired:
        return f"Error: nmap timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

    if result.returncode != 0:
        return f"nmap failed (exit {result.returncode}): {result.stderr.strip()}"

    hosts = _parse_nmap_grepable(result.stdout)
    if not hosts:
        return "No hosts found."

    lines = []
    for h in hosts:
        lines.append(f"Host: {h['host']} ({h['status']})")
        for p in h.get("ports", []):
            lines.append(f"  {p['port']}/{p['proto']}  {p['state']}  {p['service']}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    print("nmap-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
