import json
import re
import subprocess
import sys
import tempfile
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
                pm = re.match(
                    r"(\d+)/(open|filtered|closed)/(tcp|udp)/([^/]*)/([^/]*)/([^/]*)/(.*)",
                    part,
                )
                if pm:
                    ports.append({
                        "port": int(pm.group(1)),
                        "state": pm.group(2),
                        "proto": pm.group(3),
                        "service": pm.group(7).strip() if pm.group(7) else pm.group(4),
                    })
            host["ports"] = ports
        hosts.append(host)
    return hosts


@app.tool()
def scan_ports(target: str, top_ports: int = 1000, timeout: int = 300) -> str:
    cmd = ["nmap", "-T4", "--top-ports", str(top_ports), "-oG", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
    cmd = ["nmap", "-T4", "-p", ports, "-sV", "-oG", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
