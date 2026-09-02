import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import job_runtime  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("nmap-mcp")

# See dalfox-mcp/server.py for the full rationale -- same background-job
# pattern, same per-process-only job storage.
_jobs: dict = {}
_targets: dict[str, str] = {}


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


def _format_findings(stdout: str, returncode: int, stderr: str) -> str:
    if returncode != 0:
        return f"nmap failed (exit {returncode}): {stderr.strip()}"

    hosts = _parse_nmap_grepable(stdout)
    if not hosts:
        return "No hosts found."

    lines = []
    for h in hosts:
        lines.append(f"Host: {h['host']} ({h['status']})")
        for p in h.get("ports", []):
            lines.append(f"  {p['port']}/{p['proto']}  {p['state']}  {p['service']}")
        lines.append("")
    return "\n".join(lines)


def _start(target: str, args: list[str], timeout: int) -> str:
    try:
        result = job_runtime.start_job("nmap", args, timeout, _jobs)
    except FileNotFoundError:
        return "Error: nmap not found. Install with: apt install nmap"
    except Exception as e:
        return f"Error: {e}"
    job_id = result["job_id"]
    _targets[job_id] = target
    return (f"Started nmap scan of {target} (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def scan_ports(target: str, top_ports: int = 1000, timeout: int = 300) -> str:
    """Start a fast nmap scan of the `top_ports` (default 1000) most
    common ports on `target` -- no service-version detection, just
    open/closed state -- in the background, returning immediately with a
    job_id. A full top-ports sweep can take longer than an MCP client's
    own per-call timeout, so this never blocks waiting for nmap to finish.
    Poll check_scan(job_id) for the result. Use scan_deep() for -sV
    service fingerprinting on a specific range."""
    args = ["-T4", "--top-ports", str(top_ports), "-oG", "-", target]
    return _start(target, args, timeout)


@app.tool()
def scan_deep(target: str, ports: str = "1-10000", timeout: int = 600) -> str:
    """Start a deeper nmap scan with -sV service/version detection on
    `ports` (default "1-10000" -- an nmap-style range or comma list, e.g.
    "80,443,8080") in the background. Slower than scan_ports(); narrow
    `ports` to what scan_ports() already found open when possible. Poll
    check_scan(job_id) for the result."""
    args = ["-T4", "-p", ports, "-sV", "-oG", "-", target]
    return _start(target, args, timeout)


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a scan started by scan_ports()/scan_deep(). Returns "status:
    running (Xs elapsed)" while nmap is still working, or the same
    host/port-formatted text those tools used to return directly once
    it's done. Keep polling every ~10-15s until it stops saying
    "running"."""
    result = job_runtime.poll_job(job_id, _jobs)
    if "status" not in result:
        # Only the true "no such job" case has no status key at all --
        # a "timeout" status also carries an "error" key (alongside
        # stdout/stderr/elapsed_s), and must fall through to the
        # cleanup below rather than returning early and leaking it.
        return result["error"]

    if result["status"] == "running":
        return f"Still running -- {result['elapsed_s']}s elapsed so far. Poll again shortly."

    _targets.pop(job_id, None)
    if result["status"] == "timeout":
        return result["error"]
    formatted = _format_findings(result["stdout"], result["returncode"], result["stderr"])
    return job_runtime.block_prefix(result) + formatted


@app.tool()
def list_scans() -> str:
    """List nmap scans still running in this session -- job_id, target,
    elapsed time, and whether a scan has been running long enough
    (30+ min) that it's likely been abandoned rather than genuinely still
    busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No nmap scans currently running."
    lines = ["Running nmap scans:", ""]
    for j in jobs:
        target = _targets.get(j["job_id"], "?")
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {target}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("nmap-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
