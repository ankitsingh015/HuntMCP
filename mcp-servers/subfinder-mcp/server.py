import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import job_runtime  # noqa: E402
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("subfinder-mcp")

# See dalfox-mcp/server.py for the full background-job rationale.
# list_sources() stays a direct run_tool() call -- it's a fixed, fast
# (15s-capped) local lookup, not a scan against a live target, so it
# was never at risk of the timeout mismatch this module exists to fix.
_jobs: dict = {}
_domains: dict[str, str] = {}


def _format_findings(domain: str, stdout: str, returncode: int, stderr: str) -> str:
    if returncode != 0:
        return f"subfinder failed (exit {returncode}): {stderr.strip()}"

    subdomains = [s.strip() for s in stdout.splitlines() if s.strip()]
    if not subdomains:
        return "No subdomains found."

    lines = [f"Found {len(subdomains)} subdomains for {domain}:", ""]
    for s in sorted(subdomains):
        lines.append(f"  {s}")
    return "\n".join(lines)


@app.tool()
def run_subfinder(domain: str, sources: str = "", threads: int = 10, timeout: int = 120) -> str:
    """Start passive subdomain enumeration for `domain` via subfinder in
    the background, returning immediately with a job_id -- a full source
    sweep can take longer than an MCP client's own per-call timeout, so
    this never blocks waiting for subfinder to finish. `sources`
    optionally restricts to a comma-separated subset of list_sources()'
    output (e.g. "crtsh,virustotal") -- omit to use every configured
    source. Poll check_scan(job_id) for the sorted, deduplicated list of
    discovered subdomains."""
    args = ["-d", domain, "-silent", "-t", str(threads)]
    if sources:
        args.extend(["-sources", sources])

    try:
        result = job_runtime.start_job("subfinder", args, timeout, _jobs)
    except FileNotFoundError:
        return "Error: subfinder not found. Install with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    except Exception as e:
        return f"Error: {e}"

    job_id = result["job_id"]
    _domains[job_id] = domain
    return (f"Started subfinder run for {domain} (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a run started by run_subfinder(). Returns "status: running (Xs
    elapsed)" while subfinder is still working, or the same
    subdomain-list text run_subfinder() used to return directly once it's
    done. Keep polling every ~10-15s until it stops saying "running"."""
    result = job_runtime.poll_job(job_id, _jobs)
    if "status" not in result:
        # Only the true "no such job" case has no status key at all --
        # a "timeout" status also carries an "error" key (alongside
        # stdout/stderr/elapsed_s), and must fall through to the
        # cleanup below rather than returning early and leaking it.
        return result["error"]

    if result["status"] == "running":
        return f"Still running -- {result['elapsed_s']}s elapsed so far. Poll again shortly."

    domain = _domains.pop(job_id, "target")
    if result["status"] == "timeout":
        return result["error"]
    formatted = _format_findings(domain, result["stdout"], result["returncode"], result["stderr"])
    return job_runtime.block_prefix(result) + formatted


@app.tool()
def list_scans() -> str:
    """List subfinder runs still running in this session -- job_id,
    domain, elapsed time, and whether a run has been going long enough
    (30+ min) that it's likely been abandoned rather than genuinely still
    busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No subfinder runs currently running."
    lines = ["Running subfinder runs:", ""]
    for j in jobs:
        domain = _domains.get(j["job_id"], "?")
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {domain}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


@app.tool()
def list_sources() -> str:
    """List every subdomain-enumeration source subfinder is configured to
    use (marked with * if it needs an API key that isn't set). No
    arguments -- the output's source names are what run_subfinder()'s
    optional `sources` param accepts."""
    try:
        result = run_tool("subfinder", ["-ls"], timeout=15)
    except FileNotFoundError:
        return "Error: subfinder not found."
    except Exception as e:
        return f"Error: {e}"
    return result.stdout.strip() or "No sources listed."


if __name__ == "__main__":
    print("subfinder-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
