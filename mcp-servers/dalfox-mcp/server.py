import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import job_runtime  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("dalfox-mcp")

# Background jobs live only in this process's memory -- see
# job_runtime.py's module docstring for why. _targets tracks
# job_id -> (label, verbose): the url/param being scanned, and whether
# check_scan() should format it scan_url()-style (full block per finding)
# or scan_parameter()-style (compact one-liner) -- purely local
# presentation state job_runtime itself doesn't need to know about.
_jobs: dict = {}
_targets: dict[str, tuple[str, bool]] = {}


def _format_findings(label: str, stdout: str, returncode: int, stderr: str, verbose: bool) -> str:
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "vuln": data.get("vuln", "?"),
            "param": data.get("param", "?"),
            "evidence": data.get("evidence", ""),
            "severity": data.get("severity", "?"),
            "type": data.get("type", "?"),
            "payload": data.get("payload", ""),
        })

    # A crashed/failed run with no parsed findings used to be silently
    # reported as "no XSS found" instead of surfacing the failure.
    if returncode != 0 and not findings:
        return f"dalfox failed (exit {returncode}): {stderr.strip()[:500]}"

    if not findings:
        return f"No XSS vulnerabilities found on {label}." if verbose else f"No XSS found on parameter '{label}'."

    if verbose:
        lines = [f"dalfox found {len(findings)} XSS issue(s) on {label}:", ""]
        for f in findings:
            lines.append(f"  [{f['severity'].upper()}] {f['vuln']}")
            lines.append(f"    Parameter: {f['param']}")
            lines.append(f"    Payload:   {f['payload'][:120]}")
            if f["evidence"]:
                lines.append(f"    Evidence:  {f['evidence'][:120]}")
            lines.append("")
        return "\n".join(lines)

    lines = [f"XSS findings on parameter '{label}' ({len(findings)}):", ""]
    for f in findings:
        lines.append(f"  [{f['vuln']}] Payload: {f['payload'][:120]}")
    return "\n".join(lines)


def _start(label: str, args: list[str], timeout: int, verbose: bool) -> str:
    try:
        result = job_runtime.start_job("dalfox", args, timeout, _jobs)
    except FileNotFoundError:
        return "Error: dalfox not found. Install with: go install github.com/hahwul/dalfox/v2@latest"
    except Exception as e:
        return f"Error: {e}"
    job_id = result["job_id"]
    _targets[job_id] = (label, verbose)
    return (f"Started dalfox scan of {label} (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def scan_url(url: str, timeout: int = 180) -> str:
    """Start a dalfox scan of `url` for reflected/DOM XSS in the
    background and return immediately with a job_id -- tests every query
    parameter it finds automatically. Poll check_scan(job_id) for the
    result once it's done; a scan this thorough can take longer than an
    MCP client's own per-call timeout, so this never blocks waiting for
    dalfox to finish. Use scan_parameter() to target one specific
    parameter instead of all of them."""
    args = ["url", url, "--silence", "--format", "json"]
    return _start(url, args, timeout, verbose=True)


@app.tool()
def scan_parameter(url: str, param: str, timeout: int = 180) -> str:
    """Like scan_url(), but restricted to testing only `param` -- faster,
    and useful when you already suspect one specific parameter (e.g. a
    search/query field) rather than scanning every parameter on the page.
    Also backgrounded -- poll check_scan(job_id) for the result."""
    args = ["url", url, "--param", param, "--silence", "--format", "json"]
    return _start(param, args, timeout, verbose=False)


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a scan started by scan_url()/scan_parameter(). Returns "status:
    running (Xs elapsed)" while dalfox is still working, or the same
    findings-formatted text scan_url()/scan_parameter() used to return
    directly once it's done. Keep polling every ~10-15s until it stops
    saying "running"."""
    result = job_runtime.poll_job(job_id, _jobs)
    if "status" not in result:
        # Only the true "no such job" case has no status key at all --
        # a "timeout" status also carries an "error" key (alongside
        # stdout/stderr/elapsed_s), and must fall through to the
        # cleanup below rather than returning early and leaking it.
        return result["error"]

    if result["status"] == "running":
        return f"Still running -- {result['elapsed_s']}s elapsed so far. Poll again shortly."

    label, verbose = _targets.pop(job_id, ("target", True))
    if result["status"] == "timeout":
        return result["error"]
    formatted = _format_findings(label, result["stdout"], result["returncode"], result["stderr"], verbose)
    return job_runtime.block_prefix(result) + formatted


@app.tool()
def list_scans() -> str:
    """List dalfox scans still running in this session -- job_id, target,
    elapsed time, and whether a scan has been running long enough
    (30+ min) that it's likely been abandoned (agent stopped polling, or
    the session that started it ended) rather than genuinely still busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No dalfox scans currently running."
    lines = ["Running dalfox scans:", ""]
    for j in jobs:
        label, _ = _targets.get(j["job_id"], ("?", True))
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {label}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("dalfox-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
