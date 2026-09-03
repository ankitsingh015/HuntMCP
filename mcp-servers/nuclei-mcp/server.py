import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import job_runtime  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("nuclei-mcp")

# See dalfox-mcp/server.py for the full rationale -- same background-job
# pattern, same per-process-only job storage. _targets carries (target,
# no_findings_message) so check_scan() reproduces the exact "no
# vulnerabilities" wording each tool used to return directly, without
# job_runtime needing to know anything about nuclei's own message shapes.
_jobs: dict = {}
_targets: dict[str, tuple[str, str]] = {}


def _format_findings(target: str, no_findings_message: str, stdout: str, returncode: int, stderr: str) -> str:
    if returncode != 0 and not stdout:
        return f"nuclei failed (exit {returncode}): {stderr.strip()}"

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
            "template": data.get("template-id", "?"),
            "name": data.get("info", {}).get("name", "?"),
            "severity": data.get("info", {}).get("severity", "?"),
            "matched": data.get("matched-at", data.get("host", "?")),
            "type": data.get("type", "?"),
        })

    if not findings:
        return no_findings_message

    lines = [f"nuclei found {len(findings)} issue(s) on {target}:", ""]
    for f in findings:
        lines.append(f"  [{f['severity'].upper()}] {f['name']}")
        lines.append(f"    Template: {f['template']}")
        lines.append(f"    Target:   {f['matched']}")
        lines.append(f"    Type:     {f['type']}")
        lines.append("")
    return "\n".join(lines)


def _start(target: str, args: list[str], timeout: int, no_findings_message: str) -> str:
    try:
        result = job_runtime.start_job("nuclei", args, timeout, _jobs)
    except FileNotFoundError:
        return ("Error: nuclei not found. Install with: "
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    except Exception as e:
        return f"Error: {e}"
    job_id = result["job_id"]
    _targets[job_id] = (target, no_findings_message)
    return (f"Started nuclei scan of {target} (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def scan_target(target: str, severity: str = "medium,high,critical", timeout: int = 300) -> str:
    """Start nuclei's full default template set against `target`, filtered
    to `severity` (comma-separated: info,low,medium,high,critical --
    default "medium,high,critical"), in the background -- returns
    immediately with a job_id since a full-template run can take longer
    than an MCP client's own per-call timeout. Poll check_scan(job_id) for
    the result. Use scan_with_templates() instead to run a specific
    template/category rather than everything at that severity."""
    args = ["-u", target, "-severity", severity, "-silent", "-json"]
    return _start(target, args, timeout, f"No vulnerabilities found on {target} (severity: {severity}).")


@app.tool()
def scan_with_templates(target: str, templates: str, timeout: int = 300) -> str:
    """Run specific nuclei template(s) against `target` instead of the full
    default set. `templates` is nuclei's own -t syntax: a template ID/tag
    (e.g. "cves/2021" or "exposed-panels"), a file path, a directory path,
    or a comma-separated list of any of those. Also backgrounded -- poll
    check_scan(job_id) for the result."""
    args = ["-u", target, "-t", templates, "-silent", "-json"]
    return _start(target, args, timeout, "No vulnerabilities found with the specified templates.")


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a scan started by scan_target()/scan_with_templates(). Returns
    "status: running (Xs elapsed)" while nuclei is still working, or the
    same findings-formatted text those tools used to return directly once
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

    target, no_findings_message = _targets.pop(job_id, ("target", "No vulnerabilities found."))
    if result["status"] == "timeout":
        return result["error"]
    formatted = _format_findings(target, no_findings_message, result["stdout"], result["returncode"], result["stderr"])
    return job_runtime.block_prefix(result) + formatted


@app.tool()
def list_scans() -> str:
    """List nuclei scans still running in this session -- job_id, target,
    elapsed time, and whether a scan has been running long enough
    (30+ min) that it's likely been abandoned rather than genuinely still
    busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No nuclei scans currently running."
    lines = ["Running nuclei scans:", ""]
    for j in jobs:
        target, _ = _targets.get(j["job_id"], ("?", ""))
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {target}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("nuclei-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
