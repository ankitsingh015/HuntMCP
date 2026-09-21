import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import job_runtime  # noqa: E402
import templates_pin  # noqa: E402

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


def _resolve_templates_arg(templates: str) -> str:
    """Resolve each comma-separated entry of a caller-supplied -t value
    against the pinned templates snapshot, same way nuclei itself resolves
    a relative -t value against ITS OWN default template directory --
    except nuclei's own default directory is deliberately left unpopulated
    now (see templates_pin.py's module docstring: auto-update is disabled
    to avoid refilling the 64MB /tmp tmpfs), so a relative value like
    "http/exposed-panels" must be joined onto TEMPLATES_DIR here instead,
    or nuclei would silently fail to find it.

    Each entry is stripped of surrounding whitespace and empty entries are
    dropped -- found live (code review): an un-stripped "a, b" (the
    natural way to write a comma list) left a leading space baked into the
    second path, and a trailing comma produced an EMPTY entry that
    os.path.join(TEMPLATES_DIR, "") resolves to TEMPLATES_DIR itself,
    silently adding the entire pinned template library as a second -t
    entry. Raises ValueError if nothing usable remains after that -- an
    all-empty templates argument (e.g. "" or ",") is a caller mistake, not
    "scan everything".

    Every entry -- relative or absolute -- is only ever usable if it
    resolves INSIDE TEMPLATES_DIR: _start() only ever bind-mounts
    TEMPLATES_DIR into the sandbox (see its own extra_mounts= call), never
    an arbitrary caller-supplied path, so anything outside it could never
    actually be found by nuclei running in the read-only container.
    Raises ValueError otherwise, rather than silently building a -t
    argument nuclei can never resolve -- do NOT widen this to mount
    arbitrary host paths. The containment check is applied to the fully
    resolved (realpath'd) candidate for BOTH branches, not just absolute
    entries: os.path.join() does not collapse ".." components, so a
    relative entry like "../../../../etc/passwd" would otherwise skip the
    check entirely by taking the "not absolute" path -- adversarial
    review caught this exact gap in an earlier version of this function
    that only validated the isabs() branch."""
    entries = [e.strip() for e in templates.split(",") if e.strip()]
    if not entries:
        raise ValueError(f"{templates!r} contains no usable template path/ID")

    root = os.path.realpath(templates_pin.TEMPLATES_DIR)
    resolved = []
    for entry in entries:
        candidate = entry if os.path.isabs(entry) else os.path.join(templates_pin.TEMPLATES_DIR, entry)
        real = os.path.realpath(candidate)
        if real != root and not real.startswith(root + os.sep):
            raise ValueError(
                f"{entry!r} resolves outside the approved template root "
                f"({templates_pin.TEMPLATES_DIR}) -- only the pinned nuclei-templates "
                "snapshot is mounted into the sandbox, so a path escaping it (via a "
                "leading \"/\" or a \"..\" traversal) can never actually be found there. "
                "Pass a path relative to the snapshot instead (e.g. \"http/exposed-panels\")."
            )
        resolved.append(real)
    return ",".join(resolved)


def _start(target: str, args: list[str], timeout: int, no_findings_message: str) -> str:
    if not templates_pin.templates_available():
        return templates_pin.missing_templates_error()

    # -duc: without it nuclei still attempts an outbound network update
    # check on every run even though -t already points at a local,
    # non-default directory -- see templates_pin.py's module docstring.
    args = [*args, "-duc"]
    try:
        result = job_runtime.start_job(
            "nuclei", args, timeout, _jobs,
            extra_mounts=[templates_pin.TEMPLATES_DIR],
        )
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
    the result. Runs the complete pinned nuclei-templates library (see
    templates_pin.py) -- use scan_with_templates() instead to run a
    specific template/category rather than everything at that severity."""
    args = ["-u", target, "-severity", severity, "-silent", "-jsonl",
            "-t", templates_pin.TEMPLATES_DIR]
    return _start(target, args, timeout, f"No vulnerabilities found on {target} (severity: {severity}).")


@app.tool()
def scan_with_templates(target: str, templates: str, timeout: int = 300) -> str:
    """Run specific nuclei template(s) against `target` instead of the full
    default set. `templates` is nuclei's own -t syntax: a path relative to
    the pinned nuclei-templates snapshot (e.g. "http/exposed-panels" or
    "http/cves/2021"), or an absolute path -- but only if it resolves
    INSIDE that same pinned snapshot (only the snapshot is mounted into
    the sandbox, so an absolute path outside it can never actually be
    found there); or a comma-separated list of either. Also backgrounded
    -- poll check_scan(job_id) for the result."""
    try:
        resolved = _resolve_templates_arg(templates)
    except ValueError as e:
        return f"Error: {e}"
    args = ["-u", target, "-t", resolved, "-silent", "-jsonl"]
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
