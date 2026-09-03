import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engagement_paths import resolve_dir  # noqa: E402
import job_runtime  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("sqlmap-mcp")

# See dalfox-mcp/server.py for the full background-job rationale. sqlmap
# additionally needs a scratch --output-dir per run; unlike the original
# `with tempfile.TemporaryDirectory(...)` (which cleaned up the moment the
# `with` block exited -- fine for a blocking call, wrong here since the
# scan is still running long after start_job() returns), the dir is now
# created with mkdtemp() and torn down explicitly in check_scan() once the
# job is actually done, tracked per job_id in _meta alongside the exact
# "no injection found" wording and header line each tool used to return.
_jobs: dict = {}
_meta: dict[str, dict] = {}


def _output_dir() -> str:
    # Resolved fresh per call (not cached at import time) so a mid-session
    # `switch-engagement.sh` actually takes effect -- sqlmap's scratch dumps
    # land under the ACTIVE target's own data/engagements/<slug>/tmp-sqlmap/
    # directory instead of a flat, unscoped /tmp path shared across every
    # target ever hunted from this machine. Falls back to the old flat /tmp
    # path only when no engagement is active at all (ad hoc dev/testing).
    return resolve_dir("tmp-sqlmap", override_env="HUNTMCP_SQLMAP_TMP",
                        legacy_default="/tmp/huntmcp-sqlmap")


def _parse_vulns(output: str, include_type: bool) -> list[str]:
    vulns = []
    for line in output.splitlines():
        if "sqlmap identified the following" in line.lower():
            vulns.append("sqlmap identified injection point(s)")
        m = re.search(r"Parameter:\s+(.+?)\s+\((\w+)\)", line)
        if m:
            vulns.append(f"  Parameter: {m.group(1)} ({m.group(2)})")
        if include_type:
            # sqlmap prints Type:/Title:/Payload: on separate lines, never
            # on the same line as each other -- greedy-match to end of
            # line rather than a lazy `.+?` that would grab only the
            # first character of the type.
            m = re.search(r"Type:\s+(.+)", line)
            if m:
                vulns.append(f"  Type: {m.group(1).strip()}")
    return vulns


def _start(args: list[str], timeout: int, tmpdir: str,
           no_result_message: str, found_header: str, include_type: bool) -> str:
    try:
        result = job_runtime.start_job("sqlmap", args, timeout, _jobs)
    except FileNotFoundError:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return "Error: sqlmap not found. Install with: pip install sqlmap"
    except Exception as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return f"Error: {e}"
    job_id = result["job_id"]
    _meta[job_id] = {
        "tmpdir": tmpdir,
        "no_result_message": no_result_message,
        "found_header": found_header,
        "include_type": include_type,
    }
    return (f"Started sqlmap scan (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def test_injection(url: str, method: str = "GET", data: str = "", level: int = 1, risk: int = 1, timeout: int = 300) -> str:
    """Start sqlmap against `url` (GET params in the URL itself, or POST
    body via `data` when method="POST" -- `data` is silently ignored for
    GET, it's not appended as a query string) in the background, returning
    immediately with a job_id -- sqlmap runs can take longer than an MCP
    client's own per-call timeout, so this never blocks waiting for it to
    finish. Also auto-detects and tests any HTML forms on the page
    (--forms). `level`/`risk` are sqlmap's own 1-5 scales (higher = more
    payloads tried, slower). Poll check_scan(job_id) for the result. Use
    test_with_data() for a POST-only call without the GET/forms
    auto-detection path."""
    tmpdir = tempfile.mkdtemp(dir=_output_dir())
    args = [
        "-u", url,
        "--batch",
        "--output-dir", tmpdir,
        "--level", str(level),
        "--risk", str(risk),
        "--threads", "5",
    ]
    if method.upper() == "POST" and data:
        args.extend(["--data", data])
    args.extend(["--forms"])
    return _start(args, timeout, tmpdir,
                  f"No injection found at {url} (level={level}, risk={risk}).",
                  f"sqlmap results for {url}:", include_type=True)


@app.tool()
def test_with_data(url: str, data: str, method: str = "POST", level: int = 2, timeout: int = 300) -> str:
    """Like test_injection(), but with an explicit request body (`data`,
    e.g. "username=x&password=y" for a form-encoded POST, or a JSON string
    sqlmap can also parse). `method` is currently informational only --
    sqlmap is always invoked in --data mode here regardless of its value.
    No auto-form-detection -- this is for a known endpoint/body shape you
    already have. Also backgrounded -- poll check_scan(job_id) for the
    result."""
    tmpdir = tempfile.mkdtemp(dir=_output_dir())
    args = [
        "-u", url,
        "--data", data,
        "--batch",
        "--output-dir", tmpdir,
        "--level", str(level),
        "--threads", "5",
    ]
    return _start(args, timeout, tmpdir,
                  "No injection found with the provided data.",
                  "sqlmap results:", include_type=False)


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a scan started by test_injection()/test_with_data(). Returns
    "status: running (Xs elapsed)" while sqlmap is still working, or the
    same results-formatted text those tools used to return directly once
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

    meta = _meta.pop(job_id, None)
    tmpdir = meta["tmpdir"] if meta else None
    if tmpdir:
        shutil.rmtree(tmpdir, ignore_errors=True)
    if result["status"] == "timeout":
        return result["error"]
    if meta is None:
        return "sqlmap finished, but this job's scratch-dir/message metadata was already collected."

    output = result["stdout"] + result["stderr"]
    vulns = _parse_vulns(output, meta["include_type"])
    if not vulns:
        return job_runtime.block_prefix(result) + meta["no_result_message"]
    lines = [meta["found_header"], ""]
    lines.extend(vulns)
    return job_runtime.block_prefix(result) + "\n".join(lines)


@app.tool()
def list_scans() -> str:
    """List sqlmap scans still running in this session -- job_id, elapsed
    time, and whether a scan has been running long enough (30+ min) that
    it's likely been abandoned rather than genuinely still busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No sqlmap scans currently running."
    lines = ["Running sqlmap scans:", ""]
    for j in jobs:
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("sqlmap-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
