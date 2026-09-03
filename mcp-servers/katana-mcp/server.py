import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import job_runtime  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("katana-mcp")

# See dalfox-mcp/server.py for the full background-job rationale.
# _targets carries the target url per job (or None for crawl_with_filter,
# whose header never names a single url) -- NOT a pre-built header string.
# An earlier version built "Discovered {n} endpoint(s) for " + url + ":"
# as a template and ran it through .format(n=...) later; a url containing
# a literal "{"/"}" (a REST path template like /users/{id} -- plausible
# input in exactly this security-testing context) collided with that
# placeholder and raised KeyError inside check_scan(), by which point the
# job was already popped, permanently losing the crawl's results. Building
# the header fresh with an f-string at format-time (like nuclei-mcp/
# dalfox-mcp already do) sidesteps the whole class of bug: an f-string
# only interprets "{"/"}" written literally in the source, never from a
# runtime string's contents.
_jobs: dict = {}
_targets: dict[str, str | None] = {}


def _format_findings(url: str | None, stdout: str, returncode: int, stderr: str) -> str:
    if returncode != 0:
        return f"katana failed (exit {returncode}): {stderr.strip()}"

    endpoints = sorted(set(e.strip() for e in stdout.splitlines() if e.strip()))
    if not endpoints:
        return "No endpoints discovered."

    header = f"Discovered {len(endpoints)} endpoint(s) for {url}:" if url else \
        f"Discovered {len(endpoints)} endpoint(s) with filter:"
    lines = [header, ""]
    for ep in endpoints:
        lines.append(f"  {ep}")
    return "\n".join(lines)


def _start(args: list[str], timeout: int, url: str | None) -> str:
    try:
        result = job_runtime.start_job("katana", args, timeout, _jobs)
    except FileNotFoundError:
        return "Error: katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest"
    except Exception as e:
        return f"Error: {e}"
    job_id = result["job_id"]
    _targets[job_id] = url
    return (f"Started katana crawl (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def crawl(url: str, depth: int = 2, delay: int = 0, timeout: int = 120) -> str:
    """Start crawling `url` with katana in the background, returning
    immediately with a job_id -- a deep crawl can take longer than an MCP
    client's own per-call timeout, so this never blocks waiting for katana
    to finish. `depth` is how many link-hops deep to follow (default 2).
    `delay` adds seconds between requests (0 = no delay). Poll
    check_scan(job_id) for every discovered endpoint URL (deduplicated,
    sorted)."""
    args = ["-u", url, "-d", str(depth), "-silent", "-o", "-"]
    if delay > 0:
        args.extend(["-delay", str(delay)])
    return _start(args, timeout, url)


@app.tool()
def crawl_with_filter(url: str, depth: int = 2, extensions: str = "", timeout: int = 120) -> str:
    """Like crawl(), but `extensions` is an EXCLUDE list (katana's -ef
    flag), not an include filter -- e.g. extensions="png,css,js" drops
    those from the results, it doesn't restrict to only them. Comma-
    separated, no leading dots (e.g. "png,css" not ".png,.css"). Also
    backgrounded -- poll check_scan(job_id) for the result."""
    args = ["-u", url, "-d", str(depth), "-silent", "-o", "-"]
    if extensions:
        args.extend(["-ef", extensions])
    return _start(args, timeout, None)


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a crawl started by crawl()/crawl_with_filter(). Returns
    "status: running (Xs elapsed)" while katana is still working, or the
    same endpoint-list text those tools used to return directly once it's
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

    url = _targets.pop(job_id, None)
    if result["status"] == "timeout":
        return result["error"]
    return _format_findings(url, result["stdout"], result["returncode"], result["stderr"])


@app.tool()
def list_scans() -> str:
    """List katana crawls still running in this session -- job_id, elapsed
    time, and whether a crawl has been going long enough (30+ min) that
    it's likely been abandoned rather than genuinely still busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No katana crawls currently running."
    lines = ["Running katana crawls:", ""]
    for j in jobs:
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("katana-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
