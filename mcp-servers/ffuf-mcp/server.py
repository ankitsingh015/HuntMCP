import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import job_runtime  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("ffuf-mcp")

PROJECT_WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "wordlists")
SYSTEM_WORDLIST_DIR = "/usr/share/wordlists"

# See dalfox-mcp/server.py for the full background-job rationale. _meta
# tracks per-job (url, no_results_message, field_key) so check_scan()
# reproduces each tool's original wording without job_runtime needing to
# know anything about ffuf's own output shape. The header is built fresh
# with an f-string at format-time (see _format_results) rather than
# stored as a template string run through .format(n=...) later -- an
# earlier version did the latter, and a url containing a literal "{"/"}"
# (a REST path template like /users/{id}, plausible input here) collided
# with the {n} placeholder, raising KeyError inside check_scan() after
# the job was already popped, permanently losing the run's results.
_jobs: dict = {}
_meta: dict[str, dict] = {}


def _resolve_wordlist(wordlist: str) -> str:
    """Prefer HuntMCP's own curated wordlists (knowledge/wordlists/) over
    the system default -- those are project-tracked, reviewed content;
    /usr/share/wordlists is whatever happened to get installed on this
    machine, if anything did. Absolute paths and explicit system-relative
    names (e.g. "seclists/...") still work unchanged."""
    if wordlist.startswith("/"):
        return wordlist
    if not wordlist:
        default = os.path.join(PROJECT_WORDLIST_DIR, "directories.txt")
        if os.path.isfile(default):
            return default
        return os.path.join(SYSTEM_WORDLIST_DIR, "dirb", "common.txt")
    project_path = os.path.join(PROJECT_WORDLIST_DIR, wordlist)
    if os.path.isfile(project_path):
        return project_path
    return os.path.join(SYSTEM_WORDLIST_DIR, wordlist)


def _format_results(url: str | None, stdout: str, returncode: int, stderr: str,
                     no_results_message: str, field_key: str) -> str:
    if not stdout.strip():
        # ffuf ALWAYS writes its banner + progress bar to stderr, even on a
        # completely successful run that just happens to find zero matches
        # (the common case) -- `if stderr:` was true on every such run, so
        # a normal "nothing found" outcome was reported as if something
        # had gone wrong, stderr dump and all. returncode is the actual
        # signal for a real failure.
        if returncode != 0:
            return f"ffuf failed (exit {returncode}). Stderr: {stderr.strip()[:300]}"
        return no_results_message

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return stdout.strip()[:1000]

    results = data.get("results", [])
    if not results:
        return no_results_message

    header = f"ffuf found {len(results)} path(s) on {url}:" if field_key == "path" else \
        f"ffuf found {len(results)} result(s):"
    lines = [header, ""]
    for r in sorted(results, key=lambda x: x.get("status", 0)):
        val = r.get("input", {}).get("FUZZ", "?")
        status = r.get("status", "?")
        length = r.get("length", "?")
        words = r.get("words", "?")
        if field_key == "path":
            lines.append(f"  /{val:40s} {status:3d}  [{length}b / {words}w]")
        else:
            lines.append(f"  FUZZ={val:30s} {status:3d}  [{length}b]")
    return "\n".join(lines)


def _start(args: list[str], timeout: int, url: str | None,
           no_results_message: str, field_key: str) -> str:
    try:
        result = job_runtime.start_job("ffuf", args, timeout, _jobs)
    except FileNotFoundError:
        return "Error: ffuf not found. Install with: go install github.com/ffuf/ffuf/v2@latest"
    except Exception as e:
        return f"Error: {e}"
    job_id = result["job_id"]
    _meta[job_id] = {
        "url": url,
        "no_results_message": no_results_message,
        "field_key": field_key,
    }
    return (f"Started ffuf run (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def fuzz_directory(url: str, wordlist: str = "", extensions: str = "", timeout: int = 180) -> str:
    """Start a directory/file brute-force of `url` with ffuf in the
    background, returning immediately with a job_id -- a full wordlist run
    can take longer than an MCP client's own per-call timeout, so this
    never blocks waiting for ffuf to finish. `url` is the BASE URL only --
    "/FUZZ" is appended automatically, don't include it yourself.
    `wordlist` is a filename resolved against HuntMCP's own knowledge/
    wordlists/ first, then /usr/share/wordlists/ (or an absolute path);
    empty defaults to knowledge/wordlists/directories.txt. `extensions` is
    comma-separated, no leading dots (e.g. "php,bak"). 404 responses are
    filtered out automatically. Poll check_scan(job_id) for the result."""
    wordlist = _resolve_wordlist(wordlist)
    args = [
        "-u", f"{url}/FUZZ",
        "-w", f"{wordlist}:FUZZ",
        "-fc", "404",
        "-of", "json",
        "-o", "-",
        "-t", "50",
    ]
    if extensions:
        args.extend(["-e", extensions])
    return _start(args, timeout, url, f"No directories found on {url}.", "path")


@app.tool()
def fuzz_with_data(url: str, wordlist: str = "", method: str = "POST",
                    data_template: str = "user=FUZZ&pass=test", timeout: int = 180) -> str:
    """Start fuzzing a request body against `url` (e.g. brute-forcing a
    login field or an ID in a POST body) in the background -- `data_template`
    MUST contain the literal word "FUZZ" exactly where each wordlist entry
    should be substituted (default "user=FUZZ&pass=test" fuzzes the
    username). `wordlist` resolves the same way as fuzz_directory()'s. 404
    responses are filtered out automatically. Poll check_scan(job_id) for
    the result."""
    wordlist = _resolve_wordlist(wordlist)
    args = [
        "-u", url,
        "-w", f"{wordlist}:FUZZ",
        "-X", method,
        "-d", data_template,
        "-fc", "404",
        "-of", "json",
        "-o", "-",
        "-t", "30",
    ]
    return _start(args, timeout, None, "No results found.", "fuzz")


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a run started by fuzz_directory()/fuzz_with_data(). Returns
    "status: running (Xs elapsed)" while ffuf is still working, or the
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
    if result["status"] == "timeout":
        return result["error"]
    if meta is None:
        return "ffuf finished, but this job's result-formatting metadata was already collected."
    formatted = _format_results(meta["url"], result["stdout"], result["returncode"], result["stderr"],
                                 meta["no_results_message"], meta["field_key"])
    return job_runtime.block_prefix(result) + formatted


@app.tool()
def list_scans() -> str:
    """List ffuf runs still running in this session -- job_id, elapsed
    time, and whether a run has been going long enough (30+ min) that
    it's likely been abandoned rather than genuinely still busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No ffuf runs currently running."
    lines = ["Running ffuf runs:", ""]
    for j in jobs:
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("ffuf-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
