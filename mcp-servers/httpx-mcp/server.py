import html
import json
import os
import shutil
import sys
import tempfile

try:
    from datetime import UTC, datetime
except ImportError:  # datetime.UTC was added in Python 3.11; README's
    # documented minimum is 3.10 -- without this shim, the whole module
    # fails to import on 3.10 and the server crashes before it even
    # starts, which OpenCode/Claude Code just report as "connection
    # closed"/"not working" with the real ImportError never surfaced.
    from datetime import datetime, timezone
    UTC = timezone.utc

from mcp.server.fastmcp import FastMCP

sys.path.insert(0, __file__.rsplit("/", 2)[0])
import job_runtime

app = FastMCP("httpx-mcp")

REPORTS_DIR = __file__.rsplit("/", 3)[0] + "/data/reports"

# See dalfox-mcp/server.py for the full background-job rationale. _meta
# tracks per-job cleanup/formatting state (the input file listing domains,
# and for screenshot_hosts, the -srd scratch dir) that has to survive
# until check_scan() actually collects the finished job -- unlike the old
# blocking calls' `finally:` blocks, which ran before the caller had any
# result to inspect, cleanup here has to happen AFTER the result is read.
_jobs: dict = {}
_meta: dict[str, dict] = {}


def _write_domains_file(domains: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        for d in domains.replace(",", "\n").splitlines():
            d = d.strip()
            if d:
                f.write(d + "\n")
        return f.name


def _format_probe(stdout: str, returncode: int, stderr: str) -> str:
    if returncode != 0 and not stdout:
        return f"httpx failed (exit {returncode}): {stderr.strip()}"

    lines = []
    for raw in stdout.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            lines.append(raw)
            continue

        url = data.get("url", "")
        status = data.get("status_code", "?")
        title = data.get("title", "?")
        tech = ", ".join(data.get("tech", [])) if data.get("tech") else "?"
        server = data.get("webserver", "?")
        length = data.get("content_length", "?")

        parts = [f"  {url}"]
        parts.append(f"    Status: {status} | Title: {title} | Server: {server}")
        parts.append(f"    Tech: {tech} | Length: {length}")
        lines.append("\n".join(parts))

    if not lines:
        return "No live hosts found."
    return f"Probed {len(lines)} host(s):\n" + "\n".join(lines)


@app.tool()
def probe_hosts(domains: str, ports: str = "80,443", threads: int = 50, timeout: int = 120) -> str:
    """Start probing hosts for liveness with httpx in the background,
    returning immediately with a job_id -- status code, title, tech stack,
    server header, content length. `domains` is a single string of one or
    more hostnames, comma- or newline-separated (e.g.
    "example.com,api.example.com" or "example.com\\napi.example.com") --
    NOT a list. Each domain is probed on every port in `ports` (default
    "80,443"). Poll check_scan(job_id) for the result -- a large host list
    can take longer than an MCP client's own per-call timeout, so this
    never blocks waiting for httpx to finish."""
    input_path = _write_domains_file(domains)
    args = [
        "-l", input_path,
        "-ports", ports,
        "-threads", str(threads),
        "-silent",
        "-status-code", "-title", "-tech-detect",
        "-content-length", "-web-server",
        "-json",
    ]
    try:
        result = job_runtime.start_job("httpx", args, timeout, _jobs)
    except FileNotFoundError:
        os.unlink(input_path)
        return "Error: httpx not found. Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    except Exception as e:
        os.unlink(input_path)
        return f"Error: {e}"

    job_id = result["job_id"]
    _meta[job_id] = {"kind": "probe", "input_path": input_path, "work_dir": None}
    return (f"Started httpx probe (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def screenshot_hosts(domains: str, ports: str = "80,443", timeout: int = 180) -> str:
    """Start screenshotting each live host with a headless browser in the
    background, returning immediately with a job_id -- once done, builds a
    single self-contained HTML gallery (screenshots embedded as base64 --
    no external image files to keep track of). Doubles as report PoC
    evidence for visual/UI-based findings. Uses the local system
    Chrome/Chromium if one's installed (fast); otherwise httpx downloads
    its own headless browser on first run, which can take several
    minutes -- exactly the kind of run that used to risk exceeding an MCP
    client's own per-call timeout while blocking. Poll check_scan(job_id)
    for the result."""
    input_path = _write_domains_file(domains)
    work_dir = tempfile.mkdtemp(prefix="huntmcp-httpx-ss-")

    args = [
        "-l", input_path,
        "-ports", ports,
        "-silent",
        "-screenshot",
        "-json",
        # httpx always writes response/screenshot files somewhere for
        # -screenshot (not just when -store-response is passed) -- -srd
        # pins that to a throwaway dir instead of littering wherever this
        # process's cwd happens to be. We only need screenshot_bytes from
        # the JSON below, so the files themselves are deleted afterward.
        "-srd", work_dir,
    ]
    if shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser"):
        args.append("-system-chrome")

    try:
        result = job_runtime.start_job("httpx", args, timeout, _jobs, cwd=work_dir)
    except FileNotFoundError:
        os.unlink(input_path)
        shutil.rmtree(work_dir, ignore_errors=True)
        return "Error: httpx not found. Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    except Exception as e:
        os.unlink(input_path)
        shutil.rmtree(work_dir, ignore_errors=True)
        return f"Error: {e}"

    job_id = result["job_id"]
    _meta[job_id] = {"kind": "screenshot", "input_path": input_path, "work_dir": work_dir}
    return (f"Started httpx screenshot run (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s -- a first-run headless-browser "
            f"download can take several minutes).")


def _build_gallery(stdout: str) -> list[dict]:
    shots = []
    for raw in stdout.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        b64 = data.get("screenshot_bytes")
        if not b64:
            continue
        shots.append({
            "url": data.get("url", data.get("input", "?")),
            "title": data.get("title") or "(no title)",
            "status": data.get("status_code", "?"),
            "webserver": data.get("webserver") or "?",
            "b64": b64,
        })
    return shots


def _write_gallery(shots: list[dict]) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    gallery_path = os.path.join(REPORTS_DIR, f"screenshots-{ts}.html")

    cards = []
    for s in shots:
        cards.append(f"""
    <div class="card">
      <img src="data:image/png;base64,{s['b64']}" alt="{html.escape(s['url'])}">
      <div class="meta">
        <strong>{html.escape(s['url'])}</strong><br>
        {html.escape(str(s['status']))} &middot; {html.escape(s['title'])} &middot; {html.escape(s['webserver'])}
      </div>
    </div>""")

    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>HuntMCP screenshot gallery -- {ts}</title>
<style>
body {{ font-family: system-ui, sans-serif; background: #111; color: #eee; margin: 2rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 1.5rem; }}
.card {{ background: #1a1a1a; border-radius: 8px; overflow: hidden; border: 1px solid #333; }}
.card img {{ width: 100%; display: block; border-bottom: 1px solid #333; }}
.meta {{ padding: 0.75rem 1rem; font-size: 0.85rem; word-break: break-all; }}
</style></head>
<body>
<h1>HuntMCP screenshot gallery</h1>
<p>{len(shots)} host(s) &middot; generated {ts}</p>
<div class="grid">{"".join(cards)}</div>
</body></html>
"""
    with open(gallery_path, "w") as f:
        f.write(page)
    return gallery_path


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a run started by probe_hosts()/screenshot_hosts(). Returns
    "status: running (Xs elapsed)" while httpx is still working; once
    done, returns the same probe summary probe_hosts() used to return
    directly, or (for a screenshot_hosts() job) the path to the generated
    gallery HTML file. Keep polling every ~10-15s until it stops saying
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
    if meta:
        try:
            os.unlink(meta["input_path"])
        except OSError:
            pass
        if meta["work_dir"]:
            shutil.rmtree(meta["work_dir"], ignore_errors=True)

    if result["status"] == "timeout":
        return result["error"]
    if meta is None:
        return "httpx finished, but this job's cleanup/formatting metadata was already collected."

    prefix = job_runtime.block_prefix(result)

    if meta["kind"] == "probe":
        return prefix + _format_probe(result["stdout"], result["returncode"], result["stderr"])

    # screenshot_hosts job
    if result["returncode"] != 0 and not result["stdout"]:
        return prefix + f"httpx failed (exit {result['returncode']}): {result['stderr'].strip()}"
    shots = _build_gallery(result["stdout"])
    if not shots:
        return prefix + "No screenshots captured (no live hosts, or headless browser unavailable)."
    gallery_path = _write_gallery(shots)
    return prefix + f"Screenshotted {len(shots)} host(s). Gallery: {gallery_path}"


@app.tool()
def list_scans() -> str:
    """List httpx runs (probe or screenshot) still running in this
    session -- job_id, elapsed time, and whether a run has been going long
    enough (30+ min) that it's likely been abandoned rather than genuinely
    still busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No httpx runs currently running."
    lines = ["Running httpx runs:", ""]
    for j in jobs:
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("httpx-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
