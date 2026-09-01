import html
import json
import shutil
import subprocess
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
from tool_resolver import run_tool

app = FastMCP("httpx-mcp")

REPORTS_DIR = __file__.rsplit("/", 3)[0] + "/data/reports"


@app.tool()
def probe_hosts(domains: str, ports: str = "80,443", threads: int = 50, timeout: int = 120) -> str:
    """Probe hosts for liveness with httpx -- status code, title, tech
    stack, server header, content length. `domains` is a single string of
    one or more hostnames, comma- or newline-separated (e.g.
    "example.com,api.example.com" or "example.com\\napi.example.com") --
    NOT a list. Each domain is probed on every port in `ports` (default
    "80,443")."""
    import os as _os
    input_path = None
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        for d in domains.replace(",", "\n").splitlines():
            d = d.strip()
            if d:
                f.write(d + "\n")
        input_path = f.name

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
        result = run_tool("httpx", args, timeout=timeout)
    except FileNotFoundError:
        return "Error: httpx not found. Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    except subprocess.TimeoutExpired:
        return f"Error: httpx timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"
    finally:
        if input_path:
            _os.unlink(input_path)

    if result.returncode != 0 and not result.stdout:
        return f"httpx failed (exit {result.returncode}): {result.stderr.strip()}"

    lines = []
    for raw in result.stdout.splitlines():
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
def screenshot_hosts(domains: str, ports: str = "80,443", timeout: int = 180) -> str:
    """Screenshot each live host with a headless browser and build a single
    self-contained HTML gallery (screenshots embedded as base64 -- no
    external image files to keep track of). Doubles as report PoC evidence
    for visual/UI-based findings. Uses the local system Chrome/Chromium if
    one's installed (fast); otherwise httpx downloads its own headless
    browser on first run, which can take several minutes."""
    import os as _os

    input_path = None
    work_dir = tempfile.mkdtemp(prefix="huntmcp-httpx-ss-")
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        for d in domains.replace(",", "\n").splitlines():
            d = d.strip()
            if d:
                f.write(d + "\n")
        input_path = f.name

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
        result = run_tool("httpx", args, timeout=timeout, cwd=work_dir)
    except FileNotFoundError:
        return "Error: httpx not found. Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    except subprocess.TimeoutExpired:
        return f"Error: httpx timed out after {timeout}s (headless screenshots are slow -- raise timeout or narrow the host list)"
    except Exception as e:
        return f"Error: {e}"
    finally:
        if input_path:
            _os.unlink(input_path)
        shutil.rmtree(work_dir, ignore_errors=True)

    if result.returncode != 0 and not result.stdout:
        return f"httpx failed (exit {result.returncode}): {result.stderr.strip()}"

    shots = []
    for raw in result.stdout.splitlines():
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

    if not shots:
        return "No screenshots captured (no live hosts, or headless browser unavailable)."

    _os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    gallery_path = _os.path.join(REPORTS_DIR, f"screenshots-{ts}.html")

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

    return f"Screenshotted {len(shots)} host(s). Gallery: {gallery_path}"


if __name__ == "__main__":
    print("httpx-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
