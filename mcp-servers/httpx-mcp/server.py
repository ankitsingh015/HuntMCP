import json
import subprocess
import sys
import tempfile
from mcp.server.fastmcp import FastMCP

app = FastMCP("httpx-mcp")


@app.tool()
def probe_hosts(domains: str, ports: str = "80,443", threads: int = 50, timeout: int = 120) -> str:
    import os as _os
    input_path = None
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        for d in domains.replace(",", "\n").splitlines():
            d = d.strip()
            if d:
                f.write(d + "\n")
        input_path = f.name

    cmd = [
        "httpx", "-l", input_path,
        "-ports", ports,
        "-threads", str(threads),
        "-silent",
        "-status-code", "-title", "-tech-detect",
        "-content-length", "-web-server",
        "-json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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


if __name__ == "__main__":
    print("httpx-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
