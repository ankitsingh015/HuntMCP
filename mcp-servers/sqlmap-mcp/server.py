import json
import os
import re
import subprocess
import sys
import tempfile
from mcp.server.fastmcp import FastMCP

app = FastMCP("sqlmap-mcp")

OUTPUT_DIR = "/tmp/huntmcp-sqlmap"


def _ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


@app.tool()
def test_injection(url: str, method: str = "GET", data: str = "", level: int = 1, risk: int = 1, timeout: int = 300) -> str:
    _ensure_output_dir()
    with tempfile.TemporaryDirectory(dir=OUTPUT_DIR) as tmpdir:
        cmd = [
            "sqlmap", "-u", url,
            "--batch",
            "--output-dir", tmpdir,
            "--level", str(level),
            "--risk", str(risk),
            "--threads", "5",
        ]
        if method.upper() == "POST" and data:
            cmd.extend(["--data", data])
        cmd.extend(["--forms"])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return "Error: sqlmap not found. Install with: pip install sqlmap"
        except subprocess.TimeoutExpired:
            return f"Error: sqlmap timed out after {timeout}s"
        except Exception as e:
            return f"Error: {e}"

        output = result.stdout + result.stderr

        vulns = []
        for line in output.splitlines():
            if "sqlmap identified the following" in line.lower():
                vulns.append("sqlmap identified injection point(s)")
            m = re.search(r"Parameter:\s+(.+?)\s+\((\w+)\)", line)
            if m:
                vulns.append(f"  Parameter: {m.group(1)} ({m.group(2)})")
            m = re.search(r"Type:\s+(.+?)(?:\s+Title:\s+(.+?))?(?:\s+Payload:\s+(.+))?", line)
            if m:
                vulns.append(f"  Type: {m.group(1).strip()}")

        if not vulns:
            return f"No injection found at {url} (level={level}, risk={risk})."

        lines = [f"sqlmap results for {url}:", ""]
        lines.extend(vulns)
        return "\n".join(lines)


@app.tool()
def test_with_data(url: str, data: str, method: str = "POST", level: int = 2, timeout: int = 300) -> str:
    _ensure_output_dir()
    with tempfile.TemporaryDirectory(dir=OUTPUT_DIR) as tmpdir:
        cmd = [
            "sqlmap", "-u", url,
            "--data", data,
            "--batch",
            "--output-dir", tmpdir,
            "--level", str(level),
            "--threads", "5",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return "Error: sqlmap not found."
        except subprocess.TimeoutExpired:
            return f"Error: sqlmap timed out after {timeout}s"
        except Exception as e:
            return f"Error: {e}"

        output = result.stdout + result.stderr
        vulns = []
        for line in output.splitlines():
            if "sqlmap identified the following" in line.lower():
                vulns.append("sqlmap identified injection point(s)")
            m = re.search(r"Parameter:\s+(.+?)\s+\((\w+)\)", line)
            if m:
                vulns.append(f"  Parameter: {m.group(1)} ({m.group(2)})")

        if not vulns:
            return f"No injection found with the provided data."

        lines = [f"sqlmap results:", ""]
        lines.extend(vulns)
        return "\n".join(lines)


if __name__ == "__main__":
    print("sqlmap-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
