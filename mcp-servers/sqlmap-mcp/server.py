import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from engagement_paths import resolve_dir  # noqa: E402
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("sqlmap-mcp")


def _output_dir() -> str:
    # Resolved fresh per call (not cached at import time) so a mid-session
    # `switch-engagement.sh` actually takes effect -- sqlmap's scratch dumps
    # land under the ACTIVE target's own data/engagements/<slug>/tmp-sqlmap/
    # directory instead of a flat, unscoped /tmp path shared across every
    # target ever hunted from this machine. Falls back to the old flat /tmp
    # path only when no engagement is active at all (ad hoc dev/testing).
    return resolve_dir("tmp-sqlmap", override_env="HUNTMCP_SQLMAP_TMP",
                        legacy_default="/tmp/huntmcp-sqlmap")


@app.tool()
def test_injection(url: str, method: str = "GET", data: str = "", level: int = 1, risk: int = 1, timeout: int = 300) -> str:
    with tempfile.TemporaryDirectory(dir=_output_dir()) as tmpdir:
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

        try:
            result = run_tool("sqlmap", args, timeout=timeout)
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
            # sqlmap prints Type:/Title:/Payload: on separate lines, never on
            # the same line as each other -- so the trailing optional groups
            # this used to have never matched, and the lazy `.+?` before them
            # grabbed only the first character of the type (e.g. "b" instead
            # of "boolean-based blind"). Greedy-match to end of line instead.
            m = re.search(r"Type:\s+(.+)", line)
            if m:
                vulns.append(f"  Type: {m.group(1).strip()}")

        if not vulns:
            return f"No injection found at {url} (level={level}, risk={risk})."

        lines = [f"sqlmap results for {url}:", ""]
        lines.extend(vulns)
        return "\n".join(lines)


@app.tool()
def test_with_data(url: str, data: str, method: str = "POST", level: int = 2, timeout: int = 300) -> str:
    with tempfile.TemporaryDirectory(dir=_output_dir()) as tmpdir:
        args = [
            "-u", url,
            "--data", data,
            "--batch",
            "--output-dir", tmpdir,
            "--level", str(level),
            "--threads", "5",
        ]
        try:
            result = run_tool("sqlmap", args, timeout=timeout)
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
