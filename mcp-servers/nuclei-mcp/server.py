import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("nuclei-mcp")


@app.tool()
def scan_target(target: str, severity: str = "medium,high,critical", timeout: int = 300) -> str:
    """Run nuclei's full default template set against `target`, filtered to
    `severity` (comma-separated: info,low,medium,high,critical -- default
    "medium,high,critical"). Use scan_with_templates() instead to run a
    specific template/category rather than everything at that severity."""
    args = [
        "-u", target,
        "-severity", severity,
        "-silent", "-json",
    ]
    try:
        result = run_tool("nuclei", args, timeout=timeout)
    except FileNotFoundError:
        return "Error: nuclei not found. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    except subprocess.TimeoutExpired:
        return f"Error: nuclei timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

    if result.returncode != 0 and not result.stdout:
        return f"nuclei failed (exit {result.returncode}): {result.stderr.strip()}"

    findings = []
    for line in result.stdout.splitlines():
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
        return f"No vulnerabilities found on {target} (severity: {severity})."

    lines = [f"nuclei found {len(findings)} issue(s) on {target}:", ""]
    for f in findings:
        lines.append(f"  [{f['severity'].upper()}] {f['name']}")
        lines.append(f"    Template: {f['template']}")
        lines.append(f"    Target:   {f['matched']}")
        lines.append(f"    Type:     {f['type']}")
        lines.append("")
    return "\n".join(lines)


@app.tool()
def scan_with_templates(target: str, templates: str, timeout: int = 300) -> str:
    """Run specific nuclei template(s) against `target` instead of the full
    default set. `templates` is nuclei's own -t syntax: a template ID/tag
    (e.g. "cves/2021" or "exposed-panels"), a file path, a directory path,
    or a comma-separated list of any of those."""
    args = [
        "-u", target,
        "-t", templates,
        "-silent", "-json",
    ]
    try:
        result = run_tool("nuclei", args, timeout=timeout)
    except FileNotFoundError:
        return "Error: nuclei not found."
    except subprocess.TimeoutExpired:
        return f"Error: nuclei timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

    findings = []
    for line in result.stdout.splitlines():
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
        })

    if not findings:
        return "No vulnerabilities found with the specified templates."

    lines = [f"Found {len(findings)} issue(s) with custom templates:", ""]
    for f in findings:
        lines.append(f"  [{f['severity'].upper()}] {f['name']} — {f['matched']}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("nuclei-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
