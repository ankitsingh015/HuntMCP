import json
import subprocess
import sys
from mcp.server.fastmcp import FastMCP

app = FastMCP("dalfox-mcp")


@app.tool()
def scan_url(url: str, timeout: int = 180) -> str:
    cmd = [
        "dalfox", "url", url,
        "--silence",
        "--format", "json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return "Error: dalfox not found. Install with: go install github.com/hahwul/dalfox/v2@latest"
    except subprocess.TimeoutExpired:
        return f"Error: dalfox timed out after {timeout}s"
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
            "vuln": data.get("vuln", "?"),
            "param": data.get("param", "?"),
            "evidence": data.get("evidence", ""),
            "severity": data.get("severity", "?"),
            "type": data.get("type", "?"),
            "payload": data.get("payload", ""),
        })

    if not findings:
        return f"No XSS vulnerabilities found on {url}."

    lines = [f"dalfox found {len(findings)} XSS issue(s) on {url}:", ""]
    for f in findings:
        lines.append(f"  [{f['severity'].upper()}] {f['vuln']}")
        lines.append(f"    Parameter: {f['param']}")
        lines.append(f"    Payload:   {f['payload'][:120]}")
        if f['evidence']:
            lines.append(f"    Evidence:  {f['evidence'][:120]}")
        lines.append("")
    return "\n".join(lines)


@app.tool()
def scan_parameter(url: str, param: str, timeout: int = 180) -> str:
    cmd = [
        "dalfox", "url", url,
        "--param", param,
        "--silence",
        "--format", "json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return "Error: dalfox not found."
    except subprocess.TimeoutExpired:
        return f"Error: dalfox timed out after {timeout}s"
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
            "vuln": data.get("vuln", "?"),
            "evidence": data.get("evidence", ""),
            "payload": data.get("payload", ""),
        })

    if not findings:
        return f"No XSS found on parameter '{param}'."

    lines = [f"XSS findings on parameter '{param}' ({len(findings)}):", ""]
    for f in findings:
        lines.append(f"  [{f['vuln']}] Payload: {f['payload'][:120]}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("dalfox-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
