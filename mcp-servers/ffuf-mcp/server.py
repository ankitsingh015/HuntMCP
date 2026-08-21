import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("ffuf-mcp")

WORDLIST_DIR = "/usr/share/wordlists"


@app.tool()
def fuzz_directory(url: str, wordlist: str = "", extensions: str = "", timeout: int = 180) -> str:
    if not wordlist:
        wordlist = f"{WORDLIST_DIR}/dirb/common.txt"
    if not wordlist.startswith("/"):
        wordlist = f"{WORDLIST_DIR}/{wordlist}"

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

    try:
        result = run_tool("ffuf", args, timeout=timeout)
    except FileNotFoundError:
        return "Error: ffuf not found. Install with: go install github.com/ffuf/ffuf/v2@latest"
    except subprocess.TimeoutExpired:
        return f"Error: ffuf timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

    if not result.stdout.strip():
        if result.stderr:
            return f"ffuf output empty. Stderr: {result.stderr.strip()[:300]}"
        return f"No results from ffuf for {url}/FUZZ"

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout.strip()[:1000]

    results = data.get("results", [])
    if not results:
        return f"No directories found on {url}."

    lines = [f"ffuf found {len(results)} path(s) on {url}:", ""]
    for r in sorted(results, key=lambda x: x.get("status", 0)):
        path = r.get("input", {}).get("FUZZ", "?")
        status = r.get("status", "?")
        length = r.get("length", "?")
        words = r.get("words", "?")
        lines.append(f"  /{path:40s} {status:3d}  [{length}b / {words}w]")
    return "\n".join(lines)


@app.tool()
def fuzz_with_data(url: str, wordlist: str = "", method: str = "POST", data_template: str = "user=FUZZ&pass=test") -> str:
    if not wordlist:
        wordlist = f"{WORDLIST_DIR}/dirb/common.txt"
    if not wordlist.startswith("/"):
        wordlist = f"{WORDLIST_DIR}/{wordlist}"

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
    try:
        result = run_tool("ffuf", args, timeout=180)
    except FileNotFoundError:
        return "Error: ffuf not found."
    except subprocess.TimeoutExpired:
        return "Error: ffuf timed out"
    except Exception as e:
        return f"Error: {e}"

    if not result.stdout.strip():
        return "No results."

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.stdout.strip()[:1000]

    results = data.get("results", [])
    if not results:
        return "No results found."

    lines = [f"ffuf found {len(results)} result(s):", ""]
    for r in sorted(results, key=lambda x: x.get("status", 0)):
        fuzz_val = r.get("input", {}).get("FUZZ", "?")
        status = r.get("status", "?")
        length = r.get("length", "?")
        lines.append(f"  FUZZ={fuzz_val:30s} {status:3d}  [{length}b]")
    return "\n".join(lines)


if __name__ == "__main__":
    print("ffuf-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
