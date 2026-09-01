import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("ffuf-mcp")

PROJECT_WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "wordlists")
SYSTEM_WORDLIST_DIR = "/usr/share/wordlists"


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


@app.tool()
def fuzz_directory(url: str, wordlist: str = "", extensions: str = "", timeout: int = 180) -> str:
    """Directory/file brute-force `url` with ffuf. `url` is the BASE URL
    only -- "/FUZZ" is appended automatically, don't include it yourself.
    `wordlist` is a filename resolved against HuntMCP's own knowledge/
    wordlists/ first, then /usr/share/wordlists/ (or an absolute path);
    empty defaults to knowledge/wordlists/directories.txt. `extensions` is
    comma-separated, no leading dots (e.g. "php,bak"). 404 responses are
    filtered out automatically."""
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

    try:
        result = run_tool("ffuf", args, timeout=timeout)
    except FileNotFoundError:
        return "Error: ffuf not found. Install with: go install github.com/ffuf/ffuf/v2@latest"
    except subprocess.TimeoutExpired:
        return f"Error: ffuf timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

    if not result.stdout.strip():
        # ffuf ALWAYS writes its banner + progress bar to stderr, even on a
        # completely successful run that just happens to find zero matches
        # (the common case) -- `if result.stderr:` was true on every such
        # run, so a normal "nothing found" outcome was reported as if
        # something had gone wrong, stderr dump and all. returncode is the
        # actual signal for a real failure (confirmed live: a clean 5/5-
        # words-tried, zero-matches run returns 0 with a non-empty stderr
        # banner, identical in shape to a real crash under the old check).
        if result.returncode != 0:
            return f"ffuf failed (exit {result.returncode}). Stderr: {result.stderr.strip()[:300]}"
        return f"No directories found on {url}."

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
    """Fuzz a request body against `url` (e.g. brute-forcing a login
    field or an ID in a POST body) -- `data_template` MUST contain the
    literal word "FUZZ" exactly where each wordlist entry should be
    substituted (default "user=FUZZ&pass=test" fuzzes the username).
    `wordlist` resolves the same way as fuzz_directory()'s. 404 responses
    are filtered out automatically."""
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
