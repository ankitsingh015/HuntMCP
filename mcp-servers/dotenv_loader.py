"""Tiny built-in .env loader -- no python-dotenv dependency for something
this small. Every MCP server that reads a credential via os.getenv()
(osint-mcp, hackerone-mcp, second-opinion-mcp, github-security-mcp) calls
load_dotenv_if_present() once at import time, so a .env file at the repo
root (already gitignored -- see .gitignore's `.env` line, and
.env.example for the documented format) is picked up automatically
instead of requiring the user to `export` each var in their shell.

Real environment variables always win over .env -- this only fills in
values that aren't already set, matching standard dotenv semantics (a
value you've explicitly exported takes precedence over a file).
"""

import os

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
_ENV_PATH = os.path.join(_REPO_ROOT, ".env")
_loaded = False


def load_dotenv_if_present(path: str = _ENV_PATH) -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
