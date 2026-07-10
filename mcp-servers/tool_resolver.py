"""Resolve tool binary paths for MCP servers.

MCP servers call external tools (subfinder, httpx, etc.) via subprocess.
This module ensures they find the correct binary even when Python packages
shadow the Go/system binary names (e.g., Python httpx vs ProjectDiscovery httpx).
"""

import os
import shlex
import shutil
import subprocess
import sys

GO_BIN = os.path.expanduser("~/go/bin")
GO_BIN_CANDIDATES = [
    GO_BIN,
    "/usr/local/go/bin",
    "/usr/lib/go/bin",
    "/snap/go/current/bin",
]


def resolve_tool(name: str) -> str:
    """Resolve a tool binary path, preferring Go/system binaries over Python wrappers."""
    # First check ~/go/bin directly (fast path)
    go_path = os.path.join(GO_BIN, name)
    if os.path.isfile(go_path) and os.access(go_path, os.X_OK):
        return go_path

    # Use shutil.which but exclude Python wrappers
    result = shutil.which(name)
    if result:
        return result

    # Search Go bin candidates
    for candidate in GO_BIN_CANDIDATES:
        candidate_path = os.path.join(candidate, name)
        if os.path.isfile(candidate_path) and os.access(candidate_path, os.X_OK):
            return candidate_path

    return name


def run_tool(name: str, args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a tool with the resolved binary path."""
    binary = resolve_tool(name)
    return subprocess.run([binary, *args], **kwargs)
