"""Out-of-band interaction listener (Phase 2.8 backlog).

Wraps ProjectDiscovery's interactsh-client to generate per-injection
callback URLs and correlate inbound DNS/HTTP/SMTP hits back to a finding --
this is how exploit-agent proves blind SSRF/XXE/SQLi/RCE actually fired,
without depending on Burp Collaborator (optional, not everyone has Burp
Pro).

Unlike the other MCP servers here, interactsh-client is long-lived: it
needs to keep polling for interactions that may arrive any time after the
payload is sent. So generate_payload_url() starts it as a detached
background process (not tool_resolver.run_tool()'s one-shot subprocess.run)
and registers it in a small on-disk registry that check_interactions() /
list_listeners() / stop_listener() then operate on.

generate_payload_url() never touches the actual bug-bounty target -- it
only talks to interactsh's own public infrastructure to mint a callback
domain -- so it is NOT scope-gated. Scope enforcement applies when
exploit-agent later embeds the returned URL in an actual payload sent to
the target via a Tier-2 tool call, exactly as today.
"""

import json
import os
import re
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from budget_guard import enforce as _enforce_budget  # noqa: E402
from tool_resolver import resolve_tool  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("oob-mcp")

OOB_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "oob-sessions"
)
REGISTRY_PATH = os.path.join(OOB_DIR, "registry.json")

_URL_RE = re.compile(r"\b([a-z0-9]{15,}\.(?:oast\.\w+|[a-z0-9.-]+\.(?:com|net|io)))\b", re.I)


def _load_registry() -> dict:
    if not os.path.isfile(REGISTRY_PATH):
        return {}
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def _save_registry(registry: dict) -> None:
    os.makedirs(OOB_DIR, exist_ok=True)
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def _prune_dead(registry: dict) -> dict:
    return {url: entry for url, entry in registry.items() if _is_alive(entry["pid"])}


@app.tool()
def generate_payload_url(label: str = "") -> str:
    """Start a new OOB listener and return a unique callback URL/domain to
    embed in a blind SSRF/XXE/SQLi/RCE payload. `label` is a free-text note
    (e.g. the endpoint/param being tested) stored alongside the listener so
    `list_listeners()` output stays readable across a multi-finding
    engagement."""
    binary = resolve_tool("interactsh-client")
    try:
        _enforce_budget("interactsh-client")
    except Exception as e:  # BudgetExceeded
        return f"Error: {e}"

    session_id = uuid.uuid4().hex[:12]
    work_dir = os.path.join(OOB_DIR, session_id)
    os.makedirs(work_dir, exist_ok=True)
    session_file = os.path.join(work_dir, "session.json")
    interactions_file = os.path.join(work_dir, "interactions.jsonl")
    startup_log_path = os.path.join(work_dir, "startup.log")

    # Log to a file rather than a live pipe -- this process must keep
    # running long after this function returns (and after whatever short-
    # lived call spawned it exits), so nothing here can depend on us
    # continuing to read its stdout.
    try:
        with open(startup_log_path, "w") as log_f:
            proc = subprocess.Popen(
                [
                    binary,
                    "-session-file", session_file,
                    "-o", interactions_file,
                    "-json",
                    "-duc",  # disable-update-check -- don't block startup on a version check
                ],
                stdout=log_f,
                stderr=subprocess.STDOUT,
                cwd=work_dir,
                start_new_session=True,  # detach from our process group --
                # must outlive whatever spawned this MCP server call
            )
    except FileNotFoundError:
        return (
            "Error: interactsh-client not found. Install with: "
            "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        )

    url = None
    deadline = time.time() + 20
    while time.time() < deadline:
        if os.path.isfile(startup_log_path):
            with open(startup_log_path) as f:
                content = f.read()
            match = _URL_RE.search(content)
            if match:
                url = match.group(1)
                break
        if proc.poll() is not None:
            break
        time.sleep(0.5)

    if not url:
        proc.kill()
        proc.wait(timeout=5)
        tail = ""
        if os.path.isfile(startup_log_path):
            with open(startup_log_path) as f:
                tail = "\n".join(f.read().splitlines()[-10:])
        return (
            "Error: interactsh-client did not produce a callback URL within 20s. "
            f"Output:\n{tail}"
        )

    registry = _prune_dead(_load_registry())
    registry[url] = {
        "pid": proc.pid,
        "session_id": session_id,
        "interactions_file": interactions_file,
        "label": label,
        "started_at": time.time(),
    }
    _save_registry(registry)

    return (
        f"OOB listener started. Callback URL: {url}\n"
        f"Embed this in a blind SSRF/XXE/SQLi/RCE payload, then call "
        f"check_interactions('{url}') after triggering it -- interactsh "
        f"polls automatically, no need to re-run anything. Call "
        f"stop_listener('{url}') when done with this finding."
    )


@app.tool()
def check_interactions(url: str) -> str:
    """Check for any inbound DNS/HTTP/SMTP interactions on a callback URL
    previously returned by generate_payload_url(). Safe to call repeatedly
    -- the background listener keeps polling on its own poll-interval."""
    registry = _load_registry()
    entry = registry.get(url)
    if not entry:
        return f"No active listener for {url!r}. Call generate_payload_url() first."

    interactions_file = entry["interactions_file"]
    if not os.path.isfile(interactions_file):
        return f"No interactions yet for {url!r}."

    hits = []
    with open(interactions_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                hits.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not hits:
        return f"No interactions yet for {url!r}."

    lines = [f"{len(hits)} interaction(s) for {url!r}:"]
    for h in hits:
        proto = h.get("protocol", h.get("protocol-type", "?"))
        remote = h.get("remote-address", "?")
        ts = h.get("timestamp", "?")
        lines.append(f"  [{proto}] from {remote} at {ts}")
    return "\n".join(lines)


@app.tool()
def list_listeners() -> str:
    """List all currently-running OOB listeners (url, label, age)."""
    registry = _prune_dead(_load_registry())
    _save_registry(registry)
    if not registry:
        return "No active OOB listeners."

    lines = ["Active OOB listeners:"]
    now = time.time()
    for url, entry in registry.items():
        age_min = (now - entry["started_at"]) / 60
        label = entry.get("label") or "(no label)"
        lines.append(f"  {url} -- {label} -- running {age_min:.1f}m")
    return "\n".join(lines)


@app.tool()
def stop_listener(url: str) -> str:
    """Stop a listener and remove it from the registry. The interactions
    file is left on disk for the record."""
    registry = _load_registry()
    entry = registry.pop(url, None)
    if not entry:
        return f"No active listener for {url!r} (already stopped, or never started)."

    if _is_alive(entry["pid"]):
        try:
            os.kill(entry["pid"], 15)  # SIGTERM
        except ProcessLookupError:
            pass

    _save_registry(registry)
    return f"Stopped listener for {url!r}."


if __name__ == "__main__":
    print("oob-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
