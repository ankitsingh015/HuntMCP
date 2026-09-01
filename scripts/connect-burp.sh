#!/usr/bin/env bash
# connect-burp.sh — Register HuntMCP's live Burp Suite MCP bridge.
#
# What this wires up: Burp Suite's own official "MCP Server" extension
# (PortSwigger/mcp-server, installed via the BApp Store) runs an MCP server
# *inside* Burp while it's open. This script registers a `claude mcp add
# --scope local` entry that bridges to it via `mcp-proxy-all.jar` (shipped
# alongside the extension under ~/.BurpSuite/mcp-proxy/ once it's installed).
#
# Deliberately --scope local, not the repo's tracked .mcp.json: this only
# works while Burp is open on YOUR machine with the extension running, so
# it's your personal config, not something every clone of this repo should
# be forced to load (see ARCHITECTURE.md's "PortSwigger mcp-server" row and
# AGENTS.md's runtime-dependencies section for the full rationale).
#
# This registers with the Claude Code CLI only. OpenCode has no equivalent
# non-interactive "add a local stdio MCP server" flag on `opencode mcp add`
# (confirmed against its own --help: only --url/--env/--header, both aimed
# at remote servers) -- see the printed note at the end for the manual
# opencode.jsonc snippet if you drive HuntMCP via `opencode run` instead.
#
# Usage:
#   ./scripts/connect-burp.sh              # register/repair the bridge
#   ./scripts/connect-burp.sh --remove     # unregister it
#
# Prereqs (one-time, inside Burp itself):
#   1. Extensions tab > BApp Store > install "MCP Server" (PortSwigger's
#      official extension) > start it.
#   2. Confirm it's listening: Extensions > MCP Server settings shows the
#      port (default 9876).
# Then run this script, and restart your Claude Code session so it picks up
# the newly-registered `burp` MCP server.

set -euo pipefail

PORT="${BURP_MCP_PORT:-9876}"
JAR="${BURP_MCP_PROXY_JAR:-$HOME/.BurpSuite/mcp-proxy/mcp-proxy-all.jar}"

for bin in claude curl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo "Error: '$bin' CLI not found on PATH." >&2
        exit 1
    fi
done

remove_registration() {
    claude mcp remove burp --scope local >/dev/null 2>&1 || true
}

if [ "${1:-}" = "--remove" ]; then
    remove_registration
    echo "Removed 'burp' from local MCP config."
    exit 0
fi

if ! command -v java >/dev/null 2>&1; then
    echo "Error: 'java' not found on PATH — required to run mcp-proxy-all.jar." >&2
    exit 1
fi

if [ ! -f "$JAR" ]; then
    cat >&2 <<EOF
Error: mcp-proxy-all.jar not found at $JAR

This ships alongside Burp's official "MCP Server" extension. In Burp:
  Extensions tab > BApp Store > install "MCP Server" > start it.
If it's installed somewhere else on your machine, set BURP_MCP_PROXY_JAR
to the real path and re-run this script.
EOF
    exit 1
fi

# The extension serves plain HTTP on this port by default, not HTTPS --
# confirmed live (an https:// URL fails with "Invalid TLS record type code:
# 72", i.e. the proxy sending a TLS handshake at a plaintext listener).
# Probe both instead of hardcoding, in case a future Burp version switches.
#
# The endpoint is a long-lived SSE stream, so a plain GET never "finishes"
# — curl reports a timeout even on a perfectly working connection. Probe
# with a generous timeout (a just-started extension can be slow to answer
# its first request) and check the response itself: real HTTP status *and*
# an `event-stream` content type, so an unrelated service that happens to
# be squatting on the same port doesn't get mistaken for Burp. The https
# probe does NOT skip certificate verification — if the extension serves an
# untrusted cert, the java bridge registered below would fail against it
# anyway (mcp-proxy-all.jar's own --help has no matching insecure-TLS
# flag), so a strict probe here is what actually predicts whether the
# registered command will work, not just "did any TLS handshake complete."
probe_scheme() {
    local scheme="$1"
    local headers
    headers="$(curl -s --max-time 5 -D - -o /dev/null "${scheme}://localhost:${PORT}/" 2>/dev/null || true)"
    echo "$headers" | grep -qi '^HTTP/' && echo "$headers" | grep -qi 'event-stream'
}

URL=""
if probe_scheme http; then
    URL="http://localhost:${PORT}"
elif probe_scheme https; then
    URL="https://localhost:${PORT}"
else
    cat >&2 <<EOF
Error: nothing answered like Burp's MCP extension on http(s)://localhost:${PORT}.

Is Burp Suite open, with the "MCP Server" extension started? Check
Extensions > MCP Server settings for the actual port (override with
BURP_MCP_PORT=<port> if it's not $PORT). If the extension serves HTTPS with
a self-signed certificate, this probe deliberately won't accept it -- the
registered bridge can't either.
EOF
    exit 1
fi

remove_registration
claude mcp add --scope local burp -- java -jar "$JAR" --sse-url "$URL"

cat <<EOF

Registered. Restart your Claude Code session to pick up the 'burp' MCP
server (mcp__burp__* tools -- send_http1_request, create_repeater_tab,
generate_collaborator_payload, get_collaborator_interactions,
get_proxy_http_history, get_scanner_issues, plus the rest of Burp's
proxy/scanner/organizer/repeater toolset).

It only works while Burp stays open with the extension running -- if you
close Burp, the tool calls just fail to connect; nothing else in HuntMCP is
affected.

Driving HuntMCP via OpenCode instead? \`opencode mcp add\` has no
non-interactive way to register a local stdio server like this one, so add
it by hand to your personal (untracked) ~/.config/opencode/opencode.jsonc:

  "burp": {
    "type": "local",
    "command": ["java", "-jar", "$JAR", "--sse-url", "$URL"]
  }
EOF
