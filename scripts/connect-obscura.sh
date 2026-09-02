#!/usr/bin/env bash
# connect-obscura.sh — Register HuntMCP's Obscura headless-browser MCP bridge.
#
# What this wires up: Obscura (h4ckf0r0day/obscura) ships its own native MCP
# server (`obscura mcp`, stdio transport) -- a lighter/faster alternative to
# browser-mcp's Playwright/Chromium for the same JS/DOM-execution-
# confirmation and screenshot role. Unlike Burp (connect-burp.sh), nothing
# needs to already be running -- the MCP client launches `obscura mcp`
# itself, fresh, each session.
#
# Deliberately --scope local, NOT the repo's tracked .mcp.json, even though
# Obscura self-launches (so it wouldn't fail-to-start the way Burp's bridge
# would for someone without Burp open). This was tried as a tracked entry
# first and reverted after a code review surfaced real problems with that:
#   - Obscura IS its own MCP server process (a compiled binary, not a
#     mcp-servers/*/server.py wrapper), so its tool calls never pass through
#     tool_resolver.py's run_tool() -- meaning budget_guard's Tier-2 circuit
#     breaker and audit_log's per-call trail never fire for it, unlike every
#     other tool-backed MCP server in this repo. That's a real, structural
#     gap (shared with Burp's bridge, for the same reason), not something a
#     tracked-vs-personal registration choice fixes on its own -- but making
#     it tracked-and-default forces that gap onto every clone of this repo
#     by default instead of onto operators who've opted in.
#   - A bare `"command": "obscura"` PATH lookup in shared, committed config
#     trusts whatever binary happens to answer to that name first on
#     whoever's machine loads it -- worth eyeballing yourself (this script
#     prints the resolved path + version before registering) rather than
#     silently trusting on every clone by default.
#   - Matches this repo's own established precedent: Burp's own native MCP
#     server is deliberately kept personal/local for the same "not every
#     clone should be forced to load this" reasoning (see ARCHITECTURE.md's
#     PortSwigger `mcp-server` row) -- Obscura is the same shape of thing
#     (a third-party binary shipping its own MCP server), so it gets the
#     same treatment for consistency, not a special case.
#
# Usage:
#   ./scripts/connect-obscura.sh              # register/repair the bridge
#   ./scripts/connect-obscura.sh --remove     # unregister it
#
# Prereq: the `obscura` binary on PATH -- grab a release from
# https://github.com/h4ckf0r0day/obscura/releases or `cargo install --git
# https://github.com/h4ckf0r0day/obscura`. Verify the checksum/signature on
# whatever you download -- this script only shows you what it resolved and
# its version so you can eyeball it, it does not verify authenticity itself.

set -euo pipefail

if ! command -v claude >/dev/null 2>&1; then
    echo "Error: 'claude' CLI not found on PATH." >&2
    exit 1
fi

remove_registration() {
    claude mcp remove obscura-mcp --scope local >/dev/null 2>&1 || true
}

if [ "${1:-}" = "--remove" ]; then
    remove_registration
    echo "Removed 'obscura-mcp' from local MCP config."
    exit 0
fi

RESOLVED="$(command -v obscura || true)"
if [ -z "$RESOLVED" ]; then
    cat >&2 <<EOF
Error: 'obscura' not found on PATH.

Grab a release binary from https://github.com/h4ckf0r0day/obscura/releases
and put it on PATH, or: cargo install --git https://github.com/h4ckf0r0day/obscura
EOF
    exit 1
fi

echo "Resolved obscura to: $RESOLVED"
echo "Version: $(obscura --version 2>&1 || echo '(no --version output -- eyeball the path above before continuing)')"
echo ""
echo "If that's not what you expected (e.g. a different tool shadowing this"
echo "name earlier on PATH), Ctrl-C now and fix PATH before continuing."
echo ""

remove_registration
claude mcp add --scope local obscura-mcp -- obscura mcp

cat <<EOF

Registered. Restart your Claude Code session to pick up the 'obscura-mcp'
MCP server (mcp__obscura-mcp__* tools -- browser_navigate, browser_screenshot,
browser_evaluate, browser_click/fill/type, plus the rest of its ~32-tool
surface). Already scope-gated the same way browser-mcp/playwright-mcp are
(scripts/hooks/scope_gate_hook.py's TIER2_MCP_SERVERS).

Note: only browser_navigate(url) carries a host to scope-check -- later
calls in the same session (browser_click, browser_evaluate,
browser_screenshot) don't take a url param, so they aren't independently
re-gated. Always browser_navigate to the exact in-scope URL you mean to
test; don't rely on in-page navigation (a clicked link, a redirect) to stay
in scope.

Driving HuntMCP via OpenCode instead? \`opencode mcp add\` has no
non-interactive way to register a local stdio server like this one, so add
it by hand to your personal (untracked) ~/.config/opencode/opencode.jsonc:

  "obscura-mcp": {
    "type": "local",
    "command": ["obscura", "mcp"]
  }
EOF
