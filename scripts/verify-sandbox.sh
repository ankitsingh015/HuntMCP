#!/usr/bin/env bash
# S5 (IMPLEMENTATION-TASK-TRACKER.md): operator-facing check that the
# rootless per-run execution boundary is actually usable on this machine
# -- podman installed, running rootless, and the pinned sandbox image
# built. Run this before relying on S5 protection, and again after any
# mcp-servers/sandbox/Dockerfile change.
#
# Usage: scripts/verify-sandbox.sh
#   (re)build the image first if this reports it missing:
#     podman build -t localhost/huntmcp-sandbox:2026-09-15 -f mcp-servers/sandbox/Dockerfile .
set -euo pipefail

IMAGE="localhost/huntmcp-sandbox:2026-09-15"
FAIL=0

echo "== S5 sandbox verification =="

if ! command -v podman >/dev/null 2>&1; then
    echo "FAIL: podman not installed. Install with: sudo apt install podman"
    FAIL=1
else
    echo "OK: podman found ($(podman --version))"

    if [ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" = "true" ]; then
        echo "OK: podman is running rootless"
    else
        echo "FAIL: podman is NOT running rootless -- see IMPLEMENTATION-TASK-TRACKER.md S5"
        FAIL=1
    fi

    if podman image exists "$IMAGE" 2>/dev/null; then
        echo "OK: $IMAGE is built"
        echo "-- verifying a real sandboxed run reaches the network and cleans up --"
        if podman run --rm --userns=keep-id --cap-drop=ALL \
            --security-opt=no-new-privileges --read-only --tmpfs=/tmp:rw,size=64m \
            "$IMAGE" /usr/bin/curl -s -o /dev/null -w '%{http_code}' https://example.com \
            | grep -q "200"; then
            echo "OK: a real sandboxed curl call succeeded end to end"
        else
            echo "FAIL: sandboxed curl call did not succeed -- check network/image"
            FAIL=1
        fi
    else
        echo "FAIL: $IMAGE not built. Build with:"
        echo "  podman build -t $IMAGE -f mcp-servers/sandbox/Dockerfile ."
        FAIL=1
    fi
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "S5 sandbox is ready."
else
    echo "S5 sandbox is NOT ready -- see failures above. Tier-2 tool calls will"
    echo "fail closed (not run natively) until this is fixed, per S5's own design."
    exit 1
fi
