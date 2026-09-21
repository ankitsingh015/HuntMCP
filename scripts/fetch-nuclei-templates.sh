#!/usr/bin/env bash
# fetch-nuclei-templates.sh — Fetch/pin the official nuclei-templates repo
# at the exact commit mcp-servers/nuclei-mcp/templates_pin.py records, into
# data/nuclei-templates/ (gitignored -- fetched content, not authored by
# this repo, same convention as data/chroma/). Idempotent: no-ops if the
# checkout is already at the pinned commit. Run this once per machine (and
# again whenever templates_pin.py's TEMPLATES_PINNED_SHA is bumped) before
# nuclei-mcp can run a real scan -- see templates_pin.py's own module
# docstring for why a host-side pinned snapshot exists at all.
# Usage: scripts/fetch-nuclei-templates.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$HERE")"

read -r REPO_URL PIN_SHA <<EOF
$(python3 -c "
import sys
sys.path.insert(0, '$REPO_ROOT/mcp-servers/nuclei-mcp')
import templates_pin
print(templates_pin.TEMPLATES_REPO_URL, templates_pin.TEMPLATES_PINNED_SHA)
")
EOF

TARGET_DIR="$REPO_ROOT/data/nuclei-templates"

if [ -d "$TARGET_DIR/.git" ]; then
    current_sha="$(git -C "$TARGET_DIR" rev-parse HEAD 2>/dev/null || echo "")"
    if [ "$current_sha" = "$PIN_SHA" ]; then
        echo "nuclei-templates already at pinned commit $PIN_SHA -- nothing to do."
        exit 0
    fi
    echo "Re-pinning nuclei-templates: $current_sha -> $PIN_SHA"
else
    echo "Cloning nuclei-templates at pinned commit $PIN_SHA into $TARGET_DIR"
    rm -rf "$TARGET_DIR"
    mkdir -p "$TARGET_DIR"
    git init -q "$TARGET_DIR"
    git -C "$TARGET_DIR" remote add origin "$REPO_URL"
fi

# Shallow fetch of exactly the pinned commit -- observed live: GitHub's
# HTTPS endpoint from this network is intermittently flaky ("Recv failure:
# Connection reset by peer") even though it succeeds on retry, so this
# retries a few times before giving up rather than failing on the first
# transient reset.
#
# Each attempt is wrapped in `timeout 60s` -- a CLEAN failure (connection
# reset) already exits promptly and hits the retry loop below on its own,
# but a network STALL (the connection hangs instead of erroring) would
# otherwise let a single `git fetch` block forever, with the 5-attempt
# retry loop never even getting a chance to run. Bounding each attempt is
# what makes the retry count above actually mean something -- 5 attempts *
# (60s timeout + 3s backoff) is a ~5.25min worst case for this step, well
# inside the step-level timeout-minutes set on this step's CI job (see
# .github/workflows/ci.yml) as a second, independent backstop.
attempt=1
until timeout 60s git -C "$TARGET_DIR" fetch --quiet --depth=1 origin "$PIN_SHA"; do
    if [ "$attempt" -ge 5 ]; then
        echo "ERROR: failed to fetch $PIN_SHA from $REPO_URL after $attempt attempts (each capped at 60s)" >&2
        exit 1
    fi
    echo "fetch attempt $attempt failed or stalled, retrying..." >&2
    attempt=$((attempt + 1))
    sleep 3
done
git -C "$TARGET_DIR" checkout -q --detach FETCH_HEAD

actual_sha="$(git -C "$TARGET_DIR" rev-parse HEAD)"
if [ "$actual_sha" != "$PIN_SHA" ]; then
    echo "ERROR: checked-out SHA $actual_sha does not match pinned $PIN_SHA" >&2
    exit 1
fi

echo "nuclei-templates pinned at $PIN_SHA in $TARGET_DIR"
