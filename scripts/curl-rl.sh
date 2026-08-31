#!/usr/bin/env bash
# Drop-in curl wrapper with the same reactive rate-limit backoff
# tool_resolver.run_tool() already gives every Tier-2 MCP-wrapped tool
# (nuclei/sqlmap/subfinder/etc.), for raw curl calls specifically -- which
# don't go through that Python subprocess wrapper at all. A
# PreToolUse/tool.execute.before HOOK (scripts/hooks/scope_gate_hook.py)
# cannot do this itself: a hook can only ALLOW or BLOCK a command before
# it runs, it has no way to wrap/retry the actual subprocess execution --
# so the retry logic has to live in a real wrapper agents call instead of
# raw curl, not hook-side logic. Confirmed this design constraint against
# a real engagement's own feedback before building it this way.
#
# Usage: identical to curl -- scripts/curl-rl.sh <same args you'd give curl>
#
# Still scope-gated exactly like raw curl: scripts/hooks/scope_gate_hook.py's
# TIER2_BASH_TOOLS includes "curl-rl.sh" specifically so this wrapper gets
# the same scope/budget/audit treatment curl/wget already get -- using a
# differently-named binary must not be a way to silently skip that check.
#
# Response headers always go to a separate temp file via an added `-D`
# flag (never touching the caller's own stdout/output), so the status
# line/Retry-After header can be inspected for the retry decision without
# changing what a normal curl invocation would show.
#
# The response BODY is handled two different ways depending on whether the
# caller already asked for a file (`-o`/`-O`/their long forms):
# - If they did (e.g. recon-agent's own documented
#   `curl -o "<dir>/<name>.js" <url>` JS-download pattern) -- don't touch
#   it. curl writes to their chosen destination on every attempt as normal;
#   a retry just overwrites it with the successful attempt's content,
#   which is the correct final state either way.
# - If they didn't (a plain curl-to-stdout call, the common case for
#   reading a page/API response) -- redirect the body to our own temp
#   file instead of letting it hit real stdout directly, and `cat` only
#   the LAST attempt's body at the end. Without this, a 429-then-retry
#   sequence would print the failed attempt's error body immediately,
#   THEN the successful retry's body, concatenated into one confusing
#   blob -- caught live while testing this script for real.
#
# Never more than one retry, same as tool_resolver.run_tool()'s own rule:
# a second block means something else is wrong, not a transient rate limit.
set -euo pipefail

HEADER_FILE=$(mktemp)
BODY_FILE=$(mktemp)
trap 'rm -f "$HEADER_FILE" "$BODY_FILE"' EXIT

caller_has_own_output() {
  for arg in "$@"; do
    case "$arg" in
      -o|--output|-O|--remote-name|--remote-name-all) return 0 ;;
    esac
  done
  return 1
}

run_once() {
  if caller_has_own_output "$@"; then
    curl -D "$HEADER_FILE" "$@"
  else
    curl -D "$HEADER_FILE" -o "$BODY_FILE" "$@"
  fi
}

set +e
run_once "$@"
rc=$?
set -e

if grep -qiE '^HTTP/[0-9.]+[[:space:]]+429|^retry-after:' "$HEADER_FILE" 2>/dev/null; then
  echo "curl-rl.sh: rate-limit signal detected (429/Retry-After), backing off 5s and retrying once" >&2
  sleep 5
  : > "$HEADER_FILE"
  : > "$BODY_FILE"
  set +e
  run_once "$@"
  rc=$?
  set -e
fi

if ! caller_has_own_output "$@"; then
  cat "$BODY_FILE"
fi

exit "$rc"
