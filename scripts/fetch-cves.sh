#!/usr/bin/env bash
# fetch-cves.sh — Fetch CVEs from NVD into data/writeups/ for RAG ingestion.
# Usage: scripts/fetch-cves.sh <keyword> [--limit N]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/../mcp-servers/writeup-mcp/cve_fetch.py" "$@"
