#!/usr/bin/env bash
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$HERE/.."

WRITEUP_DIR="$BASE/data/writeups"
LOG_DIR="$BASE/logs"
LOG_FILE="$LOG_DIR/cron-ingestion.log"

# Feed URLs — edit to add/remove sources
FEEDS=(
  "https://hackerone.com/hacktivity/activity.rss"
  "https://portswigger.net/research/rss"
)

# GitHub writeup repos to scan (user/repo)
GITHUB_REPOS=(
  "swisskyrepo/PayloadsAllTheThings"
  "daffainfo/AllAboutBugBounty"
)

# Track already-seen URLs
SEEN_FILE="$BASE/data/.cron-seen-urls.txt"

# ── Helpers ────────────────────────────────────────────────────────
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; echo "$*"; }
err() { log "ERROR: $*"; }

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTION]

Automated writeup ingestion from RSS feeds and GitHub repos.

Options:
  --install-cron   Install daily (6AM) and weekly (Sunday noon) crontab entries
  --remove-cron    Remove installed crontab entries
  --refresh        Full re-scan (ignore seen-urls tracking)
  --help           Show this help

Without options, runs a single scan cycle and ingests new writeups.
EOF
  exit 0
}

ensure_dirs() {
  mkdir -p "$WRITEUP_DIR" "$LOG_DIR"
  touch "$SEEN_FILE"
}

# ── Python RSS parser (reads from stdin) ─────────────────────────
parse_rss() {
  python3 -c "
import sys, xml.etree.ElementTree as ET
raw = sys.stdin.read()
try:
    root = ET.fromstring(raw)
except ET.ParseError:
    sys.exit(1)
items = []
# RSS 2.0
for item in root.iter('item'):
    title = item.findtext('title', '').strip()
    link  = item.findtext('link',  '').strip()
    desc  = item.findtext('description', '').strip()
    items.append(f'{title}|--SEP--|{link}|--SEP--|{desc}')
# Atom
ns = '{http://www.w3.org/2005/Atom}'
for entry in root.iter(ns + 'entry'):
    title = entry.findtext(ns + 'title', '').strip()
    link_el = entry.find(ns + 'link')
    link = link_el.get('href', '').strip() if link_el is not None else ''
    desc = entry.findtext(ns + 'content', '')
    if not desc:
        desc = entry.findtext(ns + 'summary', '')
    desc = desc.strip()
    items.append(f'{title}|--SEP--|{link}|--SEP--|{desc}')
for i in items:
    print(i)
"
}

# ── Create writeup file from feed entry ───────────────────────────
create_writeup() {
  local title="$1" url="$2" desc="$3"
  local date slug filename filepath
  date="$(date +%Y-%m-%d)"
  slug="$(echo "$title" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g; s/--*/-/g; s/^-//; s/-$//' | head -c 80)"
  filename="${date}-${slug}.md"
  filepath="$WRITEUP_DIR/$filename"

  cat > "$filepath" <<EOF
---
title: "$title"
url: "$url"
vuln_class: "unknown"
tech: "unknown"
bounty: 0
date: $date
---

## Summary

Auto-fetched from cron feed.

$desc

## Original URL

$url
EOF

  echo "$filepath"
}

# ── Embed into ChromaDB via writeup-mcp modules ──────────────────
embed_writeup() {
  local filepath="$1"
  python3 -c "
import sys, os
sys.path.insert(0, 'mcp-servers/writeup-mcp')
os.chdir('$BASE')
from chunker import chunk_writeup
from embedder import embed
from chroma_client import upsert_chunks

chunks = chunk_writeup('$filepath')
if not chunks:
    sys.exit(0)

texts = [c['text'] for c in chunks]
ids = [c['id'] for c in chunks]
metadatas = [c['metadata'] for c in chunks]
embeddings = embed(texts)
upsert_chunks(ids, embeddings, texts, metadatas)
print(f'  embedded {len(chunks)} chunks')
" 2>&1 | grep -v '^$' | grep -v progress || true
}

# ── Process a single feed entry ──────────────────────────────────
process_entry() {
  local title="$1" link="$2" desc="$3"

  if grep -Fq "$link" "$SEEN_FILE" 2>/dev/null; then
    return 1
  fi

  log "  New: $title"
  echo "$link" >> "$SEEN_FILE"

  local filepath
  filepath=$(create_writeup "$title" "$link" "$desc")
  log "    wrote $(basename "$filepath")"
  embed_writeup "$filepath"
  return 0
}

# ── Scan RSS feeds ────────────────────────────────────────────────
scan_feeds() {
  local count=0
  for feed_url in "${FEEDS[@]}"; do
    log "  Fetching feed: $feed_url"
    local raw
    raw=$(curl -sL --max-time 15 "$feed_url" 2>/dev/null || true)
    if [[ -z "$raw" ]]; then
      err "  Empty response from $feed_url"
      continue
    fi

    local entries
    entries=$(echo "$raw" | parse_rss 2>/dev/null || true)
    if [[ -z "$entries" ]]; then
      log "  No parseable entries from $feed_url"
      continue
    fi

    while IFS='|--SEP--|' read -r title link desc; do
      [[ -z "$link" || -z "$title" ]] && continue
      if process_entry "$title" "$link" "$desc"; then
        count=$((count + 1))
      fi
    done < <(echo "$entries")
  done
  echo "$count"
}

# ── Scan GitHub repos (optional, requires gh CLI) ────────────────
scan_github() {
  if ! command -v gh &>/dev/null; then
    log "  Skipping GitHub (gh CLI not installed)"
    echo 0
    return
  fi
  local count=0
  for repo in "${GITHUB_REPOS[@]}"; do
    log "  Scanning GitHub: $repo"
    local files
    files=$(gh api "repos/$repo/contents" --jq '.[].name' 2>/dev/null | grep -i '\.md$' | head -5 || true)
    [[ -z "$files" ]] && continue

    while read -r fname; do
      local raw_url="https://raw.githubusercontent.com/$repo/main/$fname"
      if grep -Fq "$raw_url" "$SEEN_FILE" 2>/dev/null; then
        continue
      fi
      log "  New GitHub file: $fname"
      echo "$raw_url" >> "$SEEN_FILE"

      local content title_text
      content=$(curl -sL --max-time 10 "$raw_url" 2>/dev/null || true)
      title_text=$(echo "$fname" | sed 's/\.md$//; s/-/ /g; s/_/ /g')
      local filepath
      filepath=$(create_writeup "$title_text" "$raw_url" "$content")
      log "    wrote $(basename "$filepath")"
      embed_writeup "$filepath"
      count=$((count + 1))
    done < <(echo "$files")
  done
  echo "$count"
}

# ── Install/remove crontab ────────────────────────────────────────
install_cron() {
  local script="$(realpath "$0")"
  local job_daily="0 6 * * * $script"
  local job_weekly="0 12 * * 0 $script --refresh"
  (crontab -l 2>/dev/null | grep -v "cron-fetch.sh"; echo "$job_daily"; echo "$job_weekly") | crontab -
  log "Crontab installed"
  echo "Crontab installed: daily 6AM, weekly Sunday noon."
}

remove_cron() {
  (crontab -l 2>/dev/null | grep -v "cron-fetch.sh") | crontab - || true
  log "Crontab removed"
  echo "Crontab entries removed."
}

# ── Main ───────────────────────────────────────────────────────────
main() {
  ensure_dirs
  local refresh_flag=""
  refresh_flag="${1:-}"

  case "$refresh_flag" in
    --help|-h) usage ;;
    --install-cron) install_cron; exit 0 ;;
    --remove-cron)  remove_cron;  exit 0 ;;
    --refresh)
      log "=== Full refresh ==="
      rm -f "$SEEN_FILE"
      ;;
    *)
      log "=== Cron run ==="
      ;;
  esac

  log "Scanning RSS feeds..."
  local feed_count=0 gh_count=0
  feed_count=$(scan_feeds)

  log "Scanning GitHub repos..."
  gh_count=$(scan_github)

  local total=$((feed_count + gh_count))
  log "Done. Ingested $total new writeups (feeds: $feed_count, github: $gh_count)"
  echo "Done. $total new writeups ingested."
}

main "$@"
