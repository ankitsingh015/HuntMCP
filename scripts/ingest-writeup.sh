#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") --url <url> --title "Title" --vuln-class XSS [options]

Required:
  --url <url>            URL of the original writeup
  --title "Title"        Writeup title
  --vuln-class <class>   Vulnerability class (XSS, IDOR, SQLi, SSTI, etc.)

Optional:
  --tech "React, Node"   Target technology stack (comma-separated)
  --bounty <amount>      Bounty amount (numeric)
  --author "name"        Author/hunter name
  --file <path>          Read writeup content from file (instead of fetching URL)
  --help                 Show this help

Examples:
  $(basename "$0") \\
    --url "https://medium.com/..." \\
    --title "Reflected XSS in Search" \\
    --vuln-class XSS \\
    --tech React \\
    --bounty 1500 \\
    --author "jane_doe"
EOF
  exit 0
}

# Parse args
URL=""
TITLE=""
VULN_CLASS=""
TECH=""
BOUNTY=""
AUTHOR=""
FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --title) TITLE="$2"; shift 2 ;;
    --vuln-class) VULN_CLASS="$2"; shift 2 ;;
    --tech) TECH="$2"; shift 2 ;;
    --bounty) BOUNTY="$2"; shift 2 ;;
    --author) AUTHOR="$2"; shift 2 ;;
    --file) FILE="$2"; shift 2 ;;
    --help|-h) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [[ -z "$URL" || -z "$TITLE" || -z "$VULN_CLASS" ]]; then
  echo "Error: --url, --title, and --vuln-class are required"
  usage
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
WRITEUP_DIR="$HERE/../data/writeups"

# Generate filename
DATE="$(date +%Y-%m-%d)"
SLUG="$(echo "$TITLE" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g; s/^-//; s/-$//')"
FILENAME="$DATE-$SLUG.md"
FILEPATH="$WRITEUP_DIR/$FILENAME"

# Build frontmatter
cat > "$FILEPATH" <<FRONTMATTER
---
title: "$TITLE"
url: "$URL"
vuln_class: "$VULN_CLASS"
tech: "$TECH"
bounty: $BOUNTY
date: $DATE
$( [[ -n "$AUTHOR" ]] && echo "author: $AUTHOR" )
---

FRONTMATTER

# Append content
if [[ -n "$FILE" ]]; then
  if [[ ! -e "$FILE" ]]; then
    echo "Error: file not found: $FILE"
    exit 1
  fi
  cat "$FILE" >> "$FILEPATH"
elif [[ -n "$URL" ]]; then
  {
    echo ""
    echo "_Auto-fetched from $URL_"
    echo ""
    echo '```'
    curl -sL "$URL" || echo "(could not fetch content)"
    echo '```'
  } >> "$FILEPATH"
fi

echo "Wrote $FILEPATH"
echo "Run 'reindex_all' on writeup-mcp to embed it into ChromaDB."
