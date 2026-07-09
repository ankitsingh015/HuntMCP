#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/.."

echo "==> Creating data directories..."
mkdir -p data/chroma data/writeups logs

echo "==> Initializing Memory DB (SQLite)..."
python3 -c "
import sys
sys.path.insert(0, 'mcp-servers/memory-mcp')
from db import _get_conn
conn = _get_conn()
conn.close()
print('    memory.db schema created')
"

echo "==> Verifying ChromaDB import..."
python3 -c "
import chromadb
print('    chromadb ready')
" 2>&1 | grep -v progress

echo ""
echo "Done. Writeups in data/writeups/ will be embedded into ChromaDB"
echo "on first 'reindex_all' call or when writeup-mcp starts."
