---
description: Ingest a bug bounty writeup into the RAG knowledge base from a URL or file.
---

Ingest a writeup into the RAG database.

1. Run: `./scripts/ingest-writeup.sh $ARGUMENTS` from the project root.
2. After the writeup file is created, call writeup-mcp `reindex_all` tool to re-embed all writeups into ChromaDB.
3. Return the path of the newly created writeup file and the ChromaDB stats after reindex.

Required flags: --url, --title, --vuln-class.
Optional flags: --tech, --bounty, --author, --file.
