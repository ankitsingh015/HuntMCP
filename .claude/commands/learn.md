---
description: Query the writeup RAG database for techniques matching a vulnerability class, tech stack, or attack vector.
---

Query the writeup RAG database for relevant bug bounty techniques and payloads.

1. Call writeup-mcp `query_rag` with the user's query text (from $ARGUMENTS).
2. If the result contains writeups, return them formatted with title, similarity score, vulnerability class, tech stack, and excerpt.
3. If no matches found, suggest the user try different keywords or add writeups via /ingest.
