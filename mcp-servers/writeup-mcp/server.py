import os
import sys
from mcp.server.fastmcp import FastMCP

from chunker import chunk_writeup
from embedder import embed
from chroma_client import query, upsert_chunks, collection_stats

app = FastMCP("writeup-mcp")

WRITEUP_DIR = os.getenv(
    "WRITEUP_DIR",
    os.path.join(os.path.dirname(__file__), "../../data/writeups"),
)


@app.tool()
def query_rag(query_text: str, top_k: int = 5) -> str:
    emb = embed([query_text])
    results = query(emb, top_k=top_k)
    if not results or not results.get("ids") or not results["ids"][0]:
        return "No matching writeups found."
    lines = []
    for i in range(len(results["ids"][0])):
        meta = results["metadatas"][0][i]
        doc = results["documents"][0][i][:300]
        dist = results["distances"][0][i]
        score = round(1 - dist, 4)
        lines.append(
            f"[{i+1}] {meta.get('title', 'Untitled')} "
            f"(score={score}, class={meta.get('vuln_class', '?')}, "
            f"tech={meta.get('tech', '?')})"
        )
        lines.append(f"    URL: {meta.get('url', 'N/A')}")
        lines.append(f"    {doc}...")
        lines.append("")
    return "\n".join(lines)


@app.tool()
def ingest_writeup(filepath: str) -> str:
    resolved = filepath if os.path.isabs(filepath) else os.path.join(WRITEUP_DIR, filepath)
    if not os.path.exists(resolved):
        return f"File not found: {resolved}"
    chunks = chunk_writeup(resolved)
    if not chunks:
        return "No content found in writeup."
    texts = [c["text"] for c in chunks]
    ids = [c["id"] for c in chunks]
    metadatas = [c["metadata"] for c in chunks]
    embeddings = embed(texts)
    upsert_chunks(ids, embeddings, texts, metadatas)
    return f"Ingested {len(chunks)} chunks from {os.path.basename(resolved)}"


@app.tool()
def reindex_all() -> str:
    if not os.path.isdir(WRITEUP_DIR):
        return f"Writeup directory not found: {WRITEUP_DIR}"
    md_files = sorted(f for f in os.listdir(WRITEUP_DIR) if f.endswith(".md"))
    if not md_files:
        return "No .md files found in data/writeups/"
    total_chunks = 0
    for fname in md_files:
        fpath = os.path.join(WRITEUP_DIR, fname)
        chunks = chunk_writeup(fpath)
        if not chunks:
            continue
        texts = [c["text"] for c in chunks]
        ids = [c["id"] for c in chunks]
        metadatas = [c["metadata"] for c in chunks]
        embeddings = embed(texts)
        upsert_chunks(ids, embeddings, texts, metadatas)
        total_chunks += len(chunks)
    stats = collection_stats()
    return f"Reindexed {len(md_files)} files ({total_chunks} chunks). DB now has {stats['count']} chunks."


@app.tool()
def stats() -> str:
    s = collection_stats()
    return f"Collection '{s['name']}' has {s['count']} chunks."


if __name__ == "__main__":
    print(f"Writeup MCP starting...", file=sys.stderr)
    print(f"  Model: all-MiniLM-L6-v2", file=sys.stderr)
    print(f"  ChromaDB: {os.path.join(os.path.dirname(__file__), '../../data/chroma')}", file=sys.stderr)
    print(f"  Writeup dir: {WRITEUP_DIR}", file=sys.stderr)
    app.run(transport="stdio")
