import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import disclosed_reports
from chroma_client import collection_stats, query, upsert_chunks
from chunker import chunk_writeup
from cve_fetch import fetch_cves as _fetch_cves
from embedder import embed
from mcp.server.fastmcp import FastMCP

app = FastMCP("writeup-mcp")

WRITEUP_DIR = os.getenv(
    "WRITEUP_DIR",
    os.path.join(os.path.dirname(__file__), "../../data/writeups"),
)


def _embed_file(fpath: str) -> int:
    """Chunk + embed one writeup file into ChromaDB. Returns chunk count."""
    chunks = chunk_writeup(fpath)
    if not chunks:
        return 0
    texts = [c["text"] for c in chunks]
    ids = [c["id"] for c in chunks]
    metadatas = [c["metadata"] for c in chunks]
    embeddings = embed(texts)
    upsert_chunks(ids, embeddings, texts, metadatas)
    return len(chunks)


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
    base = os.path.realpath(WRITEUP_DIR)
    candidate = filepath if os.path.isabs(filepath) else os.path.join(WRITEUP_DIR, filepath)
    resolved = os.path.realpath(candidate)
    if os.path.commonpath([base, resolved]) != base:
        return f"Error: {filepath!r} resolves outside the writeups directory ({WRITEUP_DIR}); refusing to ingest it."
    if not os.path.isfile(resolved):
        # isfile (not exists) so an empty/"."/boundary-directory filepath
        # -- which legitimately resolves inside WRITEUP_DIR and would
        # otherwise pass the containment check above -- returns this
        # message instead of crashing _embed_file() with IsADirectoryError.
        return f"File not found: {resolved}"
    n = _embed_file(resolved)
    if not n:
        return "No content found in writeup."
    return f"Ingested {n} chunks from {os.path.basename(resolved)}"


@app.tool()
def reindex_all() -> str:
    if not os.path.isdir(WRITEUP_DIR):
        return f"Writeup directory not found: {WRITEUP_DIR}"
    md_files = sorted(f for f in os.listdir(WRITEUP_DIR) if f.endswith(".md"))
    if not md_files:
        return "No .md files found in data/writeups/"
    total_chunks = 0
    for fname in md_files:
        total_chunks += _embed_file(os.path.join(WRITEUP_DIR, fname))
    stats = collection_stats()
    return f"Reindexed {len(md_files)} files ({total_chunks} chunks). DB now has {stats['count']} chunks."


@app.tool()
def fetch_cves(keyword: str, limit: int = 20) -> str:
    """Fetch CVEs from NVD for a product/vendor keyword (e.g. 'wordpress',
    'apache struts') and add them to the writeup RAG, embedding them
    immediately so they're searchable via query_rag right away. Safe to
    call repeatedly with the same keyword -- already-fetched CVEs are
    skipped, not re-downloaded."""
    try:
        written = _fetch_cves(keyword, limit=limit, writeup_dir=WRITEUP_DIR)
    except Exception as e:
        return f"CVE fetch failed: {e}"

    if not written:
        return f"No new CVEs found for '{keyword}' (or all already ingested)."

    total_chunks = 0
    for fname in written:
        total_chunks += _embed_file(os.path.join(WRITEUP_DIR, fname))

    return (
        f"Fetched and embedded {len(written)} new CVE(s) for '{keyword}' "
        f"({total_chunks} chunks)."
    )


@app.tool()
def search_disclosed_reports(vuln_class: str = "", platform: str = "", keyword: str = "", limit: int = 10) -> str:
    """Search a locally-cached catalog of 11k+ real disclosed vulnerability
    reports (bug-bounty-disclosures.vercel.app) for real-world precedent to
    cite -- e.g. writing/enhancing a skill's "real disclosed reports"
    section, or exploit-agent checking whether a vuln class has known
    precedent on a similar platform/program. Filter by vuln_class (e.g.
    'Cross-site scripting', 'Access control'), platform (e.g. 'HackerOne'),
    and/or a keyword matched against title/program. Does not auto-refresh
    the cache -- call refresh_disclosed_reports() first if it might be
    empty/stale. This is citation material only, not scope authorization."""
    results = disclosed_reports.search(vuln_class=vuln_class, platform=platform, keyword=keyword, limit=limit)
    if not results:
        return "No matching disclosed reports (check filters, or the cache may need refresh_disclosed_reports())."
    lines = [f"{len(results)} matching report(s):"]
    for r in results:
        bounty = f", ${r['bounty']}" if r.get("bounty") else ""
        cves = f", {', '.join(r['cves'])}" if r.get("cves") else ""
        lines.append(
            f"  [{r.get('platform', '?')}] {r.get('title', 'Untitled')} "
            f"(program: {r.get('program', '?')}, class: {r.get('vulnerabilityClass', '?')}"
            f"{bounty}{cves}) -- {r.get('url', 'N/A')}"
        )
    return "\n".join(lines)


@app.tool()
def refresh_disclosed_reports(force: bool = False) -> str:
    """Refresh the local cache of the disclosed-reports catalog. This
    dataset moves slowly (a daily refresh is plenty) -- skips the download
    if the cache is under 24h old unless force=True."""
    result = disclosed_reports.refresh(force=force)
    if not result.get("refreshed"):
        return f"Not refreshed: {result.get('reason', 'unknown')} (cached: {result.get('count', 0)} reports)"
    return f"Refreshed -- {result['count']} disclosed reports cached."


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
