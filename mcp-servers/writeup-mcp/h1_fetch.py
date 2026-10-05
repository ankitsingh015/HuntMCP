"""Fetch disclosed HackerOne reports (public .json) into the writeup RAG.

Mirrors cve_fetch.py's role: an external knowledge-source fetcher that lives
*inside* the writeup-mcp server rather than shelling out to curl -- the same
reason fetch_cves() (NVD) and disclosed_reports.py (bug-bounty-disclosures)
already fetch external hosts from server code. It reads only *public disclosed*
reports, is throttled with a sleep between requests, idempotent (skips reports
already on disk / already done), and resumable across runs.

For each report it writes data/writeups/h1-<class>-<id>-<slug>.md with the same
frontmatter shape every other writeup uses, so it flows through
chunk_writeup() -> embed() -> ChromaDB unchanged.

A report's body (`vulnerability_information`) is public only when its
visibility is "full"; otherwise the field is empty and we fall back to the
team/researcher `summaries`. The chosen source is recorded as
`content_quality: full|summary-only`.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

WRITEUP_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "writeups")
DEFAULT_CATALOG = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "disclosed-reports-cache", "catalog.json"
)
H1_JSON = "https://hackerone.com/reports/{}.json"
UA = "HuntMCP-writeup-h1/1.0 (+personal bug-bounty knowledge base)"
DONE_FILE = os.path.join(WRITEUP_DIR, ".h1-done.txt")
EMBED_BATCH = 25  # files embedded per flush


def report_id(url_or_id) -> int | None:
    s = str(url_or_id).strip()
    if s.isdigit():
        return int(s)
    m = re.search(r"/reports/(\d+)", s)
    return int(m.group(1)) if m else None


def _slug(s: str, n: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return (s[:n] or "report").strip("-") or "report"


def fetch_report(rid: int, retries: int = 3, timeout: int = 25) -> dict | None:
    url = H1_JSON.format(rid)
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": UA, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return None
            if e.code in (403, 429) and attempt < retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            return None
        except (urllib.error.URLError, TimeoutError, ConnectionResetError):
            if attempt < retries - 1:
                time.sleep(3 * (attempt + 1))
                continue
            return None
    return None


def report_to_markdown(d: dict, fallback_class: str = "") -> tuple[str, str, str]:
    rid = d.get("id")
    title = (d.get("title") or f"HackerOne report {rid}").strip()
    weakness = ((d.get("weakness") or {}).get("name") or fallback_class or "unknown").strip()
    team = d.get("team") or {}
    program = ((team.get("profile") or {}).get("name") or team.get("handle") or "").strip()
    try:
        bounty = int(float(d.get("bounty_amount") or 0))
    except (TypeError, ValueError):
        bounty = 0
    votes = d.get("vote_count") or 0
    sev = (d.get("severity_rating") or "").strip()
    cves = ",".join(d.get("cve_ids") or [])
    body = (d.get("vulnerability_information") or "").strip()
    quality = "full" if body else "summary-only"
    parts: list[str] = []
    if body:
        parts.append(body)
    else:
        for s in d.get("summaries") or []:
            c = (s or {}).get("content")
            if c:
                parts.append(f"## {(s.get('category') or 'summary').title()} summary\n{c.strip()}")
    text = "\n\n".join(parts) or "_(no public content; metadata only)_"
    fm = (
        "---\n"
        f"title: {json.dumps(title)}\n"
        f'url: "https://hackerone.com/reports/{rid}"\n'
        f"vuln_class: {json.dumps(weakness)}\n"
        f"tech: {json.dumps(program)}\n"
        f"bounty: {bounty}\n"
        f"program: {json.dumps(program)}\n"
        f"severity: {json.dumps(sev)}\n"
        f"votes: {votes}\n"
        f"cve: {json.dumps(cves)}\n"
        f'content_quality: "{quality}"\n'
        f'source: "HackerOne disclosed report"\n'
        "---\n\n"
    )
    fname = f"h1-{_slug(weakness, 30)}-{rid}-{_slug(title, 40)}.md"
    return fname, fm + text + "\n", quality


def _done_set() -> set[str]:
    if not os.path.exists(DONE_FILE):
        return set()
    try:
        with open(DONE_FILE) as f:
            return {ln.strip() for ln in f if ln.strip()}
    except OSError:
        return set()


def _already(rid: int, done: set[str]) -> bool:
    if str(rid) in done:
        return True
    return bool(
        glob.glob(os.path.join(WRITEUP_DIR, f"*-{rid}-*.md"))
        or glob.glob(os.path.join(WRITEUP_DIR, f"*-{rid}.md"))
    )


def _mark(rid: int) -> None:
    os.makedirs(WRITEUP_DIR, exist_ok=True)
    with open(DONE_FILE, "a") as f:
        f.write(f"{rid}\n")


def _embed_and_clear(buf: list[str], log) -> int:
    """Chunk + embed a batch of just-written files (does NOT reindex_all, which
    would re-embed every historical file every time). Returns chunks added."""
    if not buf:
        return 0
    sys.path.insert(0, os.path.dirname(__file__))
    from chroma_client import upsert_chunks
    from chunker import chunk_writeup
    from embedder import embed

    ids, docs, metas = [], [], []
    for p in buf:
        for c in chunk_writeup(p):
            ids.append(c["id"])
            docs.append(c["text"])
            metas.append(c["metadata"])
    if not ids:
        return 0
    added = 0
    for i in range(0, len(ids), 64):
        sl = slice(i, i + 64)
        vecs = embed(docs[sl])
        upsert_chunks(ids[sl], vecs, docs[sl], metas[sl])
        added += len(ids[sl])
    log(f"    embedded {added} chunks from {len(buf)} file(s)")
    return added


def ingest(ids, sleep_s: float = 1.5, embed: bool = True, limit: int = 0, log=print) -> dict:
    os.makedirs(WRITEUP_DIR, exist_ok=True)
    done = _done_set()
    written, fails, consec = [], 0, 0
    buf: list[str] = []
    for n, rid in enumerate(ids, 1):
        if limit and len(written) >= limit:
            break
        if _already(rid, done):
            continue
        d = fetch_report(rid)
        if not d or "id" not in d:
            fails += 1
            consec += 1
            if consec >= 15:
                log("    15 consecutive failures -- backing off 60s")
                time.sleep(60)
                consec = 0
            time.sleep(sleep_s)
            continue
        consec = 0
        fname, text, quality = report_to_markdown(d)
        with open(os.path.join(WRITEUP_DIR, fname), "w") as f:
            f.write(text)
        _mark(rid)
        done.add(str(rid))
        written.append({"id": rid, "file": fname, "quality": quality})
        log(f"[{n}] {rid} {quality} {fname}")
        if embed:
            buf.append(os.path.join(WRITEUP_DIR, fname))
            if len(buf) >= EMBED_BATCH:
                try:
                    _embed_and_clear(buf, log)
                except Exception as e:  # a Chroma/model hiccup must not kill the fetch run
                    log(f"    embed batch failed (re-run later to catch up): {e}")
                buf = []
        time.sleep(sleep_s)
    if embed and buf:
        try:
            _embed_and_clear(buf, log)
        except Exception as e:
            log(f"    final embed failed: {e}")
    return {"written": written, "fails": fails}


def _ids_from_catalog(path: str, klass: str = "", sort: str = "bounty") -> list[int]:
    with open(path) as f:
        cat = json.load(f)
    rows = []
    for r in cat:
        if (r.get("platform") or "") != "HackerOne":
            continue
        if klass and klass.lower() not in (r.get("vulnerabilityClass") or "").lower():
            continue
        i = report_id(r.get("url") or "")
        if not i:
            continue
        try:
            b = int(float(r.get("bounty") or 0))
        except (TypeError, ValueError):
            b = 0
        try:
            v = int(r.get("votes") or 0)
        except (TypeError, ValueError):
            v = 0
        rows.append((i, b, v))
    # Best-first by default so the most useful reports land in the RAG first
    # (the catalog itself is roughly oldest-first, i.e. low-value first).
    if sort == "votes":
        rows.sort(key=lambda x: (-x[2], -x[1]))
    elif sort == "id":
        pass
    else:  # "bounty"
        rows.sort(key=lambda x: (-x[1], -x[2]))
    return [r[0] for r in rows]


def _dedupe(seq):
    seen = set()
    return [x for x in seq if not (x in seen or seen.add(x))]


def _cli() -> None:
    ap = argparse.ArgumentParser(description="Bulk-ingest disclosed HackerOne reports into data/writeups/.")
    ap.add_argument("--ids", nargs="*", default=[], help="report ids or URLs")
    ap.add_argument("--catalog", default=DEFAULT_CATALOG)
    ap.add_argument("--class", dest="klass", default="", help="filter catalog by vulnerabilityClass substring")
    ap.add_argument("--sort", default="bounty", choices=["bounty", "votes", "id"], help="catalog order (best-first by default)")
    ap.add_argument("--limit", type=int, default=0, help="max reports to ingest this run (0 = all)")
    ap.add_argument("--sleep", type=float, default=1.5, help="seconds between HTTP requests")
    ap.add_argument("--no-embed", action="store_true")
    ap.add_argument("--embed-only", action="store_true", help="just (re)embed existing data/writeups/h1-*.md")
    args = ap.parse_args()

    if args.embed_only:
        paths = sorted(glob.glob(os.path.join(WRITEUP_DIR, "h1-*.md")))
        n = 0
        for i in range(0, len(paths), EMBED_BATCH):
            n += _embed_and_clear(paths[i : i + EMBED_BATCH], print)
        print(f"embedded {n} chunk(s) from {len(paths)} h1 file(s)")
        return

    ids = _dedupe([i for i in (report_id(x) for x in args.ids) if i])
    if not ids and os.path.exists(args.catalog):
        ids = _dedupe(_ids_from_catalog(args.catalog, args.klass, args.sort))
    print(f"{len(ids)} candidate HackerOne report id(s); sleep={args.sleep}s limit={args.limit or 'all'}")
    res = ingest(ids, sleep_s=args.sleep, embed=not args.no_embed, limit=args.limit)
    print(f"done: wrote {len(res['written'])}, failed {res['fails']}")


if __name__ == "__main__":
    _cli()
