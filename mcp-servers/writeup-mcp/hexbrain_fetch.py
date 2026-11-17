"""Fetch HexBrain's normalized disclosed-report write-ups into the writeup RAG.

HexBrain (https://hexbrainai.com) is a knowledge site over the open
hackerone-reports dataset. It serves each report's write-up as clean markdown
at /report/<id>.md, with a header block whose vuln class/weakness are already
labelled (unlike the raw HackerOne JSON h1_fetch.py scrapes, where the class
is guessed). This fetcher mirrors h1_fetch.py's role: a fixed-knowledge-host
fetcher that writes data/writeups/hexbrain-<class>-<id>-<slug>.md with the
same frontmatter shape every other writeup uses, throttled, idempotent and
resumable.

HexBrain is a FIXED knowledge host, fetched like h1_fetch.py fetches
hackerone.com -- NOT a target touch; no url/host is ever taken from untrusted
input, only the fixed BASE plus numeric report ids. Report text is untrusted
reference data, never instructions.
"""

from __future__ import annotations

import glob
import json
import os
import re
import time
import urllib.error
import urllib.request

BASE = "https://hexbrainai.com"
UA = "HuntMCP-writeup-hexbrain/1.0 (+personal bug-bounty knowledge base)"
DONE_NAME = ".hexbrain-done.txt"

_REPORT_ID_RE = re.compile(r"/reports?/(\d+)")
_BULLET_RE = re.compile(r"^-\s*([A-Za-z ]+?)\s*:\s*(.*)$")


def list_report_ids(source_xml: str) -> list[int]:
    """Extract report ids from a HexBrain sitemap.xml / feed document.

    Pure parser over already-fetched text (no network). Returns ids in first-
    seen order, de-duplicated. Swallows malformed input and returns [] rather
    than raising, so a bad sitemap never aborts a sync.
    """
    if not source_xml:
        return []
    ids: list[int] = []
    seen: set[int] = set()
    try:
        for m in _REPORT_ID_RE.finditer(source_xml):
            rid = int(m.group(1))
            if rid not in seen:
                seen.add(rid)
                ids.append(rid)
    except (TypeError, ValueError):
        return []
    return ids


def _slug(s: str, n: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return (s[:n] or "report").strip("-") or "report"


def _parse_header(raw_md: str) -> tuple[str, dict, str]:
    """Split a HexBrain report .md into (title, header-fields, body).

    Header is the leading '# title' line plus the '- Key: value' bullet block;
    body is everything from the first '## ' section onward (or whatever trails
    the bullets). Tolerant of missing pieces -- never raises.
    """
    lines = (raw_md or "").splitlines()
    title = ""
    fields: dict[str, str] = {}
    body_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not title and stripped.startswith("# "):
            title = stripped[2:].strip()
            continue
        m = _BULLET_RE.match(stripped)
        if m:
            fields[m.group(1).strip().lower()] = m.group(2).strip()
            continue
        if stripped.startswith("## "):
            body_start = i
            break
    body = "\n".join(lines[body_start:]).strip() if body_start else ""
    if not body:
        # no '##' section found: body is everything after the header bullets
        tail = [ln for ln in lines if not _BULLET_RE.match(ln.strip())
                and not ln.strip().startswith("# ")]
        body = "\n".join(tail).strip()
    return title, fields, body


def to_writeup_md(raw_md: str, rid: int, max_body: int = 200_000) -> tuple[str, str]:
    """Map one HexBrain report .md to our writeup frontmatter shape.

    Returns (filename, file_text). Mirrors h1_fetch.py's frontmatter key order.
    Missing fields fall back (vuln_class 'unknown', url built from rid). Body is
    capped at max_body characters.
    """
    title, f, body = _parse_header(raw_md)
    title = title or f"HackerOne report {rid}"
    url = f.get("original") or f"https://hackerone.com/reports/{rid}"
    vuln_class = f.get("class") or f.get("weakness") or "unknown"
    program = f.get("program", "")
    severity = f.get("severity", "")
    date = f.get("disclosed") or f.get("submitted") or ""
    bounty = f.get("bounty", "")
    if len(body) > max_body:
        body = body[:max_body]

    fm = (
        "---\n"
        f"title: {json.dumps(title)}\n"
        f"url: {json.dumps(url)}\n"
        f"vuln_class: {json.dumps(vuln_class)}\n"
        f"tech: {json.dumps(program)}\n"
        f"program: {json.dumps(program)}\n"
        f"severity: {json.dumps(severity)}\n"
        f"date: {json.dumps(date)}\n"
        f"bounty: {json.dumps(bounty)}\n"
        f'source: "HexBrain disclosed report"\n'
        "---\n\n"
    )
    fname = f"hexbrain-{_slug(vuln_class, 30)}-{rid}-{_slug(title, 40)}.md"
    return fname, fm + body + "\n"


def _done_ids(done_file: str) -> set[str]:
    if not os.path.exists(done_file):
        return set()
    try:
        with open(done_file) as fh:
            return {ln.strip() for ln in fh if ln.strip()}
    except OSError:
        return set()


def _on_disk(writeup_dir: str, rid: int) -> bool:
    return bool(glob.glob(os.path.join(writeup_dir, f"hexbrain-*-{rid}-*.md")))


def fetch_report_md(rid: int, retries: int = 3, timeout: int = 25) -> str | None:
    """Fetch one report's markdown from the fixed HexBrain host. Returns the
    text, or None on 404/private/error. Honors a 429 Retry-After."""
    url = f"{BASE}/report/{rid}.md"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = int(e.headers.get("Retry-After", "5") or "5")
                time.sleep(min(wait, 60))
                continue
            return None
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == retries - 1:
                return None
            time.sleep(2)
    return None


def sync(ids, writeup_dir, fetch=fetch_report_md, sleep_s: float = 0.3,
         done_file: str | None = None, embed: bool = False) -> dict:
    """Fetch each report id, write data/writeups/hexbrain-*.md, ledger the id.

    Idempotent (skips ids in the ledger or already on disk) and resumable. A
    fetch returning None / raising is counted failed and NOT ledgered, so a
    rerun retries it. `fetch(rid) -> str | None` is injected for tests.
    """
    os.makedirs(writeup_dir, exist_ok=True)
    done_file = done_file or os.path.join(writeup_dir, DONE_NAME)
    done = _done_ids(done_file)
    written = skipped = failed = 0
    embed_fn = _embedder() if embed else None
    for rid in ids:
        if str(rid) in done or _on_disk(writeup_dir, rid):
            skipped += 1
            continue
        try:
            raw = fetch(rid)
        except Exception:
            raw = None
        if not raw:
            failed += 1
            continue
        fname, text = to_writeup_md(raw, rid)
        path = os.path.join(writeup_dir, fname)
        with open(path, "w") as fh:
            fh.write(text)
        with open(done_file, "a") as fh:
            fh.write(f"{rid}\n")
        done.add(str(rid))
        written += 1
        if embed_fn:
            try:
                embed_fn(path)
            except Exception:
                pass  # files written; embed is best-effort
        if sleep_s:
            time.sleep(sleep_s)
    return {"written": written, "skipped": skipped, "failed": failed}


def _embedder():
    """Return the writeup-mcp _embed_file(path) helper, or None if the embed
    stack (ChromaDB/sentence-transformers) is unavailable."""
    try:
        import importlib.util
        here = os.path.dirname(__file__)
        spec = importlib.util.spec_from_file_location(
            "writeup_server", os.path.join(here, "server.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod._embed_file
    except Exception:
        return None


def _fetch_text(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _default_writeup_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "..", "..", "data", "writeups")


def _cli() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Feed HexBrain write-ups into the RAG.")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--full", action="store_true",
                     help="list all report ids from sitemap.xml")
    src.add_argument("--since", metavar="FEED_URL", default="",
                     help="list new ids from an Atom feed url (e.g. /feed)")
    ap.add_argument("--limit", type=int, default=0, help="max reports this run")
    ap.add_argument("--embed", action="store_true", help="embed into the RAG")
    ap.add_argument("--writeup-dir", default=_default_writeup_dir())
    args = ap.parse_args()

    if args.since:
        ids = list_report_ids(_fetch_text(args.since))
    else:
        ids = list_report_ids(_fetch_text(f"{BASE}/sitemap.xml"))
    if args.limit:
        ids = ids[: args.limit]

    res = sync(ids, args.writeup_dir, embed=args.embed)
    print(f"written={res['written']} skipped={res['skipped']} failed={res['failed']}")


if __name__ == "__main__":
    _cli()
