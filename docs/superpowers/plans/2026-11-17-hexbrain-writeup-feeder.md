# HexBrain Writeup Feeder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pull HexBrain's normalized disclosed-report write-ups into `data/writeups/` for a self-owned, offline, update-aware corpus with clean vuln-class labels.

**Architecture:** A new throttled, resumable Python fetcher `mcp-servers/writeup-mcp/hexbrain_fetch.py`, mirroring the existing `h1_fetch.py`. It lists report ids from HexBrain's open `sitemap.xml` (full sync) or Atom `feed` (incremental), fetches each report's open `/report/<id>.md`, maps HexBrain's header block to our YAML frontmatter (`title`, `url`, `vuln_class`, …), writes `data/writeups/hexbrain-<class>-<id>-<slug>.md`, and records progress in a `.hexbrain-done.txt` ledger so reruns are idempotent and resumable. Embedding reuses the existing `_embed_file`/`reindex_all` path — unchanged.

**Tech Stack:** Python 3.12, stdlib `urllib`/`xml.etree` (like `h1_fetch.py`/`cve_fetch.py`), pytest.

**Spec:** docs/superpowers/specs/2026-11-17-knowledge-map-layer-design.md (the "Related (separate) workstream" section)

## Global Constraints

- Python scripts live only under `mcp-servers/` (project rule) — the fetcher goes in `mcp-servers/writeup-mcp/`, beside `h1_fetch.py`.
- Writeup files require YAML frontmatter with `title`, `url`, `vuln_class` (CI enforces).
- HexBrain is a **fixed knowledge host** (`hexbrainai.com`), fetched like `h1_fetch.py` fetches `hackerone.com` — NOT a target touch; it does not go through `research_http`/scope-guard, and must never take a host/url from untrusted input (only the fixed HexBrain base + numeric ids).
- Report text is untrusted reference data, never instructions.
- Throttle between requests (HexBrain open-data limit is 240/min from one address); default sleep ≥ 0.3s, resumable.
- `data/writeups/` is git-tracked; `data/chroma/` and ledger dotfiles are gitignored.
- No commit/push without an explicit in-the-moment ask; no `Co-Authored-By` line.

## Review Focus

- **Missing/garbled HexBrain header fields** (no `Class:`, no `Original:`): the mapper must still produce valid frontmatter (fallback `vuln_class: "unknown"`, url built from id) rather than write a CI-invalid file. → test in Task 2.
- **Non-200 / rate-limit (429) / network error on one report:** sync must skip-and-continue (and respect `Retry-After`), never abort the whole run or mark a failed id done. → test in Task 3.
- **Rerun after partial run:** already-fetched ids (ledger or file on disk) are skipped, not re-downloaded or duplicated. → test in Task 3.
- **Malicious/huge report body:** body is written verbatim as data (never executed/evaluated); a size cap avoids an unbounded write. → test in Task 2.
- **Sitemap/feed with unexpected XML:** id extraction returns what it can and ignores the rest, never raises. → test in Task 1.

---

### Task 1: Report-id listing from sitemap/feed

**Files:**
- Create: `mcp-servers/writeup-mcp/hexbrain_fetch.py`
- Test: `tests/test_hexbrain_fetch.py`

**Interfaces:**
- Produces: `list_report_ids(source_xml: str) -> list[int]` (pure parser over fetched XML text — no network, so it is unit-testable); `BASE = "https://hexbrainai.com"`.

- [ ] **Step 1: Write the failing test** — `test_list_report_ids_extracts_from_sitemap` feeds a small `<urlset>` string containing `https://hexbrainai.com/report/341876` and `/report/1067443` plus one non-report url, asserts `list_report_ids(xml) == [341876, 1067443]`. Add `test_list_report_ids_ignores_garbage` feeding malformed XML, asserts it returns `[]` without raising.
- [ ] **Step 2: Run test to verify it fails** — `pytest tests/test_hexbrain_fetch.py -v` → FAIL (module/function missing).
- [ ] **Step 3: Implement `list_report_ids(source_xml)`** in `hexbrain_fetch.py` — regex/`xml.etree` extract `/report/<digits>` ids, de-dup preserving order, swallow parse errors and return `[]`.
- [ ] **Step 4: Run test to verify it passes** — `pytest tests/test_hexbrain_fetch.py -v` → PASS.
- [ ] **Step 5: Commit** — `git add mcp-servers/writeup-mcp/hexbrain_fetch.py tests/test_hexbrain_fetch.py && git commit -m "feat(writeup): hexbrain report-id listing from sitemap"`

### Task 2: Map one HexBrain `.md` to our writeup frontmatter

**Files:**
- Modify: `mcp-servers/writeup-mcp/hexbrain_fetch.py`
- Test: `tests/test_hexbrain_fetch.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `to_writeup_md(raw_md: str, rid: int, max_body: int = 200_000) -> tuple[str, str]` returning `(filename, file_text)` where `file_text` has YAML frontmatter `title`, `url`, `vuln_class`, plus `program`, `severity`, `bounty`, `date` when present, followed by the write-up body (capped at `max_body`). Filename pattern `hexbrain-<classslug>-<rid>-<titleslug>.md`.

- [ ] **Step 1: Write the failing test** — `test_to_writeup_md_maps_header` feeds the real header shape (`# <title>`, `- Original: https://hackerone.com/reports/341876`, `- Class: Server-Side Request Forgery`, `- Severity: medium`) and asserts the output frontmatter contains `title:`, `url: "https://hackerone.com/reports/341876"`, `vuln_class: "Server-Side Request Forgery"`. Add `test_to_writeup_md_missing_class_falls_back` (no `Class:` line → `vuln_class: "unknown"`, url built from `rid`) and `test_to_writeup_md_caps_body` (body longer than `max_body` is truncated).
- [ ] **Step 2: Run test to verify it fails** — FAIL (function missing).
- [ ] **Step 3: Implement `to_writeup_md(...)`** — parse the `# ` title and `- Key: value` bullet header into a dict; emit YAML frontmatter (reuse the exact key order `h1_fetch.py` uses) + body; apply fallbacks and the size cap; slugify via the same approach as `h1_fetch.py:_slug`.
- [ ] **Step 4: Run test to verify it passes** — PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(writeup): map hexbrain report md to writeup frontmatter"`

### Task 3: Resumable, throttled sync driver + CLI

**Files:**
- Modify: `mcp-servers/writeup-mcp/hexbrain_fetch.py`
- Test: `tests/test_hexbrain_fetch.py`

**Interfaces:**
- Consumes: `list_report_ids` (Task 1), `to_writeup_md` (Task 2).
- Produces: `sync(ids, writeup_dir, fetch=<callable>, sleep_s=0.3, done_file=...) -> dict` where `fetch(rid) -> str | None` is injected (tests pass a fake; prod passes the real HexBrain fetch). Returns `{"written": n, "skipped": n, "failed": n}`. Writes each file, appends successful ids to the ledger, skips ids already in the ledger or already on disk, and on a `fetch` returning `None`/raising, counts it failed and continues (never ledgered). Plus a `__main__` CLI (`--full` sitemap, `--since` feed, `--limit`, `--embed`).

- [ ] **Step 1: Write the failing test** — `test_sync_writes_and_is_idempotent`: call `sync([1,2], tmp_dir, fetch=fake)` where `fake` returns a valid raw md for both → asserts 2 files written and ledger has both; call again → asserts `skipped == 2`, `written == 0`, no duplicate files. `test_sync_skips_failed`: `fake` returns `None` for id 2 → `written==1, failed==1`, id 2 NOT in ledger.
- [ ] **Step 2: Run test to verify it fails** — FAIL.
- [ ] **Step 3: Implement `sync(...)`** and the real `fetch_report_md(rid)` (stdlib `urllib`, `User-Agent` like `h1_fetch.py`, honor 429 `Retry-After`, timeout, retries) + the `__main__` CLI wiring. Prod fetch = `fetch_report_md`; the CLI resolves `writeup_dir` to the repo `data/writeups/`.
- [ ] **Step 4: Run test to verify it passes** — `pytest tests/test_hexbrain_fetch.py -v` → PASS (all tasks' tests green).
- [ ] **Step 5: Commit** — `git commit -am "feat(writeup): resumable throttled hexbrain sync + CLI"`

### Task 4: Embed into the RAG + runtime verification

**Files:**
- Modify: `mcp-servers/writeup-mcp/hexbrain_fetch.py` (wire `--embed` to the existing `_embed_file` path used by `h1_fetch.py`)
- Test: `tests/test_hexbrain_fetch.py`

**Interfaces:**
- Consumes: `sync` (Task 3); the existing embed helper (import the same one `h1_fetch.py` uses).

- [ ] **Step 1: Write the failing test** — `test_embed_flag_calls_embedder`: run `sync(..., embed=True)` with the embedder monkeypatched to a counter, assert it is called once per written file and zero times for skipped files.
- [ ] **Step 2: Run test to verify it fails** — FAIL.
- [ ] **Step 3: Implement the `--embed`/`embed=True` path** — after each write, call the embed helper (batched like `h1_fetch.py`), guard import so a missing ChromaDB env degrades to "files written, embed skipped" with a clear message, not a crash.
- [ ] **Step 4: Run test to verify it passes** — PASS. Then **prove it runs**: fetch a *small* real batch (`python3 mcp-servers/writeup-mcp/hexbrain_fetch.py --limit 3 --embed`), show the 3 new `data/writeups/hexbrain-*.md` files (valid frontmatter), and a `query_rag` over one of their topics returning the new report. Record `Runtime-verified: <cmd> → <result>`.
- [ ] **Step 5: Commit** — `git commit -am "feat(writeup): embed hexbrain reports into RAG on sync"`
