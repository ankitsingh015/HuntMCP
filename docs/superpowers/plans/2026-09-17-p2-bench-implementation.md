# P2-BENCH Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the multi-vuln-class benchmark + evaluator substrate (`P2-BENCH`) that later gated tasks (P2-COV, P3-SCHEMA, P3-VALAUTHZ, P4-BM, P5-A1) will measure against.

**Architecture:** One loopback-only, stdlib-`http.server` target app (`bench_app.py`) with 6 planted vulnerable/patched endpoint pairs and an independent request log; a blind case index (`bench_scenarios.py`) + evaluator-only, SHA-256-locked answer key (`bench_answer_key.py`); an arm-agnostic scoring function (`bench_evaluator.py`: `ObservedFinding` → `evaluate()` → `BenchReport`); a fixture self-test that proves each planted bug is real by driving HuntMCP's actual Tier-2 MCP tool functions against the live target; and evaluator-logic tests proving the scoring math independent of any tool.

**Tech Stack:** Python stdlib only (`http.server`, `hashlib`, `sqlite3`, `urllib`) — no new dependency. Real Tier-2 tools already in this repo: sqlmap, dalfox, idor-mcp, ffuf, nuclei, curl.

**Spec:** `docs/superpowers/specs/2026-09-17-p2-bench-design.md` — this plan implements that spec exactly; read it first for the 10 non-negotiable principles every task below must honor.

## Global Constraints

- Never restrict what a real hunt may do — this is measurement infrastructure only (spec principle 1–2).
- `bench_answer_key.py`'s `verification_tool` field is read ONLY by the fixture self-test files (Tasks 11–16); `bench_evaluator.evaluate()` never reads it (principle 4).
- `novel_findings` (unmatched confirmed claims) are never false positives and never discarded (principles 5–6).
- False positives are ONLY confirmed claims against a case currently in `patched` mode (principle 6).
- Every fixture module is prefixed `bench_` — never reuse `cem_target`'s bare names (`scenarios.py`, `answer_key.py`, `evaluator.py`, `harness.py`, `integrity.py`) to avoid Python module-cache collisions across the two fixture packages in one pytest process.
- Zero lines changed under `tests/fixtures/cem_target/`, `cem_engine.py`, `case-mcp/server.py`, `tests/test_cem_benchmark.py`, or any `mcp-servers/*` production module (principle 9) — **narrowly superseded for `sandbox_runner.py` only, see the 2026-09-22 note below.**
- No change to `scope_gate_hook.py`, `job_runtime.py`, or any other S1–S6/S-GATE file (principle 10). `sandbox_runner.py` gets exactly one narrow, dormant-by-default exception, see below.

**Networking-seam decision (2026-09-22, human-authorized, supersedes the Tasks 12–17 deferral):** Tasks 12–17 route through the real MCP tool functions, which always call `job_runtime.start_job()` → `sandbox_runner.build_argv()`, which give every real Tier-2 invocation its own isolated rootless-Podman network namespace with no host-loopback reverse connectivity (confirmed empirically, see the now-superseded blocker note previously recorded in `IMPLEMENTATION-TASK-TRACKER.md`'s P2-BENCH row). Rather than deferring these tasks or weakening S5 generally, `sandbox_runner.build_argv()` gains exactly one new internal check: if the process environment variable `HUNTMCP_BENCH_NETWORK` is set (a name reserved and documented as test-harness-only, never set by any production launch config in `opencode.jsonc`), append `--network=<value>` to the podman argv instead of the current default network handling. No new parameter is added to `build_argv()`, `start_job()`, or any MCP server tool function — the agent-facing surface of every MCP tool is completely unchanged, and there is no code path from an MCP tool-call argument to this variable. For every real hunt this variable is never present, so behavior is byte-identical to today.

The benchmark harness (new code, under `tests/fixtures/bench_target/` only) is responsible for the full lifecycle: create a uniquely-named, `--internal` (no route to the internet or the host) Podman network per test run; start `bench_app` as its own container attached to that network with no published host port; set `HUNTMCP_BENCH_NETWORK` for the duration of the test process only (e.g. via `monkeypatch.setenv`); call the real, unmodified MCP tool function with the bench container's address as the `url`; tear down the container and network afterward. This mechanism is never imported by, or reachable from, any production code path — only `sandbox_runner.py` itself changes, and its change is inert outside a benchmark test process.

**Hardening added in adversarial review (2026-09-23):** the initial version spliced `HUNTMCP_BENCH_NETWORK`'s value into `--network=<value>` with no validation at all -- a stray/typo'd/leftover-debug value of `"host"` (or Podman's other special values: `none`/`bridge`/`container:x`) would have silently granted every subsequent real Tier-2 tool call in that process full host networking, defeating S5 entirely. `sandbox_runner._validate_bench_network()` now rejects any value not matching `SandboxedBenchApp`'s own generated-name prefix (`huntmcp-bench-net-`), raising a new `UnsafeBenchNetwork` before it ever reaches argv. Regression: `tests/test_sandbox_runner.py::test_build_argv_rejects_a_bench_network_value_not_matching_the_expected_prefix`.
- All target-app traffic binds `127.0.0.1` only, ephemeral port — never a real external target (`security.md`).
- Every test file isolates its own budget/audit paths (`HUNTMCP_BUDGET_PATH`, `HUNTMCP_AUDIT_LOG` env overrides, or monkeypatching `_enforce_budget`/`_log_call`) so it never touches this machine's real active engagement's own ledger files — same pattern already used by `tests/test_job_runtime.py`'s `_no_budget`/`_no_audit` helpers.

**Spec correction found while writing this plan:** the spec's §3 table lists `httpx-mcp` as the open-redirect fixture-proof tool. `httpx-mcp`'s `probe_hosts()` formats output as status/title/tech/server/length only — it never surfaces the `Location` header value, so it cannot actually distinguish "redirects anywhere" from "redirects only same-origin." `curl` (already a real, sandboxed, Tier-2-listed tool via `tool_resolver.run_tool()`) directly exposes `Location` via `-D -`, so Task 16 uses `curl` instead. This is a build-time-proof-tool substitution only (spec principle 4 already says this mapping is never a hunting restriction) — no other part of the design changes.

---

### Task 1: `bench_integrity.py` — protected-file integrity utility

**Files:**
- Create: `tests/fixtures/bench_target/__init__.py` (empty)
- Create: `tests/fixtures/bench_target/bench_integrity.py`
- Test: `tests/test_p2_bench_evaluator.py` (new file, integrity section)

**Interfaces:**
- Produces: `file_sha256(path) -> str`, `lock_path_for(path) -> str`, `read_lock(path) -> str | None`, `verify(path) -> tuple[bool, str]`, `update(path) -> str`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p2_bench_evaluator.py
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "bench_target"))

import bench_integrity


def test_verify_fails_when_no_lock_file_exists(tmp_path):
    target = tmp_path / "some_file.py"
    target.write_text("x = 1\n")
    ok, msg = bench_integrity.verify(str(target))
    assert ok is False
    assert "integrity lock missing" in msg


def test_update_then_verify_succeeds(tmp_path):
    target = tmp_path / "some_file.py"
    target.write_text("x = 1\n")
    bench_integrity.update(str(target))
    ok, msg = bench_integrity.verify(str(target))
    assert ok is True
    assert "integrity OK" in msg


def test_verify_fails_after_the_file_changes_post_lock(tmp_path):
    target = tmp_path / "some_file.py"
    target.write_text("x = 1\n")
    bench_integrity.update(str(target))
    target.write_text("x = 2\n")  # tampered, no re-lock
    ok, msg = bench_integrity.verify(str(target))
    assert ok is False
    assert "INTEGRITY FAILURE" in msg
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_evaluator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'bench_integrity'`

- [ ] **Step 3: Write the implementation**

Create `tests/fixtures/bench_target/__init__.py` (empty file).

Create `tests/fixtures/bench_target/bench_integrity.py` as an exact copy of `tests/fixtures/cem_target/integrity.py`'s content (same ~40 lines, same functions: `file_sha256`, `lock_path_for`, `read_lock`, `verify`, `update`) — copy the file verbatim, do not modify `cem_target/integrity.py` itself.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_evaluator.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/__init__.py tests/fixtures/bench_target/bench_integrity.py tests/test_p2_bench_evaluator.py
git commit -m "feat(p2-bench): add bench_integrity.py protected-file lock utility"
```

---

### Task 2: `bench_app.py` skeleton + SQL injection case

**Files:**
- Create: `tests/fixtures/bench_target/bench_app.py`
- Test: `tests/test_p2_bench_fixture.py` (new file, this task's section)

**Interfaces:**
- Produces: `class BenchApp` with `__init__(self, mode: str)`, `.start() -> "BenchApp"` (binds loopback ephemeral port, returns self), `.stop()`, `.base_url: str`, `.request_log: list[dict]` (each entry: `{"path": str, "query": dict, "headers": dict, "cookie": str}`), `.reset()`.
- Consumes: nothing (stdlib only).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_p2_bench_fixture.py
import os
import sqlite3
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "bench_target"))

from bench_app import BenchApp


@pytest.fixture
def vulnerable_app():
    app = BenchApp(mode="vulnerable").start()
    try:
        yield app
    finally:
        app.stop()


@pytest.fixture
def patched_app():
    app = BenchApp(mode="patched").start()
    try:
        yield app
    finally:
        app.stop()


def test_app_binds_loopback_only_and_returns_a_base_url(vulnerable_app):
    assert vulnerable_app.base_url.startswith("http://127.0.0.1:")


def test_sqli_vulnerable_boolean_injection_returns_all_products(vulnerable_app):
    import urllib.request
    baseline = urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/products?id=1").read().decode()
    injected = urllib.request.urlopen(
        f"{vulnerable_app.base_url}/bench/products?id=1%20OR%201=1"
    ).read().decode()
    assert injected.count("PRODUCT-") > baseline.count("PRODUCT-")


def test_sqli_patched_boolean_injection_has_no_effect(patched_app):
    import urllib.request
    baseline = urllib.request.urlopen(f"{patched_app.base_url}/bench/products?id=1").read().decode()
    injected = urllib.request.urlopen(
        f"{patched_app.base_url}/bench/products?id=1%20OR%201=1"
    ).read().decode()
    assert injected.count("PRODUCT-") == baseline.count("PRODUCT-")


def test_request_log_records_the_path_and_query(vulnerable_app):
    import urllib.request
    urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/products?id=7")
    assert any(
        e["path"] == "/bench/products" and e["query"].get("id") == ["7"]
        for e in vulnerable_app.request_log
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'bench_app'`

- [ ] **Step 3: Write the implementation**

```python
# tests/fixtures/bench_target/bench_app.py
"""Constructed multi-vuln-class benchmark target (TEST FIXTURE ONLY).

See docs/superpowers/specs/2026-09-17-p2-bench-design.md for the full
design. Loopback-only (127.0.0.1, ephemeral port), zero outbound calls,
two behavior modes ("vulnerable"/"patched"). Holds an independent
in-process request log so a test can verify a claimed finding is backed
by real, differing requests rather than a tool's own narrative -- same
role as tests/fixtures/cem_target/cem_benchmark_app.py's request log.

Does NOT import bench_scenarios/bench_answer_key -- this app has no path
to its own expected answers, matching cem_benchmark_app.py's own
"safe by construction" property.
"""
from __future__ import annotations

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOOPBACK = "127.0.0.1"

# Fake-but-recognizable content so a real tool's own output can be checked
# against something specific, not just "some text changed."
_BACKUP_FILE_CONTENT = "DB_PASSWORD=bench-fixture-fake-secret-not-real\n"
_MISCONFIG_BANNER = "X-Bench-Debug-Panel: build 2026.09-DEBUG-ENABLED"


class _State:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.lock = threading.Lock()
        self.request_log: list[dict] = []
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.execute("CREATE TABLE products (id INTEGER, name TEXT)")
        self.db.executemany(
            "INSERT INTO products VALUES (?, ?)",
            [(1, "PRODUCT-alpha"), (2, "PRODUCT-bravo"), (3, "PRODUCT-charlie")],
        )
        self.db.commit()
        # orders: id -> owner session token. Order 42 belongs to "owner-session".
        self.orders = {42: {"owner": "owner-session", "data": "ORDER-DETAIL-42-SECRET"}}

    def reset(self) -> None:
        with self.lock:
            self.request_log.clear()


def _cookie_value(headers) -> str:
    return headers.get("Cookie", "") or ""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a, **k) -> None:
        return

    def _send(self, status: int, body: str, headers: dict | None = None) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _record(self, path: str, qs: dict) -> None:
        st: _State = self.server.state  # type: ignore[attr-defined]
        with st.lock:
            st.request_log.append({
                "path": path, "query": qs,
                "headers": dict(self.headers.items()),
                "cookie": _cookie_value(self.headers),
            })

    def do_GET(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler's own naming convention
        st: _State = self.server.state  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        self._record(path, qs)

        if path == "/bench/decoy":
            self._send(200, "nothing interesting here")
            return

        if path == "/bench/products":
            raw_id = qs.get("id", ["1"])[0]
            if st.mode == "vulnerable":
                # Real, string-concatenated SQL injection -- genuinely
                # exploitable, not a toy check.
                query = f"SELECT id, name FROM products WHERE id = {raw_id}"
                try:
                    rows = st.db.execute(query).fetchall()
                except sqlite3.Error as e:
                    self._send(500, f"db error: {e}")
                    return
            else:
                try:
                    rows = st.db.execute(
                        "SELECT id, name FROM products WHERE id = ?", (raw_id,)
                    ).fetchall()
                except sqlite3.Error:
                    rows = []
            self._send(200, "\n".join(f"{r[0]}: {r[1]}" for r in rows) or "no products")
            return

        self._send(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        self._send(404, "not found")


def _make_server(mode: str) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((LOOPBACK, 0), _Handler)
    server.state = _State(mode)  # type: ignore[attr-defined]
    return server


class BenchApp:
    def __init__(self, mode: str) -> None:
        assert mode in ("vulnerable", "patched")
        self.mode = mode
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "BenchApp":
        self._server = _make_server(self.mode)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    def reset(self) -> None:
        self._server.state.reset()  # type: ignore[attr-defined]

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address  # type: ignore[union-attr]
        return f"http://{LOOPBACK}:{port}"

    @property
    def request_log(self) -> list[dict]:
        return self._server.state.request_log  # type: ignore[attr-defined]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_app.py tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): add bench_app skeleton + real SQLi vulnerable/patched case"
```

---

### Task 3: Reflected XSS case

**Files:**
- Modify: `tests/fixtures/bench_target/bench_app.py` (add `/bench/search` route)
- Test: `tests/test_p2_bench_fixture.py` (add this task's section)

**Interfaces:**
- Consumes: `_Handler.do_GET`, `_State` (Task 2)
- Produces: no new public interface; `/bench/search?q=` is now a recognized route

- [ ] **Step 1: Write the failing test**

```python
def test_xss_vulnerable_reflects_script_tag_unescaped(vulnerable_app):
    import urllib.request
    body = urllib.request.urlopen(
        f"{vulnerable_app.base_url}/bench/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    ).read().decode()
    assert "<script>alert(1)</script>" in body


def test_xss_patched_escapes_the_script_tag(patched_app):
    import urllib.request
    body = urllib.request.urlopen(
        f"{patched_app.base_url}/bench/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    ).read().decode()
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k xss -v`
Expected: FAIL — `/bench/search` returns 404

- [ ] **Step 3: Write the implementation**

Add to `bench_app.py`'s imports: `import html`. Add this branch inside `do_GET`, before the final `self._send(404, ...)`:

```python
        if path == "/bench/search":
            term = qs.get("q", [""])[0]
            if st.mode == "vulnerable":
                body = f"<html><body>Results for: {term}</body></html>"
            else:
                body = f"<html><body>Results for: {html.escape(term)}</body></html>"
            self._send(200, body)
            return
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k xss -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_app.py tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): add reflected-XSS vulnerable/patched case"
```

---

### Task 4: IDOR case

**Files:**
- Modify: `tests/fixtures/bench_target/bench_app.py` (add `/bench/orders/<id>` route)
- Test: `tests/test_p2_bench_fixture.py`

- [ ] **Step 1: Write the failing test**

```python
def test_idor_vulnerable_attacker_session_sees_owners_order(vulnerable_app):
    import urllib.request
    req = urllib.request.Request(
        f"{vulnerable_app.base_url}/bench/orders/42", headers={"Cookie": "session=attacker-session"}
    )
    body = urllib.request.urlopen(req).read().decode()
    assert "ORDER-DETAIL-42-SECRET" in body


def test_idor_patched_attacker_session_is_refused(patched_app):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        f"{patched_app.base_url}/bench/orders/42", headers={"Cookie": "session=attacker-session"}
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req)
    assert exc.value.code == 403


def test_idor_patched_owner_session_still_works(patched_app):
    import urllib.request
    req = urllib.request.Request(
        f"{patched_app.base_url}/bench/orders/42", headers={"Cookie": "session=owner-session"}
    )
    body = urllib.request.urlopen(req).read().decode()
    assert "ORDER-DETAIL-42-SECRET" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k idor -v`
Expected: FAIL — `/bench/orders/42` returns 404

- [ ] **Step 3: Write the implementation**

Add to `bench_app.py`'s `do_GET`, before the final 404:

```python
        if path.startswith("/bench/orders/"):
            order_id_raw = path.rsplit("/", 1)[-1]
            try:
                order_id = int(order_id_raw)
            except ValueError:
                self._send(404, "not found")
                return
            order = st.orders.get(order_id)
            if order is None:
                self._send(404, "no such order")
                return
            session = st.orders_session_of(self.headers)
            if st.mode == "vulnerable" or session == order["owner"]:
                self._send(200, order["data"])
            else:
                self._send(403, "forbidden")
            return
```

Add this method to `_State`:

```python
    def orders_session_of(self, headers) -> str:
        cookie = _cookie_value(headers)
        return cookie.split("session=", 1)[-1] if "session=" in cookie else ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k idor -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_app.py tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): add IDOR vulnerable/patched case"
```

---

### Task 5: Exposed backup file case

**Files:**
- Modify: `tests/fixtures/bench_target/bench_app.py` (add `/backup.sql.bak` route)
- Test: `tests/test_p2_bench_fixture.py`

- [ ] **Step 1: Write the failing test**

```python
def test_backup_file_vulnerable_is_present(vulnerable_app):
    import urllib.request
    body = urllib.request.urlopen(f"{vulnerable_app.base_url}/backup.sql.bak").read().decode()
    assert "DB_PASSWORD=bench-fixture-fake-secret-not-real" in body


def test_backup_file_patched_is_absent(patched_app):
    import urllib.error
    import urllib.request
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{patched_app.base_url}/backup.sql.bak")
    assert exc.value.code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k backup_file -v`
Expected: FAIL — always 404 (route doesn't exist yet, even in vulnerable mode)

- [ ] **Step 3: Write the implementation**

Add to `bench_app.py`'s `do_GET`, before the final 404:

```python
        if path == "/backup.sql.bak":
            if st.mode == "vulnerable":
                self._send(200, _BACKUP_FILE_CONTENT)
            else:
                self._send(404, "not found")
            return
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k backup_file -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_app.py tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): add exposed-backup-file vulnerable/patched case"
```

---

### Task 6: Security misconfiguration case + custom nuclei template

**Files:**
- Modify: `tests/fixtures/bench_target/bench_app.py` (add `X-Bench-Debug-Panel` header to `/bench/status`)
- Create: `tests/fixtures/bench_target/templates/misconfig-banner.yaml`
- Test: `tests/test_p2_bench_fixture.py`

- [ ] **Step 1: Write the failing test**

```python
def test_misconfig_vulnerable_banner_header_present(vulnerable_app):
    import urllib.request
    resp = urllib.request.urlopen(f"{vulnerable_app.base_url}/bench/status")
    assert resp.headers.get("X-Bench-Debug-Panel") == "build 2026.09-DEBUG-ENABLED"


def test_misconfig_patched_banner_header_absent(patched_app):
    import urllib.request
    resp = urllib.request.urlopen(f"{patched_app.base_url}/bench/status")
    assert resp.headers.get("X-Bench-Debug-Panel") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k misconfig -v`
Expected: FAIL — `/bench/status` returns 404

- [ ] **Step 3: Write the implementation**

Add to `bench_app.py`'s `do_GET`, before the final 404:

```python
        if path == "/bench/status":
            headers = {"X-Bench-Debug-Panel": _MISCONFIG_BANNER} if st.mode == "vulnerable" else {}
            self._send(200, "status: ok", headers=headers)
            return
```

Create `tests/fixtures/bench_target/templates/misconfig-banner.yaml` — a real, minimal, self-contained nuclei
template (does not depend on ProjectDiscovery's public/live-updated template set):

```yaml
id: bench-debug-panel-exposed

info:
  name: Bench Fixture Debug Panel Header Exposed
  author: huntmcp-bench
  severity: medium
  description: Detects the HuntMCP benchmark fixture's planted debug-panel response header.

http:
  - method: GET
    path:
      - "{{BaseURL}}/bench/status"
    matchers:
      - type: word
        part: header
        words:
          - "X-Bench-Debug-Panel"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k misconfig -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_app.py tests/fixtures/bench_target/templates/misconfig-banner.yaml tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): add misconfiguration vulnerable/patched case + custom nuclei template"
```

---

### Task 7: Open redirect case

**Files:**
- Modify: `tests/fixtures/bench_target/bench_app.py` (add `/bench/login` route)
- Test: `tests/test_p2_bench_fixture.py`

- [ ] **Step 1: Write the failing test**

```python
def test_open_redirect_vulnerable_follows_any_next(vulnerable_app):
    import urllib.request
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(_NoRedirect)
    resp = opener.open(f"{vulnerable_app.base_url}/bench/login?next=https://attacker.example/steal")
    assert resp.status == 302
    assert resp.headers.get("Location") == "https://attacker.example/steal"


def test_open_redirect_patched_ignores_external_next(patched_app):
    import urllib.request
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(_NoRedirect)
    resp = opener.open(f"{patched_app.base_url}/bench/login?next=https://attacker.example/steal")
    assert resp.status == 302
    assert resp.headers.get("Location") == "/bench/home"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k open_redirect -v`
Expected: FAIL — `/bench/login` returns 404

- [ ] **Step 3: Write the implementation**

Add to `bench_app.py`'s `do_GET`, before the final 404:

```python
        if path == "/bench/login":
            next_url = qs.get("next", ["/bench/home"])[0]
            if st.mode == "vulnerable":
                location = next_url
            else:
                location = next_url if next_url.startswith("/") else "/bench/home"
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k open_redirect -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_app.py tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): add open-redirect vulnerable/patched case"
```

---

### Task 8: `bench_scenarios.py` + `bench_answer_key.py` + integrity locks + blindness guard

**Files:**
- Create: `tests/fixtures/bench_target/bench_scenarios.py`
- Create: `tests/fixtures/bench_target/bench_answer_key.py`
- Create: `tests/fixtures/bench_target/bench_scenarios.py.sha256.lock`
- Create: `tests/fixtures/bench_target/bench_answer_key.py.sha256.lock`
- Test: `tests/test_p2_bench_evaluator.py`

**Interfaces:**
- Produces: `bench_scenarios.SCENARIOS: dict[str, dict]` (`{"endpoint": str, "method": str}`), `bench_scenarios.FORBIDDEN_ANSWER_FIELDS: tuple[str, ...]`; `bench_answer_key.EXPECTED_BY_MODE: dict[str, dict[str, dict]]`

- [ ] **Step 1: Write the failing test**

```python
import bench_scenarios
import bench_answer_key


def test_scenarios_covers_all_six_cases():
    assert set(bench_scenarios.SCENARIOS) == {
        "case_sqli", "case_xss", "case_idor", "case_backup_file", "case_misconfig", "case_open_redirect",
    }


def test_scenarios_never_leaks_a_forbidden_answer_field():
    import json
    blob = json.dumps({k: dict(v) for k, v in bench_scenarios.SCENARIOS.items()})
    for field in bench_scenarios.FORBIDDEN_ANSWER_FIELDS:
        assert field not in blob, f"{field!r} leaked into the blind scenario manifest"


def test_answer_key_has_an_entry_for_every_scenario_case():
    assert set(bench_answer_key.EXPECTED_BY_MODE) == set(bench_scenarios.SCENARIOS)


def test_answer_key_expects_confirmed_true_in_vulnerable_and_false_in_patched():
    for case_id, by_mode in bench_answer_key.EXPECTED_BY_MODE.items():
        assert by_mode["vulnerable"]["confirmed"] is True, case_id
        assert by_mode["patched"]["confirmed"] is False, case_id


def test_bench_scenarios_and_answer_key_integrity_locks_hold():
    import os

    import bench_integrity
    fixture_dir = os.path.dirname(bench_scenarios.__file__)
    for name in ("bench_scenarios.py", "bench_answer_key.py"):
        ok, msg = bench_integrity.verify(os.path.join(fixture_dir, name))
        assert ok, msg
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_evaluator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'bench_scenarios'`

- [ ] **Step 3: Write the implementation**

```python
# tests/fixtures/bench_target/bench_scenarios.py
"""BLIND case index -- endpoint/method only. NEVER imported by any
mcp-servers/* production code and NEVER handed to a hunting tool call --
a real hunt only ever receives the target's base URL, exactly like a
real engagement. This file exists purely as the evaluator's own
bookkeeping (which path maps to which case_id) and as the future home of
P4-COVMATRIX's endpoint x class x role index. See
docs/superpowers/specs/2026-09-17-p2-bench-design.md section 5."""
from __future__ import annotations

from types import MappingProxyType

SCENARIOS = MappingProxyType({
    "case_sqli": MappingProxyType({"endpoint": "/bench/products", "method": "GET"}),
    "case_xss": MappingProxyType({"endpoint": "/bench/search", "method": "GET"}),
    "case_idor": MappingProxyType({"endpoint": "/bench/orders", "method": "GET"}),
    "case_backup_file": MappingProxyType({"endpoint": "/backup.sql.bak", "method": "GET"}),
    "case_misconfig": MappingProxyType({"endpoint": "/bench/status", "method": "GET"}),
    "case_open_redirect": MappingProxyType({"endpoint": "/bench/login", "method": "GET"}),
})

# Fields that must NEVER appear in this manifest.
FORBIDDEN_ANSWER_FIELDS = (
    "vuln_class", "severity", "verification_tool", "confirmed", "expected",
)
```

```python
# tests/fixtures/bench_target/bench_answer_key.py
"""EVALUATOR-ONLY answer key. `verification_tool` is read ONLY by the
fixture self-test files (tests/test_p2_bench_fixture.py) to prove each
planted bug is genuine at BUILD time -- bench_evaluator.evaluate() never
reads this field when scoring an actual hunt run (spec principle 4)."""
from __future__ import annotations

from types import MappingProxyType

EXPECTED_BY_MODE = MappingProxyType({
    "case_sqli": MappingProxyType({
        "vuln_class": "sql_injection", "severity": "high", "verification_tool": "sqlmap-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_xss": MappingProxyType({
        "vuln_class": "reflected_xss", "severity": "medium", "verification_tool": "dalfox-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_idor": MappingProxyType({
        "vuln_class": "idor", "severity": "high", "verification_tool": "idor-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_backup_file": MappingProxyType({
        "vuln_class": "information_disclosure", "severity": "medium", "verification_tool": "ffuf-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_misconfig": MappingProxyType({
        "vuln_class": "misconfiguration", "severity": "medium", "verification_tool": "nuclei-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_open_redirect": MappingProxyType({
        "vuln_class": "open_redirect", "severity": "low", "verification_tool": "curl",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
})
```

Generate the lock files (maintainer action, not part of any test run):

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, 'tests/fixtures/bench_target')
import bench_integrity
bench_integrity.update('tests/fixtures/bench_target/bench_scenarios.py')
bench_integrity.update('tests/fixtures/bench_target/bench_answer_key.py')
"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_evaluator.py -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_scenarios.py tests/fixtures/bench_target/bench_answer_key.py \
        tests/fixtures/bench_target/bench_scenarios.py.sha256.lock tests/fixtures/bench_target/bench_answer_key.py.sha256.lock \
        tests/test_p2_bench_evaluator.py
git commit -m "feat(p2-bench): add blind scenario index + evaluator-only answer key + integrity locks"
```

---

### Task 9: `bench_evaluator.py` — arm-agnostic scoring

**Files:**
- Create: `tests/fixtures/bench_target/bench_evaluator.py`
- Test: `tests/test_p2_bench_evaluator.py`

**Interfaces:**
- Produces: `ObservedFinding(NamedTuple)` (`location: str, confirmed: bool, tool: str = "", evidence: dict | None = None`, plus an `.evidence_or_empty()` helper -- NOT a bare `dict = {}` default, which is a real NamedTuple mutable-default aliasing bug, see Task 9's own code block), `BenchReport(dataclass, frozen)` (`coverage: float, yield_: int, false_positives: int, novel_findings: int, cost: dict, per_case: dict`), `evaluate(observed: list[ObservedFinding], mode: str, cost: dict | None = None) -> BenchReport`, `reproducibility(reports: list[BenchReport]) -> tuple[bool, str]`
- Consumes: `bench_scenarios.SCENARIOS` (for path matching), `bench_answer_key.EXPECTED_BY_MODE` (for expected confirmed-by-mode)

- [ ] **Step 1: Write the failing test**

```python
from bench_evaluator import ObservedFinding, evaluate, reproducibility


def test_evaluate_scores_a_correct_confirmation_as_coverage_and_yield():
    observed = [ObservedFinding(location="/bench/products", confirmed=True, tool="sqlmap")]
    report = evaluate(observed, mode="vulnerable")
    assert report.yield_ == 1
    assert report.coverage == 1 / 6
    assert report.false_positives == 0
    assert report.novel_findings == 0


def test_evaluate_counts_a_patched_mode_confirmation_as_a_false_positive():
    observed = [ObservedFinding(location="/bench/products", confirmed=True, tool="sqlmap")]
    report = evaluate(observed, mode="patched")
    assert report.false_positives == 1
    assert report.yield_ == 0


def test_evaluate_buckets_an_unmatched_confirmation_as_novel_never_as_a_false_positive():
    observed = [ObservedFinding(location="/bench/totally-unplanted-endpoint", confirmed=True, tool="curl")]
    report = evaluate(observed, mode="vulnerable")
    assert report.novel_findings == 1
    assert report.false_positives == 0
    assert report.coverage == 0.0


def test_evaluate_ignores_query_string_when_matching_path():
    observed = [ObservedFinding(location="/bench/products?id=99", confirmed=True, tool="sqlmap")]
    report = evaluate(observed, mode="vulnerable")
    assert report.yield_ == 1


def test_evaluate_matches_a_parameterized_idor_path_to_its_general_route():
    """Regression for a pre-flight-scan finding: bench_scenarios' case_idor
    endpoint is the general route "/bench/orders" (no id) -- a real
    observed IDOR finding's location carries the specific object id (e.g.
    "/bench/orders/42"), which must still match case_idor, not be bucketed
    as a novel finding."""
    observed = [ObservedFinding(location="/bench/orders/42", confirmed=True, tool="idor-mcp")]
    report = evaluate(observed, mode="vulnerable")
    assert report.yield_ == 1
    assert report.novel_findings == 0


def test_reproducibility_true_across_identical_reports():
    observed = [ObservedFinding(location="/bench/products", confirmed=True, tool="sqlmap")]
    r1 = evaluate(observed, mode="vulnerable")
    r2 = evaluate(observed, mode="vulnerable")
    ok, msg = reproducibility([r1, r2])
    assert ok, msg


def test_reproducibility_false_across_differing_reports():
    r1 = evaluate([ObservedFinding(location="/bench/products", confirmed=True)], mode="vulnerable")
    r2 = evaluate([], mode="vulnerable")
    ok, msg = reproducibility([r1, r2])
    assert not ok
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_evaluator.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'bench_evaluator'`

- [ ] **Step 3: Write the implementation**

```python
# tests/fixtures/bench_target/bench_evaluator.py
"""Arm-agnostic scoring (TEST-ONLY). Consumes a normalized
list[ObservedFinding] -- any arm (HuntMCP's real pipeline today, a future
frontier-only baseline) just needs to produce this shape; this function
never changes for a new arm. See
docs/superpowers/specs/2026-09-17-p2-bench-design.md sections 6-7.

Matching is by PATH ONLY (query string ignored) against bench_scenarios's
endpoints -- never by anything an arm was told in advance, since nothing
is told in advance (a real hunt only ever sees the target's base URL).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlsplit

import bench_answer_key as AK
import bench_scenarios as SC


class ObservedFinding(NamedTuple):
    """`evidence` defaults to None, not {} -- a NamedTuple field default is
    evaluated once at class-definition time and shared by every instance
    that omits the field (the same class of bug as a mutable default
    argument on a function, and NamedTuple's own immutability does NOT
    protect against in-place mutation of that shared default). Found in
    task review (empirically confirmed): omitting `evidence` on two
    separate ObservedFinding instances made them share ONE dict object,
    so mutating one's `.evidence` in place silently corrupted the other's
    too, for the lifetime of the process. `evaluate()` itself never reads
    `.evidence` today, but this is the shared interface every future arm-
    adapter reports through -- the fix must land before anything starts
    populating it."""
    location: str
    confirmed: bool
    tool: str = ""
    evidence: dict | None = None

    def evidence_or_empty(self) -> dict:
        return self.evidence if self.evidence is not None else {}


@dataclass(frozen=True)
class BenchReport:
    coverage: float
    yield_: int
    false_positives: int
    novel_findings: int
    cost: dict = field(default_factory=dict)
    per_case: dict = field(default_factory=dict)


def _path_of(location: str) -> str:
    return urlsplit(location).path or location


def _case_id_for_path(path: str) -> str | None:
    """Exact match for a flat route (e.g. /bench/products), OR a
    path-prefix match for a parameterized route (e.g. bench_scenarios'
    case_idor endpoint "/bench/orders" must match a real observed
    location like "/bench/orders/42" -- the scenario entry names the
    general route, not one specific instance)."""
    for case_id, spec in SC.SCENARIOS.items():
        endpoint = spec["endpoint"]
        if path == endpoint or path.startswith(endpoint + "/"):
            return case_id
    return None


def evaluate(observed: list[ObservedFinding], mode: str, cost: dict | None = None) -> BenchReport:
    total_cases = len(SC.SCENARIOS)
    yield_ = 0
    false_positives = 0
    novel_findings = 0
    per_case: dict = {}
    correctly_confirmed: set[str] = set()

    for finding in observed:
        if not finding.confirmed:
            continue
        case_id = _case_id_for_path(_path_of(finding.location))
        if case_id is None:
            novel_findings += 1
            continue
        expected = AK.EXPECTED_BY_MODE[case_id][mode]["confirmed"]
        if expected:
            yield_ += 1
            correctly_confirmed.add(case_id)
        else:
            false_positives += 1
        per_case[case_id] = {"expected_confirmed": expected, "reported_confirmed": True, "tool": finding.tool}

    coverage = len(correctly_confirmed) / total_cases if total_cases else 0.0
    return BenchReport(
        coverage=coverage, yield_=yield_, false_positives=false_positives,
        novel_findings=novel_findings, cost=dict(cost or {}), per_case=per_case,
    )


def reproducibility(reports: list[BenchReport]) -> tuple[bool, str]:
    if not reports:
        return False, "no reports"
    first = (round(reports[0].coverage, 6), reports[0].yield_, reports[0].false_positives, reports[0].novel_findings)
    for r in reports[1:]:
        if (round(r.coverage, 6), r.yield_, r.false_positives, r.novel_findings) != first:
            return False, "non-reproducible across runs"
    return True, f"reproducible across {len(reports)} runs"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_evaluator.py -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_evaluator.py tests/test_p2_bench_evaluator.py
git commit -m "feat(p2-bench): add arm-agnostic bench_evaluator (ObservedFinding -> BenchReport)"
```

---

### Task 10: Evidence-trail cross-check (IDOR + SQLi) and coexistence-with-CEM regression

**Files:**
- Modify: `tests/fixtures/bench_target/bench_evaluator.py` (add `verify_evidence_trail`)
- Test: `tests/test_p2_bench_evaluator.py`

**Interfaces:**
- Produces: `verify_evidence_trail(request_log: list[dict], case_id: str, evidence: dict) -> tuple[bool, str]`

- [ ] **Step 1: Write the failing test**

```python
def test_verify_evidence_trail_confirms_two_differing_idor_requests():
    from bench_evaluator import verify_evidence_trail
    request_log = [
        {"path": "/bench/orders/42", "cookie": "session=owner-session"},
        {"path": "/bench/orders/42", "cookie": "session=attacker-session"},
    ]
    ok, msg = verify_evidence_trail(request_log, "case_idor", {"baseline": 0, "perturbed": 1})
    assert ok, msg


def test_verify_evidence_trail_rejects_identical_baseline_and_perturbed():
    from bench_evaluator import verify_evidence_trail
    request_log = [
        {"path": "/bench/orders/42", "cookie": "session=owner-session"},
        {"path": "/bench/orders/42", "cookie": "session=owner-session"},
    ]
    ok, msg = verify_evidence_trail(request_log, "case_idor", {"baseline": 0, "perturbed": 1})
    assert not ok


def test_bench_and_cem_fixtures_coexist_in_one_pytest_session():
    """Regression for the module-cache collision risk named in the spec:
    both fixture packages' identically-shaped-but-differently-named
    modules must not cross-contaminate."""
    import bench_scenarios
    import scenarios as cem_scenarios  # tests/fixtures/cem_target's own bare-named module

    assert "case_sqli" in bench_scenarios.SCENARIOS
    assert "case_sqli" not in cem_scenarios.SCENARIOS
    assert "case_01" in cem_scenarios.SCENARIOS
    assert "case_01" not in bench_scenarios.SCENARIOS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_evaluator.py -v`
Expected: FAIL — `verify_evidence_trail` doesn't exist yet; the coexistence test needs `tests/fixtures/cem_target` on `sys.path` too (see step 3)

- [ ] **Step 3: Write the implementation**

Add to `bench_evaluator.py`:

```python
def verify_evidence_trail(request_log: list[dict], case_id: str, evidence: dict) -> tuple[bool, str]:
    """B1-style cross-check (mirrors cem_target/evaluator.py's
    verify_evidence_trail): confirm a claimed finding is backed by two
    REAL requests that actually differ in the field that matters for this
    case, per the target's own independent request log -- not a tool's
    own narrative."""
    if "baseline" not in evidence or "perturbed" not in evidence:
        return False, f"no evidence refs for {case_id!r}"
    try:
        base = request_log[evidence["baseline"]]
        pert = request_log[evidence["perturbed"]]
    except (IndexError, KeyError):
        return False, "evidence refs point outside the recorded request log"
    key = "cookie" if case_id == "case_idor" else "path"
    if base.get(key) == pert.get(key):
        return False, f"baseline and perturbed requests do NOT differ ({key!r}) -- unbacked claim"
    return True, f"evidence trail OK for {case_id!r}: {base.get(key)!r} vs {pert.get(key)!r}"
```

Add this `sys.path` line near the top of `tests/test_p2_bench_evaluator.py` (alongside the existing
`bench_target` insertion) so the coexistence test can import `cem_target`'s own `scenarios` module too:

```python
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures", "cem_target"))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_evaluator.py -v`
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_evaluator.py tests/test_p2_bench_evaluator.py
git commit -m "feat(p2-bench): add evidence-trail cross-check + CEM-coexistence regression"
```

---

### Task 11: `bench_harness.py` — loopback-only auxiliary HTTP client

**Files:**
- Create: `tests/fixtures/bench_target/bench_harness.py`
- Test: `tests/test_p2_bench_fixture.py`

**Interfaces:**
- Produces: `http_get(url, headers=None, timeout=5.0) -> tuple[int, str]`, `class ExternalTargetRefused(Exception)`

- [ ] **Step 1: Write the failing test**

```python
def test_harness_refuses_a_non_loopback_url():
    from bench_harness import ExternalTargetRefused, http_get
    with pytest.raises(ExternalTargetRefused):
        http_get("https://example.com")


def test_harness_reaches_the_real_loopback_target(vulnerable_app):
    from bench_harness import http_get
    status, body = http_get(f"{vulnerable_app.base_url}/bench/decoy")
    assert status == 200
    assert "nothing interesting" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k harness -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'bench_harness'`

- [ ] **Step 3: Write the implementation**

Copy `tests/fixtures/cem_target/harness.py`'s structure verbatim into `tests/fixtures/bench_target/bench_harness.py`,
renaming the module-level docstring reference and dropping its `CemBenchmarkServer` re-export line (this
fixture's app is imported directly as `BenchApp` where needed, not re-exported through the harness):

```python
# tests/fixtures/bench_target/bench_harness.py
"""Loopback-only HTTP client for this fixture's own auxiliary checks
(TEST FIXTURE ONLY). Real MCP tool invocations (sqlmap/dalfox/ffuf/
nuclei/curl) use their own network paths in tests/test_p2_bench_fixture.py --
this is only for the evaluator/test file's own sanity pings."""
from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class ExternalTargetRefused(Exception):
    """Raised if a call here is aimed at a non-loopback host."""


def _assert_loopback(url: str) -> None:
    host = urlparse(url).hostname or ""
    if host not in _LOOPBACK_HOSTS:
        raise ExternalTargetRefused(
            f"bench harness refuses non-loopback host {host!r} -- this fixture only "
            "ever talks to 127.0.0.1 by construction"
        )


def http_get(url: str, headers: dict[str, str] | None = None, timeout: float = 5.0) -> tuple[int, str]:
    _assert_loopback(url)
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k harness -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/bench_target/bench_harness.py tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): add loopback-only bench_harness for auxiliary checks"
```

---

### Task 12: Real-tool fixture proof — SQL injection (sqlmap-mcp)

**Files:**
- Test: `tests/test_p2_bench_fixture.py`

**Interfaces:**
- Consumes: `mcp-servers/sqlmap-mcp/server.py`'s `test_injection(url, ...) -> str` and `check_scan(job_id) -> str` (loaded via `importlib.util.spec_from_file_location`, exactly as `test_cem_benchmark.py` already does for `case-mcp/server.py`)

**Fixture note (2026-09-22, applies to Tasks 12-17):** these tests use `sandboxed_vulnerable_app`/`sandboxed_patched_app` (container-based, `bench_sandboxed_app.SandboxedBenchApp`), not the plan's originally-drafted `vulnerable_app`/`patched_app` (host-thread, loopback-only) -- see this file's own 2026-09-22 networking-seam decision note above for why. Otherwise the code below is unchanged from the original design.

**Real bug found and fixed while implementing this task (2026-09-22, refined 2026-09-23 via adversarial review):** `test_injection()` unconditionally appended `--forms` to every sqlmap invocation. Direct reproduction confirmed this sqlmap version (1.8.4) treats `-u <url-with-params> --forms` (no `--crawl`) as a FORMS-ONLY scan: against a page with no HTML `<form>` (bench_app's `/bench/products?id=` -- and the common case for any API/query-string-driven endpoint), sqlmap prints `[CRITICAL] there were no forms found at the given target URL` and exits WITHOUT testing the URL's own parameter at all -- a silent false negative that would have affected every real hunt using this tool against a formless page, not just this benchmark. The first fix simply removed `--forms`, which correctly restored URL-parameter testing but was caught in adversarial review as ALSO silently losing the documented "auto-detects and tests any HTML forms on the page" capability for pages that do have one, with no replacement. The refined fix instead adds `--crawl=1` alongside `--forms`: `--crawl=1` makes sqlmap treat `url` as a genuine crawl target (tested directly, exactly as bare `-u` would), while `--forms` still auto-tests any co-located form found during that crawl -- confirmed by direct reproduction against both a vulnerable and a patched target (with `--flush-session` to rule out cached-result false positives) that this combination detects the URL-parameter injection at the plan's originally-specified `level=1, risk=1` without the abort, and produces no false positive in patched mode. Regression test: `tests/test_sqlmap_mcp.py::test_injection_pairs_forms_with_crawl_so_it_never_aborts_on_a_formless_page`.

- [ ] **Step 1: Write the failing test**

```python
import importlib.util
import re
import shutil
import time

requires_sqlmap = pytest.mark.skipif(shutil.which("sqlmap") is None, reason="sqlmap not installed")


def _load_mcp_server(dashed_dir: str, module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name, os.path.join(ROOT, "mcp-servers", dashed_dir, "server.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _poll_mcp_tool(check_scan_fn, start_result: str, timeout_s: int = 120) -> str:
    m = re.search(r'job_id="([^"]+)"', start_result)
    assert m, f"could not find job_id in: {start_result!r}"
    job_id = m.group(1)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        result = check_scan_fn(job_id)
        if "still running" not in result.lower():
            return result
        time.sleep(2)
    raise AssertionError(f"job {job_id} did not finish within {timeout_s}s")


@requires_sqlmap
def test_real_sqlmap_confirms_sqli_in_vulnerable_mode(vulnerable_app, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("HUNTMCP_SQLMAP_TMP", str(tmp_path / "sqlmap-tmp"))
    sqlmap_mcp = _load_mcp_server("sqlmap-mcp", "sqlmap_mcp_p2bench")
    started = sqlmap_mcp.test_injection(f"{vulnerable_app.base_url}/bench/products?id=1", level=1, risk=1, timeout=90)
    result = _poll_mcp_tool(sqlmap_mcp.check_scan, started, timeout_s=90)
    assert "identified" in result.lower() or "injection point" in result.lower(), result


@requires_sqlmap
def test_real_sqlmap_finds_nothing_in_patched_mode(patched_app, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("HUNTMCP_SQLMAP_TMP", str(tmp_path / "sqlmap-tmp"))
    sqlmap_mcp = _load_mcp_server("sqlmap-mcp", "sqlmap_mcp_p2bench_patched")
    started = sqlmap_mcp.test_injection(f"{patched_app.base_url}/bench/products?id=1", level=1, risk=1, timeout=90)
    result = _poll_mcp_tool(sqlmap_mcp.check_scan, started, timeout_s=90)
    assert "no injection found" in result.lower(), result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_sqlmap -v`
Expected: FAIL if sqlmap is installed (helpers/imports not wired) or SKIPPED if it isn't — either is acceptable evidence the test exists; if sqlmap IS installed, expect a real failure/error at this stage since nothing's broken yet in the app, so this should actually be close to passing already given Task 2 built a real SQLi — treat any non-skip failure here as a real signal to fix in step 3, not an error to ignore.

- [ ] **Step 3: Verify/adjust the implementation**

This task adds no new `bench_app.py`/`bench_evaluator.py` code — Task 2 already built the real SQLi bug. If sqlmap
doesn't detect it with `level=1, risk=1` against the `id=` GET parameter, raise `level=2` (still fast) in both
calls above until it reliably confirms — SQLite's error messages differ from MySQL/Postgres, so verify sqlmap's
generic boolean-blind technique (not error-based) is what actually fires; boolean-blind works against any backend
since it only needs the response to differ between a true and false condition, which this app's row-count-driven
output naturally provides.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_sqlmap -v`
Expected: 2 passed (or 2 skipped if sqlmap isn't installed in this environment)

- [ ] **Step 5: Commit**

```bash
git add tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): real sqlmap-mcp fixture proof for the SQLi case"
```

---

### Task 13: Real-tool fixture proof — reflected XSS (dalfox-mcp)

**Files:**
- Test: `tests/test_p2_bench_fixture.py`

**Fixture note:** uses `sandboxed_vulnerable_app`/`sandboxed_patched_app`, see Task 12's 2026-09-22 fixture note above.

**Real bug found and fixed while implementing this task (2026-09-22):** `scan_url()`/`scan_parameter()` both passed `--format json` to dalfox. Direct reproduction confirmed dalfox's `json` format is a pretty-printed JSON ARRAY across multiple lines ("[", "{...},", "{}]"), not one-JSON-object-per-line -- `_format_findings()`'s line-by-line `json.loads()` parser therefore failed to parse EVERY line and always reported "No XSS found," even when dalfox found and verified a real XSS. dalfox has a distinct `--format jsonl` that produces true one-object-per-line output; switching to it fixed detection. This wasn't caught by `tests/test_dalfox_mcp.py`'s existing unit tests because their own mocked `stdout` fixture was already JSONL-shaped, never exercising the real CLI flag. Regression test added: `tests/test_dalfox_mcp.py::test_scan_url_and_scan_parameter_request_jsonl_not_pretty_json`.

- [ ] **Step 1: Write the failing test**

```python
requires_dalfox = pytest.mark.skipif(shutil.which("dalfox") is None, reason="dalfox not installed")


@requires_dalfox
def test_real_dalfox_confirms_xss_in_vulnerable_mode(vulnerable_app, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    dalfox_mcp = _load_mcp_server("dalfox-mcp", "dalfox_mcp_p2bench")
    started = dalfox_mcp.scan_url(f"{vulnerable_app.base_url}/bench/search?q=test", timeout=60)
    result = _poll_mcp_tool(dalfox_mcp.check_scan, started, timeout_s=60)
    assert "xss" in result.lower() and "no xss" not in result.lower(), result


@requires_dalfox
def test_real_dalfox_finds_nothing_in_patched_mode(patched_app, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    dalfox_mcp = _load_mcp_server("dalfox-mcp", "dalfox_mcp_p2bench_patched")
    started = dalfox_mcp.scan_url(f"{patched_app.base_url}/bench/search?q=test", timeout=60)
    result = _poll_mcp_tool(dalfox_mcp.check_scan, started, timeout_s=60)
    assert "no xss" in result.lower(), result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_dalfox -v`
Expected: SKIPPED if dalfox isn't installed, otherwise runs against the already-real XSS bug from Task 3

- [ ] **Step 3: Verify the implementation**

No new fixture code needed (Task 3 already built the real XSS bug). If dalfox's default payload set doesn't fire
against this simple, unescaped reflection, no fixture change is needed — dalfox's baseline reflection-detection
payloads are designed for exactly this shape; if a real run doesn't confirm, check dalfox's own `-b`/blind mode
isn't accidentally required and that `--silence --format json` (already set in `scan_url`) doesn't suppress the
finding lines themselves (it doesn't — it only silences dalfox's own banner/progress noise).

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_dalfox -v`
Expected: 2 passed (or 2 skipped)

- [ ] **Step 5: Commit**

```bash
git add tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): real dalfox-mcp fixture proof for the XSS case"
```

---

### Task 14: Real-tool fixture proof — IDOR (idor-mcp)

**Files:**
- Test: `tests/test_p2_bench_fixture.py`

**Fixture note:** idor-mcp is pure-stdlib `urllib` -- it never routes through `tool_resolver.run_tool()`/`sandbox_runner` (see idor-mcp/server.py's own module docstring), so this task uses the original host-thread `vulnerable_app`/`patched_app` fixtures directly, unlike Tasks 12-13.

**Test-harness gap found and fixed while implementing this task (2026-09-22, not a production bug):** `_load_mcp_server()` loaded each server.py via `importlib.util.spec_from_file_location()`, which does not replicate CPython's own automatic "prepend the running script's directory to sys.path[0]" behavior. sqlmap-mcp/dalfox-mcp only import shared `mcp-servers/` siblings (already handled by their own explicit `sys.path.insert`), so this went unnoticed; idor-mcp/server.py imports `idor_sweep.py`, a SAME-DIRECTORY sibling, and failed with `ModuleNotFoundError` under the helper as originally written. Fixed by having `_load_mcp_server()` also insert the target server's own directory onto `sys.path` before exec'ing it -- restores parity with real `python3 server.py` execution; idor-mcp's own production code was never at fault.

- [ ] **Step 1: Write the failing test**

```python
def test_real_idor_mcp_confirms_leak_in_vulnerable_mode(vulnerable_app, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    idor_mcp = _load_mcp_server("idor-mcp", "idor_mcp_p2bench")
    result = idor_mcp.sweep_idor(
        url=f"{vulnerable_app.base_url}/bench/orders/{{id}}",
        object_ids=["42"],
        owner_cookie_header="session=owner-session",
        other_cookie_header="session=attacker-session",
    )
    assert "LEAKED" in result, result


def test_real_idor_mcp_reports_protected_in_patched_mode(patched_app, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    idor_mcp = _load_mcp_server("idor-mcp", "idor_mcp_p2bench_patched")
    result = idor_mcp.sweep_idor(
        url=f"{patched_app.base_url}/bench/orders/{{id}}",
        object_ids=["42"],
        owner_cookie_header="session=owner-session",
        other_cookie_header="session=attacker-session",
    )
    assert "PROTECTED" in result, result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_idor -v`
Expected: idor-mcp is pure-stdlib (no external binary), so this either passes immediately (Task 4's real bug
already exists) or fails if `sweep_idor`'s own cookie-header wiring doesn't match this app's cookie format —
diagnose against `idor_sweep.py`'s real request-construction code if so.

- [ ] **Step 3: Verify the implementation**

No new fixture code needed. If `sweep_idor` reports `OWNER_BASELINE_FAILED` instead of `LEAKED`/`PROTECTED`, the
owner request itself isn't succeeding — check `bench_app.py`'s `/bench/orders/<id>` route returns 200 (not 403/404)
for the owner's own cookie in BOTH modes, which Task 4 already covers via
`test_idor_patched_owner_session_still_works`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_idor -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): real idor-mcp fixture proof for the IDOR case"
```

---

### Task 15: Real-tool fixture proof — exposed backup file (ffuf-mcp)

**Files:**
- Test: `tests/test_p2_bench_fixture.py`

**Fixture note:** ffuf-mcp sandboxes via `job_runtime`/`sandbox_runner` (like sqlmap/dalfox), so this uses `sandboxed_vulnerable_app`/`sandboxed_patched_app`. The plan's Step 3 concern (a `tmp_path` wordlist rejected by `_resolve_wordlist`'s approved-root check) was confirmed correct on the first real run -- `knowledge/wordlists/p2bench-backup-filenames.txt` was added as planned. Both tests passed cleanly on the first real run; no bug found in ffuf-mcp itself.

- [ ] **Step 1: Write the failing test**

```python
requires_ffuf = pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf not installed")


@requires_ffuf
def test_real_ffuf_discovers_backup_file_in_vulnerable_mode(vulnerable_app, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    wordlist = tmp_path / "backup-filenames.txt"
    wordlist.write_text("backup.sql.bak\nadmin\nconfig.php\n")
    ffuf_mcp = _load_mcp_server("ffuf-mcp", "ffuf_mcp_p2bench")
    started = ffuf_mcp.fuzz_directory(vulnerable_app.base_url, wordlist=str(wordlist), timeout=60)
    result = _poll_mcp_tool(ffuf_mcp.check_scan, started, timeout_s=60)
    assert "backup.sql.bak" in result, result


@requires_ffuf
def test_real_ffuf_finds_nothing_in_patched_mode(patched_app, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    wordlist = tmp_path / "backup-filenames.txt"
    wordlist.write_text("backup.sql.bak\nadmin\nconfig.php\n")
    ffuf_mcp = _load_mcp_server("ffuf-mcp", "ffuf_mcp_p2bench_patched")
    started = ffuf_mcp.fuzz_directory(patched_app.base_url, wordlist=str(wordlist), timeout=60)
    result = _poll_mcp_tool(ffuf_mcp.check_scan, started, timeout_s=60)
    assert "no directories found" in result.lower(), result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_ffuf -v`
Expected: SKIPPED if ffuf isn't installed; otherwise check `_resolve_wordlist`'s own approved-directory
requirement (see step 3) before assuming a real failure.

- [ ] **Step 3: Verify the implementation**

`ffuf-mcp`'s `_resolve_wordlist()` only accepts wordlists in HuntMCP's own `knowledge/wordlists/` or
`/usr/share/wordlists/` by default, or an already-existing absolute path passed straight through — check
`mcp-servers/ffuf-mcp/server.py`'s `_resolve_wordlist` implementation directly if `wordlist=str(wordlist)` (a
`tmp_path` absolute path) is rejected as `WordlistNotApproved`; if so, write the test wordlist under
`knowledge/wordlists/p2bench-backup-filenames.txt` instead (a small, committed file) rather than `tmp_path`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_ffuf -v`
Expected: 2 passed (or 2 skipped)

- [ ] **Step 5: Commit**

```bash
git add tests/test_p2_bench_fixture.py knowledge/wordlists/p2bench-backup-filenames.txt 2>/dev/null || true
git commit -m "feat(p2-bench): real ffuf-mcp fixture proof for the exposed-backup-file case"
```

---

### Task 16: Real-tool fixture proof — misconfiguration (nuclei-mcp, custom template)

**Files:**
- Test: `tests/test_p2_bench_fixture.py`

**PREREQUISITE — check before implementing this task for real (code review, 2026-09-18, deferred not fixed):**
`bench_misconfig_template` (below) copies its fixture template into `data/nuclei-templates/_bench-fixtures/`, which is `templates_pin.TEMPLATES_DIR` — the SAME directory `.github/workflows/ci.yml`'s `unit-tests` job now caches across CI runs (`actions/cache@v4`, keyed on `templates_pin.py`'s content). The fixture's `try/finally` cleans this up on a normal test failure, but a `finally` block cannot run if the CI runner itself is killed mid-test (timeout, OOM-kill, cancellation) — no code-level fix closes that gap, since Python can't intercept SIGKILL. If that happens, the leftover `_bench-fixtures/` file would be cached and restored on a LATER, unrelated CI run, and could fail `tests/test_nuclei_mcp.py`'s `test_live_real_scan_does_not_modify_pinned_templates_host_state` (which asserts `git status --porcelain` on `TEMPLATES_DIR` is clean) with a confusing, misattributed diff. Before actually implementing Task 16, decide on a mitigation -- e.g. have `scripts/fetch-nuclei-templates.sh` hard-reset (`git clean -fdx` / `git reset --hard`) to the pinned SHA on every run rather than only on a SHA mismatch, or have the CI cache step explicitly exclude `_bench-fixtures/`, or verify a clean git state as a CI step before trusting a cache hit. Not fixed now because Task 16 itself isn't implemented yet (this file is still a plan, not shipped code) -- no benchmark or CI redesign should happen around a hypothetical SIGKILL case before the code it protects even exists.

**Implementation note (2026-09-22):** used `sandboxed_vulnerable_app`/`sandboxed_patched_app`. Both tests passed on the first real run; verified empirically that `data/nuclei-templates/_bench-fixtures/` and `git status --porcelain` in that directory are clean after the fixture's teardown -- confirming the PREREQUISITE note above is a real-but-narrow SIGKILL-only gap, not an issue in normal test execution. No bug found in nuclei-mcp itself.

- [ ] **Step 1: Write the failing test**

**S5-follow-up note (2026-09-18):** `nuclei-mcp`'s `scan_with_templates()` now validates that its `templates` argument resolves *inside* the pinned, sandbox-mounted template root (`templates_pin.TEMPLATES_DIR`, see `mcp-servers/nuclei-mcp/server.py`'s `_resolve_templates_arg()`) — a path outside that root, such as this fixture's original location under `tests/fixtures/bench_target/templates/`, is correctly rejected with `ValueError`/an `"Error: ..."` string, not silently misused. This is intentional hardening (an adversarial-review fix, not a bug to route around), so the fixture template must be placed *inside* the approved root before the scan runs — exactly what a real custom-template user has to do under this contract. The `bench_misconfig_template` fixture below copies it there for the duration of the test and cleans up after.

```python
requires_nuclei = pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei not installed")

_SOURCE_TEMPLATE = os.path.join(ROOT, "tests", "fixtures", "bench_target", "templates", "misconfig-banner.yaml")


@pytest.fixture
def bench_misconfig_template():
    """Copies the fixture template into templates_pin.TEMPLATES_DIR (the
    pinned, sandbox-mounted nuclei-templates root) under a leading-
    underscore subfolder reserved for bench-local content -- distinct from
    the pinned upstream categories (http/, dns/, ...) so it can never
    collide with a real one -- then yields the RELATIVE path to pass as
    scan_with_templates()'s `templates=` argument. Skips if the pinned
    snapshot hasn't been fetched (scripts/fetch-nuclei-templates.sh) --
    same precondition scan_with_templates() itself enforces via
    templates_pin.templates_available()."""
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers", "nuclei-mcp"))
    import templates_pin
    if not templates_pin.templates_available():
        pytest.skip("nuclei-templates snapshot not fetched -- run scripts/fetch-nuclei-templates.sh")
    dest_dir = os.path.join(templates_pin.TEMPLATES_DIR, "_bench-fixtures")
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, "misconfig-banner.yaml")
    try:
        # copyfile (not just the yield) is inside the try -- if it fails
        # partway (disk full, permission error, source missing), dest_dir
        # was already created by makedirs() above and must still be
        # cleaned up in the finally below, same as a failure during the
        # test itself. (code review, 2026-09-18: an earlier version of
        # this fixture ran copyfile BEFORE the try, so a copy failure
        # left dest_dir orphaned inside the pinned template root with no
        # cleanup at all.)
        shutil.copyfile(_SOURCE_TEMPLATE, dest_path)
        yield "_bench-fixtures/misconfig-banner.yaml"
    finally:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        try:
            os.rmdir(dest_dir)  # only succeeds if now empty; never raises if not
        except OSError:
            pass


@requires_nuclei
def test_real_nuclei_confirms_misconfig_in_vulnerable_mode(vulnerable_app, bench_misconfig_template, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    nuclei_mcp = _load_mcp_server("nuclei-mcp", "nuclei_mcp_p2bench")
    started = nuclei_mcp.scan_with_templates(vulnerable_app.base_url, bench_misconfig_template, timeout=60)
    result = _poll_mcp_tool(nuclei_mcp.check_scan, started, timeout_s=60)
    assert "bench-debug-panel-exposed" in result.lower(), result


@requires_nuclei
def test_real_nuclei_finds_nothing_in_patched_mode(patched_app, bench_misconfig_template, tmp_path, monkeypatch):
    monkeypatch.setenv("HUNTMCP_BUDGET_PATH", str(tmp_path / "budget.json"))
    monkeypatch.setenv("HUNTMCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    nuclei_mcp = _load_mcp_server("nuclei-mcp", "nuclei_mcp_p2bench_patched")
    started = nuclei_mcp.scan_with_templates(patched_app.base_url, bench_misconfig_template, timeout=60)
    result = _poll_mcp_tool(nuclei_mcp.check_scan, started, timeout_s=60)
    assert "no vulnerabilities found" in result.lower(), result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_nuclei -v`
Expected: SKIPPED if nuclei isn't installed or the templates snapshot isn't fetched; otherwise runs against Task 6's real header

- [ ] **Step 3: Verify the implementation**

No new fixture code needed — Task 6 already built the header and the template. If nuclei reports a template
syntax/validation error, run `nuclei -validate -t <template path>` locally to fix the YAML before re-running the
test (a real, standard nuclei workflow, not something to work around in test code).

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_nuclei -v`
Expected: 2 passed (or 2 skipped)

- [ ] **Step 5: Commit**

```bash
git add tests/test_p2_bench_fixture.py
git commit -m "feat(p2-bench): real nuclei-mcp fixture proof for the misconfiguration case"
```

---

### Task 17: Real-tool fixture proof — open redirect (curl via `tool_resolver`) + full regression + tracker update

**Files:**
- Test: `tests/test_p2_bench_fixture.py`
- Modify: `IMPLEMENTATION-TASK-TRACKER.md` (P2-BENCH row)

**Interfaces:**
- Consumes: `tool_resolver.run_tool(name, args) -> subprocess.CompletedProcess` (already-existing production code, called read-only, never modified)

- [ ] **Step 1: Write the failing test**

```python
def test_real_curl_confirms_open_redirect_in_vulnerable_mode(vulnerable_app, tmp_path, monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import tool_resolver
    monkeypatch.setattr(tool_resolver, "_enforce_budget", lambda name: None)
    result = tool_resolver.run_tool(
        "curl", ["-s", "-o", "/dev/null", "-D", "-",
                 f"{vulnerable_app.base_url}/bench/login?next=https://attacker.example/steal"],
    )
    assert "location: https://attacker.example/steal" in result.stdout.lower()


def test_real_curl_shows_same_origin_redirect_in_patched_mode(patched_app, tmp_path, monkeypatch):
    sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
    import tool_resolver
    monkeypatch.setattr(tool_resolver, "_enforce_budget", lambda name: None)
    result = tool_resolver.run_tool(
        "curl", ["-s", "-o", "/dev/null", "-D", "-",
                 f"{patched_app.base_url}/bench/login?next=https://attacker.example/steal"],
    )
    assert "location: https://attacker.example/steal" not in result.stdout.lower()
    assert "location: /bench/home" in result.stdout.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_curl -v`
Expected: passes immediately if curl is installed (it always is in this repo's own dev environment; Task 7 already
built the real redirect) — if `tool_resolver.run_tool`'s own S5 sandboxing path requires podman and it isn't
available, this will raise `FileNotFoundError`; if so, mark both tests with the same
`requires_sandbox_image`-style skip condition already used in `tests/test_sandbox_runner.py` (import and reuse
that same skip predicate rather than redefining it).

- [ ] **Step 3: Verify the implementation**

No new fixture code needed. If sandboxed curl can't reach `127.0.0.1` (container network isolation from the host
loopback), fall back to calling `subprocess.run(["curl", ...])` directly for JUST this test (documented as a
known, narrow exception: verifying a loopback-only test fixture, not a real Tier-2 network call, so sandboxing
isn't the relevant property being tested here) rather than forcing `tool_resolver.run_tool`'s sandboxed path to
somehow reach the host's own loopback server.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_p2_bench_fixture.py -k real_curl -v`
Expected: 2 passed

- [ ] **Step 5: Full regression + tracker update + commit**

Run the complete suite:

```bash
.venv/bin/python -m pytest tests/ -q
```

Expected: all green, no regression in any pre-existing test (in particular `tests/test_cem_benchmark.py` — the
coexistence test from Task 10 already checks this at the unit level, this is the full-suite confirmation).

Update `IMPLEMENTATION-TASK-TRACKER.md`'s `P2-BENCH` row: `[ ]` → `[x]`, following the same evidence-citation depth
as every other completed row in that table (implementation summary, test file names, real-tool verification
results per class, full regression count, explicit confirmation of zero changes under `cem_target`/`case-mcp`).

```bash
git add tests/test_p2_bench_fixture.py IMPLEMENTATION-TASK-TRACKER.md
git commit -m "feat(p2-bench): real curl fixture proof for open-redirect case; mark P2-BENCH complete"
```
