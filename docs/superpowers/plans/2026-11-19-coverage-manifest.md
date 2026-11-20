# Coverage Manifest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A surface × vuln-class coverage manifest + exhaustion gate that refuses to call a surface "exhausted" until every (discovered node × its required vuln-class) cell is evidence-backed-covered or explicitly N/A-with-reason.

**Architecture:** Derive covered-ness from evidence (never a stored flag) by joining the surface-map node inventory with case_store's evidence-backed findings — joined primarily on the node's explicit `findings` link (`attach_finding`), with a normalized-endpoint fallback. A fixed per-kind battery UNION the node's precedent-surfaced classes defines what's required. A hard gate (`is_exhausted()`) reports open cells; N/A requires a stored reason.

**Tech Stack:** Python 3.10+ (3.12 CI), FastMCP, pytest, stdlib only (no new deps).

**Spec:** [docs/superpowers/specs/2026-11-19-coverage-manifest-design.md](../specs/2026-11-19-coverage-manifest-design.md)

## Global Constraints

- Offline, read-only over `surface_map` (local JSON) + `case_store` (read-only `case_export`); no network/scope/budget interaction (same pattern as `coverage_signal.py`).
- "Covered" reuses the evidence-backed bar (≥1 evidence row for the finding) — NEVER a bare finding or a self-written flag (`.claude/rules/benchmarks.md`: no quality reduction).
- Conservative class matching: when unsure whether a finding's `vuln_class` maps to a battery class, do NOT count it covered — a false "open" (re-check) is safe; a false "covered" hides a gap.
- Empty/whitespace N/A reason is rejected (anti-gaming).
- Honest limits stated in-module (repo convention).
- No AI-attribution in commits; commit per concern; branch `fix/wiring-and-testing-159-164`.

## Review Focus

- **Endpoint join normalization** (node label/meta endpoint vs finding endpoint: scheme, host case, default port, trailing slash, query/fragment) → false "open" if mismatched. Pinned in Task 3.
- **vuln_class name mismatch** (battery `xss` vs finding `xss-js-confirmation`/`cross-site-scripting`; `sqli` vs `sql-injection`) → false open/covered. Conservative matcher pinned in Task 2.
- **Covered requires evidence, not a bare finding** (a finding with zero evidence rows must NOT count covered) → pinned in Task 1.
- **Empty N/A reason rejected** → pinned in Task 4.
- **No nodes / no case.db** → manifest is vacuously exhausted (nothing discovered to cover), never a crash → pinned in Task 3.

---

### Task 1: `evidence_backed_findings()` helper in `coverage_signal.py`

**Files:**
- Modify: `mcp-servers/coverage_signal.py`
- Test: `tests/test_coverage_signal.py`

**Interfaces:**
- Produces: `evidence_backed_findings(db_path: str | None = None) -> list[dict]` — one dict per finding that has ≥1 linked evidence row: `{"id": int, "endpoint": str, "vuln_class": str}` (RAW, unredacted — this is for internal joining, not display). Reuses the existing evidence-by-finding linkage from `compute_coverage_matrix`; returns `[]` when no case.db (same `resolve_db_path`+`isfile` guard).

- [ ] **Step 1: Write the failing test** `test_evidence_backed_findings_requires_evidence`: build a case_store (reuse an existing case-test fixture/helper) with finding A (has an evidence row) and finding B (no evidence); assert the result contains A's `(id, endpoint, vuln_class)` and NOT B's.
- [ ] **Step 2: Run** `pytest tests/test_coverage_signal.py::test_evidence_backed_findings_requires_evidence -v` → FAIL (function missing).
- [ ] **Step 3: Implement** `evidence_backed_findings()` — factor the evidence-count-by-finding map already in `compute_coverage_matrix`; emit raw `{id, endpoint, vuln_class}` for findings with count ≥ 1.
- [ ] **Step 4: Run** → PASS; also run the full `tests/test_coverage_signal.py` (don't regress the redaction/no-write invariants).
- [ ] **Step 5: Commit** "feat: coverage_signal.evidence_backed_findings() raw helper for manifest join (#159)".

### Task 2: battery + matchers in new `coverage_manifest.py` (pure functions)

**Files:**
- Create: `mcp-servers/coverage_manifest.py`
- Test: `tests/test_coverage_manifest.py`

**Interfaces:**
- Produces:
  - `BATTERY_BY_KIND: dict[str, set[str]]` — seed: `endpoint`→{xss, sqli, idor, access-control, ssrf, open-redirect, csrf}; `feature`/`flow`→{access-control, business-logic, auth, idor}; `host`→{info-disclosure, security-misconfig, subdomain-takeover}; `tech`→{known-cve}. (Canonical names; the join matcher maps finding classes onto these.)
  - `required_classes(node: dict) -> set[str]` — `BATTERY_BY_KIND.get(node["kind"], set())` UNION classes parsed from `node.get("precedent")` text via `_classes_in_text`.
  - `_classes_in_text(text: str | None) -> set[str]` — scan text for known battery class tokens + aliases.
  - `_normalize_endpoint(s: str) -> str` — lowercase scheme+host, strip default ports (:80/:443), drop trailing slash, drop query+fragment.
  - `_class_matches(finding_class: str, battery_class: str) -> bool` — normalize both (lowercase, unify `-`/`_`/space) then match via an alias map (`sqli`↔`sql-injection`; `xss`↔`cross-site-scripting`/`xss-js-confirmation`; `idor`↔`idor-bola`/`bola`; `ssrf`↔`blind-ssrf-oob`; etc.); conservative — no loose substring that could over-match.

- [ ] **Step 1: Write failing tests**: `test_required_classes_floor_by_kind` (endpoint node w/ no precedent → the endpoint floor set); `test_required_classes_unions_precedent` (precedent text mentioning "prototype pollution" adds that class on top of the floor); `test_normalize_endpoint_equates_trivially_different_forms` (`https://A.com/x/?q=1` and `http://a.com:80/x` normalize equal minus scheme — assert host/path/no-query equal); `test_class_matches_aliases` (`xss-js-confirmation`↔`xss` True; `sql-injection`↔`sqli` True; `csrf`↔`sqli` False).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the constants + four functions.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** "feat: coverage_manifest battery + endpoint/class matchers (#159)".

### Task 3: `compute_manifest()` — the join + gate verdict

**Files:**
- Modify: `mcp-servers/coverage_manifest.py`
- Test: `tests/test_coverage_manifest.py`

**Interfaces:**
- Consumes: Task 1 `evidence_backed_findings`, Task 2 battery/matchers, `surface_map.load_map`.
- Produces: `compute_manifest(db_path: str | None = None, map_path: str | None = None) -> dict` →
  `{"nodes": [{"node_id", "kind", "label", "cells": [{"vuln_class", "state", "reason"?}]}], "open_cells": [{"node_id","vuln_class"}], "counts": {"covered","na","open"}, "exhausted": bool}`.
  Cell `state`: **covered** iff some `evidence_backed_findings` row F has `_class_matches(F.vuln_class, class)` AND (F["id"] in `node["findings"]` OR `_normalize_endpoint(F["endpoint"]) == _node_endpoint(node)`); **na** iff `class` in `node.get("na", {})` (reason non-empty); else **open**. `exhausted` = no open cells across all nodes. `_node_endpoint(node)` = `node["meta"].get("endpoint") or node["label"]`.

- [ ] **Step 1: Write failing tests** (inject a fixture map via `HUNTMCP_SURFACE_MAP_PATH`/`map_path`, and a case.db via the Task-1 fixture): `test_cell_covered_via_attached_finding` (node.findings links an evidence-backed matching finding → covered); `test_cell_covered_via_endpoint_match` (no attach link, but an evidence-backed finding's endpoint normalizes-equal + class matches → covered); `test_cell_open_when_finding_has_no_evidence` (matching finding but zero evidence → open); `test_na_cell_closes_without_evidence` (node marked N/A for a class → na, not open); `test_exhausted_true_when_empty_map` (no nodes → exhausted True, counts all 0); `test_exhausted_false_lists_open_cells`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `compute_manifest` + `_node_endpoint`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** "feat: coverage_manifest.compute_manifest join + exhaustion verdict (#159)".

### Task 4: `surface_map.mark_na` + `na` node field

**Files:**
- Modify: `mcp-servers/surface_map.py`
- Test: `tests/test_surface_map_mcp.py` (or a new `tests/test_surface_map.py` if cleaner — match existing placement)

**Interfaces:**
- Produces: `surface_map.mark_na(node_id: int, vuln_class: str, reason: str, path: str | None = None) -> bool` — stores `{vuln_class: reason}` under the node's `na` dict; raises `ValueError` on empty/whitespace `reason`; returns False for unknown node. New nodes get `na: {}` (absent treated as `{}` by readers, back-compat with existing maps).

- [ ] **Step 1: Write failing tests**: `test_mark_na_stores_reason` (then `get_node` shows `na[class]==reason`); `test_mark_na_rejects_empty_reason` (raises ValueError); `test_mark_na_unknown_node_returns_false`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `mark_na` (reuse `_update`); add `na` to the `add_node` node dict; readers use `n.get("na", {})`.
- [ ] **Step 4: Run** → PASS (+ existing surface-map tests still green — back-compat).
- [ ] **Step 5: Commit** "feat: surface_map.mark_na + na field (coverage N/A escape valve, #159)".

### Task 5: surface-map-mcp tools — `mark_na`, `coverage_status`, `is_exhausted`

**Files:**
- Modify: `mcp-servers/surface-map-mcp/server.py`
- Test: `tests/test_surface_map_mcp.py`

**Interfaces:**
- Consumes: Task 3 `compute_manifest`, Task 4 `surface_map.mark_na`.
- Produces three `@app.tool()`s:
  - `mark_na(node_id: int, vuln_class: str, reason: str) -> str` — wraps `surface_map.mark_na`; returns confirmation or the ValueError text.
  - `coverage_status() -> str` — formats `compute_manifest()`: counts + the open `(node, class)` cells, precedent-bound nodes first.
  - `is_exhausted() -> str` — "EXHAUSTED: every required (node × class) cell is covered or N/A." when `exhausted`, else "NOT EXHAUSTED: <n> open cells:" + the list. (Text, MCP convention; the word NOT/EXHAUSTED is the machine-checkable signal.)

- [ ] **Step 1: Write failing tests** (load the server via importlib like the existing `test_surface_map_mcp.py`; isolate via `HUNTMCP_SURFACE_MAP_PATH`): `test_tool_is_exhausted_true_on_empty_map`; `test_tool_coverage_status_lists_open_cell_after_add_node`; `test_tool_mark_na_then_cell_not_open`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the three tools.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** "feat: surface-map-mcp coverage_status/is_exhausted/mark_na tools (#159)".

### Task 6: huntbrain wiring + drift/scoping green

**Files:**
- Modify: `.claude/agents/huntbrain.md`

**Interfaces:** consumes Task 5 tools (already in surface-map-mcp, which huntbrain does NOT have in its allowlist — recon-agent owns surface-map). Decision to settle in this task: either (a) add surface-map-mcp to huntbrain's tools so it can call `is_exhausted()` directly, or (b) have huntbrain instruct recon/scan to report coverage_status and treat open cells as work. Prefer (a) only if it keeps `test_orchestrator_is_tightly_scoped`'s asserted set correct — that test pins huntbrain to exactly 7 servers, so adding one means updating that test deliberately; (b) avoids widening the orchestrator. Pick (b) unless there's a strong reason, to keep huntbrain tight.

- [ ] **Step 1:** Add a step to huntbrain's Phase 5 / "before declaring a surface exhausted": consult coverage (`is_exhausted()` via the owning agent), treat each open `(node, class)` as remaining work routed to the owning specialist; N/A requires a recorded reason, never a silent skip. State plainly that an open cell = unfinished.
- [ ] **Step 2: Run** `pytest tests/test_agent_tool_scoping.py tests/test_agent_mcp_registry_drift.py -v` → PASS (if (a) was chosen, update `test_orchestrator_is_tightly_scoped` in the same commit with rationale).
- [ ] **Step 3: Commit** "feat: huntbrain consults the coverage gate before declaring a surface exhausted (#159)".

### Task 7: Verify + prove-it-runs + review-and-audit

- [ ] **Step 1:** `pytest tests/test_coverage_manifest.py tests/test_coverage_signal.py tests/test_surface_map_mcp.py -v` → all PASS; then the broader suite.
- [ ] **Step 2: prove-it-runs:** in-session, drive the real flow against a controlled fixture map: `mcp__surface-map-mcp__add_node` an endpoint node → `coverage_status()` shows its classes OPEN → `mark_na` one with a reason → `is_exhausted()` returns NOT EXHAUSTED with the remaining open cells. Capture the real tool output. (Requires the new tools loaded — a session restart, like #160.)
- [ ] **Step 3: review and audit** (`/code-review` + `/security-review`) on the #159 diff; fix findings.

## Self-Review notes

- **Spec coverage:** battery (T2), derived evidence-backed covered (T1+T3), manifest+gate (T3), N/A-with-reason (T4), tools (T5), huntbrain wiring (T6), verify+review (T7). All spec sections mapped.
- **Anti-gaming** lives in T1 (`evidence_backed_findings` requires an evidence row) + T4 (non-empty reason) — the two gameable points, both pinned by tests.
- **Join robustness**: T3 covers both the attach-finding link and the endpoint-normalization fallback, and the two Review-Focus mismatch risks (endpoint, class) each have a pinned test.
- **Back-compat**: `na` is read via `.get("na", {})`, so existing maps and `coverage_signal`/`compute_coverage_matrix` are untouched.
- **Proportion**: plan gives signatures + test names/assertions, not bodies — implementer writes the code.
