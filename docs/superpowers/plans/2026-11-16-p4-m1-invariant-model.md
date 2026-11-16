# P4-M1 Full Invariant Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the P4-M0 invariant prototype into a hunt-usable capability — real captured-request corpus, real-request-mapped CEM hypotheses, two new CEM-provable templates (vertical-privilege, state-gated-parameter), an MCP tool + agent wiring — proven on a blind benchmark at FCC==0.

**Architecture:** A new read-only `invariant_corpus.py` assembles the observed-exchange corpus from already-captured Burp-import endpoints (identity from the auth header, resource from the path, status, real request skeleton) plus optional `case_store` wire-evidence bodies. `invariant_probe.py` gains a per-`(resource, session)` state-transition view and templates T3/T4; every candidate's `cem_spec.base_request` becomes the real captured request and every condition names a header/param actually present in it, so the FROZEN `run_cem_pipeline` can drop it. A read-only `mine_invariants` case-mcp tool stages survivors as `DISCOVERED` findings. The protected long-horizon benchmark gains blind T3/T4 scenarios + secured decoys.

**Tech Stack:** Python 3.12, stdlib only (no new dependency). Existing modules: `invariant_probe`, `authz_diff`, `case_store`, `case-mcp` tools, `burp-import-mcp/db.py`, frozen `cem_engine`/`run_cem_pipeline`. pytest + the `lh_target`/`inv_*` fixture discipline.

**Spec:** `docs/superpowers/specs/2026-11-16-p4-m1-invariant-model-design.md`

## Global Constraints

- **Frozen CEM untouched:** zero lines changed in `mcp-servers/cem_engine.py`, `tests/test_cem_benchmark.py`, `tests/fixtures/cem_target/`, CEM schema. `scripts/verify-phase1.sh` G1–G9 must PASS after every task that could touch shared code.
- **CEM-provability (C1):** every emitted candidate's `cem_spec` must be applicable by the unchanged `case-mcp._perturbation_for`/`_apply` — each condition `name` matches a header (case-insensitive, `Authorization` alias) **or** a query param present in `base_request`; perturbation is exactly `{"drop": true}`; `base_request.method` ∈ {GET, HEAD, OPTIONS}. A candidate whose condition is not so applicable must NOT be emitted.
- **Passive corpus (C2):** `invariant_corpus` issues zero network/subprocess calls and writes nothing; only `run_cem_pipeline` (already gated) touches the target.
- **Status discipline (C3):** mined candidates are `DISCOVERED`; the tool never runs CEM, never advances status.
- **No new dependency.** stdlib + existing project modules only.
- **Protected-benchmark change (C5):** new `lh_target`/`inv_answer_key`/`inv_decoys` scenarios + SHA-256 re-lock are the only benchmark edits, matching the approved spec §8; blindness held (probe never imports the key).
- **No S6-protected-file edit:** the `mine_invariants` tool has no `url` param, so no `scope_gate_hook.py` change. If review concludes otherwise, that edit needs a human-run `scripts/confirm-hook-edit.sh`, called out, never silent.
- **Redaction:** identity labels / bodies pass through existing `redact`/`authz_diff` helpers; raw cookies/auth values never stored.

## Review Focus

- **Corpus with no bodies** (Burp stores none): T1/T2 require a non-empty body / body divergence today — the corpus builder yields `body=""`, so without the body-optional change the probe silently finds nothing on real data. → Task 2 test: body-absent corpus still yields high-recall candidates (status/identity/repetition), confidence capped, `content_relation="unknown"`. (Documented limit: body-absent oracle is status-only.)
- **Non-applicable condition** (a staged condition naming neither a header nor a query param in `base_request`) → `run_counterfactual` raises mid-pipeline. → Task 2 test: every staged candidate's condition is accepted by `_perturbation_for(...)._apply(base_request)` without raising; Task 3/4 repeat for T3/T4.
- **Non-idempotent base_request** (a real captured POST/PUT) slipping into a counterfactual. → Task 1/2 test: corpus rows whose captured method is not GET/HEAD/OPTIONS are excluded from (or down-converted for) CEM candidates, never emitted as a droppable-condition GET hypothesis they didn't issue.
- **Malformed / partial captured data** (missing headers_json, unparseable URL, no auth header). → Task 1 test: each degrades to skipping that row, never raises into the hunt; empty corpus → `[]`.
- **Benchmark blindness/anti-gaming** (a new scenario whose opaque id or shape leaks the answer, or a probe import path to the key). → Task 7 test: integrity locks verify; `inv_answer_key` not importable by `mcp-servers/*`; a candidate on a secured decoy is rejected by CEM (FCC unaffected).

---

### Task 1: Read-only corpus builder (`invariant_corpus.py`)

**Files:**
- Create: `mcp-servers/invariant_corpus.py`
- Test: `tests/test_invariant_corpus.py`

**Interfaces:**
- Consumes: `burp-import-mcp/db.py` `list_endpoints(target, authenticated_only, limit)` / `get_endpoint(id)` row shape `{id, method, url, host, path, status, mimetype, headers_json}`; optionally `case_store` evidence rows for bodies.
- Produces:
  - `build_corpus(target: str, *, burp_rows: list[dict] | None = None, db_path: str | None = None) -> list[dict]` — returns exchange rows `{identity, resource, action, args, status, body, session, base_request}` where `base_request = {method, url, headers, body}` is the real captured request and `headers` retains the identity-bearing header. `burp_rows` injectable for tests; when `None`, reads via the burp db.
  - `identity_label(headers: dict) -> str` — stable, redacted label derived from the Cookie/Authorization header (hash/prefix, never the raw secret); `"anon"` when none.
  - `resource_of(url: str) -> str` — the object-instance path (path only, query stripped).
  - `action_of(method: str) -> str` — `"read"` for GET/HEAD, else a lowercased verb token.

- [ ] **Step 1: Write failing tests** in `tests/test_invariant_corpus.py`:
  - `test_build_corpus_extracts_identity_resource_status_from_burp_rows` — two rows, same path, different auth headers → two exchanges, distinct `identity`, same `resource`, each `base_request.url` == the captured url.
  - `test_identity_label_is_redacted_and_stable` — same auth header → same label; label does not contain the raw token.
  - `test_body_absent_yields_empty_string_not_missing` — burp rows (no body) → every exchange has `body == ""`.
  - `test_non_get_method_row_is_marked_not_cem_eligible` — a POST row → exchange present but flagged (`base_request.method == "POST"`) so Task 2 excludes it from CEM candidates.
  - `test_malformed_row_is_skipped_not_fatal` — a row with bad `headers_json` / unparseable url → skipped; other rows still returned.
  - `test_empty_or_none_source_returns_empty_list`.
- [ ] **Step 2: Run** `pytest tests/test_invariant_corpus.py -v` — expect FAIL (module missing).
- [ ] **Step 3: Implement** the four functions in `mcp-servers/invariant_corpus.py`. Pure/read-only; parse `headers_json` with stdlib `json`; derive identity via existing `redact` helper; strip query via `urllib.parse.urlsplit`. Degrade-to-skip on any per-row exception.
- [ ] **Step 4: Run** the test file — expect PASS.
- [ ] **Step 5: Commit** `feat: P4-M1 read-only captured-request corpus builder`.

---

### Task 2: Real-request mapping + body-optional T1/T2 in `invariant_probe.py`

**Files:**
- Modify: `mcp-servers/invariant_probe.py` (`_mine_ownership`, `_mine_one_time_use`, add a helper; do NOT change `to_cem_hypothesis`'s store path)
- Test: `tests/test_invariant_probe.py` (extend)

**Interfaces:**
- Consumes: Task 1 exchange rows (may carry `base_request`).
- Produces: candidates whose `cem_spec.base_request` is the row's real `base_request` when present (condition `name` = the real identity header name actually in those headers, e.g. `"Authorization"`/`"Cookie"`), and whose behavior is **unchanged** when a row carries no `base_request` (the P4-M0 synthesized `invariant.local` query-param shape, so existing pipeline tests keep passing). New helper `_cem_spec_for(resource, condition_name, category, baseline_value, base_request, success_signature) -> dict`.

- [ ] **Step 1: Write failing tests** (extend `tests/test_invariant_probe.py`):
  - `test_ownership_uses_real_base_request_when_present` — exchanges carry a real `base_request` with an `Authorization` header → candidate `cem_spec.base_request` == that request and `conditions[0]["name"]` == `"Authorization"`.
  - `test_real_request_condition_is_cem_applicable` — import `case-mcp`'s `_perturbation_for`; `_perturbation_for(candidate["cem_spec"]["conditions"][0])._apply(candidate["cem_spec"]["base_request"])` does not raise and actually removes the header.
  - `test_body_absent_still_yields_ownership_candidate_high_recall` — ≥2 identities, 2xx, `body==""` → candidate emitted, `confidence` ≤ medium, `negative_control.content_relation == "unknown"`.
  - `test_body_present_behavior_unchanged` — the existing P4-M0 body-divergent corpus yields the identical candidate as before (regression pin).
  - `test_non_get_captured_request_not_emitted_as_cem_candidate` — a row flagged POST is not turned into a droppable-GET candidate.
- [ ] **Step 2: Run** the new tests — expect FAIL.
- [ ] **Step 3: Implement**: add `_cem_spec_for`; branch in both miners to use the real `base_request` + real header/param condition name when present, else the existing synthesized shape; relax the `body.strip()` requirement to body-optional with `content_relation="unknown"` + capped confidence when all bodies empty; exclude non-idempotent captured methods from CEM candidates.
- [ ] **Step 4: Run** `pytest tests/test_invariant_probe.py -v` — expect PASS (incl. all pre-existing P4-M0 tests).
- [ ] **Step 5: Run** `pytest tests/test_invariant_probe_pipeline.py -v` — expect PASS (regression: synthesized path intact).
- [ ] **Step 6: Commit** `feat: P4-M1 real-request mapping + body-optional invariant templates`.

---

### Task 3: State-transition view + T3 vertical-privilege template

**Files:**
- Modify: `mcp-servers/invariant_probe.py` (add `_sequence_by_object_session`, `_mine_vertical_privilege`; register in `mine_invariants`)
- Test: `tests/test_invariant_probe.py` (extend)

**Interfaces:**
- Produces: `_sequence_by_object_session(exchanges) -> dict[tuple[str,str], list[dict]]` — ordered `(actor, action, status, body_state_class)` per `(resource, session)`; `_mine_vertical_privilege(resource, rows)` → candidate when a privileged action (non-read, or a read of a resource that denies at least one identity) succeeds for a lower-privilege identity with no denial, condition = the identity/role header → `{"drop": true}`. Candidate dict same shape as T1 with `"invariant": "vertical_privilege"`.

- [ ] **Step 1: Write failing tests**:
  - `test_sequence_view_orders_actions_per_object_session` — mixed rows → correct ordered sequences keyed by `(resource, session)`.
  - `test_vertical_privilege_candidate_when_lowpriv_succeeds_where_another_is_denied` — identity A gets 403 on an action, identity B (lower priv) gets 2xx → candidate, condition names the real auth header, `confidence == "high"` (denial seen).
  - `test_vertical_privilege_condition_is_cem_applicable` — `_perturbation_for(...)._apply(base_request)` removes the auth header without raising.
  - `test_no_vertical_privilege_candidate_when_all_denied_or_all_allowed` — no differential → none (precision guard).
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement** the two functions; reuse `_negative_control`; emit via `_cem_spec_for` with the real request.
- [ ] **Step 4: Run** `pytest tests/test_invariant_probe.py -v` — expect PASS.
- [ ] **Step 5: Commit** `feat: P4-M1 state-transition view + vertical-privilege template (T3)`.

---

### Task 4: T4 state-gated-parameter template

**Files:**
- Modify: `mcp-servers/invariant_probe.py` (add `_mine_state_gated_param`; register)
- Test: `tests/test_invariant_probe.py` (extend)

**Interfaces:**
- Produces: `_mine_state_gated_param(resource, rows, sequences) -> list[dict]` — within a `(resource, session)` sequence, when an action succeeds carrying a query param the sequence identifies as the authorization/ownership/nonce gate (param present in the URL, varies by identity/object, and whose absence elsewhere co-occurs with denial), emit a candidate with condition = that **query param name** → `{"drop": true}`, `"invariant": "state_gated_param"`. High recall; CEM is precision.

- [ ] **Step 1: Write failing tests**:
  - `test_state_gated_param_candidate_names_the_gate_query_param` — a sequence where a `token=`/`owner=` param gates success → candidate, `conditions[0]["name"]` == that param, `base_request.url` contains it.
  - `test_state_gated_param_condition_is_cem_applicable` — `_apply` drops the query param (uses `_drop_query_param` path) without raising.
  - `test_no_candidate_when_no_param_distinguishes_gate` — a resource with no identity/object-varying param → none.
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement**; keep the gate heuristic conservative/structural (param present + varies by identity-or-object); no fixed name allow-list required, but a small known-gate-name hint set is acceptable.
- [ ] **Step 4: Run** `pytest tests/test_invariant_probe.py -v` — expect PASS.
- [ ] **Step 5: Commit** `feat: P4-M1 state-gated-parameter template (T4)`.

---

### Task 5: `mine_invariants` read-only case-mcp tool

**Files:**
- Modify: `mcp-servers/case-mcp/server.py` (add `@app.tool() def mine_invariants(...)`)
- Test: `tests/test_case_mcp_mine_invariants.py` (create)

**Interfaces:**
- Consumes: `invariant_corpus.build_corpus`, `invariant_probe.mine_invariants`, existing `invariant_probe.to_cem_hypothesis`.
- Produces: `mine_invariants(target: str = "", limit: int = 100) -> str` — JSON: builds the corpus for the active/declared target, mines candidates, stages each via `to_cem_hypothesis` as a `DISCOVERED` finding, returns `{staged: [{finding_id, hypothesis_id, invariant, resource, confidence, condition_names}], count}`. No `url` param, no network, no CEM run, no status change.

- [ ] **Step 1: Write failing tests**:
  - `test_mine_invariants_stages_discovered_findings_from_corpus` — injected corpus → findings created at `DISCOVERED`, response lists them with `condition_names`.
  - `test_mine_invariants_never_runs_cem_or_advances_status` — no `cem_meta` row created; finding status stays `DISCOVERED` (mirror `test_case_mcp_ingest_schemathesis_falsifiers` assertions).
  - `test_mine_invariants_empty_corpus_is_noop` — `count == 0`, no findings.
  - `test_mine_invariants_has_no_url_param` — introspect the signature (guards the no-hook-edit contract).
- [ ] **Step 2: Run** — expect FAIL.
- [ ] **Step 3: Implement** the tool (isolated temp-db autouse fixture like the pipeline test). Free text through `redact_text`.
- [ ] **Step 4: Run** `pytest tests/test_case_mcp_mine_invariants.py -v` — expect PASS.
- [ ] **Step 5:** Confirm NOT added to `scope_gate_hook.TIER2_MCP_TOOLS` (no url); run `pytest tests/test_cem_scope_gate.py tests/test_scope_gate_hook.py -q` — expect PASS unchanged.
- [ ] **Step 6: Commit** `feat: P4-M1 read-only mine_invariants case-mcp tool`.

---

### Task 6: Exploit-agent wiring

**Files:**
- Modify: `.opencode/agents/exploit-agent.md` and `.claude/agents/exploit-agent.md` (keep both in sync, as prior tasks did)
- Test: `tests/test_agent_tool_scoping.py` (re-verify invariants; add a presence check if that suite has a pattern for it)

**Interfaces:** documentation/agent-instruction only; no code contract.

- [ ] **Step 1:** Add a step (sibling of the P3-CEMHUNT step 3.5) describing: after independent validation, call `mine_invariants`, review staged candidates, and for each that reaches `CONFIRMED` via the normal flow, run the existing gated `run_cem_pipeline`; explicit skip rules (state-changing steps, path-segment/IDOR-only, OOB/browser-proof) mirroring the existing CEM guidance. State candidates are `DISCOVERED` and never auto-confirmed.
- [ ] **Step 2: Run** `pytest tests/test_agent_tool_scoping.py -v` — expect PASS (no new server re-enabled; `case-mcp` already enabled for exploit-agent — verify).
- [ ] **Step 3: Commit** `docs: P4-M1 wire invariant mining into exploit-agent`.

---

### Task 7: Blind benchmark extension (protected — approved §8) + pipeline measurement

**Files:**
- Modify: `tests/fixtures/lh_target/lh_target.py` (new `_h_hotel` T3 violation, `_h_india` T4 violation, `_h_juliet` secured role decoy, `_h_kilo` secured param decoy) and its `.sha256.lock`
- Modify: `tests/fixtures/invariant_target/inv_answer_key.py` (+ 4 opaque entries) and its `.sha256.lock`; optionally `inv_decoys.py` + lock
- Modify: `tests/test_invariant_probe_pipeline.py` (new measurement tests + extend `test_measured_pipeline_go_no_go`); `tests/test_lh_benchmark.py` / `tests/test_invariant_probe.py` integrity assertions if present
- Test: the above pipeline/benchmark files

**Interfaces:** scenarios follow the existing `LhTarget.act` / `Response(status, body, sig)` contract; the pipeline test `_executor` is extended to decode the T3 (role/auth-header) and T4 (gate query-param) base requests back into simulator actions, staying deterministic per call.

- [ ] **Step 1: Write failing tests** (`tests/test_invariant_probe_pipeline.py`):
  - `test_pipeline_confirms_vertical_privilege_hotel` — T3 violation mined → CEM confirms the auth header **necessary**.
  - `test_pipeline_confirms_state_gated_param_india` — T4 violation → CEM confirms the gate param **necessary** (class-less differential value).
  - `test_pipeline_rejects_secured_role_decoy_juliet` and `test_pipeline_rejects_secured_param_decoy_kilo` — candidate emitted (high recall) but CEM returns not-necessary → rejected (FCC unaffected).
  - Extend `test_measured_pipeline_go_no_go` to include the 4 new scenarios: FCCR == 0 over the extended set.
- [ ] **Step 2: Run** — expect FAIL (scenarios/key entries missing).
- [ ] **Step 3: Implement** the 4 simulator handlers (genuinely-planted behaviour, each self-evidently a violation / secured), the 4 `inv_answer_key` entries (opaque ids; `in_family`/`family`/`class_scannable` set honestly), and the `_executor` decode extensions. Do NOT import the answer key from any `mcp-servers/*` path.
- [ ] **Step 4: Re-lock** the integrity files: recompute SHA-256 for every edited protected fixture and write its `.sha256.lock` (record the re-lock in the commit message as human-approved per spec §8/C5).
- [ ] **Step 5: Run** `pytest tests/test_invariant_probe_pipeline.py tests/test_invariant_probe.py tests/test_lh_benchmark.py -v` — expect PASS incl. integrity verify + blindness.
- [ ] **Step 6: Commit** `test: P4-M1 blind T3/T4 benchmark scenarios + FCC==0 measurement (re-locked, approved)`.

---

### Task 8: Integration — frozen-CEM gate, full regression, tracker

**Files:**
- Modify: `IMPLEMENTATION-TASK-TRACKER.md` (§8 record P4-M0 GO 2026-11-16; P4-M1 `[!]` → `[~]`/`[x]` per evidence; §12 summary) — NOT an S6-protected file.

- [ ] **Step 1: Run** `scripts/verify-phase1.sh` — expect G1–G9 PASS (frozen CEM provably untouched). Confirm `git diff --stat` shows zero changes under `cem_engine.py`/`test_cem_benchmark.py`/`tests/fixtures/cem_target/`.
- [ ] **Step 2: Run** the full suite `.venv/bin/python -m pytest tests/ -q` — expect green (document any pre-existing load-dependent flakes per the tracker's precedent, reproduced with the change stashed).
- [ ] **Step 3: Run** `ruff check mcp-servers/ --ignore E402,F811 --target-version py312` and `py_compile` on changed servers — expect clean.
- [ ] **Step 4:** Update the tracker rows with per-task evidence (tests, FCC==0, verify-phase1 PASS). Mark P4-M1 status honestly (`[~]` if agent-adoption/live measurement remains, `[x]` if the acceptance gate is fully met).
- [ ] **Step 5: Commit** `docs: P4-M1 record GO + status + evidence in tracker`.

---

## Self-Review notes
- **Spec coverage:** corpus builder (T1), real-request mapping + body-optional (T2), deeper model T3/T4 (T3/T4), MCP tool (T5), agent wiring (T6), blind benchmark FCC==0 (T7), frozen-CEM gate + tracker (T8). All spec §2 goals mapped.
- **CEM-provability** is pinned by an explicit `_perturbation_for(...)._apply(...)`-does-not-raise test in Tasks 2/3/4 — the single most important correctness property.
- **Backward-compat:** Task 2 keeps the synthesized `invariant.local` path so every P4-M0 test and `test_invariant_probe_pipeline.py` keeps passing; `test_body_present_behavior_unchanged` pins it.
- **Proportion:** plan carries decisions (signatures, condition-naming contract, test names, benchmark scenario roster), not function bodies.
