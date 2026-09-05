# Phase 1 (CEM Vertical Slice) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task under `superpowers:test-driven-development`.
> Tasks use `[ ]/[~]/[x]/[!]` status. **UD-1..UD-4 are RESOLVED (approved 2026-09-04, §2). Do not start
> implementation until the human gives implementation approval (gate G0).**

**Goal:** Build the smallest *scientifically-trustworthy* Counterfactual Evidence Minimization slice: given a
confirmed finding + candidate conditions + a machine-checkable success oracle, experimentally determine
necessary / apparently_not_necessary / inconclusive conditions, detect uncontrolled nondeterminism, and emit a
reproducible Triager-Proof Bundle — with false-causal-conclusion-rate == 0 on a constructed benchmark.

**Architecture:** Extend `case-mcp` with CEM tools backed by a new `cem_engine.py` module (mirroring how
`idor_sweep.py` backs `idor-mcp/server.py`); reuse the existing SQLite case/evidence store, guards, and audit
log; add `case-mcp` to the scope hook's Tier-2 set so target-touching CEM tools are scope-gated. No new MCP
server, no new runtime dependency.

**Tech Stack:** Python 3.12, stdlib (`urllib`, `sqlite3`, `dataclasses`, `http.server`), FastMCP, pytest.

**Spec:** [PHASE1-PLAN.md](PHASE1-PLAN.md) (argues from [XYZ.md](XYZ.md)). Read both alongside this plan.

---

## 1. Repository ground-truth (verified this session)

Confirmed reusable primitives (exact locations):
- `mcp-servers/idor-mcp/idor_sweep.py`: `FetchResult(status, body, error)`; `_fetch(url, method, headers, body, timeout_s)` (handles 401/403/404 as real responses); `_build_headers(cookie_header, bearer_token)`; `DEFAULT_TIMEOUT_S=15`.
- `mcp-servers/case_store.py`: SQLite per-engagement `case.db` via `engagement_paths.resolve`; tables `hypotheses/findings/evidence/experiments/root_causes`; `add_evidence` (content-addressed SHA-256, `EVIDENCE_TYPES={request,response,callback,screenshot,dns,source,metadata}`); `log_experiment`; `create_finding`; `update_finding_status` (evidence-gated CONFIRMED); `score_finding_confidence`; `group_root_cause`.
- `mcp-servers/case-mcp/server.py`: FastMCP wrappers over `case_store` (local-only today; NOT in Tier-2 set).
- `mcp-servers/scope_guard.py`: `load_engagement`, `is_in_scope` (returns True for `is_safe_test_host` incl. loopback/private IPs), `Engagement`.
- `scripts/hooks/scope_gate_hook.py`: `TIER2_MCP_SERVERS` (per-server gate); `HOST_ARG_KEYS=("domains","domain","target","targets","url","host","hosts")`; `if not candidates: return 0` (host-arg-less calls pass); exempts safe/loopback hosts from candidates.
- `mcp-servers/budget_guard.py`: `enforce(tool_name)` raises `BudgetExceeded`; `MAX_CALLS=500` per engagement (`HUNTMCP_MAX_TOOL_CALLS`).
- `mcp-servers/audit_log.py`: `log_call(tool, args, returncode, duration_ms, block, path=None)`; redacts args via `redact.redact_text`.
- Tests: `pytest tests/`; `tests/conftest.py` adds `mcp-servers/` + `scripts/hooks/` to `sys.path`. CI (`.github/workflows/ci.yml`) = ruff (`--ignore E402,F811`) + `py_compile` + `pytest` + content_scanner (advisory). **No Makefile; no top-level test-runner script.**

## 2. Decisions (RESOLVED — approved 2026-09-04)

All four are approved; rulings recorded below. No further design input is required to begin implementation once
the human gives implementation approval (G0).

- **UD-1 — HTTP primitive sharing.** `idor_sweep.py` is under `mcp-servers/idor-mcp/`, but `case-mcp`/`cem_engine`
  import from `mcp-servers/` root. Options:
  - **(A)** cem_engine adds the idor-mcp dir to `sys.path` and imports `idor_sweep._fetch` (couples case-mcp to idor-mcp layout).
  - **(B, recommended)** extract the ~15-line fetch primitive into a new shared `mcp-servers/http_probe.py`; refactor `idor_sweep.py` to import it (behavior-preserving; guarded by existing `tests/test_idor_sweep.py`). DRY, minimal coupling, but touches a working Tier-2 file.
  - **(C)** cem_engine re-implements its own tiny urllib fetch (zero coupling, ~15 lines duplicated — mild DRY violation).
  **RULING (approved 2026-09-04): B** — extract a shared `mcp-servers/http_probe.py`; refactor `idor_sweep.py`
  to import it, preserving behavior with `tests/test_idor_sweep.py` as the regression guard. Fallback C is NOT used.
- **UD-2 — CEM budget accounting.** CEM sends real requests counted against the same per-engagement 500-call
  `budget.json` as hunting. Options: **(A)** share the cap with an internal per-finding CEM request ceiling
  (e.g. `HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING`) so one finding's CEM can't dominate; **(B)** a separate CEM
  sub-budget env. **RULING (approved 2026-09-04): A** — CEM shares the engagement-wide 500-call cap AND enforces a per-finding
  CEM request ceiling so one finding's CEM cannot dominate the shared hunting budget.
- **UD-3 — success_signature source.** D5 requires a machine-checkable oracle as a new Phase-1 input. Confirmed
  no existing schema. Decision: caller supplies it explicitly at `define_conditions` (recommended, explicit) vs
  derived from the baseline response (implicit, more failure-prone). **RULING (approved 2026-09-04): EXPLICIT**
  — the caller supplies `success_signature` at `define_conditions`. **Auto-derivation of the security oracle from
  baseline responses is explicitly disallowed and must NOT be implemented.**
- **UD-4 — non-idempotent perturbations.** Some interventions could be state-changing. Phase-1 policy: refuse
  non-idempotent/non-GET perturbations unless a human explicitly approves per finding (default idempotent/GET).
  **RULING (approved 2026-09-04): REFUSE-BY-DEFAULT** — non-idempotent/state-changing perturbations are refused.
  Any future exception requires explicit per-finding human approval (no blanket override).

## 3. File structure (what gets created / modified)

| Path | New/Mod | Responsibility |
|---|---|---|
| `mcp-servers/cem_engine.py` | NEW | All CEM logic: dataclasses, oracle eval, determinism gate, intervention runner, verdict classifier, minimal-set search (ddmin), PoC minimization, bundle assembly. MCP-free, unit-testable. |
| `mcp-servers/http_probe.py` | NEW (UD-1=B) | Shared urllib fetch primitive (`FetchResult`, `fetch`, `build_headers`), imported by both idor_sweep and cem_engine. |
| `mcp-servers/idor-mcp/idor_sweep.py` | MOD (UD-1=B) | Import fetch primitive from `http_probe` (behavior-preserving; guarded by test_idor_sweep.py). |
| `mcp-servers/case_store.py` | MOD | Add 4 CEM tables to `_init_schema` + CRUD helpers. |
| `mcp-servers/case-mcp/server.py` | MOD | Add 6 CEM `@app.tool()` wrappers; senders enforce budget + audit inline. |
| `scripts/hooks/scope_gate_hook.py` | MOD | Add `"case-mcp"` to `TIER2_MCP_SERVERS`. |
| `.opencode/agents/report-agent.md` | MOD | Document the Counterfactual Evidence Bundle section. |
| `tests/fixtures/cem_target/app.py` | NEW | Constructed ground-truth benchmark HTTP target (localhost). |
| `tests/fixtures/cem_target/ground_truth.py` | NEW | Read-only expected labels (protected; see §8). |
| `tests/test_cem_engine.py` | NEW | Unit tests (no network; fake fetch). |
| `tests/test_cem_case_store.py` | NEW | Schema/CRUD/isolation tests. |
| `tests/test_cem_scope_gate.py` | NEW | Hook gates case-mcp senders; allows local tools. |
| `tests/test_cem_benchmark.py` | NEW | End-to-end benchmark + FCCR gate. |
| `tests/test_cem_safety.py` | NEW | Safety/security tests (§10). |
| `tests/test_cem_performance.py` | NEW | Non-regression / inactivity-overhead (§12). |
| `scripts/verify-phase1.sh` | NEW | One-command verifier (§14). |
| `docs/cem-phase1.md` | NEW | Human-facing usage/design doc (§N). |

## 4. Data model (new tables in `case.db`) — final

`cem_meta(finding_id PK, base_request JSON, success_signature JSON, determinism_status DEFAULT 'UNTESTED',
cem_status DEFAULT 'DEFINED', k DEFAULT 5, incomplete INT DEFAULT 0)`;
`cem_conditions(id PK, finding_id, name, category, baseline_value, perturbation JSON)`;
`cem_trials(id PK, finding_id, condition_id NULLABLE, arm, k_index, http_status, oracle_hit INT,
request_evidence_hash, response_evidence_hash, controls JSON, created_at)`;
`cem_verdicts(id PK, finding_id, condition_id, verdict, k, controls JSON, detail, created_at)`.
All FK → `findings(id) ON DELETE CASCADE`. Trials reference the existing content-addressed evidence store by
hash (reuse `add_evidence`, no parallel blob store). Verdict enum:
`necessary | apparently_not_necessary | inconclusive | interacting | probabilistic`. (Matches PHASE1-PLAN §D.)

---

## 5. Repository-exact implementation map

Legend: FILE · EXISTING · CHANGE · REASON · REUSED PRIMITIVE · TEST · RISK

- **`case_store.py`** · `_init_schema()` · add 4 CEM tables + CRUD helpers (`cem_define`, `cem_record_trial`,
  `cem_record_verdict`, `cem_load_state`) · persist CEM state in the same per-engagement DB · reuse
  `_get_conn`, `add_evidence`, `engagement_paths.resolve` · `test_cem_case_store.py` · **Low** (additive tables;
  `CREATE TABLE IF NOT EXISTS`).
- **`cem_engine.py`** · NEW · pure logic · testability + separation from MCP · reuse fetch primitive (UD-1),
  `redact.redact_text` · `test_cem_engine.py` · **Med** (core algorithm correctness — mitigated by TDD).
- **`http_probe.py` / `idor_sweep.py`** · `_fetch/_build_headers/FetchResult` · extract to shared module (UD-1=B,
  approved) · DRY, no duplicate HTTP mechanism · existing `test_idor_sweep.py` as regression guard · **Med**
  (touches a working Tier-2 file — behavior-preserving refactor only; gate on test_idor_sweep green).
- **`case-mcp/server.py`** · tool registrations · add 6 tools; senders (`determinism_gate`, `run_counterfactual`)
  take a `url` arg and call `_enforce_budget("case-mcp")` + `_log_call(...)` inline · Tier-2 gating + audit ·
  reuse `budget_guard.enforce`, `audit_log.log_call` (same pattern as `idor-mcp/server.py`) ·
  `test_cem_scope_gate.py` + `test_cem_safety.py` · **Med** (mixed local/Tier-2 server — gated per-call by
  host-arg presence).
- **`scope_gate_hook.py`** · `TIER2_MCP_SERVERS` · add `"case-mcp"` · gate the senders · reuse existing hook
  logic (no new logic — `url` already in `HOST_ARG_KEYS`) · `test_cem_scope_gate.py` · **Low** (host-arg-less
  local tools hit `if not candidates: return 0`).
- **Scope/rate/budget/audit** · reuse as-is · no duplicate mechanisms · reason: PHASE1-PLAN mandates preserving
  them · **Note:** the CEM urllib path bypasses `tool_resolver`, so rate handling is executor-local
  (`spacing_ms` + `429`/throttle → `inconclusive`), same bypass idor-mcp already accepts · `test_cem_safety.py`
  · **Med** (executor must self-space; covered by tests).
- **Evidence** · `add_evidence(type in {request,response,metadata})` · reuse content-addressed store · no new
  blob store · `test_cem_case_store.py` · **Low**.
- **Validation/proof** · reuse the `create_finding→CONFIRMED` evidence gate as CEM's precondition · CEM operates
  only on already-CONFIRMED findings · **Low**.

**Anti-duplication rule for the implementer:** prefer the primitives above over new abstractions; if you find
yourself writing a second HTTP fetch, budget counter, evidence blob store, or scope check, STOP and reuse.

---

## 6. Granular TODO system

Status: `[ ]` PENDING · `[~]` IN PROGRESS · `[x]` COMPLETE · `[!]` BLOCKED. Update in place as work proceeds.
Each task: **ID — description** | deps | files | verify | acceptance. Follow TDD (write failing test first).

### A. Repository preparation
- [x] **A1** — Resolve UD-1..UD-4 with human; record rulings in §2. | deps: none | files: this doc | verify: rulings written in §2 | accept: all 4 resolved. **DONE 2026-09-04 (B / A / explicit / refuse-by-default).**
- [x] **A2** — Create isolated worktree/branch for Phase 1 (via `superpowers:using-git-worktrees`). | A1 | — | verify: `git status` on new branch | accept: not on main. **DONE (pre-existing) — verified 2026-09-04: `git branch --show-current` = `claude/phase1-cem-implementation-6e1693` (not main); `git worktree list` shows it as a linked worktree at `.claude/worktrees/phase1-cem-implementation-6e1693` with its own git-dir (`.git/worktrees/phase1-cem-implementation-6e1693`), separate from the main checkout (`/home/ankit/HuntMCP`, branch `main`). Both the literal accept criterion ("not on main") and the fuller "isolated worktree" intent are satisfied. Not created via an explicit `superpowers:using-git-worktrees` invocation this session — the worktree already existed as the session's working directory — but the resulting state meets the stated verify/accept bar exactly, so no further action is required.**
- [x] **A3** — Baseline capture: full suite recorded. | — | docs/cem-phase1-baseline.txt | verify: file present | accept: recorded. **DONE 2026-09-04 — 637 passed (624 pre-existing + 13 new env tests), ~11s.**
- [x] **A4** (UD-1=B) — Extract `http_probe.py`; refactor `idor_sweep.py` to import it. | A1 ✔ | http_probe.py, idor_sweep.py | verify: `pytest tests/test_idor_sweep.py` | accept: idor tests green, byte-for-byte behavior preserved (regression guard). **DONE 2026-09-04 — `mcp-servers/http_probe.py` created (FetchResult, build_headers, fetch, DEFAULT_TIMEOUT_S — same mechanics as before, unmodified urllib logic); `idor_sweep.py` now imports these instead of defining them, keeping the same module-level names (`_fetch`, `_build_headers`, `FetchResult`, `DEFAULT_TIMEOUT_S`) so existing monkeypatching and `idor-mcp/server.py`'s direct attribute access (`idor_sweep._fetch`, `idor_sweep._build_headers`, `idor_sweep.DEFAULT_TIMEOUT_S`) keep working unchanged. New `tests/test_http_probe.py` (10 tests, real loopback HTTP, no network mocking) written first (RED), then made GREEN. `tests/test_idor_sweep.py` 37/37 green unmodified. Full suite 671 passed (661 baseline + 10 new), 0 regressions. `ruff check` clean on both files. `idor-mcp/server.py` smoke-imports clean.**

### B. Schema / data model
- [x] **B1** — Failing test for the 4 CEM tables + isolation. | A2 | test_cem_case_store.py | verify: test fails | accept: red. **DONE 2026-09-04 — `tests/test_cem_case_store.py` created (19 tests): table-exists + exact-column-set + primary-key checks for all 4 tables (`cem_meta`, `cem_conditions`, `cem_trials`, `cem_verdicts`) per §4's schema; `cem_meta` defaults (`determinism_status='UNTESTED'`, `cem_status='DEFINED'`, `k=5`, `incomplete=0`); schema-level FK-to-`findings(id)`-`ON DELETE CASCADE` check per table (parametrized); two per-engagement isolation tests (`cem_meta`, `cem_conditions` rows never visible from a second engagement's case.db), following test_case_store.py's existing explicit-`db_path`-via-`tmp_path` isolation pattern. All 19 RED for the single correct reason — schema not yet added by B2 (`AssertionError` on empty column sets / missing table names; `sqlite3.OperationalError: no such table` on the two INSERT-based tests). `ruff check` clean. Full suite: 671 passed (unchanged) + 19 new RED = 690 collected, 0 unexpected failures/regressions. CRUD helpers and cascade-delete runtime behavior intentionally deferred to B2/B3.**
- [x] **B2** — Add tables to `_init_schema` + CRUD helpers. | B1 | case_store.py | verify: `pytest tests/test_cem_case_store.py` | accept: green; existing `test_case_store.py` still green. **DONE 2026-09-04 — 4 CEM tables added to `_init_schema()` verbatim per §4's "final" schema (only a `finding_id → findings(id) ON DELETE CASCADE` FK per table, no invented `condition_id` FK, matching the plan's exact DDL). CRUD helpers `cem_define`/`cem_record_trial`/`cem_record_verdict`/`cem_load_state` added, mirroring this file's existing conventions exactly (FK checks via `_row_exists`/`_missing_fk_error`, enum validation via new `CEM_TRIAL_ARMS`/`CEM_VERDICTS` constants alongside the existing `HYPOTHESIS_STATUSES`-style ones, `{"error": ...}` returns not exceptions). `cem_define` enforces UD-3 at the persistence layer (rejects empty/missing `success_signature` — never silently accepts a null oracle) and is one-shot per finding. All 19 B1 tests green. `test_case_store.py` 36/36 green, unmodified. CRUD helpers verified by direct execution (happy path, FK errors, enum rejection, UD-3 rejection, duplicate-define rejection, JSON round-trip through `cem_load_state`) since B1's tests only cover schema, not CRUD — not committed as a permanent test file (out of this task's stated verification scope), but run and its output inspected before claiming completion. DEVIATION (human-approved via AskUserQuestion this session): `tests/test_cem_harness_security.py::test_no_cem_production_logic_exists` — a Phase-1a pre-G0 tripwire asserting no CEM symbols exist in `case_store.py`/`case-mcp/server.py` — necessarily failed once B2 legitimately added those symbols under granted G0 approval. Retired (deleted) with the human's explicit sign-off after I stopped and reported it rather than editing unilaterally; module docstring updated to record why. The other 5 tests in that file (loopback-only, tamper detection, benchmark-blindness) are untouched and still green.**
- [x] **B3** — Cascade-delete + per-engagement isolation tests. | B2 | test_cem_case_store.py | verify: pytest | accept: deleting a finding removes its CEM rows; two engagements don't mix. **DONE 2026-09-05 — 6 new tests added to `tests/test_cem_case_store.py` (25 total in the file now). Cascade-delete: `test_deleting_finding_cascades_all_four_cem_tables` (deletes via `DELETE FROM findings`, proves via `cem_load_state` + a per-table row-count check that all 4 CEM tables — not just `cem_meta` — actually cascade, not just declare the FK), `test_deleting_finding_leaves_sibling_finding_and_its_cem_state_intact`, `test_deleting_finding_with_no_cem_state_does_not_error`. Deeper isolation: `test_cem_load_state_never_mixes_engagements_even_with_same_finding_id` (both engagements' own autoincrement sequences independently assign finding id=1 — the real isolation risk — and their content never mixes), `test_cem_record_trial_and_verdict_never_cross_engagements`, `test_deleting_finding_in_one_engagement_does_not_affect_the_other`. All 6 built through the real public CRUD surface (`cem_define`/`cem_record_trial`/`cem_record_verdict`/`cem_load_state`) rather than raw SQL, per the black-box instruction — raw SQL used only for the per-table row-count proof and the delete itself, where no public accessor exists (mirrors B1's own precedent). All 6 passed on first run against the existing B2 implementation — no production code changed; verified non-vacuous by an ephemeral (uncommitted) spike proving the same delete leaves an orphaned row when `PRAGMA foreign_keys=OFF`, i.e. the test would have caught a real regression. Full `test_cem_case_store.py` 25/25, `test_case_store.py` 36/36 unmodified, ruff clean, full suite 695 passed. No protected benchmark file (`scenarios.py`/`answer_key.py`/`evaluator.py`/`integrity.py`/`ground_truth.py`) touched.**

### C. CEM engine (pure logic, TDD)
- [x] **C1** — `SuccessSignature` + `evaluate_signature(FetchResult, sig)` (status set / body substring / regex / similarity-to-baseline). Oracle is **caller-supplied only** (UD-3). | A4 | cem_engine.py, test_cem_engine.py | verify: pytest | accept: matcher covers each case; **no code path auto-derives the oracle from a baseline response.** **DONE 2026-09-05 — `mcp-servers/cem_engine.py` created (first CEM production module). `SimilarityToBaseline(body, threshold)` + `SuccessSignature(status_in, body_contains, body_regex, similarity_to_baseline)` dataclasses; `SuccessSignature.from_dict()` bridges the JSON shape `case_store.cem_define`/`cem_load_state` already use; `evaluate_signature(FetchResult, SuccessSignature) -> bool`, pure/deterministic, AND-semantics across whichever fields are set, `.error`-carrying FetchResult never satisfies any signature. Validation lives in `__post_init__` (both direct construction and `from_dict` funnel through it) so an empty/all-None signature is refused everywhere, never silently treated as always-true (UD-3). CONTRACT AMBIGUITY — stopped and asked rather than guessed (see KNOWN DEVIATIONS): `similarity_to_baseline` resolved as a nested `{body, threshold}` object embedded in the signature, human-approved 2026-09-05. TDD: `tests/test_cem_engine.py` written first (31 tests), confirmed RED (`ModuleNotFoundError: No module named 'cem_engine'`), then implementation added, 31/31 GREEN on first pass. `ruff check mcp-servers/` flagged 3 real TRY004 issues (ValueError used where TypeError is correct for a type-mismatch, vs ValueError for a value-range/shape issue) — fixed properly and consistently across the whole file, not just the 3 flagged lines, with 5 tests updated to expect the corrected exception type. `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, full suite 726 passed (695 + 31 new), ruff clean on both new files. No CEM database write, no network call, no MCP tool, no determinism gate, no perturbation/execution logic — pure oracle-evaluation only, exactly C1's scope.**
- [x] **C2** — `determinism_gate(base_request, k)` using a fake fetch: STABLE iff all-k HIT; else NONDETERMINISTIC. | C1 | cem_engine.py | verify: pytest | accept: mixed baseline → NONDETERMINISTIC. **DONE 2026-09-05 — `determinism_gate(base_request, k, success_signature, fetch_fn) -> DeterminismResult` added to `mcp-servers/cem_engine.py`. `success_signature`/`fetch_fn` weren't in the task's shorthand 2-arg line but are structurally required (HIT needs an oracle; a fetch needs a fetch mechanism) — same precedent as D2's shorthand omitting `budget_cb` while its detailed design section requires it; not treated as ambiguous since the task itself explicitly required "an injected/fake fetch mechanism." `fetch_fn` matches `http_probe.fetch`'s exact signature `(url, method, headers, body, timeout_s) -> FetchResult` (positionally compatible so a later task's production wiring can pass `http_probe.fetch` directly, zero adapter code — UD-1 anti-duplication rule) rather than inventing a new callable shape. `DeterminismResult(status, hits, k)` — strict binary `STABLE`/`NONDETERMINISTIC`, no third bucket for "consistently MISSing" or "all fetch errors" (both verified `NONDETERMINISTIC` by explicit test, per "do not silently expand the definition of determinism"). No spacing/Controls/confounder-pinning added (that's D1/D2). TDD: `tests/test_cem_engine.py` extended with 18 C2 tests, written first, confirmed RED (`ImportError: cannot import name 'DeterminismResult'`), then implemented, 49/49 (31 C1 + 18 C2) GREEN — no existing C1 test modified/weakened. Explicitly tests: all-k HIT, one/alternating/all miss, k=1, invalid k (zero/negative/non-int/bool), exact k call count, base_request fields passed through correctly, gate-classification determinism (both STABLE and NONDETERMINISTIC cases), fetch-error trials counted as MISS not a new status, and — via `monkeypatch.setattr(http_probe, "fetch", <raises>)` — proof `determinism_gate` never calls the real `http_probe.fetch`. Full suite 744 passed (726 + 18), `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, all unmodified. ruff clean on both files after two minor autofix-adjacent style corrections (see KNOWN DEVIATIONS).**
- [x] **C3** — `classify(baseline_hits, perturbed_hits, k)` → verdict rules (necessary/apparently_not_necessary/inconclusive; throttle→inconclusive; mixed→inconclusive). | C1 | cem_engine.py | verify: pytest | accept: every rule row from PHASE1-PLAN §D covered. **DONE 2026-09-05 — `classify(baseline_hits, perturbed_hits, k) -> str` added to `mcp-servers/cem_engine.py`, exactly the literal 3-arg signature (no extra params, unlike C2). Implements all 4 unanimity rules from PHASE1-PLAN.md §D: baseline not all-HIT → `inconclusive`; perturbed all-MISS (baseline all-HIT) → `necessary`; perturbed all-HIT (baseline all-HIT) → `apparently_not_necessary`; perturbed mixed (baseline all-HIT) → `inconclusive`. Returns exactly one of 3 verdict strings, never a 4th (interacting/probabilistic are separate later tasks C4/C6). SCOPE-BOUNDARY AMBIGUITY — stopped and asked rather than guessed (see KNOWN DEVIATIONS): 429/throttle detection resolved as OUT of classify()'s scope, belongs to the executor (task D3); classify() only ever sees plain `list[bool]` hit sequences, matching `DeterminismResult.hits`' type exactly — human-approved 2026-09-05. A dedicated test (`test_classify_signature_has_no_throttle_parameter_by_design`, via `inspect.signature`) pins this boundary down so a future task can't silently widen the signature without an equally explicit decision. TDD: 18 new tests appended to `tests/test_cem_engine.py`, written first, confirmed RED (`ImportError: cannot import name 'classify'`), then implemented, 67/67 GREEN (49 C1+C2 + 18 C3) on first pass — no existing C1/C2 test modified/weakened. Explicitly tests: stable-baseline+stable-miss→necessary, stable-baseline+stable-hit→apparently_not_necessary, mixed baseline (both perturbed directions)→inconclusive, mixed perturbed→inconclusive, baseline all-miss→inconclusive (not a special case, just "not all-HIT"), all-miss-perturbed-with-valid-baseline→necessary (explicit item-7 phrasing), the throttle scope-boundary signature test, mismatched-length rejection (both arms), non-list/non-bool element rejection, invalid k (zero/negative/non-int/bool), deterministic repeated classification, proof `http_probe.fetch` is never touched, and a 3-verdict-closure test across multiple input combinations. Full suite 762 passed (744 + 18), `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, all unmodified. ruff clean on both files with zero fixes needed (first C-group task with no ruff findings).**
- [x] **C4** — race/TOCTOU path → `probabilistic` (report perturbed HIT-rate; never necessary). | C3 | cem_engine.py | verify: pytest | accept: flagged-race input never yields `necessary`. **DONE 2026-09-05 — `classify_race(perturbed_hits, k) -> RaceResult` added to `mcp-servers/cem_engine.py`. PHASE1-PLAN.md's C4 line names no function/signature (unlike C1/C2/C3, each of which named its exact function) — genuine API ambiguity, stopped and asked rather than guessed. Resolved (human-approved, of 4 options presented): a new, separate pure function rather than widening classify()'s C3-pinned 3-arg signature; no baseline_hits (plan wording only ever says "report perturbed HIT-rate"); no boolean race flag — being routed to this dedicated function at all IS the race flag, mirroring how determinism_gate/classify are already separate pure functions per concern. `RaceResult(verdict, hit_rate, k)` — `verdict` hardcoded to `VERDICT_PROBABILISTIC` so the function structurally cannot return `necessary` regardless of the observed hit pattern (proven by an exhaustive test over every hit pattern for k=1..4, plus the specific all-MISS case that would trip `classify()` into `necessary`); `hit_rate = count(True)/k` over `perturbed_hits`, preserving uncertainty explicitly rather than collapsing it into a boolean. TDD: `tests/test_cem_engine.py` extended with 15 C4 tests, written first, confirmed RED (`ImportError: cannot import name 'RaceResult'`), then implemented, 82/82 GREEN (67 C1+C2+C3 + 15 C4) on first pass — no existing C1/C2/C3 test modified/weakened. Explicitly tests: all-HIT/all-MISS/mixed hit-rate computation, all-MISS still `probabilistic` never `necessary`, exhaustive never-`necessary` sweep over every k=1..4 hit pattern, `RaceResult` instance check, signature-introspection test pinning `(perturbed_hits, k)` with no baseline/flag param, invalid-`k`/invalid-element/length-mismatch rejection (mirroring classify's validation), determinism across repeated calls, and proof `http_probe.fetch` is never touched. Full suite 777 passed (762 + 15), `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, all unmodified. ruff clean on both files with zero fixes needed.**
- [x] **C5** — `minimal_condition_sets()`: ddmin for one 1-minimal set. | C3 | cem_engine.py | verify: pytest with known set | accept: recovers planted minimal set. **DONE 2026-09-05 — `MinimalSetResult(minimal_set, predicate_calls)` + `minimal_condition_sets(conditions: list[str], is_interesting: Callable[[frozenset[str]], bool]) -> MinimalSetResult` added to `mcp-servers/cem_engine.py`. API AMBIGUITY — stopped and asked rather than guessed (see KNOWN DEVIATIONS): PHASE1-PLAN.md names the ddmin interestingness property precisely ("a subset is interesting iff, with all conditions outside it perturbed to non-triggering, the oracle is unanimously HIT over k") but, unlike C1/C2/C3, gives no concrete pure-function signature at the engine layer — only the DB-backed `minimal_condition_sets(finding_id)` (a later E1 task, out of scope for pure/DB-free C5). Human-approved (of 3 options presented): an injected pure predicate `is_interesting: Callable[[frozenset[str]], bool]`, matching classic ddmin(test, circumstances) exactly and mirroring C2's fetch_fn-injection precedent; strictly bool (no inconclusive/tri-state channel invented — the plan's own definition of "interesting" is already binary; a predicate returning non-bool is a hard TypeError, proven by a dedicated test). Algorithm: deterministic single-element-removal sweep to a fixed point (hand-traced, correctness-equivalent simplification of classical partition-based ddmin appropriate for CEM's small per-finding condition counts) — guarantees 1-minimality on termination, fully deterministic for a deterministic predicate. Precondition enforced: `frozenset(conditions)` itself must be interesting or `ValueError` (ddmin cannot minimize a set that doesn't reproduce the effect). Finds exactly ONE 1-minimal set — no alternates, no interaction detection (both C6). TDD: `tests/test_cem_engine.py` extended with 21 C5 tests, written first, confirmed RED (`ImportError: cannot import name 'MinimalSetResult'`), then implemented, 103/103 GREEN (82 C1-C4 + 21 C5) on first pass — no existing C1-C4 test modified/weakened. Explicitly tests: one-unnecessary-condition removal, a "planted minimal set" scenario mirroring the benchmark's `/doc/{id}` auth-necessary shape, repeated-removal convergence over 4 conditions, an AND-interaction shape where neither condition is individually removable, an OR-shape with 2 valid minimal sets (verified generically 1-minimal, plus the exact deterministic outcome for this algorithm/order), predicate always called with a `frozenset`, empty/single-condition inputs (including a singleton that reduces to the empty set), subset-of-input invariant, invalid inputs (non-list, non-string elements, duplicates, non-callable predicate, full-set-not-interesting, predicate-returns-non-bool), determinism across repeated calls, an exact hand-traced predicate-call count (4 calls) for a known 2-condition scenario, proof `http_probe.fetch` is never touched, and a signature-introspection test pinning `(conditions, is_interesting)` with no `finding_id`/DB/network parameter. `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, full suite 798 passed (777 + 21), ruff clean on both files (one round of fixes: `# noqa: E731` comments on lambda assignments were flagged RUF100 "unused noqa" since E731 isn't an enabled rule in this repo's ruff config — removed). No protected benchmark file touched. No real network access, no DB write, no MCP tool, no perturbation/execution logic, no C3/C4 modification, no SuccessSignature change, no alternates/interaction search — pure ddmin set-minimization over a caller-supplied predicate only, exactly C5's scope.**
- [x] **C6** — alternates + interaction detection (bounded; report completeness). | C5 | cem_engine.py | verify: pytest | accept: ≥2 sets when planted; interaction-only flagged `interacting`; bound reported. **DONE 2026-09-05 — `InteractionEvidence(pair)` + `AlternateSetsResult(minimal_sets, interacting, interacting_pairs, sets_found, trials_used, bounded)` + `find_alternate_condition_sets(conditions: list[str], is_interesting: Callable[[frozenset[str]], bool], max_trials: int) -> AlternateSetsResult` added to `mcp-servers/cem_engine.py`, built strictly on top of C5's `minimal_condition_sets()` (called directly, never reimplemented). Implements PHASE1-PLAN.md sec 11 literally: Alternates ("for each c in M1, force-exclude c and re-run ddmin → collect distinct minimal sets", scoped to M1's own members) + 2 explicit interaction rules (Rule 1: singly-droppable but present in every other recovered set; Rule 2: a pair whose joint removal flips the oracle while neither single removal does) + the literal `sets_found`/`trials_used`/`bounded` reporting triple, `bounded` implemented as an injected `max_trials` cap (never a real `budget_guard` import — C6 stays pure). TWO API/semantics ambiguities — stopped and asked rather than guessed (see KNOWN DEVIATIONS): (1) Rule 1's "present in every recovered minimal set" excludes c's own force-excluded alternate (structurally can never contain c) AND M1 itself when c∈M1 (tautological, restates the premise) — human-approved, of 3 options presented, the only reading under which Rule 1 can ever actually fire. (2) The candidate pool for individual-droppability testing (feeding both rules) is broadened to ALL conditions in the original S, not just M1's members — human-approved, of 2 options presented — because ddmin's greedy sweep can drop one half of a genuine interacting pair before it ever reaches M1 (concrete counterexample worked through with the human: conditions=[a,b,d], is_interesting=d∧(a∨b), ddmin drops "a" immediately, M1={b,d}, yet is_interesting(S-{a})=is_interesting(S-{b})=True and is_interesting(S-{a,b})=False is a genuine Rule-2 interaction an M1-only scope would miss). TDD: `tests/test_cem_engine.py` extended with 27 C6 tests, written first, confirmed RED (`ImportError: cannot import name 'AlternateSetsResult'`), then implemented, 130/130 GREEN (103 C1-C5 + 27 C6) on first pass — no existing C1-C5 test modified/weakened. Four hand-traced scenarios validate the design end-to-end: OR-redundancy (header/cookie, mirrors `/report`) → 2 sets, Rule 2 flags both (documented honestly as a literal-but-expected corollary of "only 2 paths exist", not suppressed); pure-AND-no-redundancy (role_admin/flag_on, mirrors `/merge` in isolation) → 1 set, `interacting=frozenset()` (proves no over-inference from mere multi-condition co-occurrence); a 3-condition mutually-substitutable-plus-gate scenario proving Rule 2 catches a real interaction even when one member never reaches M1; a 4-condition "any-2-of-3" scenario giving a genuine non-vacuous Rule-1 firing (for the 2 members that do survive into M1) alongside Rule 2 independently catching all 3 pairs. Also tests: exact hand-traced call accounting for 3 scenarios (8, 7, 22, and the any-2-of-3 case again under a tight budget), `bounded=True` with graceful partial (non-crashing) results under a deliberately tight `max_trials`, empty-conditions triviality, determinism across repeated calls, full invalid-input matrix (non-list/non-string/duplicate conditions, non-callable predicate, non-int/bool/zero/negative `max_trials`), a spy proving `minimal_condition_sets` is genuinely reused rather than reimplemented (exact call count), proof `classify`/`classify_race` are never touched (interacting is orthogonal to necessary/apparently_not_necessary/inconclusive/probabilistic — never a 4th verdict), proof `http_probe.fetch` is never touched, a structural field-set check on `AlternateSetsResult` guarding against a verdict-like field ever sneaking in, and a signature-introspection pin (`conditions, is_interesting, max_trials`). `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, full suite 825 passed (798 + 27), ruff clean on both files with zero fixes needed. No protected benchmark file touched. No real network access, no DB write, no MCP tool, no C1-C5 modification (SuccessSignature/determinism_gate/classify/classify_race/minimal_condition_sets all reused verbatim), no race-becomes-necessary path (C6 never calls classify_race), no PoC minimization (C7) — pure alternates/interaction search over a caller-supplied predicate only, exactly C6's scope.**
- [x] **C7** — `minimize_poc()`: ddmin over conditions/steps, runs AFTER verdicts, re-validated by determinism gate. | C5 | cem_engine.py | verify: pytest | accept: unnecessary condition dropped; minimal PoC re-passes gate. **DONE 2026-09-05 — `PocMinimizationResult(poc, accepted, determinism, predicate_calls)` + `minimize_poc(conditions: list[str], is_interesting: Callable[[frozenset[str]], bool], revalidate: Callable[[frozenset[str]], DeterminismResult]) -> PocMinimizationResult` added to `mcp-servers/cem_engine.py`. Reuses `minimal_condition_sets()` (C5) directly for the ddmin search — never reimplemented — per PHASE1-PLAN.md sec 12's literal "PoC minimization reuses the SAME ddmin with the oracle as interestingness." "steps" was checked and confirmed NOT a separate concept anywhere in the plan (only ever a loose synonym for "conditions/fields", no dedicated dataclass) — minimize_poc() operates over the exact same `conditions` abstraction as C5/C6, no new abstraction invented. Re-validation ("output re-validated through determinism_gate ... guards a DD local optimum dropping a real step") is an injected `revalidate` callable standing in for the real `determinism_gate` (C2) — kept abstract so C7 stays pure/no-network, exactly how `is_interesting` already stands in for a real oracle, reusing C2's own `DeterminismResult` type unmodified rather than inventing new determinism vocabulary. ONE design fork resolved directly from the plan's own text rather than guessed (no AskUserQuestion needed — textually unambiguous once traced): what happens when revalidation reports NONDETERMINISTIC. PHASE1-PLAN.md sec 15 explicitly separates the mandatory step ("re-validate minimal set/PoC via determinism gate") from an explicitly-OPTIONAL one ("optional DDMIN* re-iterate") — so minimize_poc() does NOT retry/backtrack on failure; it reports `accepted=False` honestly (poc still returned as evidence) rather than silently accepting a possibly-wrong minimal reproducer or attempting recovery logic the plan itself marks out of Phase 1's minimum scope. TDD: `tests/test_cem_engine.py` extended with 17 C7 tests, written first, confirmed RED (`ImportError: cannot import name 'PocMinimizationResult'`), then implemented, 147/147 GREEN (130 C1-C6 + 17 C7) on first pass — no existing C1-C6 test modified/weakened. Explicitly tests: the literal accept criterion via the `/doc/{id}`-mirroring auth_cookie/trace_param scenario (unnecessary condition dropped, `accepted=True`), exact hand-traced predicate-call count (4, matching C5's own trace of the identical scenario), honest `accepted=False` reporting on a NONDETERMINISTIC revalidation stub (no crash, no silent accept), proof `revalidate` is called exactly once even on failure (no automatic re-iteration), a spy proving `minimal_condition_sets` is genuinely reused (exact call), proof `classify`/`classify_race`/`find_alternate_condition_sets`/the real `determinism_gate`/`http_probe.fetch` are never touched, validation-inheritance proof (conditions/is_interesting errors propagate from C5 unduplicated), invalid-`revalidate` handling (non-callable, non-`DeterminismResult` return), determinism across repeated calls, empty-conditions triviality, and a signature-introspection pin (`conditions, is_interesting, revalidate`). `test_http_probe.py`+`test_case_store.py`+`test_cem_case_store.py` 71/71, full suite 842 passed (825 + 17), ruff clean on both files with zero fixes needed. No protected benchmark file touched. No real network access, no DB write, no MCP tool, no C1-C6 modification, no automatic retry/DDMIN* re-iteration (explicitly out of Phase-1 scope per the plan) — pure PoC minimization + honest re-validation reporting only, exactly C7's scope.**
- [x] **C8** — `assemble_bundle()`: all 15 §2.8 fields; redacted via `redact_text`. | C3..C7 | cem_engine.py | verify: pytest | accept: bundle schema has every field; redaction applied. **DONE 2026-09-05 (via `superpowers:subagent-driven-development`) — `assemble_bundle(finding_id, original_baseline, baseline_determinism, intervention_matrix, controls, observed_confounders, verdict_labels, inconclusive_experiments, alternate_sets, poc, audit_trail, k) -> dict` added to `mcp-servers/cem_engine.py`, plus a private `_redact_recursive()` helper (recurses dicts/lists/tuples, applies `redact.redact_text` to every string leaf, leaves int/float/bool/None untouched, applied exactly once at the end of assembly). RULING (controller-resolved, not escalated — see `.superpowers/sdd/PHASE1-EXECUTION-PLAN/progress.md`): C8's only deps are C3..C7, not D1-D3/case_store (neither exists yet), so the function must accept already-computed typed results as parameters rather than execute anything live — same injected-dependency pattern as C2's `fetch_fn`/C7's `revalidate`. Produces a 16-key dict: all 15 §2.8 fields (`original_baseline`, `baseline_replication_results`, `intervention_matrix`, `replication_counts`, `controlled_pinned_conditions`, `observed_confounders`, `inconclusive_experiments`, `identified_necessary_conditions`, `minimal_condition_sets`, `minimized_reproduction_evidence`, `complete_audit_trail`, `verdict_labels`, `controls`, `k`, `completeness_bound`) plus `finding_id` for bundle identity. Fields 4/14 (`replication_counts`/`k`) and 5/13 (`controlled_pinned_conditions`/`controls`) are deliberately duplicated per the spec's own field list, not collapsed. `identified_necessary_conditions` is derived from `verdict_labels` (never caller-supplied separately, closing a silent-disagreement risk); `minimal_condition_sets`/`completeness_bound` unpack `AlternateSetsResult` into two distinct top-level keys (set contents vs. completeness counts, not nested); `minimized_reproduction_evidence` unpacks `PocMinimizationResult`. `isinstance` validation (TypeError) on the three typed params (`baseline_determinism`, `alternate_sets`, `poc`); the other 9 params are intentionally unchecked, matching the brief's own explicit scope. TDD: 27 new tests appended to `tests/test_cem_engine.py` (RED confirmed via `ImportError: cannot import name 'assemble_bundle'`, then GREEN), covering schema-completeness (real key-set equality), one test per field-derivation rule, a non-vacuous redaction proof (explicit `redact_text(secret) != secret` check before three bundle-level redaction tests rely on it), non-string-survival, no-live-execution (every C1-C7 function plus `http_probe.fetch` monkeypatched to raise), determinism, 3 TypeError-rejection tests, and a signature-introspection pin. Full suite 869 passed (842 + 27), 0 failed — independently re-verified by the controller after the implementer's own run. `ruff check` clean on both files (also independently re-verified by the controller). Task-reviewer pass (spec + quality, full detail in the SDD ledger): **Approved**, 0 Critical, 0 Important, 2 Minor deferred (a test hardcodes the literal `"necessary"` string instead of the `VERDICT_NECESSARY` constant; no type/shape validation on the 9 untyped params — both cosmetic/forward-looking, not gaps against what was asked). No fix loop needed. No protected benchmark file touched. Commit: `8ac2eb9`.**

### D. Intervention executor
- [ ] **D1** — `Controls` dataclass + pinning helpers (session headers, cache-buster, ordering, `spacing_ms`, concurrency=1; uncontrollable confounder → recorded, forces inconclusive). | C1 | cem_engine.py | verify: pytest | accept: uncontrolled confounder → inconclusive.
- [ ] **D2** — `run_intervention(base_request, controls, perturbation|None, k, budget_cb)`: loops fetch, spacing, oracle eval; budget via injected callback (MCP-free). | D1, A4 | cem_engine.py | verify: pytest with fake fetch + spy budget_cb | accept: k calls, budget_cb called per request, one-variable-at-a-time honored.
- [ ] **D3** — `429`/throttle detection in executor → inconclusive. | D2 | cem_engine.py | verify: pytest | accept: throttled arm never yields necessary.

### E. MCP tool integration
- [ ] **E1** — Add `define_conditions`, `determinism_gate`, `run_counterfactual`, `minimal_condition_sets`, `minimize_poc`, `evidence_bundle` wrappers in `case-mcp/server.py`. | B2, C8, D3 | case-mcp/server.py | verify: import + smoke test | accept: tools registered; delegate to engine/store.
- [ ] **E2** — Senders (`determinism_gate`, `run_counterfactual`) take `url` and call `_enforce_budget("case-mcp")` + `_log_call(...)` inline. | E1 | case-mcp/server.py | verify: test_cem_safety.py | accept: budget+audit invoked per real request.
- [ ] **E3** — Guards: CEM tools refuse (a) a finding not in CONFIRMED state, and (b) `define_conditions` with a missing/invalid `success_signature` (UD-3 — no fallback derivation). | E1 | case-mcp/server.py | verify: pytest | accept: non-confirmed finding rejected; missing/invalid oracle → hard error, never auto-derived.

### F. Scope / rate / budget / audit safety
- [ ] **F1** — Add `"case-mcp"` to `TIER2_MCP_SERVERS`. | E2 | scope_gate_hook.py | verify: test_cem_scope_gate.py | accept: out-of-scope sender blocked (rc 2); local tool (no url) allowed (rc 0).
- [ ] **F2** — (UD-2=A) Share the engagement-wide 500-call cap AND enforce a per-finding CEM request ceiling (`HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING`, sane default). | A1 ✔, E2 | cem_engine.py/server.py | verify: pytest | accept: CEM requests count against shared budget via `enforce("case-mcp")`; exceeding the per-finding ceiling stops with partial `incomplete=1` bundle and no necessity from an incomplete arm.
- [ ] **F3** — (UD-4=refuse-by-default) Refuse non-idempotent/state-changing perturbations. | A1 ✔, D2 | cem_engine.py | verify: pytest | accept: non-GET/stateful perturbation refused by default; only a per-finding explicit human-approval flag can permit one (no blanket/global override).

### G. Evidence handling
- [ ] **G1** — Every trial stores request+response via `add_evidence` (content-addressed) linked to finding_id; trial rows reference the hash. | B2, D2 | cem_engine.py, case_store.py | verify: test_cem_case_store.py | accept: identical bytes dedupe; bundle rebuildable from stored evidence.

### H. Benchmark environment  ✅ TEST-ENVIRONMENT SUBSTRATE COMPLETE (2026-09-04) — see files below; CEM assertion tests remain deferred.
- [x] **H1** — Benchmark target (stdlib http.server, 127.0.0.1, ephemeral port) with all §8 cases. Implemented as `tests/fixtures/cem_target/cem_benchmark_app.py` (+ `harness.py` loopback-guarded client). | none | fixtures | verify: `pytest tests/test_cem_environment.py` | accept: each endpoint behaves per §8. **DONE 2026-09-04 — 13/13 env tests green.**
- [x] **H2** — Protected `ground_truth.py` (frozen MappingProxyType) + `ground_truth.sha256.lock` integrity gate + pytest fixture (start/reset/stop) in `tests/test_cem_environment.py`. Fixture defined in the test module (NOT global conftest) → zero regression risk to the existing suite. | H1 ✔ | fixtures, test module | verify: env test file | accept: server starts/resets/stops; integrity gate + tamper detection verified. **DONE 2026-09-04.**

### I. Unit tests  (produced alongside C/D via TDD — this group tracks completeness)
- [ ] **I1** — Coverage check: every verdict rule, gate branch, ddmin path, bundle field has a unit test. | C8, D3 | test_cem_engine.py | verify: pytest -v | accept: all engine branches covered.

### J. Integration tests
- [ ] **J1** — End-to-end on the benchmark target: define→gate→counterfactual→minimal sets→minimize→bundle. | E3, H2 | test_cem_benchmark.py | verify: pytest | accept: full flow runs against localhost target.

### K. Security benchmark (ground-truth correctness)
- [ ] **K1** — Assert each §8 expected verdict/label matches CEM output. | J1 | test_cem_benchmark.py | verify: pytest | accept: all labels match.
- [ ] **K2** — Compute + assert **false-causal-conclusion-rate == 0** (§9). | K1 | test_cem_benchmark.py | verify: pytest | accept: FCCR==0 or test FAILS.

### L. Regression tests
- [ ] **L1** — Full existing suite green + `test_case_store.py`/`test_idor_sweep.py` unchanged behavior. | B2, A4 | — | verify: `pytest tests/` | accept: pass count ≥ A3 baseline; no pre-existing test modified to pass.

### M. Performance / non-regression
- [ ] **M1** — Measure A(CEM absent)/B(installed-inactive)/C(active) per §12 (wall-clock, HTTP count, DB growth). | J1 | test_cem_performance.py | verify: pytest | accept: B overhead vs A within the defined threshold (§12); thresholds derived from A3 baseline, not invented.

### N. Documentation
- [ ] **N1** — `docs/cem-phase1.md` (usage, tool signatures, bundle format, safety notes). | E3 | docs | verify: doc review | accept: a new session can run CEM from the doc.
- [ ] **N2** — Update ROADMAP.md PROJECT STATE + this doc's CURRENT EXECUTION STATE. | P1 | ROADMAP.md, this doc | verify: read-back | accept: state reflects reality.

### O. Final security audit
- [ ] **O1** — Run the §15 audit checklist against actual code (not just tests). | all | — | verify: checklist signed | accept: no unresolved High/Med.

### P. Final acceptance
- [ ] **P1** — Run `scripts/verify-phase1.sh`; confirm gates G1–G9 (§13). | all | — | verify: verifier report | accept: all gates pass; else BLOCKED.

---

## 7. Automated testing environment  (§7)

`scripts/verify-phase1.sh` orchestrates, using the repo's existing pytest — no new deps:
1. **Validate prerequisites** (`scripts/venv-python.sh`, Python 3.12, pytest/pyyaml/mcp present).
2. **Start** the benchmark target (pytest fixture; ephemeral localhost port).
3. **Reset** benchmark state (fixture per-test reset).
4. Run **unit** (`pytest tests/test_cem_engine.py`), 5. **integration** (`test_cem_benchmark.py::test_flow`),
6. **CEM benchmark + FCCR** (`test_cem_benchmark.py`), 7. **safety** (`test_cem_safety.py`,
`test_cem_scope_gate.py`), 8. **regression** (full `pytest tests/`), 9. **performance** (`test_cem_performance.py`).
10. **Collect** results (JUnit XML + captured stdout). 11. **Stop/clean up** the target (fixture teardown; assert
no lingering process/port). 12. **Human-readable** summary (pass/fail per gate). 13. **Machine-readable**
`phase1-report.json` (gate → status, FCCR value, counts).

All target-touching happens on `127.0.0.1` (allowed by `is_safe_test_host`); unit/integration tests call
`cem_engine` directly and never traverse the live scope hook, so no engagement.yaml is required for tests.

## 8. Ground-truth benchmark  (§8)

`tests/fixtures/cem_target/app.py` endpoints and protected expected labels (`ground_truth.py`):

| Endpoint | Planted truth | Expected CEM output |
|---|---|---|
| `/doc/{id}` (needs auth cookie) | auth necessary | cookie → `necessary` |
| `/doc/{id}?trace=1` | `trace` irrelevant | `trace` → `apparently_not_necessary`; absent from minimal PoC |
| `/report` via header OR cookie | two independent paths | ≥2 minimal condition sets |
| `/merge` needs role=admin AND flag=on | interaction | `interacting` (neither alone) |
| `/flaky` random 200/403 | flaky red herring | determinism gate → NONDETERMINISTIC; **never `necessary`** |
| `/cached` 200 then 403 (cache) | confounder red herring | `inconclusive` (not `necessary`) |
| `/race` succeeds only under parallel hits | genuine race | `probabilistic` |
| session/auth state | present | pinned as a control |
| CSRF token (where feasible) | present | pinned; if unpinnable → `inconclusive` |

**Ground-truth protection:** expected labels live in `ground_truth.py` imported **read-only** by the test; the
CEM engine has no import path to it and no write path to it. The verifier additionally checks a **SHA-256
checksum** of `ground_truth.py` at start and end of the run and **fails the run if it changed** — so an
implementation cannot "win" by editing expected answers during test execution. `ground_truth.py` changes are
review-only, never made by the implementation or test-run.

## 9. False-causal-conclusion-rate (FCCR)  (§9)

- **Numerator:** number of conditions the benchmark labels as *not truly necessary* (i.e. planted
  `apparently_not_necessary`, flaky, cached-confounder, or race cases) to which CEM assigned the **`necessary`**
  verdict.
- **Denominator:** total conditions across benchmark findings that have a defined "not-necessary / must-not-be-
  necessary" ground truth (the set at risk of a false necessity claim).
- **A false causal conclusion** = emitting `necessary` for any condition whose ground truth is not-necessary,
  OR labeling a flaky/cached/race case `necessary` instead of `inconclusive`/`probabilistic`.
- **`inconclusive`** is *never* a false conclusion — it is the correct, honest outcome when controls fail; it is
  excluded from the numerator (and tracked separately as an honesty metric).
- **`probabilistic`** (race) is *never* counted as a necessity claim; a race labeled `probabilistic` is correct.
- **Reporting:** `phase1-report.json` records `fccr = numerator/denominator` and the per-case verdict table.
  **Release gate G5 requires `fccr == 0`.**
- **Honesty caveat (must appear in the bundle/docs):** FCCR==0 is asserted **only** on the constructed
  benchmark with known ground truth. **No zero-false-conclusion claim is made for real-world targets** where
  ground truth is unknown.

## 10. Security / safety tests  (§10) — `test_cem_safety.py` + `test_cem_scope_gate.py`
Scope enforcement (out-of-scope `url` blocked rc2; in-scope/localhost allowed subject to budget); URL
validation / no non-HTTP schemes; SSRF-adjacent (perturbation cannot redirect to a new host — host is pinned
from the confirmed finding, not caller-mutable to an arbitrary host); rate handling (`429`→inconclusive,
spacing enforced); budget cap (`BudgetExceeded` stops sending); per-finding request ceiling (UD-2); request
count honored; audit line per real request; evidence integrity (content-addressed hash matches); malformed
input (bad base_request/JSON); missing success_signature → hard error; invalid success_signature → hard error;
missing conditions → hard error; determinism failure → necessity suppressed; confounder detection →
inconclusive; intervention/network failure → recorded, not a false verdict; replication count honored; DB
consistency (trials/verdicts FK-consistent); **local bookkeeping tools cannot bypass target safety** (they send
no requests; senders always gate); cleanup on failure (partial run marks `incomplete`, no dangling state).

## 11. Regression testing  (§11)
Existing suite (`pytest tests/`, ~40+ test files incl. `test_case_store.py`, `test_idor_sweep.py`,
`test_scope_gate_hook.py`, `test_budget_guard.py`, `test_audit_log.py`, `test_scope_guard.py`) is the regression
harness. G1 requires it green with pass-count ≥ the A3 baseline. **Documented coverage gaps (do not pretend
otherwise):** there is **no automated end-to-end test of full multi-agent hunting** (agents are markdown +
live tools); MCP-server *process* startup is not exercised in CI beyond import/smoke. Phase 1 mitigates by not
changing agent logic and by smoke-importing `case-mcp/server.py`. Memory/reporting subsystems have unit tests
(`test_*`) but no integration harness — Phase 1 does not touch them, so regression risk is low but coverage is
partial; flagged, not papered over.

## 12. Performance / non-regression  (§12)
Three configs on a fixed localhost scenario: **A** CEM absent, **B** CEM installed but not invoked, **C** CEM
actively run on N confirmed findings. Measure wall-clock, HTTP request count, intervention/replication counts,
DB/evidence growth, CPU/mem where cheaply available (model tokens N/A in Phase 1 — no model calls).
**Critical requirement:** B (installed-inactive) must not materially slow the normal path — thresholds are
**derived from the A3 baseline**, not invented: define "material" as **B wall-clock ≤ A × 1.02** for the normal
hunting scenario (import/registration overhead only) and **zero extra HTTP requests in config B**. C's cost is
reported (not bounded) since CEM is opt-in post-validation. If a threshold needs a firmer number, capture the
A baseline first (A3), then set it.

## 13. Pass/fail gates  (§13)
- **G0** — plan approved + UD-1..UD-4 resolved. *(precedes all.)*
- **G1** existing regression suite passes (≥ A3 baseline).
- **G2** Phase-1 unit tests pass.
- **G3** Phase-1 integration tests pass.
- **G4** ground-truth benchmark labels all match.
- **G5** **FCCR == 0** on the benchmark.
- **G6** scope/rate/budget/audit tests pass.
- **G7** no meaningful normal-path regression (config B within §12 threshold).
- **G8** no unreviewed deviation from PHASE1-PLAN.md (deviations documented + approved here).
- **G9** benchmark cleanup / environment isolation succeeds (no lingering process/port; ground-truth checksum
  unchanged).

**On any gate failure:** the corresponding task becomes `[!] BLOCKED`; implementation of *dependent* tasks
stops; independent tasks may proceed. A failed gate is reported to the human with evidence (per
`superpowers:verification-before-completion`), and **no acceptance test may be weakened or deleted to pass**
(rule from ROADMAP §Standing rules). G5/G8/O1 failures always require human review before continuing.

## 14. One-command verification  (§14)
`bash scripts/verify-phase1.sh` runs: prerequisite validation → start isolated target → unit → integration →
security → causal benchmark → FCCR calc → regression → performance → cleanup → `phase1-report.json` +
human summary. Exit non-zero if any gate G1–G9 fails. The implementer runs this before claiming Phase 1
complete (and it is what P1 checks). Document the exact invocation in `docs/cem-phase1.md`.

## 15. Final security audit checklist  (§15, acceptance gate O1 — inspect CODE, not just tests)
Target isolation (localhost-only benchmark; no external egress) · scope enforcement (case-mcp in Tier-2; host
pinned from finding) · SSRF (perturbations cannot change target host) · URL handling (scheme allowlist,
no file://) · request controls (spacing, ceiling) · rate limiting (429→inconclusive) · budget enforcement
(inline enforce) · auditability (every real request logged + redacted) · evidence integrity (content-address
hash verified) · DB safety (parameterized SQL only; no string-built queries) · injection risks (no shell for
CEM; urllib only) · command execution (none introduced) · secrets handling (headers redacted in audit/bundle;
no token in evidence unredacted) · unsafe defaults (idempotent/GET default; k≥3; refuse missing oracle) ·
failure handling (partial → incomplete, never false necessity) · cleanup (fixture teardown) · benchmark
isolation (ground-truth checksum gate).

## 16. Superpowers workflow (engineering process, NOT a project dependency)
Use during implementation (the repo remains runnable without Superpowers):
- **brainstorming** — already applied at spec time; re-invoke only if UD resolutions reopen design.
- **writing-plans** — this document (applied now).
- **using-git-worktrees** — A2 isolated branch/worktree.
- **test-driven-development** — mandatory for Groups B–G (Iron Law: failing test first).
- **subagent-driven-development** — recommended executor: fresh implementer subagent per task + per-task review
  + broad final review. (Falls back to **executing-plans** if no subagents.)
- **systematic-debugging** — for any failing gate (root-cause before fix).
- **requesting-code-review / receiving-code-review** — after each task and a broad review before P1.
- **verification-before-completion** — no gate/status claim without fresh command output (blocks G-claims).
- **finishing-a-development-branch** — after P1 green, present integration options (do NOT auto-merge to main).
Do not force a skill where inappropriate; do not alter architecture to fit a skill.

## 17. Future intelligence allocation — NOT in Phase 1
No model routing / selection / frontier escalation / cost-based model decisions / CEM-driven routing in Phase 1
(per INTELLIGENCE-ALLOCATION-MEMO.md, Phase 5 hypothesis). **Optional zero-impact future instrumentation
(document only, do not build unless trivially free):** CEM already writes structured `cem_trials`/`cem_verdicts`
with per-request cost-shaped fields (counts, timings) — that is sufficient for later passive efficiency analysis
without any Phase-1 behavior change. Signatures are **not assumed to transfer** across targets. This must not
expand Phase-1 scope.

## 18. Future-compatibility constraints (lightweight only)
- CEM outputs machine-readable (JSON bundle + typed DB rows). · Evidence/signatures structured + content-
  addressed. · No model/provider logic coupled into `cem_engine` (stays pure; `model_gateway` untouched). ·
  Future variant discovery (Phase 4) can consume `cem_verdicts` + minimal sets as-is. · Future intelligence
  allocation (Phase 5) can observe `cem_trials` metadata without schema change. · No hard-coded future model
  strategy. Do not design future phases here.

---

## 19. CURRENT EXECUTION STATE  (implementer updates after each milestone)

```
CURRENT MILESTONE:     Phase 1a COMPLETE & verified; G0 human implementation approval GRANTED; Group A
                       COMPLETE (A1-A4); Group B (schema) COMPLETE (B1-B3); Group C (CEM engine) COMPLETE —
                       C1 DONE (SuccessSignature/evaluate_signature), C2 DONE (determinism_gate), C3 DONE
                       (classify), C4 DONE (classify_race), C5 DONE (minimal_condition_sets), C6 DONE
                       (find_alternate_condition_sets), C7 DONE (minimize_poc), C8 DONE (assemble_bundle).
                       Group C is now fully complete; Group D (intervention executor) not yet started.
COMPLETED TASKS:       A1 (decisions), A2 (isolated worktree/branch — confirmed pre-existing, not on main),
                       A3 (baseline), A4 (http_probe.py extraction), B1 (CEM-schema tests), B2 (CEM tables +
                       CRUD helpers in case_store.py), B3 (cascade-delete + deeper per-engagement isolation
                       tests), C1 (SuccessSignature + evaluate_signature), C2 (determinism_gate +
                       DeterminismResult), C3 (classify — verdict classifier), C4 (classify_race — race/TOCTOU
                       probabilistic path), C5 (minimal_condition_sets — ddmin for one 1-minimal set), C6
                       (find_alternate_condition_sets — alternates + interaction detection), C7 (minimize_poc
                       — PoC minimization + determinism re-validation), C8 (assemble_bundle — Triager-Proof
                       Bundle assembly, 15 §2.8 fields + finding_id, redacted via a new _redact_recursive
                       helper), H1 (target), H2 (ground truth+ fixture); Phase 1a A1-A4 + B1-B3 (blind
                       manifest / answer-key split / independent evaluator / harness security / evidence
                       trail / mutation target / metrics)
IN-PROGRESS TASK:      (none — C8 complete/verified via subagent-driven-development, review clean; D1 not yet started)
BLOCKED TASKS:         (none)
FILES CHANGED (A4):    mcp-servers/http_probe.py (NEW — FetchResult, build_headers(), fetch(),
                       DEFAULT_TIMEOUT_S; extracted verbatim from idor_sweep.py, no mechanics changed);
                       mcp-servers/idor-mcp/idor_sweep.py (MOD — now imports FetchResult/build_headers/fetch
                       from http_probe as _fetch/_build_headers/FetchResult/DEFAULT_TIMEOUT_S, preserving every
                       module-level name test_idor_sweep.py and idor-mcp/server.py depend on; inline
                       def/dataclass bodies removed, no other line changed); tests/test_http_probe.py (NEW,
                       10 tests, real loopback HTTP server, no mocked _fetch)
FILES CHANGED (B1):    tests/test_cem_case_store.py (NEW, 19 tests — schema contract only; no production code
                       touched, `case_store.py` NOT modified this task)
FILES CHANGED (B2):    mcp-servers/case_store.py (MOD — 4 CEM tables added to `_init_schema()`; `CEM_TRIAL_ARMS`/
                       `CEM_VERDICTS` constants added; `cem_define`/`cem_record_trial`/`cem_record_verdict`/
                       `cem_load_state` helpers added; module docstring's schema list updated); docstring/tests
                       reference in tests/test_cem_harness_security.py updated (see KNOWN DEVIATIONS) — one
                       obsolete-by-design test removed with explicit human approval, no other test touched.
FILES CHANGED (B3):    tests/test_cem_case_store.py (MOD — 6 new tests appended, 19→25 total; no other file
                       touched, case_store.py NOT modified this task — B2's implementation already satisfied
                       B3's requirements).
FILES CHANGED (C1):    mcp-servers/cem_engine.py (NEW — first CEM production module: SimilarityToBaseline,
                       SuccessSignature, SuccessSignature.from_dict(), evaluate_signature()); tests/
                       test_cem_engine.py (NEW, 31 tests).
FILES CHANGED (C2):    mcp-servers/cem_engine.py (MOD — added DeterminismResult, determinism_gate(), FetchFn
                       type alias; module docstring updated); tests/test_cem_engine.py (MOD — 18 new C2 tests
                       appended, 31→49 total; module docstring updated; no C1 test changed).
FILES CHANGED (C3):    mcp-servers/cem_engine.py (MOD — added VERDICT_* constants, _validate_hit_sequence()
                       helper, classify(); module docstring updated); tests/test_cem_engine.py (MOD — 18 new
                       C3 tests appended, 49→67 total; module docstring updated; no C1/C2 test changed).
FILES CHANGED (C4):    mcp-servers/cem_engine.py (MOD — added VERDICT_PROBABILISTIC constant, RaceResult
                       dataclass, classify_race(); module docstring updated); tests/test_cem_engine.py (MOD —
                       15 new C4 tests appended, 67→82 total; module docstring updated; no C1/C2/C3 test
                       changed).
FILES CHANGED (C5):    mcp-servers/cem_engine.py (MOD — added MinimalSetResult dataclass,
                       minimal_condition_sets(); module docstring updated); tests/test_cem_engine.py (MOD —
                       21 new C5 tests appended, 82→103 total; module docstring updated; no C1-C4 test
                       changed).
FILES CHANGED (C6):    mcp-servers/cem_engine.py (MOD — added itertools import, VERDICT_INTERACTING
                       constant, InteractionEvidence + AlternateSetsResult dataclasses,
                       find_alternate_condition_sets(); module docstring updated); tests/test_cem_engine.py
                       (MOD — 27 new C6 tests appended, 103→130 total; module docstring updated; no C1-C5
                       test changed).
FILES CHANGED (C7):    mcp-servers/cem_engine.py (MOD — added PocMinimizationResult dataclass,
                       minimize_poc(); module docstring updated); tests/test_cem_engine.py (MOD — 17 new C7
                       tests appended, 130→147 total; module docstring updated; no C1-C6 test changed).
FILES CHANGED (C8):    mcp-servers/cem_engine.py (MOD — added assemble_bundle() + private
                       _redact_recursive() helper; `from redact import redact_text` is the only new import;
                       module docstring updated); tests/test_cem_engine.py (MOD — 27 new C8 tests appended,
                       147→174 total; no C1-C7 test changed). This was also the FIRST git commit of both
                       files (they had been untracked in this worktree since C1) — commit 8ac2eb9 therefore
                       contains all of C1-C8, not a C8-sized diff; verified via `git status` that no other
                       file (case_store.py, idor_sweep.py, http_probe.py, PHASE1-EXECUTION-PLAN.md,
                       test_cem_case_store.py, test_http_probe.py) was staged alongside it.
TESTS PASSING:         869 passed, 0 failed (full suite; independently re-verified by the controller, not
                       just the implementer's report). Breakdown: 842 post-C7 + 27 new C8 tests = 869.
                       tests/test_cem_engine.py: 174/174 GREEN (147 C1-C7 + 27 C8; C8's RED-then-GREEN TDD
                       confirmed: ImportError for assemble_bundle before implementation, then implemented —
                       all 27 passed on first run). tests/test_cem_case_store.py: 25/25 GREEN, unmodified.
                       tests/test_case_store.py: 36/36 green, unmodified. tests/test_http_probe.py: 10/10
                       green. ruff clean on both cem_engine.py (mcp-servers/) and test_cem_engine.py
                       (tests/) — independently re-verified by the controller via
                       `.venv/bin/ruff check mcp-servers/cem_engine.py tests/test_cem_engine.py`.
BENCHMARK STATUS:      Unchanged from Phase 1a hardening. CEM assertion/FCCR gates still PENDING (no engine yet).
SECURITY AUDIT STATUS: Unchanged; O1 (code audit) remains post-CEM-engine.
KNOWN DEVIATIONS:      RESOLVED UD-1..UD-4 (unchanged). A4 implementation note: DEFAULT_TIMEOUT_S/FetchResult/
                       build_headers/fetch live in http_probe.py; idor_sweep.py re-exports them under their
                       original private names (_fetch/_build_headers) rather than renaming call sites, per
                       "smallest behavior-preserving extraction" — this is the D2/UD-1=B design as specified,
                       not a new deviation. B1 implementation note: isolation tests use two explicit db_path
                       values (tmp_path-based), matching test_case_store.py's existing pattern exactly, rather
                       than monkeypatching engagement_paths (which test_case_store.py does not actually do,
                       despite PHASE1-PLAN.md §E's prose suggesting it) — not a deviation from the plan's
                       intent (isolation is verified), just from one sentence of loosely-worded prose; the
                       actual repo convention was followed. B2 DEVIATION (human-approved 2026-09-04 via
                       AskUserQuestion): tests/test_cem_harness_security.py::test_no_cem_production_logic_exists
                       (a Phase-1a pre-G0 "no CEM production code yet" tripwire) was deleted after it correctly
                       failed once B2 legitimately added CEM symbols to case_store.py under granted G0
                       approval — its guarded precondition no longer holds by design. I stopped and reported
                       this rather than editing it unilaterally; the human chose "retire it now" from 4
                       options. The other 5 tests in that file (loopback-only, tamper detection, benchmark-
                       blindness) are untouched. No protected benchmark ground truth (answer_key.py,
                       scenarios.py, ground_truth.py, evaluator.py) was touched. CRUD helper cascade-delete
                       runtime behavior and MCP-tool-level guards (CONFIRMED-state check, missing/invalid
                       success_signature hard-error) intentionally NOT added in B2 — cascade-delete is B3's own
                       acceptance criterion; MCP-tool guards are E3's scope. B2 does enforce UD-3 (non-empty
                       success_signature) at the persistence layer since cem_define is the one function that
                       writes it. B3 implementation note: all 6 new tests passed on first run against the
                       existing B2 implementation — no production code change was needed (B2's schema + CRUD
                       already correctly satisfied cascade-delete and deep isolation). This was verified
                       non-vacuous via an ephemeral, uncommitted spike (PRAGMA foreign_keys=OFF) proving the
                       same delete leaves an orphaned cem_meta row without FK enforcement, so the new test
                       would genuinely catch a regression, not just pass trivially. No case_store.py delete-
                       finding API was added (B3's own file column in this plan lists only
                       test_cem_case_store.py) — deletion in tests goes through _get_conn() directly via a
                       small test-local helper, same precedent as B1's raw-SQL schema checks. C1 CONTRACT
                       AMBIGUITY (human-approved 2026-09-05 via AskUserQuestion, not guessed): PHASE1-PLAN.md
                       D5's `similarity_to_baseline >= t` shorthand reads as a bare threshold, but
                       evaluate_signature is documented everywhere as strictly 2-arg (FetchResult, sig) — a
                       similarity check needs two bodies, and nothing in the plan says where the second comes
                       from. Resolved: similarity_to_baseline is a nested `{body, threshold}` object embedded
                       in the signature itself (the human's chosen option, of 4 presented), keeping
                       evaluate_signature strictly 2-arg and self-contained. C1 TRY004 fix: ruff flagged 3
                       ValueError-for-type-mismatch spots in cem_engine.py; fixed to TypeError consistently
                       across the whole file (not just the 3 flagged lines) — TypeError for wrong type,
                       ValueError for right-type-wrong-value (empty status_in list, out-of-range threshold,
                       invalid regex syntax, unknown dict key, zero-matchers-set). 5 tests updated to match.
                       C2 implementation note: determinism_gate's params (success_signature, fetch_fn) go
                       beyond the plan's shorthand `determinism_gate(base_request, k)` line — both are
                       structurally required (an oracle to classify HIT/MISS; a fetch mechanism to call, per
                       this task's own explicit instruction to inject one) and were resolved without a
                       stop-and-ask, unlike C1's genuine ambiguity, because there was no logical conflict to
                       arbitrate — just an implementation detail within the task's own explicit request. Two
                       ruff style fixes applied (both pre-existing-pattern, not novel): `from typing import
                       Callable` → `from collections.abc import Callable` (UP035); an unused unpacked loop
                       variable prefixed `_timeout_s` (RUF059, test file only). C3 scope-boundary decision
                       (human-approved 2026-09-05, stopped and asked rather than guessed): 429/throttle
                       detection is NOT classify()'s job — belongs to the executor (task D3). classify()'s
                       literal 3-arg signature (baseline_hits, perturbed_hits, k) has no throttle channel, and
                       a plain bool can't distinguish "oracle mismatch" from "rate-limited" — pinned down with
                       a dedicated signature-introspection test so a later task can't silently widen it. C4 API
                       AMBIGUITY (human-approved 2026-09-05 via AskUserQuestion, not guessed): PHASE1-PLAN.md's
                       C4 line ("race/TOCTOU path → `probabilistic` (report perturbed HIT-rate; never
                       `necessary`)") names no function/signature, unlike C1/C2/C3 which each named their exact
                       function. Resolved: a new, separate `classify_race(perturbed_hits, k) -> RaceResult`
                       function (the human's chosen option, of 4 presented) rather than widening classify()'s
                       C3-pinned 3-arg signature; no baseline_hits (plan wording only ever says "report
                       perturbed HIT-rate"); no boolean race flag — being routed to this dedicated function at
                       all is treated as the race flag itself, consistent with C1-C3's pattern of one pure
                       function per concern rather than mode-flag branching. C5 API AMBIGUITY (human-approved
                       2026-09-05 via AskUserQuestion, not guessed): PHASE1-PLAN.md names ddmin's
                       interestingness property precisely but no concrete pure engine-layer function
                       signature (only the DB-backed orchestration-level minimal_condition_sets(finding_id),
                       a later E1 task). Resolved (the human's chosen option, of 3 presented): an injected
                       pure predicate is_interesting: Callable[[frozenset[str]], bool], strictly bool — no
                       inconclusive/tri-state channel invented, matching the plan's own binary "interesting"
                       definition; a non-bool predicate return is a hard TypeError. C5 ruff fix: removed 9
                       # noqa: E731 comments (RUF100 "unused noqa" — E731 is not an enabled rule in this
                       repo's ruff config, unlike C1's TRY004-driven fix which changed real exception types).
NEXT EXACT TASK:       D1 — `Controls` dataclass + pinning helpers (session headers, cache-buster, ordering,
                       spacing_ms, concurrency=1; uncontrollable confounder → recorded, forces inconclusive),
                       in cem_engine.py. Deps: C1 ✔. Verify: pytest. Accept: uncontrolled confounder →
                       inconclusive. NOT yet started. Group C (C1-C8) is now fully complete.
LAST VERIFICATION CMD: python3 -m pytest tests/ -q  (869 passed, 0 failed) — run independently by the
                       controller after the implementer's own run, not taken on report alone.
LAST VERIFICATION RESULT: C8 GREEN, executed via `superpowers:subagent-driven-development` (fresh
                       implementer subagent + independent task-reviewer subagent, both on a standard model,
                       both dispatched by the controller — first task in this plan run through the SDD
                       ledger/review process rather than direct single-session implementation; ledger at
                       `.superpowers/sdd/PHASE1-EXECUTION-PLAN/progress.md`). All 27 new tests in
                       test_cem_engine.py pass (174/174 total), RED-then-GREEN TDD confirmed (ImportError:
                       cannot import name 'assemble_bundle' before implementation). No existing C1-C7 test
                       modified/weakened. Task reviewer (independent subagent, diff-only, did not trust the
                       implementer's report) verified every one of the 15 §2.8 field-derivation rules
                       individually against the code, the exact 12-parameter signature ruling, the
                       redaction helper's placement/behavior, and every global constraint (MCP/network-free,
                       reuse-not-rederive, additive-only, ground_truth untouched) — verdict: Approved, 0
                       Critical, 0 Important, 2 Minor deferred (literal "necessary" string instead of the
                       VERDICT_NECESSARY constant in one test; no validation on 9 of 12 params, matching the
                       brief's own explicit scope). No fix loop needed — clean on first review pass.
                       test_cem_case_store.py 25/25, test_case_store.py 36/36, test_http_probe.py 10/10, all
                       unmodified. ruff clean on both cem_engine.py and test_cem_engine.py, zero fixes
                       needed — independently re-verified by the controller, not just reported. No protected
                       benchmark file touched. No real network call, no DB write, no MCP tool, no C1-C7
                       modification (DeterminismResult/AlternateSetsResult/PocMinimizationResult/
                       VERDICT_NECESSARY all reused verbatim, proven via monkeypatch that no C1-C7 function
                       or http_probe.fetch is called) — pure bundle assembly + redaction only, exactly C8's
                       scope. bash scripts/verify-phase1.sh not run this task (C8 adds no CEM
                       execution/MCP-tool behavior); full verify-phase1.sh remains the P1 gate.
                       HANDOFF NOTE for the next session: mcp-servers/case_store.py, mcp-servers/idor-mcp/
                       idor_sweep.py, mcp-servers/http_probe.py, tests/test_cem_case_store.py, tests/
                       test_http_probe.py all carry substantial, already-tested, already-green A4/B1-B3 work
                       that predates this session and has NOT been committed to git (only cem_engine.py +
                       test_cem_engine.py, covering C1-C8, are committed so far, in 8ac2eb9). This was
                       flagged to the human rather than committed unilaterally, since committing it was
                       outside this session's C8-only scope.
```

A brand-new session resumes by reading, in order: **ROADMAP.md → PHASE1-PLAN.md → PHASE1-EXECUTION-PLAN.md**
(this file, especially §19 and §6), with no conversation memory required.

---

## 20. Plan consistency audit (self-check performed while writing)

- Every PHASE1-PLAN.md requirement maps to a task: conditions/oracle→C1/B; determinism gate→C2; one-var
  interventions→D2; replicated arms→D2/C3; confounders→D1/C3; multiple minimal sets→C5/C6; interactions→C6;
  race→C4; PoC minimization-after-causal→C7; audit→E2/G1; scope/rate/budget→E2/F1/F2/D3; benchmark→H/K;
  FCCR gate→K2/G5; no-hot-path-slowdown→M1/G7. ✔
- Every task has a verification method + acceptance criterion. ✔
- Every target-touching op has safety coverage (F, §10). ✔
- Ground truth protected (checksum gate, no engine import path). ✔
- Benchmark + testing run automatically (§7, §14). ✔
- Regression (L1/G1) + performance (M1/G7) covered; coverage gaps documented (§11). ✔
- Final security audit is a gate (O1). ✔
- Acceptance gates explicit (G0–G9). ✔
- Session recovery possible (§19 + ROADMAP PROJECT STATE). ✔
- Future phases not implemented (§17, §18 constraints only). ✔
- Model routing has NOT leaked into Phase 1 (§17). ✔
- CEM methodology not weakened (determinism gate, replicated arms, verdicts intact). ✔
- No unnecessary deps/architecture (stdlib + existing primitives; ≤1 new shared module). ✔

**Open gaps requiring human input:** NONE — UD-1..UD-4 resolved (§2). The only remaining precondition to
implementation is the human G0 approval; no unresolved design decision or scope conflict remains.
