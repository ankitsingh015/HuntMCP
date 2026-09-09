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

> **RECOVERY STATUS (completion effort, updated 2026-09-07):** the B1–B3 work performed in an earlier session
> lived only as uncommitted changes in the `phase1-cem-implementation-6e1693` worktree (branch
> `claude/phase1-cem-implementation-6e1693`, HEAD `e1b9644`). This effort recovered it one task at a time, and
> **Group B (B1 + B2 + B3) is now fully recovered and verified on this branch** (`claude/cem-phase-1-completion-1a5cd5`):
> B1 = 4-table CEM schema in `_init_schema()` + 19 schema-contract tests; B2 = `CEM_TRIAL_ARMS`/`CEM_VERDICTS`
> constants + the 4 CRUD helpers `cem_define`/`cem_record_trial`/`cem_record_verdict`/`cem_load_state`; B3 = the
> 6 cascade-delete + deep-isolation tests (+ `_full_cem_state`/`_cem_row_counts`/`_delete_finding` helpers),
> `tests/test_cem_case_store.py` now 25 tests. `mcp-servers/case_store.py` is byte-identical to the
> `phase1-cem-implementation-6e1693` copy except two disclosed doc-comment lines; `tests/test_cem_case_store.py`
> is byte-identical to the recovered copy except its module docstring (adapted per B1/B3 across this effort).
> **Nothing from Group B is committed to `main`** — it lives as uncommitted working-tree changes on this branch.
> Each prior-session `DONE` paragraph is retained as a history record; the `[x]` marker reflects this branch's
> actual state. Next dependency: D1.

- [x] **B1** — 4 CEM tables in `_init_schema()` + schema-contract tests + isolation. | A2 | case_store.py, test_cem_case_store.py | verify: `pytest tests/test_cem_case_store.py` | accept: 19 green; `test_case_store.py`/`test_cem_engine.py` unchanged. **RECOVERED & VERIFIED 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`)** — `tests/test_cem_case_store.py` (NEW, 19 schema-contract tests) written first, confirmed RED on this branch (`sqlite3.OperationalError: no such table` / column-set `AssertionError` — the 4 CEM tables did not exist here); then the 4 `CREATE TABLE IF NOT EXISTS` statements (`cem_meta`/`cem_conditions`/`cem_trials`/`cem_verdicts`) added to `case_store._init_schema()` **byte-for-byte identical** to the `phase1-cem-implementation-6e1693` uncommitted work (verified via a targeted DDL diff) + a schema paragraph in the module docstring. 19/19 GREEN. Scope held to B1: **no** `CEM_TRIAL_ARMS`/`CEM_VERDICTS` constants and **no** CRUD helpers recovered (those are B2 — cleanly separable: the DDL references neither, and the recovered B1 tests use only `_get_conn`/`create_finding` + raw SQL + `PRAGMA`, never the helpers); the recovered file's B3 section (6 CRUD-dependent tests + `_full_cem_state`/`_cem_row_counts`/`_delete_finding` helpers) excluded. Terminology cross-checked against C1–C8 (`cem_engine.py`): `verdict` set, `arm` set, `determinism_status` lifecycle, `success_signature`/`base_request` JSON shapes all consistent — no conflict. Test-module docstring reworded (only) to drop the prior session's "deliberately RED until B2" framing, since on this branch B1 lands schema + contract tests together; all test bodies + the 5 PRAGMA helpers are verbatim from the recovered work. `ruff check` clean on both changed files. `test_case_store.py` 36/36 unmodified, `test_cem_engine.py` 211/211 unmodified. Full suite **911 passed** (892 pre-B1 baseline + 19 new), 0 failures, 0 regressions. No protected benchmark file (`answer_key.py`/`scenarios.py`/`ground_truth.py`/`evaluator.py`/`integrity.py`) touched. No commit.
  <br>**Prior-session B1 history record (test-file-only, per the original plan's B1/B2 split; not on mainline):** **DONE 2026-09-04 — `tests/test_cem_case_store.py` created (19 tests): table-exists + exact-column-set + primary-key checks for all 4 tables (`cem_meta`, `cem_conditions`, `cem_trials`, `cem_verdicts`) per §4's schema; `cem_meta` defaults (`determinism_status='UNTESTED'`, `cem_status='DEFINED'`, `k=5`, `incomplete=0`); schema-level FK-to-`findings(id)`-`ON DELETE CASCADE` check per table (parametrized); two per-engagement isolation tests (`cem_meta`, `cem_conditions` rows never visible from a second engagement's case.db), following test_case_store.py's existing explicit-`db_path`-via-`tmp_path` isolation pattern. All 19 RED for the single correct reason — schema not yet added by B2 (`AssertionError` on empty column sets / missing table names; `sqlite3.OperationalError: no such table` on the two INSERT-based tests). `ruff check` clean. Full suite: 671 passed (unchanged) + 19 new RED = 690 collected, 0 unexpected failures/regressions. CRUD helpers and cascade-delete runtime behavior intentionally deferred to B2/B3.**
- [x] **B2** — `CEM_TRIAL_ARMS`/`CEM_VERDICTS` constants + CRUD helpers (`cem_define`/`cem_record_trial`/`cem_record_verdict`/`cem_load_state`) in `case_store.py`. | B1 | case_store.py | verify: `pytest tests/test_cem_case_store.py` + `test_case_store.py` + ephemeral CRUD smoke | accept: 19 + 36 green; helpers execute correctly. **RECOVERED & VERIFIED 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`)** — the `CEM_TRIAL_ARMS`/`CEM_VERDICTS` constants (near `EVIDENCE_TYPES`) and the 4 CRUD helpers (new `# ---- CEM (Phase 1)` section at EOF) recovered **byte-for-byte** from the `phase1-cem-implementation-6e1693` worktree; the only delta is one stale comment line (`-- that's cem_engine.py's job (task C/D), not yet implemented.` → `… (task C/D; C1-C8 implemented, D pending).`, since `cem_engine.py` C1–C8 exists on this branch). No other code changed. Depends only on the already-present `_get_conn`/`_row_exists`/`_missing_fk_error`/`import json` — no new plumbing. After B2, `mcp-servers/case_store.py` (723 lines) is byte-identical to the recovered copy except that comment line + B1's docstring-paragraph wording. Scope held to B2: **no B3 tests added** (the permanent CRUD tests — `_full_cem_state`/`_cem_row_counts`/`_delete_finding` + 6 cascade/isolation tests — are B3, and B3's own file column lists only `test_cem_case_store.py`). Verification: B1's 19 schema tests still 19/19; `test_case_store.py` 36/36 unmodified; `test_cem_engine.py` 211/211 unmodified; full suite **911 passed**, 0 regressions; `ruff check` clean (no new `case_store.py` findings in the CI-exact `ruff check mcp-servers/` run); `py_compile` clean. An **ephemeral, uncommitted** direct-execution smoke (18 checks) exercised: `cem_define` happy path / one-shot rejection / UD-3 empty-signature rejection / unknown-finding FK error; `cem_record_trial` baseline+perturbed insert / invalid-arm rejection / bad-`condition_id` FK error; `cem_record_verdict` happy path / invalid-verdict rejection; `cem_load_state` full round-trip (JSON fields decoded back to dicts, defaults present, 2 conditions / 2 trials / 1 verdict, per-row `perturbation`/`controls` decoded) / no-state `{"error": …}`. All 18 passed. No protected benchmark file touched. No commit.
  <br>**Prior-session B2 history record (per the original plan's B1/B2 split — schema + CRUD in one task; not on mainline):** **DONE 2026-09-04 (prior session; not on mainline — see box above) — 4 CEM tables added to `_init_schema()` verbatim per §4's "final" schema (only a `finding_id → findings(id) ON DELETE CASCADE` FK per table, no invented `condition_id` FK, matching the plan's exact DDL). CRUD helpers `cem_define`/`cem_record_trial`/`cem_record_verdict`/`cem_load_state` added, mirroring this file's existing conventions exactly (FK checks via `_row_exists`/`_missing_fk_error`, enum validation via new `CEM_TRIAL_ARMS`/`CEM_VERDICTS` constants alongside the existing `HYPOTHESIS_STATUSES`-style ones, `{"error": ...}` returns not exceptions). `cem_define` enforces UD-3 at the persistence layer (rejects empty/missing `success_signature` — never silently accepts a null oracle) and is one-shot per finding. All 19 B1 tests green. `test_case_store.py` 36/36 green, unmodified. CRUD helpers verified by direct execution (happy path, FK errors, enum rejection, UD-3 rejection, duplicate-define rejection, JSON round-trip through `cem_load_state`) since B1's tests only cover schema, not CRUD — not committed as a permanent test file (out of this task's stated verification scope), but run and its output inspected before claiming completion. DEVIATION (human-approved via AskUserQuestion this session): `tests/test_cem_harness_security.py::test_no_cem_production_logic_exists` — a Phase-1a pre-G0 tripwire asserting no CEM symbols exist in `case_store.py`/`case-mcp/server.py` — necessarily failed once B2 legitimately added those symbols under granted G0 approval. Retired (deleted) with the human's explicit sign-off after I stopped and reported it rather than editing unilaterally; module docstring updated to record why. The other 5 tests in that file (loopback-only, tamper detection, benchmark-blindness) are untouched and still green.**
- [x] **B3** — Cascade-delete + per-engagement isolation tests. | B2 | test_cem_case_store.py | verify: pytest | accept: deleting a finding removes its CEM rows; two engagements don't mix. **RECOVERED & VERIFIED 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`)** — the B3 section (`_full_cem_state`/`_cem_row_counts`/`_delete_finding` helpers + 6 tests: `test_deleting_finding_cascades_all_four_cem_tables`, `test_deleting_finding_leaves_sibling_finding_and_its_cem_state_intact`, `test_deleting_finding_with_no_cem_state_does_not_error`, `test_cem_load_state_never_mixes_engagements_even_with_same_finding_id`, `test_cem_record_trial_and_verdict_never_cross_engagements`, `test_deleting_finding_in_one_engagement_does_not_affect_the_other`) appended to `tests/test_cem_case_store.py` **byte-for-byte identical** to the `phase1-cem-implementation-6e1693` recovered work (verified via a full-section diff — 2 blank lines + both comment blocks + 3 helpers + 6 tests, zero deltas); the file's module docstring was updated (only) so its title/framing covers B1 + B3 rather than "B1, RED until B2". `tests/test_cem_case_store.py` now **25/25 GREEN**. No production code changed (B1+B2 already satisfy every B3 assertion). Non-vacuity proven by an ephemeral, uncommitted spike: deleting a finding via a `PRAGMA foreign_keys=OFF` connection leaves all 4 CEM tables with orphaned rows, so `test_deleting_finding_cascades_all_four_cem_tables` would fail against a real cascade regression. Verification: `test_case_store.py` 36/36 unmodified, `test_cem_engine.py` 211/211 unmodified; full suite **917 passed** (911 pre-B3 + 6 new), 0 failures, 0 regressions; `ruff check` + `py_compile` clean on the test file. No `case_store.py` change this task. No protected benchmark file touched. No commit.
  <br>**Prior-session B3 history record (not on mainline):** **DONE 2026-09-05 (prior session; not on mainline — see box above) — 6 new tests added to `tests/test_cem_case_store.py` (25 total in the file now). Cascade-delete: `test_deleting_finding_cascades_all_four_cem_tables` (deletes via `DELETE FROM findings`, proves via `cem_load_state` + a per-table row-count check that all 4 CEM tables — not just `cem_meta` — actually cascade, not just declare the FK), `test_deleting_finding_leaves_sibling_finding_and_its_cem_state_intact`, `test_deleting_finding_with_no_cem_state_does_not_error`. Deeper isolation: `test_cem_load_state_never_mixes_engagements_even_with_same_finding_id` (both engagements' own autoincrement sequences independently assign finding id=1 — the real isolation risk — and their content never mixes), `test_cem_record_trial_and_verdict_never_cross_engagements`, `test_deleting_finding_in_one_engagement_does_not_affect_the_other`. All 6 built through the real public CRUD surface (`cem_define`/`cem_record_trial`/`cem_record_verdict`/`cem_load_state`) rather than raw SQL, per the black-box instruction — raw SQL used only for the per-table row-count proof and the delete itself, where no public accessor exists (mirrors B1's own precedent). All 6 passed on first run against the existing B2 implementation — no production code changed; verified non-vacuous by an ephemeral (uncommitted) spike proving the same delete leaves an orphaned row when `PRAGMA foreign_keys=OFF`, i.e. the test would have caught a real regression. Full `test_cem_case_store.py` 25/25, `test_case_store.py` 36/36 unmodified, ruff clean, full suite 695 passed. No protected benchmark file (`scenarios.py`/`answer_key.py`/`evaluator.py`/`integrity.py`/`ground_truth.py`) touched.**

### C. CEM engine (pure logic, TDD)
- [x] **C1** — `SuccessSignature` + `evaluate_signature(FetchResult, sig)` (status set / body substring / regex / similarity-to-baseline). Oracle is **caller-supplied only** (UD-3). | A4 | cem_engine.py, test_cem_engine.py | verify: pytest | accept: matcher covers each case; **no code path auto-derives the oracle from a baseline response.** **DONE 2026-09-05 — `mcp-servers/cem_engine.py` created (first CEM production module). `SimilarityToBaseline(body, threshold)` + `SuccessSignature(status_in, body_contains, body_regex, similarity_to_baseline)` dataclasses; `SuccessSignature.from_dict()` bridges the JSON shape `case_store.cem_define`/`cem_load_state` already use; `evaluate_signature(FetchResult, SuccessSignature) -> bool`, pure/deterministic, AND-semantics across whichever fields are set, `.error`-carrying FetchResult never satisfies any signature. Validation lives in `__post_init__` (both direct construction and `from_dict` funnel through it) so an empty/all-None signature is refused everywhere, never silently treated as always-true (UD-3). CONTRACT AMBIGUITY — stopped and asked rather than guessed (see KNOWN DEVIATIONS): `similarity_to_baseline` resolved as a nested `{body, threshold}` object embedded in the signature, human-approved 2026-09-05. TDD: `tests/test_cem_engine.py` written first (31 tests), confirmed RED (`ModuleNotFoundError: No module named 'cem_engine'`), then implementation added, 31/31 GREEN on first pass. `ruff check mcp-servers/` flagged 3 real TRY004 issues (ValueError used where TypeError is correct for a type-mismatch, vs ValueError for a value-range/shape issue) — fixed properly and consistently across the whole file, not just the 3 flagged lines, with 5 tests updated to expect the corrected exception type. `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, full suite 726 passed (695 + 31 new), ruff clean on both new files. No CEM database write, no network call, no MCP tool, no determinism gate, no perturbation/execution logic — pure oracle-evaluation only, exactly C1's scope.
  **RETROSPECTIVE AUDIT FIX (later session, 2026-09-05):** an independent audit of C1-C8 found that "at least one matcher set" (the check above) was not the same guarantee as "no matcher can be vacuously always-true" — `body_contains=""` (`"" in body` is `True` for every body) and `similarity_to_baseline.threshold<=0.0` (`SequenceMatcher.ratio()` is never negative) both passed construction while `evaluate_signature` always returned `True` regardless of the target's real response, confirmed live against the actual code. Fixed with TDD (5 new tests, RED confirmed, then GREEN): `body_contains == ""` now raises `ValueError`; `SimilarityToBaseline.threshold`'s valid range narrowed from `[0.0, 1.0]` to `(0.0, 1.0]`. No other C1 behavior changed — `evaluate_signature`'s AND-semantics, the 4-matcher contract, and every original C1 test are untouched. **Still open, out of this fix's scope:** `body_regex=""` remains a third, unfixed vacuous-oracle vector (confirmed live it still constructs and always matches) — not part of what was approved to fix in that audit round.**
- [x] **C2** — `determinism_gate(base_request, k)` using a fake fetch: STABLE iff all-k HIT; else NONDETERMINISTIC. | C1 | cem_engine.py | verify: pytest | accept: mixed baseline → NONDETERMINISTIC. **DONE 2026-09-05 — `determinism_gate(base_request, k, success_signature, fetch_fn) -> DeterminismResult` added to `mcp-servers/cem_engine.py`. `success_signature`/`fetch_fn` weren't in the task's shorthand 2-arg line but are structurally required (HIT needs an oracle; a fetch needs a fetch mechanism) — same precedent as D2's shorthand omitting `budget_cb` while its detailed design section requires it; not treated as ambiguous since the task itself explicitly required "an injected/fake fetch mechanism." `fetch_fn` matches `http_probe.fetch`'s exact signature `(url, method, headers, body, timeout_s) -> FetchResult` (positionally compatible so a later task's production wiring can pass `http_probe.fetch` directly, zero adapter code — UD-1 anti-duplication rule) rather than inventing a new callable shape. `DeterminismResult(status, hits, k)` — strict binary `STABLE`/`NONDETERMINISTIC`, no third bucket for "consistently MISSing" or "all fetch errors" (both verified `NONDETERMINISTIC` by explicit test, per "do not silently expand the definition of determinism"). No spacing/Controls/confounder-pinning added (that's D1/D2). TDD: `tests/test_cem_engine.py` extended with 18 C2 tests, written first, confirmed RED (`ImportError: cannot import name 'DeterminismResult'`), then implemented, 49/49 (31 C1 + 18 C2) GREEN — no existing C1 test modified/weakened. Explicitly tests: all-k HIT, one/alternating/all miss, k=1, invalid k (zero/negative/non-int/bool), exact k call count, base_request fields passed through correctly, gate-classification determinism (both STABLE and NONDETERMINISTIC cases), fetch-error trials counted as MISS not a new status, and — via `monkeypatch.setattr(http_probe, "fetch", <raises>)` — proof `determinism_gate` never calls the real `http_probe.fetch`. Full suite 744 passed (726 + 18), `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, all unmodified. ruff clean on both files after two minor autofix-adjacent style corrections (see KNOWN DEVIATIONS).**
- [x] **C3** — `classify(baseline_hits, perturbed_hits, k)` → verdict rules (necessary/apparently_not_necessary/inconclusive; throttle→inconclusive; mixed→inconclusive). | C1 | cem_engine.py | verify: pytest | accept: every rule row from PHASE1-PLAN §D covered. **DONE 2026-09-05 — `classify(baseline_hits, perturbed_hits, k) -> str` added to `mcp-servers/cem_engine.py`, exactly the literal 3-arg signature (no extra params, unlike C2). Implements all 4 unanimity rules from PHASE1-PLAN.md §D: baseline not all-HIT → `inconclusive`; perturbed all-MISS (baseline all-HIT) → `necessary`; perturbed all-HIT (baseline all-HIT) → `apparently_not_necessary`; perturbed mixed (baseline all-HIT) → `inconclusive`. Returns exactly one of 3 verdict strings, never a 4th (interacting/probabilistic are separate later tasks C4/C6). SCOPE-BOUNDARY AMBIGUITY — stopped and asked rather than guessed (see KNOWN DEVIATIONS): 429/throttle detection resolved as OUT of classify()'s scope, belongs to the executor (task D3); classify() only ever sees plain `list[bool]` hit sequences, matching `DeterminismResult.hits`' type exactly — human-approved 2026-09-05. A dedicated test (`test_classify_signature_has_no_throttle_parameter_by_design`, via `inspect.signature`) pins this boundary down so a future task can't silently widen the signature without an equally explicit decision. TDD: 18 new tests appended to `tests/test_cem_engine.py`, written first, confirmed RED (`ImportError: cannot import name 'classify'`), then implemented, 67/67 GREEN (49 C1+C2 + 18 C3) on first pass — no existing C1/C2 test modified/weakened. Explicitly tests: stable-baseline+stable-miss→necessary, stable-baseline+stable-hit→apparently_not_necessary, mixed baseline (both perturbed directions)→inconclusive, mixed perturbed→inconclusive, baseline all-miss→inconclusive (not a special case, just "not all-HIT"), all-miss-perturbed-with-valid-baseline→necessary (explicit item-7 phrasing), the throttle scope-boundary signature test, mismatched-length rejection (both arms), non-list/non-bool element rejection, invalid k (zero/negative/non-int/bool), deterministic repeated classification, proof `http_probe.fetch` is never touched, and a 3-verdict-closure test across multiple input combinations. Full suite 762 passed (744 + 18), `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, all unmodified. ruff clean on both files with zero fixes needed (first C-group task with no ruff findings).**
- [x] **C4** — race/TOCTOU path → `probabilistic` (report perturbed HIT-rate; never necessary). | C3 | cem_engine.py | verify: pytest | accept: flagged-race input never yields `necessary`. **DONE 2026-09-05 — `classify_race(perturbed_hits, k) -> RaceResult` added to `mcp-servers/cem_engine.py`. PHASE1-PLAN.md's C4 line names no function/signature (unlike C1/C2/C3, each of which named its exact function) — genuine API ambiguity, stopped and asked rather than guessed. Resolved (human-approved, of 4 options presented): a new, separate pure function rather than widening classify()'s C3-pinned 3-arg signature; no baseline_hits (plan wording only ever says "report perturbed HIT-rate"); no boolean race flag — being routed to this dedicated function at all IS the race flag, mirroring how determinism_gate/classify are already separate pure functions per concern. `RaceResult(verdict, hit_rate, k)` — `verdict` hardcoded to `VERDICT_PROBABILISTIC` so the function structurally cannot return `necessary` regardless of the observed hit pattern (proven by an exhaustive test over every hit pattern for k=1..4, plus the specific all-MISS case that would trip `classify()` into `necessary`); `hit_rate = count(True)/k` over `perturbed_hits`, preserving uncertainty explicitly rather than collapsing it into a boolean. TDD: `tests/test_cem_engine.py` extended with 15 C4 tests, written first, confirmed RED (`ImportError: cannot import name 'RaceResult'`), then implemented, 82/82 GREEN (67 C1+C2+C3 + 15 C4) on first pass — no existing C1/C2/C3 test modified/weakened. Explicitly tests: all-HIT/all-MISS/mixed hit-rate computation, all-MISS still `probabilistic` never `necessary`, exhaustive never-`necessary` sweep over every k=1..4 hit pattern, `RaceResult` instance check, signature-introspection test pinning `(perturbed_hits, k)` with no baseline/flag param, invalid-`k`/invalid-element/length-mismatch rejection (mirroring classify's validation), determinism across repeated calls, and proof `http_probe.fetch` is never touched. Full suite 777 passed (762 + 15), `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, all unmodified. ruff clean on both files with zero fixes needed.**
- [x] **C5** — `minimal_condition_sets()`: ddmin for one 1-minimal set. | C3 | cem_engine.py | verify: pytest with known set | accept: recovers planted minimal set. **DONE 2026-09-05 — `MinimalSetResult(minimal_set, predicate_calls)` + `minimal_condition_sets(conditions: list[str], is_interesting: Callable[[frozenset[str]], bool]) -> MinimalSetResult` added to `mcp-servers/cem_engine.py`. API AMBIGUITY — stopped and asked rather than guessed (see KNOWN DEVIATIONS): PHASE1-PLAN.md names the ddmin interestingness property precisely ("a subset is interesting iff, with all conditions outside it perturbed to non-triggering, the oracle is unanimously HIT over k") but, unlike C1/C2/C3, gives no concrete pure-function signature at the engine layer — only the DB-backed `minimal_condition_sets(finding_id)` (a later E1 task, out of scope for pure/DB-free C5). Human-approved (of 3 options presented): an injected pure predicate `is_interesting: Callable[[frozenset[str]], bool]`, matching classic ddmin(test, circumstances) exactly and mirroring C2's fetch_fn-injection precedent; strictly bool (no inconclusive/tri-state channel invented — the plan's own definition of "interesting" is already binary; a predicate returning non-bool is a hard TypeError, proven by a dedicated test). Algorithm: deterministic single-element-removal sweep to a fixed point (hand-traced, correctness-equivalent simplification of classical partition-based ddmin appropriate for CEM's small per-finding condition counts) — guarantees 1-minimality on termination, fully deterministic for a deterministic predicate. Precondition enforced: `frozenset(conditions)` itself must be interesting or `ValueError` (ddmin cannot minimize a set that doesn't reproduce the effect). Finds exactly ONE 1-minimal set — no alternates, no interaction detection (both C6). TDD: `tests/test_cem_engine.py` extended with 21 C5 tests, written first, confirmed RED (`ImportError: cannot import name 'MinimalSetResult'`), then implemented, 103/103 GREEN (82 C1-C4 + 21 C5) on first pass — no existing C1-C4 test modified/weakened. Explicitly tests: one-unnecessary-condition removal, a "planted minimal set" scenario mirroring the benchmark's `/doc/{id}` auth-necessary shape, repeated-removal convergence over 4 conditions, an AND-interaction shape where neither condition is individually removable, an OR-shape with 2 valid minimal sets (verified generically 1-minimal, plus the exact deterministic outcome for this algorithm/order), predicate always called with a `frozenset`, empty/single-condition inputs (including a singleton that reduces to the empty set), subset-of-input invariant, invalid inputs (non-list, non-string elements, duplicates, non-callable predicate, full-set-not-interesting, predicate-returns-non-bool), determinism across repeated calls, an exact hand-traced predicate-call count (4 calls) for a known 2-condition scenario, proof `http_probe.fetch` is never touched, and a signature-introspection test pinning `(conditions, is_interesting)` with no `finding_id`/DB/network parameter. `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, full suite 798 passed (777 + 21), ruff clean on both files (one round of fixes: `# noqa: E731` comments on lambda assignments were flagged RUF100 "unused noqa" since E731 isn't an enabled rule in this repo's ruff config — removed). No protected benchmark file touched. No real network access, no DB write, no MCP tool, no perturbation/execution logic, no C3/C4 modification, no SuccessSignature change, no alternates/interaction search — pure ddmin set-minimization over a caller-supplied predicate only, exactly C5's scope.**
- [x] **C6** — alternates + interaction detection (bounded; report completeness). | C5 | cem_engine.py | verify: pytest | accept: ≥2 sets when planted; interaction-only flagged `interacting`; bound reported. **DONE 2026-09-05 — `InteractionEvidence(pair)` + `AlternateSetsResult(minimal_sets, interacting, interacting_pairs, sets_found, trials_used, bounded)` + `find_alternate_condition_sets(conditions: list[str], is_interesting: Callable[[frozenset[str]], bool], max_trials: int) -> AlternateSetsResult` added to `mcp-servers/cem_engine.py`, built strictly on top of C5's `minimal_condition_sets()` (called directly, never reimplemented). Implements PHASE1-PLAN.md sec 11 literally: Alternates ("for each c in M1, force-exclude c and re-run ddmin → collect distinct minimal sets", scoped to M1's own members) + 2 explicit interaction rules (Rule 1: singly-droppable but present in every other recovered set; Rule 2: a pair whose joint removal flips the oracle while neither single removal does) + the literal `sets_found`/`trials_used`/`bounded` reporting triple, `bounded` implemented as an injected `max_trials` cap (never a real `budget_guard` import — C6 stays pure). TWO API/semantics ambiguities — stopped and asked rather than guessed (see KNOWN DEVIATIONS): (1) Rule 1's "present in every recovered minimal set" excludes c's own force-excluded alternate (structurally can never contain c) AND M1 itself when c∈M1 (tautological, restates the premise) — human-approved, of 3 options presented, the only reading under which Rule 1 can ever actually fire. (2) The candidate pool for individual-droppability testing (feeding both rules) is broadened to ALL conditions in the original S, not just M1's members — human-approved, of 2 options presented — because ddmin's greedy sweep can drop one half of a genuine interacting pair before it ever reaches M1 (concrete counterexample worked through with the human: conditions=[a,b,d], is_interesting=d∧(a∨b), ddmin drops "a" immediately, M1={b,d}, yet is_interesting(S-{a})=is_interesting(S-{b})=True and is_interesting(S-{a,b})=False is a genuine Rule-2 interaction an M1-only scope would miss). TDD: `tests/test_cem_engine.py` extended with 27 C6 tests, written first, confirmed RED (`ImportError: cannot import name 'AlternateSetsResult'`), then implemented, 130/130 GREEN (103 C1-C5 + 27 C6) on first pass — no existing C1-C5 test modified/weakened. Four hand-traced scenarios validate the design end-to-end: OR-redundancy (header/cookie, mirrors `/report`) → 2 sets, Rule 2 flags both (documented honestly as a literal-but-expected corollary of "only 2 paths exist", not suppressed); pure-AND-no-redundancy (role_admin/flag_on, mirrors `/merge` in isolation) → 1 set, `interacting=frozenset()` (proves no over-inference from mere multi-condition co-occurrence); a 3-condition mutually-substitutable-plus-gate scenario proving Rule 2 catches a real interaction even when one member never reaches M1; a 4-condition "any-2-of-3" scenario giving a genuine non-vacuous Rule-1 firing (for the 2 members that do survive into M1) alongside Rule 2 independently catching all 3 pairs. Also tests: exact hand-traced call accounting for 3 scenarios (8, 7, 22, and the any-2-of-3 case again under a tight budget), `bounded=True` with graceful partial (non-crashing) results under a deliberately tight `max_trials`, empty-conditions triviality, determinism across repeated calls, full invalid-input matrix (non-list/non-string/duplicate conditions, non-callable predicate, non-int/bool/zero/negative `max_trials`), a spy proving `minimal_condition_sets` is genuinely reused rather than reimplemented (exact call count), proof `classify`/`classify_race` are never touched (interacting is orthogonal to necessary/apparently_not_necessary/inconclusive/probabilistic — never a 4th verdict), proof `http_probe.fetch` is never touched, a structural field-set check on `AlternateSetsResult` guarding against a verdict-like field ever sneaking in, and a signature-introspection pin (`conditions, is_interesting, max_trials`). `test_http_probe.py` 10/10, `test_case_store.py`+`test_cem_case_store.py` 61/61, full suite 825 passed (798 + 27), ruff clean on both files with zero fixes needed. No protected benchmark file touched. No real network access, no DB write, no MCP tool, no C1-C5 modification (SuccessSignature/determinism_gate/classify/classify_race/minimal_condition_sets all reused verbatim), no race-becomes-necessary path (C6 never calls classify_race), no PoC minimization (C7) — pure alternates/interaction search over a caller-supplied predicate only, exactly C6's scope.**
- **C6 addendum — mutual AND-necessity detection** (not an original A-P task; added in a later session as an approved fix arising from the retrospective C1-C8 audit, human-approved Option 2 of 3 presented, 2026-09-05). **Finding:** the audit found that C6's Rule 1/Rule 2 above cannot detect a pure "both conditions strictly required together" pattern (e.g. `role_admin` AND `flag_on`, PHASE1-PLAN.md's own `/merge` example) — confirmed live: `find_alternate_condition_sets(["role_admin","flag_on"], and_predicate, 100).interacting == frozenset()`. Root cause: PHASE1-PLAN.md §11's Rule 2 wording ("a pair whose joint removal flips the oracle while neither single removal does") is the mathematical signature of OR-redundancy, not AND-necessity — for a genuine AND, neither condition ever enters Rule 1/Rule 2's `droppable_singly` candidate pool, by design, not by bug. **Fix:** `AndNecessityGroup(members: frozenset[str])` + `find_and_necessity_groups(minimal_sets: list[frozenset[str]]) -> list[AndNecessityGroup]` added to `mcp-servers/cem_engine.py`, immediately after `find_alternate_condition_sets` — a separate, additive, pure post-processing function over the SAME `minimal_sets` list C6 already returns (zero additional `is_interesting` calls: the signal is already implicit in ddmin's own 1-minimality guarantee — any recovered minimal set with ≥2 members means removing any single member breaks the effect). `find_alternate_condition_sets` itself is untouched — confirmed via `git diff`, zero removed lines in that function; its own pre-existing 26-test section runs unmodified. `classify()`/`classify_race()` are not called by this addendum and are not modified anywhere — `classify()` still independently and correctly returns `"necessary"` for both `role_admin` and `flag_on` (confirmed live); the new signal is an additional, orthogonal structural annotation, never a replacement verdict — this is the exact representation decision approved (Option 2, not Option 1's "rewrite the ground truth" or Option 3's "redefine what `interacting` means bundle-wide"). TDD: 19 new tests (pure AND, pure OR-redundancy as a negative case, a mixed case, an end-to-end 3-simultaneous-group case reusing the real `ANY_TWO_OF_THREE` C6 scenario, dedup, empty/invalid-input, determinism, signature pin), all RED-then-GREEN, no existing C1-C7 test modified. Full suite 904 passed (885 + 19), ruff clean. **Still open:** `answer_key.py`'s `EXPECTED["case_03"]` still literally expects `"interacting"`/`"interacting"` and its schema has no key for this new signal at all — wiring this capability into the benchmark's ground truth/evaluator is explicitly deferred future work, not done here; the protected benchmark files were not modified (checksums verified unchanged against their `.sha256.lock` files).**
- [x] **C7** — `minimize_poc()`: ddmin over conditions/steps, runs AFTER verdicts, re-validated by determinism gate. | C5 | cem_engine.py | verify: pytest | accept: unnecessary condition dropped; minimal PoC re-passes gate. **DONE 2026-09-05 — `PocMinimizationResult(poc, accepted, determinism, predicate_calls)` + `minimize_poc(conditions: list[str], is_interesting: Callable[[frozenset[str]], bool], revalidate: Callable[[frozenset[str]], DeterminismResult]) -> PocMinimizationResult` added to `mcp-servers/cem_engine.py`. Reuses `minimal_condition_sets()` (C5) directly for the ddmin search — never reimplemented — per PHASE1-PLAN.md sec 12's literal "PoC minimization reuses the SAME ddmin with the oracle as interestingness." "steps" was checked and confirmed NOT a separate concept anywhere in the plan (only ever a loose synonym for "conditions/fields", no dedicated dataclass) — minimize_poc() operates over the exact same `conditions` abstraction as C5/C6, no new abstraction invented. Re-validation ("output re-validated through determinism_gate ... guards a DD local optimum dropping a real step") is an injected `revalidate` callable standing in for the real `determinism_gate` (C2) — kept abstract so C7 stays pure/no-network, exactly how `is_interesting` already stands in for a real oracle, reusing C2's own `DeterminismResult` type unmodified rather than inventing new determinism vocabulary. ONE design fork resolved directly from the plan's own text rather than guessed (no AskUserQuestion needed — textually unambiguous once traced): what happens when revalidation reports NONDETERMINISTIC. PHASE1-PLAN.md sec 15 explicitly separates the mandatory step ("re-validate minimal set/PoC via determinism gate") from an explicitly-OPTIONAL one ("optional DDMIN* re-iterate") — so minimize_poc() does NOT retry/backtrack on failure; it reports `accepted=False` honestly (poc still returned as evidence) rather than silently accepting a possibly-wrong minimal reproducer or attempting recovery logic the plan itself marks out of Phase 1's minimum scope. TDD: `tests/test_cem_engine.py` extended with 17 C7 tests, written first, confirmed RED (`ImportError: cannot import name 'PocMinimizationResult'`), then implemented, 147/147 GREEN (130 C1-C6 + 17 C7) on first pass — no existing C1-C6 test modified/weakened. Explicitly tests: the literal accept criterion via the `/doc/{id}`-mirroring auth_cookie/trace_param scenario (unnecessary condition dropped, `accepted=True`), exact hand-traced predicate-call count (4, matching C5's own trace of the identical scenario), honest `accepted=False` reporting on a NONDETERMINISTIC revalidation stub (no crash, no silent accept), proof `revalidate` is called exactly once even on failure (no automatic re-iteration), a spy proving `minimal_condition_sets` is genuinely reused (exact call), proof `classify`/`classify_race`/`find_alternate_condition_sets`/the real `determinism_gate`/`http_probe.fetch` are never touched, validation-inheritance proof (conditions/is_interesting errors propagate from C5 unduplicated), invalid-`revalidate` handling (non-callable, non-`DeterminismResult` return), determinism across repeated calls, empty-conditions triviality, and a signature-introspection pin (`conditions, is_interesting, revalidate`). `test_http_probe.py`+`test_case_store.py`+`test_cem_case_store.py` 71/71, full suite 842 passed (825 + 17), ruff clean on both files with zero fixes needed. No protected benchmark file touched. No real network access, no DB write, no MCP tool, no C1-C6 modification, no automatic retry/DDMIN* re-iteration (explicitly out of Phase-1 scope per the plan) — pure PoC minimization + honest re-validation reporting only, exactly C7's scope.**
- [x] **C8** — `assemble_bundle()`: all 15 §2.8 fields; redacted via `redact_text`. | C3..C7 | cem_engine.py | verify: pytest | accept: bundle schema has every field; redaction applied. **DONE 2026-09-05 (via `superpowers:subagent-driven-development`) — `assemble_bundle(finding_id, original_baseline, baseline_determinism, intervention_matrix, controls, observed_confounders, verdict_labels, inconclusive_experiments, alternate_sets, poc, audit_trail, k) -> dict` added to `mcp-servers/cem_engine.py`, plus a private `_redact_recursive()` helper (recurses dicts/lists/tuples, applies `redact.redact_text` to every string leaf, leaves int/float/bool/None untouched, applied exactly once at the end of assembly). RULING (controller-resolved, not escalated — see `.superpowers/sdd/PHASE1-EXECUTION-PLAN/progress.md`): C8's only deps are C3..C7, not D1-D3/case_store (neither exists yet), so the function must accept already-computed typed results as parameters rather than execute anything live — same injected-dependency pattern as C2's `fetch_fn`/C7's `revalidate`. Produces a 16-key dict: all 15 §2.8 fields (`original_baseline`, `baseline_replication_results`, `intervention_matrix`, `replication_counts`, `controlled_pinned_conditions`, `observed_confounders`, `inconclusive_experiments`, `identified_necessary_conditions`, `minimal_condition_sets`, `minimized_reproduction_evidence`, `complete_audit_trail`, `verdict_labels`, `controls`, `k`, `completeness_bound`) plus `finding_id` for bundle identity. Fields 4/14 (`replication_counts`/`k`) and 5/13 (`controlled_pinned_conditions`/`controls`) are deliberately duplicated per the spec's own field list, not collapsed. `identified_necessary_conditions` is derived from `verdict_labels` (never caller-supplied separately, closing a silent-disagreement risk); `minimal_condition_sets`/`completeness_bound` unpack `AlternateSetsResult` into two distinct top-level keys (set contents vs. completeness counts, not nested); `minimized_reproduction_evidence` unpacks `PocMinimizationResult`. `isinstance` validation (TypeError) on the three typed params (`baseline_determinism`, `alternate_sets`, `poc`); the other 9 params are intentionally unchecked, matching the brief's own explicit scope. TDD: 27 new tests appended to `tests/test_cem_engine.py` (RED confirmed via `ImportError: cannot import name 'assemble_bundle'`, then GREEN), covering schema-completeness (real key-set equality), one test per field-derivation rule, a non-vacuous redaction proof (explicit `redact_text(secret) != secret` check before three bundle-level redaction tests rely on it), non-string-survival, no-live-execution (every C1-C7 function plus `http_probe.fetch` monkeypatched to raise), determinism, 3 TypeError-rejection tests, and a signature-introspection pin. Full suite 869 passed (842 + 27), 0 failed — independently re-verified by the controller after the implementer's own run. `ruff check` clean on both files (also independently re-verified by the controller). Task-reviewer pass (spec + quality, full detail in the SDD ledger): **Approved**, 0 Critical, 0 Important, 2 Minor deferred (a test hardcodes the literal `"necessary"` string instead of the `VERDICT_NECESSARY` constant; no type/shape validation on the 9 untyped params — both cosmetic/forward-looking, not gaps against what was asked). No fix loop needed. No protected benchmark file touched. Commit: `8ac2eb9`.
  **RETROSPECTIVE AUDIT FIX, round 1 (later session, 2026-09-05):** an independent audit found that `redact_text()`'s two name-based rules (header line, key=value) require the secret's key NAME to be embedded in the SAME STRING as the value — but `_redact_recursive`'s dict walk redacts each VALUE in isolation, stripped of its key, so only the two VALUE-SHAPE rules (JWT, card number) ever actually fired on a dict value. Confirmed live: `{"headers": {"Authorization": "Bearer sk-live-<opaque>"}}` passed straight through `assemble_bundle` completely unredacted. Fixed with TDD (8 new tests, RED confirmed, then GREEN): `_redact_recursive` now redacts a dict value whole when its key is an *exact* (case-insensitive) match against a new public `redact.KNOWN_SECRET_HEADER_NAMES` constant (the same 4 names `_HEADER_LINE_RE` already recognized) — exact match, not substring, so real CEM condition names used elsewhere in this codebase (`session_cookie`, `auth_cookie`) are never wrongly caught (a dedicated collision-guard test confirms this). `redact.py`'s private `_redacted()` formatter was renamed to public `redacted()` (its 4 internal call sites updated, `_HEADER_LINE_RE`'s regex now built from the new public constant, functionally verified byte-identical) so `cem_engine` reuses the exact same hash/format convention rather than duplicating it — grepped the whole repo first: no other file referenced the old private name. `test_redact.py` 18/18 (15 original + 3 new), `test_audit_log.py` (the only other `redact.py` consumer) 4/4 unmodified. Full suite 885 passed (869 + 16: 5 C1-fix + 8 C8-fix + 3 redact.py tests), ruff clean. **Residual gap found by the SAME audit, not fixed in this round:** a secret-carrying header represented as a LIST of strings (e.g. repeated `Set-Cookie` values) still leaked an opaque list element — see round 2 below.
  **RETROSPECTIVE AUDIT FIX, round 2 (later session, 2026-09-05):** closed the round-1 residual gap. `_redact_recursive` now also redacts each non-empty string element of a list/tuple value when its dict key is an exact `KNOWN_SECRET_HEADER_NAMES` match (same `redacted()`/"header-value" convention as the scalar case, so both shapes look uniform in the bundle); empty elements stay empty; any other shape (a stray non-string element, a nested dict) falls back to the ordinary recursive walk rather than guessing. TDD (5 new tests, RED confirmed, then GREEN): redacts every opaque element in a list-valued `Set-Cookie`, matches the scalar redaction convention exactly, preserves empty elements, leaves a non-secret list-valued key untouched (collision guard), and falls back safely on a mixed string/non-string list. Full suite 909 passed (904 + 5), ruff clean. **Still open, deliberately out of scope for both rounds** (a pre-existing `redact.py` limitation, not introduced or widened by either fix): header names outside the 4 canonical ones (e.g. `X-Auth-Token`, `X-Session-Id`) remain unredacted in both the flat-text and dict-value paths — confirmed this is true even before either fix (`redact_text("X-Auth-Token: secret")` was already a no-op). Widening `KNOWN_SECRET_HEADER_NAMES` was deliberately not done, since the broader `DENY_KEY_TOKENS` substring set (password/token/secret/auth/session/etc.) would collide with real CEM condition names (`session_cookie`, `auth_cookie`, `csrf_token`) if matched as dict keys.**

### D. Intervention executor
- [x] **D1** — `Controls` dataclass + pinning helpers (session headers, cache-buster, ordering, `spacing_ms`, concurrency=1; uncontrollable confounder → recorded, forces inconclusive). | C1 | cem_engine.py | verify: pytest | accept: uncontrolled confounder → inconclusive. **DONE 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`; first non-recovery task, full TDD)** — `Controls` dataclass + `apply_control_gate(verdict, controls) -> str` added to `mcp-servers/cem_engine.py` (appended after `assemble_bundle`; C1–C8 bodies byte-untouched — the only removed lines are the module docstring's "Deliberately NOT here" paragraph, rewritten to add a Task-D1 paragraph, and `from dataclasses import dataclass` → `..., field`). **API AMBIGUITY — stopped and asked, not guessed (human-approved 2026-09-07 via AskUserQuestion, 2 questions), matching the C4/C5/C6 precedent:** PHASE1-PLAN.md §9 names the `Controls` *fields* + the *behavior* ("uncontrolled confounder → `uncontrolled:<name>`, forces `inconclusive`") but no engine-layer signatures. Resolved: **(1)** methods on `Controls` (`pin`, `record`, `has_uncontrolled`) + a module-level `apply_control_gate` — mirrors `SuccessSignature` (methods) alongside `classify`/`classify_race` (module fns); **(2)** full CSRF: `csrf_header_name: str|None` + injected `csrf_provider: Callable[[], str]|None` (like C2's `fetch_fn`) — header-name-without-provider auto-adds `"csrf_token"` to the effective uncontrolled set. `Controls` fields: `session_headers` (name→value dict), `csrf_header_name`, `csrf_provider`, `cache_buster` (default True), `ordering` (must be `"sequential"` in Phase 1), `spacing_ms` (carried, applied by D2), `concurrency` (must be `1`), `uncontrolled` (caller's extra names). `pin(request, trial_index)` → NEW dict: merges `session_headers` identically every trial, mints the CSRF header via the provider per trial, appends a per-trial-unique `_cb=<trial_index>` query param when `cache_buster` — scheme/host/path/fragment untouched (SSRF guard), input never mutated, only the injected `csrf_provider` is ever called (no fetch). `record()` → JSON snapshot for `cem_trials.controls` / the bundle: **header NAMES only, never values** (security.md — session secrets never enter the DB/report), `uncontrolled` entries as the literal `"uncontrolled:<name>"` per §9, plus `csrf: "pinned"|"uncontrolled"|"n/a"`. `apply_control_gate` is the ONE place the "uncontrolled → `inconclusive`" rule lives (D2/E call it around `classify()` output; `classify()` stays controls-unaware, C3-pinned) — returns `VERDICT_INCONCLUSIVE` when `has_uncontrolled`, else passes any of the 5 verdict strings through unchanged. TDD: 41 tests appended to `tests/test_cem_engine.py` (211→252), written first, confirmed RED (`ImportError: cannot import name 'Controls'`), then GREEN. Covers: every field's type/value validation, `has_uncontrolled` (clean / caller-declared / CSRF-without-provider / CSRF-with-provider / dedupe), `pin` (identical headers per trial, per-trial-unique cache-buster, cache-buster-off no-op, scheme/host/path/query/fragment preservation, stale-`_cb` replacement, csrf provider called once per trial, provider not called when absent, non-str provider return rejected, input not mutated, `trial_index`/`request` validation, determinism, never-calls-`http_probe.fetch`), `record` (**names-only secret-safety proof** — a planted `sid=SUPERSECRETVALUE` / `Bearer LEAKME` is absent from the JSON blob, pinned config carried, `uncontrolled:` prefix, `csrf` status, JSON round-trip), `apply_control_gate` (**literal acceptance criterion**: `Controls(csrf_header_name=…)` + `classify(...)="necessary"` → `"inconclusive"`; clean-controls passthrough for all 5 verdicts; forced-inconclusive for all 5 when dirty; validation; never-calls-fetch; signature pin), and a `Controls` field-order pin. `ruff check` (CI-exact) + `py_compile` clean on both files (one TRY004 round: a `ValueError` behind an `isinstance` check → `TypeError`, plus splitting a bundled non-empty-string check into `TypeError`/`ValueError`, consistent with C1's documented convention; 3 of my own net-new test expectations updated to match — no C1–C8 test touched). `test_case_store.py` 36/36, `test_cem_case_store.py` 25/25, `test_http_probe.py` 10/10 unmodified. Full suite **958 passed** (917 pre-D1 + 41), 0 failures, 0 regressions. `tests/test_cem_engine.py` diff is **purely additive** — `git diff | grep '^-[^-]'` on it is empty; no C1–C8 test modified/weakened. No protected benchmark file touched. No DB write, no MCP tool, no fetch loop / spacing sleep / budget callback (D2), no `429` detection (D3), no perturbation. No commit.
- [x] **D2** — `run_intervention(base_request, controls, perturbation|None, k, budget_cb)`: loops fetch, spacing, oracle eval; budget via injected callback (MCP-free). | D1, A4 | cem_engine.py | verify: pytest with fake fetch + spy budget_cb | accept: k calls, budget_cb called per request, one-variable-at-a-time honored. **DONE 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`, full TDD)** — `Trial` dataclass + `run_intervention(...)` + `ARM_BASELINE`/`ARM_PERTURBED` constants added to `mcp-servers/cem_engine.py` (appended after `apply_control_gate`; C1–D1 bodies byte-untouched — only removed lines cumulative across D1+D2 are the module docstring's old "Deliberately NOT here" paragraph, rewritten, and `from dataclasses import dataclass` → `..., field`). Actual signature `run_intervention(base_request, controls, perturbation, k, budget_cb, success_signature, fetch_fn, sleep_fn=time.sleep)` — `success_signature`/`fetch_fn` beyond the §6 shorthand are structurally required (oracle to eval, fetch to call), the **exact C2 precedent** (its shorthand `determinism_gate(base_request, k)` likewise grew `success_signature`/`fetch_fn`), so not escalated. **TWO design forks human-approved 2026-09-07 via AskUserQuestion, not guessed (C4/C5/C6/D1 precedent):** (1) `perturbation` is an injected `Callable[[dict], dict]` (`None` = baseline/determinism arm), not a structured dict D2 interprets — D2 stays a pure loop, "one variable at a time" is the caller's contract, the E-layer translates the stored `cem_conditions.perturbation` JSON into a callable; (2) inter-trial spacing via an injected `sleep_fn: Callable[[float], None] = time.sleep` (spy-able), not a bare `time.sleep`. **Semantics:** one call = ONE arm, k trials. Per trial, in order: `sleep_fn(controls.spacing_ms/1000)` only BETWEEN trials (k−1 times, never before the first / after the last, skipped when `spacing_ms==0`); one `budget_cb()` (a raise propagates and stops sending — the per-finding ceiling + partial-`incomplete` bundle is F2's job, not this loop's); `controls.pin(base_request, i)`; `perturbation(...)` composed once on top for the perturbed arm; `fetch_fn(url, method, headers, body, DEFAULT_TIMEOUT_S)` (injected, `http_probe.fetch` signature — UD-1 anti-dup); `evaluate_signature` (a fetch-error `FetchResult` → MISS, same as C2; D3 later refines 429). Returns `list[Trial]` (`arm`/`k_index`/`http_status`/`oracle_hit`/`request`/`response`); hit sequence for `classify`/`determinism_gate` = `[t.oracle_hit for t in trials]`. Does **not** refactor C2's standalone `determinism_gate` (one-task rule — `run_intervention(perturbation=None)` is a usage pattern the E-layer can adopt, they coexist). TDD: 25 tests appended to `tests/test_cem_engine.py` (252→277), written first, confirmed RED (`ImportError: cannot import name 'ARM_BASELINE'`), then GREEN. Covers: signature pin, baseline/perturbed arm tagging + `k_index`, exact-k `fetch_fn` calls, `budget_cb` once per request + **a raise on call 3 → `fetch_fn` ran only twice** (checked-before-fetch, stops sending), **one-variable-at-a-time** (baseline arm request == `controls.pin(base, i)`; perturbation spy sees exactly the pinned request, composed once), spacing (`sleep_fn` spy == `[0.2]*(k−1)`, none for `spacing_ms==0`, none for `k==1`), `oracle_hit` == `evaluate_signature` incl. 403/error → MISS, `http_status` None on error, fetch positional args from the pinned request, per-trial cache-buster uniqueness, per-trial CSRF minting, `base_request` not mutated, determinism, **never calls the real `http_probe.fetch`** (monkeypatch guard), full validation matrix (non-`Controls`, non-callable `perturbation`/`budget_cb`/`fetch_fn`/`sleep_fn`, bad `k`, non-`SuccessSignature`, non-dict `base_request`, perturbation returning non-dict), an **end-to-end `run_intervention`→`classify` == "necessary"**, ARM-constant values, `Trial` field-order pin. `ruff check` (CI-exact) + `py_compile` clean on both files, zero fixes. `test_case_store.py` 36/36, `test_cem_case_store.py` 25/25, `test_http_probe.py` 10/10 unmodified. `tests/test_cem_engine.py` diff **purely additive** (`git diff | grep '^-[^-]'` empty — no C1–D1 test touched). Full suite **983 passed** (958 pre-D2 + 25), 0 failures, 0 regressions. No protected benchmark file touched. No DB write, no evidence hashing, no `429` detection (D3), no per-finding ceiling / `incomplete` handling (F2), no F3 non-idempotent refusal, no MCP tool. No commit.
- [x] **D3** — `429`/throttle detection in executor → inconclusive. | D2 | cem_engine.py | verify: pytest | accept: throttled arm never yields necessary. **DONE 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`, full TDD)** — `THROTTLE_STATUS = 429` constant + `throttled_in(trials) -> bool` + `apply_throttle_gate(verdict, trials) -> str` added to `mcp-servers/cem_engine.py` (appended after `run_intervention`), **plus a targeted 3-line change inside `run_intervention`'s loop** — D3's task line explicitly mandates detection "in executor", dep D2, so modifying the D2 function is in-scope, not "refactoring adjacent code". **TWO design forks human-approved 2026-09-07 via AskUserQuestion (C4/C5/C6/D1/D2 precedent):** (1) throttle signal = **HTTP 429 only** (`http_status == 429`) — plan-literal, and `FetchResult` carries no headers so `Retry-After` is unavailable; a 503/other status is already a MISS (`!= 200`) so it can at worst reach `inconclusive` via C3's mixed rule, never a false `necessary`; (2) `run_intervention` **aborts the arm on the first 429** — appends that `Trial` (it is the evidence) then `break`s, so a throttled arm returns **fewer than k trials** (stop hammering an in-scope target). `throttled_in` / `apply_throttle_gate` parallel D1's `has_uncontrolled` / `apply_control_gate` exactly — the ONE place the "429 → `inconclusive`" rule lives; the E-layer composes `apply_throttle_gate(apply_control_gate(classify(...), controls), trials)`; `classify()` stays status-blind (C3-pinned, its dedicated signature-pin test still passes). `apply_throttle_gate` forces `inconclusive` **regardless of the verdict passed in**, so a throttled arm can never yield `necessary` even from a buggy caller. A network-error trial (`status None`) is NOT a throttle and does not abort. TDD: 19 tests appended to `tests/test_cem_engine.py` (277→296), written first, confirmed RED (`ImportError: cannot import name 'THROTTLE_STATUS'`), then GREEN. Covers: constant value, abort on first 429 (mid-run → 3 trials + `fetch_fn` called 3× not k; on trial 0 → 1 trial; on the last trial → natural end), **no-429 runs all k unchanged** (D2 regression), abort applies to the perturbed arm, abort stops the whole loop (`budget_cb`/`sleep_fn` call counts prove it, not just fetch), network error does NOT abort, `throttled_in` (empty→False, 429→True, 200/403/None→False, validation), `apply_throttle_gate` (**literal acceptance**: a 429-aborted arm + `"necessary"` → `"inconclusive"`; clean arm passthrough for all 5 verdicts; forced-inconclusive for all 5 when throttled; composes with `apply_control_gate`; validation; never-calls-fetch; signature pin). `ruff check` (CI-exact) + `py_compile` clean on both files, **zero fixes**. `test_case_store.py` 36/36, `test_cem_case_store.py` 25/25, `test_http_probe.py` 10/10 unmodified. `tests/test_cem_engine.py` diff **purely additive** (`git diff | grep '^-[^-]'` empty — no C1–D2 test touched; the 25 D2 tests all still pass with the `break` added, since none use a 429 sequence). Full suite **1002 passed** (983 pre-D3 + 19), 0 failures, 0 regressions. No protected benchmark file touched. No DB write, no evidence hashing, no per-finding ceiling / `incomplete` (F2), no F3 non-idempotent refusal, no baseline-re-check interleave (a PHASE1-PLAN *mitigation idea*, not a D3 acceptance requirement), no MCP tool. No commit.

### E. MCP tool integration
- [x] **E1** — Add `define_conditions`, `determinism_gate`, `run_counterfactual`, `minimal_condition_sets`, `minimize_poc`, `evidence_bundle` wrappers in `case-mcp/server.py`. | B2, C8, D3 | case-mcp/server.py | verify: import + smoke test | accept: tools registered; delegate to engine/store. **DONE 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`, full TDD; first task touching an MCP server file)** — all 6 `@app.tool()` wrappers added to `mcp-servers/case-mcp/server.py` (inserted before `if __name__ == "__main__"`; the existing 15 case-mcp tools are **byte-untouched** — the only removed lines are `0`, the only import-block change adds `import cem_engine` / `import http_probe` / `urllib.parse`). `tests/test_cem_mcp.py` NEW (18 smoke tests, server module loaded via `spec_from_file_location`, `http_probe.fetch` monkeypatched — no real network; `HUNTMCP_CASE_DB_PATH` env for per-test DB isolation). **TWO design forks human-approved 2026-09-07 via AskUserQuestion (C4–D3 precedent):** (1) **depth = "fuller"** — beyond "registered + delegate", the senders persist `cem_trials` rows as trials happen and `run_counterfactual` persists one `cem_verdicts` row (per PHASE1-PLAN §B steps 2–3); (2) **perturbation vocabulary = the implicit `{"drop": true}` shape** already in `tests/test_cem_case_store.py` — a helper `_perturbation_for(condition)` translates it to a `Callable[[dict], dict]` that drops the header or query param the condition names (with `auth_cookie`/`session_cookie`→`Cookie`, `bearer_token`/`authorization`→`Authorization` aliases); any other perturbation shape or an un-locatable target is a hard `{"error": …}`, never a silent no-op. **Tool behaviour:** `define_conditions` → `case_store.cem_define` (JSON-string args parsed with error handling, like the existing `score_finding_confidence`). `determinism_gate(finding_id, url, k)` (sender) → loads state, `SuccessSignature.from_dict`, `cem_engine.run_intervention(base, Controls(), None, k, budget=lambda:None, sig, http_probe.fetch)`, persists baseline `cem_trials`, returns `{determinism_status, hits, k, throttled}` (STABLE iff not-throttled ∧ len==k ∧ all-HIT). `run_counterfactual(finding_id, url, condition_id, k)` (sender) → runs baseline + perturbed arms, persists all `cem_trials` + one `cem_verdicts`; **checks `throttled_in` / partial-arm BEFORE `classify`** (the D2/D3-audit-flagged length-mismatch guard) and short-circuits to `inconclusive`, else `classify` → `apply_control_gate` → `apply_throttle_gate`. `minimal_condition_sets` / `minimize_poc` (local) → delegate to `cem_engine.find_alternate_condition_sets` / `minimize_poc` with a **stored-verdict predicate** (a condition outside a set is droppable iff its recorded verdict is `apparently_not_necessary`); single-necessary-condition short-circuits to the trivial set. `evidence_bundle` (local) → `cem_engine.assemble_bundle` from recorded state (base request, per-condition verdicts, baseline determinism from stored trials; `observed_confounders=[]`, `audit_trail=[]`, empty `AlternateSetsResult`/`PocMinimizationResult` where nothing is persisted yet), returns the redacted 16-key bundle JSON. **DELIBERATELY DEFERRED (not E1):** budget + audit inline in the senders (E2 — E1 passes `budget_cb=lambda:None`), CONFIRMED-state check + `SuccessSignature`-shape guard on `define_conditions` (E3 — `cem_define`'s own empty-signature UD-3 rejection still fires), `"case-mcp"` in `TIER2_MCP_SERVERS` / scope gating (F1), the per-finding request ceiling (F2), non-idempotent-perturbation refusal (F3), content-addressed request/response evidence hashes on trial rows + a fresh determinism-gate re-run for `minimize_poc` re-validation + live bounded subset re-trials for `minimal_condition_sets` (G1), persisting `cem_meta.determinism_status` (no `case_store` setter exists — `determinism_gate` returns the status but does not write the column). TDD: 18 tests written first, confirmed RED (`ModuleNotFoundError` / `AttributeError` on the 6 names), then GREEN. Covers: all 6 tools exist + callable, module imports `cem_engine`/`http_probe`, `define_conditions` happy + bad-JSON + empty-signature-rejected, `determinism_gate` STABLE / NONDETERMINISTIC-on-mixed / unknown-finding + baseline trials persisted, `run_counterfactual` necessary (+ 6 trials + 1 verdict row persisted) / apparently_not_necessary (drop a `?trace=1` query param) / 429→inconclusive / unsupported-perturbation / unknown-condition, `minimal_condition_sets` needs-a-necessary-verdict-first + after-run_counterfactual → `[["auth_cookie"]]`, `minimize_poc` → `poc == ["auth_cookie"]`, `evidence_bundle` assembles (16-key bundle, `verdict_labels["auth_cookie"] == "necessary"`) + unknown-finding error. `ruff check` (CI-exact) + `py_compile` clean on both files (one I001 import-sort fix in the test file). `cem_engine.py` / `case_store.py` / `test_cem_engine.py` **not touched by E1**. Full suite **1020 passed** (1002 pre-E1 + 18), 0 failures; `test_cem_engine.py` 296/296, `test_case_store.py` 36/36, `test_cem_case_store.py` 25/25, `test_idor_mcp_server.py` 3/3 unmodified. No protected benchmark file touched. No commit.
- [x] **E2** — Senders (`determinism_gate`, `run_counterfactual`) take `url` and call `_enforce_budget("case-mcp")` + `_log_call(...)` inline. | E1 | case-mcp/server.py | verify: test_cem_safety.py | accept: budget+audit invoked per real request. **DONE 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`, full TDD)** — `mcp-servers/case-mcp/server.py` imports `budget_guard.enforce as _enforce_budget` / `budget_guard.BudgetExceeded` / `audit_log.log_call as _log_call` + `time`, **exactly mirroring `idor-mcp/server.py`** (§5 says "same pattern as idor-mcp"). **No ambiguity escalated:** §5's "same pattern as idor-mcp" + §6's "per real request" reconcile once idor-mcp is read — idor-mcp enforces budget per request (inside its send loop) and audits **once per tool call** (a summary line after the loop); "per real request" distinguishes the *senders* (which do both) from the *local assembler tools* (which do neither, matching §5's host-arg split). **Wiring:** both senders pass `budget_cb=lambda: _enforce_budget("case-mcp")` into `cem_engine.run_intervention` — D2's designed injection point, called **before each fetch** (D2 record: "the server injects `budget_guard.enforce`"); `run_intervention` propagates a `BudgetExceeded` raise (D2 behaviour), which each sender catches (`budget_hit = str(e)`) and turns into a graceful `{"error": "Tier-2 budget exhausted: …", "incomplete": true}` result — **no partial trials/verdict persisted** (partial-arm preservation + the per-finding ceiling are F2's explicit acceptance, not E2's). After the run each sender calls `_log_call("case-mcp", ["<tool>", url, f"finding {id}", …], returncode=None, duration_ms=(monotonic-delta)*1000, block="budget" if budget_hit else None)` — **one line per invocation**, `args` redacted by `audit_log` itself. `run_counterfactual` also emits an audit line with `block="error"` on the `_perturbation_for` `ValueError` path. The 4 local tools (`define_conditions`, `minimal_condition_sets`, `minimize_poc`, `evidence_bundle`) are untouched — no budget, no audit (verified by a spy test). TDD: `tests/test_cem_safety.py` NEW (8 tests), written first, confirmed RED (`AttributeError: module … has no attribute 'BudgetExceeded'`), then GREEN. Covers: budget enforced **once per request** (`determinism_gate` k=3 → 3 calls; `run_counterfactual` k=3 → 6 = 2 arms × 3), budget checked **before the fetch** (a raise on call 1 → `http_probe.fetch` never called), audit **once per tool call** with `tool=="case-mcp"` + the tool name + `url` in `args` + `duration_ms` in kwargs, budget exhaustion **handled not crashed** (`{"error", "incomplete": true}` + audit line still written with `block="budget"`), `run_counterfactual` budget-exhaustion writes **no `cem_verdicts` row**, and the 4 local tools call **neither** spy. **DEVIATION (test-isolation correction, disclosed):** E1's `tests/test_cem_mcp.py` `cem_db` fixture predated budget/audit and only isolated `HUNTMCP_CASE_DB_PATH`; post-E2 its sender smoke tests hit the *real* `_enforce_budget`/`_log_call` (bumping the gitignored repo `budget.json` counter + appending to `data/audit.jsonl`). Added `HUNTMCP_BUDGET_PATH` + `HUNTMCP_AUDIT_LOG` to that fixture — a per-test isolation fix forced by E2's contract change, **not** a weakening (every E1 assertion unchanged; double-run now stable). `ruff check` (CI-exact) + `py_compile` clean on all 3 E-files, zero production-code fixes. `cem_engine.py` / `case_store.py` / `test_cem_engine.py` **not touched by E2**. Full suite **1028 passed** (1020 pre-E2 + 8), 0 failures; `test_cem_mcp.py` 18/18 (with the isolated fixture), `test_cem_engine.py` 296/296, `test_case_store.py` 36/36, `test_idor_mcp_server.py` 3/3 unmodified. No protected benchmark file touched. No commit.
  <br>**E2 ADDENDUM — B-1 + T-2 (post-audit, human-approved 2026-09-07; audit verdict was SAFE WITH IMPROVEMENTS):** the E2 audit found no A-class issue but flagged the inline‑duplicated (and already subtly divergent) budget/audit control flow in the two senders as a B‑class extensibility risk for F2. **B-1 (de-dup):** added `_make_budget_cb(finding_id)` (the single factory for the per-request budget check `run_intervention` calls — today just `_enforce_budget("case-mcp")`; F2 adds the per-finding ceiling here, `finding_id` already threaded, no per-sender edit) + `_sender_run(tool_args)` (a `@contextmanager` — pattern already used in `mcp-servers/file_lock.py` — that times the block, writes exactly ONE `_log_call` in its `finally` with `block="budget"`/`"error"`/`None`, swallows `BudgetExceeded` so the sender emits a graceful incomplete result, re-raises `ValueError` after auditing it). Both senders rewritten to `with _sender_run([...]) as run:` + `_make_budget_cb(finding_id)`; **zero inline `try/except BudgetExceeded` / `lambda: _enforce_budget` / `_log_call` remains in either sender** (the only `except BudgetExceeded` in the file is now inside `_sender_run`). Budget stays E‑layer (no `budget_guard` import added to `cem_engine.py` — engine untouched). **Semantics preserved exactly for every reachable state** — one micro-hardening: a `ValueError` from `determinism_gate`'s `run_intervention` (only reachable via `k<1`, which callers can't hit since `k` defaults from `meta["k"]≥1`) now gets one audit line before propagating (E2 wrote none). **T-2 (strengthen partial-persistence regression):** the two budget-exhaustion tests renamed to `test_*_budget_exhaustion_persists_nothing_and_stops_sending` and extended with behaviour assertions — `len(fetched) == <requests that passed the check>` (no network after denial), `cem_load_state(fid)["trials"] == []` **and** `["verdicts"] == []` (nothing persisted). Non-vacuity confirmed by a mutation: forcing `determinism_gate` to persist a partial trial on budget hit makes the new assertion fail; reverting restores green. New B-1 behaviour test `test_budget_callback_factory_is_the_single_extension_point_for_both_senders` — a swapped `_make_budget_cb` (simulating F2's stricter ceiling) is honoured by **both** senders with `finding_id` threaded through and no persistence. TDD: B-1 test RED (`AttributeError … has no attribute '_make_budget_cb'`) → GREEN; T-2 assertions strengthened then mutation-verified. `ruff` (CI-exact) + `py_compile` clean, zero fixes. `cem_engine.py`/`case_store.py`/`test_cem_engine.py` still untouched. Full suite **1029 passed** (1028 + 1 net new test); `test_cem_mcp.py` 18/18 unchanged. B-2 (`determinism_status` conflates NONDETERMINISTIC with throttle/budget/partial) and B-3 (audit-before-persist; audit omits the outcome) **deliberately deferred** to their later architectural context (E3/G1) per the human's instruction. No commit.
- [x] **E3** — Guards: CEM tools refuse (a) a finding not in CONFIRMED state, and (b) `define_conditions` with a missing/invalid `success_signature` (UD-3 — no fallback derivation). | E1 | case-mcp/server.py | verify: pytest | accept: non-confirmed finding rejected; missing/invalid oracle → hard error, never auto-derived. **DONE 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`, full TDD)** — **TWO forks human-approved 2026-09-07 via AskUserQuestion:** (1) guard scope = `define_conditions` (entry) **+ both senders** (`determinism_gate`, `run_counterfactual` — re-checked so a finding demoted to FALSE_POSITIVE/DUPLICATE after `define_conditions` can't still send real requests); the 3 local assemblers (`minimal_condition_sets`/`minimize_poc`/`evidence_bundle`) are **not** gated (they only read already-vetted CEM state, send nothing). (2) "confirmed" = `status in {"CONFIRMED", "IMPACT_PROVEN"}` — the two `case_store.EVIDENCE_GATED_STATUSES`, which a finding can only reach with ≥1 linked evidence row (= PHASE1-PLAN §B's "independently confirmed" precondition). **`mcp-servers/case_store.py`:** added a public `get_finding(finding_id, db_path=None) -> dict | None` read accessor (the module had `create_finding`/`update_finding_status`/`score_finding_confidence` but no plain finding reader; 1-query `SELECT * FROM findings WHERE id=?`, mirrors the 3 existing inline existence-check queries; **0 removed lines**, B1/B2 CEM schema/CRUD untouched). The `case_store.py` touch is beyond E3's plan "files" column but was explicitly part of the human-approved guard-scope option. **`mcp-servers/case-mcp/server.py`:** `_CONFIRMED_STATES = ("CONFIRMED", "IMPACT_PROVEN")` + `_confirmed_or_error(finding_id)` helper (returns error-JSON if the finding is missing or not confirmed, else `None`), called at 3 sites — `define_conditions` (guard a), `determinism_gate`, `run_counterfactual` (both after `_load_cem_or_error`, before any real request). **Guard (b) in `define_conditions`:** after JSON-parse and the confirmed check, `cem_engine.SuccessSignature.from_dict(sig)` is called for its validation side effect — an unknown key, wrong type, non-dict, empty/all-`None`, `body_contains=""`, invalid `body_regex`, or out-of-range `threshold` → `{"error": "invalid success_signature (UD-3: caller-supplied only, never derived): …"}`, **before** `cem_define`; there is no auto-derivation path anywhere. `cem_define`'s own empty-`success_signature` rejection (B2) still stands as the persistence-layer backstop. TDD: 7 tests appended to `tests/test_cem_safety.py` + 1 to `tests/test_case_store.py`, written first, confirmed RED (`AttributeError: module 'case_store' has no attribute 'get_finding'` + the 6 guard behaviours), then GREEN. Covers: `define_conditions` refuses a `DISCOVERED` finding (and nothing is persisted) / accepts an `IMPACT_PROVEN` finding / refuses a `{"bogus_key": 1}` signature (not persisted, not derived) / refuses a non-object signature; `determinism_gate` + `run_counterfactual` each refuse a finding demoted to `FALSE_POSITIVE`/`DUPLICATE` **after** `define_conditions` (`fetch` spy proves **no request sent**); the 3 local assemblers still operate on a finding demoted after its verdict was recorded (not gated); `case_store.get_finding` returns the row / `None`. `ruff check` (CI-exact) + `py_compile` clean on both production files, **zero fixes**. `cem_engine.py` / `test_cem_engine.py` **not touched by E3**. Full suite **1037 passed** (1029 pre-E3 + 8), 0 failures; `test_cem_mcp.py` 18/18 (E1 helpers confirm + add evidence, so the guard is satisfied), `test_cem_engine.py` 296/296, `test_case_store.py` 36→37, `test_idor_mcp_server.py` 3/3 unmodified. No protected benchmark file touched. No commit.

### F. Scope / rate / budget / audit safety
- [x] **F1** — CEM scope enforcement: the two CEM HTTP senders cannot make an out-of-scope request. | E2 | scope_gate_hook.py, case-mcp/server.py | verify: test_cem_scope_gate.py | accept: the URL actually fetched is scope-checked before HTTP; local case-mcp bookkeeping stays usable; existing Tier-2 semantics unchanged. **DONE 2026-09-07, then REMEDIATED 2026-09-07 after an independent red-team audit returned FIXES REQUIRED (SEC-1 A-class, SEC-2 B-class).**

  **Initial F1 (superseded):** added `"case-mcp"` to `TIER2_MCP_SERVERS` and relied on the hook checking the senders' `url` argument. Audit found two substantive problems: **SEC-1** — the hook checked the caller-supplied `url` arg, but `run_intervention` actually fetches `meta["base_request"]["url"]` (stored by the un-gated local `define_conditions`); a caller passing `url=""` / a mismatched in-scope `url` while `base_request["url"]` is out of scope bypassed the gate. **SEC-2/ARCH-1** — server-level gating also scope-blocked the pre-existing local bookkeeping tools `log_experiment` / `check_experiment_exists` (their `target` arg matched `HOST_ARG_KEYS`), a capability regression.

  **Remediation (this entry — full TDD, RED confirmed then GREEN):**
  - **SEC-2/ARCH-1 → hook, reusable abstraction.** New `TIER2_MCP_TOOLS: dict[str, frozenset[str]]` in `scripts/hooks/scope_gate_hook.py` — a per-server allowlist of the tool names that touch a live target. `case-mcp` moved OUT of `TIER2_MCP_SERVERS` into `TIER2_MCP_TOOLS = {"case-mcp": {"determinism_gate", "run_counterfactual"}}`; the `main()` mcp branch gained an `elif server in TIER2_MCP_TOOLS` arm that gates only those tool names and returns 0 for every other tool on the server. New `_mcp_tool_name()` helper. Any future mixed MCP server adds one dict entry; the whole-server `TIER2_MCP_SERVERS` path is byte-unchanged for every existing server. Not a two-name exception — it is a generic mixed-server mechanism.
  - **SEC-1 → sender, decoupling-proof, no parallel validator.** `mcp-servers/case-mcp/server.py` gained `import scope_guard` + `_scope_or_error(base_request)`: before `run_intervention`, both senders call `scope_guard.is_in_scope(meta["base_request"]["url"], engagement)` — the exact value the executor fetches — reusing the SAME `scope_guard` module the hook and `scripts/check-scope.sh` use (no second source of truth for scope rules). The caller's `url` arg no longer affects the security decision. Mirrors the hook's semantics: a safe test host (loopback/RFC1918/example.*/dev-infra) needs no engagement; any other host requires an active engagement whose `in_scope` covers it. Fail-closed on missing/blank target, unreadable engagement, or any evaluation error. Runs before `_sender_run` → before `_enforce_budget` and before `http_probe.fetch`; a refusal persists nothing. The only Phase-1 perturbation (`{"drop": true}`) removes a header/query param and never changes the host, so checking `base_request["url"]` covers both arms. `cem_meta.base_request` is write-once (INSERT-only, guarded) so the load→check→use path has no TOCTOU window (same in-memory dict object throughout).
  - **Loopback edge (verified, NOT fixed here — separate follow-up).** The SENDER correctly allows a `127.0.0.1:<ephemeral>` `base_request` with or without an engagement (benchmark path). The HOOK's `url`-arg early filter still returns rc 2 for a scheme+port loopback `url` when there is no engagement — a pre-existing `_extract_hosts_from_tool_input` quirk (it does not `urlsplit` a scheme-bearing value the way `_extract_hosts_from_bash` does); not CEM-specific, fail-closed, not exercised by the benchmark. Two `test_KNOWN_*` tests pin it; a general-scope-hook fix is out of F1's scope.

  **Files:** `scripts/hooks/scope_gate_hook.py` (+`TIER2_MCP_TOOLS`, `_mcp_tool_name`, reworked mcp branch; `"case-mcp"` removed from `TIER2_MCP_SERVERS`), `mcp-servers/case-mcp/server.py` (+`import scope_guard`, `_scope_or_error`, one call in each sender, sender docstrings corrected), `tests/test_cem_scope_gate.py` (rewritten: 43 tests — hook tool-level gating incl. SEC-2, sender SEC-1 attacker matrix incl. empty/mismatched/malformed `url`, casing/port/userinfo normalization, missing url key, missing engagement, loopback, stored-state reroute, "block is upstream of HTTP and budget" replacing the old near-vacuous test, OpenCode tool-name translation, existing-Tier-2-unchanged), `tests/test_cem_mcp.py` + `tests/test_cem_safety.py` (fixtures gained an in-scope `engagement.yaml` via `HUNTMCP_ENGAGEMENT_PATH` — per-test isolation forced by the SEC-1 check, E2 precedent; every E1/E2/E3 assertion unchanged).

  **Verification:** `test_cem_scope_gate.py` 43/43; `test_scope_gate_hook.py` 40/40 unchanged; `test_scope_guard.py`, `test_cem_engine.py` 296/296, `test_cem_case_store.py` 25/25, `test_case_store.py` 37/37, `test_idor_sweep.py`+`test_http_probe.py` 47/47 unmodified; `test_cem_mcp.py` 18/18, `test_cem_safety.py` 23/23 (fixture-only change). Full suite **1080 passed, 0 failed**. Known watch-mcp timing flake (`test_check_target_twice_quickly_reuses_the_same_job_instead_of_racing`) reproduced 1/5 in isolation with zero code path to the scope hook / case-mcp — pre-existing, not attributable to F1. CI-exact `ruff check mcp-servers/ --ignore E402,F811` unchanged at 136 advisory findings (0 in any touched file); `ruff` clean on all test files; `py_compile` clean. Benchmark integrity: `scenarios.py` + `answer_key.py` `.sha256.lock` verify OK; no `tests/fixtures/cem_target/` file modified. No commit/push/merge. F2/F3/G1 not started.
- [x] **F2** — (UD-2=A) Share the engagement-wide 500-call cap AND enforce a per-finding CEM request ceiling (`HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING`, sane default). | A1 ✔, E2 | cem_engine.py/server.py | verify: pytest | accept: CEM requests count against shared budget via `enforce("case-mcp")`; exceeding the per-finding ceiling stops with partial `incomplete=1` bundle and no necessity from an incomplete arm. **DONE 2026-09-09 (completion branch `claude/cem-phase-1-completion-1a5cd5`, full TDD, attacker-first).**

  **What was built.** `budget_guard.py`: `CEM_MAX_REQUESTS_PER_FINDING_DEFAULT = 200` + `_cem_max_per_finding()` (re-reads `HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING` fresh each call; unset / malformed / non-positive → default) + `enforce_cem_finding(finding_id, path=None)` (records one CEM request in `budget.json`'s new `by_cem_finding` bucket keyed by finding id, **under the same `file_lock`** as the engagement counter; record-then-raise like `enforce()` — the denying request is counted, so retries keep climbing and never reset; raises `BudgetExceeded` once the finding's count **exceeds** the ceiling, i.e. exactly `ceiling` requests pass) + read-only `cem_requests_used()`. `_status()`/`check_budget()` **unchanged** (the exact-equality regression test still holds — `by_cem_finding` never leaks into that dict). `case_store.py`: `cem_mark_incomplete(finding_id)` (`UPDATE cem_meta SET incomplete = 1`; idempotent; no-op if undefined). `case-mcp/server.py`: `_make_budget_cb`'s `_cb()` now calls `_enforce_cem_finding(finding_id)` **then** `_enforce_budget("case-mcp")` — per-finding first so a capped finding raises *before* touching the shared counter (it can never nibble the engagement budget one denied call at a time; UD-2's stated goal). Both senders' `if run["budget_hit"]:` branch calls `case_store.cem_mark_incomplete(finding_id)`. `evidence_bundle` surfaces `bundle["incomplete"] = bool(meta["incomplete"])`. The E2 B-1 seam (`_make_budget_cb`) and `_sender_run` swallow→incomplete→one-audit-line path are reused verbatim — a per-finding `BudgetExceeded` flows through exactly like an engagement one.

  **Ordering (final):** E3 guards → F1 `_scope_or_error(base_request["url"])` → `_sender_run` → `run_intervention` → per trial: `budget_cb()` = [per-finding ceiling → engagement cap] → fetch. On any `BudgetExceeded`: in-flight trials discarded, `cem_mark_incomplete`, sender returns `incomplete:true`, **zero** `cem_record_trial`/`cem_record_verdict`, exactly one audit line `block="budget"`. Invariants I1–I11 (F2 report) all preserved; verified against every E2/E3/F1 assertion.

  **Attacker matrix (all via the real senders + a fetch spy):** cannot decouple the ceiling from a different finding (`by_cem_finding` keyed by the validated `finding_id`; a wrong/undefined/demoted finding errors out before `_make_budget_cb` is built — `spy.calls==0`, counters untouched); cannot reset the counter (persisted in `budget.json`; only `rm budget.json` resets; retry-after-denial keeps climbing); cannot consume another finding's budget (buckets independent — proven at unit + sender level); cannot bypass the engagement cap by switching sender or tool (both senders build `_cb` from the one seam; the 3 local assemblers do no HTTP and never call the ceiling — spy proves it); cannot bypass via another execution path (`run_intervention` is the only `http_probe.fetch` caller and always calls `budget_cb()` first); cannot trigger network after denial (`budget_cb()` raises before `controls.pin`/`fetch_fn`); cannot dominate the shared 500 budget with one finding (`test_single_finding_cannot_dominate_the_engagement_budget`: 20 spammed calls, engagement `calls` frozen at the finding's 6 real requests). Concurrency: N-thread race for the last per-finding slot and for the last engagement slot each admit exactly one, every attempt recorded, no lost update (`file_lock`).

  **Files:** `mcp-servers/budget_guard.py`, `mcp-servers/case_store.py` (+`cem_mark_incomplete` only), `mcp-servers/case-mcp/server.py` (+1 import, `_cb` body, 2× `cem_mark_incomplete`, bundle flag), `tests/test_budget_guard.py` (+14 unit tests), `tests/test_cem_budget_f2.py` NEW (30 tests: boundary / per-finding & engagement exhaustion / multi-finding sharing & isolation / ordering E3→scope→budget / no-network & no-persistence after denial / one-audit-line / env-var handling / seam / bundle flag / sender & unit concurrency). Written first, RED confirmed, then GREEN (3 initial reds were test-side wrong assumptions about pre-existing `enforce()` `>=`/`_load_cem_or_error` order/`classify` — corrected, none masked an impl bug).

  **Verification:** focused F2 52/52; all CEM + budget + scope + case-store files 624/624; full suite **1126 passed, 0 failed** (watch-mcp timing flake passed this run, and has no code path to F2 — `budget_guard`/`case_store`/`case-mcp` untouched by `test_watch_mcp.py`). CI-exact `ruff check mcp-servers/ --ignore E402,F811` unchanged at 136 advisory findings, **0 in any F2-touched file**; `ruff` clean on both test files; `py_compile` clean. Benchmark integrity: `scenarios.py` + `answer_key.py` `.sha256.lock` verify OK; no `tests/fixtures/cem_target/` file modified. No commit/push/merge/rebase. F3/G1 not started.
- [x] **F3** — CEM perturbation handling cannot invalidate the F1 scope guarantee (future-proofed). | E2, F1 | cem_engine.py, case-mcp/server.py | verify: test_cem_f3_perturbation_scope.py | accept: the URL scope-checked is the exact URL fetched, per trial, AFTER the perturbation; a perturbed arm cannot run unguarded; out-of-scope perturbed URL rejected before fetch, nothing persisted, one audit line. **DONE 2026-09-07 (completion branch `claude/cem-phase-1-completion-1a5cd5`, full TDD).**

  **Gap closed:** F1's `_scope_or_error` checks the stored `meta["base_request"]["url"]`; `run_intervention` actually fetches `perturbation(controls.pin(base, i))["url"]`. Today's only perturbation (`{"drop": true}`) is host-preserving, so nothing STRUCTURAL stopped a future / corrupt / hostile perturbation from rewriting scheme/host/port AFTER the F1 check and being fetched unchecked.

  **Design (A∘C — injected per-trial callback + single resolution point):** `cem_engine.run_intervention` gained `scope_check: Callable[[str], None] | None`. Inside the loop, per trial: `pin` → `perturbation` → **`scope_check(req["url"])`** → `budget_cb()` → `fetch_fn(req["url"], …)`. The scope-checked value and the fetched value are the **same local variable, one statement apart, in one function** — no perturbation type can route around it. `scope_check` is **required (`TypeError`) whenever `perturbation is not None`** — the type-level guarantee that a future perturbed arm cannot run unguarded. Ordered **before `budget_cb()`**: a scope-refused request is never counted (scope > budget > fetch). `cem_engine` stays pure — the check is injected exactly like `budget_cb` / `fetch_fn`.

  **Server:** `_make_scope_cb(engagement)` builds the callback from `scope_guard.is_in_scope` (same source of truth as F1 and the hook — no second scope validator); engagement resolved once per sender via `_scope_cb_or_error()` (fail-closed). New `ScopeDenied(Exception)`; `_sender_run` gained an `except ScopeDenied` arm (`block="scope"`, swallow, `outcome["scope_hit"]`) mirroring F2's `budget_hit`. Both senders pass `scope_check=scope_cb` to **every** `run_intervention` (baseline arm too — defence in depth) and handle `run["scope_hit"]` → `cem_mark_incomplete` + graceful `{"error", "incomplete": true}`, before any persistence. F1's `_scope_or_error` kept byte-for-byte as the cheap fail-fast on the base URL (only refactored to share `_resolve_engagement()`; behaviour identical — F1 tests unchanged and green).

  **Files:** `mcp-servers/cem_engine.py` (`run_intervention` signature +`scope_check`, loop wiring, validation, D2/invariant docstrings), `mcp-servers/case-mcp/server.py` (`ScopeDenied`, `_resolve_engagement`, `_make_scope_cb`, `_scope_cb_or_error`, `_sender_run` arm, both senders), `tests/test_cem_f3_perturbation_scope.py` NEW (31 tests: host-preserving still works; host-changing → OOS/2nd-in-scope/port/scheme/userinfo/malformed/casing/query-only; caller-vs-actual confusion; indirect bypass via extra url fields / Host header / missing url; error/default fail-closed; no-engagement loopback vs real-OOS; network-boundary via fetch spy for both senders incl. budget-not-consumed + one `block="scope"` audit line; engine-level scope-before-budget / resolved-URL / stops-arm / refuses-unguarded-perturbed-arm), `tests/test_cem_engine.py` (6 perturbed `run_intervention` calls thread the now-required `scope_check`; signature-pin + validation updated).

  **Verification:** F3 31/31; `test_cem_engine.py` (incl. updated D2/validation) green; `test_cem_scope_gate.py` (F1) + `test_cem_budget_f2.py` + `test_budget_guard.py` (F2) + `test_cem_safety.py` + `test_cem_mcp.py` + case-store/scope suites all green (599/599 for that set). Full suite **1158 passed, 0 failed** (watch-mcp timing flake did not trigger; `test_watch_mcp.py` has 0 references to any F3-touched module). CI-exact `ruff check mcp-servers/ --ignore E402,F811` back to **136**, 0 findings in `cem_engine.py` / `case-mcp/server.py`; `ruff` clean on both test files; `py_compile` clean. Benchmark integrity: `scenarios.py` + `answer_key.py` `.sha256.lock` verify OK; no `tests/fixtures/cem_target/` file modified. No commit/push/merge/rebase. G1 not started.

  **F3b / UD-4 (the plan's original F3 line) — DONE 2026-09-07 (completion branch, full TDD).** Refuse non-idempotent / state-changing CEM requests by default; a state-changing method runs only with an explicit, structured, method-specific per-finding authorization.
  - **Policy (`cem_engine.py`, pure):** `CEM_READ_ONLY_METHODS = {GET, HEAD, OPTIONS}` always pass. Any other resolved method (POST/PUT/PATCH/DELETE, TRACE/CONNECT, a custom verb, whitespace/garbage, a non-str, missing→"GET" default) is REFUSED unless a valid authorization lists it. `check_method_allowed(method, approval)` + `check_request_allowed(method, headers, approval)` — the latter also refuses a **method-override header** (`X-HTTP-Method-Override` / `X-HTTP-Method` / `X-Method-Override`) whose value is non-read-only, so a "GET" that smuggles the real verb via a framework override is caught. `normalize_method` (strip+upper) makes it case/whitespace-insensitive. All fail-closed.
  - **Authorization:** new nullable `cem_meta.nonidempotent_approval` column; set ONLY at `define_conditions` (new optional `nonidempotent_approval` JSON param), one-shot with the rest of CEM setup, never a sender argument. Shape `{"methods": [<>=1 of POST/PUT/PATCH/DELETE>], "reason": <non-empty>, "authorized_by": <non-empty>}` — `validate_nonidempotent_approval` rejects a bare bool, `{}`, a missing/blank `reason`/`authorized_by`, a non-approvable verb (TRACE/CONNECT/custom can never be authorized), a non-list `methods`. Finding status (CONFIRMED / IMPACT_PROVEN) never implies authorization. Bound to the finding by the `cem_meta` PK — cannot leak to another finding; the policy re-validates on every read, so a tampered DB row still fails closed.
  - **Enforcement (`case-mcp/server.py`):** distinct `PerturbationRefused` exception; `_sender_run` gains `block="method"`; `_nonidempotent_or_error(meta)` fail-fast on the STORED base request (ordering E3 → **UD-4** → F1 scope → F2 budget), and a per-trial `method_check(req)` (F3-style injected callback into `run_intervention`, required for any perturbed arm, ordered method → scope → budget → fetch) that catches a future perturbation that rewrites the method or injects an override header. Refusal → graceful `{"error", "incomplete": true, "refused": "nonidempotent_perturbation"}`, nothing sent, no partial trial/verdict; per-trial path marks `cem_meta.incomplete` and writes the one `block="method"` audit line (fail-fast returns before `_sender_run`, no audit line, like F1/E3).
  - **Files:** `cem_engine.py` (policy fns + `run_intervention` `method_check` param), `case_store.py` (`cem_meta.nonidempotent_approval` + `cem_define`/`cem_load_state`), `case-mcp/server.py` (`PerturbationRefused`, `_nonidempotent_or_error`, `_make_method_cb`, `_sender_run`, both senders, `define_conditions` param), `tests/test_cem_f3b_nonidempotent.py` NEW (~87 cases: pure policy matrix incl. override headers + malformed approvals; persistence + define-rejects-bad-approval; POST/PUT/PATCH/DELETE base method blocked (both senders); valid approval reaches fetch with normal audit; approval is method-specific + finding-bound + not caller-supplied + corrupted-row-fails-closed; ordering vs E3/F1/F2; future perturbation rewrites method / injects override header / dict-subclass divergence; alternate representations lowercase/whitespace/custom/missing/conflicting-keys; plain-GET regression), plus `tests/test_cem_engine.py` (perturbed sites thread `method_check`; signature-pin + validation) and `tests/test_cem_case_store.py` (`cem_meta` column set) and `tests/test_cem_f3_perturbation_scope.py` (engine-level perturbed sites).
  - **Verification:** F3b ~87/87; full suite **1246 passed, 0 failed**; CI-exact `ruff check mcp-servers/` unchanged at 136 (0 in any touched file); `ruff` clean on test files; `py_compile` clean; benchmark `.sha256.lock`s verify, no `tests/fixtures/cem_target/` file modified. **Limitation:** the approval has no TTL / version — `cem_meta` has no time semantics; it is valid for the life of the finding's one-shot CEM state (engagement-scoped DB). A compromised model that also fabricates a syntactically-valid approval is not prevented by an in-band control — mitigated by the mandatory human review before submission and the persisted, attributable (`reason` + `authorized_by`) audit trail. No commit/push/merge/rebase. G1 not started.

### G. Evidence handling
- [x] **G1** — System-level adversarial integration / security review of the COMPLETE CEM Phase-1 control stack (E3 → UD-4 → F1 → F2 → run_intervention → fetch). | D1–D3, E1–E3, F1, F2, F3, F3b | (review; +1 fix in case-mcp/server.py) | verify: test_cem_g1_integration.py | accept: no combination of inputs/state/retries/perturbations/failures bypasses a CEM invariant or produces misleading evidence; all frozen phases still green. **DONE 2026-09-09 (completion branch `claude/cem-phase-1-completion-1a5cd5`, review + one B-class fix).**
  - **Method:** reconstructed the full production control flow end-to-end; attacked the composition (cross-control ordering, first-authoritative-denial + no-later-side-effect, evidence integrity under truncation, alternate paths to `fetch_fn`, TOCTOU/concurrency, hostile persisted state). New `tests/test_cem_g1_integration.py` (23 cases) drives the REAL case-mcp tools / `run_intervention` with a recording fetch spy and asserts actual fetch URLs/methods/counts, persisted trials/verdicts, `cem_meta.incomplete`, audit `block`, and budget counters.
  - **Composition verified:** ordering E3 → UD-4 → F1 → F2 → HTTP holds in both senders; each control yields its own distinct signal; `_perturbation_for` runs between E3b and UD-4 as a pure translation step (not a gate). For every ALL-FOUR scenario (FALSE_POSITIVE+OOS+POST+budget, CONFIRMED+OOS+POST+approval, CONFIRMED+in-scope+POST+no-approval, all-pass+exhausted-budget, invalid-signature+OOS+POST, valid-everything+GET) the FIRST authoritative denial fires and NOTHING downstream happens: `spy.calls == []`, no trials/verdicts persisted, `by_cem_finding` untouched (UD-4/F1/E3 fail-fasts precede the budget callback). Retries after any denial stay denied and leak nothing.
  - **Evidence integrity verified:** a perturbed-arm denial DISCARDS the already-executed baseline arm (nothing persisted, `incomplete=1`); a throttle-aborted perturbed arm → `inconclusive`, never `necessary` (partial/throttle guard + `apply_throttle_gate`); `classify()` hard-requires `len==k` per arm and is only called when `not partial`; `evidence_bundle` reports a denied condition as `untested` (never a fake verdict), `identified_necessary_conditions` derived from real stored verdicts, `incomplete: true` when any sender marked it; local assemblers never reach `fetch_fn` even on a demoted finding.
  - **Alternate paths verified:** `http_probe.fetch` is passed ONLY to `run_intervention` at exactly 3 call sites (determinism_gate ×1, run_counterfactual ×2); `run_intervention` is called ONLY by the two senders; local assemblers (`minimal_condition_sets`/`minimize_poc`/`evidence_bundle`) are pure/read-only; the `url` sender arg is an audit label and an OOS stored base cannot be laundered through it; no CEM tool writes or resets `budget.json`.
  - **Concurrency verified:** `cem_meta.base_request` / `success_signature` / `nonidempotent_approval` are write-once (INSERT-only `cem_define`, one-shot; only `UPDATE` anywhere is `cem_mark_incomplete` → `incomplete=1`) so the approval/base/signature snapshots have no TOCTOU; budget counters mutate under a shared cross-process `file_lock`; 6 concurrent `run_counterfactual` runs for one finding produce 6 honest verdicts (no `necessary` from a race), additive consistent trials, and exactly-once budget accounting.
  - **B-1 (found + FIXED in G1):** a budget-denied `determinism_gate` returned `determinism_status: "NONDETERMINISTIC"` — a value computed from zero trials that a consumer could read on its own as a real observation. Fixed (`case-mcp/server.py` determinism_gate: `if out.get("incomplete"): out["determinism_status"] = "INCOMPLETE"`). Regression test added; `determinism_gate`'s return is not persisted and every existing `determinism_status` assertion is on a *completing* run, so 0 regressions.
  - **Accepted (C/D):** TOCTOU on finding *status* between the E3 check and the in-flight fetches (per-trial requests are still F1/F2/UD-4-gated, no false evidence — E3 correctly gates run *initiation*); fail-fast denials write no audit line (codebase-wide "audit executed calls only" convention, reviewed & accepted at F1/F2/F3b; per-trial denials ARE audited with distinct `block`); `evidence_bundle` aggregates baseline determinism across multiple runs' baseline arms; malformed condition dict at `define_conditions` → ungraceful KeyError but clean rollback, nothing persisted, local tool.
  - **The plan's original G1 (content-addressed request/response evidence hashing — `cem_trials.request_evidence_hash`/`response_evidence_hash`, `assemble_bundle`'s `audit_trail`) remains UNBUILT** — a capability limitation (the exact request/response bytes cannot be rebuilt from the bundle), NOT a security or correctness defect: trials persist `arm`/`k_index`/`http_status`/`oracle_hit`, verdicts are honest, the bundle honestly signals `incomplete`. Track as a separate follow-up.
  - **Verification:** G1 23/23; per-suite all green (test_cem_engine 296, test_cem_safety 16, test_cem_scope_gate 43, test_cem_budget_f2 26, test_cem_f3_perturbation_scope 32, test_cem_f3b_nonidempotent 87, test_cem_case_store 25, test_cem_mcp 18, test_scope_guard 24, test_budget_guard 27, test_scope_gate_hook 56); full suite **1269 passed, 0 failed**; CI-exact `ruff check mcp-servers/` unchanged at 136 (0 in any touched file); `ruff`/`py_compile` clean on touched files; benchmark `.sha256.lock`s verify, `tests/fixtures/cem_target/` untouched. No commit/push/merge/rebase.

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
- [~] **N2** — Update ROADMAP.md PROJECT STATE + this doc's CURRENT EXECUTION STATE. | P1 | ROADMAP.md, this doc | verify: read-back | accept: state reflects reality. **PARTIAL — 2026-09-07:** state-reconciliation pass done as the first task of the CEM Phase-1 completion effort (out of P1 order, by explicit human instruction): §19 "Mainline reconciliation" box added; §6 B1–B3 markers `[x]`→`[~]` with a not-on-mainline box; ROADMAP.md PROJECT STATE block rewritten to reflect G0 granted / A+C+H merged / B1–B3 recoverable-uncommitted / D–P not started / acceptance gate pending. No implementation code touched. _(Update 2026-09-07: the completion effort has since recovered all of Group B onto this branch — B1 (CEM schema + schema tests), B2 (CEM enum constants + 4 CRUD helpers), B3 (6 cascade/isolation tests + helpers) — so §6 B1/B2/B3 are all back to `[x]` and the box is titled "RECOVERY STATUS". Still uncommitted / not on `main`.)_ The final N2 read-back (post-P1, once Phase-1 actually passes its gates) is still pending — marker stays `[~]`.

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

### Mainline reconciliation (task N2 — 2026-09-07)

The code block below accumulated across earlier sessions and predates PR #93. It is **retained as a session
history record**. For the **authoritative current state of `main` / this completion branch**, use this
reconciliation (verified against `git ls-files`, `git show HEAD:…`, and `.venv/bin/python -m pytest tests/ -q`):

- **Merged to `main`** (branch HEAD `1421174` == `main`; first-add provenance from `git log --diff-filter=A`):
  - **Group A** — A1 (decisions) / A2 (worktree): process/doc only. A3 (`docs/cem-phase1-baseline.txt`): first
    tracked in **PR #92** (`3cb25bb`). A4 (`mcp-servers/http_probe.py` + `tests/test_http_probe.py` +
    `idor_sweep.py` re-export refactor): **PR #93** (`796831a`).
  - **Group C** — C1–C8 pure CEM engine (`mcp-servers/cem_engine.py` + `tests/test_cem_engine.py`), including
    the two retrospective C1–C8 audit-fix rounds and the C6 AND-necessity addendum (`redact.py`
    `KNOWN_SECRET_HEADER_NAMES` / `redacted()` also present on HEAD) — **PR #93** (`796831a`).
  - **Group H** — H1/H2 benchmark environment (`tests/fixtures/cem_target/*`, `tests/test_cem_environment.py`)
    and Phase-1a testing-architecture hardening (blind manifest / answer-key split / independent evaluator /
    harness-security / metrics — `test_cem_evaluator.py`, `test_cem_harness_security.py`,
    `test_cem_scenarios_blind.py`) — **PR #92** (`3cb25bb`), an ancestor of HEAD. (`826449f`, called the
    "Phase-1a checkpoint" in #93's commit message, is a pre-squash commit and is **not** in HEAD's history.)
  - Planning docs (ROADMAP.md, PHASE1-PLAN.md, PHASE1-EXECUTION-PLAN.md, XYZ.md,
    INTELLIGENCE-ALLOCATION-MEMO.md) — first tracked in **PR #93** (`796831a`).
- **Group B — B1 + B2 + B3 all recovered onto this branch (completion effort); nothing on `main`:**
  - **B1 — RECOVERED & VERIFIED (2026-09-07).** The 4 CEM tables (`cem_meta`/`cem_conditions`/`cem_trials`/
    `cem_verdicts`) in `case_store._init_schema()` (byte-for-byte from the `phase1-cem-implementation-6e1693`
    worktree) + a schema paragraph in the module docstring; the 19 schema-contract tests in
    `tests/test_cem_case_store.py`. See §6 B1.
  - **B2 — RECOVERED & VERIFIED (2026-09-07).** `CEM_TRIAL_ARMS`/`CEM_VERDICTS` constants + the 4 CRUD helpers
    `cem_define`/`cem_record_trial`/`cem_record_verdict`/`cem_load_state` recovered byte-for-byte (one
    disclosed stale-comment-line delta). `mcp-servers/case_store.py` (723 lines) is byte-identical to the
    recovered copy except that comment + B1's docstring wording. See §6 B2.
  - **B3 — RECOVERED & VERIFIED (2026-09-07).** `_full_cem_state`/`_cem_row_counts`/`_delete_finding` helpers +
    6 cascade-delete/deep-isolation tests appended to `tests/test_cem_case_store.py` (now **25 tests**),
    byte-for-byte from the recovered worktree (module docstring aside). No production code changed. Full suite
    **917 passed**; non-vacuity proven via a `foreign_keys=OFF` spike. See §6 B3.
  - **On `main`: none of B1/B2/B3.** All of it is uncommitted working-tree state on
    `claude/cem-phase-1-completion-1a5cd5`. `tests/test_cem_case_store.py` is untracked; `case_store.py` is
    modified-not-committed.
- **D1 — DONE & VERIFIED on this branch (2026-09-07).** First non-recovery task, full TDD. `Controls` dataclass
  (session-header pinning, per-trial cache-buster, injected `csrf_provider`, `ordering`/`concurrency` Phase-1
  locks, `uncontrolled` set) + `apply_control_gate(verdict, controls)` in `mcp-servers/cem_engine.py`
  (appended after `assemble_bundle`; C1–C8 bodies byte-untouched). 41 new tests (211→252). Full suite
  **958 passed**. API shape (methods on `Controls` + module gate fn; full `csrf_provider` injection)
  human-approved 2026-09-07 via AskUserQuestion. See §6 D1.
- **D2 — DONE & VERIFIED on this branch (2026-09-07).** Full TDD. `Trial` dataclass + `run_intervention(...)`
  + `ARM_BASELINE`/`ARM_PERTURBED` in `mcp-servers/cem_engine.py` (appended after `apply_control_gate`;
  C1–D1 bodies byte-untouched). One call = one arm, k trials: injected `perturbation: Callable[[dict],dict]|None`
  (`None`=baseline), injected `sleep_fn` for inter-trial spacing, `budget_cb()` per request (a raise
  propagates — F2 owns partial/`incomplete`), `Controls.pin` + `perturbation` + `fetch_fn` + `evaluate_signature`.
  Both forks (perturbation-as-callable, sleep_fn injection) human-approved 2026-09-07 via AskUserQuestion.
  25 new tests (252→277). Full suite **983 passed**. See §6 D2.
- **D3 — DONE & VERIFIED on this branch (2026-09-07).** Full TDD. `THROTTLE_STATUS = 429` + `throttled_in(trials)`
  + `apply_throttle_gate(verdict, trials)` in `mcp-servers/cem_engine.py` (parallel to D1's `has_uncontrolled`
  / `apply_control_gate`), **plus a 3-line change inside `run_intervention`** — the loop appends a 429 `Trial`
  then `break`s (aborts the arm; a throttled arm returns < k trials). Both forks (429-only signal;
  abort-on-first-429) human-approved 2026-09-07 via AskUserQuestion. `apply_throttle_gate` forces
  `inconclusive` regardless of the verdict passed in → a throttled arm can never yield `necessary`. `classify()`
  stays status-blind (C3-pinned). 19 new tests (277→296). Full suite **1002 passed**. See §6 D3.
  **Group D (intervention executor) is now complete.**
- **E1 — DONE & VERIFIED on this branch (2026-09-07).** First task touching an MCP server file. All 6 CEM
  `@app.tool()` wrappers added to `mcp-servers/case-mcp/server.py` (existing 15 tools byte-untouched; only
  import-block change adds `cem_engine`/`http_probe`/`urllib.parse`). `tests/test_cem_mcp.py` NEW (18 smoke
  tests; server loaded via `spec_from_file_location`, `http_probe.fetch` monkeypatched, `HUNTMCP_CASE_DB_PATH`
  per-test DB). Depth = "fuller" (senders persist `cem_trials`; `run_counterfactual` persists one `cem_verdicts`)
  and perturbation vocab = implicit `{"drop": true}` — both human-approved 2026-09-07 via AskUserQuestion.
  `run_counterfactual` checks `throttled_in`/partial-arm before `classify` then `apply_control_gate` +
  `apply_throttle_gate`. Budget/audit (E2), CONFIRMED/UD-3 guards (E3), `TIER2_MCP_SERVERS` (F1), request
  ceiling (F2), non-idempotent refusal (F3), evidence hashes + live subset re-trials + `determinism_status`
  persistence (G1) all deferred. `cem_engine.py`/`case_store.py` not touched. Full suite **1020 passed**. See §6 E1.
- **E2 — DONE & VERIFIED on this branch (2026-09-07).** Both senders now wire `budget_guard.enforce("case-mcp")`
  (via D2's `budget_cb` injection — one check before every real request) + `audit_log.log_call("case-mcp", …)`
  (one line per tool call), mirroring `idor-mcp/server.py`. A `BudgetExceeded` raise → graceful
  `{"error", "incomplete": true}`, no partial persistence (F2 owns partial). `tests/test_cem_safety.py` NEW
  (8 tests). E1's `test_cem_mcp.py` fixture gained `HUNTMCP_BUDGET_PATH`/`HUNTMCP_AUDIT_LOG` isolation (a
  correction forced by E2's contract change, not a weakening). Local tools untouched. `cem_engine.py`/
  `case_store.py` not touched. Full suite **1028 passed**. **B-1 + T-2** (post-audit, human-approved): the
  budget/audit control flow is now shared via a `_make_budget_cb(finding_id)` factory (F2's per-finding-ceiling
  seam) + a `_sender_run(...)` contextmanager (one audit line, swallow `BudgetExceeded`, re-raise `ValueError`)
  — zero inline duplication left in the senders, engine still untouched; the 2 budget-exhaustion tests
  strengthened to prove `trials==[] ∧ verdicts==[] ∧ no fetch after the denied check` (mutation-verified). B-2
  (`determinism_status` conflation) / B-3 (audit-before-persist) deferred to E3/G1. Full suite **1029 passed**.
  See §6 E2.
- **E3 — DONE & VERIFIED on this branch (2026-09-07).** Guards: `define_conditions` + both senders refuse a
  finding not in `{CONFIRMED, IMPACT_PROVEN}` (senders re-check, so a post-`define` demotion can't send real
  requests); the 3 local assemblers are not gated. `define_conditions` also rejects a missing/invalid
  `success_signature` via `cem_engine.SuccessSignature.from_dict` (UD-3 — no derivation). New public
  `case_store.get_finding()` read accessor (0 removed lines; B1/B2 untouched — the `case_store.py` touch was
  part of the human-approved guard-scope option). Both forks human-approved 2026-09-07 via AskUserQuestion. 8
  new tests. Full suite **1037 passed**. See §6 E3. **Group E (MCP tool integration) is now complete.**
- **Not started:** Groups **F–P** except H — F1–F3 (scope/rate/budget/idempotency), G1 (evidence
  persistence), I1 (coverage), J1 (integration), K1/K2 (benchmark + FCCR), L1 (regression), M1
  (performance), N1 (docs), O1 (security audit), P1 (final acceptance). N2 is the doc-reconciliation pass
  (this section).
- **Phase-1 acceptance gate:** still **PENDING**. `scripts/verify-phase1.sh` gates G1–G9 have not been run to
  green; FCCR has not been measured against the CEM engine; `case-mcp` is still not in `TIER2_MCP_SERVERS`
  (F1) — the 6 CEM tools exist (E1), are budget/audit-wired (E2), and CONFIRMED/UD-3-guarded (E3), but are
  **not scope-gated yet**.
- **This-branch test suite:** `1037 passed` (`.venv/bin/python -m pytest tests/ -q`, 2026-09-07; 892 pre-Group-B
  baseline + 19 B1 + 6 B3 + 41 D1 + 25 D2 + 19 D3 + 18 E1 + 8 E2 + 1 E2‑B1 + 8 E3 tests; B2 added no tests).
  The `909 passed` figure in the block below is an older, different-tree measurement.

```
CURRENT MILESTONE:     [SUPERSEDED for current-state — see "Mainline reconciliation" above. History record:]
                       Phase 1a COMPLETE & verified; G0 human implementation approval GRANTED; Group A
                       COMPLETE (A1-A4); Group B (schema) implemented in a prior session but NOT on mainline
                       (B1-B3 recoverable/uncommitted in the phase1-cem-implementation-6e1693 worktree);
                       Group C (CEM engine) COMPLETE —
                       C1 DONE (SuccessSignature/evaluate_signature), C2 DONE (determinism_gate), C3 DONE
                       (classify), C4 DONE (classify_race), C5 DONE (minimal_condition_sets), C6 DONE
                       (find_alternate_condition_sets), C7 DONE (minimize_poc), C8 DONE (assemble_bundle).
                       Group C is now fully complete; Group D (intervention executor) not yet started.
                       Since C8, TWO independent retrospective audits of C1-C8 ran (later sessions, both
                       2026-09-05) and their approved findings are now fixed: C1's vacuous-oracle gap
                       (body_contains=""/similarity threshold<=0.0), C8's dict-value redaction blind spot
                       (fixed in two rounds — scalar header values, then list-valued headers), and a new
                       C6 addendum (AndNecessityGroup/find_and_necessity_groups, human-approved Option 2)
                       for mutual AND-necessity detection, which C6's original Rule 1/Rule 2 cannot express.
                       See each task's own bullet below for full detail; none of this altered C1-C7's
                       original semantics or any protected benchmark file (checksums verified unchanged).
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
TESTS PASSING (CURRENT, post-audit-fixes, later sessions, 2026-09-05): 909 passed, 0 failed (full
                       suite). Breakdown: 869 (C8's own total, above) + 5 C1-fix tests + 8 C8-redaction-
                       fix-round-1 tests + 3 redact.py tests + 19 C6-addendum tests + 5 C8-redaction-
                       fix-round-2 tests = 909. tests/test_cem_engine.py: 211/211 GREEN. tests/
                       test_redact.py: 18/18 GREEN (15 original + 3 new). No C1-C7 test modified or
                       removed anywhere across either audit round — every diff to test_cem_engine.py is
                       purely additive (`git diff | grep '^-'` on that file returns nothing). ruff clean
                       on every file touched by either audit round (cem_engine.py, redact.py,
                       test_cem_engine.py, test_redact.py) and on the CI-exact command (`ruff check
                       mcp-servers/ --ignore E402,F811 --target-version py312` — 136 pre-existing,
                       unrelated repo-wide errors, none in any CEM file).
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
                       D1 API AMBIGUITY (human-approved 2026-09-07 via AskUserQuestion, 2 questions, not
                       guessed — same class as C4/C5/C6): PHASE1-PLAN.md §9 names the `Controls` fields + the
                       "uncontrolled → `uncontrolled:<name>` → `inconclusive`" behavior but no engine-layer
                       signatures. Resolved: (1) methods on `Controls` (`pin`/`record`/`has_uncontrolled`) +
                       a module-level `apply_control_gate(verdict, controls)` — not an all-free-functions
                       shape and not folded into D2; (2) full CSRF machinery in D1 — `csrf_header_name` +
                       an injected `csrf_provider: Callable[[], str]` (C2 `fetch_fn` precedent), header-name-
                       without-provider auto-marks `"csrf_token"` uncontrolled — not deferred to D2.
                       Additional D1 design calls taken from the plan text + repo rules, not guessed:
                       `record()` stores session-header NAMES only, never values (security.md — no secrets in
                       the DB/report); `ordering`/`concurrency` are hard Phase-1 locks (`"sequential"`/`1`),
                       any other value rejected at construction; the per-trial cache-buster is
                       `_cb=<trial_index>` (deterministic/reproducible for the Triager-Proof Bundle, and the
                       one field that intentionally differs per trial). D1 ruff fix (TRY004, C1 precedent):
                       one `ValueError` behind an `isinstance(..., str)` check on `request["url"]` → `TypeError`;
                       a bundled "non-empty string" check on `uncontrolled` split into `TypeError` (wrong type)
                       + `ValueError` (empty) — 3 of D1's own net-new test expectations updated to match, no
                       C1–C8 test touched.
                       D2 DESIGN FORKS (human-approved 2026-09-07 via AskUserQuestion, 2 questions, not
                       guessed — C4/C5/C6/D1 precedent): (1) `perturbation` is an injected
                       `Callable[[dict], dict]` (`None` = baseline/determinism arm), NOT a structured dict
                       D2 interprets — `run_intervention` stays a pure loop, "one variable at a time" is the
                       caller's contract, the E-layer translates the stored `cem_conditions.perturbation`
                       JSON into a callable; (2) inter-trial spacing via an injected
                       `sleep_fn: Callable[[float], None] = time.sleep` (spy-able), NOT a bare `time.sleep`.
                       `success_signature`/`fetch_fn` added beyond the §6 shorthand are the exact C2
                       precedent (structurally required — oracle + fetch), not escalated. `budget_cb` raise
                       propagates (partial/`incomplete` is F2); C2's standalone `determinism_gate` is NOT
                       refactored (one-task rule — coexists with `run_intervention(perturbation=None)`).
                       No D2 ruff fixes needed.
                       D3 DESIGN FORKS (human-approved 2026-09-07 via AskUserQuestion, 2 questions, not
                       guessed): (1) throttle signal = HTTP 429 only (`http_status == 429`) — plan-literal,
                       `FetchResult` has no headers so `Retry-After` is unavailable; a 503/other is already a
                       MISS so it can at worst reach `inconclusive` via C3's mixed rule, never a false
                       `necessary`; (2) `run_intervention` aborts the arm on the first 429 (appends that
                       `Trial`, then `break` — a throttled arm returns < k trials). Modifying `run_intervention`
                       (a D2 fn) is IN SCOPE — D3's task line says detection "in executor", dep D2. `classify()`
                       untouched (C3-pinned; its signature-pin test still passes). No baseline-re-check
                       interleave (a PHASE1-PLAN mitigation *idea*, not a D3 acceptance requirement). No D3
                       ruff fixes needed.
                       E1 DESIGN FORKS (human-approved 2026-09-07 via AskUserQuestion, 2 questions):
                       (1) depth = "fuller" — the senders persist `cem_trials` rows and `run_counterfactual`
                       persists one `cem_verdicts` row (PHASE1-PLAN §B steps 2-3), beyond the bare
                       "registered + delegate" accept; (2) perturbation vocabulary = the implicit
                       `{"drop": true}` shape from `tests/test_cem_case_store.py` — drop the header or query
                       param the condition names (auth-header aliases; unknown shape / un-locatable target →
                       hard error, never a silent no-op). `success_signature`/`fetch_fn`/`budget_cb=lambda:None`
                       injected into the engine per the C2/D2 precedent. `minimal_condition_sets`/`minimize_poc`
                       use a stored-verdict predicate (droppable iff recorded `apparently_not_necessary`) —
                       live bounded subset re-trials need the budget guard (E2) and are G1's wiring.
                       `determinism_status` is returned but not persisted (no `case_store` setter — deferred).
                       One I001 ruff import-sort fix in the test file; no production-code ruff fixes.
                       E2 (no fork escalated): §5's "same pattern as idor-mcp" resolves §6's "per real
                       request" — idor-mcp enforces budget per request but audits once per tool call; E2
                       mirrors that (budget via D2's `budget_cb=lambda: _enforce_budget("case-mcp")`, one
                       `_log_call` summary per invocation, `block="budget"`/`"error"` on the failure paths).
                       `BudgetExceeded` → graceful `{"error","incomplete":true}`, no partial persistence
                       (F2 owns partial). DEVIATION (disclosed, test-isolation): E1's `test_cem_mcp.py`
                       fixture gained `HUNTMCP_BUDGET_PATH`/`HUNTMCP_AUDIT_LOG` — required because E2 made
                       the senders touch real budget/audit files; every E1 assertion unchanged.
                       E2 B-1/T-2 (post-audit, human-approved, verdict SAFE WITH IMPROVEMENTS): de-dup the
                       two senders' budget/audit control flow into `_make_budget_cb(finding_id)` (F2 seam —
                       `finding_id` threaded now, unused today) + `_sender_run(tool_args)` (`@contextmanager`,
                       one audit line in its `finally`, swallow `BudgetExceeded`, re-raise `ValueError`).
                       Semantics preserved for every reachable state; one micro-hardening — a `ValueError`
                       from `determinism_gate`'s `run_intervention` (only via `k<1`, which callers can't
                       reach) now gets one audit line before propagating (E2 wrote none). B-2/B-3 explicitly
                       deferred (E3/G1). E3 (2 forks human-approved via AskUserQuestion): guard scope =
                       `define_conditions` + both senders (not the 3 assemblers); "confirmed" =
                       `{CONFIRMED, IMPACT_PROVEN}` (the `EVIDENCE_GATED_STATUSES`). `case_store.py` gained a
                       `get_finding()` read accessor — beyond E3's plan "files" column but part of the
                       approved guard-scope option (0 removed lines; B1/B2 untouched). No E3 ruff fixes.
NEXT EXACT TASK:       [SUPERSEDED — see "Mainline reconciliation" above. Group B recovered; Group D complete;
                       Group E (MCP tool integration) complete — E1 (6 CEM `@app.tool()` wrappers), E2
                       (`budget_guard.enforce` + `audit_log.log_call` inline in the 2 senders, idor-mcp
                       pattern; + B-1 `_make_budget_cb`/`_sender_run` de-dup + T-2), E3 (CONFIRMED/IMPACT_PROVEN
                       guard on `define_conditions` + both senders; `SuccessSignature.from_dict` validation on
                       `define_conditions`; new `case_store.get_finding()`) all DONE & VERIFIED on this branch
                       2026-09-07 (full TDD; 18 + 9 + 8 tests; full suite 1037 passed; every design decision
                       human-approved via AskUserQuestion). The next completion task is F1: add `"case-mcp"`
                       to `scope_gate_hook.TIER2_MCP_SERVERS` so the two senders' `url` arg is scope-gated
                       (out-of-scope `url` → rc 2; host-arg-less local tools → rc 0). In
                       `scripts/hooks/scope_gate_hook.py`. Deps: E2 ✔. Verify: `test_cem_scope_gate.py` (new).
                       Accept: out-of-scope sender blocked; local tool allowed. History record of the pre-#93
                       pointer follows:]
                       D1 — `Controls` dataclass + pinning helpers (session headers, cache-buster, ordering,
                       spacing_ms, concurrency=1; uncontrollable confounder → recorded, forces inconclusive),
                       in cem_engine.py. Deps: C1 ✔. Verify: pytest. Accept: uncontrolled confounder →
                       inconclusive. [Now DONE — see §6 D1.] Group C (C1-C8) is fully complete, and two
                       rounds of retrospective C1-C8 audit fixes (below) are also complete.
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

LAST VERIFICATION CMD (CURRENT, post-audit-fixes): python3 -m pytest tests/ -q  (909 passed, 0 failed) —
                       run independently, not taken on any prior report alone; `ruff check
                       mcp-servers/cem_engine.py mcp-servers/redact.py tests/test_cem_engine.py
                       tests/test_redact.py` → All checks passed.
LAST VERIFICATION RESULT (CURRENT): two independent retrospective audits of C1-C8 ran in later sessions
                       (both 2026-09-05), each reading the actual code/tests/git-diff fresh rather than
                       trusting the prior report. Round 1 fixed the two audit-confirmed HIGH findings (C1's
                       vacuous body_contains=""/threshold<=0.0 oracle; C8's dict-value redaction blind spot
                       for scalar header values) and added the human-approved C6 addendum (AndNecessityGroup
                       / find_and_necessity_groups). The second, independent audit re-verified all of round
                       1 live (not from memory), confirmed zero regressions and zero scope creep, and found
                       one new Medium finding (list-valued secret headers, e.g. repeated Set-Cookie, still
                       leaking an opaque element) plus this plan document being out of sync with the actual
                       code state. This edit resolves the plan-sync finding; the list-valued-header fix
                       (round 2, above under C8) resolves the Medium finding. Every C1-C8 audit finding
                       classified HIGH or Medium across both audits is now resolved. Findings deliberately
                       left open (explicitly out of scope for what was approved, tracked above under each
                       task's own bullet): SuccessSignature's `body_regex=""` vacuous-oracle vector (C1);
                       header names outside the 4 canonical ones, e.g. `X-Auth-Token`/`X-Session-Id` (C8);
                       `case_store.cem_define` not yet validating `success_signature` via
                       `SuccessSignature.from_dict()` (deferred to E3, as originally planned); C6's
                       `max_trials` counting abstract predicate calls rather than real k-multiplied HTTP
                       request cost (deferred to Group D/F2 wiring); `http_probe.fetch()` having no scheme/
                       host validation of its own (deferred to Group D/E — currently unreachable, since
                       `case-mcp` is still not in `TIER2_MCP_SERVERS` and no CEM MCP tool exists yet,
                       reconfirmed this session); the `answer_key.py` case_03 ground-truth reconciliation
                       (deferred future work per the approved C6 decision — the protected benchmark files
                       were not modified in either audit-fix round, checksums verified unchanged against
                       their `.sha256.lock` files both times). No C1-C7 semantics changed at any point
                       across either round — confirmed both by full regression (909/909) and by `git diff`
                       showing zero removed lines in any C2-C7 function body.
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
