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
- [ ] **A2** — Create isolated worktree/branch for Phase 1 (via `superpowers:using-git-worktrees`). | A1 | — | verify: `git status` on new branch | accept: not on main.
- [x] **A3** — Baseline capture: full suite recorded. | — | docs/cem-phase1-baseline.txt | verify: file present | accept: recorded. **DONE 2026-09-04 — 637 passed (624 pre-existing + 13 new env tests), ~11s.**
- [ ] **A4** (UD-1=B) — Extract `http_probe.py`; refactor `idor_sweep.py` to import it. | A1 ✔ | http_probe.py, idor_sweep.py | verify: `pytest tests/test_idor_sweep.py` | accept: idor tests green, byte-for-byte behavior preserved (regression guard).

### B. Schema / data model
- [ ] **B1** — Failing test for the 4 CEM tables + isolation. | A2 | test_cem_case_store.py | verify: test fails | accept: red.
- [ ] **B2** — Add tables to `_init_schema` + CRUD helpers. | B1 | case_store.py | verify: `pytest tests/test_cem_case_store.py` | accept: green; existing `test_case_store.py` still green.
- [ ] **B3** — Cascade-delete + per-engagement isolation tests. | B2 | test_cem_case_store.py | verify: pytest | accept: deleting a finding removes its CEM rows; two engagements don't mix.

### C. CEM engine (pure logic, TDD)
- [ ] **C1** — `SuccessSignature` + `evaluate_signature(FetchResult, sig)` (status set / body substring / regex / similarity-to-baseline). Oracle is **caller-supplied only** (UD-3). | A4 | cem_engine.py, test_cem_engine.py | verify: pytest | accept: matcher covers each case; **no code path auto-derives the oracle from a baseline response.**
- [ ] **C2** — `determinism_gate(base_request, k)` using a fake fetch: STABLE iff all-k HIT; else NONDETERMINISTIC. | C1 | cem_engine.py | verify: pytest | accept: mixed baseline → NONDETERMINISTIC.
- [ ] **C3** — `classify(baseline_hits, perturbed_hits, k)` → verdict rules (necessary/apparently_not_necessary/inconclusive; throttle→inconclusive; mixed→inconclusive). | C1 | cem_engine.py | verify: pytest | accept: every rule row from PHASE1-PLAN §D covered.
- [ ] **C4** — race/TOCTOU path → `probabilistic` (report perturbed HIT-rate; never necessary). | C3 | cem_engine.py | verify: pytest | accept: flagged-race input never yields `necessary`.
- [ ] **C5** — `minimal_condition_sets()`: ddmin for one 1-minimal set. | C3 | cem_engine.py | verify: pytest with known set | accept: recovers planted minimal set.
- [ ] **C6** — alternates + interaction detection (bounded; report completeness). | C5 | cem_engine.py | verify: pytest | accept: ≥2 sets when planted; interaction-only flagged `interacting`; bound reported.
- [ ] **C7** — `minimize_poc()`: ddmin over conditions/steps, runs AFTER verdicts, re-validated by determinism gate. | C5 | cem_engine.py | verify: pytest | accept: unnecessary condition dropped; minimal PoC re-passes gate.
- [ ] **C8** — `assemble_bundle()`: all 15 §2.8 fields; redacted via `redact_text`. | C3..C7 | cem_engine.py | verify: pytest | accept: bundle schema has every field; redaction applied.

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
CURRENT MILESTONE:     Phase 1a (testing-architecture hardening) COMPLETE & verified; CEM engine NOT started (awaiting G0)
COMPLETED TASKS:       A1 (decisions), A3 (baseline), H1 (target), H2 (ground truth+fixture);
                       Phase 1a A1-A4 + B1-B3 (blind manifest / answer-key split / independent evaluator /
                       harness security / evidence trail / mutation target / metrics)
IN-PROGRESS TASK:      (none)
BLOCKED TASKS:         (none) — CEM tasks (A2/A4/B..P) gated only on human G0 implementation approval
FILES CHANGED:         tests/fixtures/cem_target/{cem_benchmark_app,scenarios,answer_key,evaluator,integrity,
                       ground_truth(tripwire),__init__}.py + *.sha256.lock; tests/test_cem_environment.py;
                       tests/test_cem_scenarios_blind.py; tests/test_cem_evaluator.py;
                       tests/test_cem_harness_security.py; scripts/verify-phase1.sh; docs/cem-phase1-baseline.txt
                       (NO existing production source modified; NO CEM logic added)
TESTS PASSING:         661 total (37 Phase-1a CEM-env/hardening tests + 624 pre-existing); 0 failing
BENCHMARK STATUS:      Hardened: blind scenario manifest + evaluator-only answer key (split, both integrity-locked),
                       independent evaluator (FCCR/coverage/missed/FP/reproducibility), evidence trail, vulnerable/
                       patched mutation target, loopback-only. CEM assertion/FCCR gates still PENDING (no engine).
SECURITY AUDIT STATUS: harness-security tests green (loopback, no-redirect, tamper detect, no-CEM-production); O1 (code audit) is post-CEM
KNOWN DEVIATIONS:      RESOLVED UD-1..UD-4. (Impl notes) old ground_truth.py converted to an import TRIPWIRE
                       (rm blocked repo-wide); target routes renamed to neutral /svc/* for true blindness;
                       H2 fixture lives in test modules, not global conftest.
NEXT EXACT TASK:       A2 — isolated worktree/branch for CEM (after human G0 implementation approval)
LAST VERIFICATION CMD: bash scripts/verify-phase1.sh
LAST VERIFICATION RESULT: run-now PASS (prereqs, integrity_start, phase1a_tests 37, regression 661, integrity_end); CEM gates PENDING
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
