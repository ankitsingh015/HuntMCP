# PHASE1-PLAN.md — CEM Phase 1 Implementation Plan (review before coding)

Scope: **Phase 1 only** — the scientifically-trustworthy CEM vertical slice defined in [XYZ.md](XYZ.md) §5.
Treats XYZ.md as the spec. No implementation here; this is the plan to be reviewed first.

Non-goals (excluded, per XYZ.md §5): autonomous graph planning, autonomous condition discovery, attack-path
planning, new graph/playbook MCP servers, autonomous variant hunting, self-expansion, complex ML, `networkx`,
`cryptography`, XBOW-class breadth.

---

## Key architectural decisions (and their justification)

- **D1 — No new MCP server. Extend `case-mcp` + add it to `TIER2_MCP_SERVERS`.**
  *Demonstration that an existing component supports the requirement:* the interventional tools send real HTTP,
  so they need Tier-2 scope-gating. The scope hook ([scripts/hooks/scope_gate_hook.py](scripts/hooks/scope_gate_hook.py:295))
  gates **per server** and, for a server in the set, returns `0` (allow) when a call has **no host arg**
  (`if not candidates: return 0`). Therefore adding `case-mcp` to the set gates only the tools carrying a
  `url` arg (senders) while the existing local bookkeeping tools (`log_hypothesis`, etc.) pass through
  unchanged. A new server is unnecessary; case-mcp already provides the exact substrate (per-engagement SQLite,
  evidence store, findings/experiments tables).
- **D2 — One new shared module `mcp-servers/cem_engine.py`** (a plain module, not a server), mirroring how
  `idor-mcp/idor_sweep.py` backs `idor-mcp/server.py`. Holds all logic; unit-testable without MCP.
- **D3 — Reuse `idor_sweep._fetch` / `_build_headers` / `FetchResult`** as the HTTP primitive
  ([mcp-servers/idor-mcp/idor_sweep.py](mcp-servers/idor-mcp/idor_sweep.py:124)). They already handle
  401/403/404-as-response and stdlib-only requests.
- **D4 — stdlib `dataclasses`, not `pydantic`.** Phase 1 needs typed structs, not validation middleware; keep
  new deps at **zero**. (XYZ.md allows moderate deps; Phase 1 spends none.)
- **D5 — A confirmed finding must also supply a `success_signature` (the capability oracle).** You cannot test
  necessity without a machine-checkable definition of "the capability fired." This is a small, necessary
  addition to the Phase-1 inputs ("candidate conditions" alone are insufficient). Signature = a matcher over
  `FetchResult`: `{status_in:[...], body_contains/body_regex, or similarity_to_baseline >= t}`.
- **D6 — Verdicts require *unanimous* k-consistency in Phase 1** (not majority). Trustworthiness over
  statistical nuance; a statistical model is a later phase.

---

## 18-requirement → repository map

| # | Requirement | Reuse (existing) | Modify | New |
|---|---|---|---|---|
| 1 | Reuse existing files | `idor_sweep.py` (`_fetch`,`_build_headers`,`FetchResult`), `case_store.py`, `audit_log.py`, `budget_guard.py`, `scope_guard.py`, `engagement_paths.py`, `redact.py`, `session_context.py` | — | — |
| 2 | Files to modify | — | `case-mcp/server.py`, `case_store.py`, `scripts/hooks/scope_gate_hook.py`, `report-agent.md` | — |
| 3 | New files | — | — | `cem_engine.py`, `tests/test_cem_engine.py`, `tests/test_cem_case_store.py`, `tests/fixtures/cem_target/app.py`, `tests/test_cem_benchmark.py` |
| 4 | Schema changes | `case.db` (SQLite via `case_store`) | `case_store._init_schema` | tables: `cem_meta`, `cem_conditions`, `cem_trials`, `cem_verdicts` |
| 5 | Execution flow | case lifecycle (`create_finding`→`CONFIRMED`) | new CEM tools sequence | §B below |
| 6 | Intervention executor | `idor_sweep._fetch`/`_build_headers` | — | `cem_engine.run_intervention()` |
| 7 | Determinism gate | `_fetch` | — | `cem_engine.determinism_gate()` |
| 8 | Replication | `budget_guard.enforce` per request | — | k-loop in executor (default k=5, unanimity) |
| 9 | Confounder representation | headers via `_build_headers` | — | `Controls` dataclass + pinning helpers |
| 10 | Verdict model | `case_store` banding pattern | — | enum `necessary/apparently_not_necessary/inconclusive/interacting/probabilistic` |
| 11 | Multiple minimal sets | — | — | `cem_engine.minimal_condition_sets()` (ddmin + alternates, budget-bounded) |
| 12 | PoC minimization | — | — | `cem_engine.minimize_poc()` (ddmin, runs after causal evidence) |
| 13 | Triager-Proof Bundle | `case_export` pattern, `redact.redact_text` | — | `cem_engine.evidence_bundle()` (15-field JSON) |
| 14 | Audit/evidence | `audit_log.log_call`, `case_store.add_evidence` (content-addressed) | — | trials reference evidence `content_hash` |
| 15 | Scope/rate/budget | `scope_gate_hook`, `budget_guard.enforce`, request spacing | add `case-mcp` to `TIER2_MCP_SERVERS` | inline enforce in sender tools (like idor-mcp) |
| 16 | Test strategy | `tests/conftest.py`, `test_case_store.py`, `test_idor_sweep.py` patterns | — | §E below |
| 17 | Benchmark | `is_safe_test_host` (localhost allowed) | — | constructed `http.server` app, §F |
| 18 | Release gates | — | — | §H, enforced by `test_cem_benchmark.py` |

---

## A. Current architecture → Phase-1 architecture mapping

```
BEFORE (today)                          AFTER (Phase 1 adds, in italics)
──────────────                          ────────────────────────────────
case-mcp/server.py  ── case_store.py    case-mcp/server.py ─┬─ case_store.py (+4 CEM tables)
   (local, non-Tier2)   (case.db)          + 6 CEM @tools    └─ *cem_engine.py* ── idor_sweep._fetch
idor-mcp/server.py  ── idor_sweep.py    *(case-mcp now in TIER2_MCP_SERVERS;*
   (Tier-2 sender)      (_fetch, ...)     *senders carry `url`, gated; local tools ungated)*
scope_gate_hook.py (per-server gate)    scope_gate_hook.py (+ "case-mcp")
audit_log / budget_guard / redact  ───► reused unchanged by CEM senders (inline enforce, like idor-mcp)
report-agent.md ───────────────────────► + "Counterfactual Evidence Bundle" section
```

Trust-tier cleanliness: senders (`determinism_gate`, `run_counterfactual`) take a `url` arg ⇒ scope-checked;
assemblers (`define_conditions`, `minimal_condition_sets`, `minimize_poc`, `evidence_bundle`) take no host arg
⇒ pass through the hook's `if not candidates: return 0`. Budget + audit are enforced **inline** in the two
senders (case-mcp does not route through `tool_resolver`), exactly as `idor-mcp/server.py` does.

## B. Detailed execution sequence for one finding

Precondition: finding already **independently confirmed** through the normal flow — `create_finding(...)` →
`add_evidence(..., finding_id)` → `update_finding_status(id, "CONFIRMED")` (existing evidence gate).

1. **`define_conditions(finding_id, base_request, conditions, success_signature)`** *(local)*
   Persists `cem_meta` (base_request JSON, success_signature JSON) + `cem_conditions` rows. Each condition:
   `{name, category, baseline_value, perturbation}` where `perturbation` says how to set the condition to a
   *non-triggering* value (drop param / swap identity / change value).
2. **`determinism_gate(finding_id, k=5)`** *(sender, Tier-2)*
   Runs `base_request` k times (spaced), evaluates `success_signature` each. Stores k trials + evidence.
   - all-k HIT → `determinism_status = STABLE`, proceed.
   - mixed → `determinism_status = NONDETERMINISTIC`; auto-log a hypothesis (race/state/cache); **necessity
     testing is suppressed** (release gate #1/#4). Bundle still emitted, labeled nondeterministic.
3. **`run_counterfactual(finding_id, condition_id, k=5)`** *(sender, Tier-2)* — once per condition, one
   variable at a time. Pins the `Controls` set (§9); perturbs only this condition; runs baseline arm + perturbed
   arm k times each; evaluates oracle; classifies (§D verdict rules). Stores trials, evidence, one `cem_verdicts`
   row. Enforces `budget_guard.enforce("case-mcp")` and `audit_log.log_call(...)` per request; detects `429`/
   throttle → `inconclusive`.
4. **`minimal_condition_sets(finding_id)`** *(local, may trigger more sender subset-trials)*
   From per-condition verdicts, runs bounded ddmin over the triggering-condition set to find 1-minimal sets +
   alternates + interactions (§11). Emits the MSC family with a completeness bound.
5. **`minimize_poc(finding_id)`** *(local/sender)* — ddmin over request steps/conditions using the oracle as the
   interestingness test; re-validates the minimal reproducer against `determinism_gate` before accepting (§12).
6. **`evidence_bundle(finding_id)`** *(local)* — assembles the 15-field Triager-Proof Bundle (§D), passes text
   fields through `redact.redact_text`, returns JSON. `report-agent` renders it; never auto-submitted.

## C. File-by-file implementation plan

- **`mcp-servers/cem_engine.py`** *(new, ~stdlib only)* — dataclasses `Condition`, `Controls`, `Trial`,
  `Verdict`, `SuccessSignature`; `evaluate_signature(FetchResult, sig)`; `run_intervention(base_request, control_set, perturbation, k)`
  (loops `idor_sweep._fetch`, spacing, budget hook callback); `determinism_gate(...)`; `classify(baseline_hits, perturbed_hits, k)`;
  `minimal_condition_sets(...)` (ddmin + alternates); `minimize_poc(...)`; `assemble_bundle(...)`. No MCP imports
  → unit-testable directly.
- **`mcp-servers/case-mcp/server.py`** *(modify)* — add 6 `@app.tool()` wrappers delegating to `cem_engine` +
  `case_store`; senders call `_enforce_budget("case-mcp")` and `_log_call(...)` inline (import from
  `budget_guard`/`audit_log` exactly as `idor-mcp/server.py` does).
- **`mcp-servers/case_store.py`** *(modify)* — extend `_init_schema` with 4 tables (§D); add CRUD helpers
  (`cem_define`, `cem_record_trial`, `cem_record_verdict`, `cem_load_state`); reuse `add_evidence` for raw
  request/response bytes (content-addressed) and `log_experiment` for per-trial dedupe.
- **`scripts/hooks/scope_gate_hook.py`** *(modify)* — add `"case-mcp"` to `TIER2_MCP_SERVERS`. Add a
  `test_scope_gate_hook.py` case proving local case-mcp tools (no url arg) still return 0.
- **`.opencode/agents/report-agent.md`** *(modify)* — document the Counterfactual Evidence Bundle section.
- **`opencode.jsonc`** — no change (case-mcp already registered; no new env needed).
- **Tests** — see §E.

## D. Data model / schema (new tables in `case.db`)

```sql
CREATE TABLE cem_meta (               -- one row per finding under CEM
  finding_id INTEGER PRIMARY KEY,
  base_request TEXT NOT NULL,         -- JSON {method,url,headers,body}
  success_signature TEXT NOT NULL,    -- JSON matcher (the capability oracle)
  determinism_status TEXT DEFAULT 'UNTESTED',  -- UNTESTED|STABLE|NONDETERMINISTIC
  cem_status TEXT DEFAULT 'DEFINED',  -- DEFINED|GATED|TESTED|MINIMIZED|BUNDLED
  k INTEGER DEFAULT 5,
  FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE);

CREATE TABLE cem_conditions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL,
  name TEXT NOT NULL, category TEXT NOT NULL,     -- identity|request|sequence|environment
  baseline_value TEXT, perturbation TEXT NOT NULL, -- JSON: how to set non-triggering value
  FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE);

CREATE TABLE cem_trials (
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL,
  condition_id INTEGER,               -- NULL = baseline/determinism arm
  arm TEXT NOT NULL,                  -- baseline|perturbed
  k_index INTEGER NOT NULL, http_status INTEGER, oracle_hit INTEGER NOT NULL,
  request_evidence_hash TEXT, response_evidence_hash TEXT,  -- into existing evidence store
  controls TEXT,                      -- JSON of pinned confounders for this trial
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE);

CREATE TABLE cem_verdicts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL, condition_id INTEGER,
  verdict TEXT NOT NULL,              -- necessary|apparently_not_necessary|inconclusive|interacting|probabilistic
  k INTEGER NOT NULL, controls TEXT NOT NULL, detail TEXT DEFAULT '',
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE);
```

**Verdict rules** (unanimity, k trials/arm):
- baseline arm not all-HIT → `inconclusive` for that condition (baseline unstable this run).
- perturbed all-MISS  → `necessary`.
- perturbed all-HIT   → `apparently_not_necessary`.
- perturbed mixed     → `inconclusive`.
- any arm sees `429`/throttle or an uncontrolled confounder → `inconclusive`.
- finding flagged race/TOCTOU → `probabilistic` (report perturbed HIT-rate; never `necessary`).

**Triager-Proof Bundle (15 fields, from XYZ.md §2.8):** original baseline · baseline replication results ·
intervention matrix · replication counts · controlled/pinned conditions · observed confounders · inconclusive
experiments · identified necessary conditions · minimal condition sets · minimized reproduction/evidence ·
complete audit trail — plus verdict labels, controls, k, and completeness bound.

## Intervention executor design (§6), determinism gate (§7), replication (§8), confounders (§9)

- **Executor** `run_intervention(base_request, controls, perturbation|None, k)`: builds headers via
  `_build_headers`, applies `controls` (fresh identical cookie/bearer per trial, cache-buster query param,
  sequential ordering, `spacing_ms` sleep between trials to avoid rate-limit contamination), applies the single
  perturbation if given, calls `idor_sweep._fetch` k times, evaluates `success_signature`, returns per-trial
  `Trial`s. Budget enforced via an injected callback (`budget_guard.enforce`) so the module stays MCP-free and
  testable; the server wires the real callback.
- **Determinism gate**: `run_intervention` with `perturbation=None`; STABLE iff all-k HIT (unanimity).
- **`Controls` dataclass**: `session_headers`, `csrf_token` (optional; if a `csrf_provider` pre-request is
  supplied, mint fresh per trial identically — else mark uncontrolled), `cache_buster` (bool), `ordering`
  (sequential), `spacing_ms`, `concurrency` (=1 in Phase 1 except the race carve-out). Any confounder that
  cannot be pinned is recorded in the trial's `controls` JSON as `uncontrolled:<name>` and forces `inconclusive`.

## Multiple minimal sets (§11) & PoC minimization (§12)

- Present-condition set `S` = conditions whose baseline value is triggering. **ddmin** finds a 1-minimal subset
  `M1` (a subset is "interesting" iff, with all conditions *outside* it perturbed to non-triggering, the oracle
  is unanimously HIT over k). Alternates: for each `c ∈ M1`, force-exclude `c` and re-run ddmin → collect
  distinct minimal sets. **Interactions**: `c` singly `apparently_not_necessary` but present in every recovered
  minimal set, or a pair whose joint removal flips the oracle while neither single removal does → `interacting`.
  Bounded by `budget_guard`; report `sets_found=k, trials_used=n, bounded=True/False`.
- **PoC minimization** reuses the same ddmin with the oracle as interestingness, over request
  fields/steps; output re-validated through `determinism_gate` (guards a DD local optimum dropping a real step).
  Runs **after** verdicts exist.

## E. Test cases (pytest, wired into CI like the rest of `tests/`)

- `test_cem_engine.py` (no network — a fake `_fetch`): signature evaluation; determinism gate STABLE vs
  NONDETERMINISTIC; each verdict rule incl. throttle→inconclusive and mixed→inconclusive; ddmin recovers a
  known minimal set; alternates + interaction detection; poc minimization + re-validation; bundle has all 15
  fields; redaction applied.
- `test_cem_case_store.py`: 4 tables created; CRUD; evidence content-addressing reused; cascade on finding
  delete; per-engagement isolation via `engagement_paths` (monkeypatched, like `test_case_store.py`).
- `test_scope_gate_hook.py` (extend): case-mcp sender with `url` out-of-scope → blocked (rc 2); case-mcp local
  tool with no url → allowed (rc 0).
- `test_cem_benchmark.py`: drives the constructed target (§F) end-to-end; asserts §H gates.

## F. Constructed ground-truth benchmark (§17)

`tests/fixtures/cem_target/app.py` — a stdlib `http.server` app on `127.0.0.1` (allowed by
`scope_guard.is_safe_test_host`), started as a pytest fixture. Planted, labelled behaviors:

| Endpoint | Ground truth | CEM must output |
|---|---|---|
| `/doc/{id}` (needs auth cookie) | auth **necessary** | `necessary` for the cookie condition |
| `/doc/{id}?trace=1` | `trace` param irrelevant | `apparently_not_necessary`; dropped from minimal PoC |
| `/report` reachable via header **or** cookie | two independent paths | ≥2 minimal condition sets |
| `/merge` needs role=admin **and** feature-flag on | interaction | `interacting` (neither alone) |
| `/flaky` returns 200/403 at random | nondeterminism red herring | determinism gate → NONDETERMINISTIC; **never `necessary`** |
| `/cached` 200 first then 403 (cache) | confounder red herring | `inconclusive` (not `necessary`) |
| `/race` succeeds only under parallel hits | genuine race | `probabilistic`, not deterministic necessity |

## G. Failure modes & mitigations

- **Oracle mis-specification** (garbage signature) → garbage verdicts. Mitigation: bundle echoes the signature;
  determinism gate on baseline catches a signature that never HITs.
- **Rate-limit contamination** (perturbed MISS caused by throttle, not the perturbation) → false `necessary`.
  Mitigation: request spacing; detect `429`/throttle → `inconclusive`; interleave a baseline re-check.
- **Uncontrollable CSRF/session** → cannot pin. Mitigation: record `uncontrolled` → `inconclusive` (correct,
  not a false claim).
- **ddmin local optimum** drops a needed step. Mitigation: re-validate minimal set/PoC via determinism gate;
  optional DDMIN* re-iterate.
- **Budget exhaustion mid-run** → partial data. Mitigation: bundle marked `incomplete=True` with what ran;
  never emit a `necessary` from an incomplete arm.
- **Evidence bloat** from k replications. Mitigation: content-addressed evidence dedupes identical bytes.

## H. Exact Phase-1 acceptance criteria (first release gate)

All must hold, enforced by `test_cem_benchmark.py`:
1. **false-causal-conclusion-rate == 0** on the benchmark — no red herring (`/flaky`, `/cached`, `/race`)
   receives a `necessary` verdict.
2. `/doc` auth cookie → `necessary`; `/doc?trace` → `apparently_not_necessary` and absent from the minimal PoC.
3. `/report` → ≥2 minimal condition sets recovered (within budget); `/merge` → `interacting`.
4. `/flaky` → determinism gate NONDETERMINISTIC and necessity suppressed; `/race` → `probabilistic`.
5. Every emitted verdict carries {verdict, k, controls, tested-scope}; no bare "necessary".
6. Bundle contains all 15 §2.8 fields; every trial has an `audit_log` line and content-addressed evidence.
7. Non-idempotent perturbations are refused unless explicitly human-approved (idempotent/GET-shaped default).
8. New code passes `ruff` + `py_compile` + `pytest`; CI green.

Only when 1–8 pass does Phase 2 (XBOW-class breadth) begin.
