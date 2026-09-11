# CEM (Counterfactual Evidence Minimization) — Phase 1

**Status:** Phase‑1 implementation (Groups A–M). This document is the task **N1** deliverable:
usage, tool signatures, bundle format, safety notes, and the one‑command verifier invocation.

CEM is an **opt‑in, post‑confirmation** step. It never runs during normal hunting. Given a
finding that has already been *independently confirmed* through the standard flow, CEM
answers: *which request conditions are actually causally necessary for the vulnerability to
fire?* It does this by replaying the confirmed request many times, dropping one condition at
a time, and comparing an explicit success oracle across the baseline and perturbed arms.

The engine is split in two:

| Layer | File | Role |
|---|---|---|
| Pure algorithm | `mcp-servers/cem_engine.py` | signatures, classification, ddmin, bundle assembly — no I/O |
| MCP tools + persistence | `mcp-servers/case-mcp/server.py` (CEM section) + `mcp-servers/case_store.py` (`cem_*` tables/CRUD) | 6 tools, DB rows, scope/budget/audit wiring |

---

## 1. Prerequisites

Before any CEM tool will do real work:

1. **A confirmed finding.** `finding.status` must be `CONFIRMED` or `IMPACT_PROVEN`. The
   case‑store evidence gate only lets a finding reach those states with ≥ 1 linked evidence
   row, so the reproduction is already established independently of CEM.
   Typical path with the existing `case-mcp` tools:
   ```
   create_finding(vuln_class, endpoint, parameter)          -> finding_id
   add_evidence(type="http", content=..., finding_id=...)    # >= 1 row
   update_finding_status(finding_id, "CONFIRMED")
   ```
2. **An explicit success oracle.** You supply the `success_signature` (UD‑3). CEM never
   derives an oracle from a baseline response. At least one matcher must be set and it must
   not be vacuous (empty `body_contains`, `threshold` 0.0, etc. are rejected at definition
   time).
3. **Scope.** The two *sender* tools issue real HTTP. A loopback / RFC1918 / `example.*` /
   dev‑infra host needs no `engagement.yaml`; any other host requires an active engagement
   whose `in_scope` covers `base_request["url"]`. Fail‑closed.
4. **Environment (optional overrides).** All default to the per‑engagement paths:

   | Variable | Meaning | Default |
   |---|---|---|
   | `HUNTMCP_CASE_DB_PATH` | SQLite case DB (holds `cem_*` tables) | `<engagement>/case.db` |
   | `HUNTMCP_BUDGET_PATH` | Tier‑2 budget counter file | `<engagement>/budget.json` |
   | `HUNTMCP_AUDIT_LOG` | JSONL audit trail | `<engagement>/audit.jsonl` |
   | `HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING` | per‑finding CEM request ceiling | `200` |

---

## 2. The six tools

All tools take/return JSON strings (FastMCP). `finding_id` is an `int` throughout.
Two tools — `determinism_gate` and `run_counterfactual` — are **Tier‑2 senders**: they issue
real HTTP, enforce budget before every request, write one audit line per call, and are
scope‑gated (`scripts/hooks/scope_gate_hook.py` → `case-mcp: {determinism_gate,
run_counterfactual}`). The other four are local bookkeeping tools that send nothing.

### 2.1 `define_conditions` — local, one‑shot

```
define_conditions(
    finding_id: int,
    base_request: str,          # JSON object: {"method","url","headers","body"}
    success_signature: str,     # JSON object, see 2.1.1
    conditions: str,            # JSON array, see 2.1.2
    k: int = 5,                 # replication count per arm
    nonidempotent_approval: str = ""   # JSON object or "" ; see Safety §4.2
) -> str   # {"finding_id", "condition_ids": [int,...]}  |  {"error": ...}
```

One‑shot per finding (a second call for the same `finding_id` errors). Guards applied here:
finding must be CONFIRMED/IMPACT_PROVEN; `success_signature` must be a valid non‑vacuous
oracle; `nonidempotent_approval`, if given, must be shape‑valid.

**2.1.1 `success_signature` shape** (`cem_engine.SuccessSignature`; AND across whichever
fields are set; ≥ 1 required):

| Key | Type | Matches when |
|---|---|---|
| `status_in` | `[int, ...]` (non‑empty) | response status is in the list |
| `body_contains` | `str` (non‑empty) | substring present in body |
| `body_regex` | `str` (compilable) | regex search hits |
| `similarity_to_baseline` | `{"body": str, "threshold": 0<t<=1}` | `difflib` ratio ≥ threshold |

A `FetchResult` with a transport error (connection refused, timeout) satisfies **no**
signature.

**2.1.2 `conditions` shape** — array of:

```json
{ "name": "session_cookie",
  "category": "header",
  "baseline_value": "<optional string>",
  "perturbation": { "drop": true } }
```

Phase‑1 supports exactly one perturbation shape: `{"drop": true}` — remove the header or
query parameter this condition names. `name` is matched case‑insensitively against request
headers, then against query params; a small auth alias set maps
`session_cookie`/`auth_cookie`/`bearer_token`/… onto `Cookie`/`Authorization`. A path‑segment
condition has **no** `{"drop": true}` representation in Phase‑1 — `run_counterfactual`
returns a clean error for it (never a silent no‑op) and persists no trial/verdict.

### 2.2 `determinism_gate` — Tier‑2 sender

```
determinism_gate(finding_id: int, url: str, k: int = 0) -> str
# {"finding_id", "determinism_status", "hits":[bool,...], "k", "throttled"}
# on gating: adds {"error", "incomplete": true}, and "refused" for a method block;
#            "determinism_status" is then "INCOMPLETE"
```

Re‑runs the stored `base_request` `k` times **unperturbed**. `determinism_status`:

| Value | Meaning |
|---|---|
| `STABLE` | all `k` trials HIT the oracle, no throttle |
| `NONDETERMINISTIC` | any MISS, or a 429 seen |
| `INCOMPLETE` | run was gated/truncated (budget/scope/method) — no real observation |

`k` defaults to the finding's stored `k`. The `url` argument is an **audit label only** — the
request actually sent targets `meta["base_request"]["url"]`, and that is what the scope gate
checks. `throttled: true` means a 429 was observed and the result is not trustworthy.

### 2.3 `run_counterfactual` — Tier‑2 sender

```
run_counterfactual(finding_id: int, url: str, condition_id: int, k: int = 0) -> str
# {"finding_id","condition_id","condition","verdict","k",
#  "baseline_hits":[bool,...],"perturbed_hits":[bool,...]}
# on gating: {"finding_id","condition_id","error","incomplete":true[,"refused":...]}
```

Tests **one** condition, one variable at a time: pins a default `Controls` set, runs the
baseline arm (`k` trials) then the perturbed arm with only this condition dropped (`k`
trials), classifies, and records every trial plus one `cem_verdicts` row.

**Verdict vocabulary** (`cem_engine`):

| Verdict | Meaning |
|---|---|
| `necessary` | perturbed arm all‑MISS while baseline all‑HIT — dropping it kills the capability |
| `apparently_not_necessary` | capability still fires with the condition dropped |
| `inconclusive` | forced by: an uncontrolled confounder, a 429, or a partial/aborted arm |
| `interacting` | (algorithm‑level, surfaced via `minimal_condition_sets`) neither single removal alone flips the oracle |
| `probabilistic` | race‑only; **not reachable** from the Phase‑1 sender (`concurrency == 1` is hard‑locked) |

`inconclusive` is an **honest non‑answer**, never a false causal claim.

### 2.4 `minimal_condition_sets` — local

```
minimal_condition_sets(finding_id: int) -> str
# {"finding_id","minimal_sets":[[name,...],...],"interacting":[name,...],
#  "sets_found","trials_used","bounded","predicate"}  |  {"error": ...}
```

From the per‑condition verdicts already recorded by `run_counterfactual`, runs bounded ddmin
over the conditions that classified `necessary` to recover 1‑minimal condition set(s),
alternates, and interactions, with a completeness bound. Phase‑1 uses a **stored‑verdict
predicate** (a condition outside a set is droppable iff its recorded verdict is
`apparently_not_necessary`); live subset re‑trials are deferred (Phase‑2). Errors if no
condition has a `necessary` verdict yet.

### 2.5 `minimize_poc` — local

```
minimize_poc(finding_id: int) -> str
# {"finding_id","poc":[name,...],"accepted":bool,"determinism_status","revalidation"}
#  |  {"error": ...}
```

ddmin over the `necessary` conditions using the same stored‑verdict predicate, then
re‑validates the minimal set. In Phase‑1 the re‑validation is **always derived from the
recorded baseline trials** — a fresh `determinism_gate` re‑run for the minimized set was the
original G1 plan but is **unbuilt** (see §8 limitations). Drops any condition that was not
actually necessary from the reproduction set. The returned `revalidation` string reflects
this (it still reads "deferred to G1" — a stale label from the source docstring).

### 2.6 `evidence_bundle` — local

```
evidence_bundle(finding_id: int) -> str   # the Triager-Proof Bundle, see §3
```

Assembles the redacted bundle from whatever CEM state has been persisted so far. Safe to
call at any point; fields not yet produced are honestly labelled (`"untested"`, empty lists).

---

## 3. Evidence bundle format

`evidence_bundle` returns a single JSON object — the "Triager‑Proof Bundle": the 15 fields
from XYZ.md §2.8 + `PHASE1-EXECUTION-PLAN.md`, plus `finding_id` as a 16th identity key.
Assembled by `cem_engine.assemble_bundle`; every string leaf is passed through
`redact.redact_text` exactly once at the end.

| Key | Content |
|---|---|
| `finding_id` | int — bundle identity (not one of the 15) |
| `original_baseline` | the stored `base_request` dict (redacted) |
| `baseline_replication_results` | `{"status","hits":[bool,...],"k"}` from the recorded baseline trials |
| `intervention_matrix` | `[{"condition","category","verdict"}, ...]` — one row per defined condition (`verdict` is `"untested"` until `run_counterfactual` runs it) |
| `replication_counts` | `k` (literal duplicate of `k` under the §2.8 name) |
| `controlled_pinned_conditions` | `Controls.record()` snapshot — header **names** only, never values |
| `observed_confounders` | **always `[]` in Phase‑1** — structured confounder capture is unbuilt (see §8) |
| `inconclusive_experiments` | `{condition_name: reason}` for every `inconclusive` verdict |
| `identified_necessary_conditions` | sorted condition names whose verdict is `necessary` (derived from `verdict_labels`, so the two cannot disagree) |
| `minimal_condition_sets` | `{"minimal_sets":[[...]],"interacting":[...],"interacting_pairs":[[...]]}` |
| `minimized_reproduction_evidence` | `{"poc":[...],"accepted":bool,"determinism":{"status","hits","k"}}` |
| `complete_audit_trail` | **always `[]` in Phase‑1** — content‑addressed request/response evidence hashing is unbuilt (see §8); the per‑call audit record lives in `audit.jsonl`, not here |
| `verdict_labels` | `{condition_name: verdict}` for every tested condition |
| `controls` | same `Controls.record()` snapshot under the §2.8 name |
| `k` | replication count |
| `completeness_bound` | `{"sets_found","trials_used","bounded"}` — how exhaustive the minimal‑set search was |
| `incomplete` | `true` if any sender stopped this finding's run early (budget/scope/method); the bundle is then a partial artifact |

The bundle is **rendered by report‑agent and always human‑reviewed — never auto‑submitted.**

---

## 4. Safety notes

CEM adds real request‑issuing capability to `case-mcp`. These controls are part of product
behavior — do not weaken them.

### 4.1 Scope (F1 + F3, `scope_guard` — one source of truth with the hook)
- The `url` argument to the senders is an **audit/early‑filter label only**. The authoritative
  check is on `base_request["url"]` (the URL actually fetched for the baseline arm), run
  before any HTTP.
- Every trial of every arm additionally re‑verifies the **final resolved URL**
  (`perturbation(controls.pin(base, i))["url"]`) immediately before its fetch, so even a
  future perturbation type that rewrites scheme/host/port is caught against its real
  destination.
- Any failure to evaluate scope → refuse. An out‑of‑scope result → graceful
  `{"error","incomplete":true}`, nothing sent, nothing persisted, one audit line
  (`block="scope"`).

### 4.2 Read‑only by default (UD‑4)
- CEM sends `GET`/`HEAD`/`OPTIONS` only. Any other method — or a method‑override header — on
  the stored base request, or produced by a perturbation, is refused
  (`refused: "nonidempotent_perturbation"`, `block="method"`).
- To deliberately authorize a state‑changing CEM experiment for **one finding**, pass
  `nonidempotent_approval` to `define_conditions`:
  ```json
  {"methods": ["POST"], "reason": "confirmed finding is a POST-only state change; testing which headers are causally required", "authorized_by": "analyst@example.com"}
  ```
  `methods` must be a non‑empty subset of `POST`/`PUT`/`PATCH`/`DELETE`; `reason` and
  `authorized_by` must both be non‑empty strings (deliberate, auditable).
  It is stored on the finding, re‑validated at every policy gate, and **cannot** be supplied
  as a sender argument.

### 4.3 Budget (F2 + E2)
- `budget_guard.enforce_cem_finding(finding_id)` — per‑finding ceiling
  (`HUNTMCP_CEM_MAX_REQUESTS_PER_FINDING`, default **200**), checked **first**.
- `budget_guard.enforce("case-mcp")` — engagement‑wide Tier‑2 cap.
- Either raising `BudgetExceeded` stops the arm before the next fetch → graceful
  `incomplete` result, no partial trial/verdict persisted, `cem_meta.incomplete = 1`.

### 4.4 Audit & redaction
- Exactly one `audit_log.log_call("case-mcp", ...)` per sender invocation, with a `block`
  reason on refusal (`budget` / `scope` / `method` / `error` / `None`).
- Secret headers (`authorization`, `cookie`, `set-cookie`, `x-api-key`) are redacted in the
  audit log and in the bundle. `Controls.record()` stores header **names only**.

### 4.5 Causal honesty
- An uncontrolled confounder, a 429, or a partial arm forces `inconclusive` — CEM never
  emits `necessary` off an untrustworthy comparison.
- A non‑`STABLE` baseline suppresses necessity downstream.
- A gated/truncated determinism run reports `INCOMPLETE`, not a spurious `NONDETERMINISTIC`
  computed from zero trials.
- Known Phase‑1 capability boundaries (OR‑path recovery, race reproduction, path‑segment
  substitution) are documented in [`cem-phase1-limitations.md`](cem-phase1-limitations.md)
  as capability *absence*, not engine defects — none produces a false causal conclusion.

---

## 5. End‑to‑end usage (worked example)

CEM is an **MCP tool surface**. `case-mcp` is registered in `opencode.jsonc` and enabled for
`exploit-agent`, `huntbrain`, and `report-agent` (`"case-mcp*": true`); an agent invokes the
six tools by name. The example below shows the tool name and its JSON arguments/response at
each step — the same shapes whether the caller is an agent or a test.

Assume finding `42` is already `CONFIRMED` (IDOR at `GET /svc/alpha/99?trace=1`, requires a
session cookie). Loopback target, so no `engagement.yaml` is needed. `k = 5` throughout.

```jsonc
// 1. define_conditions  (local, one-shot)
//    args:
{
  "finding_id": 42,
  "base_request": "{\"method\":\"GET\",\"url\":\"http://127.0.0.1:8000/svc/alpha/99?trace=1\",\"headers\":{\"Cookie\":\"session=abc123\"},\"body\":null}",
  "success_signature": "{\"status_in\":[200],\"body_contains\":\"alpha-secret\"}",
  "conditions": "[{\"name\":\"session_cookie\",\"category\":\"header\",\"baseline_value\":\"session=abc123\",\"perturbation\":{\"drop\":true}},{\"name\":\"trace\",\"category\":\"query\",\"baseline_value\":\"1\",\"perturbation\":{\"drop\":true}}]",
  "k": 5
}
//    response:  {"finding_id": 42, "condition_ids": [1, 2]}

// 2. determinism_gate  (Tier-2 sender)  args: {"finding_id": 42, "url": "http://127.0.0.1:8000", "k": 5}
//    response: {"finding_id":42,"determinism_status":"STABLE","hits":[true,true,true,true,true],"k":5,"throttled":false}
//    -> if not STABLE, stop: the finding is not cleanly reproducible.

// 3. run_counterfactual  (Tier-2 sender) — once per condition_id
//    args: {"finding_id": 42, "url": "http://127.0.0.1:8000", "condition_id": 1, "k": 5}
//    response: {"finding_id":42,"condition_id":1,"condition":"session_cookie","verdict":"necessary",
//               "k":5,"baseline_hits":[true,...],"perturbed_hits":[false,false,false,false,false]}
//    args: {"finding_id": 42, "url": "http://127.0.0.1:8000", "condition_id": 2, "k": 5}
//    response: {..., "condition":"trace", "verdict":"apparently_not_necessary", ...}

// 4. minimal_condition_sets  (local)  args: {"finding_id": 42}
//    response: {"finding_id":42,"minimal_sets":[["session_cookie"]],"interacting":[],"sets_found":1,...}

// 5. minimize_poc  (local)  args: {"finding_id": 42}
//    response: {"finding_id":42,"poc":["session_cookie"],"accepted":true,"determinism_status":"STABLE",...}

// 6. evidence_bundle  (local)  args: {"finding_id": 42}
//    response: the 16-key Triager-Proof Bundle (§3) — handed to report-agent, human-reviewed, never auto-submitted.
```

Request cost of the above: `k` (gate) + `2·k` per condition = `5 + 10 + 10 = 25` real HTTP
requests, all counted against both budgets, each on its own audit line.

### Driving the tools in a test

The dash‑named package (`mcp-servers/case-mcp/`) is loaded by path, exactly as
`tests/test_cem_benchmark.py` does — there is no importable `server` module:

```python
import importlib.util, json, os
_spec = importlib.util.spec_from_file_location(
    "case_mcp_server", os.path.join(ROOT, "mcp-servers", "case-mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(srv)

# each tool takes/returns JSON strings:
out = json.loads(srv.define_conditions(42, json.dumps(base_request),
                                       json.dumps(success_signature),
                                       json.dumps(conditions), k=5))
```

`tests/test_cem_benchmark.py::test_flow` is the canonical worked example (case_01 through all
six tools against the real loopback benchmark app).

---

## 6. One‑command verification (§14)

```bash
bash scripts/verify-phase1.sh
```

Runs prerequisite validation → isolated localhost target → unit → integration → security →
causal benchmark → FCCR calc → regression → performance → cleanup, and writes
`phase1-report.json` at the repo root plus a human summary on stdout. Exit non‑zero if any
gate G1–G9 fails. The benchmark target binds `127.0.0.1` only and is torn down by pytest
fixtures.

Focused CEM test entry points:

```bash
.venv/bin/python -m pytest tests/test_cem_benchmark.py -q      # J1 + K1 + K2 end-to-end
.venv/bin/python -m pytest tests/test_cem_engine.py -q         # C-group pure algorithm
.venv/bin/python -m pytest tests/test_cem_performance.py -q    # M1 A/B/C perf gate
```

---

## 7. Persistence

All CEM state lives in the per‑engagement `case.db` (four additive tables, all
`ON DELETE CASCADE` from `findings`):

| Table | Rows |
|---|---|
| `cem_meta` | one per finding: `base_request`, `success_signature`, `k`, `determinism_status`, `cem_status`, `incomplete`, `nonidempotent_approval` |
| `cem_conditions` | one per candidate condition: `name`, `category`, `baseline_value`, `perturbation` |
| `cem_trials` | one per replay: `arm` (`baseline`/`perturbed`), `k_index`, `oracle_hit`, `http_status`, `controls`, `condition_id` (NULL on baseline). The `request_evidence_hash` / `response_evidence_hash` columns exist but are **never written in Phase‑1** (see §8). |
| `cem_verdicts` | one per `run_counterfactual`: `verdict`, `k`, `controls`, `condition_id`, `detail` |

`case_store.cem_load_state(finding_id)` returns
`{"meta", "conditions", "trials", "verdicts"}` with JSON fields decoded — the read model the
local tools build on.

---

## 8. Phase‑1 limitations that affect what you can expect from CEM

Fully enumerated in [`cem-phase1-limitations.md`](cem-phase1-limitations.md); the ones that
change the shape of CEM output:

- **No content‑addressed evidence.** `cem_trials.request_evidence_hash` /
  `response_evidence_hash` are never written and `evidence_bundle`'s `complete_audit_trail`
  is always `[]`. Trials persist `arm` / `k_index` / `http_status` / `oracle_hit`; the exact
  request/response bytes cannot be rebuilt from the bundle. (Was the original G1 plan;
  classified there as a capability limitation, not a correctness/security defect.)
- **No structured confounder capture.** `observed_confounders` is always `[]`. The
  confounder *gate* still works — an uncontrolled confounder forces `inconclusive` — it is
  only the itemised list in the bundle that is unpopulated.
- **`minimize_poc` re‑validation is trial‑derived**, not a fresh `determinism_gate` re‑run of
  the minimized set (its `revalidation` string still says "deferred to G1").
- **`minimal_condition_sets` uses a stored‑verdict predicate**, not live subset re‑trials —
  so OR‑path findings under‑recover their two 1‑element sets (Phase‑2).
- **One variable at a time, `concurrency == 1`.** Race conditions classify `inconclusive`
  (never `probabilistic`); path‑segment substitution conditions have no `{"drop": true}`
  form and return a clean per‑condition error.
- Several source docstrings in `case-mcp/server.py` still say behaviour is "deferred to G1";
  G1 closed without building it — treat this doc + the limitations doc as authoritative.

## 9. Related docs

- [`cem-phase1-limitations.md`](cem-phase1-limitations.md) — honest Phase‑1 capability boundaries and the §9 real‑world FCCR caveat.
- [`cem-phase1-k1-decisions.md`](cem-phase1-k1-decisions.md) — the approved benchmark ruling behind the K1 closure.
- [`cem-phase1-baseline.txt`](cem-phase1-baseline.txt) — the A3 regression baseline the M1 performance thresholds are anchored to.
- `PHASE1-EXECUTION-PLAN.md` §§7–15 — the authoritative spec, test matrix, and pass/fail gates.
