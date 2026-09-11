# HUNTMCP-NEXT-GEN-PROPOSAL-v2.md — Revised Next-Generation Proposal

> Status: **research / architecture only.** No implementation, no production-code changes, no benchmark/
> ground-truth changes, no commits, no phase started.
>
> This supersedes [HUNTMCP-NEXT-GEN-PROPOSAL.md](HUNTMCP-NEXT-GEN-PROPOSAL.md) (v1, unchanged) by folding in
> the corrections from [HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT.md](HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT.md) (controlling).
> The fixed thesis is unchanged: HuntMCP is a **proof / causal-validation engine (CEM)**; discovery breadth is
> table stakes we match, CEM is the axis we win on. Phase-1 CEM is the current focus and is **not touched** by
> anything here.
>
> Evidence tags used throughout: **OBSERVED** (verified in repo), **RESEARCH-SUPPORTED** (external literature),
> **INFERRED** (reasoned), **SPECULATIVE** (plausible, unproven), **UNVERIFIED** (claimed benefit not yet
> measured). No claim of "unseen anywhere" is made without strong evidence.

---

## 0. Controlling corrections carried from the audit

v2 resolves every material audit finding explicitly:

1. **Telemetry is two surfaces, not one.** `audit_log.py` runs inside MCP tool subprocesses that never see the
   LLM conversation **(OBSERVED)**. It can carry tool/HTTP/wall-clock/yield telemetry; **LLM token/cost is a
   separate OpenCode session/provider integration** and is treated as a **SPIKE**, not solved (§4).
2. **ARCH-STATE context savings are UNVERIFIED.** Subagents already isolate context; HuntBrain receives
   summaries, not raw dumps **(OBSERVED/INFERRED)**. ARCH-STATE is reframed around reliability, provenance,
   resumability, concurrency correctness — not tokens (§5).
3. **case.db concurrency is an explicit prerequisite.** WAL + foreign_keys are set; **`busy_timeout` is not**,
   and `file_lock` does not cover case.db **(OBSERVED)**. Any concurrent-writer work is gated behind a
   concurrency fix (§6).
4. **job_runtime does not persist raw output.** It reads temp files and **unlinks** them, returning full
   stdout/stderr through polling **(OBSERVED)**. The v1 "reuse existing disk persistence" claim is removed;
   durable artifact storage is proposed only if justified (§7).
5. **Structured memory already exists.** `memory.db` is global, structured, and tech-searchable
   (`search_by_tech`) **(OBSERVED)**. The knowledge gap is cross-reference/feedback/provenance, not absence of
   structure; a knowledge *graph* is optional/experimental (§8).
6. **DISC-GRAPH starts minimal.** Best-first over a SQLite adjacency table, benchmark-gated against the
   15-template chainer before any MCTS/A*/PDDL/networkx (§9).
7. **VAL-AUTHZ stays a top capability bet, scoped minimal** (§10).
8. **DISC-VARIANT stays high-value**, with current-vs-new separated (§11).
9. **EFF-SCHED is telemetry-gated for its cost claims**; a v0 heuristic is possible now (§12).
10. **EFF-ALLOC is ALREADY COVERED** by [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md);
    v2 only defines the interface, does not duplicate it (§13).
11. **P0-BENCH is foundational**; no architecture change may be declared successful on token reduction alone
    (§3, §14).
12. **Two parallel tracks** (Capability + Measurement/Efficiency) with explicit cross-dependencies (§15).

---

## 1. Executive Summary

HuntMCP is already a mature system with a strong safety substrate, an evidence-gated structured case store, and
a Phase-1 CEM engine in progress. The genuine next-generation leverage is **not** more prompt/schema
optimization (that lever is largely pulled: per-agent MCP scoping shipped, ~36–38% context cut, ~99.6%
continued-turn cache-read — **OBSERVED**). It is:

- **Measurement that makes capability and efficiency provable** (a standing benchmark range + feasible
  tool-telemetry + an honest spike for LLM-cost), because the project's own rules require *measurable,
  non-regressing* capability.
- **One concrete capability bet with an existing measurable baseline** — stateful authorization testing
  (VAL-AUTHZ) — targeting the class the literature says humans still win (business logic / authorization /
  audit-grade attestation, **RESEARCH-SUPPORTED**).
- **A differentiated moat-widener that rides CEM** — counterfactual variant discovery (DISC-VARIANT).
- **Waste reduction where telemetry proves it** — better experiment scheduling (EFF-SCHED), given that the real
  token lever under heavy cache-read is fewer wasted round-trips, not prompt restructuring (**INFERRED**).
- **Reliability substrate** — the case store as a durable, provenance-preserving inter-agent state layer
  (ARCH-STATE), sold on correctness/resumability, **not** tokens, and gated on a concurrency fix.

Everything else (attack-state graph planning, unified knowledge, adaptive allocation) is **experimental or
already-owned**, and is deferred until the benchmark can justify it.

**Hard constraint (unchanged):** any change that regresses high/critical discovery, coverage, validation depth,
exploitability reasoning, attack-chain discovery, evidence quality, or false-positive resistance is a **failed**
change regardless of token/cost savings.

---

## 2. Verified Baseline (what exists — corrected)

| Area | Reality (OBSERVED unless noted) |
|---|---|
| Orchestration | HuntBrain (L1, no bash) → recon/scan/exploit/chain-planner/report (L2 subagents) + dynamic specialists; **subagents isolate context** — HuntBrain gets returned summaries, not raw dumps |
| MCP scoping | Global `tools:false` + per-agent allowlists; **shipped**; recon/scan agents do **not** have case-mcp |
| Telemetry | `audit_log` per Tier-2 call: tool, redacted args, returncode, `duration_ms`, block. **No tokens/cost.** `budget_guard`: call counts (500-call breaker, 70/85/95 bands) |
| Case store | `case_store.py`: hypotheses→evidence→findings→experiments→root_causes; content-addressed evidence; evidence-gated confirm; confidence scoring; **WAL + foreign_keys, no busy_timeout**; `experiments` has a `cost` column + `finding_id` link |
| Concurrency | `file_lock.py` (flock) covers budget/work/findings JSON; **does not cover case.db** |
| Job runtime | `start_job`/`poll_job` background subprocess; returns full stdout/stderr on done-poll; **unlinks temp files** (no durable raw storage); thread variant for composite ops |
| Chaining | `chainer-mcp` = **15 static templates** matched by `required_findings`; not a search |
| CEM | `cem_engine.py` ~1115 lines; determinism gate, classify, minimal/alternate/AND sets, poc minimization, bundle; conditions human-supplied in Phase 1 |
| IDOR/authz | `idor-mcp sweep_idor`: single-request two-account replay with pair classification |
| Memory/learning | `memory.db` (**global, structured, tech-searchable**), writeup RAG (ChromaDB), lessons (freeform markdown); **not cross-referenced or fed into prioritization** |
| Model routing | `model_gateway.py` static per-role env selection; adaptive routing owned by INTELLIGENCE-ALLOCATION-MEMO |
| Safety | scope/budget/dedupe/work-registry/redact/content_scanner/stuck_detector + `rm` hard-block — strong, keep intact |

---

## 3. Token / Cost Philosophy (governs every candidate)

Priority hierarchy — **lower context is never the top objective**:

1. Preserve/increase security capability (hard floor).
2. Improve validation quality.
3. Improve useful security work per unit resource.
4. Reduce waste (redundant experiments, repeated validation, dead round-trips).
5. Reduce context/tokens/cost **only where 1–3 are not harmed.**

**Research metrics (to be measured, not assumed — all UNVERIFIED until P0-BENCH + telemetry exist):**
validated findings / model calls · validated findings / 1K tokens · validated findings / tool calls · useful
evidence / unit context · cost / validated vulnerability · wall-clock / validated vulnerability, reported
**per vuln-class** (to catch easy-class bias) and always subject to: high/critical recall ≥ baseline − ε,
FP ≤ baseline, per-class coverage ≥ baseline.

**Cache-read consequence (INFERRED):** with ~99.6% continued-turn cache-read, marginal token cost is dominated
by *new* per-turn output and tool results, not the cached prompt. So the highest-value token lever is **fewer
wasted round-trips (EFF-SCHED), not restructuring the cached prompt (ARCH-STATE).** This inverts v1's emphasis.

---

## 4. Telemetry Architecture (corrected — two surfaces)

**Design goal:** connect, per experiment, `{LLM usage} + {tool execution} + {finding yield} + {validation
result} + {latency}` — joined by `finding_id`/`experiment_id`.

### 4a. Tool-layer telemetry — **P0-TEL-TOOL** (feasible now, KEEP)
- **OBSERVED substrate:** `audit_log` already has tool/args/returncode/`duration_ms`/block; `case_store`
  already has `experiments.cost`, `experiments.finding_id`, `experiments.hypothesis_id`.
- **Smallest extension:** add HTTP-request count (where a tool exposes it) to the audit line; populate
  `experiments.cost` (tool calls / HTTP / ms) and ensure every experiment links to its finding. **No new
  subsystem.**
- **Yields (feasible):** tool-calls-per-finding, HTTP-per-finding, wall-clock-per-finding.

### 4b. LLM usage telemetry — **P0-TEL-LLM** (SPIKE REQUIRED, not solved)
- **OBSERVED constraint:** MCP subprocesses cannot see LLM token usage; it lives in OpenCode's session/provider
  layer.
- **Spike questions:** Does OpenCode expose per-turn/per-agent token+cost (session logs, provider usage, a
  hook)? Can it be joined to a `finding_id` (e.g. via engagement + timestamp correlation, or an agent-emitted
  marker)? **INFERRED** it is partially recoverable from session logs; **SPECULATIVE** that a clean per-finding
  join exists.
- **Rule:** until the spike proves feasibility, **no token/cost-per-finding claim is made.** The efficiency
  metrics in §3 that involve tokens/cost are **UNVERIFIED** and cannot gate a decision.

### 4c. The join
A minimal join table (in case.db or a sidecar) keyed by `experiment_id` → {tool_cost from 4a, llm_cost from 4b
if available, finding_id, validation_outcome, latency}. This is the substrate EFF-SCHED and the memo's
allocation policy both need. It is *additive and measurement-only* (zero capability risk).

---

## 5. ARCH-STATE — case store as durable inter-agent state (reframed)

**v1 error corrected:** ARCH-STATE is **not** sold as a context/token win (UNVERIFIED — subagents already
isolate raw output; adding case-mcp to lean recon/scan agents *re-adds* ~195 tokens/tool of schema).

**Reframed value (the honest benefits):**
- **Reliability & resumability** — durable, structured state survives context compaction (a documented real
  event in this repo's own development). HuntBrain can resume from case.db views instead of re-deriving from
  summarized-away history. **(INFERRED, high-confidence.)**
- **Provenance & evidence linkage** — every state fact cites an `audit_log` observation (extends XYZ.md §3's
  anti-hallucination invariant to the whole state layer). **(design invariant.)**
- **Duplication reduction where measurable** — `check_experiment_exists`, dedupe_check, work_registry already
  exist; wiring recon/scan into the same experiment ledger reduces repeated tests **(UNVERIFIED magnitude —
  must be benchmarked before claiming).**
- **Structured handoff** — specialists return IDs + a compact digest; raw stays on disk (see §7).

**Scope decision (measure, don't assume):** adding case-mcp to recon/scan agents is only worthwhile if the
dedup/resume value outweighs their added schema tokens — **decide from P0-TEL data, not a priori.**

**Prerequisite:** the §6 concurrency fix must land first if more than one writer can touch case.db.

---

## 6. Case-store concurrency (explicit prerequisite — new in v2)

**OBSERVED gap:** `_get_conn` sets `PRAGMA journal_mode=WAL` + `foreign_keys=ON`, **no `busy_timeout`**;
`file_lock` protects JSON state but not case.db. Today's serial single-agent use is safe; concurrent writers
(ARCH-PAR, or recon+scan writing simultaneously under ARCH-STATE) would get immediate `SQLITE_BUSY`.

**Proposed concurrency model (smallest correct):**
- **Concurrency model:** WAL — many readers, one writer at a time; writers must wait, not error.
- **Writer behavior:** wrap each load-mutate-save in a short transaction; keep write transactions minimal.
- **Locking/timeout:** add `PRAGMA busy_timeout = <N ms>` (watch-mcp already does this per the job_runtime
  docstring) so a contending writer blocks-then-succeeds instead of erroring; optionally route case.db writes
  through `file_lock.locked()` for cross-process serialization of the read-modify-write critical sections.
- **Retry policy:** on residual `SQLITE_BUSY` after busy_timeout, bounded exponential retry, then surface an
  explicit error (never silent drop).
- **Transaction semantics:** evidence-gated confirmation and finding-status transitions must remain atomic.
- **Failure handling:** a failed write must not leave a finding half-confirmed; keep the existing single-
  enforcement-point design (`update_finding_status`).
- **Tests/benchmark:** a concurrency test spawning N writers against one case.db asserting no lost updates, no
  `SQLITE_BUSY` surfacing to the agent, and preserved FK/evidence invariants.

**Verdict:** SPIKE + small implementation task; **prerequisite** for ARCH-STATE multi-writer and ARCH-PAR.

---

## 7. Job runtime & result distillation (current vs proposed — corrected)

**CURRENT (OBSERVED):** `start_job` runs a tool as a background subprocess writing stdout/stderr to temp files;
`poll_job` on the done-poll reads those files, **unlinks them**, and returns the **full** stdout/stderr to the
polling (sub)agent; each server's `check_scan` formats it. **There is no durable raw-artifact store.** The v1
claim to the contrary is withdrawn.

**PROPOSED (only if justified):** an **optional durable artifact/evidence layer** — persist large raw tool
output to the engagement's disk dir (the manual `curl -o` download pattern already writes there) under a
content hash, return a **path + schema'd digest** instead of the full dump on the done-poll.
- **Benefit:** (a) shrinks the within-subagent poll-loop context (real but bounded — **INFERRED**), (b) creates
  durable evidence artifacts that survive the session and can be attached to findings/CEM bundles.
- **Cost/risk:** disk management, redaction-before-persist (reuse `redact.py`), and the risk of over-
  distillation dropping a signal line (mitigation: raw always retained + recoverable; digest is additive,
  never lossy-only).
- **Merge:** this absorbs v1's ARCH-DISTILL. It is **not** a headline efficiency phase; it is an evidence/
  reliability improvement with a modest context side effect, and it should be measured, not assumed.

**Verdict:** MERGE ARCH-DISTILL into this; build only if P0-BENCH shows the poll-loop context or the evidence-
durability need is real.

---

## 8. Memory / knowledge (reframed — graph is optional)

**OBSERVED:** structure already exists — `memory.db` (global, structured, `search_by_tech`), `case.db`
(per-engagement structured), writeup RAG (vector), lessons (markdown). Note the **isolation mismatch**:
`memory.db` is global/cross-target by design; `case.db` is per-engagement isolated. A per-engagement fact is
**not** a global fact.

**The real gap (not "no structure"):** weak cross-reference between stores; weak linkage into prioritization/
planning; weak provenance relationships; lessons are freeform prose, not queryable signals.

**Corrected proposal — LEARN-XREF (SQLite-first, KEEP small):** a minimal cross-reference + provenance layer
over the existing stores using a shared vocabulary (vuln_class, endpoint, tech, cwe), feeding a prioritization
signal to EFF-SCHED. Provenance invariant: **target-derived text can never write an authoritative fact; only
audit-cited observations can.**

**Knowledge *graph* — DEFER/EXPERIMENTAL.** Ask first whether **SQLite + structured references + provenance**
suffices (it likely does initially — **INFERRED**). A graph adds a **GraphRAG-poisoning** surface (GragPoison
~98% success, existing defenses inadequate — **RESEARCH-SUPPORTED**) for marginal early benefit. Adopt a graph
(and networkx) only if SQLite cross-referencing provably hits a wall.

**LEARN-SIG (CEM causal-signature reuse) — EXPERIMENTAL, KEEP as prototype.** The memo's defensible research
bet (question C). Signatures are **re-confirmed hints, never skips**; nondeterministic signatures are
non-cacheable; the oracle must still fire. Gated on Phase-4 signatures + measured transfer without floor breach.

---

## 9. DISC-GRAPH — attack-state graph (minimal-first — corrected)

**Do not** start with MCTS/A*/PDDL/networkx. Corrected staged approach:

**Stage 1 — minimal representation (SQLite adjacency):**
- **Nodes:** capabilities gained (e.g. "read user-B object", "SSRF to metadata"), observed states, findings.
- **Edges:** `enables` / `depends-on`, **each citing a real `audit_log` id** (poisoning + hallucination
  defense).
- **Preconditions/postconditions:** capability sets per edge.
- **Evidence:** every edge linked to case.db evidence.

**Stage 2 — best-first search only:** greedy on `severity × confidence`; branching factor for one target's
finding set is small (tens of nodes — **INFERRED**), so best-first is very likely sufficient. Pruning:
drop dominated/duplicate paths; stopping: budget cap (`budget_guard`) + no-improvement cutoff; search budget:
bounded node expansions.

**Stage 3 — benchmark gate:** on P0-BENCH, must **recover chains the 15-template matcher cannot, at no FP
cost**, before anything richer is considered.

**Stage 4 (only if Stage 3 shows best-first tunnels-visions):** beam search; then, only if proven necessary,
MCTS (for genuinely large/uncertain state) or a planner + networkx. **RESEARCH-SUPPORTED** that MCTS suits
unknown-topology network pentest (ShotFlex), **INFERRED** that it is overkill for a finished web finding set.

**CEM integration:** minimal-condition-set signatures as edge weights / precondition hints (presupposes CEM
Phase 1 + Phase-4 signatures).

**Verdict:** EXPERIMENTAL prototype; Stage-1/2 only until the benchmark justifies more.

---

## 10. VAL-AUTHZ — stateful authorization (top capability bet, minimal scope)

**OBSERVED baseline:** `idor-mcp sweep_idor` = single-request, single-endpoint, two-account replay with pair
classification.

**Gap (RESEARCH-SUPPORTED — AuthProbe/BACFuzz/RESTler):** (1) **multi-step workflows** (authz at step 1, an
unrevalidated id carried into step 2); (2) a **ground-truth-fetch oracle** (compare cross-account response to
the true owner's fetch, not status/length alone); (3) an **identity/role matrix** (unauth, low-priv, admin,
tenant-B) beyond two peers.

**Smallest useful version (build only this first):**
- Strengthen the existing sweep's oracle to **owner-fetch-and-compare** (reduces length/status-only FPs).
- Add a **two-step replay primitive**: capture a short workflow as account A, replay step N under account B's
  identity while holding earlier steps, classify the same way.
- Emit confirmed findings straight into `case_store.create_finding` with candidate CEM conditions (identity,
  step-order, carried id) — direct CEM synergy.

**Safety:** idempotent/GET-shaped default; non-idempotent steps require the UD-4 human gate; `scope_guard` on
every request; reuse the shared HTTP primitive (`http_probe.py`).

**Benchmark & success criteria:** planted multi-step authz labels on P0-BENCH; success = recovers multi-step
authz findings the single-request sweep misses, **zero new false positives**, verdicts agree with ground truth.

**Verdict:** KEEP — #1 capability bet (extends a tested tool, measurable baseline, targets the human-advantage
class).

---

## 11. DISC-VARIANT — counterfactual variant discovery (current vs new)

**Current (OBSERVED):** CEM already records an incidental "capability survives under a different value/state"
observation if it falls out of a necessity trial (XYZ.md §2.7 — Phase-1 records, Phase-4 acts). `dedupe_check`
exists to avoid double-reporting.

**New:** turn that byproduct into **active** neighboring-param/endpoint probing:
- **Find** nearby variants — perturb a confirmed condition to an adjacent value/identity/endpoint and re-test.
- **Extract** causal conditions/signatures — reuse CEM's minimal-set machinery (no new engine).
- **Prioritize** likely variants — by signature similarity + severity potential (feeds EFF-SCHED).
- **Validate** variants — through the same CEM oracle + evidence gate (never reported unconfirmed).

**Safety:** same gates as VAL-AUTHZ (state-changing perturbation → human gate); dedupe to avoid re-reporting a
known finding as a "variant."

**Novelty:** the strongest genuine differentiation claim (variant-as-necessity-testing-byproduct is
underexplored — "to our knowledge," not "unseen"). Marginal complexity is low because it rides CEM.

**Verdict:** KEEP — the moat-widener; gated behind CEM Phase 1.

---

## 12. EFF-SCHED — experiment scheduling (telemetry-gated cost claims)

**OBSERVED:** `suggest_next_action` is a trivial "finish what's in flight" heuristic; case.db already holds
hypotheses/findings/experiments/status.

**Two versions:**
- **EFF-SCHED-v0 (KEEP, possible now):** a better *heuristic* using existing case-state signals — novelty
  (untested vuln_class/endpoint), severity potential, finish-in-flight, avoid `check_experiment_exists`
  repeats. No ML, no new deps. Capability-neutral-to-positive; reduces wasted round-trips (the real token lever
  under cache-read).
- **EFF-SCHED-v1 (DEFER, telemetry-gated):** value-of-computation / information-gain scoring
  (**RESEARCH-SUPPORTED** — Russell–Wefald VOC, Bayesian experimental design) using **real** cost/gain data
  from §4. Do not build with invented cost numbers ("confidence theater").

**Guardrails:** never hard-block a not-yet-confirmed novel angle; severity-gated minimum-effort floor; audit
suppressed experiments; **fewer tool calls is only "better" if coverage + validation are intact** (per-class
coverage floor on P0-BENCH). Cost/token savings remain **UNVERIFIED** until telemetry exists.

**Verdict:** KEEP v0 now; DEFER v1 behind P0-TEL.

---

## 13. EFF-ALLOC — adaptive intelligence allocation (ALREADY COVERED)

**OBSERVED:** fully specified in [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md) (cascades,
learned routing, VOC, the CEM aleatoric/epistemic determinism signal, the A/B/C/D experiment), gated on
measurement + Phase-4/5. v2 does **not** duplicate it.

**Interface only:** the memo's allocation policy consumes exactly what v2's telemetry (§4) + LEARN-SIG (§8)
produce — the join table (cost/yield features) and CEM signatures. v2's contribution is *making those inputs
real*; the policy itself remains the memo's Phase-5 work, provider-agnostic, sitting beside `model_gateway`
(unchanged plumbing).

**Verdict:** ALREADY EXISTS (owned by the memo); v2 supplies its prerequisites, nothing more.

---

## 14. P0-BENCH — benchmark substrate (foundational)

**OBSERVED:** the CEM constructed testbed + blind-manifest/evaluator-only-key split already exist
(`test_cem_scenarios_blind.py`). Extend (additively — no edits to existing ground truth; benchmarks.md
approval) into a **standing multi-class range** with a **frontier-heavy reference arm**.

**Minimum it must measure, per vuln-class:** capability (findings), coverage, validation depth, false
positives, tool calls, model calls, tokens (once P0-TEL-LLM exists), cost, latency.

**Governing rule:** **no architecture change is "successful" on token reduction alone.** Every candidate is
A/B'd against the frontier arm; a missed high/critical the baseline found = hard fail (memo §7); medium/low/
coverage/depth deltas scored on the Pareto frontier and reported explicitly.

**Verdict:** KEEP — the single highest-leverage enabler; converts every other bet from opinion to evidence.

---

## 15. Candidate re-evaluation (all, with tags)

Dimensions abbreviated; classification is the operative output.

| Candidate | Class | Sec | Cov | Val | Chain | Eff | Tok/Ctx | Cost | Lat | Cmplx | Reliab | SecRisk | Maint | Research | Novelty | Confidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P0-BENCH | **KEEP** | HIGH | HIGH | HIGH | MED | enabler | — | — | — | MED | HIGH | LOW | MED | HIGH | established | HIGH |
| P0-TEL-TOOL | **KEEP** | MED | — | MED | — | MED | LOW | MED(UNVERIFIED) | — | LOW | HIGH | LOW | LOW | MED | established | HIGH |
| P0-TEL-LLM | **SPIKE** | — | — | MED | — | MED | — | MED(UNVERIFIED) | — | HIGH | MED | LOW | MED | MED | established | LOW |
| VAL-AUTHZ (min) | **KEEP** | HIGH | HIGH | HIGH | MED | — | — | — | MED | MED | MED | MED | MED | MED | novel application | HIGH |
| DISC-VARIANT | **KEEP** | MED | MED | MED | MED | — | — | — | — | MED | MED | MED | MED | HIGH | novel combination | MED |
| EFF-SCHED-v0 | **KEEP** | MED | MED | MED | MED | MED | MED | MED | MED | LOW | MED | LOW-MED | LOW | LOW | competent eng | MED |
| ARCH-STATE (reframed) | **KEEP** | MED | LOW | MED | LOW | LOW | UNVERIFIED | — | LOW | MED | HIGH | MED | MED | MED | novel application | MED |
| case.db concurrency fix | **KEEP (prereq)** | MED | — | MED | — | — | — | — | — | LOW-MED | HIGH | MED | LOW | LOW | competent eng | HIGH |
| DISC-SPEC | **KEEP** | LOW | HIGH | LOW | MED | — | — | — | LOW | MED | MED | MED | MED | LOW | established | MED |
| ARCH-DISTILL | **MERGE→§7** | — | — | LOW | — | LOW | UNVERIFIED | — | LOW | MED | MED | MED | MED | LOW | established | HIGH |
| LEARN-XREF (SQLite) | **KEEP small** | MED | MED | MED | MED | LOW | LOW | — | — | MED | MED | MED | MED | MED | competent eng | MED |
| VAL-COND | **DEFER** | MED | MED | HIGH | MED | — | — | — | — | MED | MED | MED | MED | MED | novel combination | MED |
| EFF-SCHED-v1 (VOC/BED) | **DEFER** | LOW | MED | MED | MED | MED | MED | MED | MED | MED | MED | MED | MED | MED | established | LOW |
| DISC-GRAPH (best-first) | **EXPERIMENTAL** | MED | MED | MED | HIGH | LOW | — | — | MED | HIGH | MED | MED-HIGH | HIGH | HIGH | novel combination | LOW |
| LEARN-SIG | **EXPERIMENTAL** | MED | MED | HIGH | MED | MED | MED | MED | — | HIGH | MED | MED | HIGH | HIGH | research-worthy | LOW |
| ARCH-PAR | **DEFER** | MED | HIGH | — | MED | — | — | HIGH | HIGH | HIGH | MED | MED | HIGH | LOW | established | MED |
| EFF-SCAN | **DEFER** | risk↓ | risk | — | — | MED | MED | MED | HIGH | HIGH | MED | HIGH | HIGH | LOW | established | MED |
| LEARN-KG (graph) | **REJECT (for now)** | LOW | MED | MED | MED | LOW | LOW | — | — | HIGH | MED | HIGH | HIGH | MED | established | MED |
| EFF-ALLOC | **ALREADY EXISTS** | — | — | — | — | MED | MED | MED | HIGH | HIGH | MED | MED | HIGH | MED | prior art | HIGH |
| VAL-DIFF | **ALREADY PLANNED** | LOW | — | MED | — | — | — | — | — | LOW | MED | LOW | LOW | MED | novel application | HIGH |

---

## 16. V2 Roadmap — two parallel tracks

All subordinate to CEM Phase 1 shipping; all research-only until authorized; no assumption that every idea
ships. Tracks A and B run in parallel with the cross-dependencies shown.

```
                        ┌──────────────────────────────────────┐
                        │  Phase-1 CEM (existing) ships first    │
                        └──────────────────────────────────────┘
        TRACK B (measurement/efficiency)     │      TRACK A (capability)
   ──────────────────────────────────────   │   ──────────────────────────────
   P0-BENCH ─────────────────────────────── gates ── all A/B claims
   P0-TEL-TOOL                               │      VAL-AUTHZ (min)  ← DISC-SPEC feeds
   P0-TEL-LLM (spike)                        │      DISC-VARIANT (post-CEM)
   case.db concurrency fix ── enables ──────►│      (ARCH-STATE multi-writer, ARCH-PAR)
   EFF-SCHED-v0                              │
        │ (real data)                        │
        ▼                                     ▼
   EFF-SCHED-v1, LEARN-XREF ───────► feeds ─ EFF-ALLOC (memo, Phase-5)
        │                                     │
        ▼ (benchmark-gated)                   ▼ (experimental, benchmark-gated)
   EFF-SCAN                              DISC-GRAPH(best-first), LEARN-SIG
```

### Phase 0 — Benchmark + telemetry feasibility + concurrency prerequisites
- **Objective:** make capability/efficiency provable and make concurrent state safe.
- **Prerequisites:** none (parallel to CEM Phase 1 where measurement-only).
- **Scope:** P0-BENCH (additive scenarios + frontier arm); P0-TEL-TOOL (audit_log/experiments extension);
  P0-TEL-LLM (OpenCode-usage spike — may conclude "not cleanly feasible"); case.db concurrency fix
  (busy_timeout + optional file_lock + concurrency test).
- **Capability gain:** none directly (enabler). **Efficiency impact:** none directly; enables all later claims.
- **Risks:** low; benchmark changes need human approval (additive only).
- **Benchmark:** self-consistency of labels; cost/yield reconciliation from real data; N-writer concurrency test.
- **Rollback:** all additive/removable. **Exit:** frontier baseline reproducible; tool-cost-per-finding real;
  LLM-cost feasibility documented; concurrent writers safe.

### Phase 1 — Low-risk substrate that unlocks reliability + waste reduction
- **Objective:** durable state/provenance + fewer wasted round-trips.
- **Prerequisites:** Phase 0 concurrency fix (for multi-writer); P0-TEL-TOOL (to measure dedup value).
- **Scope:** ARCH-STATE (reframed: reliability/provenance/resumability; recon/scan wiring **only if** telemetry
  shows net benefit); EFF-SCHED-v0; optional durable-artifact layer (§7) if justified; LEARN-XREF (SQLite
  cross-reference).
- **Capability gain:** indirect (less duplication, better resume). **Efficiency:** fewer round-trips
  (**UNVERIFIED magnitude** until measured).
- **Risks:** concurrency (mitigated Phase 0); over-distillation (raw retained). **Benchmark:** equal finding set
  at ≤ resources; no capability change. **Rollback:** revert to prose handoff / trivial scheduler. **Exit:**
  measured reliability/waste improvement with zero finding-set change.

### Phase 2 — Capability bets (evidence- and dependency-ordered)
- **Objective:** widen the moat on the human-advantage class + differentiated variant discovery.
- **Prerequisites:** P0-BENCH; VAL-AUTHZ benefits from DISC-SPEC; DISC-VARIANT requires CEM Phase 1.
- **Scope:** VAL-AUTHZ (min) → DISC-SPEC (feeds it) → DISC-VARIANT (post-CEM) → VAL-COND (later).
- **Capability gain:** HIGH (multi-step authz findings + variants). **Efficiency:** neutral/flat.
- **Risks:** mutation safety (gated), oracle FPs (owner-fetch compare). **Benchmark:** planted multi-step authz
  labels; variant yield. **Rollback:** flag off → existing sweep/CEM. **Exit:** recovers findings the baseline
  misses, zero new FP.

### Phase 3 — Learning / advanced planning / adaptive efficiency
- **Objective:** compounding learning + real value-of-computation efficiency + interface to allocation.
- **Prerequisites:** Phase 0 telemetry (real data); Phase 2 (CEM signatures for LEARN-SIG); the memo (EFF-ALLOC).
- **Scope:** EFF-SCHED-v1 (VOC/BED on real data); LEARN-SIG (experimental, hints-not-skips); provide telemetry
  + signatures to the memo's EFF-ALLOC policy.
- **Capability gain:** MED (learning). **Efficiency:** MED (measured). **Risks:** stale signatures (→ missed
  bugs, hints-not-skips), confidence theater (real data only). **Benchmark:** signature transfer rate; C-vs-D
  ablation with floor held. **Rollback:** disable reuse/scoring. **Exit:** measured gain with no floor breach.

### Phase 4 — Experimental research directions
- **Objective:** the high-risk/high-upside bets, benchmark-gated, none assumed to ship.
- **Scope:** DISC-GRAPH (best-first prototype, must beat template matcher on P0-BENCH); ARCH-PAR (after
  concurrency fix); EFF-SCAN (per-class coverage floor enforced); knowledge *graph* only if SQLite XREF hits a
  wall.
- **Risks:** complexity-as-innovation, coverage regression, poisoning. **Benchmark:** each must beat its
  incumbent on P0-BENCH at no capability cost. **Rollback:** fall back to incumbent. **Exit:** demonstrated
  benefit over the simpler existing mechanism, or the idea is dropped.

---

## 17. Smallest set that meaningfully improves capability AND efficiency long-term

**Answer:** four investments, in this order of confidence:

1. **P0-BENCH** — the standing ground-truth range + frontier reference arm. Without it, "more capable" and
   "more efficient" are opinions. It is the cheapest way to make every later decision evidence-based.
2. **VAL-AUTHZ (minimal)** — the one capability bet with a clear gap, an existing measurable baseline
   (`idor-mcp`), and a documented human-advantage target class.
3. **P0-TEL-TOOL + EFF-SCHED-v0** — the honest efficiency pair: measure tool/HTTP/yield, then cut wasted
   round-trips (the real lever under cache-read), never at the cost of coverage.
4. **DISC-VARIANT** — the differentiated moat-widener that rides CEM at low marginal complexity.

Everything else is either a prerequisite (concurrency fix), a reliability substrate (ARCH-STATE), owned
elsewhere (EFF-ALLOC), or experimental (DISC-GRAPH, LEARN-SIG). **This is the smallest set** because it delivers
one capability gain, one differentiated capability gain, one measured efficiency gain, and the measurement
backbone that guards the floor — with no speculative infrastructure.

---

## 18. Novelty Audit (honest model retained)

- **Genuinely novel:** none claimed outright.
- **Novel combination (to our knowledge underexplored):** DISC-VARIANT (variant as CEM necessity-testing
  byproduct); CEM-signature-guided DISC-GRAPH; LEARN-SIG (CEM amortization — research-worthy, unproven).
- **Novel application:** VAL-AUTHZ (multi-step + owner-oracle feeding CEM); ARCH-STATE (structured belief state
  for a security agent); VAL-DIFF.
- **Established technique:** P0-BENCH, P0-TEL, DISC-SPEC, EFF-SCHED, EFF-SCAN, best-first search, LEARN-XREF.
- **Prior art (owned elsewhere):** EFF-ALLOC (the memo), model routing, cascades, RAG, MCTS/PDDL planning.

No "unseen anywhere" claims. GraphRAG-poisoning risk (**RESEARCH-SUPPORTED**) is preserved as a hard constraint
on any graph/knowledge candidate.

---

## 19. What Changed From V1

**Claims corrected:**
- Token telemetry via `audit_log` — corrected: MCP layer can't see LLM tokens; split into P0-TEL-TOOL (feasible)
  + P0-TEL-LLM (spike).
- ARCH-STATE "HIGH context savings" — corrected to UNVERIFIED; reframed to reliability/provenance/resumability.
- ARCH-DISTILL "reuse existing disk persistence" — corrected: job_runtime unlinks output; no such persistence
  exists; merged into an optional durable-artifact layer.
- LEARN-KG "learning is unstructured, build a knowledge architecture" — corrected: `memory.db` is already
  structured + tech-searchable; gap is cross-reference/feedback, not structure.
- "Telemetry is the highest-leverage first step" — corrected: it's the highest-leverage *enabler* but delivers
  zero capability; capability work (VAL-AUTHZ) runs in parallel, not behind it.

**Candidates downgraded:** DISC-GRAPH (KEEP → EXPERIMENTAL, best-first-first); LEARN-KG graph (KEEP → REJECT for
now); ARCH-DISTILL (standalone → MERGE); EFF-ALLOC (candidate → ALREADY EXISTS/interface-only); ARCH-STATE
(efficiency win → reliability win, token benefit UNVERIFIED); EFF-SCAN/ARCH-PAR/VAL-COND (→ DEFER).

**Candidates promoted / clarified:** P0-BENCH (→ foundational #1 enabler); VAL-AUTHZ (→ #1 capability bet with a
minimal scope defined); EFF-SCHED-v0 (→ do-now, given cache-read economics); DISC-VARIANT (→ flagship
differentiation).

**Ordering changed:** single serial chain → **two parallel tracks** (capability + measurement) with explicit
cross-dependencies; VAL-AUTHZ no longer waits behind telemetry.

**Prerequisites added:** case.db concurrency fix (busy_timeout + locking + tests) before any multi-writer state
work; P0-TEL-LLM feasibility spike before any token/cost claim.

**Ideas rejected:** knowledge-graph infrastructure (for now); PDDL/MCTS/A*/networkx at v0; ML/Bayesian
scheduling before real data; duplicating EFF-ALLOC.

**Uncertainty introduced where evidence is missing:** all token/cost efficiency figures are UNVERIFIED until
P0-TEL + P0-BENCH exist; LLM-cost recoverability from OpenCode is SPECULATIVE pending the spike; DISC-GRAPH's
advantage over templates is unproven; CEM signature transfer is an open question.

---

## 20. Top 3–5 Bets (long-term capability)

1. **P0-BENCH** — evidence backbone; nothing else is provable or floor-protected without it. *Highest
   confidence.*
2. **VAL-AUTHZ (minimal multi-step + owner-fetch oracle)** — clearest capability gap, cleanest existing
   baseline, targets the human-advantage class, feeds CEM.
3. **DISC-VARIANT** — most differentiated, cheap because it rides CEM machinery.
4. **P0-TEL-TOOL + EFF-SCHED-v0** — the honest efficiency lever (fewer wasted round-trips), measured not assumed.
5. **ARCH-STATE re-scoped to reliability/provenance** (with the concurrency fix) — the durable substrate the
   graph/scheduler/learning phases eventually need; bet on correctness, not tokens.

Deliberately **not** top bets: DISC-GRAPH (prototype-gate), knowledge graph (reject), adaptive routing (memo
owns it), token-reduction-as-headline (re-scoped to a measured, floor-guarded metric).

---

## 21. Unresolved Research Questions

1. Is LLM token/cost recoverable from OpenCode session usage and joinable to `finding_id`? (Gates every
   token/cost claim.)
2. What is HuntBrain's real context breakdown (system vs agent-instructions vs MCP schema vs carried summaries)?
   (Determines whether ARCH-STATE has any token benefit at all.)
3. On P0-BENCH, does best-first over an attack-state graph recover any chain the 15 templates cannot, at no FP
   cost? (Go/no-go for DISC-GRAPH.)
4. What fraction of real-hunt experiments are redundant / re-derivable? (Sizes the EFF-SCHED opportunity.)
5. Do CEM signatures transfer across findings/targets? (LEARN-SIG / the memo's crux.)
6. Does the multi-step authz owner-fetch oracle hold FP rate ≤ baseline?
7. Does giving recon/scan agents case-mcp cost more schema tokens than the dedup/resume value returned?
8. Is SQLite cross-referencing genuinely sufficient, or does a knowledge graph eventually earn its poisoning
   risk?

---

## 22. Final Confidence

- **Strategy & floor discipline:** HIGH — the capability-floor-as-hard-constraint, CEM-untouched, extend-don't-
  multiply posture is sound and consistent with the repo's own rules.
- **Capability bets (VAL-AUTHZ, DISC-VARIANT):** MED-HIGH — grounded in existing baselines + literature;
  success criteria are measurable.
- **Efficiency claims:** LOW until P0-TEL + P0-BENCH exist — deliberately held as UNVERIFIED; no token/cost
  improvement is asserted, only a measurement path.
- **Experimental bets (DISC-GRAPH, LEARN-SIG, knowledge graph):** LOW — correctly gated as prototypes behind
  the benchmark.

**Overall:** v2 is internally consistent, factually reconciled with the code, and safe to treat as the planning
baseline. It commits to measurement and one capability bet, defers the speculative infrastructure, and asserts
**no efficiency gain that isn't yet measurable.** It remains research-only; no phase is authorized to start.
