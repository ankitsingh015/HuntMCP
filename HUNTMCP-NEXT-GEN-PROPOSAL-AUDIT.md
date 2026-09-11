# HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT.md — Independent Skeptical Review

> Scope: adversarial architecture/research review of [HUNTMCP-NEXT-GEN-PROPOSAL.md](HUNTMCP-NEXT-GEN-PROPOSAL.md),
> verified against the actual repository. **Research only.** No implementation, no production/benchmark changes,
> no commits, no phase started. Claims below are tagged **OBSERVED** (verified in repo), **RESEARCH-SUPPORTED**
> (external literature), **INFERRED** (reasoned, not directly verified), or **SPECULATIVE**.

---

## 1. Audit Summary

The proposal is **directionally sound but factually loose in several load-bearing places**, and its headline
efficiency framing does not survive contact with the code. The strategic posture (capability floor as a hard
constraint, measurement-gated efficiency, extend-don't-multiply, CEM untouched) is correct and worth keeping.
But four claims are wrong or overstated, and they matter:

1. **Token telemetry cannot live where the proposal puts it.** `audit_log.py` runs inside MCP tool
   subprocesses that never see the LLM conversation; LLM token/cost is an OpenCode-session concern, not an
   MCP-layer one. **(OBSERVED)**
2. **The context-savings headline is weak.** OpenCode subagents already isolate context — HuntBrain receives
   returned summaries, not raw tool dumps — so ARCH-STATE/ARCH-DISTILL's savings are mostly *within a
   subagent's own poll loop*, not the cross-agent win implied. **(OBSERVED/INFERRED)**
3. **ARCH-DISTILL's "reuse the existing disk-persistence pattern" is false.** `job_runtime` reads and then
   **unlinks** raw output; nothing persists it. That persistence would be new work. **(OBSERVED)**
4. **LEARN-KG's "learning has no structure, build a knowledge architecture" is overstated.** `memory.db` is
   already a global structured cross-target store with tech-based search; the real gap is cross-referencing and
   feedback, not absence of structure. **(OBSERVED)**

Plus a concrete safety/scalability gap the proposal missed: **`case_store` sets WAL + foreign_keys but no
`busy_timeout`**, and `file_lock` does not cover `case.db` — so ARCH-STATE + ARCH-PAR (concurrent writers)
would hit "database is locked". **(OBSERVED)**

None of this sinks the roadmap, but it means the correct first move is **not** "telemetry first." It is a
**benchmark range** (the thing that makes any claim provable) plus **one concrete capability bet with an
existing measurable baseline (VAL-AUTHZ)** — with telemetry split into its feasible half (tool/HTTP/wall-clock)
and its harder half (LLM tokens via OpenCode).

**Verdict: REQUIRES RESEARCH REVISION** (see §20).

---

## 2. Confirmed Strengths (survive the review)

- **OBSERVED — The safety substrate is genuinely strong and the proposal respects it.** scope_guard,
  budget_guard (500-call breaker, banded), dedupe_check, work_registry, `file_lock` (advisory flock on JSON
  state), audit_log (redacted, per-call), content_scanner, redact, the unconditional `rm` hard-block. The
  proposal's §19 "do not change yet" list is correct.
- **OBSERVED — Evidence-gated confirmation is real** (`update_finding_status` refuses CONFIRMED with zero
  evidence) and content-addressed evidence is a good foundation. The proposal correctly keeps it.
- **OBSERVED — Per-agent MCP scoping is genuinely shipped** (`opencode.jsonc` global `false` + per-agent
  allowlists). Correctly treated as done, not re-proposed.
- **OBSERVED — CEM engine is substantial and well-structured** (determinism gate, classify, minimal/alternate
  sets, AND-necessity, poc minimization, bundle). Treating it as the untouchable current focus is right.
- **RESEARCH-SUPPORTED — The "humans still win on authz/business-logic + audit-grade attestation" claim is
  well-grounded** and correctly maps to VAL-AUTHZ + CEM. This is the strongest strategic thread.
- **The novelty honesty** (Appendix A) is mostly accurate: the proposal already refuses to overclaim routing,
  RAG, planning, BED. Good discipline.

---

## 3. Findings / Weaknesses (ranked)

| # | Severity | Finding |
|---|---|---|
| F1 | **High** | Token telemetry mislocated: LLM tokens invisible to the MCP layer (P0-TEL half infeasible as written). |
| F2 | **High** | Context-savings headline overstated; subagent isolation already does most of the work. |
| F3 | **High** | `case.db` concurrency gap (no busy_timeout, not in file_lock) blocks ARCH-STATE+ARCH-PAR as written. |
| F4 | Med | ARCH-DISTILL "reuse disk pattern" is false; the pattern doesn't exist. |
| F5 | Med | LEARN-KG novelty/necessity overstated; structured cross-target store already exists (`memory.db`). |
| F6 | Med | "Telemetry is the highest-leverage first step" conflates *enabler* with *leverage*; it delivers zero capability and gates only the efficiency tier. |
| F7 | Med | EFF-SCHED "blocked on telemetry" is overstated; a v0 using existing case-state signals is possible now. |
| F8 | Low | EFF-ALLOC largely duplicates INTELLIGENCE-ALLOCATION-MEMO; should be merged into it, not re-listed as a candidate. |
| F9 | Low | DISC-GRAPH risk of being complexity-for-its-own-sake; needs a hard "beats the template matcher on the benchmark" gate before any planner beyond best-first. |
| F10 | Low | The proposal's scorecard marks ARCH-STATE context gain "HIGH"; evidence supports "LOW–MED" at best. |

---

## 4. Candidate-by-Candidate Audit

Format: **Classification** — real gap (verified) · key risk · verdict rationale. Dimensions A–Q folded into
prose; the full matrix is in §15.

### P0-TEL — Cost/yield/information telemetry
- **MERGE + PARTIAL-REJECT.** **OBSERVED:** `audit_log` already records tool, redacted args, returncode,
  `duration_ms`, block per Tier-2 call; `budget_guard` counts calls by tool. The *tool/HTTP/wall-clock/yield*
  half is a clean extension (add request count + a `finding_id` link on `experiments`, which `case_store`
  already has a `cost` column for). The *LLM-token/cost* half **cannot** be done here — MCP subprocesses never
  see the conversation. That half must read OpenCode session/provider usage, a separate surface.
- **Verdict:** KEEP the feasible half (call it **P0-TEL-TOOL**), scoped as an `audit_log`/`case_store`
  extension; **DEFER/RE-SCOPE** the token half (**P0-TEL-LLM**) as an OpenCode-integration research spike, not
  an `audit_log` change. Do **not** headline "yield per total cost" until both sources exist.

### P0-BENCH — Ground-truth benchmark range
- **KEEP (promote to first).** **OBSERVED:** the CEM constructed testbed + evaluator split already exist
  (`test_cem_scenarios_blind.py`, evaluator-only key). Extending to a standing multi-class range with a
  frontier reference arm is the single highest-value enabler — nothing else is provable without it. Higher
  real value than P0-TEL. **Risk:** benchmark-methodology changes need human approval (benchmarks.md) — treat
  as *additive new scenarios*, never edits to existing ground truth.

### ARCH-STATE — Case store as inter-agent state bus
- **KEEP but RE-FRAME + DOWNGRADE the context claim.** See deep review §9. **OBSERVED:** case-mcp is already
  used by huntbrain/exploit-agent/chain-planner; recon-agent/scan-agent do **not** have case-mcp in their
  allowlists, so "all agents write structured records" requires adding case-mcp tools to the lean agents
  (re-adding ~195 tokens/tool of schema to exactly the agents kept lean). Net context effect is ambiguous, not
  "HIGH." The real, defensible value is **reliability/dedup/post-compaction resume + provenance**, not tokens.
- **Verdict:** KEEP, but sell it as a *correctness/reliability* change with a *modest* efficiency side effect,
  and fix the concurrency gap (F3) first.

### ARCH-DISTILL — Tool-result distillation at MCP boundary
- **MERGE into ARCH-STATE + correct the false claim.** **OBSERVED:** `job_runtime` streams full stdout/stderr
  back on the done-poll and then **unlinks** the temp files — there is no raw-to-disk persistence to reuse. A
  distillation layer would need (a) new persistent raw storage and (b) a schema'd summary. The context cost it
  targets is *within a subagent's poll loop*, which is real but smaller than implied.
- **Verdict:** MERGE into ARCH-STATE as "structured returns + optional raw persistence"; do not run as a
  separate headline efficiency phase.

### VAL-AUTHZ — Stateful authorization differential engine
- **KEEP (top capability bet).** See deep review §11. **OBSERVED:** `idor-mcp sweep_idor` does single-request
  two-account replay with PROTECTED/LEAKED/AMBIGUOUS/etc. classification. The genuine gap is **multi-step
  workflow** authz (authz in step 1, unrevalidated id in step 2) and a **ground-truth-fetch oracle**. This
  extends an existing, tested tool and has a measurable baseline. **Risk:** state-changing mutations — must
  default idempotent, human-gate non-idempotent (UD-4 already rules this way).
- **Verdict:** KEEP; define the smallest useful version (§11).

### VAL-COND — Autonomous CEM condition extraction
- **DEFER (correctly Phase-4-ish).** **OBSERVED:** XYZ.md §2.1 explicitly keeps conditions human-supplied in
  Phase 1 for trust reasons. Auto-extraction is real value but must not undermine the determinism/trust gates.
- **Verdict:** DEFER until CEM Phase 1 ships and a benchmark can show auto-extracted conditions don't inflate
  false-necessity. NEEDS MORE EVIDENCE that extraction quality is high enough.

### VAL-DIFF — Structural differentiation evidence
- **ALREADY PLANNED (DEFER).** This is XYZ.md §2.6 verbatim (Phase 3+). Not a new candidate; it is existing
  roadmap. Keep it there. **Verdict:** DEFER (owned by the existing spec chain).

### DISC-VARIANT — Counterfactual variant discovery
- **KEEP (best novelty-per-cost).** **OBSERVED:** XYZ.md §1.3/§2.7 already identifies this as genuinely
  underexplored and Phase-4. It rides CEM's own machinery (a perturbation that keeps the capability alive under
  a different value = a variant), so marginal complexity is low. **Risk:** state-changing perturbations; same
  gate as VAL-AUTHZ. **Verdict:** KEEP as the flagship differentiated capability, gated behind CEM Phase 1.

### DISC-SPEC — Spec-driven surface expansion
- **KEEP (low novelty, solid value).** **OBSERVED:** `endpoint_template.py` + secrets-mcp `extract_endpoints`
  already pull route literals from JS; recon already mines JS. Adding OpenAPI/GraphQL schema parsing is a
  natural, well-understood extension. Not novel (RESTler/Schemathesis). **Verdict:** KEEP, low priority, feeds
  VAL-AUTHZ and scan targeting.

### DISC-GRAPH — Attack-state graph + planner
- **DEFER to experimental prototype only.** See deep review §10. **OBSERVED:** chaining is 15 static templates
  — genuinely weak. But the jump to a searched attack-state graph is large, and the benchmark to justify it
  (chains a template can't encode) doesn't exist yet. **Risk:** complexity-as-innovation, graph poisoning,
  branching blowup. **Verdict:** DEFER; prototype **best-first over a SQLite adjacency graph only**, gated on
  beating the template matcher on P0-BENCH. Reject PDDL/MCTS/A* until best-first is proven insufficient.

### ARCH-PAR — Parallel-solver orchestration
- **DEFER (table stakes, not differentiator).** **OBSERVED:** work_registry + budget_guard exist; the phase
  loop is sequential. Parallel solvers are XBOW-established, add real breadth, but also add the case.db
  concurrency problem (F3) and orchestration complexity. **Verdict:** DEFER behind ARCH-STATE's concurrency fix;
  it is Phase-2 "match breadth" work, not a moat move.

### LEARN-KG — Unified poison-resistant knowledge layer
- **REJECT the graph; KEEP a much smaller cross-reference layer.** See deep review §12. **OBSERVED:**
  `memory.db` (global, structured, tech-searchable) + `case.db` (per-engagement structured) + writeup RAG +
  lessons already exist. A knowledge *graph* adds a poisoning surface (GragPoison ~98%, RESEARCH-SUPPORTED)
  for benefit that SQLite cross-referencing largely delivers. **Verdict:** REJECT graph infrastructure;
  KEEP a minimal "cross-reference the existing stores + feed signals to prioritization" task, with the
  audit-cited-write invariant.

### LEARN-SIG — CEM causal-signature store & reuse
- **KEEP as research prototype (Tier 3).** **RESEARCH-SUPPORTED / INFERRED:** the memo's own question C; the
  one defensible research bet. **Risk:** stale signatures → missed bugs; the memo already specifies "hints,
  never skips." **Verdict:** KEEP but explicitly experimental, gated on Phase-4 signatures existing and on the
  benchmark measuring transfer without floor breach.

### EFF-SCHED — Info-gain experiment scheduler
- **KEEP a v0 now; DEFER the cost-optimal version.** **OBSERVED:** `suggest_next_action` is a trivial heuristic;
  case_store already holds hypotheses/findings/experiments/status — enough for a **better heuristic v0**
  (novelty = untested, severity potential, finish-in-flight) *without* full cost telemetry. The VOC/BED version
  needs P0-TEL. **Verdict:** KEEP v0 (cheap, capability-neutral-to-positive); DEFER the Bayesian version.

### EFF-SCAN — Directed scan prioritization
- **DEFER (highest coverage risk).** **OBSERVED:** scan phases are exhaustive by design. Prioritization could
  cut cost but directly threatens the coverage floor. **Verdict:** DEFER until P0-BENCH can enforce a per-class
  coverage floor and prove no high/critical miss. NEEDS MORE EVIDENCE.

### EFF-ALLOC — Adaptive intelligence allocation
- **MERGE into the existing memo (not a new candidate).** **OBSERVED:** `INTELLIGENCE-ALLOCATION-MEMO.md`
  already covers this exhaustively, gated on measurement + Phase-4/5. Re-listing it here is redundant.
  **Verdict:** MERGE/REMOVE from this proposal; defer to the memo's own gating.

**Tally:** KEEP 5 (P0-BENCH, ARCH-STATE, VAL-AUTHZ, DISC-VARIANT, DISC-SPEC) · KEEP-partial/v0 2 (P0-TEL-TOOL,
EFF-SCHED-v0) · DEFER 5 (VAL-COND, DISC-GRAPH, ARCH-PAR, EFF-SCAN, LEARN-SIG) · MERGE 3 (ARCH-DISTILL→ARCH-STATE,
EFF-ALLOC→memo, P0-TEL-LLM→spike) · REJECT 1 partial (LEARN-KG graph) · ALREADY-PLANNED 1 (VAL-DIFF).

---

## 5. Token / Context Audit

**The key correction (OBSERVED):** in OpenCode, each subagent has its own context window. recon-agent's
katana dump, scan-agent's nuclei output — these live in *those* subagents' contexts and are returned to
HuntBrain as summarized markdown. HuntBrain does **not** carry raw tool dumps. So:

- The measured ~29.5K scoped HuntBrain context is dominated by **system prompt + agent instructions + MCP
  schema for HuntBrain's own allowlist**, not by raw recon/scan output.
- **ARCH-STATE/DISTILL do not meaningfully shrink that ~29.5K.** Their real context effect is (a) *within*
  recon/scan subagents' poll loops (full stdout returned each done-poll via `job_runtime`), and (b) HuntBrain
  carrying returned phase summaries across the 6-phase loop. Both are real but modest, and (a) is bounded by
  subagent isolation already.
- **Adding case-mcp to recon/scan agents (needed for ARCH-STATE) *adds* schema tokens to them.** The net could
  be negative for those agents' contexts.

**Correct metric (unchanged from proposal, reaffirmed):** `Σ(severity_weight × validated_unique_finding) /
total_cost`, `total_cost = LLM tokens + HTTP + wall-clock`. **But** — and this is the audit's addition —
**the LLM-token term is not currently measurable from inside HuntMCP.** Until P0-TEL-LLM (OpenCode session
usage) exists, only the HTTP/tool/wall-clock terms are real. Any "token efficiency" claim before then is
**SPECULATIVE**.

**Does any proposal actually reduce uncached tokens?** With ~99.6% continued-turn cache-read, the marginal
token cost is dominated by *new* output/tool-results per turn, not the cached prompt. So the highest-value
token lever is **fewer/short­er tool-result round-trips and fewer wasted experiments** (EFF-SCHED-v0), not
restructuring the cached prompt. This inverts the proposal's emphasis: **EFF-SCHED-v0 > ARCH-STATE** on pure
token grounds.

**Conclusion:** do not reward ARCH-STATE for token savings. Reward it for reliability/provenance. Reward
EFF-SCHED-v0 for cutting wasted round-trips. Keep the token *claim* out of the headline until P0-TEL-LLM lands.

---

## 6. Security-Capability Audit (worst-case regression per optimization)

| Candidate | Worst-case regression | Blocker gate |
|---|---|---|
| P0-TEL-TOOL | None (measurement-only) | — |
| ARCH-STATE | Structured return drops a nuance the prose carried → missed lead | A/B must hold finding set constant; raw retained/recoverable |
| ARCH-DISTILL | Over-compression drops the one line that mattered (payload, header) | Keep raw; distill is additive, never lossy-only |
| VAL-AUTHZ | Bad oracle → false IDOR (FP) **or** missed multi-step authz (FN); mutation causes harm | Ground-truth-fetch oracle; idempotent default; human gate |
| DISC-VARIANT | State-changing variant probe causes harm; mislabels a variant as new finding | Same gates as VAL-AUTHZ; dedupe_check |
| DISC-GRAPH | Poisoned/hallucinated edge → wrong chain pursued, real chain missed; budget burned | Audit-cited edges only; budget cap; benchmark gate |
| LEARN-KG | Poisoned knowledge → systematic false prioritization across engagements | Audit-cited authoritative writes only; target text = untrusted |
| LEARN-SIG | Stale signature → skipped test → **missed high/critical** | Hints never skips; TTL + revalidate; oracle still fires |
| EFF-SCHED | Premature close of a promising hypothesis; easy-class bias | Severity floor; never hard-block novel angle; audit suppressions |
| EFF-SCAN | **Coverage regression → missed vuln** (the sharpest risk) | Hard per-class coverage floor; reject on any high/critical miss |
| EFF-ALLOC | Cheap model closes a high-severity path prematurely | Severity-gated min-effort floor (per memo) |

**Hard-blocker reaffirmed:** any change that misses a high/critical the baseline found = FAIL regardless of
savings. EFF-SCAN and LEARN-SIG carry this risk most directly and must be gated hardest.

---

## 7. Novelty / Prior-Art Audit

Re-checked; the proposal is mostly honest. Corrections:

- **DISC-GRAPH** was scored "HIGH novel." Downgrade to **novel *combination*, not novel idea** — attack-state
  graphs + MCTS/best-first are established (ShotFlex, VulnBot, classical-planning papers, RESEARCH-SUPPORTED).
  Only the CEM-signature-as-search-heuristic wiring is differentiated, and it's unproven.
- **LEARN-KG** "poison-resistant evidence-cited edges" was framed as the differentiator. It's a sound
  *engineering* invariant, not a novel research contribution; GraphRAG poisoning defenses are an open problem
  and HuntMCP would be applying a conservative provenance rule, not solving it. Do not claim novelty.
- **VAL-AUTHZ** correctly classified (existing technique, stronger application). AuthProbe/BACFuzz/RESTler are
  the right prior art. Fair.
- **DISC-VARIANT** — the strongest genuine differentiation claim, and it holds: variant-as-necessity-testing-
  byproduct is underexplored. Keep, but still say "to our knowledge," not "unseen."
- **LEARN-SIG** — correctly hedged as research-worthy-but-unclear. Fair.

Distinctions: *novel idea* — none, honestly. *Novel combination* — DISC-VARIANT, CEM-signature-guided
DISC-GRAPH, LEARN-SIG. *Novel application* — ARCH-STATE, VAL-AUTHZ. *Established engineering* — everything else.

---

## 8. Architectural Dependency Graph — Corrections

The proposal's linear chain (Telemetry → State → Distill → Validation → Discovery → Learning → Efficiency) is
**over-serialized and slightly mis-ordered.** Corrected DAG:

```
                 ┌────────────────────────────────────────────┐
                 │  Phase-1 CEM (existing) — must ship first   │
                 └────────────────────────────────────────────┘
                             │ (only DISC-VARIANT/VAL-COND/LEARN-SIG depend on it)
   ┌──────────────┬──────────┴───────────┬───────────────────────────┐
   ▼              ▼                       ▼                           ▼
P0-BENCH     P0-TEL-TOOL            VAL-AUTHZ (min ver)          EFF-SCHED-v0
(enabler,    (measurement,         (capability, has an          (better heuristic,
 gates all   independent of        existing baseline;           uses existing case
 efficiency  everything)           independent of telemetry)    state; independent)
 claims)          │                       │                           │
   │              │                       ▼                           │
   │              │                  DISC-SPEC (feeds authz/scan)      │
   │              ▼                       │                            │
   │        P0-TEL-LLM spike             ▼                            │
   │        (OpenCode session)     VAL-COND, DISC-VARIANT (post-CEM)  │
   │              │                       │                            │
   ▼              ▼                       ▼                            ▼
 ARCH-STATE (concurrency fix FIRST) ── enables ── ARCH-PAR, DISC-GRAPH(proto), LEARN-*
   │
   └── EFF-SCAN / EFF-ALLOC(memo) : gated on P0-BENCH floor + P0-TEL-LLM (LAST)
```

Key corrections:
- **P0-BENCH, P0-TEL-TOOL, VAL-AUTHZ(min), EFF-SCHED-v0 are independent and can proceed in parallel** — they
  do not form a chain. The proposal's "telemetry → state → …" implies a false serialization.
- **VAL-AUTHZ does not depend on telemetry** (it has its own planted-label benchmark). It should not wait
  behind the whole substrate tier.
- **ARCH-STATE has a hard prerequisite the proposal omitted: the case.db concurrency fix** (busy_timeout +
  optionally file_lock coverage). ARCH-PAR and any concurrent-writer design depend on that fix, not on
  ARCH-STATE's schema.
- **DISC-GRAPH and LEARN-* depend on P0-BENCH** (to justify themselves), not merely on their tier's position.
- **No circular dependencies found.** The main error is over-serialization and putting telemetry on the
  critical path of capability work it doesn't actually gate.

---

## 9. ARCH-STATE Deep Review (case store as state bus)

**Can `case_store` safely become the inter-agent state bus?** Partially, with fixes.

- **OBSERVED — Concurrency is the blocker.** `_get_conn` sets `PRAGMA journal_mode=WAL` and `foreign_keys=ON`
  but **no `busy_timeout`**. WAL allows concurrent readers + one writer; a second concurrent writer gets an
  immediate `SQLITE_BUSY`. `file_lock.py` guards budget/work/findings JSON but **not** `case.db`. So today,
  serial single-agent use is fine (current reality), but ARCH-PAR-style concurrent writers would error.
  **Fix before any multi-writer use:** add `PRAGMA busy_timeout` (watch-mcp already does this per the
  job_runtime docstring) and/or route case.db writes through `file_lock.locked()`.
- **Scalability — SQLite remains appropriate.** Engagement-scoped DBs are small (hundreds–low-thousands of
  rows). No need for anything heavier. **Keep SQLite.**
- **What belongs there:** hypotheses, findings, evidence (content-addressed), experiments, root causes,
  CEM records, and (new) an attack-state adjacency table. **What must NOT belong there:** raw multi-MB tool
  dumps (keep on disk, reference by path), secrets/tokens (redact first), and **anything target-derived treated
  as authoritative** without an audit-cited observation.
- **Provenance:** the XYZ.md §3 invariant (no edge without a real `audit_log` id) must extend to every
  state-bus write that could be influenced by target output. This is the poisoning defense.
- **Stale state:** engagement isolation already handles cross-target staleness; within an engagement, add
  `updated_at`-based staleness only if a resume path needs it. Don't over-build.
- **Does querying it reduce model context?** **Mostly no** (see §5) — subagents already isolate raw output.
  The honest benefit is **reliability, dedup, provenance, and post-compaction resume**, plus a *modest*
  reduction in HuntBrain's cross-phase summary carrying. **Do not sell it as a token win.**
- **Could the state bus become an indirection problem?** Yes if agents must round-trip to case-mcp for data
  they already have in context. Mitigation: write-through, read-on-resume — not read-for-every-decision.

**Verdict:** KEEP, but (1) fix concurrency first, (2) re-scope the benefit to reliability/provenance, (3) add
case-mcp to recon/scan only if the dedup/resume value outweighs their added schema tokens — measure it.

---

## 10. DISC-GRAPH Deep Review (attack-state graph + planner)

**Does an attack-state graph provide a substantial capability jump over the 15-template chainer?** Potentially,
but unproven, and the proposal reaches for too much planner.

- **OBSERVED — The template matcher is genuinely limited:** `analyze_chains` matches `required_findings` sets
  to detected classes; it cannot express "IDOR on /a + IDOR on /b share a root cause and compose into X," nor
  multi-step state, nor anything not pre-encoded in the 15 templates.
- **State representation (minimal viable):** nodes = {capabilities gained (e.g. "can read user-B object"),
  observed states, findings}; edges = {enables, depends-on} each citing an `audit_log` id; preconditions/
  postconditions as capability sets. This is a small adjacency table in case.db, not a graph database.
- **Search:** **best-first (greedy on severity×confidence) is almost certainly sufficient** for the branching
  factor of a single web target's finding set (tens, not millions, of nodes). **A\*** needs an admissible
  heuristic that doesn't exist here. **MCTS** is for large stochastic state spaces (ShotFlex's unknown-topology
  network pentest) — **overkill** for a finished finding set. **Beam search** is a reasonable middle if
  best-first tunnel-visions.
- **Risks:** graph poisoning (target text → fake capability node), branching blowup if capabilities are
  modeled too finely, repeated exploration, planner budget burn, and — most importantly — **complexity that
  never beats the template matcher on real targets.**
- **CEM integration** is the one differentiated angle: minimal-condition-set signatures as edge weights /
  precondition hints. But that presupposes CEM Phase 1 + signatures (Phase 4).

**Verdict:** DEFER to an **experimental prototype**, tightly scoped: SQLite adjacency + **best-first only**,
with a **hard gate: it must recover chains on P0-BENCH that the template matcher cannot, at no FP cost**, before
any richer planner (beam/MCTS) or dependency (networkx) is even considered. Do not adopt a planner because it
sounds advanced.

---

## 11. VAL-AUTHZ Deep Review (stateful authorization engine)

**Can it realistically beat current IDOR behavior?** Yes, and it has the cleanest measurable baseline of any
capability candidate.

- **OBSERVED — Current behavior:** `idor-mcp sweep_idor(url_template, object_ids, both-account creds)` fetches
  each id per account and classifies pairs (PROTECTED/LEAKED/AMBIGUOUS/DIFFERENT/OWNER_BASELINE_FAILED). This
  is a **single-request, single-endpoint** oracle already using a two-account design.
- **The real gap (RESEARCH-SUPPORTED, AuthProbe/BACFuzz):** (1) **multi-step workflows** — authz enforced at
  step 1, an id carried unvalidated into step 2; (2) a **ground-truth-fetch oracle** (compare cross-account
  response to the true owner's fetch, not just status/length); (3) **role/identity matrix** beyond two peers
  (unauth, low-priv, admin, tenant-B).
- **Smallest useful version (define this, build nothing else first):** extend the existing two-account sweep
  with (a) an explicit **owner-fetch comparison oracle** (already partially present via the DIFFERENT/LEAKED
  logic — strengthen it to fetch-and-compare), and (b) a **two-step replay** primitive: capture a short
  workflow as account A, replay step N with account B's identity while holding earlier steps, classify the
  same way. That alone captures the highest-value missed class.
- **Mutation safety:** default to read/GET-shaped probes; any state-changing step requires the UD-4 human gate.
  Reuse scope_guard on every request. Reuse the http primitive CEM will share (`http_probe.py`).
- **CEM interaction:** a confirmed multi-step authz finding hands CEM exactly the conditions it wants (identity,
  step-ordering, the carried id) — strong synergy, and it feeds `case_store.create_finding` directly.
- **FP/FN risks:** FP from length/status-only oracles (mitigated by owner-fetch compare); FN from missing the
  workflow capture (mitigated by spec/DISC-SPEC input). Both measurable on planted labels.

**Verdict:** KEEP as the **#1 capability bet**. It extends a tested tool, targets the documented human-advantage
class, and is benchmarkable with planted multi-step labels.

---

## 12. Learning / Knowledge Architecture Review (LEARN-KG, LEARN-SIG)

- **OBSERVED — Structure already exists.** `memory.db` is a **global** SQLite store (hunts/findings/chains)
  with `search_by_tech` cross-target lookup; `case.db` is per-engagement structured state; writeup RAG is
  vector search over technique knowledge; lessons is freeform markdown. The proposal's "fragmented, unstructured,
  build a knowledge architecture" is **half right**: it's fragmented and not fed back into prioritization, but
  it is **not** unstructured.
- **Is a knowledge *graph* necessary?** **No, not initially.** The value the proposal attributes to a graph
  (cross-referencing findings/techniques/signatures) is largely deliverable by **joining the existing SQLite
  stores + a shared vocabulary (vuln_class, endpoint, tech)**. A graph adds a poisoning surface (GragPoison
  ~98%, RESEARCH-SUPPORTED; defenses shown inadequate) for marginal early benefit.
- **Provenance/authoritative-vs-untrusted:** whatever the layer is, target-derived text must never write an
  authoritative fact; only audit-cited observations can. This is the same invariant everywhere.
- **Cross-engagement isolation:** note the mismatch — `memory.db` is **global** (cross-target by design), while
  `case.db` is **per-engagement isolated**. Any unification must respect that a per-engagement fact is not a
  global fact; leaking one target's state into another's prioritization is a correctness and possibly a
  scope-discipline problem.
- **LEARN-SIG:** the defensible research bet; keep as prototype, hints-not-skips, nondeterministic signatures
  non-cacheable, gated on Phase-4 signatures + transfer measurement.

**Verdict:** **REJECT graph infrastructure for now.** KEEP a minimal "cross-reference existing stores + feed a
prioritization signal" task (feeds EFF-SCHED). KEEP LEARN-SIG as an experimental prototype. Revisit a graph
only if SQLite cross-referencing provably hits a wall.

---

## 13. Telemetry Review (smallest sufficient schema)

Do not "add more telemetry." The **minimum** that enables the constrained objective:

- **Already present (OBSERVED):** `audit_log` line = {ts, tool, redacted args, returncode, duration_ms, block};
  `budget_guard` = {calls, by_tool}; `case_store.experiments` has an unused-ish `cost` INTEGER column and
  `finding_id`/`hypothesis_id` links.
- **Add to the tool layer (feasible, small):** per Tier-2 call — HTTP request count (where the tool exposes it)
  and a link from the call to the `experiment`/`finding` it advanced. Wall-clock is already `duration_ms`.
  This yields *tool-call yield* and *HTTP-per-finding* without a new subsystem — **extend `audit_log` +
  populate `experiments.cost`, do not build a new store.**
- **The hard part (RE-SCOPE, INFERRED):** LLM tokens/cost are **not visible to MCP subprocesses**. They live
  in OpenCode's session/provider usage. Getting them requires reading OpenCode session logs / provider usage
  APIs — a separate research spike (**P0-TEL-LLM**), not an `audit_log` edit. Until it exists, "token/cost per
  finding" is not computable and must not be claimed.
- **Validation outcomes / experiment comparison** already live in `case_store` (findings status, confidence,
  experiments). Join telemetry to those by `finding_id`.

**Verdict:** KEEP the tool-layer half as an `audit_log`/`case_store` extension (no new subsystem). Treat the
LLM-token half as a separate, honestly-flagged OpenCode-integration spike. **This is the audit's single most
important correction to the proposal's "telemetry first" framing.**

---

## 14. Dependency Review (external libraries)

| Library | Proposal's use | Audit verdict |
|---|---|---|
| pydantic | typed schemas | **OK** — already budgeted by XYZ.md; low risk |
| networkx | graph algorithms (DISC-GRAPH) | **DEFER** — do NOT adopt until best-first over SQLite adjacency is proven insufficient on P0-BENCH. Pure-Python, low risk, but unneeded at v0 |
| PDDL planner (pyperplan/unified-planning) | classical planning | **REJECT for now** — encoding attack state as PDDL is heavy; best-first suffices for the branching factor |
| scikit-learn / Bayesian libs | surrogate models (EFF-*) | **REJECT for now** — "confidence theater" without real data; closed-form info-gain first |
| openapi-core / graphql-core | DISC-SPEC parsing | **CONDITIONAL** — adopt only when DISC-SPEC is actually built; a hand-rolled parser may suffice for the common shapes |
| RL frameworks / graph-embeddings | — | **REJECT** — training infra HuntMCP shouldn't own; the proposal already rejects these |

**Principle upheld:** prototype hand-rolled first; adopt a dependency only when it's proven the bottleneck; never
add one to Phase-1 CEM. The proposal's "selective best-of-breed" is fine *as a philosophy* but the audit
tightens it to "prototype-gated best-of-breed."

---

## 15. Corrected Ranking

Scores: Sec(urity), Cap(ability), Eff(iciency), Res(earch value), Cmplx, Risk, Conf(idence in the assessment).

| Candidate | Sec | Cap | Eff | Res | Cmplx | Risk | Conf | Tier |
|---|---|---|---|---|---|---|---|---|
| P0-BENCH | HIGH | — | enabler | HIGH | MED | LOW | HIGH | **1** |
| VAL-AUTHZ (min) | HIGH | HIGH | — | MED | MED | MED | HIGH | **1** |
| P0-TEL-TOOL | MED | — | MED | MED | LOW | LOW | HIGH | **1** |
| EFF-SCHED-v0 | MED | MED | MED | LOW | LOW | LOW-MED | MED | **1** |
| DISC-VARIANT | MED | HIGH | — | HIGH | MED | MED | MED | **2** |
| ARCH-STATE (+concurrency fix) | MED | MED | LOW | MED | MED | MED | MED | **2** |
| DISC-SPEC | LOW | MED | — | LOW | MED | MED | MED | **2** |
| VAL-COND | MED | MED | — | MED | MED | MED | MED | **2** |
| LEARN (cross-ref, no graph) | MED | MED | LOW | MED | MED | MED | MED | **2** |
| P0-TEL-LLM spike | — | — | MED | MED | HIGH | LOW | LOW | **2** |
| DISC-GRAPH (best-first proto) | MED | HIGH | LOW | HIGH | HIGH | MED-HIGH | LOW | **3** |
| LEARN-SIG (proto) | MED | MED | MED | HIGH | HIGH | MED | LOW | **3** |
| ARCH-PAR | MED | MED | — | LOW | HIGH | MED | MED | **3** |
| EFF-SCAN | risk↓ | — | MED | LOW | HIGH | HIGH | MED | **3** |
| ARCH-DISTILL (standalone) | — | — | LOW | LOW | MED | MED | HIGH | **4 (merge)** |
| EFF-ALLOC (standalone) | — | — | MED | LOW | HIGH | MED | HIGH | **4 (memo)** |
| LEARN-KG (graph) | LOW | MED | LOW | MED | HIGH | HIGH | MED | **4 (reject graph)** |
| VAL-DIFF | LOW | — | — | MED | LOW | LOW | HIGH | **owned by XYZ.md** |

**Tier 1 (strongly recommended):** P0-BENCH, VAL-AUTHZ(min), P0-TEL-TOOL, EFF-SCHED-v0.
**Tier 2 (valuable, later):** DISC-VARIANT, ARCH-STATE(+fix), DISC-SPEC, VAL-COND, LEARN(cross-ref), P0-TEL-LLM.
**Tier 3 (experimental prototype only):** DISC-GRAPH(best-first), LEARN-SIG, ARCH-PAR, EFF-SCAN.
**Tier 4 (reject/merge):** ARCH-DISTILL→merge into ARCH-STATE; EFF-ALLOC→memo; LEARN-KG graph→reject.

---

## 16. Corrected Roadmap

Two **parallel tracks** (capability + measurement), not one serial chain. All subordinate to CEM Phase 1;
all research-only until authorized.

### Track M (measurement) — can start independently
- **M1 · P0-BENCH.** *Objective:* standing multi-class ground-truth range + frontier reference arm.
  *Scope:* additive scenarios only (no edits to existing CEM ground truth; benchmarks.md approval).
  *Dep:* none. *Gain:* makes every later claim provable. *Risk:* low. *Benchmark:* self-consistency of labels.
  *Rollback:* additive/removable. *Exit:* frontier baseline + planted labels reproducible per benchmarks.md.
- **M2 · P0-TEL-TOOL.** *Objective:* HTTP/tool/wall-clock yield linked to findings. *Scope:* extend
  `audit_log` + populate `experiments.cost`/`finding_id`; **no new subsystem.** *Dep:* none. *Gain:* real
  tool-cost-per-finding. *Risk:* low. *Exit:* reconciled cost/yield report from existing data.
- **M3 · P0-TEL-LLM (spike).** *Objective:* read LLM token/cost from OpenCode session usage. *Scope:* research
  spike; may conclude "not cleanly available." *Dep:* none. *Exit:* documented feasibility + a data path or a
  clear "not feasible."

### Track C (capability) — can start independently of M
- **C1 · VAL-AUTHZ (min ver).** *Objective:* multi-step + owner-fetch-oracle authz differential.
  *Scope:* extend `idor-mcp`; two-step replay + owner-compare oracle; idempotent default. *Dep:* (benefits from
  DISC-SPEC + M1). *Gain:* the human-advantage class. *Risk:* med (mutation — gated). *Benchmark:* planted
  multi-step authz labels. *Rollback:* flag off → sweep. *Exit:* recovers multi-step authz the sweep misses,
  zero new FP.
- **C2 · EFF-SCHED-v0.** *Objective:* better-than-trivial next-action using existing case state.
  *Scope:* upgrade `suggest_next_action` (novelty + severity + in-flight), no ML, no new deps. *Dep:* none.
  *Gain:* fewer wasted round-trips (token + tool). *Risk:* low-med (never hard-block novel). *Exit:* fewer
  experiments-per-finding on M1 at equal recall.
- **C3 · DISC-SPEC.** *Objective:* OpenAPI/GraphQL surface into the endpoint model. *Dep:* none. *Gain:* shadow
  endpoints, feeds C1. *Exit:* endpoints recovered beyond crawl.

### Then (post-CEM-Phase-1, gated on M1)
- **P2 · ARCH-STATE (+concurrency fix first)** → reliability/provenance; **P3 · DISC-VARIANT** (rides CEM) →
  variants; **P4 · VAL-COND**; **P5 · LEARN cross-ref** (no graph) → feeds C2.

### Experimental (Tier 3, gated on M1 proving them)
- **X1 · DISC-GRAPH best-first prototype** (must beat template matcher on M1); **X2 · LEARN-SIG** (transfer
  measured, hints-not-skips); **X3 · ARCH-PAR** (after concurrency fix); **X4 · EFF-SCAN** (per-class floor
  enforced).

### Deferred to existing memo
- **EFF-ALLOC** — owned by INTELLIGENCE-ALLOCATION-MEMO; do not duplicate.

---

## 17. Top 3–5 Bets (if unlimited time, maximize capability)

Chosen on evidence + architecture + security impact, not hype:

1. **P0-BENCH (the ground-truth range).** Unglamorous, but *nothing else is provable without it*, and the
   project's own rules demand measurable, non-regressing capability. It is the highest-leverage investment
   because it converts every other bet from opinion into evidence. **Highest confidence.**
2. **VAL-AUTHZ (minimal multi-step + owner-fetch oracle).** The clearest capability gap with the cleanest
   existing baseline (`idor-mcp`), targeting the exact class the literature says humans still win. Extends a
   tested tool, feeds CEM, benchmarkable. **The capability bet I'd make first.**
3. **DISC-VARIANT.** The most genuinely differentiated idea, and cheap because it rides CEM's existing
   machinery — variants fall out of necessity testing. High research value, low marginal complexity. **The moat
   widener.**
4. **EFF-SCHED-v0 (honest heuristic, no ML).** The real token/tool-cost lever given 99.6% cache-read is fewer
   wasted round-trips, not prompt restructuring. Cheap, capability-neutral-to-positive, no dependencies.
5. **ARCH-STATE re-scoped to reliability/provenance (with the concurrency fix).** Bet on it for correctness,
   resume-after-compaction, and as the substrate the graph/scheduler eventually need — **not** for tokens.

Notably **not** in the top bets: DISC-GRAPH (prototype-gate it), LEARN-KG graph (reject), token-telemetry-as-
headline (re-scope), adaptive model routing (the memo already owns it).

---

## 18. Rejected / Downgraded Ideas

- **LEARN-KG knowledge *graph* infrastructure** — REJECTED for now. SQLite cross-referencing delivers most of
  the value; a graph adds a poisoning surface for little early benefit.
- **ARCH-DISTILL as a standalone efficiency phase** — REJECTED as separate; MERGE into ARCH-STATE, and correct
  the false "reuse disk persistence" claim.
- **EFF-ALLOC as a new candidate** — REJECTED as duplication of INTELLIGENCE-ALLOCATION-MEMO.
- **PDDL/MCTS/A\* planners** — REJECTED at v0; best-first over SQLite adjacency first.
- **scikit-learn/Bayesian surrogate scheduling** — REJECTED at v0; closed-form/heuristic first.
- **"Telemetry first" as a serial gate on capability work** — REJECTED; capability (VAL-AUTHZ) and measurement
  (P0-BENCH/TEL) run in parallel.
- **The token-efficiency headline for ARCH-STATE/DISTILL** — DOWNGRADED to reliability/provenance.

---

## 19. Open Research Questions

1. **Is LLM token/cost even recoverable from OpenCode session usage** in a way HuntMCP can join to `finding_id`?
   (Determines whether "cost per finding" is ever real. **Blocks the whole efficiency-headline.**)
2. **What is the true HuntBrain context breakdown** (system prompt vs agent instructions vs MCP schema vs
   carried summaries)? Measure it before claiming ARCH-STATE saves context.
3. **On P0-BENCH, does best-first over an attack-state graph recover any chain the 15 templates cannot** — and
   at what FP cost? (Go/no-go for DISC-GRAPH.)
4. **What fraction of real hunt experiments are redundant / re-derivable** (the memo's Q1) — measurable only
   after M2/M3.
5. **Do CEM signatures transfer across findings/targets** (the memo's Q2 / LEARN-SIG crux)?
6. **Does the multi-step authz oracle produce false positives** at a rate the owner-fetch comparison can hold
   below the baseline?
7. **Does giving recon/scan agents case-mcp cost more schema tokens than the dedup/resume value it returns?**
   (Decides ARCH-STATE's scope.)

---

## 20. Final Verdict

# REQUIRES RESEARCH REVISION

The proposal's **strategy is sound** (capability floor as hard constraint, CEM untouched, extend-don't-multiply,
measurement-gated efficiency, honest-ish novelty) and several candidates are genuinely strong (VAL-AUTHZ,
DISC-VARIANT, P0-BENCH). But it is **not ready for implementation** because:

- a load-bearing efficiency claim (token telemetry via `audit_log`) is **infeasible as written** (F1);
- the **context-savings headline is overstated** and partly contradicted by subagent isolation + the case.db
  schema-token tradeoff (F2, §5);
- a **real concurrency prerequisite** for the state-bus/parallel work was **missed** (F3);
- **ARCH-DISTILL rests on a false claim** about existing disk persistence (F4);
- **LEARN-KG over-reaches** into graph infrastructure that existing SQLite stores make unnecessary (F5);
- the **ordering over-serializes** capability behind measurement it doesn't depend on (§8).

None require *major architectural rework* — the substrate, safety model, and CEM thesis are intact, and the
fixes are re-scoping, re-ordering, and correcting four factual claims. Revise per §16 (two parallel tracks),
re-scope P0-TEL and LEARN-KG, add the case.db concurrency fix as an explicit prerequisite, and drop the token
headline until P0-TEL-LLM is proven feasible. Then it is implementation-ready per candidate.

---

### Appendix — Evidence tags for the load-bearing claims
- **OBSERVED (verified in repo):** audit_log fields (no tokens); chainer = 15 static templates; case_store WAL
  + foreign_keys + **no busy_timeout**; file_lock covers JSON not case.db; job_runtime unlinks raw output +
  returns full stdout on done-poll; recon/scan agents lack case-mcp in allowlists; memory.db is global +
  tech-searchable; per-agent MCP scoping shipped; idor-mcp sweep is single-request two-account.
- **RESEARCH-SUPPORTED:** human advantage on authz/attestation; AuthProbe/BACFuzz stateful authz; ShotFlex/
  VulnBot planning; GraphRAG poisoning (~98%).
- **INFERRED:** subagent context isolation implies HuntBrain carries summaries not raw dumps; adding case-mcp to
  lean agents re-adds schema tokens; EFF-SCHED-v0 feasible on existing case state.
- **SPECULATIVE (flagged, not relied on):** exact magnitude of any token saving before P0-TEL-LLM exists;
  whether CEM signatures transfer; whether a graph planner beats templates.
