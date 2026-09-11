# MASTER-ROADMAP-PROPOSAL.md — HuntMCP Post-Phase-1 Master Plan (PROPOSAL)

> **Status:** planning proposal for human review. **No code. No modification of [XYZ.md](XYZ.md),
> [ROADMAP.md](ROADMAP.md), or any architecture doc.** Nothing committed/pushed/merged.
> **Ground truth verified this session:** branch `claude/huntmcp-unknown-unknowns-2d59fe`, `main` HEAD `15435a8`
> ("CEM Phase 1: complete J1–O1 and freeze", PR #101). Working tree clean except the two research artifacts.
> **CEM Phase 1 is ACCEPTED AND FROZEN** (G1–G9 green via `scripts/verify-phase1.sh`, O1 security audit
> human-approved). This proposal treats Phase 1 as an untouchable trusted foundation.
>
> **What this is:** one coherent master plan synthesizing all three completed research streams
> ([XYZ.md](XYZ.md), [INTELLIGENCE-ALLOCATION-MEMO.md](INTELLIGENCE-ALLOCATION-MEMO.md),
> [UNKNOWN-UNKNOWN-RESEARCH.md](UNKNOWN-UNKNOWN-RESEARCH.md)) into a phased, benchmarked, dependency-ordered
> roadmap. **Not** a concatenation — every research item is classified and routed; nothing is dropped silently.
>
> **Canonical spec chain remains:** XYZ.md (thesis) → PHASE1-PLAN / PHASE1-EXECUTION-PLAN (Phase-1, frozen) →
> this proposal (post-Phase-1 synthesis, pending approval). This document does **not** supersede the thesis; it
> refines the *sequence* of the future phases XYZ deliberately left high-level, and asks for the human decisions
> in §16 before anything here is locked.
>
> **Revision — Gap-Closure Pass (2026-09-11):** this version closed 14 independent-review findings without
> dropping prior content. Key additions: **P2-E1 hunt postmortem** (explicit WP, replay≠postmortem);
> **P5-T1 CEM-signature-transfer** track + **P5-A0 STOP/GO** gate (P5 is now an evidence-gated program, C≠D
> preserved); **§9.1** verification-evidence-chain + test taxonomy; **§9.2** per-WP benchmark register; **§10.1**
> adversarial-test matrix; **§11.1** memo Q1–Q8 → experiment mapping; **§15.1** dependency/positioning check;
> two new traceability columns (runtime verification, sec-audit); a terminology correction ("substrate exists" ≠
> "capabilities exist"; evidence content-addressing present vs CEM per-trial hashing unbuilt); and honest-language
> fixes (no "self-improving"/"fully autonomous"). Phase 1 remains frozen and untouched.

---

## 1. EXECUTIVE SYNTHESIS

HuntMCP has a frozen, best-in-class **proof engine** (CEM) and broad tooling, but its post-Phase-1 direction is
described by three research streams that were written independently and have never been reconciled:

- **XYZ.md** says: match discovery breadth (Phase 2), then wire CEM into hunting (Phase 3), then use causal
  signatures for variants (Phase 4), then continuous learning + allocation (Phase 5). *Discovery-first.*
- **INTELLIGENCE-ALLOCATION-MEMO** says: do **not** build a router now; the only defensible novelty is the
  CEM→amortization reuse loop; start **passive measurement early**, decide **active allocation late**, under a
  hard security-quality floor. *Measure-first.*
- **UNKNOWN-UNKNOWN-RESEARCH** says: the leverage is in the **reasoning layer** (application-invariant model,
  hypothesis resurrection, info-gain experiment selection, negative knowledge, capability-utilization
  introspection, and a schema-property-testing→CEM composition), plus a **live security gap** (tool-output
  injection) and reliability gaps. *Reasoning-first, with cheap foundation wins.*

**The synthesis:** these are not competitors; they have a **dependency order**. Almost everything valuable in the
memo (allocation) and the unknown-unknown research (info-gain selection, negative knowledge, the
allocation-quality floor, staleness detection) **depends on instrumentation that does not yet exist** — passive
cost/quality telemetry, experiment lineage, and capability-utilization signal. The memo itself says "measure
early, decide late." And the most ambitious reasoning item (the invariant model) is, by the unknown-unknown
research's own adversarial pass (V.4), the **least tractable** and must be de-risked by a shallow prototype
first.

Therefore the recommended ordering is **Option C (Hybrid): build the minimum reliability + instrumentation
foundation → amplify discovery through the CEM composition (the cheap, high-leverage library unlock) → build the
ambitious application-reasoning + causal-signature layer on the now-measured base → only then introduce active
adaptive allocation and continuous learning.** This delivers real hunting improvement early (Phase 3), closes a
live security gap immediately (Phase 2), respects XYZ's fixed thesis (proof is the moat), and refuses premature
complexity (no router, no invariant-model over-investment, no graph DB) until the data justifies it.

Five phases, plus two cross-cutting tracks (Security/Reliability, Benchmark & Measurement) that begin in Phase 2
and run continuously.

---

## 2. CURRENT BASELINE / PHASE-1 FROZEN FOUNDATION (verified against code)

| Area | Reality (verified) | Treatment in this roadmap |
|---|---|---|
| **CEM proof engine** | `cem_engine.py` + `case-mcp` + `case_store.py`; determinism gate, replicated one-var interventions, verdict labels, MSC family, ddmin PoC minimization, Triager-Proof Bundle. **Post-validation only.** G1–G9 green, FROZEN. | **Frozen foundation.** Never reopened. All later phases *build on* it and must preserve its determinism/minimization/evidence/scope/budget/benchmark integrity. |
| Phase-1 acceptance methodology | 9 gates: G1 regression floor (≥637), G2 unit, G3 integration, G4 causal-benchmark vs protected `answer_key`, G5 **fccr==0**, G6 scope/rate/budget/audit, G7 performance-non-regression, G8 review-gate, G9 harness-isolation + integrity locks. `scripts/verify-phase1.sh`. | **Reused as the per-phase acceptance template** (§9). This proven loop — research/spec → impl → focused tests → independent audit → fixes → regression → gate → freeze — is the engineering discipline for every phase. |
| Known Phase-1 limitations | Content-addressed request/response evidence hashing (orig. C8/G1) **UNBUILT** (tracked, not a defect); O1 residuals (O1-1 RFC1918 pre-emption, O1-4 k≥3 floor) = LOW non-blocking. | Folded into Phase 2 Reliability track (not a Phase-1 reopening — additive follow-ups). |
| Orchestration | 6 static agents; sequential recon→scan→chain→exploit→report; "dynamic specialists" = LLM authors an `.md` at runtime (not mechanized). | Discovery breadth + parallel fan-out addressed in Phase 3; kept honest (not "more agents = more intelligence"). |
| Knowledge | Writeup RAG, `memory-mcp` (per-target blobs + tech recall), `lessons-mcp` (CONFIRMED/CLOSED-FP), 51 skills. | Extended with **structured negative knowledge** (P2) and cross-target technique induction (P5); RAG **not** enlarged for its own sake. |
| State/case | `case_store` hypotheses/evidence/lifecycle; `suggest_next_action` = "finish in flight" (deliberately no info-gain formula, pending instrumentation). | Info-gain selection built in P4 **after** P2 instrumentation exists. |
| Guards | `scope_guard`, `budget_guard`, `audit_log`, `dedupe_check`, `work_registry`, `engagement_paths`, `stuck_detector`, `tool_gaps`, `model_gateway`, `redact`, `content_scanner`, `job_runtime`. | Reused everywhere. `audit_log` becomes the substrate for P2 telemetry/utilization/lineage. |
| Batch-8 OPEN (ARCHITECTURE §1155) | Asset Graph, Coverage Engine, Skill Router, **tool-output-injection sanitization** — all unbuilt. | Routed: injection sanitization → **P2 Security (priority)**; Coverage Engine → P2/P4; Asset Graph → P3/P4; Skill Router → P5. |
| Go backend | Present, **not wired** to the agents (two independent implementations). | Out of scope for this roadmap except a note (§15 risks); not a hunting-capability lever. |

---

## 3. THREE-RESEARCH SYNTHESIS (what each stream contributes, reconciled)

**A — Autonomous discovery breadth (XYZ Phases 2–4).** The table-stakes axis: parallel-solver breadth, provider
selection, headless-browser/OOB harness, CEM-in-hunt integration, differentiation evidence, causal-signature
variant discovery. *Contribution:* the discovery and CEM-integration content of Phases 3–4. *Correction from the
other streams:* discovery must be **led by the CEM composition** (Opp-6), not by adding scanners, and must not
precede the instrumentation that lets us measure whether it regresses quality.

**B — Intelligence allocation (memo).** *Contribution:* the **measurement methodology** (constrained
optimization under a security-quality floor; total-cost accounting; A/B/C/D experiment; passive-measure-early),
the **policy/plumbing separation** (an `intelligence_allocation` module beside `model_gateway`), and the one
defensible novelty (**CEM→amortization**). *Correction:* it is explicitly **not** an early phase; passive
measurement is a Phase-2 foundation, active allocation is Phase 5, and "route by X" is largely prior art (reject
the "weak≈frontier" formulation A).

**C — Unknown-unknown reasoning + gaps.** *Contribution:* the reasoning-layer opportunities (Opp-1…Opp-6), the
live **security gap** (UU-7), reliability gaps (UU-8), the **long-horizon benchmark** need, and the adversarial
gating discipline (V.4). *Correction from B:* Opp-3 (info-gain) and Opp-4-as-routing-input need B's
instrumentation; from A: Opp-6 is the near-term win and Opp-1 must be gated behind a prototype.

**The unifying thread:** HuntMCP reasons in vuln-classes + confirmed findings; the value is in adding a thin
**application-rules + live-hypothesis** layer that *feeds the frozen proof engine*. CEM is the constant all three
streams orbit — discovery should feed it (Opp-6, XYZ P3), reasoning should generate hypotheses for it (Opp-1/2/3),
and allocation should amortize it (memo). That is the spine of the ordering below.

---

## 4. RESEARCH OVERLAP / DEDUPLICATION (explicit merges)

| Overlap | Streams | Merge decision |
|---|---|---|
| CEM→signature reuse **=** causal-signature variant discovery | memo §9 + XYZ Phase 4 | **Merged** into Phase 4: signatures are produced by XYZ-P4 variant work and *consumed* by the memo's amortization loop. One mechanism, two consumers. |
| Info-gain routing (memo) **vs** info-gain **experiment** selection (Opp-3) | memo §3 + UU-3 | **Distinct, both kept.** Memo = *which model* (P5 active allocation). Opp-3 = *which experiment* (P4). Same VOC theory, different decision surface. Traceability shows both. |
| Aleatoric/epistemic split (memo §9) **=** CEM determinism signal driving allocation | memo + Phase-1 CEM | **Merged** into P5: the frozen determinism gate is the input; the allocation policy is the consumer. No new CEM work. |
| Asset Graph (Batch 8) **vs** application-invariant model (Opp-1) | ARCHITECTURE + UU-1 | **Layered, not duplicated.** Asset Graph = hosts/endpoints (P3 recon substrate). Invariant model = semantic actor/object/state/invariant (P4), built *on top of* the asset graph + HTTP corpus. |
| Coverage Engine (Batch 8) **vs** hunt self-evaluation (UU) **vs** long-horizon benchmark | ARCHITECTURE + UU + XYZ P5 | **Merged** into the Benchmark & Measurement track: coverage is one dimension of the self-evaluation/benchmark substrate started in P2, expanded in P4. |
| Negative knowledge (Opp-4) **vs** Skill Router (Batch 8) **vs** dedupe/stuck_detector | UU-4 + ARCHITECTURE + existing | **Merged:** Opp-4 negative-knowledge store (P2) becomes a *deprioritization input* to the Skill Router (P5); `stuck_detector`/`dedupe` are raw signal sources for it. |
| Schemathesis→CEM (Opp-6) **=** on-ramp to invariant model (Opp-1) for the API subset | UU-6 + UU-1 | **Sequenced:** Opp-6 (P3) delivers the API slice off-the-shelf and de-risks Opp-1 (P4); a schema *is* a partial invariant spec. |
| Structural differentiation evidence (XYZ §2.6) **=** dedupe against disclosed reports | XYZ + `disclosed_reports.py` | **Merged** into Phase 3 CEM-in-hunt (XYZ already scopes it Phase 3+). |
| Self-expanding toolkit (ARCHITECTURE aspirational) **vs** bounded `tool_gaps.py` (done) | ARCHITECTURE + code | **Deferred:** full autonomous form stays human-in-loop (safety); `tool_gaps` recurrence signal feeds P5 build decisions. |

---

## 5. ORDERING ANALYSIS — OPTION A vs B vs C

**Decision criteria (weighted for this project):** dependency-correctness, measurable benefit, implementation
risk, benchmarkability, CEM synergy, security, early useful delivery, avoidance of premature complexity.

| Criterion | A — Discovery-first | B — Reasoning-first | **C — Hybrid (foundation→discovery→reasoning→allocation)** |
|---|---|---|---|
| Dependency-correctness | ✗ Allocation & info-gain need instrumentation A doesn't build first | ✗ Invariant model needs a corpus + instrumentation to not emit garbage | ✅ Instrumentation/reliability first unblocks everything downstream |
| Measurable benefit early | ◐ More scanning ≠ measured quality gain | ✗ Highest-risk item first, no near-term hunting delivery | ✅ Opp-6 + security fix deliver measurable wins in P2–P3 |
| Implementation risk | ◐ "more scanners" anti-pattern | ✗ Builds the least-tractable thing first (V.4) | ✅ Cheap/certain items first; risky items gated by prototypes |
| Benchmarkability | ◐ discovery recall only | ◐ needs long-horizon benchmark that doesn't exist yet | ✅ WFC/WFD ready for P3; long-horizon benchmark built in P4 before it's needed |
| CEM synergy | ◐ feeds CEM but doesn't leverage the moat | ✅ makes CEM a discovery engine | ✅ Opp-6 makes CEM discovery→proof loop early; Opp-1 deepens it later |
| Security | ✗ leaves UU-7 live-gap unaddressed while adding surface | ✗ same | ✅ UU-7 remediated in P2 before new surface is added |
| Early useful delivery | ✅ competitive breadth | ✗ | ✅ |
| Avoids premature complexity | ◐ | ✗ | ✅ explicitly defers router + invariant over-investment |

**Recommendation: Option C.** It is *not* chosen for innovativeness — it is the only ordering whose dependencies
resolve (measurement before allocation; corpus + prototype before invariant model; security before new surface),
that delivers measurable hunting value early (Opp-6), and that honors XYZ's fixed thesis (CEM is the moat; every
phase feeds it). Option A is XYZ's literal sequence and remains viable if the human rejects inserting a
foundation phase — see §16 Decision 1. Option B is rejected as highest-risk-first.

**Relationship to XYZ's fixed sequence:** C is a *superset/refinement*, not a contradiction. XYZ P2 (breadth) and
P3 (CEM-in-hunt) merge into Master **P3**; XYZ P4 (variants) → Master **P4**; XYZ P5 (uncertainty/learning/
allocation/self-expansion) → Master **P5**. The single genuine change is **inserting Master P2 (Foundation &
Reliability) before breadth** — the one item requiring explicit approval (§16).

---

## 6. SMALL-LIBRARY / COMPOSITION ANALYSIS

| Candidate | Type | Verdict | Rationale |
|---|---|---|---|
| **`schemathesis`** (+ `hypothesis` core) | Useful library — **disproportionate unlock** | **Adopt (P3), pending dependency-budget sign-off** | Off-the-shelf *stateful* property falsifier over OpenAPI/GraphQL schemas recon already finds; every hit feeds the frozen CEM for proof. Reaches business-logic/API bugs the class-driven pipeline structurally can't. Benchmarkable on WFC/WFD. The novelty is the *composition* (discovery→CEM), not the fuzzer. |
| `RESTler` | Heavy dependency | **Optional only** | Heavier stateful REST fuzzer; keep behind a flag, not a required dep. `schemathesis` covers the near-term need at lower cost. |
| `AALpy` (active automata learning) | Research-only dependency | **Gated (P4)** | Only if Opp-1's *shallow heuristic* invariant prototype proves out first (V.4). Do not add speculatively. |
| `networkx` / graph DB (Neo4j etc.) | Unnecessary dependency (at this scale) | **Reject** | XYZ already established SQLite tables suffice; RedAmon's Neo4j is not required to model invariants at HuntMCP's scale. |
| `pydantic` | Useful (already available) | Adopt for typed schemas in new modules where dataclasses are insufficient | Phase 1 deliberately used stdlib dataclasses; new non-hot-path schemas may use `pydantic` if it clears review. |
| `pandas` | Convenience only | **Optional** | For offline utilization/telemetry reports (P2) only; weigh vs dependency budget; stdlib acceptable. |
| RL/ML training frameworks | Heavy, no payoff | **Reject** | No data, no measurable benefit vs cost; the memo already rejects learned-router training for now. |

**Principle:** adopt a dependency only when it unlocks a benchmarkable capability that would be hard/unreliable to
reproduce with ordinary prompting (schemathesis: stateful sequence generation + shrinking). Never add for novelty.

---

## 7. RECOMMENDED MASTER ROADMAP (overview)

```
Phase 1 — CEM proof engine .......................... FROZEN (do not reopen)
   │
Phase 2 — Foundation & Reliability .................. instrumentation + negative knowledge + SECURITY track
   │        (unblocks measurement; closes the live injection gap; near-free wins)
   ▼
Phase 3 — Discovery amplification via composition .... Opp-6 (schemathesis→CEM) + XBOW breadth + CEM-in-hunt
   │        (first measurable hunting-capability gain; XYZ P2+P3)
   ▼
Phase 4 — Application reasoning & causal signatures ... invariant model (gated) + variants + hypothesis
   │        resurrection + info-gain experiment selection + long-horizon benchmark (XYZ P4 + Opp-1/2/3)
   ▼
Phase 5 — Adaptive allocation & continuous learning .. active allocation (A/B/C/D) + CEM amortization +
            cross-target learning + continuous hunting + gated self-expansion (XYZ P5 + memo active)

Cross-cutting tracks (start P2, run continuously):
   • Security & Reliability track   • Benchmark & Measurement track   • Passive→Active allocation split
```

---

## 8. DETAILED PHASES

Each phase uses the Phase-1 engineering loop and the G-gate template (§9). Work packages are intentionally small.

---

### PHASE 2 — Foundation & Reliability  *(NEW glue; not in XYZ — requires §16 Decision 1)*

1. **Objective.** Build the minimum measurement + reliability substrate that every later phase depends on, and
   remediate the one live security gap — with **zero** change to Phase-1 behavior or the hot path.
2. **Why it exists.** Allocation (memo), info-gain selection (Opp-3), negative-knowledge-as-routing (Opp-4), and
   staleness detection all require telemetry that does not exist; the memo explicitly says "measure early." A live
   prompt-injection surface (UU-7) should not wait behind AI features.
3. **Capabilities delivered.** Tool-output-injection boundary; Passive cost/quality telemetry; deterministic
   experiment lineage/replay; capability-utilization observability; structured negative-knowledge store; **hunt
   postmortem/self-evaluation (analysis-only)**; the Phase-1 reliability follow-ups.
4. **Research basis.** UU-7 (security); memo §11–12 (passive measurement, decision-features); UU-4 (Opp-4),
   UU-5 (Opp-5), UU-8; **UNKNOWN-UNKNOWN "hunt postmortem/self-evaluation" IMPORTANT GAP (Part III/§VIII-6)**;
   ARCHITECTURE Batch-8 (injection sanitization, Coverage-Engine seed).
5. **Dependencies.** Phase 1 (frozen) + existing **substrate** `audit_log`, `case_store`, `stuck_detector`,
   `tool_gaps`, `dedupe_check`.
6. **What must already exist vs what is NEW (terminology correction).** The *substrate* listed in (5) exists.
   **None of the P2 capabilities exist** — they are all new modules built on that substrate. "Low-risk" here
   means *the raw signal already exists to build on and the work is offline/read-only*, **not** that the
   capabilities are already present. Specifically: **evidence *bytes* are already content-addressed** (SHA-256 in
   `case_store.add_evidence`), but the CEM per-trial request/response **content-hash population + bundle
   `audit_trail` reconstruction is UNBUILT** (the `cem_trials.request_evidence_hash`/`response_evidence_hash`
   *columns exist* but the capability to rebuild exact bytes from a bundle does not — the tracked Phase-1 C8/G1
   limitation). P2-R1 closes that specific capability; it does not "add content-addressing," which is already
   present.
7. **Internal scope ordering (gated, independently testable).** **Security (P2-S) → Measurement (P2-I) →
   Reliability (P2-R) → Knowledge/Introspection (P2-N, P2-E).** Security ships and is audited first (it is a live
   gap and adds no dependency); measurement must exist before introspection can consume it; postmortem (P2-E1)
   consumes telemetry (P2-I1), lineage (P2-I2), utilization (P2-I3), and negative knowledge (P2-N1), so it is
   last. Each sub-group is independently acceptance-gated; a failure in one does not block an earlier one.
8. **Work packages / scope.**

| WP | Deliverable | Scope | Reuses |
|---|---|---|---|
| **P2-S1** (Security, **priority #1**) | Tool-output injection **boundary** (not vague "sanitize") | See detailed spec below — attack model, boundary, mitigation, corpus, runtime proof, adversarial audit, acceptance | `content_scanner.py`, `redact.py`, scope-gate patterns |
| **P2-S2** (Security) | Phase-1 SSRF/reliability residuals | O1-1 (RFC1918 pre-emption), O1-4 (k≥3 floor) as LOW follow-ups; **no Phase-1 semantic change** | Phase-1 O1 code |
| **P2-I1** (Measurement) | Passive decision-feature + cost/quality telemetry | Log memo §6 decision features + per-stage tokens/HTTP/wall-clock, **measurement-only, no behavior change** | `audit_log` |
| **P2-I2** (Measurement) | Experiment lineage / **deterministic replay** | *Replay = reproduce what happened* (byte-level re-run to identical verdicts); lineage records per experiment | `audit_log`, content-addressed evidence |
| **P2-I3** (Measurement) | Capability-utilization report (Opp-5) | Offline mine of `audit_log`+inventory → UNDERUSED/MISUSED/OVERUSED/GAP per capability; eligibility signature per tool | `audit_log`, `tool_gaps` |
| **P2-R1** (Reliability) | CEM per-trial evidence-hash population + bundle `audit_trail` | Populate the existing `cem_trials` hash columns + rebuildable bundle audit trail (the tracked C8/G1 limitation) — **additive, no Phase-1 semantic change** | `case_store` evidence store |
| **P2-N1** (Knowledge) | Structured negative-knowledge store (Opp-4) | `(technique/tool, context-signature) → outcome tally`; **hints-not-skips**; TTL; context includes target/stack version | `lessons_store`, `stuck_detector`, `audit_log` |
| **P2-E1** (Introspection) | **Hunt postmortem / self-evaluation (analysis-only)** | See detailed spec below — *Postmortem = evaluate what happened and what was missed/wrong/inefficient*; **read-only, never self-modifying** | P2-I1/I2/I3, P2-N1, `case_store`, `dedupe_check` |

**P2-S1 detailed spec (tool-output injection boundary):**
- **Attack model.** Target/tool output (HTTP bodies, error strings, file contents, MCP tool results, page DOM)
  contains text crafted to be read by the agent as *instructions* ("ignore previous scope", "mark this
  confirmed", "call X against Y") — a prompt-injection via untrusted data, contradicting the repo's own
  untrusted-data rule.
- **Affected boundary.** The point where any tool/target output is placed into agent-visible reasoning context
  (recon/scan/exploit output rendering; MCP tool return values; browser/page text).
- **Mitigation design.** A quarantine/boundary helper that (a) structurally frames tool output as *data*
  (delimited, labeled untrusted), (b) strips/neutralizes instruction-shaped control sequences per a documented
  policy, (c) never lets tool output alter scope/budget/verdict state directly. Not a blocklist of phrases — a
  boundary contract.
- **Regression corpus.** A versioned corpus of injection attempts embedded in realistic tool output (each with a
  planted "did the agent obey?" oracle).
- **Runtime proof.** Drive a real fixture hunt whose fixture *target* serves injection payloads; observe that no
  payload changes agent behavior/scope/verdict (end-to-end, not unit-only).
- **Independent adversarial audit.** A separate adversarial pass attempts boundary bypass (encoding, nesting,
  multi-turn) against the corpus + fixture.
- **Acceptance criterion.** 0/N corpus payloads cause an instruction-follow or state change; documented residuals
  are LOW and non-blocking; no Phase-1 control weakened.

**P2-E1 detailed spec (hunt postmortem — analysis/reporting only):**
- **Inputs.** `audit_log` (calls/outcomes), `case_store` (hypotheses/experiments/findings/status), `dedupe_check`
  (repeats), P2-N1 negative knowledge (ineffective tools), P2-I3 utilization (unused capabilities), P2-I2 lineage
  (what ran), P2-I1 telemetry (cost/stopping).
- **Runtime path.** An **offline, read-only** post-hunt analyzer (like a report generator); never mutates
  engagement state, never invokes tools, never self-modifies.
- **Output schema (structured JSON).** `explored[]`, `skipped[]`, `unused_capabilities[]`,
  `duplicate_experiments[]`, `abandoned_hypotheses[]` (open hypotheses never resolved), `ineffective_tools[]`,
  `tool_failures[]`, `reasoning_failures[]` (e.g. stuck-loop aborts), `missing_capabilities[]` (from `tool_gaps`),
  `unexplored_high_value_branches[]`, `premature_stops[]`, `over_investigations[]`, `missed_chain_opportunities[]`
  — each entry cites the `audit_log`/`case_store` evidence it was derived from.
- **v1 boundary.** The branches requiring richer reasoning — `missed_chain_opportunities`,
  `unexplored_high_value_branches`, `abandoned_hypotheses` quality — start as *heuristic flags from existing
  signals* (open chainer candidates, Asset-Graph endpoints never tested, hypotheses left non-terminal) and are
  **extended in P4** once the hypothesis lifecycle + invariant model exist (P4 consumer noted in §14).
- **Tests.** Unit per detector; a **planted-fixture** hunt recording with known skips/duplicates/abandonments →
  postmortem must recover them (precision/recall).
- **Benchmark.** Baseline = the recorded fixture hunt; ground truth = the planted skips/duplicates/etc. (kept
  evaluator-only so the analyzer cannot read its own answer key); success = recall of planted items at bounded
  false-flag rate; failure = a hallucinated missed-chain/branch with no citable evidence.
- **Independent verification.** Postmortem findings cross-checked against raw `audit_log`/`case_store` by an
  independent reader.
- **Acceptance gate.** Recall ≥ threshold on planted items; **every flag cites real evidence** (no evidence →
  rejected); read-only invariant proven (no state mutation during a run).
- **Failure modes.** Fuzzy "eligibility" → false `skipped`/`unused` (mitigate: eligibility signature per
  capability, shared with P2-I3); hallucinated missed chains (mitigate: evidence-required invariant, same as
  CEM's edge rule).

9. **Required tests (by type — code is not proof, §9).** *Unit* per detector/module; *integration* (telemetry +
   lineage + postmortem on a real fixture hunt); *end-to-end runtime* (P2-S1 injection fixture; replay
   determinism; postmortem planted-fixture recall); *adversarial* (P2-S1 boundary-bypass corpus; negative-knowledge
   cannot hard-skip); full regression ≥ Phase-1 baseline.
10. **Benchmark/evaluation.** (a) injection corpus — 0 payloads reach reasoning as instructions; (b) replay —
    identical verdicts on re-run; (c) utilization report flags a deliberately-disabled tool; (d) negative-knowledge
    redundant-call reduction **at zero high/critical recall loss** (hard constraint); (e) postmortem recall of
    planted skips/duplicates/abandonments at bounded false-flag rate.
11. **Security/adversarial audit.** P2-S1 dedicated adversarial pass (independent bypass attempts); telemetry/
    postmortem must not write secrets (redaction); negative-knowledge cannot hard-skip a test; postmortem is
    read-only (no state mutation).
12. **Independent verification.** Utilization, negative-knowledge, and **postmortem** outputs cross-checked against
    raw `audit_log`/`case_store` by an independent reader (evaluator-style separation).
13. **Acceptance gates (P2-G):** G1 regression floor; G2 unit; G3 integration (telemetry+lineage+postmortem on a
    real fixture hunt); G5′ **zero recall loss** from negative knowledge; G6 scope/budget/audit preserved; G7
    hot-path non-regression (telemetry/postmortem are offline — 0 hot-path cost); **G-SEC** injection corpus fully
    blocked + independent bypass audit clean; G8 review-gate; G9 no benchmark-artifact change; **postmortem
    read-only + evidence-cited invariant proven.**
14. **Freeze criteria.** All P2-G green; UU-7 audited clean by an independent pass; hot path provably unchanged;
    postmortem read-only proven.
15. **Non-goals.** No active allocation. No model routing. No reasoning/hypothesis-generation logic. No new
    discovery. **Postmortem does not act — it only reports** (no auto-retry, no self-modification).
16. **What comes next.** The telemetry + lineage + utilization + negative-knowledge + postmortem substrate is the
    precondition for P3 measurement and P4/P5 decisions; the postmortem is *extended* (not rebuilt) in P4.

---

### PHASE 3 — Discovery Amplification via Composition  *(= XYZ Phase 2 breadth + XYZ Phase 3 CEM-in-hunt, led by Opp-6)*

1. **Objective.** Materially increase discovery — especially of **stateful/business-logic API bugs** — by
   composing off-the-shelf falsifiers with the frozen CEM, and wire CEM to run automatically after each
   independently-validated finding. Add XBOW-class breadth *measured against the quality floor*.
2. **Why it exists.** This is the first phase that improves hunting outcomes users feel; Opp-6 leverages the CEM
   moat instead of only adding scanners.
3. **Capabilities delivered.** Schema-driven stateful property testing → CEM (Opp-6); automatic CEM-in-hunt
   (XYZ P3); structural differentiation evidence vs disclosed reports (XYZ §2.6); parallel-solver fan-out +
   broader autonomous surface (XYZ P2); an Asset Graph (hosts/endpoints) substrate.
4. **Research basis.** UU-6 (Opp-6) + WFC/WFD benchmark; XYZ Phase 2 + Phase 3 + §2.6; ARCHITECTURE parallel
   fan-out / Asset Graph.
5. **Dependencies.** Phase 1 (CEM), Phase 2 (telemetry so breadth's quality effect is measurable; utilization so
   we don't add redundant tools).
6. **What must already exist.** CEM tools; recon schema discovery; scope/budget/job_runtime; P2 telemetry.
7–8. **Work packages.**

| WP | Deliverable | Scope | Reuses |
|---|---|---|---|
| **P3-A1** | `schema-fuzz` MCP wrapper (Opp-6) | FastMCP wrapper around `schemathesis` (stateful, OpenAPI+GraphQL); consumes discovered schema; scope/budget/audit/job gated; non-idempotent-refused-by-default (Phase-1 policy) | `tool_resolver`, guards, `job_runtime` |
| **P3-A2** | Property→hypothesis→CEM adapter | Map each violated property (authz monotonicity, workflow order, schema conformance, idempotency) to a `case_store` hypothesis; CEM proves necessity/minimizes/gates determinism | `case-mcp`/CEM |
| **P3-B1** | Automatic CEM-in-hunt (XYZ P3) | Every independently-validated finding auto-flows into CEM post-validation; **must not slow the hot path when inactive** (G7) | CEM, `case_store` |
| **P3-B2** | Structural differentiation evidence (XYZ §2.6) | Compare finding's minimal condition set vs documented disclosed reports; labeled "not a proof of independence" | `disclosed_reports.py`, CEM MSC |
| **P3-C1** | Parallel-solver fan-out (XYZ P2) | Bounded concurrent specialist investigation; dedupe/work-registry-guarded; **not** "more agents for their own sake" | `work_registry`, existing agents |
| **P3-C2** | Asset Graph (Batch 8) | Hosts/endpoints/params/tech substrate feeding P4's invariant model | recon MCPs, `case_store` |

9. **Required tests.** Opp-6 on labelled schema fixtures (planted authz/workflow violations); adapter→CEM
   integration; CEM-in-hunt end-to-end; fan-out concurrency/dedupe; differentiation-evidence labelling.
10. **Benchmark/evaluation.** **WFC/WFD** dataset for the API subset: business-logic/authz violations
    *surfaced-and-CEM-confirmed* vs the current class-driven scan; discovery recall + false-positive rate +
    coverage vs a Phase-2-instrumented baseline; **hard floor: no high/critical the baseline finds may be lost.**
11. **Security/adversarial audit.** Opp-6 sends real stateful sequences — audit the non-idempotent gate; SSRF
    surface of schema-driven requests (reuse Phase-1 O1 outbound policy); confirm no scope escape via schema URLs.
12. **Independent verification.** Opp-6 findings independently re-confirmed by CEM's own oracle before counting.
13. **Acceptance gates (P3-G):** G1 regression; G2/G3 unit+integration; **G4′ discovery-recall vs floor**
    (no high/critical regression); G5 CEM fccr stays 0 on the extended flow; G6 scope/budget/audit; G7 hot-path
    non-regression for CEM-in-hunt; G-SEC schema-fuzz SSRF/non-idempotent audit; G8/G9.
14. **Freeze criteria.** WFC/WFD gain demonstrated at zero quality-floor violation; CEM integrity intact.
15. **Non-goals.** No semantic invariant *inference* (that's P4 — Opp-6 only checks properties derivable from the
    schema). No adaptive model allocation. No cross-target learning.
16. **What comes next.** The Asset Graph + the API-property experience de-risk and seed P4's invariant model.

---

### PHASE 4 — Application Reasoning & Causal Signatures  *(= XYZ Phase 4 + Opp-1/2/3, gated)*

1. **Objective.** Add the thin **application-rules + live-hypothesis** layer that lets HuntMCP find invariant
   violations that belong to no vuln class, persist and resurrect hypotheses, and choose the next experiment by
   expected information gain — all feeding the frozen CEM.
2. **Why it exists.** This is the market's weakest category (business logic/chains) and the highest-leverage
   reasoning gap; it turns CEM into a discovery engine (invariant falsification), not only a validator.
3. **Capabilities delivered.** Application invariant/state model (Opp-1, **gated**); causal-signature-driven
   variant discovery (XYZ P4); conditional hypothesis resurrection (Opp-2); info-gain experiment selection
   (Opp-3); human-escalation-as-info-value (UU-9); the **long-horizon benchmark** (built here, used here + P5).
4. **Research basis.** UU-1/2/3/9; XYZ Phase 4 + §2.7; V.1/V.4 (gating discipline); memo VOC framing (for Opp-3).
5. **Dependencies (per-WP, with failure-if-missing).**
   - P4-M0/M1 ← P3-C2 Asset Graph + P3-A schema experience + the HTTP corpus (*missing → no corpus to infer a
     model from → garbage invariants*).
   - P4-E1 ← **P2-I1 telemetry** (*missing → cannot calibrate P(distinguish)/cost → the policy is uncalibrated
     and unsafe*).
   - P4-H1 ← `watch-mcp` events + `case_store` (independent of the invariant model).
   - P4-X1 ← **CEM minimal-condition-set signatures from findings** (independent of the invariant model — X1 does
     **not** depend on P4-M0/M1).
6. **Gating & non-prerequisite guard (§10 scope control).** Gating chain: **P4-M0 (prototype) → P4-M1 (full
   invariant / optional AALpy).** A failed P4-M0 **blocks the expensive P4-M1 investment** and nothing else —
   H1/E1/X1 do not depend on M0, so a failed invariant prototype must **not** silently become a prerequisite for
   resurrection, info-gain, or variant work. Research-grade M1 may not become a hidden prerequisite for any other
   WP without its own evidence. Also **extends** P2-E1 postmortem (adds `missed_chain_opportunities`,
   `unexplored_high_value_branches`, richer `abandoned_hypotheses`) once the hypothesis lifecycle exists.
7–8. **Work packages.**

| WP | Deliverable | Scope | Gate |
|---|---|---|---|
| **P4-M0** | Opp-1 **shallow-prototype gate** | Heuristic actor→action→object→state→invariant model over the HTTP corpus (no AALpy); measured before any deeper investment | **Prototype must beat class-scan on a labelled invariant benchmark or P4-M1 is not authorized** (V.4) |
| **P4-M1** | Invariant model → CEM hypotheses | Promote surviving invariants to `case_store` hypotheses (falsify = find); optional `AALpy` only if M0 justifies it | depends on P4-M0 |
| **P4-H1** | Conditional hypothesis resurrection (Opp-2) | Dormant hypotheses record a machine-checkable blocking predicate; watch/recon/credential events flip predicates → re-queue; CEM-signature-keyed | TTL + cap |
| **P4-X1** | Causal-signature variant discovery (XYZ P4) | Use CEM minimal-condition-set signatures to generate/prioritize variants | preserves FP discipline |
| **P4-E1** | Info-gain experiment selection (Opp-3) | Score experiments by P(distinguish competing hypotheses)×severity÷cost; **orders, never hard-blocks**; aleatoric/epistemic split from CEM determinism | conservative policy |
| **P4-E2** | Human-escalation-as-info-value (UU-9) | Flag "human judgment high-value here" (ambiguous semantics, unresolved competing hypotheses, high-value chain) | cheap add to P4-E1 |
| **P4-BM** | Long-horizon hunting benchmark | Blind, independent (per `.claude/rules/benchmarks.md`): sustained investigation, multi-identity, business-logic, target-change, hypothesis persistence/resurrection, recovery, **quality of a correct no-finding conclusion** | protected ground truth |

9. **Required tests.** Invariant-inference precision/recall on labelled apps; resurrection conversion on a
   two-phase target; variant yield; experiment-selection vs "finish-in-flight" baseline; escalation-value
   measurement; long-horizon benchmark harness isolation.
10. **Benchmark/evaluation.** The P4-BM long-horizon benchmark + the Opp-1 labelled-invariant benchmark; metrics:
    invariant-violation recall vs class-scan, resurrection conversion rate, findings-per-experiment, variant
    yield, **false-invariant rate** (must be low — garbage-in for CEM is the key risk).
11. **Security/adversarial audit.** Invariants are hypotheses, never asserted facts; every one must pass CEM's
    determinism gate before any claim; resurrection cannot re-run non-idempotent perturbations without approval.
12. **Independent verification.** Long-horizon benchmark ground truth is evaluator-only; implementation cannot
    derive expected invariants (blindness rule).
13. **Acceptance gates (P4-G):** G1 regression; **G4″ invariant benchmark** (recall gain, low false-invariant
    rate); G5 CEM fccr stays 0; long-horizon benchmark harness integrity (G9-style locks); G6/G7/G8; **plus the
    P4-M0 prototype gate as a hard precondition for P4-M1.**
14. **Freeze criteria.** Invariant model demonstrates net recall gain at a controlled false-invariant rate;
    resurrection + info-gain show measured benefit; no CEM regression.
15. **Non-goals.** No active model allocation (P5). No self-modifying/self-expanding code execution. No graph DB.
    Do **not** reorganize the 51-skill spine around invariants yet (that's the V.1 architecture question — §16).
16. **What comes next.** Causal signatures + telemetry make the P5 allocation experiment attributable.

---

### PHASE 5 — Adaptive Allocation & Continuous Learning  *(= XYZ Phase 5 + memo active allocation)*

1. **Objective.** Introduce **active** adaptive intelligence allocation and continuous cross-target learning —
   only now, because only now is there measurable signal (P2 telemetry) and a real decision surface (P3/P4).
2. **Why it exists.** To reduce unnecessary expensive reasoning **subject to a hard security-quality floor** (the
   memo's constrained-optimization mandate), and to close the continuous-hunting loop.
3. **Capabilities delivered.** `intelligence_allocation` policy module (beside `model_gateway`, provider-agnostic
   tiers); CEM→amortization reuse loop; Skill Router (Batch 8, fed by Opp-4/Opp-5); cross-target technique
   induction (not target-specific contamination); continuous hunting (watch→resurrection); anti-anchoring
   counter-force to memory (UU-6, as an experiment); gated self-expanding-toolkit build decisions.
4. **Research basis.** Entire memo (active); XYZ Phase 5; UU-6; ARCHITECTURE Skill Router / self-expanding
   toolkit.
5. **Dependencies (per-WP, with failure-if-missing).** P5-A1/T1 ← P2-I1 telemetry + P2-I3 utilization + P4
   signatures (*missing → no attributable cost/quality data → the experiment is uninterpretable*); P5-A2/A3 ←
   the **P5-A0 GO decision** (see below); P5-K1 ← P2-N1 negatives + P2-I3 utilization; P5-C1 ← P4-H1 resurrection.
6. **P5 IS A GATED RESEARCH PROGRAM, NOT A BUILD ORDER.** Nothing in P5 is "automatically built." The policy is
   built **only if** the experiment shows measurable, floor-passing benefit:

   ```
   P5-A1  A/B/C/D experiment  ── and ──  P5-T1  signature-transfer experiment
                    │
        does CEM-assisted allocation (D) beat fixed-mixed (B) AND does transfer
        pass the quality floor with an acceptable false-reuse rate?
                    │
          NO ──►  DEFER/REJECT the policy (record why). STOP. No P5-A2/A3.
          YES ─►  P5-A2 policy module ──► P5-A3 CEM amortization (bounded by P5-T1 safe-transfer evidence)
   ```
   **Production allocation is authorized ONLY when the evidence passes the predefined quality floor.** A/B/C/D
   stay four distinct arms; **C (adaptive) and D (CEM-assisted adaptive) are never merged** — the C-vs-D ablation
   is the entire attribution of CEM's contribution.
7–8. **Work packages.**

| WP | Deliverable | Scope |
|---|---|---|
| **P5-A0** | **Decision gate (STOP/GO)** | Formal gate: A2/A3 authorized only if P5-A1 (D>B, floor held) **and** P5-T1 (safe transfer) pass; else defer/reject with recorded reason |
| **P5-A1** | A/B/C/D allocation experiment (memo §6) | **A** frontier-heavy reference · **B** fixed-mixed control · **C** adaptive · **D** CEM-assisted adaptive; held-out ground-truth targets; **C-vs-D kept separate** (answers memo question C) |
| **P5-T1** | **CEM signature-transfer experiment (Finding 4)** | Test transfer in 3 conditions: **(a)** same finding/same structure, **(b)** different finding/structurally similar, **(c)** different target/structurally similar. Metrics: safe-transfer rate, **false-reuse rate**, **missed-finding rate**, revalidation rate, staleness effect. **Security invariant: a stale/mismatched signature must NEVER become an authoritative skip; a false reuse causing a missed security test is a SECURITY FAILURE, not a cost metric.** |
| **P5-A2** | `intelligence_allocation` policy module *(gated by P5-A0 GO)* | Provider-agnostic tier+decision; reads CEM/negative-knowledge/utilization/budget; `model_gateway` unchanged (plumbing) |
| **P5-A3** | CEM→amortization reuse *(gated by P5-A0 GO + P5-T1 safe-transfer evidence)* | Reuse determinism-STABLE signatures as cheap-confirm **hints (never skips)**; revalidate on target change/TTL/inconclusive; never reuse a NONDETERMINISTIC/probabilistic signature |
| **P5-K1** | Skill Router (Batch 8) | Capability selection using Opp-4 negatives (deprioritize) + Opp-5 utilization; **hints, not hard blocks** |
| **P5-K2** | Cross-target technique induction | Generalized technique abstraction without target-specific assumption leakage; transfer **measured (P5-T1), not assumed** |
| **P5-K3** | Anti-anchoring experiment (UU-6) | Deliberately test what memory says is dead; measure memory net-value |
| **P5-C1** | Continuous **monitoring** loop | watch-diff events → hypothesis resurrection (P4-H1) → targeted re-investigation (not cron+scanner) |
| **P5-X1** | Self-expanding toolkit (**human-gated**) | `tool_gaps` recurrence → **human-in-loop** build decisions; full autonomous code-authoring-and-execution form remains **rejected** (safety) |

9. **Required tests (by type).** *Integration/e2e*: the A/B/C/D + transfer experiments run end-to-end on held-out
   ground-truth targets (runtime, not simulated). *Adversarial*: stale/mismatched signature cannot cause a skip;
   allocation cannot suppress a novel test; cheap-tier premature-closure guard. *Regression*: full suite.
10. **Benchmark/evaluation.** Severity-weighted validated yield per **total** cost (tokens + HTTP + wall-clock),
    under the memo's **hard floor** (high/critical recall ≥ baseline−ε; FP ≤ baseline; coverage ≥ baseline).
    Per-arm and per-vuln-class (catch class bias). Transfer metrics from P5-T1. Held-out targets; never tune on
    the eval set (report train/test split).
11. **Security/adversarial audit.** Allocation must never suppress a not-yet-confirmed novel test (dedupe/negatives
    lower priority, never hard-block); **stale/mismatched signature reuse cannot cause a missed finding
    (revalidation is mandatory)**; cheap-tier cannot close a high-severity-potential hypothesis without an
    escalation check; cross-target induction cannot leak target-specific assumptions.
12. **Independent verification.** Frontier cross-check pass on a sample to detect systematic misses from
    specialization; transfer verdicts independently re-confirmed by CEM's own oracle on the new finding.
13. **Acceptance gates (P5-G):** the memo's **failed-optimization policy** — **HARD FAIL if the adaptive arm
    misses any high/critical the frontier baseline found, or exceeds baseline FP**; soft/Pareto for medium/low.
    **P5-A0 STOP/GO** is itself a gate (no policy ships on a NO). Plus G1 regression, G5 CEM fccr==0 preserved, G6
    guards, G8/G9. P5-T1 gate: **false-reuse-causing-missed-test rate == 0** before any amortization ships.
14. **Freeze criteria.** A configuration on the Pareto frontier that satisfies the floor **and** a GO from P5-A0;
    C-vs-D ablation resolves whether the CEM-amortization twist is real; P5-T1 safe-transfer proven. **If the
    evidence says NO, the correct frozen outcome is "policy deferred/rejected, reason recorded" — that is a valid,
    successful completion of P5, not a failure.**
15. **Non-goals.** No "cheaper at any cost." No learned-router training. No self-modifying code execution. No
    policy shipped without a P5-A0 GO.
16. **What comes next.** Final product state (§17).

---

## 9. BENCHMARKS & ACCEPTANCE GATES (reused template)

The Phase-1 gate family is the template; each phase instantiates the relevant subset:

| Gate | Meaning | Applies |
|---|---|---|
| G1 | Full regression ≥ prior baseline, 0 failed | every phase |
| G2 | New-unit tests green | every phase |
| G3 | Integration end-to-end on a real fixture | every phase |
| G4 | Capability benchmark vs **protected** ground truth (recall/labels) | P3 (WFC/WFD), P4 (invariant + long-horizon) |
| G5 | **CEM false-causal-conclusion-rate stays 0** | P3–P5 (CEM integrity is non-negotiable) |
| G6 | Scope/rate/budget/audit preserved | every phase |
| G7 | Hot-path performance non-regression | P2 (telemetry), P3 (CEM-in-hunt) |
| G8 | Review-gate: no unreviewed deviation | every phase |
| G9 | Benchmark harness isolation + integrity locks (blind, evaluator-only ground truth) | P3–P5 |
| G-SEC | Adversarial/security audit for phases adding network/injection surface | P2 (injection), P3 (schema-fuzz SSRF) |
| Floor | memo hard floor: no high/critical loss, FP ≤ baseline, coverage ≥ baseline | P3, P5 |

**Benchmark discipline (rejected as evidence):** "looks smarter", more agents, more tools, bigger prompts/RAG,
benchmark gaming. **Preserve CEM benchmark integrity** — no later phase may weaken the frozen `answer_key`/
`scenarios` integrity locks or the fccr==0 gate.

### 9.1 Verification evidence chain (code is not proof)

Every major capability must show this chain before it counts as done — **code inspection, presence of a
class/function, unit tests alone, docs, or mocked success are NOT sufficient when real execution is feasible:**

```
implementation → actual runtime invocation → controlled fixture/target → expected oracle/ground truth
              → observed result → independent verification
```

Test-type taxonomy each phase must distinguish (do not collapse them):

| Type | What it proves | Example in this roadmap |
|---|---|---|
| Unit | module logic in isolation | postmortem detector logic; verdict rules |
| Integration | modules wired together | telemetry+lineage+postmortem on a fixture |
| **End-to-end runtime** | the real dispatch path a live agent uses | P2-S1 injection fixture hunt; P3 Opp-6 vs WFC/WFD; P5 A/B/C/D on held-out targets |
| Adversarial/security | controls hold under attack | boundary-bypass corpus; stale-signature-skip attempt |
| Benchmark evaluation | capability vs protected ground truth | invariant recall; FCCR; transfer rates |
| Independent verification | a separate reader/oracle confirms | evaluator-only cross-check of postmortem/transfer |

Note (repo precedent): Phase-1's own history shows two "verified live" claims that had only exercised logic, not
the real tool-call dispatch path — hence the **end-to-end runtime** row is mandatory, not optional.

### 9.2 Benchmark register (every non-trivial WP)

| WP | Baseline | Ground truth | Fixture/target | Success metric | Failure metric | Accept threshold | Regression | Isolation |
|---|---|---|---|---|---|---|---|---|
| P2-S1 injection | current (no boundary) | planted "did agent obey?" oracle | fixture target serving payloads | 0 obeyed | any obey / state change | 0/N + audit clean | corpus versioned | evaluator-only oracle |
| P2-I2 replay | non-replayable run | the recorded hunt itself | recorded fixture hunt | identical verdicts | any divergence | byte-identical verdicts | — | — |
| P2-I3 utilization | none | deliberately-disabled tool | recorded engagements | flags disabled tool | misses it | correct classification | — | cross-check vs audit_log |
| P2-N1 negatives | no negatives | labelled redundant-call set | recorded hunts | redundant-call reduction | any recall loss | reduction @ **0 high/crit loss** | recall floor | hints-not-skips proven |
| P2-E1 postmortem | none | planted skips/dups/abandonments | recorded fixture hunt | recall of planted items | hallucinated flag (no evidence) | recall ≥ threshold, every flag cited | — | evaluator-only answer key |
| P3 Opp-6 | class-driven scan | WFC/WFD + planted authz/workflow | schema fixtures + WFC/WFD | violations surfaced-and-CEM-confirmed | high/crit lost vs baseline | gain @ **0 floor violation** | discovery-recall floor | protected dataset |
| P4-M0/M1 invariant | class-scan | labelled invariant violations | planted-invariant apps | invariant-violation recall | false-invariant rate high | recall gain @ low false-invariant | recall floor | evaluator-only labels |
| P4-H1 resurrection | no resurrection | phase-2 resource appearance | two-phase target | resurrection→conversion | never resurrects | measured conversion | — | — |
| P4-BM long-horizon | frontier-heavy hunt | planted long-horizon truth | multi-phase target set | sustained/persistence/no-finding quality | premature stop / missed persistence | ≥ thresholds | — | blind, evaluator-only |
| P5-A1 allocation | A frontier-heavy | known findings incl. high/crit | held-out targets | severity-weighted yield/total-cost | any high/crit miss (D vs A) | floor held + D>B | per-class floor | train/test split |
| P5-T1 transfer | no reuse | 3 transfer conditions | same/similar/cross-target | safe-transfer rate | **false-reuse→missed test** | **missed-test rate == 0** | — | held-out |

No benchmark may be designed so the implementation can derive its own expected answer (blindness rule,
`.claude/rules/benchmarks.md`).

---

## 10. SECURITY & RELIABILITY TRACK (separate from AI features)

Real gaps get their own track and are **not** buried inside a research phase:

| Item | Type | Severity | Home | Note |
|---|---|---|---|---|
| **Tool-output injection sanitization (UU-7)** | Live security gap | **High priority** | **P2-S1 (front of queue)** | Target/tool output currently flows into agent reasoning as potential instructions; contradicts the repo's own untrusted-data rule. **May jump the queue independent of everything else — §16 Decision 5.** |
| SSRF residuals O1-1 / O1-4 | Reliability follow-up | LOW | P2-S2 | Additive; no Phase-1 semantic change |
| CEM per-trial evidence-hash population + bundle audit_trail | Reliability (evidence integrity) | tracked limitation | P2-R1 | Completes the Phase-1 C8/G1 deferral. **Note:** evidence *bytes* are already content-addressed (present); this adds the per-trial hash *population* + rebuildable audit trail (columns exist, capability doesn't) |
| Deterministic replay / lineage (UU-8) | Reliability | Med | P2-I2 | Debug failed runs; benchmark determinism |
| schema-fuzz SSRF / non-idempotent surface | New security surface | audited | P3 G-SEC | Reuse Phase-1 O1 outbound policy |
| Stale-CEM-signature reuse → missed test | Security (methodology) | design constraint | P5-T1/A3 | **A false reuse causing a missed test is a security failure**; missed-test rate must be 0 |
| Allocation suppressing novel tests | Security-of-methodology | design constraint | P5 | hints-not-blocks; revalidation |

### 10.1 Adversarial-test matrix (capabilities adding network/state/agent/memory/decision authority)

| Attack class | WPs it applies to | Adversarial test / control |
|---|---|---|
| Scope bypass | P3-A1 (schema-fuzz), P4/P5 senders | out-of-scope host in schema/URL → refused (reuse scope-gate) |
| SSRF / redirect escape | P3-A1, any new HTTP | reuse Phase-1 O1 outbound policy (scheme allowlist, cloud-metadata/link-local deny, no-redirect) |
| **Tool-output prompt injection** | P2-S1 (boundary), all output rendering | injection corpus + independent bypass audit → 0 obeyed |
| Non-idempotent action bypass | P3-A1 stateful sequences, P4-H1 resurrection | Phase-1 refuse-by-default + per-finding human exception |
| Budget bypass | every sender | `budget_guard.enforce` inline (Phase-1 pattern) |
| Audit-log bypass | every sender | `audit_log.log_call` per request; no silent path |
| Stale-memory abuse | P2-N1, P5-K2 | hints-not-skips; TTL; revalidation |
| Stale-CEM-signature reuse | P5-A3/T1 | never authoritative skip; missed-test rate == 0 |
| Cross-target contamination | P5-K2 induction, `engagement_paths` | isolation preserved; no target-specific leakage |
| Race / concurrency | P3-C1 fan-out, P5-C1 watch | job locks; work-registry; dedupe |
| Duplicate suppression of novel tests | P5-K1 router, dedupe | dedupe lowers priority, never hard-blocks a novel unconfirmed angle |
| Capability-routing blind spots | P5-K1 | periodic frontier cross-check on a sample |
| Cheap-tier premature closure | P5-A2 | severity-gated minimum-effort floor before a cheap tier may close |
| High/critical finding suppression | P5 overall | **hard-fail floor** — any high/crit miss vs frontier baseline rejects the config |

**Standing rule (all phases):** never weaken scope/budget/audit/determinism/evidence controls for a feature or a
benchmark score; preserve engagement isolation; treat all external content as untrusted data.

---

## 11. INTELLIGENCE ALLOCATION PLACEMENT

Per the memo, **split passive from active**:

- **Passive measurement → Phase 2** (P2-I1): decision features + total-cost accounting, measurement-only, no
  behavior change, no hot-path slowdown. Begins as soon as it's useful.
- **Active adaptive allocation → Phase 5** (P5-A1/A2/A3): only after (a) P2 provides calibrated signal, (b)
  P3/P4 create a real decision surface, and (c) the A/B/C/D experiment can attribute value.
- **Architecture preserved:** provider-agnostic policy module beside `model_gateway` (plumbing unchanged); CEM is
  a knowledge *source* the policy reads, never coupled to a provider; the aleatoric/epistemic determinism signal
  is the one genuinely CEM-sharpened lever.
- **Quality-floor framing preserved:** constrained optimization, hard fail on any high/critical miss.
- **Rejected:** building a router now; the "weak≈frontier" formulation A (irreducible capability gap).

### 11.1 Memo open-question → experiment mapping (none dropped)

Each memo §13 open question mapped to experiment → data → metric → threshold/decision rule → action. **No
question is silently dropped.**

| # | Memo open question | Experiment | Data required | Metric | Threshold / decision rule | Resulting action |
|---|---|---|---|---|---|---|
| Q1 | Redundant frontier reasoning rate | P5-A1 (A vs C/D) | P2-I1 per-stage frontier-call telemetry | % frontier calls re-derivable from prior signatures | if small → premise weak | small → **defer allocation**; large → proceed to policy |
| Q2 | CEM signature transfer rate | **P5-T1** (3 conditions) | signatures + new findings across findings/targets | safe-transfer / false-reuse / missed-finding rate | **missed-test rate must be 0** | 0 → allow amortization; >0 → reject reuse |
| Q3 | Aleatoric vs epistemic usefulness | P5-A1 ablation (determinism-aware vs not) | CEM determinism_status + escalation outcomes | escalation-avoided w/o quality loss | net benefit > 0 under floor | yes → use determinism signal in policy |
| Q4 | Uncertainty calibration in this domain | calibration study on P2 data | oracle-sparse outcome logs | calibration error (ECE-style) | usable calibration achievable | if not → **do not gate tests on uncertainty** |
| Q5 | Pre-reasoning severity estimation | P4-E1 pre/post comparison | hypothesis features + realized severity | pre-estimate vs realized correlation | usable before spend? | if only post → severity routing is circular → **drop it** |
| Q6 | Real cost split (tokens vs HTTP/tool/wall-clock) | P2-I1 measurement | total-cost telemetry | token % of total cost | is token routing material? | if tokens small → **prioritize HTTP/wall-clock levers, not token routing** |
| Q7 | CEM signature staleness half-life | P5-T1 + watch-driven revalidation | signatures over evolving targets | correctness decay over time | TTL from measured half-life | set revalidation TTL; never skip past it |
| Q8 | Exploit-chain degradation under adaptive allocation | P5-A1 with chain-depth in floor | attack-path depth + chain discovery per arm | chain discovery vs baseline | any chain-discovery regression | regression → **config infeasible** (floor violation) |

---

## 12. INNOVATION / LIBRARY DECISIONS (summary)

| Decision | Verdict | Phase |
|---|---|---|
| schemathesis→CEM composition (Opp-6) | **Adopt** (dep sign-off needed) | P3 |
| Application invariant model (Opp-1) | Adopt **gated by shallow prototype** | P4 |
| Hypothesis resurrection (Opp-2) | Adopt | P4 |
| Info-gain experiment selection (Opp-3) | Adopt (needs P2 telemetry) | P4 |
| Negative knowledge (Opp-4) | Adopt (cheap, first) | P2 |
| Capability-utilization observability (Opp-5) | Adopt (near-free) | P2 |
| CEM→amortization reuse | Adopt (gated on P4 signatures) | P5 |
| `AALpy` | Gated / optional | P4 |
| `RESTler` | Optional flag only | P3 |
| graph DB / `networkx` | **Reject** | — |
| RL/learned-router training | **Reject** | — |
| Bigger RAG / more static agents | **Reject** | — |

---

## 13. EXPLICIT DEFERRED / REJECTED IDEAS (with reasons — nothing vanishes)

**Deferred:**
- **Full autonomous self-expanding toolkit** — unreviewed agent-authored code run against live targets is a
  different risk category (ARCHITECTURE's own reasoning). Kept human-in-loop; `tool_gaps` recurrence → P5 build
  decisions.
- **`RESTler` / `AALpy`** — deferred/optional pending evidence the lighter path (schemathesis / heuristic
  invariants) is insufficient.
- **Active allocation** — deferred to P5 (no signal / decision surface earlier).
- **Reorganizing the 51-skill spine around invariants (V.1)** — deferred as an explicit architecture question
  (§16 Decision 6); P4 adds invariants *alongside*, not *instead of*, the skill spine.
- **Go backend ↔ agent wiring** — out of scope (not a hunting-capability lever); noted as a risk only.

**Rejected (with reason):**
- **"Weak≈frontier" routing (memo A)** — irreducible model-capability gap; likely false.
- **Digital twin (XYZ)** — already demoted in favor of CEM; do not resurrect.
- **Structural Causal Model / do-calculus** — XYZ explicitly rejected; CEM approximates actual causality
  empirically.
- **Graph database** — SQLite tables suffice at HuntMCP's scale (XYZ discipline); Neo4j-style is unnecessary.
- **RL/learned-router training** — no data, no measurable payoff vs cost.
- **"More agents / bigger RAG / more scanners" as a goal** — fails the anti-hype bar in all three research docs.

---

## 14. COMPLETE TRACEABILITY MATRIX (mandatory — every major research item)

Legend: **impl**=already implemented · **frozen**=Phase-1 · **planned**=in XYZ/ROADMAP · **merge** · **new** ·
**sec/rel** · **research** · **deferred** · **rejected**.

Terminal states: **implemented · frozen · planned · merged · new · research · security/reliability · deferred ·
rejected**. Columns now include **Runtime verification** (the §9.1 evidence chain — code alone never counts) and
**Sec-audit** (the §10.1 adversarial control). Every deferred/rejected item carries a reason.

### 14.1 From XYZ.md

| Research item | Class | Phase/WP | Depends on | Runtime verification | Benchmark | Sec-audit | Gate |
|---|---|---|---|---|---|---|---|
| CEM condition model / necessity / MSC / minimization / bundle | frozen | Phase 1 | — | e2e verify-phase1.sh (done) | CEM benchmark | O1 (done) | G1–G9 done |
| Determinism/confounder protocol | frozen | Phase 1 | — | e2e (done) | fccr==0 | O1 | G5 done |
| Observed causal-graph substrate (§3) | frozen | Phase 1 tables | — | unit+integration (done) | — | — | done |
| CEM per-trial evidence-hash population + audit_trail (C8/G1) | security/reliability (unbuilt; columns exist) | **P2-R1** | Phase 1 | evidence-rebuild e2e test | evidence-integrity | evidence tamper check | P2-G |
| Structural differentiation evidence (§2.6) | planned→merged | **P3-B2** | disclosed_reports, CEM | e2e vs disclosed set | dedupe precision | label-not-proof audit | P3-G |
| Variant discovery (§2.7) | planned | **P4-X1** | CEM signatures | e2e on planted variants | variant yield | FP discipline | P4-G |
| Phase 2 XBOW breadth | planned→merged | **P3-C1** | P2 telemetry | e2e on fixtures | discovery recall vs floor | scope/fan-out audit | P3-G4′ |
| Phase 3 CEM-in-hunt | planned→merged | **P3-B1** | CEM | e2e hunt→CEM | hot-path G7 | G6 preserved | P3-G |
| Phase 4 causal-signature variants | planned | **P4-X1** | P3 | e2e | variant yield | FP discipline | P4-G |
| Phase 5 uncertainty/coverage/learning/allocation/self-expansion | planned→split | **P4-E1 + P5** | P2/P4 | e2e experiments | long-horizon + A/B/C/D | §10.1 matrix | P4-G/P5-G |
| Digital twin | **rejected** | — | — | — | — | — | reason: XYZ demoted for CEM |
| SCM / do-calculus | **rejected** | — | — | — | — | — | reason: XYZ rejected; CEM approximates empirically |

### 14.2 From INTELLIGENCE-ALLOCATION-MEMO.md

| Research item | Class | Phase/WP | Depends on | Runtime verification | Benchmark | Sec-audit | Gate |
|---|---|---|---|---|---|---|---|
| Passive measurement instrumentation | new (foundation) | **P2-I1** | Phase 1 | e2e on fixture hunt (measurement-only) | telemetry present | no-secret-leak (redaction) | P2-G7 |
| CEM→amortization reuse loop (the twist) | research→merged | **P5-A3** (gated) | P2, P4, **P5-A0 GO + P5-T1** | e2e reuse on new finding, CEM re-confirms | C-vs-D ablation | stale-reuse→missed-test==0 | P5-G |
| Security-aware routing (severity/uncertainty/cost/difficulty) | research (mostly prior art) | **P5-A2** (gated) | P2 signal, P5-A0 | e2e held-out | A/B/C/D | suppress-novel-test / cheap-closure | P5 floor |
| Info-gain routing (which model) | research | **P5-A2** | P2, P5-A0 | e2e | A/B/C/D | as above | P5 |
| Policy/plumbing separation | architecture | **P5-A2** (beside model_gateway) | — | unit+integration | — | provider-agnostic audit | P5-G |
| Constrained-optimization objective + quality floor | methodology | **Benchmark track + P5** | — | e2e per-arm | severity-weighted yield/cost | hard-fail on high/crit miss | P5 floor |
| A/B/C/D baseline experiment | methodology | **P5-A1** | P4 signatures | the experiment (e2e held-out) | itself | frontier cross-check | P5-G |
| Aleatoric vs epistemic (CEM determinism → allocation) | merged | **P5-A2** (instrument P2) | Phase 1 CEM | e2e ablation (Q3) | escalation-avoided | — | P5 |
| Open questions Q1–Q8 | research | **§11.1 mapping** | P2 data | per-question experiment (§11.1) | per-question metric | Q2/Q7 security-framed | P5 |
| Failure modes/mitigations | design constraints | carried into P5 §10.1 | — | — | — | §10.1 matrix | P5-G |
| "Weak≈frontier" (formulation A) | **rejected** | — | — | — | — | — | reason: irreducible capability gap |
| Learned-router training | **rejected** | — | — | — | — | — | reason: no data, no payoff vs cost |

### 14.3 From UNKNOWN-UNKNOWN-RESEARCH.md

| Research item | Class | Phase/WP | Depends on | Runtime verification | Benchmark | Sec-audit | Gate |
|---|---|---|---|---|---|---|---|
| Opp-1 application invariant/state model (UU-1) | new (gated) | **P4-M0→M1** | P3 corpus/Asset Graph, P2 | prototype e2e on planted-invariant apps | labelled-invariant + long-horizon | invariants=hypotheses, CEM-gated | **P4-M0 prototype gate** |
| Opp-2 conditional hypothesis resurrection (UU-2) | new | **P4-H1** | watch-mcp, case_store | e2e two-phase target | resurrection conversion | non-idempotent-refuse on re-run | P4-G |
| Opp-3 info-gain experiment selection (UU-3) | gap | **P4-E1** | **P2-I1 telemetry** | e2e vs finish-in-flight | findings-per-experiment | orders-never-blocks | P4-G |
| Opp-4 structured negative knowledge (UU-4) | gap (cheap) | **P2-N1** | audit_log | e2e redundant-call reduction | reduction @ 0 recall loss | hints-not-skips proven | P2-G5′ |
| Opp-5 capability-utilization observability (UU-5) | new (near-free) | **P2-I3** | audit_log | e2e flags disabled tool | flags disabled tool | cross-check vs audit_log | P2-G |
| Opp-6 schemathesis→CEM (UU-10) | new (library unlock) | **P3-A1/A2** | recon schema, CEM | e2e schema fixtures + WFC/WFD | WFC/WFD @ 0 floor loss | schema-fuzz SSRF/non-idempotent | P3-G4′ |
| **Hunt postmortem / self-evaluation (IMPORTANT GAP)** | **new** | **P2-E1** (extended P4) | P2-I1/I2/I3, N1, case_store | e2e planted-fixture recall | planted skips/dups recall | read-only + evidence-cited | P2-G |
| UU-7 tool-output injection sanitization | **security (priority)** | **P2-S1** | — | e2e injection fixture + bypass audit | 0 payloads obeyed | independent bypass audit | P2-G-SEC |
| UU-8 deterministic replay / lineage | security/reliability | **P2-I2** | audit_log | e2e replay to identical verdicts | replay determinism | — | P2-G |
| UU-9 human escalation as info-value | small (add-on) | **P4-E2** | P4-E1 | e2e escalated-value measure | escalated-value | — | P4-G |
| **CEM signature transfer (memo Q2, made explicit)** | **research (security-framed)** | **P5-T1** | P4 signatures, P2 | e2e 3 transfer conditions | safe/false-reuse/missed rates | **missed-test rate==0** | P5-T1 gate |
| V.1 invariant > vuln-class primitive | counter-hypothesis | **§16 Decision 6** (P4 alongside) | — | — | — | — | human decision |
| V.2 proof-before-discovery sequencing | counter-hypothesis | **resolved by Option C** | — | — | — | — | resolved |
| V.3 memory as bias / anti-anchoring (UU-6) | research | **P5-K3** | P2 | e2e memory net-value A/B | memory net-value | — | P5 |
| V.4 adversarial gating of opportunities | discipline | **P4-M0 gate + phase gating** | — | — | — | applied throughout | applied |
| Long-horizon hunting benchmark (Q11) | new (benchmark) | **P4-BM** | P3 | is the benchmark (blind) | itself | blind/evaluator-only | P4-G |
| Asset Graph (Batch 8) | planned-open→merged | **P3-C2** | recon | e2e recon substrate | — | scope preserved | P3-G |
| Coverage Engine (Batch 8) | planned-open→merged | **P2 seed / P4 expand** | audit_log | coverage report on fixture | coverage metric | — | P2/P4 |
| Skill Router (Batch 8) | planned-open→merged | **P5-K1** | Opp-4/Opp-5, P5-A0 | e2e routing on fixtures | routing quality | hints-not-blocks | P5-G |
| Self-expanding toolkit (full autonomous) | **deferred (safety)** | P5-X1 human-in-loop | tool_gaps | human-reviewed build | — | content_scanner + human review | reason: unreviewed code vs live targets |
| Parallel fan-out rework | planned→merged | **P3-C1** | P2 | e2e concurrency | concurrency/dedupe | race/dup-suppression | P3-G |
| Graph DB / networkx | **rejected** | — | — | — | — | — | reason: SQLite suffices at scale |

**No orphans:** every major item from all three sources resolves to a phase/work-package, a merge, a human
decision (§16), or an explicit deferral/rejection **with a recorded reason**. New rows added by this correction
pass: **P2-E1 hunt postmortem** and **P5-T1 CEM signature transfer** (both were implicit before and are now
first-class), plus explicit rejected-item rows carried into the matrix.

---

## 15. RISKS & DEPENDENCIES

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Inserting P2 before breadth is seen as re-litigating XYZ's sequence | Med | Med | §16 Decision 1 — explicit human approval; P2 is additive, thesis unchanged |
| Opp-1 invariant model emits false invariants (garbage into CEM) | High | High | P4-M0 shallow-prototype **hard gate**; invariants are hypotheses, CEM determinism-gates every one |
| schemathesis dependency weight / maintenance | Low-Med | Low | dependency-budget sign-off (§16 Decision 3); optional flag; RESTler stays out |
| CEM integrity eroded by later integration | Low | Critical | G5 fccr==0 enforced every phase P3–P5; freeze untouched; integrity locks preserved |
| Telemetry/allocation leaks secrets | Low | High | redaction on all telemetry; G-SEC/G6 |
| Long-horizon benchmark ground truth leaks to implementation | Med | High | blindness rule (`.claude/rules/benchmarks.md`); evaluator-only artifacts (G9) |
| Info-gain/allocation suppresses a real test | Med | High | conservative policy: orders never hard-blocks; hard-fail floor on high/critical miss |
| Stale negative knowledge / signature → missed bug on changed target | Med | High | hints-not-skips; TTL; watch-triggered revalidation; quality floor catches it |
| Continuous hunting mixes targets / racing | Low | Med | reuse `engagement_paths` isolation + watch-mcp job locks |
| Go backend divergence | Low | Low | out of scope; noted only |

**Critical path:** P2 telemetry → (P3 breadth measurement, P4 info-gain, P5 allocation). P3 Asset Graph + API
experience → P4 invariant model. P4 signatures → P5 amortization + A/B/C/D.

### 15.1 Phase/WP dependency & positioning check (why each sits where it does; what fails if a dep is missing)

| WP | Prerequisite(s) | Downstream consumer(s) | Reason for position | If dependency missing |
|---|---|---|---|---|
| P2-S1 injection | none (uses existing helpers) | all output-rendering phases | live security gap; no dep → goes first | agent stays injectable while new surface is added |
| P2-I1 telemetry | Phase 1 substrate | P3 measurement, P4-E1, P5-A1/T1 | everything measurable depends on it | allocation/info-gain uncalibrated → unsafe |
| P2-I2 replay/lineage | audit_log | P2-E1, debugging, benchmarks | reproducibility precedes evaluation | can't debug/attribute failures |
| P2-I3 utilization | audit_log | P2-E1, P5-K1 router | introspection needs the log | router/postmortem lack "unused" signal |
| P2-N1 negatives | audit_log | P5-K1, P4-E1 redundancy | cheap, feeds routing | router deprioritizes nothing |
| P2-E1 postmortem | P2-I1/I2/I3, N1 | human review; P4 extends it | consumes all P2 signals → last in P2 | no self-evaluation of hunts |
| P3-A1/A2 Opp-6 | recon schema + CEM | P4 invariant on-ramp | discovery win that leverages CEM | miss stateful/business-logic API bugs |
| P3-C2 Asset Graph | recon | P4-M0 invariant model | model needs a substrate | invariant inference has no map |
| P4-M0 prototype | P3 corpus + P2 | **gates P4-M1 only** | de-risk the least-tractable item first | (by design) blocks expensive M1 if it fails |
| P4-E1 info-gain | **P2-I1** | P4-E2, P5 | needs calibrated cost/quality | circular/uncalibrated selection |
| P5-A0 gate | P5-A1 + P5-T1 | authorizes A2/A3 | policy only on evidence | policy would ship unproven |
| P5-A3 amortization | P5-A0 GO + **P5-T1** | — | reuse only if transfer is safe | stale reuse → missed security test |

**Guard against silent prerequisites:** research-grade items (P4-M1 full invariant model, P5-A2/A3 policy) must
**not** become prerequisites for anything else without their own passing evidence. P4-H1/E1/X1 do **not** depend
on P4-M1; P5-K1/K2/C1 do **not** depend on the allocation policy shipping.

---

## 16. HUMAN DECISIONS REQUIRING APPROVAL

1. **Ordering (the big one):** approve **Option C (Hybrid)** and, specifically, **inserting Phase 2 (Foundation &
   Reliability) before discovery breadth** — a refinement of XYZ's discovery-first Phase 2. (Reject → fall back to
   Option A, XYZ's literal sequence, with P2 items folded into P3 as prerequisites.)
2. **Confirm the CEM Phase-1 freeze is untouched** by this entire roadmap (it is — every phase builds on it and
   enforces G5). Approve that later phases may *read* CEM output but never modify the frozen slice.
3. **Dependency add:** approve `schemathesis` (+`hypothesis`) as a moderate dependency for Opp-6 (P3), with
   `RESTler`/`AALpy` remaining optional/gated.
4. **Long-horizon benchmark:** approve building a new blind, protected long-horizon hunting benchmark in P4
   (protected-asset discipline; a real commitment).
5. **Security priority:** approve **UU-7 tool-output-injection sanitization jumping the queue** as an immediate
   P2 security item, independent of the AI-feature sequence.
6. **Architecture question (V.1):** decide whether the invariant model (P4) eventually *reorganizes* the
   vuln-class skill spine (invariant-as-primitive) or remains an *additional* layer alongside it. This proposal
   defaults to **alongside** (lower risk) and asks for a directional ruling before P4.
7. **Scope confirmation:** confirm the Go backend ↔ agent wiring stays out of scope for this roadmap.

---

## 17. FINAL PROPOSED PRODUCT PROGRESSION

- **Today:** a frozen, trustworthy CEM proof engine + broad tooling + sequential orchestration.
- **After P2:** the same hunting capability, now **measured, replayable, injection-hardened**, with a
  negative-knowledge memory and honest capability-utilization introspection — a reliable, observable base.
- **After P3:** a materially stronger hunter that reaches **stateful/business-logic API bugs** by composing
  off-the-shelf falsifiers with CEM, runs CEM automatically in-hunt, and has competitive breadth — *proven*
  against WFC/WFD at zero quality-floor loss.
- **After P4:** a hunter that reasons about the **application's own rules** — inferring and falsifying invariants
  (CEM as a discovery engine), persisting and *conditionally resurrecting* hypotheses, and *ranking* experiments
  by expected information gain — validated on a long-horizon benchmark. (Invariant depth is **gated** by the
  P4-M0 prototype; if it fails, P4 delivers resurrection + info-gain + variants without deep invariant inference.)
- **After P5:** a hunter with **experimentally-validated adaptive allocation** under a hard security-quality floor
  (built only on a P5-A0 GO — if the evidence says no, allocation is deferred and P5 still completes), that
  amortizes validated causal knowledge across findings/targets **where transfer is proven safe (P5-T1)**, runs
  **continuous monitoring with hypothesis resurrection**, and grows its toolkit via **human-gated** decisions.
  (Honest-language note: **not** "self-modifying" or "fully autonomous" — toolkit growth is human-in-loop,
  allocation is experimental-until-GO, and continuous hunting is monitoring-plus-resurrection, not unattended
  autonomy.)
- **The end-state matches XYZ's stated architecture** — autonomous hunting + XBOW-class breadth + independent
  validation + CEM + causal/evidence minimization + variant discovery + knowledge feedback — **with CEM the
  constant differentiator**, now reached in a dependency-correct, measured, security-first order. Each phase's
  claim is bounded by its acceptance gate; capabilities that fail their gate are **deferred with a recorded
  reason**, not shipped.

---

*Planning artifact only. No code, no commits, no changes to XYZ.md / ROADMAP.md / architecture docs. Build order,
scope, dependencies, and freeze are all subject to the §16 human decisions before anything here is locked or
implemented.*
