# MASTER-ROADMAP-FINAL-v2.md — HuntMCP Reconciled Canonical Roadmap (post-freeze-audit correction)

**Status:** canonical synthesis, v2. Read-only production of a single plan. No source code and no protected planning
document was modified; `MASTER-ROADMAP-FINAL.md` (v1) is left intact. **This v2 supersedes v1** and resolves every
MUST-FIX and justified HIGH finding in `FINAL-MASTER-ROADMAP-REVIEW.md` **without changing the validated
architecture/spine.** Primary correction authority: `FINAL-MASTER-ROADMAP-REVIEW.md`; primary reconciliation authority:
`MASTER-ROADMAP-AUDIT.md`. Where a supporting document conflicts with those, they win.

**Ground truth:** worktree `research/golden-nextgen` @ `fbbf26d`; CEM Phase 1 FROZEN (`#101`). Load-bearing
implementation claims were re-verified against the current code during the pre-freeze review (`case_store.py:308/323`,
`cem_engine.py:316-319`, `scope_gate_hook.py:main` fail-open, `watch-mcp` has no case linkage).

**Not authoritative-to-build:** architecture-level direction, gates, and evidence requirements — not a code task list
and not an authorization to begin. Implementation begins only when §14's entry conditions are met.

---

## 0. Correction Log (what changed from v1, and why)

| Review finding | Severity | v2 change | Where |
|---|---|---|---|
| F-C-1 security-gate sequencing self-contradiction | CRITICAL | Security Floor split into **Tier-1** (hard gate before any autonomous breadth) and **Tier-2** (rootless boundary, required **before Phase-3 breadth begins**, not "by end") | §2, §5(S/3), §6, §9, §12, §14 |
| F-H-1 hunt postmortem/self-evaluation (P2-E1) dropped | HIGH | Restored as a first-class Phase-2 work package with full guardrails | §4, §5(P2), §11, §15 |
| F-H-2 P5 safety invariants under-specified | HIGH | Restored verbatim (missed-test==0; no-suppress-novel-test; cheap-tier closure guard; high/crit hard-fail) + P4 invariant guardrails | §5(P4/P5), §11, §11-A |
| F-H-3 quality floor not operationalized | HIGH | Explicit quality floor defined and distinguished from absolute security invariants | §11-A (new) |
| F-H-4 coverage metric used before instrument | HIGH | Minimal coverage instrument in Phase 2; full H3 matrix in Phase 4 | §4, §5(P2/P4), §12 |
| F-M-1 C1a scope realism | MEDIUM | C1a scoped: wire-level provenance vs invocation-level provenance | §8, §9 |
| F-M-2 A/B/C/D collapsed | MEDIUM | 4-arm experiment + C-vs-D attribution restored | §5(P5), §11 |
| F-M-3 schemathesis dependency sign-off dropped | MEDIUM | New-dependency approval added as a P3 precondition | §5(P3), §4 |
| F-M-4 "fail-closed" needs scoping | MEDIUM | Fail-closed scoped to target-touching calls; internal error blocks the gated call, not the session | §6 |
| F-M-5 protected/blind ground truth | MEDIUM | Benchmark-integrity discipline referenced in gates | §11, §11-A |
| F-M-6 / F-L-1 H3/H4 phase inconsistency | MED/LOW | Phase placements made consistent | §4, §5 |
| F-L-3 C3→C1a hard-dep | LOW | Softened to "should" | §9 |

**Unchanged (passed the review — do not touch):** Option-C spine; CEM frozen; provenance conceptual distinctions;
C1a/C1b split; C3 gated; Xalgorix dispositions; Next-Gen decisions; anti-roadmap; human-decision boundaries. No
architectural decision was changed. No empirical hypothesis was promoted to proven value.

---

## 1. Executive Summary

HuntMCP's post-Phase-1 direction is settled and modest. The plan keeps the audit-endorsed **Option-C spine**
(Foundation → Discovery amplification → Application reasoning → Adaptive allocation → Continuous), fronts it with a
**two-tier Security Floor** (Tier-1 before any autonomous breadth; Tier-2 rootless boundary before Phase-3 breadth),
and makes **evidence provenance** a first-class Phase-2 item — the one change two independent research streams *and* the
code all agree on.

HuntMCP remains a **local security-research application whose moat is CEM (proof), not throughput.** It is not becoming
a platform, control plane, generic agent runtime, or cloud service. The additive substrate is separable increments
(evidence provenance, an execution-isolation floor, hunt postmortem, delta re-validation), never a single "platform"
project.

The plan is deliberately conservative: **COMMITTED** work is only what is verified-needed (security floor, provenance
binding, injection sanitization, postmortem) or off-the-shelf-small (coverage instrument, scan headers). Everything
argued-but-unproven — full reproducibility manifest, discovery amplification, invariant model, adaptive allocation,
cross-target transfer, delta re-hunt precision — is **GATED/MEASURE-FIRST** behind an explicit experiment, under a
named quality floor and absolute security invariants. The largest single unknown remains whether
provenance/reproducibility raises triager acceptance; the plan measures it rather than assuming it.

---

## 2. Final Architecture Direction

- **Core engine (unchanged, frozen):** CEM — counterfactual proof/validation (`cem_engine.py` + `case_store` CEM
  tables). The differentiator; not reopened.
- **Additive infrastructure (committed, small):** (a) **evidence provenance** binding evidence to real exchanges; (b) a
  **two-tier execution-security floor**; (c) **hunt postmortem** (analysis-only introspection); (d) later,
  **target-delta re-validation**. All extend existing primitives; none is a platform layer.
- **How CEM fits:** stays post-confirmation validation (determinism gate requires a firing capability; `case_store`
  gates CEM on `CONFIRMED`). Integrated into hunting in Phase 3 **preserving the existing entry precondition** — not
  moved earlier, not redesigned. Oracle *reach* for non-HTTP observations is a research-only question.
- **How evidence/provenance fits:** the trust layer beneath CEM. Evidence is tamper-evident (SHA-256) but the discovery
  path is model-narrated (`add_evidence(content:str)`). Provenance binding closes that; hashing alone does not.
- **How execution security fits:** a **prerequisite gate in two tiers** (§6), not a feature and not a platform.
  **Tier-1** (fail-closed hook, secrets-out, os-shell confirm) before any autonomous breadth expansion; **Tier-2**
  (rootless per-run boundary + hook tamper-resistance) **before Phase-3 breadth begins**.
- **How target deltas / re-hunting fit:** a Phase-5 capability linking the (currently unlinked) `watch.db` snapshots to
  `case.db` hypotheses — real work, gated on measured re-hunt precision.
- **How adaptive allocation fits:** deferred to Phase 5, gated on a GO decision, under the quality floor + absolute
  security invariants. No router now.
- **Intentionally uncommitted:** control plane, cloud/K8s, secret-broker build, microVM-local, graph DB,
  event-sourcing, capability-authority subsystem, unrestricted multi-agent parallelism, AI IDE (§13).

---

## 3. Current Reality / Already Implemented (do NOT rebuild)

Verified in code (review re-verification):

- **CEM Phase 1** — determinism gate, `classify()` (3–5-valued), non-vacuous `SuccessSignature`, interventions, ddmin,
  per-trial machine-hashed evidence. **FROZEN.**
- **Hypothesis lifecycle store** — `case_store` hypotheses/findings/experiments/root_causes; evidence-gated CONFIRMED.
  **Do not build a new "ledger".**
- **Content-addressed evidence** — SHA-256 store. Tamper-evident. (Provenance is the gap, not integrity.)
- **State isolation** — per-engagement dirs + per-session pointer + `file_lock` + WAL.
- **Scope enforcement** — 3-layer deny-by-default incl. PreToolUse hook (present, firing) — narrow & **fail-open**;
  harden, don't redesign.
- **Cross-run memory/learning** — memory/writeup/lessons-mcp. **Ahead of competitors; keep.**
- **Continuous recon diffing** — `watch-mcp` snapshots (**unlinked** to case state — the C3 gap).
- **Human-review-before-submit** — `hackerone-mcp` has no submit tool by design. **Technical control; keep.**
- **`chainer-mcp`** — the real attack DAG (Xalgorix "ledger-as-graph" rejected; this is the graph).

**Not present (grep-verified):** execution isolation/sandbox, capability-authority tokens, secret broker, provenance
binding, coverage instrument/matrix, scan-identification headers, tool-output-injection sanitization, hunt postmortem.

---

## 4. Canonical Decision Matrix

Categories: **ALREADY IMPLEMENTED · COMMITTED · GATED (measure-first) · DEFERRED · REJECTED.**

| Capability / Initiative | Decision | Phase | Priority | Dependencies | Rationale / Evidence | Acceptance Gate |
|---|---|---|---|---|---|---|
| CEM Phase-1 proof engine | ALREADY IMPLEMENTED | — | — | — | `cem_engine.py`, frozen `#101` | — |
| Hypothesis lifecycle store | ALREADY IMPLEMENTED | — | — | — | `case_store` | — |
| Content-addressed evidence | ALREADY IMPLEMENTED | — | — | — | SHA-256 store | — |
| State isolation / memory / watch diffing | ALREADY IMPLEMENTED | — | — | — | ahead of competitors | — |
| **Tier-1:** scope hook fail-closed + CI block-test | COMMITTED | S (Tier-1) | P0 | — | fail-open SPOF (review §8) | out-of-scope call blocked in CI |
| **Tier-1:** scope secrets out of untrusted execution | COMMITTED | S (Tier-1) | P0 | — | full-`.env` load `dotenv_loader.py` | sandboxed exec cannot read `.env` |
| **Tier-1:** `--os-shell` / state-changing confirmation tier | COMMITTED | S (Tier-1) | P0 | — | persistent RCE, no gate | RCE requires explicit confirm |
| **Tier-2:** rootless execution boundary + hook tamper-resistance (C2) | COMMITTED | S (Tier-2) | P1 | rootless runtime | whole-host TCB; hook neutralizable | adversarial regression (containment + utility) **before Phase-3 breadth** |
| Evidence provenance binding (C1a / Xalgorix H1) | COMMITTED | 2 | P1 | capture seam | 2 streams + code (`add_evidence:322`) | evidence bound to real exchange (wire- or invocation-level, §8) |
| Hunt postmortem / self-evaluation (P2-E1) | COMMITTED | 2 | P1 | telemetry, `case_store`, `dedupe_check` | committed WP (PROPOSAL §P2-E1) + UU #24 IMPORTANT GAP | planted-fixture recall; read-only proven; independent cross-check; redaction |
| Tool-output-injection sanitization (UU-7) | COMMITTED | 2 | P1 | — | live injection surface | injection regression passes |
| Benchmark + telemetry substrate | COMMITTED | 2 | P1 | — | gates all measured items | emits cost/yield/coverage |
| Coverage instrument — minimal (H3 core) | COMMITTED (small) | 2 | P1 | benchmark | needed as a P2/P3 signal (review F-H-4) | coverage signal produced + benchmarked |
| Coverage matrix — full endpoint×class×role (H3) | COMMITTED (small) | 4 | P2 | P2 coverage instrument | full breadth object | matrix populated + anti-gaming clause |
| Tool pinning + SBOM + CI SAST | COMMITTED | 2 | P2 | — | unpinned `@latest` | pinned build + SAST in CI |
| Scan-identification headers (H4) | COMMITTED (small) | 3 | P3 | — | polite authorized scan (Xalgorix) | target-only header emitted |
| Full research-run manifest (C1b) | GATED | 2→ | P3 | C1a, benchmark | value unproven | triager-acceptance A/B (XYZ §6.3) |
| Discovery amplification (schemathesis→CEM) | GATED | 3 | P2 | benchmark, **new-dependency approval**, **Tier-2 complete** | amplification unmeasured | WFC/WFD, quality floor held |
| CEM-in-hunt integration (XYZ P3) | COMMITTED | 3 | P2 | Phase-2 base | wire confirmed→CEM, **entry precondition preserved** | CEM runs in-hunt; FCC==0 |
| Structural differentiation evidence (XYZ §2.6) | COMMITTED | 3 | P3 | disclosed_reports | dedupe aid | labeled differentiation emitted |
| SuccessSignature oracle reach — browser/OOB (H2) | GATED (research-only) | research | P4 | — | HTTP-only `:316`; keep CEM pure | only if breadth-blocking; injected `observe_fn` |
| Invariant model (UU-1) | GATED | 4 | P3 | telemetry | least-tractable (UU V.4) | P4-M0 GO/NO-GO; invariants remain CEM-provable hypotheses |
| Hypothesis resurrection (UU-2) | COMMITTED (additive query) | 4 | P3 | case_store | no new store | resurrection query ships |
| Info-gain experiment selection (UU-3) | GATED | 4 | P3 | telemetry | needs cost/gain data | uplift; **orders, never hard-blocks a novel test** |
| Adaptive allocation / router (A/B/C/D) | DEFERRED (gated) | 5 | P4 | telemetry | measure-first (memo) | P5-A0 GO; C-vs-D attribution; quality floor + security invariants |
| Target-delta re-validation (C3) | GATED | 5 | P3 | should-use C1a; watch↔case link | not plumbing (audit §5) | re-hunt precision > cold start |
| Cross-target transfer (memo §9 / XYZ P4) | DEFERRED (gated) | 5 | P4 | signatures | transfer safety unproven | P5-T1: **false-reuse→missed-test == 0** |
| Human-gated toolkit growth (`tool_gaps`) | GATED | 5 | P4 | recurrence signal | human-in-loop (safety) | human approval per addition |
| Capability/tool-exposure layer | DEFERRED | V4 | — | 3rd runtime / drift | premature (Universal-Capability §11) | trigger conditions |
| Resource-aware admission control | DEFERRED | — | — | — | `budget_guard` covers cost axis | — |
| "Confirmation is CEM" / new verifier subsystem | REJECTED | — | — | — | analogy only (audit §4/§6) | — |
| audit_log as evidence store; ledger-as-graph; direction-of-travel; MAPTA/XBOW | REJECTED | — | — | — | XALGORIX-REVIEW §24 | — |
| Control plane / cloud / K8s / secret-broker build / microVM-local / graph DB / event-sourcing / AI IDE / unrestricted parallelism | REJECTED / DEFERRED | — | — | triggers | audit §13 | — |

---

## 5. Final Phase Roadmap

Five phases + a two-tier gating Security Floor. Frozen CEM sits beneath all (consumed, never modified). *(Note:
"Phase 1" is the frozen CEM slice; the first new phase is Phase 2, matching the proposal's numbering.)*

### Phase S — Security Floor  *(gating prerequisite; small; mostly hardening) — TWO TIERS*

**Tier-1 (hard gate — must pass BEFORE any autonomous breadth expansion, i.e. before Phase-2 autonomous work):**
- (1) scope hook → **fail-closed** (scoped to target-touching calls; on internal error, block the *gated call*, not
  the whole session) + CI block-test; (2) scope secrets out of untrusted execution; (3) `--os-shell`/state-changing
  confirmation tier.
- *Acceptance:* an out-of-scope call is blocked in CI; a compromised-agent test cannot read `.env`; state-changing RCE
  requires confirmation.

**Tier-2 (rootless execution boundary + hook tamper-resistance — must complete BEFORE Phase-3 breadth begins):**
- (4) rootless per-run execution boundary (swappable); (5) hook tamper-resistance (bash file-writes above the boundary
  prevented).
- *Acceptance / exit gate:* the adversarial regression (canary-secret exfil via hostile tool output; out-of-scope
  action; hostile-repo checkout) passes on **containment AND legitimate-task utility**, across the lifecycle (create →
  run → pause → resume → terminate). **Phase-3 discovery amplification does not start until this passes.**
- **Non-goals:** secret broker, capability leases, control plane, microVM.

### Phase 2 — Foundation, Evidence Integrity, Introspection & Reliability
- **Objective:** a measured, injection-hardened, provenance-bound, self-evaluating base.
- **Why now:** every downstream measured item needs telemetry + benchmark; every report needs trustable evidence; the
  postmortem substrate is a stated precondition for P3 measurement and P4/P5 decisions.
- **Prerequisites:** Phase-S **Tier-1** complete.
- **Capability groups:** (1) benchmark + telemetry substrate; (2) **evidence provenance binding (C1a)** — capture seam
  (§8 scope); (3) **hunt postmortem / self-evaluation (P2-E1)** — see spec below; (4) tool-output-injection
  sanitization (UU-7); (5) negative-knowledge + capability-utilization signal; (6) **minimal coverage instrument (H3
  core)** producing the coverage signal used later; (7) supply-chain pinning + SBOM + CI SAST; (8) *optional* C1b
  manifest, instrumented for the acceptance A/B.
- **Acceptance / metrics:** discovery evidence bound to a real exchange; injection regression passes; telemetry emits
  cost/yield/**coverage (from the P2 instrument)**; false-positive baseline recorded; **postmortem read-only proven +
  planted-fixture recall met**.
- **Exit gate:** benchmark + coverage instrument live; provenance verified on stored findings; postmortem passes
  planted-fixture recall and independent cross-check.
- **Non-goals:** invariant model, allocation, discovery breadth, self-modification.

**P2-E1 detailed spec (hunt postmortem — analysis / reporting ONLY):**
- **Analysis-only, read-only, no tools, no auto-retry, no self-modification, no policy mutation.** An offline post-hunt
  analyzer (like a report generator); never mutates `case_store`/state; never invokes a target-touching tool.
- **Purpose:** evaluate what happened and what was missed / wrong / inefficient.
- **Evidence-cited output:** every postmortem claim cites `audit_log`/`case_store`/evidence rows.
- **Planted-fixture benchmark:** on a fixture hunt with known-planted issues, postmortem must recover them
  (precision/recall).
- **Independent verification:** postmortem findings cross-checked against raw `audit_log`/`case_store` by an
  independent check (not the postmortem's own reasoning).
- **Redaction requirement:** postmortem output must not write secrets/PII (redaction verified).
- **Extension note:** *extended* (not rebuilt) in P4 (e.g. `missed_chain_opportunities`).

### Phase 3 — Discovery Amplification + CEM-in-Hunt
- **Objective:** competitive breadth under the quality floor.
- **Prerequisites:** Phase-2 substrate; **Phase-S Tier-2 boundary complete** (breadth = peak hostile-content
  ingestion); **new-dependency approval** for `schemathesis` (repo dependency-budget sign-off).
- **Capability groups:** (1) schemathesis→CEM stateful/API falsifiers (GATED); (2) CEM auto-run after independent
  validation **preserving the existing CEM entry precondition** (`CONFIRMED`/determinism gate); (3) structural
  differentiation evidence; (4) H4 scan headers.
- **Acceptance / metrics:** WFC/WFD breadth up **against protected/blind ground truth**; **quality floor held (§11-A):
  no high/critical the baseline finds is lost — hard-fail**; CEM runs in-hunt; **FCC == 0**.
- **Exit gate:** amplification measured positive; quality floor + FCC==0 intact.
- **Non-goals:** widening CEM oracle contract (H2 research-only unless breadth-blocking).

### Phase 4 — Application Reasoning + Coverage
- **Objective:** reason about the application's own rules.
- **Prerequisites:** Phase-2 telemetry + coverage instrument.
- **Capability groups:** (1) invariant model **(gated by P4-M0 prototype)** — **invariants remain hypotheses that CEM
  must still prove; invariant false positives are a quality risk, not a finding**; (2) hypothesis resurrection (additive
  `case_store` query); (3) info-gain experiment selection (GATED) — **orders experiments, never hard-blocks a novel
  test**; (4) **full coverage matrix (H3)** endpoint×class×role with anti-gaming clause.
- **Acceptance / metrics:** on a blind long-horizon benchmark, reasoning items beat baseline **at quality floor (§11-A)
  held**; coverage measurable and non-gameable.
- **Exit gate:** P4-M0 GO/NO-GO recorded; if NO-GO, ship resurrection + info-gain + coverage matrix **without** deep
  invariant inference.
- **Non-goals:** allocation, transfer.

### Phase 5 — Adaptive Allocation + Continuous / Delta
- **Objective:** amortize validated knowledge; hunt continuously — **under the quality floor and absolute security
  invariants (§11-A)**.
- **Prerequisites:** Phase-4 measurement.
- **Capability groups:** (1) adaptive allocation **(gated by P5-A0 GO)** via the **A/B/C/D experiment** (A frontier-
  heavy · B fixed-mixed · C adaptive · D CEM-assisted; **C-vs-D kept separate** = the entire attribution of CEM's
  contribution); (2) continuous monitoring + **delta re-validation (C3, gated)** + patch-bypass regression; (3)
  cross-target transfer **(gated by P5-T1)**; (4) human-gated toolkit growth.
- **Security invariants (absolute — see §11-A):** false-reuse-causing-missed-test == 0; allocation / dedupe / negative
  knowledge **may never hard-block a not-yet-confirmed novel test** (hints, never skips); **cheap-tier premature-closure
  guard** (a high-severity-potential hypothesis cannot be closed by a cheap tier without an escalation check); **any
  high/critical miss vs the frontier baseline hard-fails the config.**
- **Acceptance / metrics:** allocation improves cost/quality under the floor+invariants or is deferred; C3 beats
  cold-start re-hunt precision/recall.
- **Exit gate:** each gated item ships only on its GO; a failed gate defers with a recorded reason.
- **Non-goals:** self-modification, unattended autonomy, unrestricted parallelism.

*Cross-cutting continuous tracks: Security/Reliability hardening (P2 items); Benchmark & Measurement.*

---

## 6. Security Floor (two tiers)

**Placement: a Phase-S gating precondition in two tiers** — the audit/review are explicit that the floor must precede
the corresponding autonomous expansion, not run as a mere side-track.

**Tier-1 — hard gate before ANY autonomous breadth expansion (before Phase-2 autonomous work):**
- Scope hook **fail-closed** — **scoped to target-touching calls**; on an internal hook error, block the *gated call*,
  not the whole session (v1's blanket "fail closed" would have broken benign sessions — F-M-4) + CI block-test.
- **Secrets scoped out** of untrusted execution (stop full-`.env` load; per-key; unreadable by sandboxed exec).
- **`--os-shell`/state-changing confirmation tier.**

**Tier-2 — rootless execution boundary, required BEFORE Phase-3 breadth begins:**
- **Rootless per-run boundary** (swappable, keeps future remote/microVM possible) + **hook tamper-resistance** (bash
  file-writes above the boundary prevented).
- Exit gate = adversarial regression on **containment AND legitimate-task utility**, across the lifecycle.

**Later hardening (P2, continuous, non-gating):** tool version pinning + SBOM; Python SAST/dep-audit in CI; CI
`permissions:` block; `data/watch.db` untrack + per-engagement path.

**Deferred (with triggers):** resource-aware admission control (budget_guard suffices); capability-authority system;
secret broker (off-the-shelf only, on remote/many-keys/untrusted-third-party trigger).

**Discipline:** the floor is small — mostly hardening + one rootless boundary. It must not metastasize into platform
architecture.

---

## 7. CEM Position

- **Frozen/accepted; not reopened.** No regression, missing contract, or cross-phase dependency requires a change to
  the frozen slice.
- **Future integration:** Phase 3 wires every independently-validated finding into CEM **preserving the existing entry
  precondition** (`CONFIRMED`/determinism gate — CEM-in-hunt is integration, not a contract relaxation); Phase 5 uses
  causal signatures for variants/transfer (gated).
- **Oracle reach (H2) is research/incremental, not a redesign:** `SuccessSignature` matches HTTP responses only;
  browser-execution and OOB-callback oracles are inexpressible. If (and only if) machine-verdicting those becomes a
  breadth bottleneck, address via an *injected `observe_fn`* preserving `cem_engine.py` purity — never by coupling the
  engine to network/browser/DB.
- **Not a CEM redesign:** the Xalgorix "verifier" is establish-existence logic HuntMCP already owns; CEM consumes the
  *result*. Do not build a competing verifier. "Confirmation is CEM" is rejected — structural analogy only.
- **Applicable Xalgorix lessons without replacing CEM:** provenance seam (H1/C1a), oracle-reach question (H2), coverage
  object (H3) — all additive, none touching `cem_engine.py`.

---

## 8. Evidence & Provenance Strategy

The verified gap (`case_store.py:322` vs `cem_trials`): evidence has **two paths of unequal trust**; most reports flow
through the weak one.

| Class | Today | Trust | Plan |
|---|---|---|---|
| Model-authored evidence | `add_evidence(content:str)` | hashed string = tamper-evident, **not** provenance | **close via C1a** |
| Machine-captured evidence | `cem_trials.request/response_evidence_hash` | bound to real exchange | keep; extend earlier |
| Confirmation-gated | CEM tables behind `CONFIRMED` | strong but late | provenance must exist **pre**-confirmation |

- **Do not claim the gap is solved because hashes exist.** Hashing proves integrity, not provenance.
- **C1a scope (F-M-1) — the smallest useful milestone, not an evidence platform:**
  - **Wire-level provenance** for evidence sources that expose a structured request/response —
    curl/`tool_resolver`, `browser-mcp`, `oob-mcp`, and CEM's `fetch_fn`: bind evidence to the actual exchange.
  - **Invocation-level provenance** for scanner-sourced evidence (nuclei/sqlmap/subfinder), whose output is
    tool-narrated: bind to the tool invocation + captured raw stdout, **not** a per-HTTP exchange.
  - The acceptance gate is met when each evidence class carries the *strongest provenance available to it*, not a
    single universal wire capture.
- **Full reproducibility manifest (C1b)** — tool/model/policy versions + target-snapshot hash — is **GATED**: sound and
  cheap, but its *incremental* value over C1a integrity is unproven. Instrument, run the A/B, promote only on evidence.

---

## 9. C1 / C2 / C3 Placement

- **C1a (provenance foundation):** COMMITTED, Phase 2, P1. Scoped per §8 (wire- vs invocation-level).
- **C1b (full run manifest):** GATED, Phase 2 optional → promote via triager-acceptance A/B. Not a headline; not proven.
- **C2 (execution boundary):** COMMITTED as the **Tier-2** floor; rootless, swappable; microVM stays a future-remote
  option behind the abstraction. **Must complete before Phase-3 breadth begins** (§6). Not a capability bet, not a
  platform.
- **C3 (target-delta → affected hypotheses → targeted re-validation):** GATED, Phase 5. Real work (watch/case
  unlinked); **should** use C1a provenance for its re-validation evidence, and depends on a watch↔case link; gated on
  measured re-hunt precision.
- **Not collapsed:** separable increments across existing phases, never one "platform" project.

---

## 10. Xalgorix-Derived Lessons (surviving dispositions)

Per XALGORIX-REVIEW (corrective authority):
- **Provenance (H1):** ADOPT = C1a (Phase 2). Highest-impact convergent finding.
- **Oracle reach (H2):** RESEARCH-ONLY, gated. Keep CEM pure.
- **Coverage (H3):** ADOPT — minimal instrument P2, full matrix P4; anti-gaming clause.
- **Scan headers (H4):** ADOPT (small), Phase 3; correct destination boundary.
- **Deterministic confirmers:** ALREADY HAVE stronger (CEM verdict machinery) — no work.
- **Hypothesis ledger:** ALREADY HAVE (`case_store`) — no new store; resurrection is an additive query.
- **Evidence capture/reporting seam:** = C1a.
- **Verifier *environment* isolation:** insight → reinforces C2 (Tier-2).
- **Secure-SDLC CI:** ADOPT (insight) → Python SAST/dep-audit in CI (P2).
- **Do NOT copy wholesale:** 22-phase prompt-constant, control-plane RCE console, resource-admission subsystem,
  ledger-as-graph, direction-of-travel — rejected/deferred.

---

## 11. Measurement & Promotion Gates

Every GATED item promotes only on evidence; failure = defer with a recorded reason, never ship on argument. **All
capability benchmarks use protected/blind ground truth (labels independent of the implementation; no auto-derived
oracle; anti-gaming) per `.claude/rules/benchmarks.md`.**

| Hypothesis | Metric | Minimum experiment | Promotion criterion | If it fails |
|---|---|---|---|---|
| Provenance/reproducibility raises acceptance (C1b) | triager acceptance, time-to-triage, needs-info | A/B: findings with vs without manifest (XYZ §6.3) | acceptance uplift, no time regression | keep C1a integrity; drop C1b as headline |
| Discovery amplification (schemathesis→CEM) | new confirmed findings/target; FCC | WFC/WFD (blind) + constructed labs | breadth up, **quality floor held**, FCC==0 | defer amplification; keep CEM-in-hunt |
| Postmortem recovers what was missed | planted-fixture precision/recall; read-only proof; redaction | fixture hunt with planted issues | recall bar met; read-only + independent cross-check clean | ship narrower postmortem; never grant it action |
| C3 delta re-hunt beats cold start | re-hunt precision/recall vs cold | inject target delta; compare | higher precision at lower cost | keep watch diffing as alerting only |
| Invariant model tractable | invariant recall/precision (invariants = hypotheses) | P4-M0 shallow prototype (blind) | prototype meets bar; FP acceptable | ship resurrection+info-gain+coverage only |
| Rootless boundary preserves utility | legitimate-task success under isolation | Phase-S Tier-2 exit regression | containment high, utility ≈ baseline | narrow the profile; keep boundary, relax policy |
| Adaptive allocation pays off | cost/quality; **C-vs-D attribution** | P5-A1 A/B/C/D (held-out, blind) | improvement under floor+invariants | defer allocation; Phase 5 completes without it |
| Cross-target transfer is safe | safe-transfer / false-reuse / missed-test | P5-T1 (same/similar/cross-target) | **false-reuse→missed-test == 0** | defer transfer |

### 11-A. Quality Floor vs Absolute Security Invariants (F-H-3)

These are **distinct** and must not be conflated:

**Quality floor (hard-fail on high/critical; Pareto for medium/low):**
- **high/critical recall ≥ baseline − ε** (any high/critical the frontier baseline found but a config misses →
  **hard-fail, reject the config**);
- **false positives ≤ baseline**;
- **coverage ≥ baseline**.
Applies to P3 (discovery) and P5 (allocation/transfer).

**Absolute security invariants (zero-tolerance — stricter than the floor):**
- **CEM FCC (false-causal-conclusion) rate == 0**;
- **false-reuse-causing-missed-test == 0** (a stale/mismatched signature must NEVER become an authoritative skip — a
  false reuse causing a missed security test is a SECURITY FAILURE, not a cost metric);
- **allocation / dedupe / negative-knowledge may never hard-block a not-yet-confirmed novel test** (hints lower
  priority, never skip; suppressed experiments are audited);
- **cheap-tier premature-closure guard** (severity-gated minimum-effort floor before a cheap tier may close a
  high-severity-potential hypothesis);
- **postmortem is analysis-only** (no action, no self-modification);
- **human-review-before-submit** preserved.

---

## 12. Dependency Graph

```
              [ FROZEN: CEM Phase 1 ]  ── consumed by every phase, modified by none
                           │
Phase S Tier-1 (fail-closed hook, secrets-out, os-shell confirm)          ← HARD GATE (before any autonomous breadth)
                           ↓
Phase 2 (Benchmark+telemetry · C1a provenance · P2-E1 postmortem · UU-7 injection · coverage instrument · pinning/SBOM)
     │                                   │
     │ (C1b gated: A/B)                  ↓
     │                    Phase S Tier-2 (rootless boundary + hook tamper-resistance)   ← GATE before Phase-3 breadth
     │                                   ↓
     └────────────────────►  Phase 3 (Discovery amplification[gated, dep-approval] · CEM-in-hunt · differentiation · H4)
                                          ↓
                             Phase 4 (Invariant model[P4-M0] · resurrection · info-gain[gated] · coverage matrix H3)
                                          ↓
                             Phase 5 (Adaptive allocation[P5-A0, A/B/C/D] · Continuous + delta C3[gated] · transfer[P5-T1] · human-gated toolkit)
```

Tier-1 precedes all autonomous breadth; **Tier-2 precedes Phase-3 breadth**; the P2 coverage instrument precedes any
coverage-based acceptance signal; measurement precedes reasoning; reasoning/telemetry precede allocation; C3 should use
C1a + a watch↔case link.

---

## 13. Anti-Roadmap (intentionally NOT built this horizon)

Evidence-based, not ideological:
- **Generic control plane / multi-tenant SaaS / billing** — DEFER (trigger: multi-user).
- **Cloud / Kubernetes-first / distributed** — DEFER (keep exec boundary swappable).
- **Local microVM / bespoke VM platform** — rootless is the practical boundary. DEFER (trigger: remote exec).
- **Custom secret broker** — off-the-shelf when triggered; scoping secrets out gets ~80% now. Never build.
- **Graph database / event-sourcing** — SQLite + `chainer-mcp` DAG suffice. NO.
- **New "verifier" subsystem** — duplicates existing confirmation + frozen CEM. NO.
- **Resource-aware admission control** — `budget_guard` covers the axis. DEFER.
- **Capability-authority subsystem** — subsumed near-term by the fail-closed monitor + rootless floor + scoped secrets.
  DEFER (trigger: mutually-distrusting agents).
- **AI IDE / generic agent platform / capability marketplace / unrestricted multi-agent parallelism** — off-mission;
  parallelism stays a measured design-only backlog. DEFER/REJECT.

---

## 14. Implementation Entry Conditions

Implementation may begin when:
1. **Frozen:** CEM Phase-1 frozen; hypothesis-lifecycle store, evidence content-addressing, scope-enforcement *design*,
   and human-review-before-submit treated as fixed (harden behaviour, do not redesign).
2. **First work = Phase-S Tier-1.** No autonomous breadth work begins until Tier-1 passes. **Phase-S Tier-2 must pass
   before Phase-3 breadth begins.**
3. **Baselines before Phase 3:** benchmark + telemetry (cost/yield/coverage) + false-positive baseline + **coverage
   instrument** (Phase 2); **C1a provenance verified on stored findings**; **postmortem read-only + planted-fixture
   recall proven**.
4. **Do not rebuild** anything in §3.
5. **Phase gate discipline:** GATED items ship only on their promotion criterion (§11); a failed gate defers the item
   with a recorded reason and the phase completes without it.
6. **New dependencies** (e.g. `schemathesis`, a rootless runtime) require explicit approval before adoption.
7. **Protected-doc edits** (folding this plan into `ROADMAP.md`/`MASTER-ROADMAP-PROPOSAL.md`/execution plan) require a
   separate, explicitly human-authorized task — this file does not perform them.

---

## 15. Success Metrics

Success is **measured by hunting outcomes, never by agent/MCP/prompt/feature count.**
- **Confirmed-finding precision** (evidence-gated; **FCC == 0**).
- **Evidence quality / provenance** — share of reported evidence carrying its strongest-available provenance (C1a); if
  promoted, triager-acceptance uplift (C1b).
- **Postmortem quality** — planted-fixture recall of what was missed/wrong/inefficient (analysis-only).
- **Useful coverage** — endpoint×class×role, non-gameable (H3).
- **Experiment efficiency** — cost/time/tool-calls per confirmed finding; info-gain uplift.
- **Repeated-target improvement / re-hunt precision** — C3 beats cold start.
- **Discovery breadth under the quality floor** — WFC/WFD, **no high/critical loss**.
- **Long-horizon reliability & regression resistance** — patch-bypass regression catches reintroductions.
- **Safe autonomous operation** — the Phase-S Tier-2 adversarial regression stays green across the lifecycle;
  containment high with legitimate-task utility preserved; absolute security invariants (§11-A) hold.

---

## 16. Open Questions

1. **Does provenance/reproducibility raise triager acceptance?** (C1b.) Unproven — single largest unknown; measured.
2. **Is the browser/OOB oracle gap (H2) breadth-blocking?** Only then does it earn work.
3. **C3 re-hunt precision vs cold start** — the affected-hypothesis mapping is the crux; unmeasured.
4. **schemathesis→CEM amplification magnitude** — assumed high-leverage; unmeasured.
5. **Invariant-model tractability** — flagged least-tractable; P4-M0 gate stands.
6. **Rootless-boundary utility cost** — Phase-S Tier-2 exit measures it.
7. **Adaptive allocation & cross-target transfer** — payoff/safety unproven; both gated.

---

## 17. Final Freeze Criteria

The architecture may be frozen for implementation when:
- The Canonical Decision Matrix (§4) is accepted as-is (no reopened settled decisions).
- CEM Phase-1 is confirmed untouched by every committed item (only `case_store` provenance and the security floor touch
  adjacent code; `cem_engine.py` is not modified).
- The **two-tier** Security Floor (§6) is accepted, with Tier-1 before any breadth and Tier-2 before Phase-3 breadth.
- Evidence provenance (C1a, scoped per §8) is accepted as the first-class Phase-2 item, alongside the restored
  **postmortem (P2-E1)**.
- The **quality floor and absolute security invariants (§11-A)** are accepted as written.
- Every GATED item (§11) has its experiment and promotion criterion recorded before any work on it starts.
- The Anti-Roadmap (§13) is accepted.
- The protected-doc integration (§14.7) is authorized as a separate task.

Once these hold, Phase-S Tier-1 may begin. No further research is required to start; remaining unknowns are empirical
questions with assigned gates, not open design questions.

---

## 18. Self-Check Against Review & Audit

**Every MUST-FIX resolved?**
- **F-C-1 (CRITICAL) — YES.** Security Floor split into Tier-1 (before any autonomous breadth) and Tier-2 (rootless
  boundary, before Phase-3 breadth begins); §6/§5/§12/§14 make the ordering unambiguous and forbid breadth before
  Tier-2.
- **F-H-1 (HIGH) — YES.** P2-E1 hunt postmortem restored as a first-class Phase-2 WP with analysis-only/read-only/no-
  tools/no-auto-retry/no-self-modification/evidence-cited/planted-fixture/independent-verification/redaction guardrails.
- **F-H-2 (HIGH) — YES.** P5 invariants restored verbatim in §5(P5) and §11-A; P4 invariant guardrails (invariants =
  CEM-provable hypotheses; false positives a quality risk; info-gain orders, never blocks) added.
- **F-H-3 (HIGH) — YES.** §11-A defines the quality floor (high/critical recall ≥ baseline−ε; FP ≤ baseline; coverage ≥
  baseline) and distinguishes it from absolute security invariants (FCC==0; false-reuse→missed-test==0; no-suppress;
  cheap-closure guard).

**Every justified HIGH resolved?**
- **F-H-4 (HIGH) — YES.** Minimal coverage instrument added to Phase 2 (produces the signal used in P2/P3); full H3
  matrix remains Phase 4; §12 encodes the ordering; §4/§5 phase placements made consistent.

**MEDIUM addressed (connected to the fixes):** F-M-1 (C1a wire/invocation scope, §8), F-M-2 (A/B/C/D restored, §5/§11),
F-M-3 (schemathesis dep-approval, §4/§5/§14), F-M-4 (fail-closed scoped, §6), F-M-5 (protected/blind ground truth,
§11/§11-A). LOW: F-M-6/F-L-1 (H3/H4 phases consistent), F-L-3 (C3→C1a softened to "should").

**Any new inconsistency introduced?** Re-checked (task #7): no contradiction (Tier-1/Tier-2 ordering is now the single
source of security sequencing); no hidden prerequisite (coverage instrument now precedes its use; dep-approval
explicit); no dropped guardrail (postmortem + P5 invariants restored); no duplicated capability (coverage instrument
vs matrix are one capability in two stages, explicitly); no speculative item promoted (all unproven items remain
GATED/DEFERRED); no rejected item reintroduced (§13 intact; anti-roadmap re-scanned).

**Sections changed vs v1:** §0 (new correction log), §1, §2, §4 (matrix rows: Tier-1/Tier-2 split, postmortem,
coverage instrument+matrix, A/B/C/D, dep-approval, C3 soft-dep), §5 (Phase S two-tier; Phase 2 +postmortem+coverage
instrument; Phase 3 prereqs+floor; Phase 4 invariant guardrails+full matrix; Phase 5 invariants+A/B/C/D), §6 (two
tiers + fail-closed scope), §7 (entry-precondition wording), §8 (C1a scope), §9 (C2 tiering; C3 soft-dep), §11 (+rows,
blind ground truth), **§11-A (new)**, §12 (graph), §14 (entry conditions), §15 (metrics), §17 (freeze criteria), §18
(this self-check).

**Any decision changed?** No architectural/spine decision changed. Only sequencing precision, restored guardrails, and
explicit gates were added. No empirical hypothesis was promoted to proven value; CEM remains frozen.

**Any remaining blocker?** None identified. With v2's corrections the four MUST-FIX and the HIGH coverage-ordering
finding are resolved; the document is internally consistent and, subject to human acceptance of §17, freezeable.

---

## Report
- **Source authorities used:** `FINAL-MASTER-ROADMAP-REVIEW.md` (primary), `MASTER-ROADMAP-AUDIT.md`,
  `MASTER-ROADMAP-PROPOSAL.md` (P2-E1 + P5 invariant + A/B/C/D text), `INTELLIGENCE-ALLOCATION-MEMO.md`,
  `UNKNOWN-UNKNOWN-RESEARCH.md`, `XYZ.md`, `OPEN-SOURCE-AUDIT.md`, `NEXT-GEN-PLATFORM-RESEARCH.md`, `XALGORIX-REVIEW.md`,
  and current code. `NEXT-GEN-PLATFORM-REVIEW.md` **absent** (NEXT-GEN §63 self-audit stands in).
- **Exact file created:** `MASTER-ROADMAP-FINAL-v2.md`. `MASTER-ROADMAP-FINAL.md` (v1) left intact. No other file
  modified; nothing implemented, committed, or pushed.
