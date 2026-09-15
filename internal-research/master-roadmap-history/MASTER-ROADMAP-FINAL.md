# MASTER-ROADMAP-FINAL.md — HuntMCP Reconciled Canonical Roadmap

**Status:** canonical synthesis. Read-only production of a single plan. No source code and no protected planning
document was modified. This file **conceptually supersedes** the competing roadmap proposals (`ROADMAP.md`,
`MASTER-ROADMAP-PROPOSAL.md`, the three `HUNTMCP-NEXT-GEN-PROPOSAL*` revisions) as the reconciled plan; those remain in
the corpus as history. **Primary authority: `MASTER-ROADMAP-AUDIT.md`.** Where any supporting document conflicts with
the audit, the audit wins.

**Ground truth:** worktree `research/golden-nextgen` @ `fbbf26d`; CEM Phase 1 FROZEN (`#101`). Implementation-state
claims below were verified against code during the audit (file:line cited where load-bearing).

**Not authoritative-to-build:** this is architecture-level direction, gates, and evidence requirements — not a code
task list and not an authorization to begin. Implementation begins only when §14's entry conditions are met.

---

## 1. Executive Summary

HuntMCP's post-Phase-1 direction is settled and modest. The reconciled plan keeps the audit-endorsed **Option-C spine**
(Foundation → Discovery amplification → Application reasoning → Adaptive allocation → Continuous), adds a small
**Security Floor as a hard gate** in front of it, and makes **evidence provenance a first-class Phase-2 item** — the
one change two independent research streams *and* the code all agree on.

HuntMCP remains a **local security-research application whose moat is CEM (proof), not throughput.** It is not becoming
a platform, a control plane, a generic agent runtime, or a cloud service. The additive substrate is three separable
increments (evidence provenance, an execution-isolation floor, delta re-validation), never a single "platform" project.

The plan is deliberately conservative about ambition: the only work classified **COMMITTED** is what is either
verified-needed (security floor, provenance binding, injection sanitization) or off-the-shelf-small (coverage object,
scan headers). Everything whose value is argued-but-unproven — the full reproducibility manifest, discovery
amplification, the invariant model, adaptive allocation, cross-target transfer, delta re-hunt precision — is
**GATED/MEASURE-FIRST** behind an explicit experiment, not committed. The largest single unknown is whether
provenance/reproducibility actually raises triager acceptance; the plan measures it rather than assuming it.

---

## 2. Final Architecture Direction

- **Core engine (unchanged, frozen):** CEM — the counterfactual proof/validation machinery (`cem_engine.py` +
  `case_store` CEM tables). This is the differentiator and it is not reopened.
- **Additive infrastructure (committed, small):** (a) **evidence provenance** binding discovery-path evidence to real
  HTTP exchanges; (b) an **execution-isolation floor** (rootless per-run boundary + fail-closed, tamper-resistant
  scope enforcement + secrets scoped out); (c) later, **target-delta re-validation**. These extend existing
  primitives; none is a new platform layer.
- **How CEM fits:** stays post-confirmation validation (its determinism gate structurally requires a firing
  capability; `case_store` gates CEM on `CONFIRMED`). CEM is *integrated into hunting* in Phase 3, not moved earlier
  and not redesigned. Its one real incremental question — oracle *reach* for non-HTTP observations — is research-only.
- **How evidence/provenance fits:** the trust layer beneath CEM. Today evidence is tamper-evident (SHA-256) but the
  discovery path is *model-narrated* (`add_evidence(content:str)`). Provenance binding closes that; it is not solved by
  hashing alone.
- **How execution security fits:** a **prerequisite gate**, not a feature and not a platform. Rootless isolation +
  fail-closed hook shrink the whole-host TCB before autonomous breadth expands.
- **How target deltas / re-hunting fit:** a Phase-5 capability that links the (currently unlinked) `watch.db` recon
  snapshots to `case.db` hypotheses — real work, gated on measured re-hunt precision.
- **How future adaptive allocation fits:** deferred to Phase 5, gated on a GO decision, under a hard security-quality
  floor. No router is built now.
- **Intentionally uncommitted:** control plane, cloud/K8s, secret broker build, microVM-local, graph DB,
  event-sourcing, capability-authority subsystem, unrestricted multi-agent parallelism, AI IDE (§13).

---

## 3. Current Reality / Already Implemented (do NOT rebuild)

Verified in code (audit §2/§3):

- **CEM Phase 1** — determinism gate, `classify()` (3–5-valued verdicts), non-vacuous `SuccessSignature`,
  interventions, ddmin minimization, per-trial machine-hashed evidence. **FROZEN.**
- **Hypothesis lifecycle store** — `case_store` hypotheses/findings/experiments/root_causes; evidence-gated CONFIRMED
  (`update_finding_status` refuses zero-evidence confirmation). **Do not build a new "ledger".**
- **Content-addressed evidence** — SHA-256 store. Tamper-evident. (Provenance is the gap, not integrity.)
- **State isolation** — per-engagement dirs + per-session pointer + `file_lock` + WAL.
- **Scope enforcement** — 3-layer deny-by-default incl. PreToolUse hook (present and firing) — but narrow &
  fail-open; hardening, not redesign.
- **Cross-run memory/learning** — memory/writeup/lessons-mcp. **Ahead of competitors; keep.**
- **Continuous recon diffing** — `watch-mcp` snapshots (unlinked to case state — that link is the C3 gap).
- **Human-review-before-submit** — `hackerone-mcp` has no submit tool by design. **Technical control; keep.**
- **`chainer-mcp`** — the real attack DAG (the Xalgorix "ledger-as-graph" claim is rejected; this is the graph).

**Not present (grep-verified):** execution isolation/sandbox, capability-authority tokens, secret broker, provenance
binding, coverage matrix, scan-identification headers, tool-output-injection sanitization.

---

## 4. Canonical Decision Matrix

Categories: **ALREADY IMPLEMENTED · COMMITTED · GATED (measure-first) · DEFERRED · REJECTED.**

| Capability / Initiative | Decision | Phase | Priority | Dependencies | Rationale / Evidence | Acceptance Gate |
|---|---|---|---|---|---|---|
| CEM Phase-1 proof engine | ALREADY IMPLEMENTED | — | — | — | `cem_engine.py`, frozen `#101` | — |
| Hypothesis lifecycle store | ALREADY IMPLEMENTED | — | — | — | `case_store` | — |
| Content-addressed evidence | ALREADY IMPLEMENTED | — | — | — | SHA-256 store | — |
| State isolation / memory / watch diffing | ALREADY IMPLEMENTED | — | — | — | ahead of competitors | — |
| Scope hook fail-closed + CI block-test | COMMITTED | S | P0 | — | fail-open SPOF (audit §9) | out-of-scope call blocked in CI |
| Scope secrets out of untrusted execution | COMMITTED | S | P0 | — | full-`.env` load `dotenv_loader.py` | sandboxed exec cannot read `.env` |
| Execution-isolation floor (C2, rootless) + hook tamper-resistance | COMMITTED | S→3 | P1 | rootless runtime | whole-host TCB; hook neutralizable | adversarial regression: containment + utility |
| `--os-shell` / state-changing confirmation tier | COMMITTED | S | P1 | — | persistent RCE, no gate (audit §9) | RCE requires explicit confirm |
| Evidence provenance binding (C1a / Xalgorix H1) | COMMITTED | 2 | P1 | capture seam | 2 streams + code (`add_evidence:322`) | discovery evidence bound to real exchange |
| Tool-output-injection sanitization (UU-7) | COMMITTED | 2 | P1 | — | live injection surface | injection regression passes |
| Benchmark + telemetry substrate | COMMITTED | 2 | P1 | — | gates all measured items | emits cost/yield/coverage |
| Tool pinning + SBOM + CI SAST | COMMITTED | 2 | P2 | — | unpinned `@latest` (audit §9) | pinned build + SAST in CI |
| Coverage matrix endpoint×class×role (H3 / Coverage Engine) | COMMITTED (small) | 4/measure | P2 | benchmark | absent; needed to measure breadth | matrix populated + anti-gaming clause |
| Scan-identification headers (H4) | COMMITTED (small) | any | P3 | — | polite authorized scan (Xalgorix) | target-only header emitted |
| Full research-run manifest (C1b) | GATED | 2→ | P3 | C1a, benchmark | value unproven | triager-acceptance A/B (XYZ §6.3) |
| Discovery amplification (schemathesis→CEM) | GATED | 3 | P2 | benchmark | amplification unmeasured | WFC/WFD, zero quality-floor loss |
| CEM-in-hunt integration (XYZ P3) | COMMITTED | 3 | P2 | Phase-2 base | wire confirmed→CEM | CEM runs in-hunt; FCC rate stays 0 |
| Structural differentiation evidence (XYZ §2.6) | COMMITTED | 3 | P3 | disclosed_reports | dedupe aid | labeled differentiation emitted |
| SuccessSignature oracle reach — browser/OOB (H2) | GATED (research-only) | research | P4 | — | HTTP-only `:316`; keep CEM pure | only if breadth-blocking; injected `observe_fn` design |
| Invariant model (UU-1) | GATED | 4 | P3 | telemetry | least-tractable (UU V.4) | P4-M0 prototype GO/NO-GO |
| Hypothesis resurrection (UU-2) | COMMITTED (additive query) | 4 | P3 | case_store | no new store | resurrection query ships |
| Info-gain experiment selection (UU-3) | GATED | 4 | P3 | telemetry | needs cost/gain data | measurable selection uplift |
| Adaptive allocation / router | DEFERRED (gated) | 5 | P4 | telemetry | measure-first (memo) | P5-A0 GO |
| Target-delta re-validation (C3) | GATED | 5 | P3 | C1a, watch↔case link | not plumbing (audit §5) | re-hunt precision > cold start |
| Cross-target transfer (memo §9 / XYZ P4) | DEFERRED (gated) | 5 | P4 | signatures | transfer safety unproven | P5-T1 safe-transfer |
| Human-gated toolkit growth (`tool_gaps`) | GATED | 5 | P4 | recurrence signal | human-in-loop (safety) | human approval per addition |
| Capability/tool-exposure layer | DEFERRED | V4 | — | 3rd runtime / drift | premature (Universal-Capability §11) | trigger conditions |
| Resource-aware admission control | DEFERRED | — | — | — | `budget_guard` covers cost axis | — |
| "Confirmation is CEM" / new verifier subsystem | REJECTED | — | — | — | analogy only (audit §4/§6) | — |
| audit_log as evidence store; ledger-as-graph; direction-of-travel; MAPTA/XBOW | REJECTED | — | — | — | XALGORIX-REVIEW §24 | — |
| Control plane / cloud / K8s / secret-broker build / microVM-local / graph DB / event-sourcing / AI IDE / unrestricted parallelism | REJECTED / DEFERRED | — | — | triggers | audit §13 | — |

---

## 5. Final Phase Roadmap

Five phases + a gating Security Floor. Frozen CEM sits beneath all of them (consumed, never modified).

### Phase S — Security Floor  *(gating prerequisite; small; mostly hardening)*
- **Objective:** make expanding autonomous execution safe.
- **Why now:** the current TCB is the whole host; the scope hook fails *open* and is neutralizable by an ungated bash
  file-write (audit §2/§9). Breadth must not expand over this.
- **Prerequisites:** none.
- **Capability groups:** (1) scope hook → fail-closed + CI block-test; (2) scope secrets out of untrusted execution;
  (3) rootless execution boundary (C2) + hook tamper-resistance; (4) `--os-shell`/state-changing confirmation tier.
- **Acceptance / metrics:** an out-of-scope call is blocked in CI; a compromised-agent test cannot read `.env` or
  neuter the hook; state-changing RCE requires confirmation; **legitimate-task utility measured, not just containment.**
- **Exit gate:** adversarial regression (canary-secret exfil via hostile tool output; out-of-scope action; hostile-repo
  checkout) passes on containment **and** utility.
- **Non-goals:** secret broker, capability leases, control plane, microVM.

### Phase 2 — Foundation, Evidence Integrity & Reliability
- **Objective:** a measured, injection-hardened, provenance-bound base.
- **Why now:** every downstream measured item needs telemetry + benchmark; every report needs trustable evidence.
- **Prerequisites:** Phase S P0 items.
- **Capability groups:** (1) benchmark + telemetry substrate; (2) **evidence provenance binding (C1a)** —
  capture-at-wire seam feeding `add_evidence`; (3) tool-output-injection sanitization (UU-7); (4) negative-knowledge +
  capability-utilization signal; (5) supply-chain pinning + SBOM + CI SAST; (6) *optional* C1b manifest, instrumented
  for the acceptance A/B.
- **Acceptance / metrics:** discovery-path evidence bound to a real exchange (not a model string); injection regression
  passes; telemetry emits cost/yield/coverage; false-positive baseline recorded.
- **Exit gate:** benchmark substrate live; provenance verified on stored findings.
- **Non-goals:** invariant model, allocation, discovery breadth.

### Phase 3 — Discovery Amplification + CEM-in-Hunt
- **Objective:** competitive breadth at zero quality-floor loss.
- **Why now:** with a measured, safe, provenance-bound base, breadth can be added and *proven*.
- **Prerequisites:** Phase 2 substrate; **Phase S C2 boundary in place by end of this phase** (breadth = peak
  hostile-content ingestion).
- **Capability groups:** (1) schemathesis→CEM stateful/API falsifiers (GATED); (2) CEM auto-run after independent
  validation; (3) structural differentiation evidence; (4) H4 scan headers (small).
- **Acceptance / metrics:** WFC/WFD breadth up at zero quality-floor loss; CEM runs in-hunt; FCC rate stays 0.
- **Exit gate:** amplification measured positive; quality floor intact.
- **Non-goals:** widening CEM oracle contract (H2 research-only unless breadth-blocking).

### Phase 4 — Application Reasoning + Coverage
- **Objective:** reason about the application's own rules.
- **Prerequisites:** Phase 2 telemetry.
- **Capability groups:** (1) invariant model **(gated by P4-M0 prototype)**; (2) hypothesis resurrection (additive
  `case_store` query); (3) info-gain experiment selection (GATED); (4) coverage matrix H3 (with anti-gaming clause).
- **Acceptance / metrics:** on a long-horizon benchmark, reasoning items beat baseline at no quality-floor loss;
  coverage measurable and non-gameable.
- **Exit gate:** P4-M0 GO/NO-GO recorded; if NO-GO, ship resurrection + info-gain + coverage without deep invariant
  inference.
- **Non-goals:** allocation, transfer.

### Phase 5 — Adaptive Allocation + Continuous / Delta
- **Objective:** amortize validated knowledge; hunt continuously.
- **Prerequisites:** Phase 4 measurement.
- **Capability groups:** (1) adaptive allocation **(gated by P5-A0 GO)**; (2) continuous monitoring + **delta
  re-validation (C3, gated)** + patch-bypass regression; (3) cross-target transfer **(gated by P5-T1)**; (4)
  human-gated toolkit growth.
- **Acceptance / metrics:** allocation improves cost/quality under the security floor or is deferred; C3 beats
  cold-start re-hunt precision/recall.
- **Exit gate:** each gated item ships only on its GO.
- **Non-goals:** self-modification, unattended autonomy, unrestricted parallelism.

*Cross-cutting continuous tracks: Security/Reliability hardening (P2 items); Benchmark & Measurement.*

---

## 6. Security Floor

**Placement: a Phase-0/Phase-S gating precondition** — the audit is explicit that the *floor subset* must precede any
expansion of autonomous execution, not merely run as a continuous side-track.

**Mandatory gates (P0/P1) — block breadth expansion until met:**
- Scope hook **fail-closed** + CI test that an out-of-scope call is actually blocked.
- **Secrets scoped out** of untrusted execution (stop full-`.env` load; per-key; unreadable by sandboxed exec).
- **Execution-isolation floor** (rootless per-run) + **hook tamper-resistance** (bash file-writes above the boundary
  are prevented).
- **`--os-shell`/state-changing confirmation tier.**

**Later hardening (P2, continuous, non-gating):** tool version pinning + SBOM; Python SAST/dep-audit in CI (Xalgorix
insight); CI `permissions:` block; `data/watch.db` untrack + per-engagement path.

**Deferred (with triggers):** resource-aware admission control (budget_guard suffices); capability-authority system;
secret broker (adopt off-the-shelf only on remote/many-keys/untrusted-third-party trigger).

**Discipline:** the floor is small and mostly hardening + one rootless boundary. It must not metastasize into platform
architecture.

---

## 7. CEM Position

- **Frozen/accepted; not reopened.** No regression, missing contract, or cross-phase dependency requires a change to
  the frozen slice.
- **Future integration:** Phase 3 wires every independently-validated finding into CEM (XYZ P3); Phase 5 uses causal
  signatures for variants/transfer (gated).
- **Oracle reach (H2) is a research/incremental question, not a redesign:** `SuccessSignature` matches HTTP responses
  only; browser-execution and OOB-callback oracles are inexpressible. If (and only if) machine-verdicting those becomes
  a breadth bottleneck, address it via an *injected `observe_fn`* preserving `cem_engine.py`'s load-bearing purity —
  never by coupling the engine to network/browser/DB.
- **Not a CEM redesign:** the Xalgorix "verifier" is establish-existence logic HuntMCP already owns (exploit/browser/oob
  confirmation); CEM consumes the *result*. Do not build a competing verifier. "Confirmation is CEM" is rejected as an
  architectural proposition — it is a structural analogy only.
- **Applicable Xalgorix lessons without replacing CEM:** provenance seam (H1/C1a), oracle-reach question (H2), coverage
  object (H3) — all additive, none touching `cem_engine.py`.

---

## 8. Evidence & Provenance Strategy

The verified gap (audit §2, `case_store.py:322` vs `cem_trials`): evidence has **two paths of unequal trust**, and most
reports flow through the weak one.

| Class | Today | Trust | Plan |
|---|---|---|---|
| Model-authored evidence | `add_evidence(content:str)` | hashed string = tamper-evident, **not** provenance | **close via C1a** |
| Machine-captured evidence | `cem_trials.request/response_evidence_hash` | bound to real exchange | keep; extend earlier |
| Confirmation-gated | CEM tables behind `CONFIRMED` | strong but late | provenance must exist **pre**-confirmation |

- **Do not claim the gap is solved because hashes exist.** Hashing proves integrity, not provenance.
- **Smallest useful milestone first (C1a):** a capture-at-the-wire seam so that discovery/pre-confirmation evidence is
  bound to the actual HTTP request/response that produced it, not to a string the model typed. This is COMMITTED
  (Phase 2), highest confidence — two independent streams + code.
- **Full reproducibility manifest (C1b)** — tool/model/policy versions + target-snapshot hash — is **GATED**: sound and
  cheap, but its incremental value (does it raise triager acceptance beyond C1a's integrity?) is unproven. Instrument
  it, run the A/B, promote only on evidence.

---

## 9. C1 / C2 / C3 Placement

- **C1a (provenance foundation):** COMMITTED, Phase 2, P1. The concrete, cross-stream-validated core.
- **C1b (full run manifest):** GATED, Phase 2 optional → promote via triager-acceptance A/B. Not a headline; not
  proven.
- **C2 (execution boundary / security floor):** COMMITTED as a **floor**, Phase S, in place by end of Phase 3. Rootless,
  swappable boundary; microVM stays a future-remote option behind the abstraction. Not a capability bet, not a platform.
- **C3 (target-delta → affected hypotheses → targeted re-validation):** GATED, Phase 5. Real work (watch/case unlinked);
  depends on C1a + a watch↔case link; gated on measured re-hunt precision.
- **Not collapsed:** these are three separable increments across existing phases, never one "platform" project.

---

## 10. Xalgorix-Derived Lessons (surviving dispositions)

Per XALGORIX-REVIEW (corrective authority):

- **Provenance (H1):** ADOPT = C1a (Phase 2). The highest-impact convergent finding.
- **Oracle reach (H2):** RESEARCH-ONLY, gated. One-dataclass question; keep CEM pure.
- **Coverage matrix (H3):** ADOPT (small), Phase 4/measurement; anti-gaming clause required.
- **Scan-identification headers (H4):** ADOPT (small), any phase; correct destination boundary.
- **Deterministic confirmation patterns:** ALREADY HAVE stronger (CEM verdict machinery dominates k=1 confirmers) — no
  work.
- **Hypothesis ledger:** ALREADY HAVE (`case_store`) — no new store; resurrection is an additive query.
- **Evidence capture/reporting seam:** = C1a.
- **Verifier *environment* isolation:** insight → reinforces C2.
- **Secure-SDLC CI (gosec/semgrep/govulncheck/-race):** ADOPT (insight) → Python-equivalent SAST/dep-audit in CI (P2).
- **Do NOT copy wholesale:** the 22-phase prompt-constant, control-plane RCE console, resource-admission subsystem,
  ledger-as-graph framing, direction-of-travel narrative — all rejected/deferred.

---

## 11. Measurement & Promotion Gates

Every GATED item promotes only on evidence. If it fails its experiment, it is deferred with a recorded reason — never
shipped on argument.

| Hypothesis | Metric | Minimum experiment | Promotion criterion | If it fails |
|---|---|---|---|---|
| Provenance/reproducibility raises acceptance (C1b) | triager acceptance, time-to-triage, needs-info rate | A/B: findings with vs without manifest (XYZ §6.3) | acceptance uplift, no time regression | keep C1a integrity; drop C1b as headline |
| Discovery amplification (schemathesis→CEM) | new confirmed findings / target; FCC rate | run on WFC/WFD + constructed labs | breadth up, FCC=0 | defer amplification; keep CEM-in-hunt |
| C3 delta re-hunt beats cold start | re-hunt precision/recall vs cold | inject target delta; compare | higher precision at lower cost | keep watch diffing as alerting only |
| Invariant model tractable | invariant recall/precision | P4-M0 shallow prototype | prototype meets bar | ship resurrection+info-gain+coverage only |
| Rootless boundary preserves utility | legitimate-task success under isolation | Phase-S exit regression | containment high, utility ≈ baseline | narrow the profile; keep boundary, relax policy |
| Adaptive allocation pays off | cost/quality under security floor | P5-A0 offline eval | improvement, no quality-floor loss | defer allocation; Phase 5 completes without it |
| Cross-target transfer is safe | transfer precision; false-positive import | P5-T1 held-out targets | proven safe transfer | defer transfer |

---

## 12. Dependency Graph

```
                 [ FROZEN: CEM Phase 1 ]  ── consumed by every phase, modified by none
                              │
Phase S (Security Floor: fail-closed hook, secrets-out, rootless C2, os-shell confirm)   ← GATE
                              ↓
Phase 2 (Benchmark+telemetry · Evidence provenance C1a · UU-7 injection · pinning/SBOM)
     │                                   │
     │ (C1b gated: A/B)                  ↓
     └────────────────────►  Phase 3 (Discovery amplification[gated] · CEM-in-hunt · differentiation · H4)
                                          │  (C2 boundary in place by end of Phase 3)
                                          ↓
                             Phase 4 (Invariant model[P4-M0 gate] · resurrection · info-gain[gated] · coverage H3)
                                          ↓
                             Phase 5 (Adaptive allocation[P5-A0] · Continuous + delta C3[gated] · transfer[P5-T1] · human-gated toolkit)
```

Derived from the audit's ordering (not the prompt's illustrative example). Security floor precedes everything;
provenance precedes discovery breadth; measurement precedes reasoning; reasoning/telemetry precede allocation; C3
depends on C1a + a watch↔case link.

---

## 13. Anti-Roadmap (intentionally NOT built this horizon)

Evidence-based, not ideological:

- **Generic control plane / multi-tenant SaaS / billing** — no scale justifies it. DEFER (trigger: multi-user).
- **Cloud / Kubernetes-first / distributed** — no demand. DEFER (keep exec boundary swappable so it stays possible).
- **Local microVM / bespoke VM platform** — overkill; rootless is the practical boundary. DEFER (trigger: remote exec).
- **Custom secret broker** — mature off-the-shelf; scoping secrets out gets ~80% now. ADOPT-WHEN-TRIGGERED, never build.
- **Graph database / event-sourcing** — SQLite + `chainer-mcp` DAG suffice; already rejected. NO.
- **New "verifier" subsystem** — duplicates existing confirmation + frozen CEM. NO.
- **Resource-aware admission control** — `budget_guard` covers the axis. DEFER.
- **Capability-authority subsystem** — subsumed near-term by the fail-closed monitor + rootless floor + scoped secrets.
  DEFER (trigger: mutually-distrusting agents).
- **AI IDE / generic agent platform / capability marketplace / unrestricted multi-agent parallelism** — off-mission;
  parallelism stays a measured design-only backlog. DEFER/REJECT.

---

## 14. Implementation Entry Conditions

Implementation may begin when:

1. **Frozen:** CEM Phase-1 remains frozen; the hypothesis-lifecycle store, evidence content-addressing, scope-enforcement
   *design*, and human-review-before-submit are treated as fixed (harden behaviour, do not redesign).
2. **First work = Phase S security floor.** Nothing that expands autonomous execution begins until the Phase-S exit gate
   passes (fail-closed hook + CI test, secrets-out, rootless boundary + tamper-resistance, os-shell confirm).
3. **Baselines exist before Phase 3:** benchmark substrate + telemetry emitting cost/yield/coverage + a false-positive
   baseline (Phase 2), and **evidence provenance (C1a) verified on stored findings.**
4. **Do not rebuild** anything in §3 (already implemented).
5. **Phase gate discipline:** a phase's GATED items ship only on their promotion criterion (§11); a failed gate defers
   the item with a recorded reason and the phase completes without it.
6. **Protected-doc edits** (folding this plan into `ROADMAP.md`/`MASTER-ROADMAP-PROPOSAL.md`/execution plan) require a
   separate, explicitly human-authorized task — this file does not perform them.

---

## 15. Success Metrics

"HuntMCP Next-Gen" success is **measured by hunting outcomes, never by agent/MCP/prompt/feature count.**

- **Confirmed-finding precision** (evidence-gated, FCC rate stays 0).
- **Evidence quality / provenance** — share of reported evidence bound to a real exchange (C1a), and (if promoted)
  triager-acceptance uplift (C1b).
- **Useful coverage** — endpoint×class×role, non-gameable (H3).
- **Experiment efficiency** — cost/time/tool-calls per confirmed finding; info-gain selection uplift.
- **Repeated-target improvement / re-hunt precision** — C3 beats cold start.
- **Discovery breadth at zero quality-floor loss** — WFC/WFD.
- **Long-horizon reliability & regression resistance** — patch-bypass regression catches reintroductions.
- **Safe autonomous operation** — the Phase-S adversarial regression stays green through the lifecycle (create → run →
  pause → resume → terminate), containment high with legitimate-task utility preserved.

---

## 16. Open Questions

1. **Does provenance/reproducibility raise triager acceptance?** (C1b, and the ultimate justification for evidence work
   beyond C1a integrity.) Unproven — the single largest unknown; measured, not assumed.
2. **Is the browser/OOB oracle gap (H2) actually breadth-blocking?** Only then does it earn work.
3. **C3 re-hunt precision** vs cold start — the affected-hypothesis mapping's accuracy is the crux; unmeasured.
4. **schemathesis→CEM amplification magnitude** — assumed high-leverage, unmeasured.
5. **Invariant-model tractability** — flagged least-tractable; P4-M0 gate stands.
6. **Rootless-boundary utility cost** — will isolation break legitimate tool flows? Phase-S exit measures it.
7. **Adaptive allocation & cross-target transfer** — payoff and safety unproven; both gated.

---

## 17. Final Freeze Criteria

The architecture may be frozen for implementation when:

- The Canonical Decision Matrix (§4) is accepted as-is (no reopened settled decisions).
- CEM Phase-1 is confirmed untouched by every committed item (verified: only `case_store` provenance and the security
  floor touch adjacent code; `cem_engine.py` is not modified).
- The Security Floor (§6) is accepted as a gating precondition.
- Evidence provenance (C1a) is accepted as the first-class Phase-2 item.
- Every GATED item (§11) has its experiment and promotion criterion recorded before any work on it starts.
- The Anti-Roadmap (§13) is accepted, so deferred/rejected items are not silently reintroduced.
- The protected-doc integration (§14.6) is authorized as a separate task.

Once these hold, Phase S may begin. No further research is required to start; the remaining unknowns are all
**empirical questions with assigned gates**, not open design questions.

---

## Report

- **Source documents used:** `MASTER-ROADMAP-AUDIT.md` (primary authority); `XYZ.md`, `ARCHITECTURE.md`, `ROADMAP.md`,
  `MASTER-ROADMAP-PROPOSAL.md`, `PHASE1-PLAN.md`, `PHASE1-EXECUTION-PLAN.md`, `INTELLIGENCE-ALLOCATION-MEMO.md`,
  `UNKNOWN-UNKNOWN-RESEARCH.md`, `UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH.md`, `OPEN-SOURCE-AUDIT.md`,
  `NEXT-GEN-PLATFORM-RESEARCH.md`, `XALGORIX-RESEARCH.md`, `XALGORIX-REVIEW.md`. **`NEXT-GEN-PLATFORM-REVIEW.md` is
  absent** — its review role is served by `NEXT-GEN-PLATFORM-RESEARCH.md` §63.
- **Major decisions inherited from the audit:** Option-C spine kept; Security Floor made a gating precondition; evidence
  provenance elevated to first-class Phase-2 (C1a); C1 split (C1a committed / C1b gated); C3 reclassified as real gated
  work; CEM frozen with oracle-reach (H2) research-only; four Xalgorix items carried (H1–H4); "confirmation is CEM",
  platform over-scope, control plane/broker/microVM/graph DB, and resource-admission rejected/deferred.
- **Unresolved ambiguity:** exact phase placement of C1b/C2/C3 is defensible but a product call (audit medium
  confidence); all §16 items are empirical, each with an assigned gate. No open *design* question blocks starting
  Phase S.
- **Exact file created:** `MASTER-ROADMAP-FINAL.md`. No other file was modified; nothing was implemented, committed, or
  pushed.
