# IMPLEMENTATION-TASK-TRACKER.md — HuntMCP (from frozen `MASTER-ROADMAP-FINAL-v3.md`)

**Status:** planning artifact only. No implementation performed; no source code, roadmap, architecture, or thesis doc
modified. Planning authority: `MASTER-ROADMAP-FINAL-v3.md` (frozen canonical). Current-state reconciled against the
working tree `@fbbf26d` (this session's code verifications).

**Not an authorization to build.** Implementation begins only when v3 §14 entry conditions are met, task by task, in
dependency order.

---

## 1. Task-tracking rules (per `CLAUDE.md`)

- `[ ]` not started
- `[~]` in progress / partially implemented (integration, tests, or verification missing)
- `[x]` completed **and verified** — implementation **+** required tests **+** verification **+** applicable
  acceptance gates all present
- `[!]` blocked / requires human decision

A parent is never `[x]` while any required child remains. "Substrate exists" ≠ "capability complete." No gated research
item is `[x]` until its gate has actually passed.

---

## 2. Current Implementation Baseline (reconciliation)

| Capability | Current implementation | Tests | Real status | What remains |
|---|---|---|---|---|
| CEM Phase-1 proof engine | `cem_engine.py`, `case_store` CEM tables | `tests/test_cem_benchmark.py` + `fixtures/cem_target/` | **[x] FROZEN/VERIFIED (#101)** | nothing — do not rebuild |
| Hypothesis lifecycle store | `case_store` hypotheses/findings/evidence/experiments | case-store tests | [x] baseline | provenance + lineage (see C1a) |
| Content-addressed evidence | SHA-256 store (`add_evidence(content:str)`) | yes | [~] integrity only | provenance binding (C1a) |
| Scope enforcement | 3-layer + PreToolUse `scope_gate_hook.py` | partial | **[~] fail-OPEN, narrow** | fail-closed + tamper-resist + CI test (S1/S2/S6) |
| Secret handling | `dotenv_loader` loads full `.env` into `os.environ` | — | **[~] over-broad** | secrets-out (S3) |
| Engagement/state isolation | `engagement_paths.py`, `file_lock`, WAL | yes | [x] baseline | — |
| Cross-run memory/knowledge | memory/writeup/lessons-mcp | yes | [x] baseline | — |
| Continuous recon diffing | `watch-mcp` snapshots (⊥ `case.db`) | yes | [~] recon-only | watch↔case link (C3) |
| Authorization testing baseline | `idor-mcp sweep_idor` (single-request, two-account) | yes | [x] baseline | multi-step/role-matrix engine (VAL-AUTHZ) |
| Attack-chain DAG | `chainer-mcp` | yes | [x] baseline | — (this is "the graph"; no graph DB) |
| Human-review-before-submit | `hackerone-mcp` read-only (no submit tool) | — | [x] control | preserve |
| Budget / audit / jobs | `budget_guard.py`, `audit_log.py`, `job_runtime.py` | yes | [x] baseline | — |
| Toolkit-gap capture | `tool_gaps.py` (bounded first step) | yes | [~] capture only | human-gated growth (P5-TOOLKIT) |
| Second-opinion review | `second-opinion-mcp` (cross-model) | yes | [x] baseline | (env-isolation unexamined) |
| CI | `.github/workflows/ci.yml` (ruff, py_compile, bash -n) | — | [~] | scope-gate block-test + SAST/dep-audit (S2, P2-SC) |
| Execution isolation / sandbox | **none** (grep=0) | — | **[ ]** | Tier-2 (S5/S6) |
| Telemetry / coverage / postmortem / provenance | **none** | — | **[ ]** | P2 work packages |
| schemathesis / discovery amplification | **absent** | — | **[ ]** | P3 |

---

## 3. Phase S — Security Floor (gating prerequisite; two tiers)

*Ordering (frozen, v3 §6/§14): Tier-1 before ANY autonomous breadth; **Tier-2 MUST complete before Phase-3 breadth
begins.** Tier-2 is NOT optional.*

| ID | St | Task · Why | Deps | v3 § |
|---|---|---|---|---|
| **S1** | [x] | Scope hook **fail-closed** for target-touching calls (internal error blocks the *gated call*, not the session). *Why:* current hook fails open; SPOF. | — | §6 Tier-1 |
| **S2** | [~] | CI **scope-gate block-test** — prove an out-of-scope call is actually blocked. *Why:* fail-open registration SPOF. Implementation + tests + local verification done (incl. a clean-clone run reproducing CI's exact job/dependency set); the tracker's own §10 evidence requirement ("CI run") is not yet satisfied since this job hasn't executed on GitHub Actions — flip to [x] after the first real CI run passes. | S1 | §6 Tier-1 |
| **S3** | [ ] | **Secrets-out** of untrusted execution — per-key injection; `.env` unreadable by sandboxed exec. *Why:* full-`.env` load is harvestable. | — | §6 Tier-1 |
| **S4** | [ ] | **`--os-shell` / state-changing confirmation tier** — explicit human confirm. *Why:* persistent RCE, no distinct gate today. | — | §6 Tier-1 |
| **S5** | [ ] | **Rootless per-run execution boundary** (swappable; no root; egress-restricted). *Why:* whole-host TCB. | S1–S4 | §6 Tier-2 |
| **S6** | [ ] | **Hook tamper-resistance** — bash file-writes above the boundary prevented. *Why:* hook neutralizable mid-session. | S5 | §6 Tier-2 |
| **S-GATE** | [ ] | **Tier-2 exit gate** — adversarial regression (canary-secret exfil via hostile tool output; out-of-scope action; hostile-repo checkout) passing on **containment AND legitimate-task utility**, across the lifecycle (create→run→pause→resume→terminate). **Blocks Phase-3 breadth.** | S5,S6 | §6, §11(rootless), §14.2 |

---

## 4. Phase 2 — Foundation, Evidence Integrity, Introspection & Reliability

*Prereq: Phase-S Tier-1 (S1–S4).*

| ID | St | Task · Why | Deps | v3 § |
|---|---|---|---|---|
| **P2-BENCH** | [ ] | Benchmark + telemetry substrate: standing multi-class ground-truth range (blind, protected) + frontier reference arm; emit cost/yield/coverage. *Note:* CEM-specific benchmark already exists (`test_cem_benchmark.py`) and may be **extended**, not rebuilt. | S1 | §4, §5(P2), §11 |
| **P2-TEL** | [ ] | Passive telemetry: HTTP/tool/wall-clock/token yield linked to findings (offline; 0 hot-path cost). | P2-BENCH | §5(P2), §15 |
| **C1a** | [ ] | Evidence **provenance binding** — capture seam feeding `add_evidence`: **wire-level** provenance for structured sources (curl/`tool_resolver`, `browser-mcp`, `oob-mcp`, CEM `fetch_fn`, VAL-AUTHZ `http_probe`); **invocation-level** provenance for scanner-narrated output. *Why:* discovery-path evidence is model-narrated today. | — | §8, §9 |
| **P2-E1** | [ ] | **Hunt postmortem / self-evaluation** — analysis-only, read-only, no tools, no auto-retry, no self-modification, no policy mutation; evidence-cited (cites `audit_log`/`case_store`); planted-fixture precision/recall; independent cross-check vs raw stores; redaction verified. | P2-TEL, `case_store`, `dedupe_check` | §5(P2 spec) |
| **P2-INJ (UU-7)** | [ ] | Tool-output-injection sanitization / quarantine. *Why:* live injection surface. | — | §4, §5(P2) |
| **P2-NK** | [ ] | Negative-knowledge + capability-utilization signal. | P2-TEL | §5(P2) |
| **P2-COV** | [ ] | **Minimal coverage instrument (H3 core)** — produce the coverage signal used in P2/P3. *Why:* metric must exist before it is a decision signal. | P2-BENCH | §4, §5(P2), §12 |
| **P2-SC** | [ ] | Supply-chain: pin tool versions + SBOM; Python SAST/dep-audit in CI; CI `permissions:`; `data/watch.db` untrack + per-engagement path. | — | §4, §6(P2 hardening) |
| **C1b** | [ ] GATED | Full research-run manifest (tool/model/policy versions + target-snapshot hash), instrumented for the acceptance A/B. **Do not promote without evidence.** | C1a, P2-BENCH | §8, §9, §11 |

---

## 5. Phase 3 — Discovery Amplification, Authorization Differential + CEM-in-Hunt

*Prereq: Phase-2 substrate; **Phase-S Tier-2 (S-GATE) complete before breadth begins.***

| ID | St | Task · Why | Deps | v3 § |
|---|---|---|---|---|
| **P3-DEP** | [!] | **Human decision:** approve `schemathesis` (and a spec parser only if hand-rolled proves insufficient) per dependency-budget. *Why:* new dependency = stop-condition. | — | §5(P3), §14.6 |
| **P3-SCHEMA** | [ ] GATED | schemathesis→CEM stateful/API property falsifiers. *Complementary to VAL-AUTHZ (property-fuzz vs authz-differential).* | P3-DEP, S-GATE, P2-BENCH | §4, §5(P3) |
| **P3-ADAPTER** | [ ] | property→hypothesis→CEM adapter (each falsifier hit becomes a hypothesis fed to CEM). | P3-SCHEMA | §5(P3) |
| **P3-CEMHUNT** | [ ] | CEM auto-run after independent validation **preserving the existing CEM entry precondition** (`CONFIRMED`/determinism gate). *Not a CEM change.* | CEM (frozen), case_store | §5(P3), §7 |
| **P3-DIFF** | [ ] | Structural differentiation evidence vs disclosed reports (dedupe aid). | `disclosed_reports` | §4, §5(P3) |
| **P3-DISCSPEC** | [ ] | **DISC-SPEC** — parse OpenAPI/GraphQL into a stateful endpoint/parameter model (hand-rolled first; treat spec as untrusted) feeding scan targeting **and VAL-AUTHZ workflow capture**. | — | §4, §5(P3) |
| **P3-VALAUTHZ** | [ ] GATED | **VAL-AUTHZ (min)** — stateful/multi-step **authorization differential**: (a) strengthen sweep oracle to **owner-fetch-and-compare**; (b) **two-step replay** (capture workflow as identity A; replay step N under identity B holding earlier steps); (c) role/identity matrix (unauth/low-priv/admin/tenant-B). Emit findings to `case_store.create_finding` with CEM conditions (identity, step-order, carried id). **Idempotent/read-GET default; state-changing steps require human gate; `scope_guard` every request.** *Must NOT be `[x]` merely because code exists — the benchmark must show multi-identity/stateful differential behavior at zero new FP.* | S-GATE, P2-BENCH, benefits from P3-DISCSPEC; extends `idor-mcp` | §4, §5-VA, §11, §12 |
| **P3-FANOUT** | [ ] | **Bounded, dedupe-aware** parallel fan-out (concurrency for discovery only). *Guardrail:* bounded; **unrestricted parallelism remains rejected (§13).** | P2-BENCH | §13 (bounded only) |
| **P3-H4** | [ ] | Scan-identification headers (target-only, correct destination boundary). | — | §4, §5(P3) |
| **P3-ASSETGRAPH** | [!]/REJECTED | "Asset Graph" as a graph-DB substrate is **NOT a committed v3 capability** — `chainer-mcp` is the DAG; graph DB is rejected (§13). Listed to avoid silent omission; no active task unless a future human decision revisits it. | — | §13, §10-A |

---

## 6. Phase 4 — Application Reasoning + Coverage

*Prereq: Phase-2 telemetry + coverage instrument. M0 failure blocks ONLY M1 — not the independent P4 items.*

| ID | St | Task · Why | Deps | v3 § |
|---|---|---|---|---|
| **P4-M0** | [ ] GATED | Invariant-model **prototype** (shallow) → GO/NO-GO. *Why:* invariant inference is the least-tractable bet. | P2-TEL, P2-BENCH | §4, §5(P4) |
| **P4-M1** | [!] | Full invariant model — **blocked on P4-M0 GO only**. Invariants remain **CEM-provable hypotheses**; invariant **false positives are a quality risk**, not findings. | P4-M0 GO | §5(P4) |
| **P4-RESURRECT** | [ ] | Hypothesis resurrection — additive `case_store` query (no new store). **Independent of M0.** | case_store | §4, §5(P4) |
| **P4-INFOGAIN** | [ ] GATED | Info-gain experiment **ordering** — **orders, never hard-blocks a novel test.** **Independent of M0.** | P2-TEL | §4, §5(P4), §11-A |
| **P4-SIG** | [ ] | Causal signatures from CEM minimal-sets (feeds P5 transfer/variants). | CEM (frozen) | §5(P4/P5) |
| **P4-ESCALATE** | [ ] | Human escalation as an **information-value** mechanism (not approval-fatigue). | P2-TEL | §5(P4) |
| **P4-BM** | [ ] | **Blind, independent** long-horizon benchmark (sustained investigation, multi-identity, business-logic, target-change, hypothesis persistence/resurrection, recovery, quality of a correct no-finding). | P2-BENCH | §5(P4), §11 |
| **P4-COVMATRIX** | [ ] | Full coverage matrix endpoint×class×role (H3) **with anti-gaming clause**. | P2-COV | §4, §5(P4) |
| **P4-PM+** | [ ] | Postmortem **extensions** (e.g. `missed_chain_opportunities`) — *extends* P2-E1, analysis-only. | P2-E1 | §5(P4) |
| **P4-VALCOND** | [ ] DEFERRED | Autonomous CEM condition extraction — human-supplied default retained; parity gate (no new false necessity). | CEM, P2-BENCH | §4 (VAL-COND) |

---

## 7. Phase 5 — Adaptive Allocation + Continuous / Delta *(GATED research program — not guaranteed builds)*

| ID | St | Task · Why | Deps | v3 § |
|---|---|---|---|---|
| **P5-A0** | [!] | **STOP/GO** decision to authorize the allocation program. | P4 measurement | §5(P5), §11 |
| **P5-A1** | [ ] GATED | **A/B/C/D experiment** (A frontier-heavy · B fixed-mixed · C adaptive · D CEM-assisted), held-out/blind; **C-vs-D kept separate = the entire attribution of CEM's contribution**. | P5-A0 GO, P4-SIG | §5(P5), §11 |
| **P5-ALLOC** | [!] | Adaptive allocation policy — **only after P5-A0 GO and passing the floor+invariants**. Never suppress a novel test; cheap-tier premature-closure guard. | P5-A0 GO, P5-A1 | §5(P5), §11-A |
| **P5-T1** | [ ] GATED | CEM signature-transfer experiment (same/similar/cross-target). Gate: **false-reuse→missed-test == 0.** | P4-SIG, P5-A0 | §5(P5), §11 |
| **P5-AMORT** | [!] | CEM amortization / signature reuse — **only after P5-T1 proves safe transfer**. | P5-T1 pass | §5(P5) |
| **C3** | [ ] GATED | Continuous monitoring + **delta re-validation** (watch↔case link → affected hypotheses → CEM re-run) + patch-bypass regression. Gate: re-hunt precision > cold start. | C1a (should-use), watch↔case link | §4, §5(P5), §9 |
| **P5-VARIANT** | [ ] GATED | Active counterfactual variant discovery (DISC-VARIANT) — rides CEM; zero double-report. | CEM, P4-SIG | §4, §5(P5) |
| **P5-XTARGET** | [ ] DEFERRED | Cross-target technique induction — no cross-target contamination; gated by P5-T1. | P5-T1 | §4, §5(P5) |
| **P5-ANTIANCHOR** | [ ] | Anti-anchoring — realized via C-vs-D attribution + blind ground truth (not a separate engine). | P5-A1 | §5(P5), §11-A |
| **P5-ROUTER** | [ ] DEFERRED | Skill Router / capability-exposure layer — DEFERRED to V4 (trigger conditions). | trigger | §4 (V4) |
| **P5-TOOLKIT** | [~] | Human-gated toolkit growth — `tool_gaps.py` capture exists (bounded first step); **growth requires human approval per addition**. | tool_gaps, recurrence signal | §4, §5(P5) |

---

## 8. Human-Decision Blockers `[!]`

| ID | Decision required | Blocks |
|---|---|---|
| P3-DEP | approve `schemathesis` / spec-parser dependency | P3-SCHEMA (breadth) |
| (S5 dep) | approve rootless runtime dependency | S5/S6 Tier-2 |
| P4-M0 | invariant-model GO/NO-GO | P4-M1 only |
| P5-A0 | allocation STOP/GO | P5-A1/ALLOC |
| P5-T1 | transfer-safety promotion | P5-AMORT/P5-XTARGET |
| C1b | manifest promotion (A/B outcome) | C1b build |
| ROADMAP-INT | authorize folding v3 into protected docs (`ROADMAP.md`/proposal/exec-plan) | canonicalization |
| V4-TRIGGER | capability-exposure layer (3rd runtime / drift) | P5-ROUTER |

*Not converted into "already decided" implementation tasks.*

---

## 9. Dependency Graph

```
[x] CEM Phase 1 (FROZEN)  ── consumed everywhere, modified nowhere
        │
S Tier-1 (S1 S2 S3 S4)                 ← HARD GATE before any autonomous breadth
        ↓
Phase 2 (P2-BENCH · P2-TEL · C1a · P2-E1 · P2-INJ · P2-NK · P2-COV · P2-SC ; C1b gated)
        │
S Tier-2 (S5 S6 → S-GATE)              ← GATE before Phase-3 breadth
        ↓
Phase 3 (P3-DEP[!] → P3-SCHEMA · P3-ADAPTER · P3-CEMHUNT · P3-DIFF · P3-DISCSPEC → P3-VALAUTHZ · P3-FANOUT · P3-H4)
        ↓
Phase 4 (P4-M0 →(GO) P4-M1 ;  P4-RESURRECT · P4-INFOGAIN · P4-SIG · P4-ESCALATE · P4-BM · P4-COVMATRIX · P4-PM+  independent of M0)
        ↓
Phase 5 (P5-A0[!] → P5-A1 → P5-ALLOC ;  P5-T1 → P5-AMORT/P5-XTARGET ;  C3 ; P5-VARIANT ; P5-TOOLKIT)
```

Independent-not-serialized: P2 items run in parallel; P4-RESURRECT/INFOGAIN/BM/COVMATRIX do not wait on P4-M0; P3-H4 is
off the critical path; C3 needs only C1a + the watch↔case link (not the whole of P4).

---

## 10. Acceptance-Evidence Matrix

*Every non-trivial task's required evidence. "n/a" = category not applicable, with reason.*

| ID | Implementation | Tests | Runtime verification | Adversarial / security | Acceptance gate |
|---|---|---|---|---|---|
| S1 | fail-closed target-touch path | unit: block on error | live: gated call blocked | inject malformed/hostile hook input | out-of-scope call blocked; benign session not broken |
| S2 | CI job | CI smoke test | CI run | out-of-scope fixture call | CI fails if not blocked |
| S3 | per-key secret injection | unit | live: tool sees only its key | compromised-agent `cat .env` test | sandboxed exec cannot read `.env` |
| S4 | confirm tier | unit | live prompt | attempt os-shell w/o confirm | RCE requires explicit confirm |
| S5/S6/S-GATE | rootless boundary + tamper-resist | unit | lifecycle run | **adversarial regression corpus** | containment **AND** utility; lifecycle-stable |
| P2-BENCH | multi-class range | harness self-test | run baseline | ground-truth blind/protected | frontier arm + labels reproducible |
| P2-TEL | telemetry emit | unit | offline capture | n/a (offline; no hot-path) | cost/yield/coverage emitted, 0 hot-path cost |
| C1a | capture seam | unit | live: evidence↔exchange bound | tamper/forge attempt | discovery evidence carries strongest-available provenance |
| P2-E1 | offline analyzer | unit | **planted-fixture recall** | prove read-only (no writes/tools) | recall bar; independent cross-check clean; redaction verified |
| P2-INJ | sanitizer | unit | injection regression | hostile tool-output corpus | injection regression passes |
| P2-COV | coverage signal | unit | run on benchmark | anti-gaming probe | signal produced + benchmarked |
| P2-SC | pin+SBOM+SAST | CI | CI run | dependency-audit | pinned build; SAST in CI |
| C1b | manifest | unit | A/B instrumentation | n/a | **triager-acceptance A/B** (promote only on uplift) |
| P3-SCHEMA | schemathesis→CEM | unit | WFC/WFD run | n/a | breadth up; **quality floor held**; FCC==0 |
| P3-CEMHUNT | wiring | unit | in-hunt run | verify entry precondition intact | CEM runs in-hunt; FCC==0 |
| P3-VALAUTHZ | oracle+replay+matrix | unit | run on benchmark | state-changing → human gate; scope on every req | **recovers multi-step authz the sweep misses; ZERO new FP; verdicts match ground truth**; rollback flag→sweep |
| P3-DISCSPEC | spec parser | unit | endpoints recovered | spec treated as untrusted | measurable surface gain feeding authz/scan |
| P4-M0 | prototype | unit | blind benchmark | n/a | GO/NO-GO recorded |
| P4-M1 | invariant model | unit | blind benchmark | invariant FP is a quality risk | quality floor held; invariants stay CEM-provable |
| P4-RESURRECT | query | unit | run | n/a | machine-checkable resurrection predicate |
| P4-INFOGAIN | ordering | unit | run | never hard-blocks a novel test | measurable uplift; novel tests never suppressed |
| P4-BM | benchmark | harness | run | blind/independent | protected ground truth; anti-gaming |
| P4-COVMATRIX | matrix | unit | run | anti-gaming clause | non-gameable coverage |
| P5-A1 | A/B/C/D | harness | held-out run | blind | C-vs-D attribution under floor+invariants |
| P5-T1 | transfer exp | harness | 3 conditions | stale-signature-never-authoritative-skip | **false-reuse→missed-test == 0** |
| C3 | watch↔case + re-run | unit | delta-injection run | no cross-target leakage | re-hunt precision > cold start |
| P5-TOOLKIT | gated growth | unit | run | human approval per addition | no self-modification; human-gated |

---

## 11. Safety / Quality Floors (apply to all applicable tasks; never weakened)

**Absolute security invariants (zero-tolerance):** CEM **FCC == 0**; **false-reuse→missed-test == 0**;
allocation/dedupe/negative-knowledge **never hard-block a not-yet-confirmed novel test**; **cheap-tier
premature-closure guard**; non-idempotent/state-changing actions require appropriate approval (human gate);
**no self-modifying execution**; **no uncontrolled cross-target leakage**; postmortem is analysis-only;
human-review-before-submit preserved.
**Quality floor (hard-fail on high/critical):** high/critical recall ≥ baseline − ε; FP ≤ baseline; coverage ≥
baseline (P3, P5).
**Benchmark integrity:** blind, protected, evaluator-only ground truth; no auto-derived oracle; anti-gaming
(`.claude/rules/benchmarks.md`). Any change to protected benchmark methodology = human approval.

---

## 12. Overall Progress Summary

| Phase | [x] | [~] | [ ] | [!] | Notes |
|---|---|---|---|---|---|
| CEM Phase 1 | 1 (frozen) | — | — | — | do not rebuild |
| Baseline substrate | 8 | 6 | — | — | substrate ≠ roadmap capability |
| Phase S | — | — | 6 | — | S1–S6 + S-GATE; Tier-2 gates P3 |
| Phase 2 | — | — | 8 | — | +C1b GATED |
| Phase 3 | — | — | 8 | 1 (P3-DEP) | VAL-AUTHZ GATED; Asset-Graph rejected |
| Phase 4 | — | — | 8 | 1 (P4-M1 on M0) | +VAL-COND deferred |
| Phase 5 | — | 1 (toolkit) | 6 | 3 (A0/ALLOC/AMORT) | gated research program |
| Human blockers | — | — | — | 8 | §8 |

**Nothing in Phases S–5 is `[x]`.** Only CEM Phase-1 and existing substrate primitives are complete/verified. The
**first actionable work is Phase-S Tier-1 (S1–S4)**; no roadmap capability is `[x]`, no gated item is `[x]`, no human
decision is treated as resolved.

---

## 13. Final Check (per task §17)

- ✅ CEM Phase-1 marked `[x] FROZEN` — **not** decomposed or duplicated.
- ✅ No roadmap capability silently omitted — every v3 §4 matrix item + §10-A older-stream item is represented
  (VAL-AUTHZ present as P3-VALAUTHZ GATED; DISC-SPEC as P3-DISCSPEC; VAL-COND deferred; DISC-VARIANT as P5-VARIANT;
  ARCH-STATE = the P2-TEL/C1a provenance area + a deferred recon/scan-wiring note; LEARN-KG/graph rejected;
  Asset-Graph rejected).
- ✅ No partial implementation marked `[x]` (scope hook, secrets, evidence-integrity all `[~]`/`[ ]`).
- ✅ No gated research marked `[x]` (P3-SCHEMA, P3-VALAUTHZ, C1b, P4-M0, P5-A1, P5-T1, C3, P5-VARIANT all GATED/`[ ]`).
- ✅ No human decision treated as resolved (P3-DEP, P4-M0, P5-A0, P5-T1, C1b, ROADMAP-INT, V4 all `[!]`).
- ✅ **VAL-AUTHZ present** (P3-VALAUTHZ, GATED, multi-identity/stateful benchmark).
- ✅ **P2-E1 present** (full analysis-only guardrails).
- ✅ **Security Tier-1 → Tier-2 → Phase-3-breadth ordering present** (§3, §9); Tier-2 not optional.
- ✅ Quality floors + absolute invariants present (§11).
- ✅ Benchmark gates present (§10, §11).
- ✅ P5 remains a gated research program (§7).

*Output file: `IMPLEMENTATION-TASK-TRACKER.md`. No implementation performed; no other file modified; nothing committed
or pushed.*
