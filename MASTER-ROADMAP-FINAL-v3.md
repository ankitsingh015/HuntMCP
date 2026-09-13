# MASTER-ROADMAP-FINAL-v3.md — HuntMCP Reconciled Canonical Roadmap (zero-skip correction)

**Status:** canonical synthesis, v3. Read-only production of a single plan. No source code and no protected planning
document was modified; `MASTER-ROADMAP-FINAL.md` (v1) and `-v2.md` are left intact. **This v3 supersedes v2** and
corrects the one material omission found by `FINAL-ZERO-SKIP-AUDIT.md` (**VAL-AUTHZ**) without changing the validated
architecture/spine or losing any v2 decision. Authorities: `FINAL-ZERO-SKIP-AUDIT.md` (this correction),
`FINAL-MASTER-ROADMAP-REVIEW.md` + `FINAL-MASTER-ROADMAP-FREEZE-AUDIT.md` (prior gates), `MASTER-ROADMAP-AUDIT.md`
(reconciliation), and — newly reconciled here — the older `HUNTMCP-NEXT-GEN-PROPOSAL{,-v2,-v3,-AUDIT}` +
`HUNTMCP-NEXT-GEN-EXECUTION-PLAN` stream.

**Ground truth:** worktree `research/golden-nextgen` @ `fbbf26d`; CEM Phase 1 FROZEN (`#101`). Load-bearing code claims
re-verified in prior passes (`case_store.py:308/323`, `cem_engine.py:316-319`, `scope_gate_hook.py:main` fail-open,
`watch-mcp` no case linkage; `idor-mcp sweep_idor` is single-request/single-endpoint/two-account).

**Not authoritative-to-build:** architecture-level direction, gates, and evidence requirements — not a code task list
and not an authorization to begin. Implementation begins only when §14's entry conditions are met.

---

## 0. Correction Log (what changed from v2, and why)

| Zero-skip finding | v3 change | Where |
|---|---|---|
| **Z-1 VAL-AUTHZ omitted** (older stream's Tier-1 rank #1 "top capability bet"; committed C1 there; active `T-VAL-AUTHZ`; absent from v2) | **Inserted as a GATED P3 capability item** — stateful/multi-step authorization differential engine; complementary to (not duplicate of) schemathesis→CEM | §1, §4, §5(P3), §5-VA (spec), §11, §12, §14 |
| **Z-2 DISC-SPEC partial** (spec→endpoint model only implicit via schemathesis) | **Made explicit** as the P3 surface-expansion step feeding VAL-AUTHZ + scan | §4, §5(P3) |
| **Z-3 ARCH-STATE absent** (wire recon/scan into case-mcp) | Recorded as a **DEFERRED, measured** reliability item (not forced in) | §4 |
| **Z-4 Go backend scope unstated** | One-line scope boundary added | §2 |
| Zero-orphan recheck vs older stream | Added | §10-A |

**This corrects a verified historical omission, not new research.** VAL-AUTHZ is inserted at the exact scope the older
stream defined (min version), gated, with its source benchmark and safety controls — nothing inflated.

**Everything in v2 is preserved unchanged** (Option-C spine; Tier-1/Tier-2 security floor; P2-E1 postmortem;
coverage-before-use; C1a/C1b split; C2 boundary; C3 gated; CEM frozen; Xalgorix H1–H4; Next-Gen decisions; exact P5
safety invariants; §11-A quality floor vs absolute invariants; anti-roadmap; benchmark blindness; human-decision
boundaries). No v2 decision was removed, weakened, or reordered; no rejected item reintroduced. No architectural phase
was added — VAL-AUTHZ lands inside the existing Phase 3.

---

## 1. Executive Summary

HuntMCP's post-Phase-1 direction is settled and modest. The plan keeps the audit-endorsed **Option-C spine**
(Foundation → Discovery amplification → Application reasoning → Adaptive allocation → Continuous), fronts it with a
**two-tier Security Floor** (Tier-1 before any autonomous breadth; Tier-2 rootless boundary before Phase-3 breadth), and
makes **evidence provenance** a first-class Phase-2 item. v3 additionally restores **VAL-AUTHZ** — a stateful,
multi-identity **authorization differential** capability the older Next-Gen stream ranked #1 and which v2 had dropped —
as a **gated Phase-3** item that is complementary to schemathesis→CEM (schema property-fuzz), not a duplicate.

HuntMCP remains a **local security-research application whose moat is CEM (proof), not throughput.** It is not becoming
a platform, control plane, generic agent runtime, or cloud service. The additive substrate is separable increments
(evidence provenance, an execution-isolation floor, hunt postmortem, authorization-differential testing, delta
re-validation), never a single "platform" project.

The plan is deliberately conservative: **COMMITTED** work is only what is verified-needed (security floor, provenance
binding, injection sanitization, postmortem) or off-the-shelf-small (coverage instrument, scan headers). Everything
argued-but-unproven — full reproducibility manifest, discovery amplification, **VAL-AUTHZ**, invariant model, adaptive
allocation, cross-target transfer, delta re-hunt precision — is **GATED/MEASURE-FIRST** behind an explicit experiment,
under a named quality floor and absolute security invariants.

---

## 2. Final Architecture Direction

- **Core engine (unchanged, frozen):** CEM — counterfactual proof/validation (`cem_engine.py` + `case_store` CEM
  tables). The differentiator; not reopened.
- **Additive infrastructure (committed, small):** (a) **evidence provenance**; (b) a **two-tier execution-security
  floor**; (c) **hunt postmortem** (analysis-only); (d) later, **target-delta re-validation**. All extend existing
  primitives; none is a platform layer.
- **Additive capability (gated):** **VAL-AUTHZ** — a multi-identity/multi-step authorization differential engine that
  *extends the existing `idor-mcp` sweep* and feeds CEM confirmed conditions. Not a new subsystem; a strengthening of a
  tested tool.
- **How CEM fits:** stays post-confirmation validation (determinism gate requires a firing capability; `case_store`
  gates CEM on `CONFIRMED`). Integrated into hunting in Phase 3 **preserving the existing entry precondition** — not
  moved earlier, not redesigned. VAL-AUTHZ hands CEM exactly the conditions it wants (identity, step-order, carried id).
  Oracle *reach* for non-HTTP observations is research-only.
- **How evidence/provenance fits:** the trust layer beneath CEM. Provenance binding closes the model-narrated
  discovery-path gap; hashing alone does not.
- **How execution security fits:** a **prerequisite gate in two tiers** (§6). Tier-1 before any autonomous breadth;
  Tier-2 rootless boundary before Phase-3 breadth (which now includes VAL-AUTHZ's live requests).
- **How target deltas / re-hunting fit:** a Phase-5 capability linking `watch.db` snapshots to `case.db` hypotheses.
- **How adaptive allocation fits:** deferred to Phase 5, gated (P5-A0), under the quality floor + absolute invariants.
- **Product/scope boundary:** HuntMCP the security-research *agent system* is this roadmap's subject. The **Go backend
  (`backend/`)** — a mostly-independent hosted-service part (writeup RAG + MCP bridge + Postgres/pgvector, per
  `CLAUDE.md`) — is a **separate concern outside this roadmap's scope** and has its own lifecycle.
- **Intentionally uncommitted:** control plane, cloud/K8s, secret-broker build, microVM-local, graph DB,
  event-sourcing, capability-authority subsystem, unrestricted multi-agent parallelism, AI IDE (§13).

---

## 3. Current Reality / Already Implemented (do NOT rebuild)

Verified in code:

- **CEM Phase 1** — determinism gate, `classify()` (3–5-valued), non-vacuous `SuccessSignature`, interventions, ddmin,
  per-trial machine-hashed evidence. **FROZEN.**
- **Hypothesis lifecycle store** — `case_store` hypotheses/findings/experiments/root_causes; evidence-gated CONFIRMED.
- **Content-addressed evidence** — SHA-256 store. Tamper-evident (provenance is the gap, not integrity).
- **State isolation** — per-engagement dirs + per-session pointer + `file_lock` + WAL.
- **Scope enforcement** — 3-layer deny-by-default incl. PreToolUse hook (present, firing) — narrow & **fail-open**.
- **Cross-run memory/learning** — memory/writeup/lessons-mcp. **Ahead of competitors; keep.**
- **Continuous recon diffing** — `watch-mcp` snapshots (**unlinked** to case state — the C3 gap).
- **`idor-mcp`** — `sweep_idor` = **single-request, single-endpoint, two-account** pair classification (PROTECTED/
  LEAKED/AMBIGUOUS/DIFFERENT/OWNER_BASELINE_FAILED). **This is VAL-AUTHZ's baseline to strengthen — not remove.**
- **Human-review-before-submit** — `hackerone-mcp` has no submit tool by design. **Technical control; keep.**
- **`chainer-mcp`** — the real attack DAG (Xalgorix "ledger-as-graph" rejected; this is the graph).

**Not present (grep-verified):** execution isolation/sandbox, capability-authority tokens, secret broker, provenance
binding, coverage instrument/matrix, scan-identification headers, tool-output-injection sanitization, hunt postmortem,
**multi-step / owner-fetch-compare / role-matrix authorization differential testing (VAL-AUTHZ)**.

---

## 4. Canonical Decision Matrix

Categories: **ALREADY IMPLEMENTED · COMMITTED · GATED (measure-first) · DEFERRED · REJECTED.**

| Capability / Initiative | Decision | Phase | Priority | Dependencies | Rationale / Evidence | Acceptance Gate |
|---|---|---|---|---|---|---|
| CEM Phase-1 proof engine | ALREADY IMPLEMENTED | — | — | — | `cem_engine.py`, frozen `#101` | — |
| Hypothesis lifecycle store | ALREADY IMPLEMENTED | — | — | — | `case_store` | — |
| Content-addressed evidence | ALREADY IMPLEMENTED | — | — | — | SHA-256 store | — |
| State isolation / memory / watch diffing / `idor-mcp` sweep | ALREADY IMPLEMENTED | — | — | — | baseline for VAL-AUTHZ | — |
| **Tier-1:** scope hook fail-closed + CI block-test | COMMITTED | S (Tier-1) | P0 | — | fail-open SPOF | out-of-scope call blocked in CI |
| **Tier-1:** scope secrets out of untrusted execution | COMMITTED | S (Tier-1) | P0 | — | full-`.env` load | sandboxed exec cannot read `.env` |
| **Tier-1:** `--os-shell` / state-changing confirmation tier | COMMITTED | S (Tier-1) | P0 | — | persistent RCE, no gate | RCE requires explicit confirm |
| **Tier-2:** rootless execution boundary + hook tamper-resistance (C2) | COMMITTED | S (Tier-2) | P1 | rootless runtime | whole-host TCB; hook neutralizable | adversarial regression (containment + utility) **before Phase-3 breadth** |
| Evidence provenance binding (C1a / Xalgorix H1) | COMMITTED | 2 | P1 | capture seam | 2 streams + code (`add_evidence:322`) | evidence bound to real exchange (wire/invocation, §8) |
| Hunt postmortem / self-evaluation (P2-E1) | COMMITTED | 2 | P1 | telemetry, `case_store`, `dedupe_check` | committed WP + UU #24 | planted-fixture recall; read-only proven; independent cross-check; redaction |
| Tool-output-injection sanitization (UU-7) | COMMITTED | 2 | P1 | — | live injection surface | injection regression passes |
| Benchmark + telemetry substrate | COMMITTED | 2 | P1 | — | gates all measured items | emits cost/yield/coverage |
| Coverage instrument — minimal (H3 core) | COMMITTED (small) | 2 | P1 | benchmark | needed as a P2/P3 signal | coverage signal produced + benchmarked |
| Coverage matrix — full endpoint×class×role (H3) | COMMITTED (small) | 4 | P2 | P2 coverage instrument | full breadth object | matrix populated + anti-gaming clause |
| Tool pinning + SBOM + CI SAST | COMMITTED | 2 | P2 | — | unpinned `@latest` | pinned build + SAST in CI |
| **VAL-AUTHZ — stateful/multi-step authorization differential engine (min)** | **GATED** | **3** | **P2** | **benchmark; benefits from DISC-SPEC; Tier-2 complete** | **older stream Tier-1 #1 (corrects Z-1 omission); baseline `idor-mcp` single-request** | **recovers multi-step authz the sweep misses; ZERO new FP; verdicts match ground truth** |
| **DISC-SPEC — OpenAPI/GraphQL → stateful endpoint/parameter model** | COMMITTED (small) | 3 | P3 | — (feeds VAL-AUTHZ + scan) | Z-2; surface expansion beyond crawl | endpoints recovered beyond crawl on benchmark |
| Scan-identification headers (H4) | COMMITTED (small) | 3 | P3 | — | polite authorized scan (Xalgorix) | target-only header emitted |
| Full research-run manifest (C1b) | GATED | 2→ | P3 | C1a, benchmark | value unproven | triager-acceptance A/B (XYZ §6.3) |
| Discovery amplification (schemathesis→CEM) | GATED | 3 | P2 | benchmark, **new-dependency approval**, **Tier-2 complete** | amplification unmeasured; **distinct class from VAL-AUTHZ** | WFC/WFD, quality floor held |
| CEM-in-hunt integration (XYZ P3) | COMMITTED | 3 | P2 | Phase-2 base | wire confirmed→CEM, **entry precondition preserved** | CEM runs in-hunt; FCC==0 |
| Structural differentiation evidence (XYZ §2.6) | COMMITTED | 3 | P3 | disclosed_reports | dedupe aid | labeled differentiation emitted |
| SuccessSignature oracle reach — browser/OOB (H2) | GATED (research-only) | research | P4 | — | HTTP-only `:316`; keep CEM pure | only if breadth-blocking; injected `observe_fn` |
| Invariant model (UU-1) | GATED | 4 | P3 | telemetry | least-tractable (UU V.4) | P4-M0 GO/NO-GO; invariants remain CEM-provable hypotheses |
| Hypothesis resurrection (UU-2) | COMMITTED (additive query) | 4 | P3 | case_store | no new store | resurrection query ships |
| Info-gain experiment selection (UU-3) | GATED | 4 | P3 | telemetry | needs cost/gain data | uplift; **orders, never hard-blocks a novel test** |
| Adaptive allocation / router (A/B/C/D) | DEFERRED (gated) | 5 | P4 | telemetry | measure-first (memo) | P5-A0 GO; C-vs-D attribution; floor + invariants |
| Target-delta re-validation (C3) | GATED | 5 | P3 | should-use C1a; watch↔case link | not plumbing | re-hunt precision > cold start |
| Cross-target transfer (memo §9 / XYZ P4) | DEFERRED (gated) | 5 | P4 | signatures | transfer safety unproven | P5-T1: **false-reuse→missed-test == 0** |
| Autonomous CEM condition extraction (VAL-COND) | DEFERRED | 4/5 | P4 | CEM P1, benchmark | XYZ §5 later phase; human default retained | parity with human conditions; no new false necessity |
| Active counterfactual variant discovery (DISC-VARIANT) | GATED | 5 | P3 | CEM P1 | rides CEM; XYZ §2.7 | variants recovered the incidental path misses; zero double-report |
| Durable inter-agent state — recon/scan → case-mcp (ARCH-STATE) | DEFERRED (measured) | — | — | case_store | measured reliability decision (older stream) | only if it reduces duplication more than schema-token cost |
| Human-gated toolkit growth (`tool_gaps`) | GATED | 5 | P4 | recurrence signal | human-in-loop (safety) | human approval per addition |
| Capability/tool-exposure layer | DEFERRED | V4 | — | 3rd runtime / drift | premature | trigger conditions |
| case.db concurrency multi-writer fix | SUPERSEDED | — | — | — | v2 chose isolated-exec + shared-immutable-evidence (append-only) | not needed under chosen model |
| Resource-aware admission control | DEFERRED | — | — | — | `budget_guard` covers cost axis | — |
| Knowledge graph (LEARN-KG) | REJECTED | — | — | — | SQLite cross-ref suffices; graph poisoning surface | — |
| "Confirmation is CEM" / new verifier subsystem | REJECTED | — | — | — | analogy only | — |
| audit_log as evidence store; ledger-as-graph; direction-of-travel; MAPTA/XBOW | REJECTED | — | — | — | XALGORIX-REVIEW §24 | — |
| Control plane / cloud / K8s / secret-broker build / microVM-local / graph DB / event-sourcing / AI IDE / unrestricted parallelism | REJECTED / DEFERRED | — | — | triggers | audit §13 | — |

---

## 5. Final Phase Roadmap

Five phases + a two-tier gating Security Floor. Frozen CEM sits beneath all (consumed, never modified). *(Note: "Phase
1" is the frozen CEM slice; the first new phase is Phase 2.)*

### Phase S — Security Floor *(gating prerequisite; two tiers)*
**Tier-1 (before ANY autonomous breadth expansion):** (1) scope hook **fail-closed** (scoped to target-touching calls;
on internal error, block the *gated call*, not the session) + CI block-test; (2) scope secrets out of untrusted
execution; (3) `--os-shell`/state-changing confirmation tier.
**Tier-2 (rootless boundary + hook tamper-resistance — before Phase-3 breadth begins):** rootless per-run boundary
(swappable) + hook tamper-resistance. *Exit gate:* adversarial regression (canary-secret exfil via hostile tool
output; out-of-scope action; hostile-repo checkout) passes on **containment AND legitimate-task utility**, across the
lifecycle. **Phase-3 breadth — including VAL-AUTHZ's live requests — does not start until this passes.**
**Non-goals:** secret broker, capability leases, control plane, microVM.

### Phase 2 — Foundation, Evidence Integrity, Introspection & Reliability
- **Prerequisites:** Phase-S Tier-1.
- **Groups:** (1) benchmark + telemetry substrate; (2) evidence provenance binding (C1a, §8 scope); (3) hunt postmortem
  (P2-E1, analysis-only spec below); (4) tool-output-injection sanitization (UU-7); (5) negative-knowledge +
  capability-utilization signal; (6) minimal coverage instrument (H3 core); (7) supply-chain pinning + SBOM + CI SAST;
  (8) *optional* C1b manifest instrumented for the A/B.
- **Acceptance/exit:** provenance verified on stored findings; injection regression passes; telemetry emits
  cost/yield/coverage; false-positive baseline; postmortem read-only proven + planted-fixture recall.
- **Non-goals:** invariant model, allocation, discovery breadth, self-modification.

**P2-E1 postmortem — analysis/reporting ONLY:** analysis-only, read-only, no tools, no auto-retry, no
self-modification, no policy mutation; offline post-hunt analyzer; evidence-cited (cites `audit_log`/`case_store`);
planted-fixture precision/recall; independent verification vs raw stores; redaction verified. *Extended* (not rebuilt)
in P4.

### Phase 3 — Discovery Amplification, Authorization Differential + CEM-in-Hunt
- **Objective:** competitive breadth under the quality floor, including the human-advantage authorization class.
- **Prerequisites:** Phase-2 substrate; **Phase-S Tier-2 complete** (peak hostile-content ingestion + live authz
  probing); **new-dependency approval** for `schemathesis`.
- **Groups:**
  1. **schemathesis→CEM** stateful/API property falsifiers (GATED) — *schema property falsification*.
  2. **VAL-AUTHZ (min)** (GATED) — *multi-identity authorization differential*. See **§5-VA** below.
  3. **DISC-SPEC** — parse OpenAPI/GraphQL into a stateful endpoint/parameter model (hand-rolled first; parser lib only
     if proven necessary; treat spec as untrusted data) feeding scan targeting **and VAL-AUTHZ workflow capture**.
  4. CEM auto-run after independent validation **preserving the existing CEM entry precondition**.
  5. structural differentiation evidence; H4 scan headers.
- **Acceptance/metrics:** WFC/WFD breadth up **against protected/blind ground truth**; **quality floor held (§11-A):
  no high/critical the baseline finds is lost — hard-fail**; VAL-AUTHZ recovers multi-step authz at zero new FP; CEM
  runs in-hunt; **FCC == 0**.
- **Non-goals:** widening CEM oracle contract (H2 research-only unless breadth-blocking).

**§5-VA — VAL-AUTHZ minimal-version spec (faithful to `HUNTMCP-NEXT-GEN-PROPOSAL-v3.md §5.2` + its AUDIT §11/§16):**
- **Baseline (OBSERVED):** `idor-mcp sweep_idor(url_template, object_ids, both-account creds)` — single-request,
  single-endpoint, two-account pair classification.
- **Gap (RESEARCH-SUPPORTED — AuthProbe/BACFuzz/RESTler):** (1) **multi-step workflows** (authz at step 1, an id
  carried unvalidated into step 2); (2) a **ground-truth owner-fetch-and-compare oracle** (not status/length only);
  (3) a **role/identity matrix** beyond two peers (unauth, low-priv, admin, tenant-B where authorized).
- **Smallest useful version (build nothing else first):** (a) strengthen the sweep's oracle to
  **owner-fetch-and-compare**; (b) add a **two-step replay primitive** — capture a short workflow as identity A, replay
  step N under identity B while holding earlier steps, classify the same way. Emit confirmed findings to
  `case_store.create_finding` with candidate CEM conditions (identity, step-order, carried id).
- **CEM synergy:** a confirmed multi-step authz finding hands CEM exactly the conditions it wants — strong synergy;
  CEM remains the proof engine (VAL-AUTHZ discovers/validates existence, CEM proves necessity later).
- **Why complementary, not a duplicate:** schemathesis→CEM = schema/stateful *property* falsification; VAL-AUTHZ =
  *multi-identity authorization differential*. Different bug classes; they can share the DISC-SPEC endpoint model and
  the shared HTTP primitive (`http_probe.py`).

### Phase 4 — Application Reasoning + Coverage
- **Prerequisites:** Phase-2 telemetry + coverage instrument.
- **Groups:** (1) invariant model **(gated by P4-M0)** — invariants remain CEM-provable hypotheses; false positives a
  quality risk; (2) hypothesis resurrection (additive query); (3) info-gain selection (GATED) — orders, never
  hard-blocks a novel test; (4) full coverage matrix H3 (anti-gaming); (VAL-COND autonomous condition extraction is a
  P4/P5 deferred item, human-supplied default retained).
- **Exit:** P4-M0 GO/NO-GO recorded; if NO-GO, ship resurrection + info-gain + coverage matrix without deep invariant
  inference.

### Phase 5 — Adaptive Allocation + Continuous / Delta
- **Groups:** (1) adaptive allocation **(P5-A0 GO)** via **A/B/C/D** (A frontier-heavy · B fixed-mixed · C adaptive ·
  D CEM-assisted; **C-vs-D = the entire attribution of CEM's contribution**); (2) continuous monitoring + **delta
  re-validation (C3, gated)** + patch-bypass regression; (3) cross-target transfer **(P5-T1)**; (4) active
  counterfactual **DISC-VARIANT** (rides CEM); (5) human-gated toolkit growth.
- **Absolute security invariants (§11-A):** false-reuse→missed-test == 0; allocation/dedupe/negative-knowledge **never
  hard-block a not-yet-confirmed novel test**; **cheap-tier premature-closure guard**; **any high/critical miss vs the
  frontier baseline hard-fails the config.**
- **Exit:** each gated item ships only on its GO; a failed gate defers with a recorded reason.
- **Non-goals:** self-modification, unattended autonomy, unrestricted parallelism.

*Cross-cutting continuous tracks: Security/Reliability hardening (P2 items); Benchmark & Measurement.*

---

## 6. Security Floor (two tiers)

**Tier-1 — hard gate before ANY autonomous breadth (before Phase-2 autonomous work):** scope hook **fail-closed**
(scoped to target-touching calls; internal error blocks the gated call, not the session) + CI block-test; secrets
scoped out; `--os-shell`/state-changing confirmation.
**Tier-2 — rootless boundary before Phase-3 breadth begins:** rootless per-run boundary (swappable) + hook
tamper-resistance; exit = adversarial regression on containment **AND** utility, across the lifecycle. **This gates
VAL-AUTHZ's live authorization probing as well as schemathesis breadth.**
**Later hardening (P2, continuous, non-gating):** pinning + SBOM; Python SAST/dep-audit in CI; CI `permissions:`;
`data/watch.db` untrack + per-engagement path.
**Deferred (with triggers):** resource-aware admission; capability-authority; secret broker (off-the-shelf only).
**Discipline:** the floor is small — hardening + one rootless boundary; it must not metastasize into platform
architecture.

---

## 7. CEM Position

- **Frozen/accepted; not reopened.** Later work only consumes/extends around it.
- **Future integration:** Phase-3 wires validated findings into CEM **preserving the entry precondition**
  (`CONFIRMED`/determinism gate); **VAL-AUTHZ feeds CEM candidate conditions** (identity, step-order, carried id);
  Phase-5 uses causal signatures for variants/transfer (gated).
- **Oracle reach (H2):** research-only, via an injected `observe_fn`; never couple the engine.
- **Not a CEM redesign:** VAL-AUTHZ and the Xalgorix "verifier" *establish existence*; CEM consumes the result. No
  competing verifier; "confirmation is CEM" rejected.
- **Applicable Xalgorix lessons:** provenance seam (C1a), oracle-reach (H2), coverage (H3) — all additive, none
  touching `cem_engine.py`.

---

## 8. Evidence & Provenance Strategy

Two paths of unequal trust (`case_store.py:322` vs `cem_trials`); most reports flow through the weak one.
- **Do not claim the gap is solved because hashes exist** — hashing proves integrity, not provenance.
- **C1a (smallest useful milestone, not a platform):** **wire-level provenance** for sources with a structured
  request/response (curl/`tool_resolver`, `browser-mcp`, `oob-mcp`, CEM `fetch_fn`, **and VAL-AUTHZ's `http_probe`
  requests**); **invocation-level provenance** for scanner-narrated output (nuclei/sqlmap/subfinder). Each evidence
  class carries its strongest available provenance.
- **C1b (full manifest):** GATED — value unproven; instrument, run the triager-acceptance A/B, promote only on
  evidence.

---

## 9. C1 / C2 / C3 Placement

- **C1a:** COMMITTED, P2, P1 (scoped per §8). **C1b:** GATED (A/B). **C2:** COMMITTED Tier-2 floor, before Phase-3
  breadth; rootless/swappable; microVM future-remote only. **C3:** GATED, P5; should use C1a; depends on a watch↔case
  link; gated on re-hunt precision. Separable increments, never one platform project.

---

## 10. Xalgorix-Derived Lessons

H1 provenance → C1a (P2); H2 oracle reach → research-only; H3 coverage → P2 instrument / P4 matrix; H4 scan-headers →
P3. Deterministic confirmers = already stronger; hypothesis ledger = already have; verifier *environment* isolation →
reinforces C2; secure-SDLC CI → P2 SAST. Do NOT copy wholesale: 22-phase prompt-constant, control-plane RCE console,
resource-admission, ledger-as-graph, direction-of-travel — rejected/deferred.

## 10-A. Zero-Orphan Recheck vs the older HuntMCP-Next-Gen stream

| Older-stream item | v3 disposition |
|---|---|
| P0-BENCH | MERGED → benchmark substrate (P2) |
| **VAL-AUTHZ** | **RESTORED → GATED P3 (§5-VA)** — corrects Z-1 |
| DISC-SPEC | RESTORED/EXPLICIT → P3 surface-expansion feeding VAL-AUTHZ + scan |
| DISC-VARIANT | GATED → P5 (rides CEM) |
| VAL-COND | DEFERRED → P4/P5 (XYZ §5 later phase; human default retained) |
| ARCH-STATE (recon/scan→case-mcp) | DEFERRED (measured reliability decision) |
| case.db concurrency multi-writer fix | SUPERSEDED (append-only isolated-exec + shared-immutable-evidence) |
| EFF-SCHED-v0 | MERGED → info-gain experiment selection (P4) |
| EFF-ALLOC | DEFERRED → adaptive allocation (P5, gated) |
| LEARN-SIG | GATED → CEM signature transfer (P5-T1) |
| LEARN-KG (knowledge graph) | REJECTED (SQLite cross-ref suffices; poisoning surface) |
| DISC-GRAPH (attack-state graph) | `chainer-mcp` is the DAG; graph-DB REJECTED |

**No older-stream item is silently lost.** Every item is represented, merged, deferred (with reason), superseded, or
explicitly rejected.

---

## 11. Measurement & Promotion Gates

All capability benchmarks use protected/blind ground truth (labels independent of the implementation; no auto-derived
oracle; anti-gaming) per `.claude/rules/benchmarks.md`. GATED items promote only on evidence; failure = defer.

| Hypothesis | Metric | Minimum experiment | Promotion criterion | If it fails |
|---|---|---|---|---|
| Provenance raises acceptance (C1b) | triager acceptance, time-to-triage | A/B with vs without manifest | uplift, no time regression | keep C1a; drop C1b headline |
| Discovery amplification (schemathesis→CEM) | new confirmed/target; FCC | WFC/WFD (blind) + labs | breadth up, floor held, FCC==0 | defer; keep CEM-in-hunt |
| **VAL-AUTHZ recovers missed authz** | **multi-step authz recall vs sweep; new-FP rate; verdict-vs-ground-truth agreement** | **planted multi-step authz labels (owner/second identity, role matrix, cross-tenant where authorized, multi-step sequence) on the benchmark range; differential oracle; independent confirmation** | **recovers multi-step authz the sweep misses; ZERO new false positives; verdicts match ground truth** | **flag off → existing `idor-mcp` sweep** |
| DISC-SPEC surface gain | endpoints beyond crawl | parse OpenAPI/GraphQL on benchmark | measurable surface gain feeding authz/scan | disable spec ingestion |
| Postmortem recovers what was missed | planted-fixture precision/recall; read-only; redaction | fixture hunt with planted issues | recall bar met; independent cross-check clean | narrower postmortem; never grant action |
| C3 delta re-hunt beats cold start | re-hunt precision/recall | inject target delta | higher precision at lower cost | keep watch diffing as alerting |
| Invariant model tractable | invariant recall/precision (=hypotheses) | P4-M0 (blind) | prototype meets bar; FP acceptable | ship resurrection+info-gain+coverage only |
| Rootless boundary preserves utility | legitimate-task success under isolation | Tier-2 exit regression | containment high, utility ≈ baseline | narrow profile; keep boundary |
| Adaptive allocation pays off | cost/quality; **C-vs-D** | P5-A1 A/B/C/D (held-out) | improvement under floor+invariants | defer allocation |
| Cross-target transfer safe | safe-transfer / false-reuse / missed-test | P5-T1 (same/similar/cross-target) | **false-reuse→missed-test == 0** | defer transfer |

### 11-A. Quality Floor vs Absolute Security Invariants

**Quality floor (hard-fail on high/critical; Pareto for medium/low):** high/critical recall ≥ baseline − ε; FP ≤
baseline; coverage ≥ baseline. Applies to P3 (incl. VAL-AUTHZ + schemathesis) and P5.
**Absolute security invariants (zero-tolerance):** CEM FCC == 0; **false-reuse→missed-test == 0**;
allocation/dedupe/negative-knowledge **never hard-block a not-yet-confirmed novel test** (hints, never skips);
**cheap-tier premature-closure guard**; **VAL-AUTHZ: zero new false positives** and state-changing steps require the
human gate; postmortem is analysis-only; human-review-before-submit preserved.

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
     └──────►  Phase 3 (schemathesis→CEM[gated,dep] · VAL-AUTHZ[gated] · DISC-SPEC → feeds VAL-AUTHZ · CEM-in-hunt · differentiation · H4)
                                          ↓
                             Phase 4 (Invariant[P4-M0] · resurrection · info-gain[gated] · coverage matrix H3)
                                          ↓
                             Phase 5 (Allocation[P5-A0,A/B/C/D] · Continuous+delta C3[gated] · transfer[P5-T1] · DISC-VARIANT · human-gated toolkit)
```

Tier-1 precedes all autonomous breadth; **Tier-2 precedes Phase-3 breadth (VAL-AUTHZ + schemathesis)**; **DISC-SPEC
feeds VAL-AUTHZ** (both P3, DISC-SPEC first or in parallel); the P2 coverage instrument precedes coverage-based signals;
measurement precedes reasoning; reasoning/telemetry precede allocation; C3 uses C1a + a watch↔case link.

---

## 13. Anti-Roadmap (intentionally NOT built this horizon)

Generic control plane / multi-tenant SaaS (DEFER: multi-user); cloud/K8s (DEFER; keep boundary swappable); local
microVM (DEFER: remote exec); custom secret broker (off-the-shelf when triggered; never build); graph DB /
event-sourcing (SQLite + `chainer` DAG suffice; NO); new "verifier" subsystem (duplicates CEM; NO); knowledge graph
LEARN-KG (REJECT); resource-aware admission (`budget_guard` covers; DEFER); capability-authority subsystem (subsumed
near-term; DEFER: mutually-distrusting agents); AI IDE / generic agent platform / capability marketplace / unrestricted
multi-agent parallelism (off-mission; DEFER/REJECT). **VAL-AUTHZ is NOT a generic authorization framework** — it is a
bounded extension of `idor-mcp` (owner-fetch oracle + two-step replay + role matrix); do not inflate it.

---

## 14. Implementation Entry Conditions

1. **Frozen:** CEM Phase-1; hypothesis store, evidence content-addressing, scope-enforcement *design*,
   human-review-before-submit fixed (harden, don't redesign).
2. **First work = Phase-S Tier-1.** No autonomous breadth begins until Tier-1 passes. **Tier-2 must pass before Phase-3
   breadth (VAL-AUTHZ + schemathesis) begins.**
3. **Baselines before Phase 3:** benchmark + telemetry + false-positive baseline + coverage instrument (P2); C1a
   provenance verified; postmortem read-only + planted-fixture recall proven; **VAL-AUTHZ's planted multi-step authz
   labels present in the benchmark range**.
4. **Do not rebuild** anything in §3 (esp. do not remove the `idor-mcp` sweep — VAL-AUTHZ extends it).
5. **Phase gate discipline:** GATED items ship only on their promotion criterion (§11); a failed gate defers with a
   recorded reason.
6. **New dependencies** (`schemathesis`, rootless runtime; a spec parser only if hand-rolled proves insufficient)
   require explicit approval.
7. **Protected-doc edits** (folding this into `ROADMAP.md`/proposal/execution plan) require a separate,
   human-authorized task.

---

## 15. Success Metrics

Measured by hunting outcomes, never by agent/MCP/prompt/feature count: confirmed-finding precision (FCC==0); evidence
provenance share (C1a) + triager acceptance (C1b if promoted); **multi-step authorization findings recovered
(VAL-AUTHZ) at zero new FP**; postmortem recall; useful coverage (H3); experiment efficiency; repeated-target
improvement / re-hunt precision (C3); discovery breadth under the quality floor (WFC/WFD, no high/critical loss);
long-horizon reliability & regression resistance; safe autonomous operation (Tier-2 regression green across the
lifecycle; absolute invariants hold).

---

## 16. Open Questions

1. Does provenance/reproducibility raise triager acceptance? (C1b) — largest unknown; measured.
2. Is the browser/OOB oracle gap (H2) breadth-blocking? Only then does it earn work.
3. C3 re-hunt precision vs cold start — unmeasured.
4. schemathesis→CEM amplification magnitude — unmeasured.
5. **VAL-AUTHZ multi-step recall + false-positive rate** — HIGH confidence in the source, but unproven on HuntMCP's own
   benchmark; the gate decides.
6. Invariant-model tractability — P4-M0.
7. Rootless-boundary utility cost — Tier-2 exit measures it.
8. Adaptive allocation & cross-target transfer — payoff/safety unproven; both gated.

---

## 17. Final Freeze Criteria

Freeze when: the Canonical Decision Matrix (§4) is accepted as-is; CEM Phase-1 confirmed untouched by every committed
item; the two-tier Security Floor (§6) accepted; C1a + P2-E1 accepted as first-class P2 items; **VAL-AUTHZ accepted as
a gated P3 item (§5-VA)**; the quality floor and absolute security invariants (§11-A) accepted; every GATED item (§11)
has its experiment + promotion criterion recorded before work starts; the Anti-Roadmap (§13) accepted; the protected-doc
integration authorized as a separate task. Once these hold, Phase-S Tier-1 may begin.

---

## 18. Self-Check

- **VAL-AUTHZ now represented?** Yes — §1, §4, §5(P3)/§5-VA, §10-A, §11, §12, §14, §15, §16.
- **Falsely labeled already-implemented?** No — the *baseline* `idor-mcp` sweep is ALREADY IMPLEMENTED (§3); VAL-AUTHZ
  itself is **GATED** (a strengthening of that baseline).
- **Gated with an explicit benchmark?** Yes — planted multi-step authz labels; recovers-what-the-sweep-misses at zero
  new FP; verdicts match ground truth; rollback = flag off → existing sweep (§11).
- **Safety boundary explicit?** Yes — idempotent/read-GET default; state-changing steps require the human gate;
  `scope_guard` on every request; engagement isolation; Tier-2 gates its live probing (§5-VA, §6, §11-A).
- **New architectural phase?** No — inserted into existing Phase 3.
- **Duplicates schemathesis?** No — schemathesis = schema property falsification; VAL-AUTHZ = multi-identity
  authorization differential; explicitly complementary (§5-VA), can share DISC-SPEC + `http_probe.py`.
- **Any v2 decision lost?** No — §0 preserves all; every v2 section retained.
- **Rejected item reintroduced?** No — LEARN-KG/graph/control-plane/etc. remain rejected/deferred (§13); VAL-AUTHZ was
  never rejected (it was Tier-1 #1).
- **Zero-skip vs older stream?** Yes — §10-A shows every older-stream item represented/merged/deferred/superseded/
  rejected.

---

## Report

- **Exact source sections used:** `HUNTMCP-NEXT-GEN-PROPOSAL-v3.md §5.2` (VAL-AUTHZ definition, oracle, two-step
  replay, role matrix, benchmark, safety, exit, confidence HIGH); `HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT.md §11` (deep review:
  "#1 capability bet", cleanest measurable baseline, smallest-useful-version) + §15 (ranking Tier-1 #1) + §16 (corrected
  roadmap C1: extend `idor-mcp`, two-step replay + owner-compare oracle, idempotent default, exit); `HUNTMCP-NEXT-GEN-
  EXECUTION-PLAN.md` (`T-VAL-AUTHZ` NOT STARTED, deps T-P0-BENCH, benefits from T-DISC-SPEC). Also v3 §5.3 (DISC-SPEC),
  §5.6 (ARCH-STATE). Cross-checked against `idor-mcp` baseline behavior.
- **VAL-AUTHZ original disposition:** PROPOSED, **Tier-1 rank #1 / "top capability bet"**, HIGH confidence, committed as
  C1 in the older corrected roadmap; still an active NOT-STARTED tracked task.
- **Why it was missing:** the older HuntMCP-Next-Gen capability stream (v3 + its audit + its execution tracker) was
  never reconciled into `MASTER-ROADMAP-PROPOSAL.md` (0 references to its candidate tags); VAL-AUTHZ fell through that
  merge gap into v1/v2.
- **Why P3 is correct:** it is a discovery/validation capability that finds new authorization findings and feeds CEM;
  it needs the P2 benchmark + Tier-2 boundary; it pairs with DISC-SPEC (P3) and is complementary to schemathesis→CEM
  (also P3). It does not depend on P4/P5, and creates no new phase.
- **Benchmark/gate added:** planted multi-step authz labels (owner/second identity, role matrix, cross-tenant where
  authorized, multi-step sequence), differential oracle, independent confirmation; promote only if it recovers
  multi-step authz the sweep misses at **zero new FP** with verdicts matching ground truth; else roll back to the sweep.
- **Older-stream items still not built (with reason):** VAL-COND (DEFERRED — XYZ later phase), DISC-VARIANT (GATED P5),
  ARCH-STATE recon/scan wiring (DEFERRED — measured), concurrency multi-writer fix (SUPERSEDED by append-only model),
  LEARN-KG (REJECTED), DISC-GRAPH-as-DB (REJECTED; chainer is the DAG). None silently lost — all in §4/§10-A.
- **Is v3 zero-skip against the older Next-Gen stream?** **Yes** (§10-A). No material item remains unrepresented.
- **Exact file created:** `MASTER-ROADMAP-FINAL-v3.md`. v1/v2 left intact. No other file modified; nothing implemented,
  committed, or pushed.
