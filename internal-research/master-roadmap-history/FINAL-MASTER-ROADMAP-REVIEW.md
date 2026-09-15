# FINAL-MASTER-ROADMAP-REVIEW.md — Pre-Implementation Freeze Audit of `MASTER-ROADMAP-FINAL.md`

**Status:** independent, adversarial pre-freeze review. Read-only. No source code, no protected planning document, no
research/audit document, and **not `MASTER-ROADMAP-FINAL.md` itself** was modified. Only this file was created.

**Method (per the review's own rules):** `MASTER-ROADMAP-FINAL.md` was re-read in full (all 17 sections + tables +
report). `MASTER-ROADMAP-AUDIT.md` and the supporting corpus were checked for fidelity and dropped decisions. **Load-
bearing code claims were re-verified fresh against the current worktree — not trusted from the prior audit.** Findings
that rest only on a document are tagged **[doc]**; freshly code-verified this pass, **[code✓]**.

**Freshly re-verified this pass (code > docs):**
- `scope_gate_hook.py:main()` returns `0` (allow) on malformed input — *fails open by design* ("never break the
  session"); OSS-audit L143 separately documents the registration SPOF ("if it silently breaks … allow everything"). **[code✓]**
- `case_store.py:308/323` — `add_evidence(type, content: str, …)` hashes a model-supplied string. Provenance gap real. **[code✓]**
- `cem_engine.py:316-319` — `SuccessSignature` = `status_in/body_contains/body_regex/similarity_to_baseline`, HTTP-only.
  H2 real. **[code✓]**
- `watch-mcp/server.py` — zero reference to `case_store`/`case.db`/hypotheses. C3 is real work, not plumbing. **[code✓]**

The roadmap's **factual/implementation base is accurate and current.** The defects below are contradictions,
omissions, and under-specification — not false code claims.

---

## 1. Executive Verdict

`MASTER-ROADMAP-FINAL.md`'s **architecture and spine are correct and should not be reconsidered**: Option-C ordering,
CEM-as-frozen-moat, evidence provenance elevated, a security floor as a gate, the anti-roadmap, and the
committed/gated/deferred discipline are all sound and faithful to `MASTER-ROADMAP-AUDIT.md`. There is **no evidence the
architecture is wrong.**

However, it is **not yet safe to freeze.** One **CRITICAL** internal contradiction sits in the security-gate sequencing
(the execution-isolation boundary is simultaneously a "hard gate that blocks breadth expansion" *and* a deliverable
that may land "by end of Phase 3" — but Phase 3 *is* the breadth expansion). And the synthesis, in compressing the
audit, **silently dropped or under-specified several committed safety capabilities that exist in the corpus**: the
Phase-2 hunt postmortem/self-evaluation work package (a committed WP *and* an UNKNOWN-UNKNOWN IMPORTANT GAP, with its
own read-only guardrails); the explicit Phase-5 security-of-methodology invariants (`false-reuse→missed-test == 0`,
"allocation/dedupe/negatives never hard-block a novel test", cheap-tier premature-closure guard, high/critical
hard-fail floor); the A/B/C/D attribution design; and the protected/blind ground-truth discipline. These are exactly
the guardrails that keep an autonomous discovery/allocation system from silently degrading recall — omitting them from
the *canonical* plan is a freeze blocker even though the audit "covered" them at a higher altitude.

These are correctable without touching the spine. **Freeze decision: C — DO NOT FREEZE; SIGNIFICANT CORRECTIONS
REQUIRED** (not D — the architecture is sound; not B — the omissions are safety-relevant, not cosmetic).

---

## 2. Freeze Decision

**C — DO NOT FREEZE — SIGNIFICANT CORRECTIONS REQUIRED.**

- Not **A/B**: a CRITICAL security-sequencing contradiction + multiple HIGH safety omissions exceed "minor."
- Not **D**: the spine, security-floor concept, provenance elevation, CEM freeze, and anti-roadmap are evidence-backed
  and internally coherent; no architectural reconsideration is warranted.
- Path to freeze: apply the 4 MUST-FIX corrections (§21). None requires new research; all are re-insertions or
  disambiguations traceable to the corpus.

---

## 3. Completeness / Fidelity Audit

**3a. Fidelity to `MASTER-ROADMAP-AUDIT.md` (the primary authority): HIGH.** Every major audit decision is present and
accurately represented:

| Audit decision | FINAL representation | Faithful? | Note |
|---|---|---|---|
| Option-C spine kept | §1/§5 | YES | — |
| Security Floor = gating precondition | §5 Phase S, §6, §14.2 | PARTIAL | gate scope self-contradicts on C2 (F-C-1) |
| Evidence provenance first-class P2 | §4/§8/§9 | YES | scope realism gap (F-M-1) |
| C1 split (C1a committed / C1b gated) | §8/§9 | YES | — |
| C2 execution floor | §4/§6/§9 | PARTIAL | timing contradiction (F-C-1) |
| C3 real gated work | §4/§9/§11 | YES | — |
| CEM frozen; H2 research-only | §7 | YES | strong |
| Xalgorix H1–H4 carried; rest rejected | §4/§10 | YES | — |
| Anti-roadmap (control plane/broker/microVM/graph DB/…) | §13 | YES | no resurrection found (§18) |
| Measure-first gates for invariant/allocation/transfer | §11 | PARTIAL | A/B/C/D + P5 invariants compressed (F-H-2, F-M-2) |

**3b. Fidelity to the deeper corpus (proposal/memo/UU): PARTIAL — this is where the drops are.** The audit itself
compressed three corpus items; FINAL inherited the compression. Because FINAL is the *canonical implementation plan*
(not an audit restatement), those compressions become defects at freeze:

| Source item | Corpus location | FINAL status | Classification |
|---|---|---|---|
| Hunt postmortem / self-evaluation (P2-E1) | PROPOSAL §P2-E1 (full spec); UU #24 IMPORTANT GAP | **absent** | **DROPPED INCORRECTLY (F-H-1)** |
| P5 security invariants (missed-test==0, no-suppress-novel, cheap-closure guard, high/crit hard-fail) | PROPOSAL §P5-T1/§475-598; MEMO §243/250/251 | generic "no quality-floor loss" only | **DROPPED INCORRECTLY (F-H-2)** |
| A/B/C/D 4-arm attribution (C-vs-D = CEM's contribution) | MEMO §142/§6; PROPOSAL P5-A1 | collapsed to single A/B | **PROPERLY MERGED but lossy (F-M-2)** |
| High/critical-recall hard-fail floor | PROPOSAL §356/§477/§487/§598; benchmarks.md | vague "zero quality-floor loss" | **UNDER-SPECIFIED (F-H-3)** |
| Protected/blind ground truth | PROPOSAL G4; benchmarks.md | not referenced in gates | **UNDER-SPECIFIED (F-M-5)** |
| schemathesis dependency-budget sign-off | PROPOSAL §165 | not carried | **DROPPED (F-M-3)** |
| CEM Phase-1 freeze | XYZ / code | PRESERVED | ✓ |
| Anti-roadmap rejections | audit §13 | PRESERVED | ✓ |
| Human-review-before-submit | code | PRESERVED | ✓ |

---

## 4. Critical Findings

### F-C-1 — Security-gate sequencing is self-contradictory; breadth may expand before its containment exists — **CRITICAL — BLOCKS FREEZE**
- **Location:** §1, §5 (Phase S groups + Phase 3 prereq), §6 (mandatory gates), §9, §12, §14.2.
- **Claim in doc:** §6/§14.2 list "**Execution-isolation floor (rootless per-run) + hook tamper-resistance**" among the
  **mandatory gates that "block breadth expansion until met"** and that must pass before "anything that expands
  autonomous execution begins." **Simultaneously**, §4 (`Phase S→3`), §5 (Phase 3 prereq: "C2 boundary in place *by end
  of this phase*"), §9 ("in place by end of Phase 3"), and §12 place C2 as late as the *end* of Phase 3.
- **Why it's wrong:** Phase 3 **is** the breadth expansion — §5 titles it "Discovery Amplification" and calls it "peak
  hostile-content ingestion." So the permissive reading runs autonomous discovery amplification (maximal attack-surface
  ingestion) *before* the isolation boundary that is supposed to contain it. The two statements cannot both hold: C2
  is either a hard pre-expansion gate or a by-Phase-3 deliverable.
- **Evidence:** §6 "block breadth expansion until met" + §14.2 gate list **vs** §5 Phase 3 prereq "by end of this
  phase" + §9. The audit was actually clearer (§9/§15): P0 items (fail-closed hook, secrets-out) gate *immediately*;
  C2 (P1) "by end of Phase 3 *at the latest*." FINAL merged C2 into the immediate-gate list and lost that distinction.
- **Impact:** an implementer could (a) over-block — build full rootless isolation before any Phase-2 foundation work,
  stalling everything; or (b) under-block — expand discovery breadth in Phase 3 with no containment, the precise
  security failure the floor exists to prevent. Either misdirects implementation on a security boundary.
- **Recommended correction:** split the floor explicitly. **Tier-1 (hard pre-Phase-2 gate):** fail-closed hook + CI
  block-test, secrets-out, `--os-shell` confirm. **Tier-2 (must complete before the *breadth-expanding* portion of
  Phase 3 begins, not "by end"):** rootless boundary + hook tamper-resistance. State that discovery amplification does
  not start until Tier-2 passes.
- **Blocks freeze? YES.**

---

## 5. Major Findings

### F-H-1 — Hunt postmortem / self-evaluation (P2-E1) silently dropped — **HIGH — BLOCKS FREEZE**
- **Location:** §4 matrix, §5 Phase 2 groups (has "negative-knowledge + capability-utilization signal", **no
  postmortem**).
- **Claim/omission:** FINAL's Phase 2 does not contain the hunt postmortem / self-evaluation capability.
- **Why it matters:** in the corpus this is a **committed work package with a full spec** (`PROPOSAL §P2-E1`: offline,
  read-only, never self-modifying, no auto-retry, planted-fixture precision/recall, independent cross-check vs
  `audit_log`/`case_store`, secret redaction) **and** an **UNKNOWN-UNKNOWN IMPORTANT GAP (#24)**. It is also a stated
  precondition ("the … postmortem substrate is the precondition for P3 measurement and P4/P5 decisions") and is
  *extended* in P4. Dropping it removes both a capability and a set of safety guardrails from the canonical plan.
- **Evidence [doc]:** `MASTER-ROADMAP-PROPOSAL.md:249,271-322`; `UNKNOWN-UNKNOWN-RESEARCH.md:76,461`.
- **Impact:** the plan a future engineer follows would omit a committed, safety-bounded introspection capability, and
  Phase 3's "measured base" loses part of its stated precondition.
- **Correction:** re-insert P2-E1 as a Phase-2 committed item with its read-only / no-self-modify / no-auto-retry /
  redaction / planted-fixture-recall guardrails and independent verification. If the intent was to fold it into
  "negative-knowledge", say so explicitly and preserve the guardrails.
- **Blocks freeze? YES.**

### F-H-2 — Phase-5 security-of-methodology invariants under-specified — **HIGH — BLOCKS FREEZE**
- **Location:** §5 Phase 5 (non-goals = self-modification/unattended/parallelism only), §11 (generic "no quality-floor
  loss").
- **Why it matters:** the corpus defines *hard, explicit* safety gates for the allocation/learning program that FINAL
  reduces to a vague phrase. Missing invariants: **`false-reuse-causing-missed-test rate == 0`** (P5-T1 gate; "a false
  reuse causing a missed security test is a SECURITY FAILURE, not a cost metric"); **allocation/dedupe/negatives must
  never hard-block a not-yet-confirmed novel test** (hints, never skips); **cheap-tier severity-gated
  minimum-effort/premature-closure guard**; **any high/critical miss vs frontier baseline hard-fails the config.**
- **Evidence [doc]:** `PROPOSAL:464,475,480,489,560,578,579,595,597,598,627,711-712,767`; `MEMO:243,250,251`.
- **Impact:** without these named in the canonical plan, a P5 implementation could ship an allocation policy that
  suppresses novel tests or lets a cheap tier close high-severity hypotheses — degrading recall while passing a generic
  "quality-floor" check.
- **Correction:** add these four invariants verbatim to Phase 5 non-goals/gates and to §11's promotion criteria.
- **Blocks freeze? YES.**

### F-H-3 — High/critical-recall hard-fail floor not named as the protected quality gate — **HIGH — SHOULD FIX BEFORE FREEZE**
- **Location:** §5 Phase 3/5 acceptance, §11, §15 (all say "zero quality-floor loss" / "FCC=0" but not the explicit
  high/critical hard-fail).
- **Why it matters:** the memo/proposal make "**no high/critical the baseline finds may be lost**" a *hard-fail* gate
  (not a soft Pareto), and benchmarks.md makes missing a high/critical finding a hard quality failure. "Quality-floor
  loss" is ambiguous; the freeze doc should name the exact hard constraint (high/critical recall ≥ baseline−ε; FP ≤
  baseline; coverage ≥ baseline) and mark it hard-fail for P3 and P5.
- **Evidence [doc]:** `PROPOSAL:305,356,477,487,516,598`; `benchmarks.md` quality gates.
- **Impact:** an implementer could interpret "quality-floor loss" leniently.
- **Correction:** define the hard floor explicitly and cite it in every P3/P5 gate.
- **Blocks freeze? YES (safety gate clarity).**

### F-H-4 — Coverage metric consumed before its instrument (H3) is built — **HIGH — SHOULD FIX BEFORE FREEZE**
- **Location:** §5 Phase 2 ("telemetry emits … coverage"), Phase 3 (breadth/coverage measured) vs §4/§5 (coverage
  matrix H3 = Phase 4).
- **Why it matters:** Phase 2/3 acceptance depends on a coverage signal, but the coverage object (H3, endpoint×class×
  role) is not delivered until Phase 4. Either "coverage" in P2/P3 is a simpler signal than the H3 matrix (then say so
  and define it), or H3 must move earlier. As written, a metric is used before its instrument exists.
- **Evidence:** §5 Phase 2 acceptance vs §4 row "Coverage matrix … Phase 4/measure".
- **Correction:** define a minimal Phase-2 coverage signal distinct from the Phase-4 H3 matrix, or pull H3's core into
  Phase 2's measurement substrate. Resolve the §4/§5/§10 phase inconsistency for H3 while doing so.
- **Blocks freeze? Recommended before freeze (dependency correctness).**

---

## 6. Minor Findings

- **F-M-1 (MEDIUM) — C1a scope realism.** §8 promises discovery evidence "bound to the actual HTTP request/response";
  but scanner-sourced evidence (nuclei/sqlmap/subfinder) is tool-narrated output, not structured per-exchange. A
  universal wire-capture seam is *not* the "smallest useful milestone" and risks becoming an evidence platform (the
  very thing §7 of this review's mandate warns against). *Correction:* scope C1a to evidence classes that can be
  wire-bound now (curl/`tool_resolver`, `browser-mcp`, `oob-mcp`, CEM's `fetch_fn`) as **wire-level provenance**, and
  scanner output as **invocation-level provenance** (bind to the tool invocation + raw captured stdout), not per-HTTP
  exchange. Blocks freeze? NO (scope note), but strongly recommended.
- **F-M-2 (MEDIUM) — A/B/C/D collapsed.** §11 reduces the memo's 4-arm experiment (A frontier-heavy / B fixed-mixed / C
  adaptive / D CEM-assisted) — whose **C-vs-D ablation is "the entire attribution of CEM's contribution"** — to a
  single "adaptive allocation pays off" A/B. *Correction:* restore the four arms and the C-vs-D attribution in the P5
  gate. Blocks freeze? NO.
- **F-M-3 (MEDIUM) — schemathesis dependency-budget sign-off dropped.** Proposal marks it "Adopt (P3), **pending
  dependency-budget sign-off**"; adding a dependency is a repo stop-condition. FINAL lists schemathesis→CEM GATED but
  omits the dependency-approval gate. *Correction:* add "new-dependency approval" as an explicit P3 precondition. NO.
- **F-M-4 (MEDIUM) — "fail-closed" P0 item needs scoping.** The hook fails open on malformed input *by design* ("never
  break the session", `scope_gate_hook.py:main` return 0). A naive "fail closed" that blocks all sessions on any hook
  error would harm usability. *Correction:* scope fail-closed to *target-touching* calls; on internal error, block the
  gated call, not the whole session. NO.
- **F-M-5 (MEDIUM) — protected/blind ground truth not referenced.** FINAL's gates never cite the benchmark-integrity
  discipline (blind ground truth, independence, anti-gaming, no auto-derived oracle) from `benchmarks.md`/proposal G4.
  *Correction:* reference it in §11 and §15. NO.
- **F-M-6 (MEDIUM) — H3 phase inconsistency.** §4 "Phase 4/measure", §5 "Phase 4", §10 "Phase 4/measurement" — resolve
  to one placement (ties to F-H-4). NO.
- **F-L-1 (LOW) — H4 phase inconsistency** ("any phase" §4/§10 vs Phase 3 §5).
- **F-L-2 (LOW) — phase numbering** (no "Phase 1"; first new phase is "Phase 2" — inherited from the proposal; note it
  once to avoid confusion).
- **F-L-3 (LOW) — C3 "depends on C1a"** is stated as a hard dependency; it is desirable (re-validation evidence should
  be provenance-bound) but not strictly blocking. Soften to "should".
- **F-L-4 (LOW) — header provenance of claims.** "verified against code during the audit" — this review re-verified
  them current; add the re-verification note so the freeze rests on a current check.

---

## 7. CEM Freeze Audit

**PASS — no reopening.** FINAL keeps CEM frozen and does not translate any Xalgorix/verifier finding into a "replace
CEM" requirement:
- §2/§7: CEM stays post-confirmation validation; later phases *feed* CEM (Phase 3 wires confirmed→CEM; Phase 5 uses
  signatures) rather than replacing it. **[code✓: `case_store` gates CEM on `CONFIRMED`; `SuccessSignature` HTTP-only.]**
- §7 correctly bounds oracle reach (H2) as a research-only, one-dataclass question and mandates an *injected
  `observe_fn`* preserving `cem_engine.py` purity — "never by coupling."
- §7/§10 explicitly reject "confirmation is CEM" as architecture (analogy only) and reject building a competing
  verifier.
- **Watch item (not a finding):** §5 Phase 3 "CEM auto-run after independent validation" — ensure the wording cannot be
  read as relaxing the `CONFIRMED`/determinism-gate entry contract. Add "preserving the existing CEM entry
  precondition" to be unambiguous. FCC=0 is preserved as a gate (§5/§15). No wording currently reopens "frozen."

---

## 8. Security Floor Audit

- Fail-open hook + registration SPOF: **[code✓ + doc✓]** — P0 fail-closed + CI block-test is correctly mandated.
- Secret exposure: **[code✓]** full-`.env` load; scope-secrets-out P0 correct.
- Rootless boundary / tamper-resistance: correct as a floor **but mis-sequenced (F-C-1)** and the "fail-closed" item
  needs scoping (F-M-4).
- `--os-shell` confirmation tier: correctly P0/P1.
- Supply-chain (pinning/SBOM/CI SAST), CI `permissions:`, `watch.db` untrack: correctly classified **P2 later
  hardening** (release-hygiene / work-package), not architecture. **Good separation** — no OSS-audit operational item
  was over-promoted into architecture, and no mandatory prerequisite was demoted, **except** the C2 sequencing (F-C-1).
- **Classification check:** SECURITY GATE = fail-closed hook, secrets-out, os-shell confirm, rootless boundary; SECURITY
  WORK PACKAGE = tool-output-injection sanitization (UU-7), postmortem redaction; RELEASE-HYGIENE = pinning/SBOM/CI
  perms/watch.db untrack. This matches the audit. ✓

---

## 9. Provenance / C1 Audit

- **PASS on the conceptual distinctions.** §8 explicitly separates model-authored vs machine-captured vs tamper-
  evidence vs provenance and states "**Do not claim the gap is solved because hashes exist**" and "**reproducibility
  manifest value is unproven**" (C1b gated via A/B). It does **not** commit `hash = provenance` or `manifest = proven`.
  This is the strongest section. **[code✓ base.]**
- **Gap:** the *smallest-milestone* claim is not scoped for scanner-sourced evidence (F-M-1). Fix that scope so C1a
  cannot balloon into an evidence platform.

---

## 10. Phase Dependency Audit

Reconstructed graph: `CEM(frozen) ⟂ [Phase S] → Phase 2 → Phase 3 → Phase 4 → Phase 5`, with C1b (A/B) off Phase 2,
C3 depending on C1a + a watch↔case link.

- **FALSE/AMBIGUOUS DEPENDENCY:** C2 placement (F-C-1) — the graph shows C2 "in place by end of Phase 3" while the gate
  text requires it before expansion. **Must resolve.**
- **MISSING DEPENDENCY:** coverage signal (P2/P3) → coverage matrix H3 (P4) (F-H-4).
- **SOFT-STATED-AS-HARD:** C3→C1a (F-L-3).
- **No circular dependencies** found. Resurrection correctly does *not* depend on the invariant model (§5 exit gate:
  ships even if P4-M0 NO-GO). Info-gain depends on telemetry (correct). Allocation waits for P4 telemetry + P5-A0
  (correct). **UNNECESSARY SERIALIZATION:** H4 scan-headers is independent and could land anytime (§4 says "any");
  keep it off the critical path (minor).

---

## 11. Benchmark / Measurement Audit

- **Strengths:** §11 gives every gated item an experiment, metric, promotion criterion, and a defined failure outcome —
  and failure = defer, not ship. FCC=0 preserved. Rootless-utility is measured, not assumed.
- **WEAK/AMBIGUOUS METRIC (F-H-3):** "zero quality-floor loss" is not operationalized; name the hard high/critical-
  recall / FP / coverage floor.
- **UNPROTECTED GROUND TRUTH (F-M-5):** gates don't reference blind/protected ground truth or anti-gaming (H3 mentions
  an "anti-gaming clause" but the discipline isn't generalized).
- **METRIC/CLAIM MISMATCH (F-M-2):** collapsing A/B/C/D loses CEM-contribution attribution (C-vs-D).
- **Baselines:** Phase-2 false-positive baseline + telemetry are correctly required before Phase 3 (§14.3). Good.

---

## 12. P2 Audit (Foundation)

- Contains benchmark/telemetry, C1a, UU-7 injection, negative-knowledge/utilization, pinning/SBOM. **Missing the
  committed postmortem (F-H-1).** C1a scope realism (F-M-1). Coverage-signal-before-instrument (F-H-4). Otherwise the
  "measured, injection-hardened, provenance-bound base" is coherent and correctly gates downstream. Does **not** hide a
  platform rewrite. ✓ (with the three fixes).

## 13. P3 Audit (Discovery)

- Correctly framed as schemathesis→**CEM composition** (leverage is the composition, not another scanner), not "add
  scanners." CEM-in-hunt does not weaken frozen semantics (add the entry-precondition wording, §7 watch item). WFC/WFD
  validates value; high/critical regression must be the hard floor (F-H-3). Missing: dependency-budget sign-off for
  schemathesis (F-M-3); the C2-before-breadth sequencing (F-C-1). No unnecessary "Asset Graph platform" is introduced. ✓ (with fixes).

## 14. P4 Audit (Reasoning)

- **PASS on the critical guardrails:** P4-M0 gates the invariant model; **M0 NO-GO does *not* block resurrection /
  info-gain / coverage** (§5 exit gate — matches UU intent). Resurrection is an additive `case_store` query (no new
  store, no graph DB). Info-gain is gated. **Gaps:** FINAL does not explicitly state (a) invariants remain *hypotheses*
  that CEM must still prove, (b) invariant **false positives are a quality risk**, and (c) info-gain **orders but never
  hard-blocks** a novel test. These are in UU/memo; add them (part of F-H-2 family). No AALpy/graph-DB creeps in
  mandatorily. ✓ (with the guardrail re-insertions).

## 15. P5 Audit (Allocation / Learning)

- Correctly treated as a **gated research program** (P5-A0 GO, P5-T1 transfer, "deferred if evidence negative"). **But
  the specific do-no-harm invariants are dropped (F-H-2)** — this is the most safety-relevant omission in the document.
  A/B/C/D attribution collapsed (F-M-2). Deferral-as-success is present ("completes without it"). With F-H-2 + F-M-2
  restored, P5 is sound. Currently **not freezeable** on P5 alone.

---

## 16. Xalgorix Fidelity Audit

**PASS.** §7/§10 carry forward only what `XALGORIX-REVIEW.md` supports (H1 provenance = C1a; H2 oracle reach =
research-only; H3 coverage; H4 scan-headers; secure-SDLC CI insight) and correctly reject the historical mistakes:
- "confirmation is CEM" → rejected as analogy (§7/§10). ✓
- `audit_log` as evidence store → rejected (§4). ✓
- "evidence merely narrated" → correctly reframed as the two-path seam with the strong path gated (§8). ✓
- "convergence/direction-of-travel" → rejected (§4/§10). ✓
- HuntMCP CEM/case-store not underestimated → §3 credits determinism gate, verdicts, ddmin, machine-hashed evidence,
  hypothesis lifecycle. ✓
- current implementation vs roadmap-state not confused → §3 is code-grounded. ✓

No reintroduced Xalgorix error found.

---

## 17. Next-Gen Fidelity Audit

**PASS.** Option-B additive-substrate interpretation preserved; C1/C2/C3 represented; local-first + swappable boundary
(§9, §13); scope-secrets-out (§6); C1a/C1b split faithful to NEXT-GEN §63's own correction; same-target "isolated exec
+ shared immutable evidence" is implied by the provenance/append-only model (though **not stated explicitly** — LOW:
consider adding the same-target-session concurrency stance, which NEXT-GEN Q8 settled). No premature platformization.
`NEXT-GEN-PLATFORM-REVIEW.md` remains **absent**; §63 self-audit stands in (noted, acceptable).

---

## 18. Anti-Roadmap Audit

**PASS — no "rejected here, required there" leakage found.** Searched every phase/dependency for silent reintroduction
of: graph DB, control plane, cloud/K8s, secret broker, microVM-first, event-sourcing, capability-authority, generic
agent platform, unrestricted parallelism, AI IDE. None is required as infrastructure anywhere. Telemetry is *not*
event-sourcing; `chainer-mcp` remains the DAG (no graph DB); the rootless runtime is an approved small subprocess
dependency, not a platform. Capability-authority is explicitly *subsumed* near-term (§13), not quietly required.

---

## 19. Duplication / Naming Audit

| Pair | Verdict |
|---|---|
| provenance (C1a) vs manifest (C1b) vs lineage | RELATED BUT DISTINCT — correctly separated (§8) |
| memory vs negative-knowledge | RELATED BUT DISTINCT — memory = cross-run prior; negative-knowledge = within/near-run "what didn't work" (P2) |
| hypothesis resurrection vs continuous re-hunting (C3) | RELATED BUT DISTINCT — resurrection = re-open dormant hypothesis (P4 query); C3 = target-delta-triggered revalidation (P5) |
| coverage engine (H3) vs benchmark/measurement | SAME track, distinct object — needs the P2-signal vs P4-matrix disambiguation (F-H-4) |
| CEM verifier vs Xalgorix verifier | RELATED BUT DISTINCT — explicitly (§7); no conflation |
| CEM signature transfer vs causal signatures | SAME concept — consistent |
| monitoring vs continuous hunting | SAME (Phase 5); consistent |
| postmortem vs self-evaluation | SAME — and currently **dropped** (F-H-1) |
| execution boundary vs sandbox | SAME (C2); consistent |

No wrongful duplication introduced.

---

## 20. Implementation Realism Audit

- **First phase well-defined?** Phase S is concrete *except* the C2 tier ambiguity (F-C-1) and the fail-closed scope
  (F-M-4).
- **"Phase 2 = platform rewrite?"** No — but C1a must be scoped (F-M-1) or it drifts toward one.
- **"Phase 3 secretly requires Phase 4?"** Partially — the coverage metric it reports on is a Phase-4 object (F-H-4);
  fix by defining a P2 coverage signal.
- **"Phase 4 requires a full ML stack?"** No — invariant model is gated (P4-M0) and NO-GO degrades gracefully.
- **"Phase 5 assumes success of everything?"** No — every P5 item is individually gated; deferral is a valid outcome.
- **Two-engineer ambiguity:** C1a ("bound to the actual exchange") and "fail-closed" are the two items most likely to
  be interpreted differently — both flagged. Coverage "signal" vs "matrix" is a third.
- **Runnable gates?** Mostly yes; the vague "quality-floor loss" (F-H-3) is not runnable as written.

---

## 21. Required Corrections Before Freeze

**MUST FIX BEFORE FREEZE (4):**
1. **F-C-1** — resolve the C2 gating contradiction: split the floor into Tier-1 (hard pre-Phase-2 gate) and Tier-2
   (rootless boundary, must complete before Phase-3 *breadth expansion begins*, not "by end").
2. **F-H-1** — re-insert the hunt postmortem / self-evaluation (P2-E1) with its read-only / no-auto-retry /
   no-self-modify / redaction / planted-fixture-recall / independent-verification guardrails.
3. **F-H-2** — restore the explicit Phase-5 safety invariants (`false-reuse→missed-test == 0`; allocation/dedupe/
   negatives never hard-block a novel test; cheap-tier premature-closure guard; high/critical suppression = hard-fail);
   and the P4 guardrails (invariants remain CEM-provable hypotheses; info-gain orders, never blocks).
4. **F-H-3** — name the hard quality floor (high/critical recall ≥ baseline−ε; FP ≤ baseline; coverage ≥ baseline) and
   mark it hard-fail for P3 and P5, referencing `benchmarks.md`.

**SHOULD FIX BEFORE IMPLEMENTATION (5):**
- F-H-4 coverage signal vs matrix; F-M-1 C1a scope; F-M-2 restore A/B/C/D; F-M-3 schemathesis dependency sign-off;
  F-M-5 protected/blind ground-truth reference.

**CAN DEFER (5):** F-M-4 (fold into F-C-1 fix), F-M-6, F-L-1..L-4.

---

## 22. Final Freeze Recommendation

**C — DO NOT FREEZE — SIGNIFICANT CORRECTIONS REQUIRED.** Apply the four MUST-FIX corrections (§21); re-review the
diff; then the document is freezeable. The spine, security-floor concept, provenance elevation, CEM freeze, Xalgorix
dispositions, and anti-roadmap are all sound and require no change. No further research is needed — every correction is
a re-insertion or disambiguation traceable to the existing corpus.

---

## 23. Residual Uncertainties

1. The largest *product* unknown remains whether provenance/reproducibility raises triager acceptance (C1b) —
   correctly gated, not a review defect.
2. C1a's achievable provenance fidelity for scanner-sourced evidence is an engineering unknown until the capture seam
   is scoped (F-M-1).
3. Whether the four MUST-FIX corrections were merely compressed by the *audit* (and thus the audit also needs the
   note) vs newly lost in FINAL: the evidence (§3b) shows the postmortem/P5-invariant/A-B-C-D detail lives in the
   *proposal/memo*, was thinned in the audit, and is absent/vague in FINAL — so the audit is the compression point.
   This does not change the fix (they belong in the canonical plan) but is worth recording.

---

## 24. Audit Limitations & Self-Check

- **Files read this pass:** `MASTER-ROADMAP-FINAL.md` (full), `MASTER-ROADMAP-AUDIT.md`, and targeted verification
  across `MASTER-ROADMAP-PROPOSAL.md`, `INTELLIGENCE-ALLOCATION-MEMO.md`, `UNKNOWN-UNKNOWN-RESEARCH.md`,
  `OPEN-SOURCE-AUDIT.md`, `XALGORIX-REVIEW.md`, plus `benchmarks.md`. `XYZ.md`, `ARCHITECTURE.md`, `ROADMAP.md`,
  `PHASE1-PLAN.md`, `PHASE1-EXECUTION-PLAN.md`, `UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH.md`,
  `NEXT-GEN-PLATFORM-RESEARCH.md`, `XALGORIX-RESEARCH.md` were carried from prior full reads this session; the two
  ~230KB Phase-1 CEM docs were consulted at structure level, with CEM contract facts taken from code (stronger source).
  `NEXT-GEN-PLATFORM-REVIEW.md` is **absent**.
- **Code re-verified fresh this pass:** `scripts/hooks/scope_gate_hook.py` (fail-open), `mcp-servers/case_store.py:308/323`
  (`add_evidence` content:str), `mcp-servers/cem_engine.py:316-319` (`SuccessSignature`), `mcp-servers/watch-mcp/server.py`
  (no case linkage).
- **Self-check (did I NOT…):** skip a section — no (all 17 + tables + report read); trust prior synthesis without
  re-reading — no (re-read + re-verified code); confuse planned with implemented — no (§3 code-grounded); confuse
  hashes with provenance — no (that distinction is a *finding basis*, and FINAL itself keeps it); confuse Xalgorix with
  CEM — no (§16); reopen frozen CEM — no (§7 PASS); promote gated experiments into builds — checked, none; hide/omit a
  dependency — surfaced F-H-4, F-M-3; turn cleanup into architecture — no (§8 separation verified); omit security gates
  — surfaced F-C-1, F-H-2; omit benchmark integrity — surfaced F-H-3, F-M-5; omit human-decision boundaries — §14.6
  preserved.
- **Findings by severity:** CRITICAL 1 · HIGH 4 · MEDIUM 6 · LOW 4 (= 15 total).
- **Dropped/changed audit decision detected:** the hunt postmortem (P2-E1), the explicit P5 safety invariants, and the
  A/B/C/D attribution were thinned in `MASTER-ROADMAP-AUDIT.md` and are absent/vague in `MASTER-ROADMAP-FINAL.md`
  (§3b).
- **Freeze safe?** Not yet — **C**; safe after the four MUST-FIX corrections.
- **Output file created:** `FINAL-MASTER-ROADMAP-REVIEW.md`. No other file modified; nothing implemented, committed, or
  pushed.
