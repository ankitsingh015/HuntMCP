# FINAL-ZERO-SKIP-AUDIT.md — Last Pre-Cleanup Completeness Check

**Status:** independent zero-skip completeness audit. Read-only. No source code, no roadmap/architecture/research/audit
document was modified; no cleanup, no file moves/deletes, no `.gitignore` change, no commits, no pushes. Only this file
was created.

**Standard:** zero silent skip. Prior claims of "no orphans / all resolved / freeze passed" were **not trusted** — the
older `HUNTMCP-NEXT-GEN-PROPOSAL*` stream and its execution tracker were opened and traced independently, and
tracked/untracked git state was verified directly.

---

## 1. Executive Verdict

# ⛔ C — MATERIAL OMISSION FOUND — ROADMAP CORRECTION REQUIRED

`MASTER-ROADMAP-FINAL-v2.md` is architecturally sound and its spine is not in question (so **not D**). But it is **not
zero-skip**: it silently drops **VAL-AUTHZ** — the stateful/multi-step authorization differential engine that the
*older* HuntMCP-Next-Gen stream ranked as **Tier-1 rank #1 ("top capability bet", HIGH confidence)**, listed as a
committed early item (C1) in that stream's corrected roadmap, and still tracks as an **active `[ ]` NOT-STARTED task
(`T-VAL-AUTHZ`)** in `HUNTMCP-NEXT-GEN-EXECUTION-PLAN.md`. It appears nowhere in `MASTER-ROADMAP-PROPOSAL.md` or v2.
This is the exact "research detail → audit compression → final-roadmap omission" failure mode the process was supposed
to prevent — and here it hit the older stream's *highest-ranked* capability.

Two secondary partial gaps ride on the same stream (DISC-SPEC spec→endpoint model; ARCH-STATE recon/scan wiring).
Everything else in the entire corpus traces cleanly (preserved / merged / already-implemented / gated / deferred /
rejected). CEM remains frozen; the security floor, provenance, benchmark gates, anti-roadmap, and human-decision
boundaries are all intact.

**Correction required:** add VAL-AUTHZ (min version) to v2 as a **GATED** P3 capability item (gated on the benchmark
substrate; benefits from a spec→endpoint model; state-changing-mutation risk → idempotent default + human gate;
owner-fetch-compare oracle; exit = recovers multi-step authz the sweep misses at zero new FP, verdicts match ground
truth). This is a capability-item insertion into the existing P3 discovery phase — **not** an architecture change.
After that insertion, v2 is zero-skip and freeze-safe.

---

## 2. Repository Inventory (verified against filesystem + git)

- Branch `research/golden-nextgen` @ `fbbf26d`. Working tree matches the pasted inventory.
- Uncommitted (pre-existing, unrelated to this audit): `data/watch.db` (M), `mcp-servers/scope_guard.py` (M),
  `data/writeups/gtm-env-credential-liveness-oracle.md` (??), `scripts/remind-coderpad-retest.sh` (??).
- Major code areas present: `mcp-servers/` (30+ MCP servers incl. `idor-mcp`, `case_store`, `cem_engine`, `watch-mcp`,
  `chainer-mcp`, obscura/ad-recon/cloud-postexploit/local-privesc), `.opencode/` (agents/commands), `backend/` (Go
  service: cmd/internal/migrations/embedder), `tests/`, `scripts/`, `knowledge/`, `data/`.
- `NEXT-GEN-PLATFORM-REVIEW.md` **absent** (confirmed).

## 3. Complete Source Corpus Inventory

Read/traced this session (full or targeted-with-code-verification): XYZ, ARCHITECTURE, ROADMAP, PHASE1-PLAN,
PHASE1-EXECUTION-PLAN, MASTER-ROADMAP-PROPOSAL, MASTER-ROADMAP-AUDIT, MASTER-ROADMAP-FINAL (v1),
MASTER-ROADMAP-FINAL-v2, FINAL-MASTER-ROADMAP-REVIEW, FINAL-MASTER-ROADMAP-FREEZE-AUDIT,
INTELLIGENCE-ALLOCATION-MEMO, UNKNOWN-UNKNOWN-RESEARCH, UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH, OPEN-SOURCE-AUDIT,
NEXT-GEN-PLATFORM-RESEARCH, XALGORIX-RESEARCH, XALGORIX-REVIEW, **HUNTMCP-NEXT-GEN-PROPOSAL / -v2 / -v3 / -AUDIT /
-EXECUTION-PLAN** (the previously-unexamined older stream — opened this pass), plus AGENTS.md/CLAUDE.md/README and
`.claude/rules/benchmarks.md`. **Total material documents: 24.** `NEXT-GEN-PLATFORM-REVIEW.md` absent.

## 4. Source-by-Source Traceability

| Document | Purpose | Represented in v2? | Status |
|---|---|---|---|
| XYZ.md | CEM thesis; Phase-1 frozen; later phases (autonomous condition/variant, patch-bypass) | §2/§3/§7; later phases → P4/P5 | PRESERVED |
| ARCHITECTURE.md | system architecture incl. Batch-8 (coverage), planned sandbox note | coverage→H3; sandbox→C2 | PRESERVED/MERGED |
| ROADMAP.md | prior high-level roadmap | Option-C spine | PRESERVED |
| PHASE1-PLAN / -EXECUTION-PLAN | CEM Phase-1 build (frozen) | §3 frozen | ALREADY IMPLEMENTED |
| MASTER-ROADMAP-PROPOSAL | Option-C reconciliation (P2-E1, P5 invariants, A/B/C/D, WFC/WFD) | audit→v2 | PRESERVED/MERGED |
| MASTER-ROADMAP-AUDIT | reconciliation authority | v2 | PRESERVED |
| MASTER-ROADMAP-FINAL (v1) | first canonical | superseded by v2 | HISTORICAL |
| FINAL-MASTER-ROADMAP-REVIEW | pre-freeze audit (F-C-1..F-H-4) | fixes in v2 | PRESERVED |
| FINAL-...-FREEZE-AUDIT | freeze gate (A) | — | HISTORICAL (audit) |
| INTELLIGENCE-ALLOCATION-MEMO | allocation A/B/C/D, transfer, invariants | P5 (gated), §11-A | GATED/PRESERVED |
| UNKNOWN-UNKNOWN-RESEARCH | UU-1..8, #24 postmortem | P2 (postmortem, injection), P4/P5 | PRESERVED |
| UNIVERSAL-CAPABILITY-EXPOSURE | capability-exposure layer V4 | §4 DEFERRED (V4) | DEFERRED |
| OPEN-SOURCE-AUDIT | HuntMCP security gaps | §6 security floor | PRESERVED/MERGED |
| NEXT-GEN-PLATFORM-RESEARCH | Option B, C1/C2/C3, §63 self-audit | §8/§9/§6 | PRESERVED |
| XALGORIX-RESEARCH | competitor recon (uncorrected) | via review | HISTORICAL (corrected) |
| XALGORIX-REVIEW | corrective authority; H1–H4 | §10 | PRESERVED |
| HUNTMCP-NEXT-GEN-PROPOSAL v1/v2/v3 | older capability-first stream | partial (see §5/§7) | **PARTIAL — VAL-AUTHZ DROPPED** |
| HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT | that stream's skeptical review (ranked VAL-AUTHZ #1) | not carried | **PARTIAL — DROPPED item** |
| HUNTMCP-NEXT-GEN-EXECUTION-PLAN | living V3 tracker (T-VAL-AUTHZ active) | not reconciled with v2 | **PARTIAL — orphaned tracker** |
| AGENTS.md / CLAUDE.md / README | operational docs | n/a | HISTORICAL/OPERATIONAL |

Every "HISTORICAL/superseded" classification is justified by an explicit successor. The three PARTIAL rows are the
finding.

## 5. Research Stream Coverage (100%)

- **A. XYZ:** thesis (CEM proof engine) preserved & frozen; later-phase autonomous condition/variant/patch-bypass →
  v2 P4/P5. ✓
- **B. Intelligence Allocation:** A/B/C/D, C-vs-D attribution, transfer, hard-floor, cheap-tier/premature-closure,
  no-suppress invariants → v2 §5(P5)/§11/§11-A. ✓ (restored in v2 after the review).
- **C. Unknown-Unknown:** UU-1 invariant (P4 gated), UU-2 resurrection (P4), UU-3 info-gain (P4), UU-6 schemathesis
  (P3), UU-7 injection (P2), #24 postmortem (P2, restored). ✓
- **D. Universal Capability Exposure:** capability-exposure layer → DEFERRED V4. ✓
- **E. OSS audit:** fail-open hook, secrets, os-shell, root Docker, unpinned tools → security floor + P2 hardening. ✓
- **F. Next-Gen (platform):** Option B additive substrate, C1a/C1b/C2/C3, local-first, swappable boundary,
  scope-secrets-out, isolated-exec+shared-immutable-evidence → v2. ✓
- **G. Xalgorix:** H1 provenance (C1a), H2 oracle reach (research-only), H3 coverage, H4 scan-headers; rejects
  (confirmation-is-CEM, audit_log-as-evidence, ledger-as-graph, direction-of-travel, resource-admission) → v2 §10. ✓
- **(Older) HuntMCP-Next-Gen capability stream:** P0-BENCH✓(P2), DISC-VARIANT✓(P5), VAL-COND✓(XYZ P5),
  EFF-SCHED✓(info-gain P4), EFF-ALLOC✓(P5 allocation), LEARN-SIG✓(signature transfer P5), LEARN-KG✓(rejected: graph),
  DISC-GRAPH✓(chainer + graph-DB rejected), concurrency-fix✓(superseded by append-only model), ARCH-STATE◐(partial),
  DISC-SPEC◐(partial), **VAL-AUTHZ ✗ DROPPED.**

## 6. Historical Correction Chain

research → critical review → master proposal → master audit → final v1 → pre-freeze review → v2 → freeze audit. Every
correction from the *later* chain survived into v2 (verified in the freeze audit: F-C-1..F-H-4 present; no earlier
correction removed; no historical Xalgorix error reintroduced). **The break is not inside this chain — it is at the
*merge point* where the older HuntMCP-Next-Gen capability stream (v3 + its audit + its execution tracker) was never
reconciled into MASTER-ROADMAP-PROPOSAL.** MASTER-ROADMAP-PROPOSAL contains **0 references** to VAL-AUTHZ / DISC-SPEC /
DISC-VARIANT / ARCH-STATE / EFF-SCHED tags, and states it "does not supersede the thesis" — it never claimed to
supersede the V3 capability stream, and no document maps that stream's items across. VAL-AUTHZ fell through that gap.

## 7. v2 Capability Inventory (classification)

ALREADY IMPLEMENTED: CEM P1, hypothesis store, content-addressed evidence, state isolation, memory/lessons/writeup,
watch diffing, chainer DAG, human-review-before-submit. COMMITTED: Tier-1 floor (fail-closed hook, secrets-out,
os-shell), Tier-2 rootless boundary, C1a provenance, P2-E1 postmortem, UU-7 injection, benchmark+telemetry, coverage
instrument (P2), coverage matrix (P4), pinning/SBOM/SAST, H4 scan-headers, CEM-in-hunt, differentiation.
GATED: C1b manifest, schemathesis→CEM, H2 oracle reach, invariant model (P4-M0), info-gain, C3 delta.
DEFERRED: adaptive allocation (P5-A0), cross-target transfer (P5-T1), human-gated toolkit, capability layer (V4),
resource-admission. REJECTED: confirmation-is-CEM, audit_log-as-evidence, ledger-as-graph, control plane, cloud/K8s,
secret-broker build, microVM-local, graph DB, event-sourcing, AI IDE, unrestricted parallelism.
**Missing (should be GATED, is absent): VAL-AUTHZ.**

## 8. Capability Coverage Matrix (§7-list check)

All items from the prompt's capability list are represented **except**: **stateful/multi-step authorization
(VAL-AUTHZ)** — the closest v2 items (schemathesis→CEM business-logic/authz; invariant model; existing `idor-mcp` +
access-control skills) do **not** provide VAL-AUTHZ's distinctive mechanics (owner-fetch-and-compare oracle; two-step
replay under a second identity holding earlier steps; unauth/low-priv/admin/tenant-B role matrix). Partial:
**spec→endpoint model** (DISC-SPEC) present only insofar as schemathesis consumes schemas, not as a surface-expansion
step feeding authz; **recon/scan → case-mcp wiring** (ARCH-STATE) absent (measured decision in the older stream).
Everything else (CEM/determinism/evidence/provenance/lineage/security-floor/isolation/hook/secrets/scope/budget/audit/
injection/dangerous-action/watch-db/coverage/telemetry/utilization/negative-knowledge/postmortem/discovery/schema-fuzz/
CEM-in-hunt/differentiation/parallel-fanout[deferred]/asset-graph[=chainer]/invariant/resurrection/causal-signatures/
variant/info-gain/human-escalation/long-horizon-benchmark/allocation/A-B-C-D/C-vs-D/transfer/amortization/skill-router
[deferred]/cross-target[deferred]/anti-anchoring[via C-vs-D+blind GT]/continuous/self-expansion[human-gated]) is
represented.

## 9. Security Completeness

Rebuilt from OSS-audit + Next-Gen + memo + code; every item classified and present in v2:
MANDATORY GATE: fail-closed hook (Tier-1), secrets-out (Tier-1), os-shell confirm (Tier-1), rootless isolation +
hook-tamper (Tier-2), scope-gate liveness (CI). ROADMAP WORK: tool-output-injection (UU-7, P2). RELEASE HYGIENE:
pinning/SBOM/CI-SAST/CI-perms/watch.db-untrack (P2). DEFERRED: capability-authority, secret broker, resource-admission.
Preserved invariants: FCC==0, false-reuse→missed-test==0, no-suppress-novel-test, cheap-tier-closure guard,
cross-target contamination prevention, stale-signature-never-authoritative-skip, human-review-before-submit,
no-self-modification, injection/untrusted-content boundary, benchmark blindness. SSRF/redirects/non-idempotent/race are
covered by existing skills + the idempotent-default + human-gate discipline (VAL-AUTHZ's state-changing risk would
inherit the same, another reason to place it explicitly). **No mandatory item was demoted to release hygiene.**

## 10. Benchmark / Measurement Completeness

Every listed benchmark has baseline + protected/blind ground truth + metric + threshold + failure behavior +
independent verification: Phase-1 gates + FCCR (frozen); P2 injection corpus; replay/lineage; utilization;
negative-knowledge; **postmortem planted-fixture recall**; WFC/WFD (P3, blind, high/crit hard-floor); invariant
benchmark (P4-M0, blind); long-horizon (P4, blind); A/B/C/D + C-vs-D (P5, held-out); CEM transfer (P5-T1,
missed-test==0); C1b triager-acceptance A/B; coverage (P2 instrument → P4 matrix, anti-gaming); severity-weighted
yield; cost accounting. **Gap tied to the finding:** VAL-AUTHZ's benchmark (planted multi-step authz labels on the
benchmark range) is defined in the older stream but absent from v2 because the capability is absent. No other
measurement gap.

## 11. CEM Completeness

| CEM capability | State | Frozen? | Future integration | Modify frozen? | v2 location |
|---|---|---|---|---|---|
| Proof/validation (determinism, classify, ddmin, verdicts) | implemented | YES | consumed everywhere | NO | §3/§7 |
| Evidence feeding CEM (provenance) | gap on discovery path | n/a (case_store) | C1a | NO | §8 |
| CEM-in-hunt (auto-run after validation) | future | preserves entry precondition | P3 | NO | §5/§7 |
| Signature reuse / transfer | future | — | P5-T1 (gated) | NO | §5/§7 |
| Oracle reach (browser/OOB) | gap | — | research-only, injected observe_fn | NO | §7 |
| Autonomous condition extraction (VAL-COND) | future | — | XYZ §5 later phase | NO | XYZ (v2 defers) |
| Active variant probing (DISC-VARIANT) | future | — | P5 causal signatures | NO | §7 |

No source introduced a legitimate CEM requirement that disappeared from v2. Distinctions (proof vs discovery-feeding vs
signature-reuse vs oracle-reach) are all preserved. CEM frozen. ✓

## 12. Next-Gen Completeness

All meaningful Next-Gen conclusions present: engagement/session/research-run hierarchy (C1 primitive), reproducibility
(C1a/C1b), environment-as-evidence (C1b gated), execution boundary (C2/Tier-2), local-first + swappable boundary,
evidence manifest/hash-chain/lineage (provenance §8; hash-chain via content-addressing), same-target multi-session +
shared immutable evidence (append-only model), target snapshot/delta/affected-hypotheses/revalidation (C3), platform
boundary = local application, secret-broker deferred, capability-authority deferred, graph/event-sourcing/control-plane/
microVM rejected/deferred, product boundary. ✓

## 13. Xalgorix Completeness

H1 provenance→C1a; H2 oracle reach→research-only; H3 coverage→P2 instrument/P4 matrix; H4 scan-headers→P3.
Deterministic confirmers = already stronger; hypothesis ledger = already have; verification isolation → reinforces C2;
resource-admission = deferred; evidence/reporting seam = C1a; audit_log **not** evidence (rejected); scope findings =
HuntMCP ahead; rate-limit/shims = insight; secure-SDLC = P2 SAST. No historical Xalgorix misconception reintroduced. ✓

## 14. Commitment-Level Audit (research-only vs build)

C1a COMMITTED (verified gap); C1b GATED (A/B); C2 COMMITTED floor; C3 GATED; P2-E1 COMMITTED; schemathesis GATED
(+dep-approval); invariant M0→M1 GATED; AALpy/RESTler — not committed (invariant/authz mechanisms; RESTler cited only
as prior art for VAL-AUTHZ); active allocation DEFERRED (P5-A0); CEM amortization/transfer DEFERRED (P5-T1); Skill
Router DEFERRED (V4); cross-target DEFERRED; continuous GATED (C3); anti-anchoring via C-vs-D + blind GT; self-expansion
GATED + human-gated. **No speculative item is an unconditional build. VAL-AUTHZ should be GATED, not COMMITTED, when
added** (gated on the benchmark; flag-off rollback to the existing sweep).

## 15. Dependency Graph (independent reconstruction)

`CEM(frozen) ⟂ [S Tier-1] → P2 → [S Tier-2] → P3 → P4 → P5`; C1b off P2 (A/B); C3 uses C1a + watch↔case link; coverage
instrument (P2) → coverage matrix (P4); invariant M0→M1 (P4); allocation gated P5-A0; transfer P5-T1. **No circular,
false, or hidden dependency; no metric-before-instrument; no capability-before-security-boundary** (all resolved in v2).
**Insertion point for VAL-AUTHZ:** P3, after/with a spec→endpoint model (DISC-SPEC), gated on the benchmark substrate;
its state-changing mutations inherit the idempotent-default + human-gate; parallel to schemathesis→CEM (they cover
different bug classes — property-fuzz vs multi-identity differential).

## 16. Repo-vs-Roadmap Gap Audit

- **`idor-mcp` (implemented, single-request two-account):** this is precisely VAL-AUTHZ's baseline → **SHOULD BE
  ROADMAP** (strengthen it). Reinforces the finding.
- **Go backend (`backend/`):** implemented, a *mostly-independent* hosted-service part (per CLAUDE.md) — writeup RAG +
  MCP bridge + Postgres/pgvector. v2 (the agent-capability roadmap) has **0** backend mentions. Classification:
  IMPLEMENTED, SEPARATE CONCERN — legitimately outside this roadmap's scope, but its exclusion should be **stated**
  (currently silent). Non-blocking; note in v2's scope boundary.
- **Batch-8 (Coverage Engine, tool-output-injection):** represented (coverage instrument/matrix; UU-7).
- **30+ MCP servers, cloud/AD post-exploit, obscura, watch/delta, benchmark infra, provider gateway
  (`model_gateway.py`):** IMPLEMENTED, not individually roadmap-worthy (component inventory, not capability roadmap);
  provider gateway relates to deferred provider abstraction (fine).
- No other implemented-but-unroadmapped capability of roadmap significance found.

## 17. Orphan-Roadmap-Item Audit (v2 items with no real source)

Every v2 item traces to a source: security floor (OSS-audit + code), C1a (Next-Gen + Xalgorix + code), C1b (Next-Gen),
C2 (Next-Gen + Xalgorix), C3 (Next-Gen + watch code), postmortem (proposal P2-E1 + UU #24), coverage (Xalgorix H3 +
Batch-8), schemathesis (UU-6/proposal), invariant/resurrection/info-gain (UU-1/2/3), allocation/transfer (memo),
H2/H4 (Xalgorix). **No orphan/synthesis-invented architecture found.** (v2 is, if anything, under-inclusive — the
opposite failure — which is what produced the VAL-AUTHZ omission.)

## 18. Human Decision Completeness

All substantive human decisions have a state: platform identity/primitive/sandbox/secrets/persistence/multi-session
(DECIDED via NEXT-GEN §59); C1b promotion (DEFERRED-TO-EXPERIMENT); invariant M1 (DEFERRED via P4-M0); allocation
GO/NO-GO (DEFERRED via P5-A0); cross-target transfer (DEFERRED via P5-T1); capability layer (DEFERRED V4);
self-expansion (human-gated); new dependencies (DECIDED: require approval); protected-doc integration (OPEN — needs
authorization). **New open decision surfaced by this audit:** whether VAL-AUTHZ enters the roadmap (STILL OPEN — this
audit's recommendation is to add it, gated). No prior human decision disappeared silently.

## 19. Anti-Roadmap Completeness

Every rejected/deferred direction (control plane, cloud/K8s, graph DB, secret broker, event-sourcing,
capability-authority, generic agent platform, unrestricted parallelism, AI IDE, autonomous self-expanding execution,
resource-admission) is consistent — rejected/deferred in §13 and **not** silently required elsewhere (re-scanned §5/§8/
§9/§11/§12). LEARN-KG "knowledge graph" is correctly rejected (both this and the older stream's audit rejected graph
infra; `chainer` is the only DAG). No leak.

## 20. Cleanup / Public-Repo Readiness (recommendation only — nothing moved)

| Class | Files |
|---|---|
| **A. Public authoritative** | `MASTER-ROADMAP-FINAL-v2.md` (after the VAL-AUTHZ fix), `XYZ.md`, `ARCHITECTURE.md`, `README.md`, `CLAUDE.md`, `AGENTS.md` |
| **B. Public historical** | `ROADMAP.md`, `MASTER-ROADMAP-PROPOSAL.md`, `PHASE1-PLAN.md`, `PHASE1-EXECUTION-PLAN.md`, `HUNTMCP-NEXT-GEN-PROPOSAL{,-v2,-v3,-AUDIT}.md` |
| **C. Internal research** | `NEXT-GEN-PLATFORM-RESEARCH.md`, `XALGORIX-RESEARCH.md`, `INTELLIGENCE-ALLOCATION-MEMO.md`, `UNKNOWN-UNKNOWN-RESEARCH.md`, `UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH.md` |
| **D. Internal audit** | `MASTER-ROADMAP-AUDIT.md`, `FINAL-MASTER-ROADMAP-REVIEW.md`, `FINAL-MASTER-ROADMAP-FREEZE-AUDIT.md`, `XALGORIX-REVIEW.md`, `HUNTMCP-NEXT-GEN-PROPOSAL-AUDIT.md`, `OPEN-SOURCE-AUDIT.md`, this file |
| **E. Redundant / safe to archive** | `MASTER-ROADMAP-FINAL.md` (v1 — superseded by v2); `HUNTMCP-NEXT-GEN-EXECUTION-PLAN.md` (V3 tracker — **only after** VAL-AUTHZ/DISC-SPEC/ARCH-STATE are reconciled into v2; do not archive an active tracker with an unmigrated Tier-1 item) |

**Two special cautions:**
1. **Do NOT archive `HUNTMCP-NEXT-GEN-EXECUTION-PLAN.md` before the VAL-AUTHZ reconciliation** — it is the only place
   `T-VAL-AUTHZ` is tracked; archiving it now would bury the omission permanently.
2. **`OPEN-SOURCE-AUDIT.md` is TRACKED and describes HuntMCP's own live security gaps** (fail-open hook, secret
   exposure, root Docker, os-shell). If the repo is/goes public, those are disclosed; the security floor closes them,
   after which the disclosure is historical. Flag for the owner — not a deletion recommendation.

Suggested target structure (recommendation, not an action): `docs/roadmap/` (authoritative + historical),
`docs/research/` (C), `docs/audits/` (D), keep v2 at a stable canonical path.

## 21. .gitignore Readiness

- **CURRENT STATE:** `.gitignore` has **no** research/roadmap `.md` patterns (only `RESUME-POINT.md`,
  `RESEARCH-TODO.md`, `AGENT-BRIEF.md`, `data/writeups/cve-*.md`, and data/vector/log artifacts). Tracked corpus: XYZ,
  ROADMAP, ARCHITECTURE, MASTER-ROADMAP-PROPOSAL, all 5 HUNTMCP-NEXT-GEN-* files, memo, UU, universal-capability,
  OSS-audit, PHASE1×2. **Untracked (new, uncommitted):** MASTER-ROADMAP-AUDIT/FINAL/FINAL-v2, both FINAL-* audits,
  NEXT-GEN-PLATFORM-RESEARCH, XALGORIX-RESEARCH/REVIEW (and this file).
- **RECOMMENDED STATE:** decide per-file whether each is public (commit) or internal (move under an ignored
  `docs/internal/` or a private location). The untracked files can be organized freely — **no history surgery needed**
  because they were never committed.
- **MIGRATION REQUIRED?** Only if you want the *tracked* historical/internal docs relocated — a normal `git mv`; their
  history stays public regardless.
- **HISTORY REMOVAL REQUIRED?** **No** — unless the owner decides `OPEN-SOURCE-AUDIT.md`'s pre-fix security-gap detail
  should not remain in public history; that is a deliberate owner choice (filter-repo), **not** an automatic
  requirement, and per the prompt public historical research should not be erased merely for convenience.

## 22. Missing / Omitted Items (the findings)

| ID | Item | Source authority | v2 status | Severity | Where it should enter |
|---|---|---|---|---|---|
| **Z-1** | **VAL-AUTHZ** — stateful/multi-step authorization differential engine (owner-fetch-compare oracle; two-step replay under a second identity; role matrix) | NEXT-GEN-PROPOSAL v3 §5.2 (**top bet**); its AUDIT §15/§16 (**Tier-1 #1, C1**); EXECUTION-PLAN `T-VAL-AUTHZ` (active) | **ABSENT** | **MATERIAL (C)** | **P3, GATED** — parallel to schemathesis→CEM; gated on benchmark; idempotent-default + human-gate; exit = recovers multi-step authz the sweep misses at zero new FP |
| Z-2 | DISC-SPEC — parse OpenAPI/GraphQL into a stateful endpoint/parameter model (surface expansion feeding authz + scan) | v3 §5.3; EXECUTION-PLAN `T-DISC-SPEC` | PARTIAL (only via schemathesis) | MEDIUM | P3 — make explicit as the surface-expansion step feeding Z-1 |
| Z-3 | ARCH-STATE — wire recon/scan agents into case-mcp (durable cross-pipeline provenance) | v3 §5.6; EXECUTION-PLAN `T-ARCH-STATE` | ABSENT (measured decision) | LOW | note as a measured reliability item under Phase 2 (or explicitly defer) |
| Z-4 | Go backend scope boundary | CLAUDE.md; `backend/` | unstated in v2 | LOW (editorial) | add one line to v2 scope: backend is a separate concern, out of this roadmap |

## 23. Non-Blocking Historical / Editorial Items

- v1 (`MASTER-ROADMAP-FINAL.md`) coexists with v2 — archive after freeze (housekeeping).
- `NEXT-GEN-PLATFORM-REVIEW.md` absent — v2/§63 substitution is fine.
- Phase numbering (no "Phase 1"; first new phase = "Phase 2") — already noted in v2.
- VAL-COND, DISC-VARIANT, EFF-SCHED, EFF-ALLOC, LEARN-SIG, LEARN-KG, DISC-GRAPH, concurrency-fix from the older stream
  are all adequately covered/superseded/rejected (§5) — no action.

## 24. Final Zero-Skip Decision

**C — MATERIAL OMISSION FOUND — ROADMAP CORRECTION REQUIRED.**

- **Omitted (material):** Z-1 VAL-AUTHZ.
- **Correction:** insert VAL-AUTHZ (min) into v2 as a GATED P3 capability item, with Z-2 (DISC-SPEC) made explicit as
  its feeding step; add Z-3 note and Z-4 scope line. None of these change the architecture/spine, the phase graph, CEM
  freeze, the security floor, or any gate — they add one high-value capability the corpus already vetted (Tier-1 #1)
  and two small clarifications. **After that edit, the roadmap is zero-skip and remains freeze-safe.**
- Not D: no architectural direction is missing; the spine is valid.

---

## Final Report

- **Total documents inspected:** 24 (incl. the previously-unexamined 5-file older HuntMCP-Next-Gen stream);
  `NEXT-GEN-PLATFORM-REVIEW.md` absent.
- **Code areas freshly verified this pass:** git tracked/untracked state of the full corpus; `.gitignore` contents;
  `backend/` presence; `idor-mcp` as VAL-AUTHZ's baseline (via the V3 OBSERVED baseline); v2 grep for backend/
  spec/authz/condition-extraction. (Core code claims — `case_store.py:308/323`, `cem_engine.py:316-319`,
  `scope_gate_hook.py` fail-open, `watch-mcp` no-linkage — were re-verified in the immediately preceding passes on the
  same `@fbbf26d` and are unchanged.)
- **Meaningful roadmap items traced:** ~40 across all streams.
- **Intentional deferrals/rejections confirmed:** ~15 (all justified).
- **Omissions found:** 1 material (Z-1 VAL-AUTHZ) + 2 partial (Z-2 DISC-SPEC, Z-3 ARCH-STATE) + 1 editorial (Z-4).
- **Contradictions found:** 0 (v2 internally consistent).
- **Security gaps missing from roadmap:** 0 (all present; VAL-AUTHZ's state-changing risk would inherit existing
  idempotent-default + human-gate).
- **Benchmark/measurement gaps:** 1, tied to Z-1 (VAL-AUTHZ's planted-multi-step-authz benchmark, absent because the
  capability is absent).
- **Is v2 freeze-safe?** Architecturally yes; **not zero-skip** until Z-1 is inserted. Recommend inserting Z-1 (gated
  P3) before declaring the corpus complete, then re-freeze.
- **Recommended canonical file:** `MASTER-ROADMAP-FINAL-v2.md` (after the Z-1/Z-2/Z-3/Z-4 correction).
- **Recommended cleanup plan:** §20 (do NOT archive the V3 execution tracker until VAL-AUTHZ is reconciled; treat
  OPEN-SOURCE-AUDIT public-history as an owner decision); §21 (no history surgery required for the untracked corpus).
- **Output file created:** `FINAL-ZERO-SKIP-AUDIT.md`. No other file modified; nothing implemented, moved, deleted,
  committed, or pushed.
