# MASTER-ROADMAP-AUDIT.md — Independent Adversarial Reconciliation

**Status:** independent audit. Read-only. No source, no protected planning document
(`ROADMAP.md`/`XYZ.md`/`ARCHITECTURE.md`/`MASTER-ROADMAP-PROPOSAL.md`/`PHASE1*`), and no existing research file was
modified. This is the audit's *recommendation* for what the final roadmap should contain — **not** the authoritative
roadmap and **not** an authorization to build.

**Ground truth:** worktree `research/golden-nextgen` @ `fbbf26d`; CEM Phase 1 FROZEN (`#101`). Load-bearing claims were
re-verified against code at the file:line cited inline; where a claim rests only on a document, it is tagged **[doc]**;
where verified in code, **[code]**; where uncertain, **[uncertain]**.

**Files inspected (this audit):** all 13 present corpus files (`NEXT-GEN-PLATFORM-REVIEW.md` is **absent** — noted;
its role is served by `NEXT-GEN-PLATFORM-RESEARCH.md` §63 self-audit). Code verified: `cem_engine.py`
(SuccessSignature/determinism/classify), `case_store.py` (evidence + CEM tables + status gates), `scope_guard.py`,
`engagement_paths.py`, `scripts/hooks/scope_gate_hook.py`, `dotenv_loader.py`, `watch-mcp/server.py`,
`hackerone-mcp/server.py`, `budget_guard.py`, `audit_log.py`, `job_runtime.py`, `opencode.jsonc`, `Dockerfile`.

---

## 1. Executive Verdict

**The current `MASTER-ROADMAP-PROPOSAL.md` (Option-C hybrid: Foundation/Reliability → Discovery via schemathesis→CEM →
Reasoning → Allocation → Continuous) is fundamentally sound and survives this audit.** Its core discipline
(measure-first, CEM-is-the-moat, no-router-now, graph-DB-rejected, security-quality floor) is correct and should be
preserved. The audit does **not** recommend an architectural reconsideration. Neither the Next-Gen platform stream nor
the Xalgorix stream justifies one.

**The single highest-value change** the audit recommends is small and unusually well-supported: **elevate *evidence
provenance* to a named, first-class Phase-2 foundation item.** Two independent research streams converged on the exact
same verified gap — Next-Gen's "C1 environment-as-evidence" and the Xalgorix review's "H1 discovery-path provenance
gap" are the *same finding*, and both are confirmed in code: `case_store.add_evidence(content: str)` hashes a
model-typed string (`case_store.py:322`) — tamper-evidence, not provenance — while the machine-captured strong path
(`cem_trials` request/response hashes) is gated behind `CONFIRMED` (`case_store.py:86`). Most reported evidence
therefore flows through the weak path. This is the roadmap's biggest under-scoping.

**Second:** the security floor (hook fail-closed + hook-tamper resistance + tool pinning/SBOM + `--os-shell`
confirmation + scoping secrets out of untrusted execution) should be an explicit **gating prerequisite** to any
autonomous-execution expansion, not merely a continuous side-track. OSS-audit + Next-Gen §10 + the live behaviour of
`scope_gate_hook.py` all support this.

**Corrections the audit forces on prior research (must be applied before those docs feed the roadmap):**
- "Confirmation **is** CEM" (Xalgorix research §26) → **REJECT as stated**; it is a structural analogy, not
  equivalence. CEM's verdict machinery *dominates* Xalgorix's confirmers; CEM's *oracle contract* is *narrower*
  (verified: `SuccessSignature` matches HTTP responses only, `cem_engine.py:316-319`). The real transferable item is a
  one-dataclass oracle-reach question (browser/OOB), not a CEM redesign.
- Next-Gen "C1 is high-leverage" is **sound but its *proven* half is narrower than stated**: split into **C1a
  (provenance binding — verified gap, both streams agree → build)** and **C1b (full run-environment manifest — sound
  but unproven → measure)**.
- Next-Gen "C3 delta re-validation is plumbing" → **wrong** (already self-corrected in NEXT-GEN §63): `watch.db` and
  `case.db` are unlinked; the affected-hypothesis mapping is real new logic.
- Xalgorix "direction of travel / ledger convergence", "audit_log as evidence store", "ledger is a graph",
  "resource-aware admission control as priority" → **REJECT/DEFER** (per XALGORIX-REVIEW §24).

**Net:** keep the Option-C spine; make provenance explicit and early; harden the security floor as a gate; carry
forward exactly four Xalgorix items (H1–H4, three small + one research question); reject the over-scoped platform and
the CEM-equivalence framing. Confidence: **high** on reconciliation and code-status; **medium** on exact phase
placement; the one big empirical unknown (does provenance/reproducibility raise triager acceptance) is called out and
must be measured, not assumed.

---

## 2. Repository / Implementation Reality Check

The most consequential systematic error across the prior research (identified by XALGORIX-REVIEW and re-confirmed here)
is comparing *plans* against *code*. Corrected status of the load-bearing capabilities:

- **CEM Phase 1 is real and strong** [code]: `cem_engine.py` implements determinism gate (`:437`), `classify()`
  (`:492`), typed `SuccessSignature` with non-vacuous validation (`:276`,`:309`,`:322`; a vacuous-oracle bug was
  already found and fixed, `:169`), interventions (`:1520`), and `case_store` persists `cem_meta/conditions/trials/
  verdicts` with per-trial `request_evidence_hash`/`response_evidence_hash`. Verdict rigour (k-replication, determinism
  gate, `inconclusive`/`probabilistic`/`interacting`) exceeds the Xalgorix confirmers.
- **Evidence store: two paths, unequal** [code]. Strong path = machine-hashed CEM trials (post-CONFIRMED). Weak path =
  `add_evidence(content: str)` hashing a model-typed string (`case_store.py:308-336`). Hash = integrity, not
  provenance. **This is the reality that the roadmap under-addresses.**
- **State isolation exists; execution isolation does not** [code]. Per-engagement dirs + per-session pointer +
  `file_lock` + WAL are real (`engagement_paths.py`). No sandbox/namespace/seccomp anywhere (grep = 0). The scope hook
  is deliberately narrow: it gates `rm` + target-host-touching Tier-2/curl/wget only, **not** file writes or installs
  (`scripts/hooks/scope_gate_hook.py`) — so a compromised agent can `cat .env` and overwrite the hook file, effective
  next call. [code, verified live: the hook fired on a literal `rm ` substring this session.]
- **Secrets** [code]: plaintext `.env`; `dotenv_loader.load_dotenv_if_present()` loads the *whole* file into
  `os.environ` for the 4 servers that call it (osint/hackerone/second-opinion/github-security).
- **Human-review-before-submit is a real technical control** [code]: `hackerone-mcp/server.py` exposes only
  `sync_program_scope` + `check_my_duplicates` (read-only) with an explicit "must never submit" comment.
- **watch-mcp has target snapshots but no case linkage** [code]: `snapshots`/`watch_events` tables reference targets
  only; zero reference to `case.db` findings/hypotheses.
- **Docker = packaging, root, unpinned `@latest` tools** [code]: no `USER` directive; supply-chain gap.

---

## 3. Capability Status Matrix

Columns: Capability · Claimed · Actual · Evidence · Gap · Roadmap consequence.

| Capability | Claimed | Actual | Evidence | Gap | Consequence |
|---|---|---|---|---|---|
| CEM proof engine (P1) | done/frozen | **IMPLEMENTED** | `cem_engine.py`, `case_store` CEM tables | none | Freeze; build on, don't touch |
| CEM oracle *reach* (browser/OOB) | (implicit) | **NOT PRESENT** | `SuccessSignature` = HTTP only `:316` | non-HTTP oracles inexpressible | Research-only (H2); additive if needed |
| Evidence tamper-evidence | done | **IMPLEMENTED** | SHA-256 content store | none | keep |
| Evidence **provenance** (bind to real exchange) | (assumed by "evidence machinery") | **PARTIAL — weak on discovery path** | `add_evidence(content:str)` `:322` vs `cem_trials` hashes | discovery-path evidence is model-narrated | **C1a — elevate to Phase 2** |
| Hypothesis lifecycle / ledger | future (some docs) | **IMPLEMENTED** | `case_store` hypotheses/findings/experiments | none | Xalgorix "ledger" item = NO CHANGE |
| Per-engagement state isolation | done | **IMPLEMENTED** | `engagement_paths.py` | none | keep |
| Execution isolation / sandbox | planned (ARCH 216/1224 note) | **NOT PRESENT** | grep=0 | whole-host TCB | **C2 — security floor** |
| Scope enforcement | done | **IMPLEMENTED but narrow + fail-open** | `scope_gate_hook.py` | file-write/secret/tamper ungated; SPOF allow-all | **harden: fail-closed + tamper (P0/P1)** |
| Secret handling | (n/a) | **plaintext .env, full-env load** | `dotenv_loader.py` | harvestable | **scope secrets out (P1)** |
| Target snapshot/delta | future | **PARTIAL** (recon only, unlinked) | `watch-mcp` snapshots | no case linkage / affected-hypothesis map | **C3 — real work, Phase 5/continuous** |
| Coverage (endpoint×class×role) | Batch-8 open | **NOT PRESENT** | ARCH 1155 | no coverage object | **H3 — Benchmark/Measurement track** |
| Tool-output-injection sanitization | Batch-8 / P2 (MASTER Dec.5) | **NOT PRESENT** | ARCH 1155, UU-7 | live injection surface | **keep as immediate P2 item** |
| Scan-identification headers | (n/a) | **NOT PRESENT** | Xalgorix `internal/scanheaders` | polite-scan identifier absent | **H4 — small, Security/Reliability track** |
| Capability/tool-exposure layer | V4 conditional | **DEFERRED (correct)** | UNIVERSAL-CAPABILITY §11 | none | keep deferred |
| Adaptive allocation / router | P5, deferred | **NOT PRESENT (correct)** | memo | none | keep deferred |
| Cross-run memory/learning | present | **IMPLEMENTED** | memory/writeup/lessons-mcp | none | keep |
| Resource-aware admission | Xalgorix ADAPT | **budget_guard covers cost axis** | `budget_guard.py` | minor | **DEFER** |

---

## 4. CEM Reconciliation

**CEM Phase 1 stays FROZEN.** No concrete regression, missing contract, or cross-phase dependency requiring a change to
the frozen slice was found. Specifically:

- **Does any roadmap item duplicate CEM?** No. The Xalgorix "verifier" is *not* a CEM competitor to build — HuntMCP's
  exploit/browser/oob confirmation already establishes existence, and CEM consumes the *result*. Do **not** create a
  "verifier" work item; it would duplicate existing confirmation + the frozen CEM.
- **Do Xalgorix findings imply a CEM change?** **No to the engine.** The one real transferable item (H2) is that
  `SuccessSignature` cannot express browser-execution or OOB-callback oracles [code: `:316-319`]. That is a **narrow,
  research-only question about one dataclass's input type**, not a proof-engine change, and `cem_engine.py`'s
  deliberate *purity* (injected `fetch_fn`, no network/MCP/DB) is load-bearing for testability — widening the oracle
  must be designed as an injected `observe_fn`, not a coupling. Defer unless browser/OOB machine-verdicts become a
  blocking discovery need.
- **Are the real gaps oracle/coverage/integration/placement rather than fundamentals?** **Yes.** The genuine gaps are
  (a) **provenance of the evidence that feeds CEM** (C1a/H1 — in `case_store`, *not* `cem_engine`; additive), (b)
  **oracle reach** (H2), (c) **coverage** (H3). None is a proof-engine fundamental. CEM's verdict machinery is the
  strongest asset in the repo.
- **Should CEM move earlier?** **No.** CEM's `determinism_gate` structurally requires the capability to already fire,
  and `case_store` gates CEM state on `CONFIRMED` (`EVIDENCE_GATED_STATUSES`, `:86`). "Establish existence" is a
  different primitive (confirmers), already owned elsewhere. Keep CEM as post-confirmation validation; XYZ Phase 3
  (CEM-in-hunt) is the correct integration point.

---

## 5. Next-Gen Reconciliation

The Option-B additive-substrate recommendation from NEXT-GEN-PLATFORM-RESEARCH survives, **re-partitioned** by
strength of evidence:

- **C1 — split.** **C1a (evidence provenance binding):** bind discovery-path evidence to the actual HTTP exchange that
  produced it (a capture-at-the-wire seam feeding `add_evidence`), so the weak path stops being model-narrated. **Both
  research streams independently converged here (Next-Gen C1 + Xalgorix H1), and it is verified in code** → highest
  confidence; **build, Phase 2.** **C1b (full run-environment manifest — tool/model/policy versions + target-snapshot
  hash):** architecturally sound and cheap, but its value (does it raise triager acceptance?) is **unproven** → smaller
  add-on, **measure via XYZ's A/B acceptance metric before treating as proven.** Do **not** claim C1 proven.
- **C2 — execution isolation.** Keep as recommended (rootless container per run, swappable boundary), but reclassify:
  it is a **security floor / prerequisite**, not a capability bet. The Xalgorix review independently flags the same
  principle ("verifier needs *environment* isolation, not just context isolation"; "enforcement outside the agent
  survives the agent"). Place its *floor subset* (see §9) before autonomous-execution expansion.
- **C3 — delta re-validation.** Distinct capability work (not plumbing — `watch.db`/`case.db` unlinked). Maps cleanly
  onto XYZ Phase 5 patch-bypass regression + continuous. Keep, Phase 5, medium effort.
- **"One platform phase" vs increments:** increments. There is no platform phase; C1a/C2-floor land in Foundation, C1b
  is a measured add-on, C3 lands in Continuous. This keeps every decision reversible.
- **Does Option B still survive?** Yes, but "Option B" should be understood as *three separable increments across
  existing phases*, not a new platform layer. The control-plane/broker/microVM/capability-authority items NEXT-GEN
  already deferred stay deferred (§13).

---

## 6. Xalgorix Reconciliation

Using **XALGORIX-REVIEW.md as the corrective authority** over XALGORIX-RESEARCH.md wherever they conflict (the research
doc understated HuntMCP ~50% of the time by comparing against plans, not code).

| Candidate | Verdict | Rationale (verified) |
|---|---|---|
| Deterministic per-class confirmers | **ALREADY HAVE STRONGER** | exploit-agent + CEM verdict machinery dominate; k=1 confirmers are weaker |
| Hypothesis ledger | **ALREADY HAVE** | `case_store` hypotheses/findings |
| Coverage/precision tracking (endpoint×class×role) | **ADOPT (small) — H3** | absent in HuntMCP; = Batch-8 Coverage Engine; needs anti-gaming clause |
| Resource-aware admission control | **DEFER** | `budget_guard` covers the cost axis; downgraded in review |
| Verifier *environment* isolation | **ADAPT — insight → C2** | reinforces execution-boundary floor |
| Verification/reporting choke point | **ALREADY HAVE** | `tool_resolver` chokepoint + evidence gate |
| Auth-discovery / scanheaders | **ADOPT (small) — H4** | `internal/scanheaders`; polite authorized-scan identifier; correct destination boundary |
| Rate-limit / process shims | **KEEP AS INSIGHT** | HuntMCP has `curl-rl.sh`+hook by convention; binary shim is stronger but low priority |
| Process-level execution shims | **MEASURE FIRST / part of C2** | fold into rootless-exec profile if C2 proceeds |
| Secure-SDLC CI (gosec/semgrep/govulncheck/-race) | **ADOPT (insight) — Security track** | HuntMCP CI = ruff/py_compile/bash -n; add Python-equivalent SAST/dep-audit |
| Evidence capture/reporting seam | **ADOPT — = C1a/H1** | the highest-impact convergent finding |
| Oracle contract design (non-HTTP) | **RESEARCH-ONLY — H2** | `SuccessSignature` HTTP-only; one-dataclass question |
| "Confirmation is CEM" | **REJECT as stated** | analogy only (§4) |
| Ledger-as-graph / audit_log-as-evidence / direction-of-travel / MAPTA-XBOW | **REJECT** | XALGORIX-REVIEW §24 |

**Net Xalgorix effect on the roadmap (per XALGORIX-REVIEW §23.2): outcome (6)+(3) — research-only follow-up (H1,H2) +
two small work items (H3,H4). NOT architectural reconsideration.**

---

## 7. Cross-Research Contradiction Matrix

| Claim A | Claim B | Better-supported | Decision | Affected phase |
|---|---|---|---|---|
| Xalgorix-research: "confirmation **is** CEM" | Xalgorix-review + code: analogy only, oracle contracts differ | **B** (code-verified) | Reject A; keep H2 as narrow question | CEM/Discovery |
| Next-Gen: "C1 high-leverage, decide now" | Next-Gen §63 + review: C1b value unproven | **B** | Split C1a(build)/C1b(measure) | Foundation |
| Next-Gen: "C3 is plumbing" | Code: `watch.db`⊥`case.db` | **B** (code) | C3 = real work | Continuous |
| Xalgorix-research: "evidence narrated, not captured" | Review + code: two paths, strong path exists | **B** | Reframe as C1a provenance-on-weak-path | Foundation |
| Xalgorix-research: HuntMCP lacks ledger/verdicts/scope | Code: all present | **B** | Reject; HuntMCP ahead | none |
| Master-roadmap §17: "after P2 … replayable" (lineage) | Next-Gen C1: environment replay | complementary | Reconcile wording; C1 is superset | Foundation |
| Memo: no router now | UU: reasoning-first | compatible (measure-first orders both) | Keep Option-C ordering | P4/P5 |
| Universal-Capability: capability layer V4-deferred | Golden-prompt §8 capability-authority | different meanings (tool-visibility vs security-authority) | Both deferred; C2-floor covers near-term | deferred |
| ARCH 216/1224: "planned Firecracker sandbox" | Next-Gen: rootless > microVM local | **B** (practical) | Rootless floor; microVM = future remote | Security floor |

No contradiction rises to the level of an architecture change. The contradictions are dominated by *research
overstatement corrected by code* — all resolving toward "HuntMCP is further along than claimed, and the additions are
small and additive."

---

## 8. Duplication / Consolidation Audit

Canonical concepts (collapse the aliases):

1. **Evidence Provenance** — canonical. Aliases: Next-Gen "environment-as-evidence/C1", Xalgorix "H1 discovery-path
   provenance / evidence capture seam", master-roadmap "evidence machinery / replayable", "evidence lineage". → one
   Phase-2 item (C1a build; C1b measured add-on).
2. **Execution Isolation** — canonical. Aliases: Next-Gen "C2 rootless/sandbox/security floor", Xalgorix "verifier
   environment isolation" + "process shims", ARCH "planned Firecracker sandbox". → one Security-floor item.
3. **Delta Continuity** — canonical. Aliases: Next-Gen "C3", watch-mcp "snapshot/diff", XYZ P5 "patch-bypass
   regression", master-roadmap "continuous". → one Phase-5 item.
4. **Coverage/Measurement** — canonical. Aliases: Xalgorix "H3 endpoint×class×role", Batch-8 "Coverage Engine", UU
   "utilization / hunt self-evaluation", master-roadmap "Benchmark & Measurement track". → one measurement track.
5. **Hypothesis Lifecycle** — canonical, **already implemented** (`case_store`). Aliases: Xalgorix "ledger", UU
   "hypothesis resurrection" (= a *future read/resurrect* feature on the same store, not a new store), memory. → do
   not build a new store; resurrection is an additive query.
6. **CEM verdict machinery** — canonical, frozen. Alias to reject: Xalgorix "verifier as CEM". Distinct: `chainer-mcp`
   is the real DAG (reject "ledger is a graph").
7. **Capability router / adaptive allocation / universal-capability layer** — three *distinct* deferred items; do not
   merge, but all stay deferred (measure-first / V4).

---

## 9. Security / Reliability Gate Audit

Separating **immediate security floor** (must exist) from **future platform capability** (defer). Evidence:
OSS-audit + Next-Gen §10/§63 + live hook behaviour + code.

**P0 — MUST PRECEDE any expansion of autonomous execution:**
- **Scope hook fail-closed + CI smoke test.** Today the hook fails *open* if broken (OSS-audit); verified narrow. A CI
  test that an out-of-scope call is actually blocked. [OSS-audit; code]
- **Scope secrets out of untrusted execution.** Stop full-`.env` load into tool processes; per-key scoping; `.env`
  not readable by sandboxed execution. [code: `dotenv_loader.py`]

**P1 — MUST EXIST BEFORE breadth/autonomy expansion:**
- **Hook tamper-resistance / execution isolation floor (C2).** Bash file-writes are ungated and the hook re-reads per
  call, so it is neutralizable mid-session; a rootless boundary that the agent cannot write above is the structural
  fix. [code: `scope_gate_hook.py`]
- **`--os-shell` / state-changing-RCE confirmation tier** (MASTER-ROADMAP Decision 8). [OSS-audit P2]
- **Tool-output-injection sanitization / quarantine (UU-7)** — a live injection surface for an agent that ingests
  hostile content by design. [ARCH 1155; UU-7]

**P2 — HARDEN LATER:**
- Tool version pinning + SBOM (supply-chain); Python SAST/dep-audit in CI (Xalgorix insight); CI `permissions:` block;
  `data/watch.db` untrack + per-engagement path (MASTER-ROADMAP Decision 9).

**DEFER:** resource-aware admission control (budget_guard suffices); capability-authority system; secret broker build.

**Discipline:** do not turn every security concern into architecture. The floor is small (mostly hardening + one
rootless boundary); the platform capability (broker, capability leases, control plane) is deferred with triggers.

---

## 10. Measurement / Benchmark Audit

The Option-C plan's measure-first spine is correct and must gate the reasoning/allocation phases. Classification of the
major proposed capabilities:

- **PROVEN VALUE:** none of the *new* items are yet empirically proven on HuntMCP's own targets. (CEM's value is
  argued and its correctness is benchmarkable via the constructed testbed; that is the closest to proven.)
- **SUPPORTED + VERIFIED GAP (build):** C1a provenance (two streams + code); the security floor (audit + code); H3
  coverage object (absent, needed to even measure breadth); UU-7 injection (live gap).
- **SUPPORTED BUT UNPROVEN (measure before large commitment):** C1b full manifest → **triager-acceptance A/B** (XYZ
  §6.3); C3 delta re-validation → re-hunt precision/recall vs cold start; schemathesis→CEM discovery amplification →
  WFC/WFD at zero quality-floor loss (master-roadmap P3 gate).
- **SPECULATIVE (do not commit architecture without a measurement path):** invariant model (master-roadmap already
  gates it behind a P4-M0 prototype — keep that gate), adaptive allocation (P5-A0 GO gate — keep), cross-target
  transfer (P5-T1 safe-transfer gate — keep).

**Metrics that must exist before the next architecture jump:** detection yield, confirmed-finding precision, validation
success rate, coverage (H3), repeated-target improvement (C3), triager acceptance (C1b/CEM), cost/time/tool usage,
false-positive rate, regression rate. Most of these require the **telemetry + benchmark substrate the master roadmap
already puts in Phase 2 — that ordering is correct and load-bearing.** Note the anti-gaming clause the Xalgorix review
demands for any completeness/coverage metric.

---

## 11. Phase Ordering Audit

The proposal's five phases are individually justified; the audit endorses the **spine** and recommends four
adjustments. Per-phase interrogation (condensed):

- **Phase 2 (Foundation & Reliability):** *why here* — everything downstream needs telemetry + benchmark + a trustable
  evidence base. **Adjustment 1: add C1a provenance and name it as evidence-integrity (currently only implicit).**
  **Adjustment 2: split out a Security Floor (P0/P1, §9) as a gating prerequisite, not just a continuous track.** Keep
  UU-7 here (correct). Smallest useful milestone: benchmark substrate + provenance-bound evidence + fail-closed hook.
- **Phase 3 (Discovery amplification):** schemathesis→CEM + CEM-in-hunt + differentiation evidence. Sound. **Adjustment
  3: the C2 execution boundary should be *in place by the end of Phase 3 at the latest*, because autonomous discovery
  breadth is exactly when hostile-content ingestion scales.** H2 (oracle reach) is a research-only side-question here,
  triggered only if browser/OOB machine-verdicts block breadth.
- **Phase 4 (Reasoning):** invariant model (keep the P4-M0 prototype gate), hypothesis resurrection (additive query on
  `case_store`), info-gain experiment selection, **coverage matrix (H3) lands here or in the measurement track**. No
  reorder.
- **Phase 5 (Adaptive/Continuous):** allocation (keep P5-A0 gate), continuous + **delta re-validation (C3)** +
  cross-target transfer (keep P5-T1 gate) + human-gated toolkit. H4 scanheaders is small and can land anytime.
- **Is anything mere elegance without value?** The invariant model is the highest such risk — correctly already gated
  by a prototype. Keep the gate; do not let it become a large commitment pre-measurement.

No new phases are invented. The revised shape (§15) is the same five phases + an explicit Security-Floor prerequisite +
provenance pulled forward.

---

## 12. Human Decision Boundary

- **Already decided (safe to implement, no further research):** security floor P0/P1 items (§9) — audit-identified,
  self-contained; C1a provenance binding (both streams + code); H3 coverage object; H4 scanheaders. These need
  engineering, not research.
- **Empirical questions (must be measured, not decided):** C1b manifest value (triager acceptance A/B); C3 delta
  re-hunt precision; schemathesis→CEM amplification; invariant-model tractability; allocation payoff; cross-target
  transfer safety. Each already has (or is assigned) a gate.
- **Human product/architecture choices (do not auto-decide from research):** whether to ever widen `SuccessSignature`
  for browser/OOB oracles (H2) vs keep CEM pure; whether C2's boundary is rootless-only or later gVisor; whether
  continuous hunting becomes a first-class mode. NEXT-GEN §59 already captured the operator's answers for the platform
  axis (Option B, rootless, scope-secrets-out, C1+C3 priority, all four security fixes) — those stand as *directional*
  input, not as authorization to edit protected docs.

---

## 13. Anti-Roadmap (what we should NOT build in this horizon)

Evidence-based rejections/deferrals:

- **Generic control plane / multi-tenant SaaS / billing** — no scale justifies it; premature (Next-Gen §43,
  memo/master-roadmap discipline). DEFER (trigger: multi-user).
- **Local microVM / bespoke VM platform** — overkill; rootless is the practical boundary. DEFER (trigger: remote
  execution). Keep the boundary swappable so this stays possible.
- **Custom secret broker** — mature off-the-shelf (Agent Vault/CyberArk/Vault); scoping secrets out gets ~80% now.
  ADOPT-WHEN-TRIGGERED, never build.
- **Graph database / event-sourcing** — SQLite + `chainer-mcp` DAG suffice; already rejected (master-roadmap §13). No.
- **A new "verifier" subsystem** — would duplicate existing confirmation + frozen CEM (Xalgorix-equivalence rejected).
  No.
- **Resource-aware admission control** — `budget_guard` covers the axis. DEFER.
- **AI IDE / generic agent platform / capability marketplace / unrestricted multi-agent parallelism** — off-mission;
  parallelism stays a measured design-only backlog. DEFER/REJECT.
- **Kubernetes-first orchestration / distributed cloud** — no demand. DEFER.

---

## 14. Canonical Decision Table

| Item | Source(s) | Current reality | Decision | Reason | Priority | Dependency | Phase |
|---|---|---|---|---|---|---|---|
| CEM Phase-1 slice | XYZ, code | implemented | **FREEZE** | strong, no regression | — | — | done |
| Evidence provenance binding (C1a/H1) | Next-Gen, Xalgorix, code | weak path model-narrated | **CHANGE/BUILD** | 2 streams + code; biggest under-scope | P1 | capture seam | 2 |
| Full run-env manifest (C1b) | Next-Gen | absent | **MEASURE FIRST** | value unproven | P3 | C1a, benchmark | 2→(A/B) |
| Security floor (hook fail-closed, secrets-out) | OSS-audit, Next-Gen, code | fail-open, plaintext | **CHANGE/BUILD** | verified gaps | **P0** | — | Sec floor |
| Execution isolation (C2) | Next-Gen, Xalgorix, ARCH | absent | **BUILD (floor)** | contains 4 threats | P1 | rootless runtime | Sec floor→3 |
| Hook tamper resistance | code, Next-Gen §63 | ungated file writes | **CHANGE** | neutralizable mid-session | P1 | C2 | Sec floor |
| `--os-shell` confirm tier | OSS-audit | no distinct gate | **CHANGE** | persistent RCE channel | P1 | — | Sec floor |
| Tool-output-injection sanitization (UU-7) | UU, ARCH | absent | **BUILD** | live injection surface | P1 | — | 2 |
| Tool pinning + SBOM, CI SAST | OSS-audit, Xalgorix | unpinned @latest | **CHANGE** | supply-chain | P2 | — | 2 |
| Coverage matrix (H3/Coverage Engine) | Xalgorix, Batch-8 | absent | **NEW (small)** | can't measure breadth otherwise | P2 | benchmark | 4/measurement |
| Scan-identification headers (H4) | Xalgorix | absent | **NEW (small)** | polite authorized scan | P3 | — | any |
| Delta re-validation (C3) | Next-Gen, XYZ P5, code | watch⊥case | **NEW (real work)** | not plumbing; high ROI | P3 | C1a, watch | 5 |
| SuccessSignature oracle reach (H2) | Xalgorix, code | HTTP-only | **RESEARCH ONLY** | 1-dataclass question; keep CEM pure | P4 | — | research |
| schemathesis→CEM discovery | UU-6, master-roadmap | planned | **KEEP + MEASURE** | breadth via off-the-shelf | P2 | benchmark | 3 |
| Invariant model | UU-1, master-roadmap | planned | **KEEP GATED** | tractability risk | P4 | P4-M0 prototype | 4 |
| Hypothesis resurrection | UU-2 | store exists | **KEEP (additive query)** | no new store | P4 | case_store | 4 |
| Info-gain experiment selection | UU-3, memo | planned | **KEEP + MEASURE** | needs telemetry | P4 | telemetry | 4 |
| Adaptive allocation / router | memo | absent | **DEFER (gated)** | measure-first | P5 | P5-A0 GO | 5 |
| Cross-target transfer | memo §9, XYZ P4 | absent | **DEFER (gated)** | safe-transfer unproven | P5 | P5-T1 | 5 |
| Capability/tool-exposure layer | Universal-Capability | absent | **DEFER (V4)** | premature | — | 3rd runtime | V4 |
| "Confirmation is CEM" | Xalgorix-research | — | **REJECT** | analogy only | — | — | — |
| audit_log as evidence store | Xalgorix-research | stores no output | **REJECT** | wrong store | — | — | — |
| Resource-aware admission | Xalgorix | budget_guard exists | **DEFER** | covered | — | — | — |
| Control plane / broker / microVM / graph DB / AI IDE | — | — | **REJECT/DEFER** | §13 | — | triggers | — |

**A. Roadmap gets right:** Option-C ordering; measure-first; CEM-as-moat; no-router-now; graph-DB rejection;
security-quality floor; the gated prototypes for invariant/allocation/transfer; UU-7 jumping the queue.
**B. Wrong/outdated:** treats evidence as tamper-evident ⇒ trustworthy (provenance gap); security track is
continuous-only rather than a *gate*; imports the CEM-equivalence and direction-of-travel framings if Xalgorix is used
uncorrected.
**C. Missing:** explicit provenance item (C1a); explicit execution-isolation floor (C2); coverage object (H3);
scanheaders (H4); hook fail-closed/tamper as a named gate.
**D. Duplicated:** the seven canonical/alias collapses in §8 (esp. provenance × 4 names, isolation × 3, coverage × 4).
**E. Over-scoped:** any reading that turns C1/C2 into a platform layer; invariant model if un-gated; anything in §13.
**F. Freeze:** CEM Phase-1; hypothesis lifecycle store; scope-enforcement *design* (harden behaviour, not redesign);
evidence content-addressing; human-review-before-submit.
**G. Next:** the Security Floor (P0/P1) + C1a provenance, both self-contained and both already directionally approved.

---

## 15. Proposed Final Roadmap Shape (audit recommendation — NOT the authoritative file)

**Phase S — Security Floor (prerequisite gate; small; mostly hardening).**
*Objective:* make autonomous execution safe to expand. *Prereq:* none. *Capability groups:* (1) scope hook
fail-closed + CI block-test; (2) scope secrets out of untrusted execution; (3) rootless execution boundary (C2) +
hook-tamper resistance; (4) `--os-shell`/state-changing confirmation tier. *Acceptance:* an out-of-scope call is
blocked in CI; a compromised-agent test cannot read `.env` or neuter the hook; state-changing RCE requires
confirmation. *Non-goals:* secret broker, capability leases, control plane. *Exit gate:* the adversarial regression
(canary-secret exfil via hostile tool output; out-of-scope action; hostile-repo checkout) passes on containment **and**
legitimate-task utility.

**Phase 2 — Foundation, Evidence Integrity & Reliability.**
*Objective:* a measured, injection-hardened, provenance-bound base. *Prereq:* Phase S floor items P0. *Groups:* (1)
benchmark + telemetry substrate; (2) **evidence provenance binding (C1a)** — capture-at-wire seam feeding
`add_evidence`; (3) tool-output-injection sanitization (UU-7); (4) negative-knowledge + capability-utilization signal;
(5) supply-chain pinning + SBOM + CI SAST; (6) *optional* C1b run-manifest, instrumented for the acceptance A/B.
*Acceptance:* discovery-path evidence is bound to a real exchange (not a model string); injection regression passes;
telemetry emits cost/yield/coverage. *Non-goals:* invariant model, allocation. *Exit gate:* benchmark substrate live;
provenance verified on stored findings.

**Phase 3 — Discovery Amplification + CEM-in-Hunt.**
*Objective:* competitive breadth without quality loss. *Prereq:* Phase 2 substrate + Phase S C2 boundary in place.
*Groups:* (1) schemathesis→CEM stateful/API falsifiers; (2) CEM auto-run after independent validation; (3) structural
differentiation evidence vs disclosed reports; (4) H4 scanheaders (small). *Acceptance:* WFC/WFD at zero
quality-floor loss; CEM runs in-hunt. *Non-goals:* widening CEM oracle contract (H2 stays research-only unless
blocking). *Exit gate:* breadth measured up; false-causal-conclusion rate stays 0.

**Phase 4 — Application Reasoning + Coverage.**
*Objective:* reason about the app's own rules. *Prereq:* Phase 2 telemetry. *Groups:* (1) invariant model **(gated by
P4-M0 prototype)**; (2) hypothesis resurrection (additive `case_store` query); (3) info-gain experiment selection; (4)
coverage matrix (H3) with anti-gaming clause. *Acceptance:* on a long-horizon benchmark, reasoning items beat baseline
at no quality-floor loss; if P4-M0 fails, ship resurrection + info-gain + coverage without deep invariant inference.
*Non-goals:* allocation. *Exit gate:* P4-M0 GO/NO-GO recorded.

**Phase 5 — Adaptive Allocation + Continuous/Delta.**
*Objective:* amortize validated knowledge; hunt continuously. *Prereq:* Phase 4 measurement. *Groups:* (1) adaptive
allocation **(gated by P5-A0 GO)**; (2) continuous monitoring + **delta re-validation (C3)** + patch-bypass
regression; (3) cross-target transfer **(gated by P5-T1 safe-transfer)**; (4) human-gated toolkit growth. *Acceptance:*
allocation improves cost/quality under the security floor or is deferred; C3 beats cold-start re-hunt. *Non-goals:*
self-modification, unattended autonomy, unrestricted parallelism. *Exit gate:* each gated item ships only on its GO.

*(Cross-cutting, continuous: Security/Reliability hardening P2 items; Benchmark & Measurement. Deferred with triggers:
capability layer V4, secret broker, microVM/remote, control plane, parallel investigation.)*

---

## 16. Open Questions / Evidence Gaps

1. **Does provenance/reproducibility raise triager acceptance?** (C1b, and the ultimate justification for the evidence
   work beyond C1a's integrity value.) Unproven — needs XYZ's A/B. **Largest single unknown.**
2. **Is the browser/OOB oracle gap (H2) actually blocking discovery?** Only if machine-verdicting XSS-execution/OAST
   becomes a breadth bottleneck; otherwise research-only. Not yet demonstrated.
3. **C3 re-hunt precision vs cold start** — unmeasured; the affected-hypothesis mapping's accuracy is the crux.
4. **schemathesis→CEM amplification magnitude** — assumed high-leverage (master-roadmap), unmeasured.
5. **Invariant-model tractability** — flagged least-tractable by UU's own adversarial pass; gate stands.
6. **Rootless-boundary utility cost** — will isolation break legitimate tool flows? Must measure legitimate-task
   utility in the Phase-S exit gate.
7. **PHASE1-PLAN.md / PHASE1-EXECUTION-PLAN.md** were read at structure level, not line-by-line; CEM contract details
   are taken from `cem_engine.py`/`case_store.py` directly, which is the stronger source, but a full line read was not
   performed. **[uncertain — low risk]**

---

## 17. Audit Confidence / Limitations

- **High confidence:** implementation-status matrix (§2/§3), CEM reconciliation (§4), Xalgorix reconciliation (§6 —
  backed by XALGORIX-REVIEW's exhaustive call-site traces and re-verified here at cited lines), the duplication
  collapses (§8), the security-floor classification (§9), and the rejection of architectural reconsideration.
- **Medium confidence:** exact phase placement of C1b/C2/C3 (defensible, but a product call); the magnitude of each
  measured item's payoff.
- **Explicitly uncertain:** every item in §16, especially #1 (the empirical value of provenance/reproducibility to a
  triager), which no evidence in the corpus establishes.
- **Method limits:** competitor facts about Xalgorix are taken from XALGORIX-REVIEW (which read Xalgorix source); this
  audit did not independently read the Xalgorix repository. Web-sourced 2026 prior-art in the Next-Gen stream informs
  positioning only. No code was executed; status is from source reading + this session's earlier verifications.

**Bottom line for a human about to freeze the architecture:** keep the Option-C spine; add a small Security Floor as a
gate and name evidence *provenance* as a first-class Phase-2 item (the one place two independent streams and the code
all agree); carry exactly four Xalgorix items (H1–H4); reject the CEM-equivalence framing and the platform over-scope;
and treat C1b, C3, discovery amplification, the invariant model, allocation, and transfer as **measured, gated**
increments — not commitments. The roadmap's discipline is right; its main omission is provenance, and its main risk is
letting sound-but-unproven items harden into architecture before measurement.

---

*Files inspected: 13 corpus docs (`NEXT-GEN-PLATFORM-REVIEW.md` absent). Code verified: `cem_engine.py`,
`case_store.py`, `scope_gate_hook.py`, `dotenv_loader.py`, `watch-mcp/server.py`, `hackerone-mcp/server.py`,
`engagement_paths.py`, `scope_guard.py`, `budget_guard.py`, `audit_log.py`, `job_runtime.py`, `opencode.jsonc`,
`Dockerfile`. Contradictions found: 9 (§7), all resolving toward "HuntMCP further along than claimed; additions small
and additive". Roadmap decisions changed: provenance elevated; security floor made a gate; C1 split; C3 reclassified as
real work; CEM-equivalence and platform over-scope rejected. Output file created: `MASTER-ROADMAP-AUDIT.md`. No other
file modified; nothing implemented, committed, or pushed.*
