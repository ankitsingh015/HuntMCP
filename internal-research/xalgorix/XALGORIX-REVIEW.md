# XALGORIX-REVIEW.md

**Adversarial validation of `XALGORIX-RESEARCH.md`**

Review date: 2026-09-13
Subject of review: `XALGORIX-RESEARCH.md` (2,130 lines, produced earlier the same day)
Subject system: `xalgorix/xalgorix` @ `d357389` (v4.6.75, 2026-09-10)
Reviewer posture: **hostile to the first report.** The prior document was treated as a set of hypotheses
to be broken, not as established fact.

> **Scope compliance.** No HuntMCP implementation, roadmap, planning, or architecture file was modified.
> `XYZ.md`, `MASTER-ROADMAP-PROPOSAL.md`, `HUNTMCP-NEXT-GEN-EXECUTION-PLAN.md`, and the PHASE1 plans were
> read for comparison only. No recommendation was implemented. No commit was made. This review created
> exactly one file: itself.
>
> **Research independence.** Golden-Prompt research output was not opened, referenced, or used to steer
> any conclusion here. Cross-research synthesis is explicitly deferred to the later master-roadmap phase.

---

## Headline

**The first report is directionally sound and mostly verifiable, but it is materially wrong in three
places, overstated in four, and — most importantly — it substantially understated HuntMCP's current
state, because it compared Xalgorix against HuntMCP's *design documents* rather than HuntMCP's
*implemented code*.**

`mcp-servers/cem_engine.py` (1,706 LOC) and `mcp-servers/case_store.py` (772 LOC) are **implemented and
wired into `case-mcp`**. The first report treated CEM as a proposal in `XYZ.md`. That single omission
invalidates or downgrades five of its comparison rows and one of its top-three recommendations.

The net effect on the master roadmap is **smaller** than the first report implied, not larger.

---

# 1. Review Scope and Method

## 1.1 What was reviewed

Every material architectural claim in `XALGORIX-RESEARCH.md` — defined as any claim that could plausibly
influence a HuntMCP architectural decision. Cosmetic, stylistic, and descriptive statements were not
individually adjudicated.

## 1.2 Evidence order (enforced, not aspirational)

```
SOURCE CODE  →  DOCUMENTATION  →  COMMIT HISTORY  →  ISSUE HISTORY
             →  PRIMARY PRIOR ART  →  RESEARCH INTERPRETATION
```

Where the first report cited a code comment as evidence, the review re-derived the claim from the
implementation and from an exhaustive call-site trace, not from the comment. This mattered: the first
report's single highest-severity finding rested substantially on one doc comment. It survived — but only
after independent tracing, and the tracing changed how it should be characterised.

## 1.3 What "independent" meant in practice

The Xalgorix clone was re-read at the source level for every high-impact claim. In addition, the review
did something the first pass did not do at all: **it read the current HuntMCP implementation** rather than
its planning documents. That is where most of the corrections came from.

## 1.4 Known limits of this review

- Still no execution of Xalgorix. All behavioural claims remain read-from-code.
- The hosted product remains closed and unexamined.
- `webui/` was inventoried, not audited.
- HuntMCP's own runtime behaviour was observed only incidentally (see §12.4 — the scope hook blocked two
  of this session's own commands, which is direct runtime evidence and is reported as such).

---

# 2. Sources Used

| Source | Use |
|---|---|
| `xalgorix/xalgorix` @ `d357389`, local clone | Primary. Re-read for every high-impact claim. |
| `git log`, `git show`, `--diff-filter=A`, `--name-only` | Direction-of-travel audit (§16), component dating |
| `git ls-files` | Established what is *actually shipped* vs. removed (§15) |
| `docs.xalgorix.com`, `README.md`, `CHANGELOG.md` | Claim-vs-code diffing only |
| GitHub issues (#640, #471, #429) | Empirical grounding of the evidence-integrity finding |
| MAPTA, arXiv:2508.20816 | Cited *inside Xalgorix source*; used to test benchmark comparability |
| **HuntMCP working tree** — `mcp-servers/cem_engine.py`, `case_store.py`, `case-mcp/server.py`, `scope_guard.py`, `audit_log.py`, `http_probe.py`, `scripts/hooks/scope_gate_hook.py`, `scripts/curl-rl.sh` | **The correction source.** Not read by the first pass. |
| `XALGORIX-RESEARCH.md` | Subject of review |

---

# 3. What the First Research Got Right

Stated up front so the corrections that follow are read in proportion.

1. **The 22-phase finding.** Correct, well-evidenced, and the most useful debunking in the report. It
   survives review with one small nuance (§5).
2. **The scope-enforcement finding.** Correct, and it survives a full call-site trace that the first pass
   did not perform. If anything it is now better supported (§12).
3. **Resume = restart-with-summary.** Correct and precisely characterised (§9).
4. **Continuous = cron.** Correct, triple-sourced, with no counter-evidence found (§10).
5. **The verifier's design analysis.** Accurate, including the harder observation that conversation
   isolation ≠ environment isolation (§6).
6. **The ledger's schema and semantics.** Accurately described (§7).
7. **Source analysis is regex + co-location.** Correct (§14).
8. **Negative controls in the benchmark.** Correctly identified as the project's best methodological
   asset (§15).
9. **Canonical assistant-turn rewriting** as the most original idea in the repo. Holds up.
10. **The evidence-tagging discipline** (`[V]`/`[S]`/`[I]`/`[H]`) was applied honestly enough that most
    over-reach in the body was already self-labelled as inference. The Executive Summary was less
    disciplined than the body — that is where the overstatements concentrated.

The report was also right to refuse to treat the marketing framing as architecture. That instinct was
correct and produced most of its value.

---

# 4. Claim-by-Claim Validation

Classification: **A** verified · **B** partially verified · **C** unverified · **D** misinterpreted ·
**E** outdated · **F** overstated · **G** correct but low significance.

Ordered by potential roadmap impact, not by document order.

| # | First-report claim | Verdict | What the code actually shows | Impact on HuntMCP |
|---|---|---|---|---|
| C1 | "Confirmation may be a single-condition CEM intervention" | **B / F** | Structural analogy holds for HTTP-observable classes; **formal equivalence fails on three counts** (§8). The first report labelled it `[H]` in §26 but promoted it to "the headline" and "highest-leverage question" in the summary. | Downgrades the top recommendation from *architectural* to *narrow and concrete* |
| C2 | "Evidence is narrated, not captured" | **B / F** | Xalgorix **does** capture real request/response — but only on the deterministic-confirmer path, into the ledger (`verify_sqli.go:183–190`). The blanket framing is wrong; the precise defect is that the **reporting boundary does not consume the captured evidence** (§11). | Sharpens the finding and makes it symmetric with HuntMCP's own two-path structure |
| C3 | "Nearly every feature commit since 2026-09-01 has been routing evidence into the ledger" | **D — factually wrong** | Sept 1–4 was a labelled **P1/P2 program burst**. Sept 5–10: 5 of 6 feature commits are **prompt-technique additions**; `agent_prompt.go` is the most-modified Go file in that window; **zero** new confirmers; ledger untouched after Sept 8 (§16). | Removes "convergence" as a basis for roadmap influence |
| C4 | "HuntMCP: hypothesis ledger is **B → F**, recommend ADAPT" | **D — materially understated** | `case_store.py` already has `hypotheses`, `findings`, `evidence`, `experiments`, `root_causes`, `cem_meta`, `cem_conditions`, `cem_trials`, `cem_verdicts` with FKs and lifecycle. `case-mcp` exposes the full tool surface. | **Row is wrong.** Should be A/B, action NO CHANGE → INVESTIGATE at most |
| C5 | "L2: bind reported evidence to `audit_log.py` entries" | **D — technically wrong** | `audit_log.log_call()` records `{ts, tool, args, returncode, duration_ms, block}`. **It does not store output.** It cannot be the evidence source. The correct store is `case_store.add_evidence` (SHA-256 content-addressed) / `cem_trials.response_evidence_hash`. | Recommendation survives in spirit, wrong in mechanism |
| C6 | "Engagement scope is not enforced in Xalgorix code" | **A — verified, exhaustively** | All 13 `IsLocalOrListener` call sites are operator-machine protection. `activityHosts` has exactly 3 uses, all passive-mode-only. `httpclient` has zero host restriction. `har.InScopeEndpoints` is an **ingestion-time filter**, not a request gate (§12). | Holds. HuntMCP is materially stronger. |
| C7 | "22 phases are prompt content, not architecture" | **A, with nuance** | Verified. Nuance: the keyword-**inferred** `CurrentPhase >= 20` is one of four OR-ed conditions in the abort-vs-completed decision (`scan_session.go:398`), so it drives exactly one real decision — a status/billing one, not a testing one (§5). | Holds |
| C8 | "The event log is the audit trail" | **D — wrong** | `scan_session.go:698`: persisted event `Output` is **truncated to 500 chars**. The event log is not a forensic record and cannot serve as an evidence source (§11.3). | Strengthens C2's corrected form |
| C9 | "Resume = new agent + text briefing" | **A** | `agent.Stop()` on pause; `SetResumeBriefing(formatResumeBriefing(...))` on resume. Verified (§9). | Holds |
| C10 | "Continuous mode is cron, no cross-run state" | **A** | 30 s ticker → `runMultiScan`; dedup scoped to run in three separate places; no diff logic outside benchmarks (§10). | Holds |
| C11 | "Verifier is conversation-isolated, not environment-isolated" | **A** | Verified. Shares `ScanContext` → same browser, terminal, notes, session auth (§6). | Holds — good finding |
| C12 | "Ledger `Schedulable`/`ClaimNext` are advisory tools, not a dispatcher" | **A** | Verified. Only callers are `ledger_tools.go` (tool registration) and `ledger_hooks.go:115` (a nudge). | Holds |
| C13 | "MAPTA measures 76.9% on the same 104-challenge set" (juxtaposed with Xalgorix's ~70/104) | **F — not apples-to-apples** | The XBOW harness (`cmd/xalgorix-xbow/main.go`, 225 LOC) was **deliberately removed from the tracked repo** on 2026-09-06 (`51523a2`). Neither the 58/104 baseline nor the ~70/104 projection is reproducible from the repository (§15). | The comparison should not have been drawn without this caveat |
| C14 | "Source→runtime is a real loop" | **A** | Verified: `scan_source_sinks` → `scan_source_routes` → `probe_hypothesis` → `verify_*`, joined by the ledger's `DataFlow` field (§14). | Holds |
| C15 | "Source analysis is 11 ripgrep regexes, no AST/taint" | **A** | `codesearch.go:57–69`; `SinkScan` shells to rg/grep. | Holds |
| C16 | "No database; flat JSON + atomic writes" | **A** | Verified. `bbolt` appears only as an indirect dependency. | Holds |
| C17 | "45 providers over 3 wire formats" | **A** | Verified. `HeaderStyle ∈ {openai, anthropic, gemini}` + `openai_responses`. | Holds, low significance |
| C18 | "Sub-agents share one mutable `ScanContext`" | **A** | `subArgs := []any{sctx}`; max 3 concurrent. | Holds |
| C19 | "Finish gate has a 15-attempt escape hatch" | **A** | `hooks.go:1667–1673`. | Holds |
| C20 | "Benchmark: 35 challenges, 15 negative controls" | **A** | Verified by count. | Holds — strongest methodological finding |
| C21 | "HuntMCP: verification is convention, not a code gate — **B → F**" | **B** | Partly wrong. `case-mcp` gates CEM on `_confirmed_or_error`, `_scope_or_error`, `_nonidempotent_or_error`, budget callbacks, and a per-trial scope callback. Real code gates exist — but on the *CEM* path, not the *report-drafting* path. | Row needs re-scoping, not deletion |
| C22 | "Docs claim 8 providers / no source scanning" | **A** | Verified against `docs.xalgorix.com`. | Holds, low significance |
| C23 | "No cross-run learning of any kind in Xalgorix" | **A** | Verified. | Holds |
| C24 | "Telemetry is not a control signal" | **A** | Verified — detection hooks read tool results directly, never the event stream. | Holds, low significance |
| C25 | "Resource-aware admission control is a genuine strength" | **B / G** | Real (`internal/resources`), but it is competent resource limiting rather than a novel architectural primitive. The first report's ⭐ rating overweights it (§13). | Downgrade |

**Summary of verdicts:** 15 **A**, 4 **B**, 4 **D**, 3 **F**, 2 **G** (some claims carry two tags).
Roughly **60% of high-impact claims fully verified**, **~25% needing qualification**, **~15% materially
wrong** — and the wrong ones cluster almost entirely in the HuntMCP-comparison half of the document, not
the Xalgorix-reconstruction half.

That asymmetry is the single most useful thing this review found: **the first report's Xalgorix research
is trustworthy; its HuntMCP comparison is not.**

---

# 5. 22-Phase Architecture Review

## 5.1 Independent re-derivation

Three appearances of "phase" in the system, re-verified:

**(a) Prompt constant.** `agent_prompt.go:526` `const defaultChecklist` → line 1554. 1,029 lines.
Phases are `### PHASE N:` markdown headings. Confirmed.

**(b) Prompt-level filter + one hardcoded code path.** `buildPhaseFilterInstruction`
(`autonomous.go:228`) renders the selection as prose. `phaseAllowed` and `firstSelectedPhase`
(`scan_session.go:728,747`) are pure helpers used only for prompt generation and display gating.

The **only** enforcement is `isReconReportOnlyPhaseSelection` — true iff the selection is a subset of
`{1, 22}` — which then blocks `report_vulnerability` and substring-matches a 24-entry blocklist
(`sqlmap`, `nuclei`, `union select`, `/etc/passwd`, `169.254.169.254`, `jndi:`, …). Selecting phases
6 and 9 changes no code path.

**(c) Post-hoc keyword inference.** `inferCurrentPhase` (`scan_session.go:776`) substring-matches
`tool_call` args; `CurrentPhase` advances monotonically.

## 5.2 Where the first report was slightly wrong

It stated the inferred phase "does not drive anything." **It drives exactly one decision.**
`scan_session.go:398`:

```go
producedResults := reportedVulns > 0 || len(sess.record.Vulns) > 0
                   || sess.record.CurrentPhase >= 20 || sess.record.ToolCalls >= 5
```

An aborted scan is recorded `failed` (and, per the code's own comment, refunded on hosted deployments)
unless `producedResults`. So a **keyword-inferred** phase number participates in a status/billing
decision. In practice the `ToolCalls >= 5` leg almost always fires first, making the phase leg nearly
redundant — but "drives nothing" is not accurate.

## 5.3 Hidden phase controls: searched for, none found

Grepped for phase-keyed routing, phase-gated tool registration, phase-ordered task graphs, and
phase-dependency structures across all 323 Go files. Nothing. `AllowedPhases` on `ScanState` is only
read to compute `ReconOnlyMode`.

## 5.4 Verdict

**C — prompt/checklist methodology**, with a thin **B** veneer for the recon-only special case and a
single vestigial code effect on abort classification.

**Sustained.** The first report's conclusion is correct and was the right call to make.

---

# 6. Independent Verifier Review

## 6.1 Re-verified mechanics

| Question | Answer (verified) |
|---|---|
| What creates the verifier context? | A fresh `[]llm.Message` built by `buildVerifierPrompt`; a **new** `tools.Registry` (`verifier.go:58–75`) |
| What is shared? | The structured claim only (title, severity, CWE, claimed method, CVSS, target, endpoint, HTTP method, description, claimed proof) — **plus the entire `ScanContext`**: same browser, terminal, notes, session auth |
| What is hidden? | The hunter's reasoning, conversation, and intermediate observations |
| Independent reasoning? | Yes — separate conversation, no shared message history |
| Can it rely on the hunter's assertions? | The prompt forbids it ("DO NOT TRUST — reproduce it yourself"); nothing structurally prevents it |
| Evidence captured or narrated? | **Its own observations are real** (it runs real tools and sees real output in its own conversation). **Its conclusion is narrated** — `submit_verdict(evidence=...)` is free text |
| Can output be fabricated? | Yes. Nothing binds the verdict's `evidence` string to the transcript |
| Deterministic? | No — model-driven. The **deterministic** confirmers are a separate, parallel mechanism |
| Per-class? | The prompt encodes per-class evidence standards; the *mechanism* is class-agnostic |
| Failure semantics | `confirmed` / `rejected` / `inconclusive`; unrecognised → inconclusive; rejection requires positive disproof |
| Can it become a source of false confidence? | **Yes — this is the real risk.** See below |

## 6.2 The sharpening the first report should have made

The first report said "the verifier's own evidence is also narrated" and moved on. The important
consequence was not drawn:

> **A finding that passes verification carries a stronger label than an unverified one, but the strength
> of that label is not backed by anything machine-checkable.** The verifier converts a model-narrated
> claim into a model-narrated *confirmation*, and the confirmation is what downstream reporting, PDF
> generation, and Discord/Telegram notification treat as authoritative.

That is a **false-confidence amplifier**, not merely a gap. Issue #640 is precisely this failure surfacing
at the notification boundary.

Two mitigations do exist and the first report under-credited them:

1. Confirmations that came from a `verify_*` tool are separately marked exploit-proven
   (`feat(reporting): mark verify_*-confirmed findings as exploit-proven`, 2026-09-04) — so there **is**
   a distinction between machine-confirmed and model-confirmed findings.
2. The three-valued verdict's asymmetry means the verifier's failure mode is biased toward *retaining*
   unproven findings rather than *fabricating* confirmations.

## 6.3 Exact security value

**Real but bounded.** It reliably catches the class of false positive that a skeptical re-read plus one
round of re-testing catches — reflection-vs-execution, missing baseline, circular evidence, wrong class,
by-design behaviour. It cannot catch fabrication, and it cannot catch a finding whose reproduction depends
on residual state it inherits.

**Verdict on the first report's treatment: A (accurate), with an under-drawn implication.**

---

# 7. Hypothesis Ledger Review

## 7.1 Schema — re-verified

`Hypothesis`: `ID`, `DedupKey`, `Title`, `VulnClass`, `Target`, `Endpoint`, `Parameter`, `Role`,
`DataFlow`, `Preconditions[]`, `RequiredPrivilege`, `Baseline`, `Status`, `Confidence`, `AssignedTo`,
`NextAction`, `Attempts`, `Evidence[]`, `Origin`, `CreatedAt`, `UpdatedAt`.

`Evidence`: `ID`, `Kind` (`baseline`/`control`/`probe`/`exploit`/`artifact`/`finding_ref`), `Summary`,
`Request`, `Response`, `FindingID`, `AgentID`, `Confidence`, `CreatedAt`.

Bounds: 40 evidence per hypothesis (`finding_ref` exempt from eviction), 4,096 bytes per request/response
field, 2,048 summary, 512 per hypothesis field.

Dedup key: `(VulnClass, Endpoint, Parameter, Role)` with `normalizeEndpoint` stripping the query string.

## 7.2 "Graph" — the first report's word choice was loose

The first report called it a "hypothesis graph" and "hypothesis/evidence graph" (echoing Xalgorix's own
comment). **It is not a graph.** It is a flat, dedup-keyed **map** of hypotheses, each owning a flat list
of evidence. There are no edges between hypotheses — no `depends_on`, no `chains_to`, no parent/child.
`Preconditions` is a `[]string` of free text, not a reference.

This matters for HuntMCP because *chaining* is a HuntMCP capability (`chainer-mcp`, DAG-based, 15
templates). The first report implied Xalgorix had a graph structure HuntMCP might learn from. It does
not — and HuntMCP's `chainer` is the actual graph. **Correction: `G` (correct but the label overstated
the structure).**

## 7.3 Does it drive execution?

**No.** Re-verified. `Schedulable(limit)` and `ClaimNext(class, agent)` have exactly two call sites:
`ledger_tools.go` (registering them as model-callable tools) and `ledger_hooks.go:115` (rendering up to
8 schedulable hypotheses into a delegation nudge). No dispatcher consumes them.

The commit message `feat(agent): claim_next_hypothesis — deterministic ledger scheduling` (2026-09-02)
calls this "deterministic ledger scheduling." **The scheduling primitive is deterministic; its
invocation is not.** That distinction is worth preserving precisely.

## 7.4 Persistence and mutability

Verified: `<scanDir>/ledger.json`, atomic write outside the lock, `LoadFromDisk` **merges**, evidence
append-only, `Upsert` cannot regress a proven hypothesis, `NormalizeHypothesisStatus` fails safe to
`queued`. Good design.

**Not verified as safe:** there is **no cross-process lock** on `ledger.json` or `scan.json`. `flock` is
used for `auth-profiles.json` and for shell rate limiting, but not for scan state. Two Xalgorix processes
sharing a scan directory would be last-writer-wins at the file level. (Mitigated in practice by the
per-scan directory model and by `LoadFromDisk`'s merge semantics.) **This is a missed finding — see §17.**

## 7.5 Verdict

Schema and semantics: **A — accurately described.**
"Graph": **G — imprecise label.**
"Drives orchestration": **A — correctly identified as advisory despite the commit message.**

---

# 8. CEM Equivalence Analysis

This was the first report's highest-impact claim. It receives the most adversarial pressure here.

## 8.1 What was actually claimed

> "`verify_sqli` = pin everything, perturb the quote, compare against baseline, require the control to be
> clean. That *is* a do-intervention with a held-fixed set… **CEM is not a layer on top of validation — it
> is the validation primitive, entered with a different condition set.**"

Tagged `[H]` in §26 of the first report, but presented as "the insight I'd flag" and "the highest-leverage
question" in its summary and closing. That promotion is the problem: a hypothesis was given the rhetorical
weight of a finding.

## 8.2 Primitive-level comparison

Both were re-read from source: `cem_engine.py:437` (`determinism_gate`), `:492` (`classify`),
`:309` (`SuccessSignature`), `:1520` (`run_intervention`), `:1505` (`Trial`); and
`verify_sqli.go`, `verify_ssti.go`, `xssverify.go`, `oob_verify.go`, `authz_matrix.go`.

| Primitive | HuntMCP CEM | Xalgorix confirmer |
|---|---|---|
| Baseline arm | Unperturbed request, **must HIT all k** | Benign request, **must MISS** (no DBMS error) |
| Perturbed arm | Condition removed → observe | Payload injected → observe |
| Control | `Controls` — confounder pinning, spacing | Implicit: the benign baseline *is* the control |
| Condition | First-class, typed, persisted (`cem_conditions`) | Implicit and singular: "the payload" |
| Oracle | `SuccessSignature` — `status_in` / `body_contains` / `body_regex` / `similarity_to_baseline`, AND-composed, validated non-vacuous | Per-tool hardcoded Go predicate (DBMS-error regex, product-in-body, dialog nonce, OAST origin assessment) |
| Replication | `k` trials/arm, unanimity required | **k = 1.** Three single requests total |
| Determinism handling | `determinism_gate` → STABLE / NONDETERMINISTIC; mixed → `inconclusive` | **None.** A flaky endpoint yields a confirmation |
| Verdicts | `necessary` / `apparently_not_necessary` / `inconclusive` / `probabilistic` / `interacting` | `confirmed` / `not confirmed` (+ a confidence float) |
| Minimization | `minimal_condition_sets` (ddmin), alternates, interaction rules | None |
| Evidence | `cem_trials` rows: `request_evidence_hash`, `response_evidence_hash`, `http_status`, `oracle_hit`, `arm`, `k_index` | Ledger `Evidence{Request, Response, Summary, Confidence}` |
| Entry precondition | `_confirmed_or_error(finding_id)` — **the finding must already be CONFIRMED** | Runs **pre-confirmation**; its job is to establish existence |

## 8.3 Answering the nine questions directly

**1. Are they the same abstraction?** No. They share a *shape* (two arms, an oracle, a comparison) but
answer different questions. CEM answers **"is condition C load-bearing for a known-working exploit?"**
Xalgorix answers **"does a vulnerability exist here at all?"** Necessity presupposes existence.

**2. Only superficially similar?** More than superficial, less than equivalent. The mapping
Xalgorix-probe-arm → CEM-baseline-arm and Xalgorix-benign-baseline → CEM-perturbed-arm is structurally
valid, and under it `classify()` would return `necessary` exactly when `verify_sqli` returns confirmed.
That is a real correspondence, not a coincidence.

**3. Can Xalgorix verification be represented as a special CEM case?** **Partially — 5 of 7 confirmers,
with loss.**
- ✅ Expressible: `verify_sqli` (core arm pair), `verify_ssti` (product string → `body_contains`),
  `verify_xxe` (file content → `body_contains`), `verify_csrf` (status → `status_in`), `probe_hypothesis`.
- ❌ **Not expressible:** `verify_xss` — the oracle is *a JavaScript dialog carrying a nonce fired in a
  headless browser*. `SuccessSignature` matches only a `FetchResult` (`status`, `body`, `error`). There is
  no channel for a browser-execution observation.
- ❌ **Not expressible:** `verify_oob` — the oracle is *a non-scanner-origin HTTP interaction against a
  fresh OAST token*. Again outside `FetchResult`.
- ⚠️ **Lossy:** `verify_sqli`'s third arm (doubled-quote break/recover) and `authz_matrix`'s three
  identities require decomposition into multiple `classify()` calls; the composite verdict
  ("break/recover confirmed at high confidence") is not recoverable from independent binary verdicts.

**4. Can CEM represent the verifier without losing semantics?** No — see 3. And the LLM verifier itself is
not representable at all; it is a judgement process, not an intervention.

**5. Does CEM provide what Xalgorix lacks?** **Yes, substantially.** k-replication, a determinism gate,
`inconclusive` on mixed results, ddmin minimization, alternate minimal sets, interaction detection,
race/`probabilistic` handling, typed persisted conditions, and per-trial content-addressed evidence.
Xalgorix's confirmers are k=1 with no stability check.

**6. Does Xalgorix provide what CEM lacks?** **Yes, and it is the actionable part:** non-HTTP oracles
(browser execution, OAST callback) and a **pre-confirmation entry point**. CEM's `determinism_gate`
structurally requires the capability to already fire; `case-mcp` additionally gates on
`_confirmed_or_error`.

**7. Would unifying them simplify architecture?** Only if `SuccessSignature` were widened to accept
non-HTTP observations and `determinism_gate`'s all-HIT precondition were relaxed. Both are real changes
to a Phase-1-pinned contract that was, per its own docstring, deliberately narrowed with human approval.

**8. Could unification create unacceptable coupling?** Yes — a realistic risk. `cem_engine.py` is
explicitly *pure*: no network, no MCP, no DB, injected `fetch_fn`. Admitting a browser oracle or an OAST
poller into `SuccessSignature` would either break that purity or require an abstraction (an injected
`observe_fn`) that has to be designed carefully. The purity is load-bearing for testability.

**9. Is "CEM as general validation primitive" supported?** **Not as stated.** It is supported as:
*CEM's intervention/verdict machinery is a strict superset of Xalgorix's confirmer verdict logic, while
CEM's oracle contract is a strict subset of Xalgorix's oracle expressiveness.*

## 8.4 Verdict

**ANALOGY — strong, structurally real, and useful. NOT formal equivalence.**

The first report's hypothesis **survives in weakened form** and its practical value is much narrower and
much more concrete than "confirmation is CEM":

> **The transferable finding is that `SuccessSignature`'s expressiveness — not CEM's verdict logic — is
> the gap. CEM's verdict machinery already dominates Xalgorix's. Xalgorix demonstrates two oracle
> classes (browser-execution, OOB-callback) that CEM's current oracle contract cannot express.**

That is a legitimate research question about one dataclass, not an architectural reconsideration.

---

# 9. Persistence / Resume Review

Re-verified independently. No corrections.

**Survives:** findings (`scan.json`), notes (`notes.json`), ledger (`ledger.json`, merged on load),
queue position (`queue_state.json`), schedules, provider keys.

**Does not survive:** the conversation, `ScanState`'s ~70 counters, the coverage matrix, terminal children,
browser state (unless the agent explicitly called `save_session`).

**Event history:** persisted, but each event's `Output` is **truncated to 500 chars** at persistence
(`scan_session.go:698`). Only the last **six** tool events reach the resume briefing, each further
truncated to 300 chars.

**Pause:** `inst.cancel()` + `inst.agent.Stop()`. The agent is killed.

**Resume:** a new `Agent`, `SetInitialIteration` (cosmetic), `SetResumeBriefing` (text).

**Classification: C — restart-with-summary**, with a **B** component that the first report correctly
identified and correctly flagged as unexploited: the ledger genuinely reloads, but `formatResumeBriefing`
does not include it.

**Verdict on the first report: A. Accurate and well-characterised.**

---

# 10. Continuous Security Review

Re-verified. No corrections. Four independent confirmations:

1. `scheduler.go:283` — 30 s ticker → `go s.runMultiScan(req, &scanCfg, randomSlug())`. Nothing carried
   from the previous run.
2. `reporting.go:281` — "Duplicate checks are scoped to the current scan run only."
3. `autonomous.go:160` / `:320` — "Previous scans… do NOT count as duplicates."
4. Repo-wide search for cross-run diff/regression/baseline logic: nothing outside `internal/realbench`
   (which is benchmark tooling, not product).

**Continuous execution: yes.** (Cron with startup catch-up, per-schedule panic containment, timezone
handling.)
**Continuous intelligence: no.** No baseline, no delta, no "new/fixed/regressed", no hypothesis carry-over.

**Verdict: A.** The first report's framing — "`cron(full_scan)`" — is exact.

Worth adding for fairness: this is a coherent consequence of the no-database decision, not negligence.

---

# 11. Exploitation Proof / Evidence Review

The first report's second-highest-impact claim. It needed the most correction.

## 11.1 What is actually true

**Path 1 — narrated (the reporting boundary).**
`report_vulnerability(exploitation_proof=…)`, `reporting.go:292`, documented "Paste actual output here."
Free text, model-authored. `submit_verdict(evidence=…)` likewise.

**Path 2 — captured (the confirmer path).**
`verify_sqli.go:183–190` writes to the ledger:
```go
l.AddEvidence(h.ID, scanctx.Evidence{
    Kind: "exploit", Summary: confirm,
    Request:  brokenReqLine,      // the ACTUAL request line
    Response: brokenExcerpt,      // the ACTUAL response excerpt
    Confidence: confidence, AgentID: a.ledgerOrigin(),
})
```
Same pattern in `verify_ssti`, `verify_xxe`, `verify_csrf`, `xssverify`, `oob_verify`, `authz_matrix`.

**The defect is the seam, not the absence.** Xalgorix has real captured evidence. `report_vulnerability`
accepts an optional `hypothesis_id` that *links* to the hypothesis holding it — but the link transfers no
evidence; the report's proof remains whatever the model typed.

## 11.2 Correction to the first report

"Evidence is narrated, not captured" is **too strong**. The accurate statement:

> Xalgorix captures machine-generated evidence on the deterministic-confirmer path and separately accepts
> model-narrated proof at the reporting boundary. The two are linked by an optional ID that carries no
> evidence. The captured evidence exists and is never promoted into the report.

## 11.3 Why no fallback exists

The first report suggested binding reports to event IDs. **That is not viable in Xalgorix:** persisted
event `Output` is truncated to 500 characters (`scan_session.go:698`). There is no full-fidelity
transcript anywhere outside the ledger's own bounded 4,096-byte evidence fields.

## 11.4 Is it exploitable in practice?

**Yes, demonstrated.** Issue #640 (open, 2026-09-11): the agent invents command output in the quoted
Request/Response evidence delivered to Telegram. Closed #471 and #429 record fabricated critical/high
findings with placeholder data. Same root cause: the model authors the proof.

## 11.5 Mitigating controls that do exist

- `verify_*`-confirmed findings are separately marked exploit-proven (2026-09-04).
- The reporting impact gate shares `LooksLikeSQLError` with `verify_sqli`, so gate and confirmer cannot
  drift.
- The verifier independently re-tests, so a fabricated proof must survive a second pass.
- FP-specific test files exist: `fabricated_fp_test.go`, `host_bypass_fp_test.go`, `oauth_fp_test.go`,
  `smuggling_fp_test.go`, `salvage_test.go`, `ledger_link_test.go`.

## 11.6 Severity classification

**C — evidence-integrity issue.** Not **D/E**: it is not a security vulnerability in Xalgorix, and it
does not break the trust model wholesale — the verifier and the confirmer path materially constrain it.
But it does mean **a reported proof is not attributable to an observation**, which for a tool whose entire
positioning is *"Most scanners detect. Xalgorix proves"* is a direct hit on the core claim.

The first report implied **E**. That is one level too high.

---

# 12. Security Model Review

## 12.1 Exhaustive enforcement-point trace (the first report did not do this)

All 13 `scopeguard.IsLocalOrListener` call sites:

| Site | Purpose |
|---|---|
| `agent_guard.go:339`, `:362` | Gated-tool args; `report_vulnerability` target/endpoint |
| `probe_hypothesis.go:77` | Internally-resolved host |
| `verify_sqli.go:105`, `verify_ssti.go:98`, `verify_xxe.go:98`, `verify_csrf.go:89` | Internally-resolved host |
| `authz_matrix.go:98` | Internally-resolved host |
| `web/notify.go:183` | Outbound webhook destination (SSRF via notification config) |
| `web/codescan.go:65` | Code-scan provisioned target |

**Every one protects the operator's machine.** None checks engagement scope.

`activityHosts` — exactly three uses: `agent_prompt.go:1750` (port extraction for prompt text), and
`agent_guard.go:267`/`:279` inside `shouldBlockForActivityPolicy`, which returns early unless the scan is
in passive-recon or passive-scan mode.

`internal/tools/httpclient/httpclient.go` — **zero** host restrictions.

`har.InScopeEndpoints(targetHost)` (`har/har.go:202`) — the only host-matching-against-target logic in the
codebase. It filters *endpoints parsed from an uploaded HAR file at ingestion time*. It is not a request
gate.

**Result: in an active scan there is no engagement-scope enforcement of any kind.** Claim C6 **verified**.

## 12.2 The fairness correction the first report owed

The first report framed this as negligence and as the system's "most serious gap." Two qualifications:

1. **It is deliberate and documented.** The guard's own comment cites a design decision
   ("per design.md → Open Question: Requirement 3.7"). Xalgorix's model is: the operator picks the target
   and owns scope; the tool only refuses to attack the operator.
2. **The project is not careless about security engineering.** CI runs `golangci-lint` with `gosec`,
   `errcheck`, `errorlint`, `bodyclose`, `sqlclosecheck`; semgrep with `p/golang`, `p/security-audit`,
   `p/secrets`, `p/owasp-top-ten` plus first-party rules; `govulncheck`; and `go test ./... -race`.
   This is a mature secure-SDLC posture. **The first report mentioned none of this** (§17).

The correct characterisation: **a deliberate design choice that is defensible for operator-selected
single targets and becomes materially risky the moment the agent autonomously discovers adjacent
infrastructure** — which, in wildcard mode with subdomain enumeration, is the normal case.

The `agent.go:~1461` comment that describes a scope guard the implementation explicitly disclaims remains
a genuine defect: it is a stale, actively misleading comment on the most safety-relevant path.

## 12.3 What the first report got right and should keep

`sandbox` write/read asymmetry, the `cd` workspace guard, secret redaction before telemetry emission,
auto-install off by default, the honest "best-effort guardrail" label, per-scan credential isolation, and
`hookBenchmarkIsolationGuard`. All re-verified.

## 12.4 HuntMCP's comparative position — with direct runtime evidence

`mcp-servers/scope_guard.py:181`:
```python
def is_in_scope(target, engagement) -> bool:
    host = _host_of(target)
    if is_safe_test_host(host): return True
    for pattern in engagement.out_of_scope:
        if _matches(host, pattern): return False
    return any(_matches(host, pattern) for pattern in engagement.in_scope)
```
**Deny-by-default allowlist.** Enforced at three layers: a `PreToolUse` harness hook
(`scripts/hooks/scope_gate_hook.py`) that blocks the tool call before execution; `case-mcp`'s
`_scope_or_error` before any CEM HTTP; and a **per-trial** scope callback inside `run_intervention` so the
check cannot drift from the request actually sent. `TIER2_BASH_TOOLS` includes `curl-rl.sh` specifically
so renaming the binary is not a bypass.

**Direct runtime evidence:** this session's own tool calls were blocked twice by that hook — once for a
`rm` in a command string, once for a token it parsed as an out-of-scope hostname. The gate is real and
active, not aspirational.

**An honest counter-observation for the record:** the second block was a **false positive** — the hook
read `json.load` inside an inline Python snippet as a hostname and refused the call. An over-eager scope
gate has its own failure mode: operators route around it. That is a HuntMCP observation this review
surfaces from direct evidence; it is noted, not acted on.

---

# 13. Resource / Admission Control Review

Re-verified: `EffectiveMaxInstancesForAdmission`, `memoryInstanceCapacity`, `diskHasHeadroom`,
`perInstanceMemoryBudgetMB`, `autoGoMemoryLimitMB`, `hostReserveMB`, `AcquireLLMSlot`, `ToolLease` with
`sync.Once` release preserved through panic recovery in `ScanContext.Close()`.

**Is it a reusable architectural strength or sensible resource limiting?**

**Mostly the latter.** Admission control keyed on live host stats is standard practice (schedulers,
container runtimes, connection pools). What is mildly distinctive is applying it inside a *single-binary
desktop-class tool* and tying it to a lease that survives panics.

The first report gave it a ⭐ and called it "fundamental operationally." Operationally true; the ⭐
implies transferable architectural insight it does not carry.

**Downgrade: G — correct but low significance for HuntMCP**, unless and until HuntMCP runs many
concurrent engagements on one host. HuntMCP's `budget_guard.py` addresses a different axis (Tier-2 call
counts / cost), and cost is the axis that actually binds for an LLM-driven system.

---

# 14. Source / Whitebox Review

Re-verified without correction.

- Ingestion: git clone or local path, resolved in the scan goroutine, guarded so only the first agent
  resolves it.
- Analysis: `sinkPatterns` — 11 ripgrep regexes (`codesearch.go:57–69`), executed via rg with grep
  fallback. **No AST, no parser, no taint, no call graph.** The code says so: "These are DISCOVERY aids."
- Route extraction: regex, receiver-restricted to router-like identifiers after a documented bug where
  `request.args.get('host')` was harvested as a route named `host`.
- Join: **same-file co-location** between a route declaration and a sink.
- Runtime link: `probe_hypothesis` issues one scope-gated baseline request against the live target and
  records the real response as ledger evidence, then `verify_*` confirms.

**Is "source → runtime bridge" justified?** **Yes — for the pipeline, not for the analysis.** There is a
genuine, closed loop: source artifact → typed hypothesis with `DataFlow` → reachable HTTP path → live
probe → deterministic confirmation → report, all mediated by one durable object. That is a real
architecture and better-integrated than most SAST/DAST correlation products.

The *analysis* underneath it is grep. The first report said exactly this. **Verdict: A.**

One addition the first report missed: `internal/attacksurface` seeds the surface from **OpenAPI (JSON and
YAML), HAR, Postman collections, and Android APK bundles** (`isAndroidArchive`). Spec-seeded surface is a
sibling of the source bridge and was under-covered (§17).

---

# 15. Benchmark / Claims Audit

## 15.1 What is reproducible from the repository

| Suite | Tracked? | Nature |
|---|---|---|
| `internal/bench` — 35 challenges, **15 negative controls** | ✅ | In-process `httptest` apps; agent injected as `ScanFunc`; scoring unit-tested with zero model calls |
| `internal/realbench` — Grafana 8.2.6 vs patched 8.2.7, CVE-2021-43798 | ✅ | Pinned digests, loopback-only, repeated runs, control-regression tracking |
| **XBOW 104-challenge suite** | ❌ **NOT TRACKED** | `cmd/xalgorix-xbow/main.go` (225 LOC) **deleted** 2026-09-06, commit `51523a2`: *"keep xbow harness runner as untracked operator tooling (not shipped); drop from release"* |

## 15.2 The claim under audit

`CHANGELOG.md:27`: *"On the 104 XBOW validation benchmarks this raised the pass@1 flag-capture rate from
58/104 to a **projected** ~70/104 (XSS +6, IDOR +2, SSTI +2, cmdi +2)."*

Three problems, in ascending order of importance:

1. A projection is stated in the same sentence as a measured baseline, with only the word "projected"
   separating them.
2. The per-class deltas (`XSS +6, IDOR +2, SSTI +2, cmdi +2`) are rendered with the precision of
   measurements. They sum to +12, but the headline says +12 against a "~" figure.
3. **The harness that produced the 58/104 baseline is not in the repository.** Neither number is
   reproducible by a third party from the published source.

## 15.3 Correction to the first report

The first report wrote: *"MAPTA measures 76.9% on the same 104-challenge set."* Factually true, but the
juxtaposition implies comparability. It is not comparable:

| | MAPTA | Xalgorix |
|---|---|---|
| Number | 76.9% | 58/104 measured → ~70/104 projected |
| Published | arXiv:2508.20816, peer-reviewable | CHANGELOG line |
| Harness | Described in the paper | Deliberately untracked |
| Protocol | Documented, with cost accounting | Not documented |
| Reproducible | In principle | No |

**The first report should have said: Xalgorix's only externally-comparable number is partly a projection
produced by tooling it does not ship, and therefore should not be compared to a published measurement at
all.** That is the correct statement, and it applies regardless of whether Xalgorix's number is accurate.

## 15.4 What survives, and is genuinely strong

The **internal** benchmark is excellent and fully reproducible: 15/35 negative controls, precision
reported as a first-class scorecard line, class-based (not endpoint-based) scoring, CWE-preferred
classification, object-ID dedup templating, and a runtime guard blocking `docker`/`nsenter` during
benchmark runs to prevent white-boxing a local fixture.

The first report was right to call this the project's best methodological asset. It was wrong to let the
XBOW number stand next to MAPTA's.

**Verdict: benchmark methodology A; benchmark *claims* F.**

---

# 16. Commit-History Direction Review

This is where the first report is **factually wrong**, and it matters because "direction of travel" was
one of its two headline framings.

## 16.1 What the commits actually show

**Ledger + confirmers — a labelled program, not organic drift:**

| Date | Commit |
|---|---|
| 2026-09-01 | `feat(ledger): durable hypothesis/evidence ledger foundation (P1)` |
| 2026-09-01 | `feat(agent): make the hypothesis ledger drive orchestration (P1)` |
| 2026-09-01 | `feat(p2): multi-role authorization matrix + browser XSS verification` |
| 2026-09-02 | `feat(agent): claim_next_hypothesis — deterministic ledger scheduling` |
| 2026-09-08 | `feat(scanner): add real-world CVE benchmarks and deterministic coverage (#627)` |

Confirmer file creation dates: `oob_verify` 09-01, `authz_matrix` 09-01, `xssverify` 09-01,
`scan_source_sinks` 09-02, `verify_sqli` 09-03, `verify_ssti` 09-03, `scan_source_routes` 09-03,
`probe_hypothesis` 09-03, `verify_xxe` 09-04, `verify_csrf` 09-04.

**Every confirmer was created in a four-day window: 2026-09-01 → 2026-09-04.**

**What happened next (2026-09-05 → 2026-09-10):**

| Date | Feature commit |
|---|---|
| 09-06 | Struts2/OGNL injection → RCE **technique** |
| 09-06 | MongoDB ObjectId-prediction IDOR, arbitrary-verb method-tamper, XSS filter-bypass |
| 09-06 | Escalate LFI to RCE via log/session poisoning |
| 09-06 | Deeper flag-capture exploitation (XSS exec, SSTI/cmdi/LFI escalation, IDOR enum) |
| 09-06 | Recover IDOR/discovery/SSTI benchmark classes |
| 09-08 | Real-world CVE benchmarks + deterministic coverage |

Files changed most in that window: `Makefile` (11), `cmd/xalgorix/main.go` (11),
**`internal/agent/agent_prompt.go` (8)**, `CHANGELOG.md` (6), `README.md` (4).

**Zero new confirmers. Ledger untouched after 09-08. `agent_prompt.go` — the 1,029-line checklist — is the
most-modified Go file of the week.**

## 16.2 Correction

The first report stated: *"In the two weeks since, nearly every feature commit has been about routing
evidence into that ledger."* **This is false.** The accurate statement:

> The ledger and its seven deterministic confirmers were built as a deliberate, phase-labelled (P1/P2)
> program in a four-day burst, 2026-09-01 to 09-04. In the following six days, development reverted to
> adding techniques to the prompt checklist in pursuit of XBOW flag-capture gains. When the team needed
> results in week two, they reached for the prompt, not the ledger.

## 16.3 What this does to the inference

The first report built a claim on this: *"That is a project migrating away from 'prompt the model harder'
and toward 'make the machine own the evidence.'"*

**That inference is not supported by the commit record.** Both mechanisms are being developed in
parallel, and the most recent week favoured the prompt. Whether the ledger direction continues is
**undetermined**.

The revised, defensible statement:

> Xalgorix built a real, deliberate hypothesis-ledger-plus-oracle subsystem in early September. It is
> twelve days old, has had five commits since, and coexists with an actively-growing prompt checklist.
> It is a **plausible** architectural direction, not a **demonstrated** convergence.

**Verdict: D — the direction-of-travel claim is materially wrong as stated, and must not be carried into
the master roadmap in its original form.**

---

# 17. Missed Findings

Architectural facts absent from `XALGORIX-RESEARCH.md`. Mandatory section.

## M1 — `internal/scanheaders`: authorized-scan identification headers ⭐

Operator-supplied headers (e.g. `X-Bug-Bounty: <handle>`) attached to **every target-facing request**, so
traffic is attributable in the target's access logs and allow-listable by its WAF/SOC. Passed through to
bundled tools that accept `-H` (httpx, nuclei), and injected into shell commands via
`terminal.InjectScanHeadersIntoCommand` in the agent loop. **Explicitly never** attached to LLM/provider
APIs, AgentMail, Discord/Telegram, or the dashboard.

**Why it matters:** bug-bounty programs frequently *require* an identifying header. This is a
responsible-testing primitive with a correctly-drawn destination boundary, and the first report missed it
entirely. Directly relevant to HuntMCP.

## M2 — Binary-level rate limiting via executable shims ⭐

Xalgorix does not merely rate-limit its own HTTP client. It **writes executable wrappers around
curl/wget** (`terminal.go:500–530`) containing a `flock`-serialized `rate_wait` against a shared timestamp
file, and writes a `sitecustomize.py` that monkeypatches Python HTTP calls the same way.

**Consequence:** a raw `curl` the model invents is rate-limited, and concurrent tool invocations share one
global request budget across processes. That is enforcement at the *process boundary*, not the
tool-wrapper boundary. The first report described the rate policy as a config value.

**HuntMCP parallel:** `scripts/curl-rl.sh` addresses the same gap by a different route (a wrapper agents
are told to call, registered in `TIER2_BASH_TOOLS` so the name cannot be bypassed). Xalgorix's shim
approach does not depend on the agent choosing the right binary. Worth noting as a design contrast.

## M3 — A mature secure-SDLC CI posture ⭐

`.github/workflows/ci.yml`: `make lint`, `golangci-lint` (with `gosec`, `errcheck` incl. type assertions,
`errorlint`, `bodyclose`, `rowserrcheck`, `sqlclosecheck`, `staticcheck`, `revive`), `go vet`,
`go test ./... -race -count=1`, coverage artifact upload, multi-arch builds, a macOS ARM64 smoke test.
`.semgrep.yml` pulls `p/golang`, `p/security-audit`, `p/secrets`, `p/owasp-top-ten` plus first-party rules
(e.g. no MD5/SHA-1 for auth). `.govulncheck.yaml` present.

**Why the omission mattered:** the first report's §16 read as if the scope gap were carelessness. It is
not. This context changes the interpretation of every security finding from "sloppy" to "deliberate
trade-off," which is a materially different input to a roadmap.

## M4 — Persisted event output is truncated to 500 characters

`scan_session.go:698`. The first report called the event log the audit trail. It is a 500-char-truncated
summary log, unusable as forensic evidence — and this is precisely why binding reports to event IDs is
not a viable fix in Xalgorix (§11.3).

## M5 — No cross-process locking on scan state

`flock` protects `auth-profiles.json` and shell rate limiting. `scan.json` and `ledger.json` have
**in-process** mutexes plus atomic file replacement, but nothing prevents two Xalgorix processes from
last-writer-wins on the same scan directory. Partially mitigated by `LoadFromDisk`'s merge semantics and
the per-scan directory model.

## M6 — `attacksurface` ingests APK bundles alongside OpenAPI/HAR/Postman

`isAndroidArchive`, plus OpenAPI JSON *and* YAML, HAR, and Postman with variable resolution. Spec-seeded
attack surface is a distinct primitive from crawl-based discovery and got one table row in the first
report.

## M7 — Outbound notification destinations are SSRF-guarded

`web/notify.go:183` runs `IsLocalOrListener` on the **webhook destination**. A user-supplied Discord
webhook URL cannot be pointed at the operator's own network. Small, easy to miss, correctly done.

## M8 — The XBOW harness was deliberately untracked

Commit `51523a2`, 2026-09-06. Directly undermines the reproducibility of the only externally-comparable
benchmark number. (Covered in §15; listed here because the first report did not know it.)

## M9 — The ledger is a map, not a graph

No edges between hypotheses. `Preconditions` is free-text `[]string`. (§7.2)

## M10 — Commit messages carry explicit phase labels (P1/P2)

Evidence that the ledger work was a *planned program*, which is both a stronger claim (intentional) and a
weaker one (bounded, possibly complete) than "organic convergence."

---

# 18. Overstated / Incorrect Findings

Each with evidence.

| # | Overstatement | Evidence against | Corrected form |
|---|---|---|---|
| O1 | "Nearly every feature commit since 09-01 routes evidence into the ledger" | Sept 5–10: 5/6 feature commits are prompt techniques; `agent_prompt.go` most-changed; zero new confirmers | A four-day P1/P2 burst, then a return to prompt work. Direction undetermined (§16) |
| O2 | "Evidence is narrated, not captured" (blanket) | `verify_sqli.go:183–190` writes real `Request`/`Response` to the ledger | Two paths; the captured one is never promoted into the report (§11) |
| O3 | "The event log is… the only record of what the agent did… (C) Audit" | `scan_session.go:698` truncates output to 500 chars | A truncated activity log, not an audit trail (§17 M4) |
| O4 | "`CurrentPhase`… does not drive anything" | `scan_session.go:398` uses `CurrentPhase >= 20` in the abort-vs-completed decision | Drives exactly one status/billing decision, nothing in the testing loop (§5.2) |
| O5 | "Confirmation **is** CEM with one condition" (promoted from `[H]` to headline) | Inverted entry contract; 2 of 7 confirmers inexpressible in `SuccessSignature`; `classify()` is 2-arm | Strong analogy, not formal equivalence; the real gap is oracle expressiveness (§8) |
| O6 | Severity **E** ("critical trust-model weakness") implied for the evidence gap | Verifier + exploit-proven marking + shared `LooksLikeSQLError` + 6 dedicated FP test files | **C — evidence-integrity issue** (§11.6) |
| O7 | MAPTA 76.9% juxtaposed with Xalgorix ~70/104 | XBOW harness untracked since `51523a2`; number partly projected | Not comparable; should not have been placed side by side (§15.3) |
| O8 | Resource admission control rated ⭐ "fundamental operationally" | Standard practice in schedulers/runtimes | **G** — competent, not architecturally transferable (§13) |
| O9 | Xalgorix ledger described as a "hypothesis graph" | No edges between hypotheses | A dedup-keyed map with per-node evidence lists (§7.2) |
| O10 | §16 security review reads as negligence | gosec + semgrep OWASP + govulncheck + `-race` in CI | Deliberate trade-off by a security-competent team (§12.2, §17 M3) |
| O11 | HuntMCP hypothesis ledger "**B → F**, ADAPT" | `case_store.py` has the full lifecycle; `case-mcp` exposes it | **Wrong row.** Closer to A/B, NO CHANGE (§20) |
| O12 | "L2: bind reported evidence to `audit_log.py`" | `audit_log.log_call` stores args/returncode/duration — **no output** | Right idea, wrong store: `case_store.add_evidence` / `cem_trials` (§20) |
| O13 | HuntMCP verification "convention, not a code gate — B → F" | `case-mcp` has `_confirmed_or_error`, `_scope_or_error`, `_nonidempotent_or_error`, budget + per-trial scope callbacks | Real gates exist on the CEM path; the gap is narrower than stated (§20) |

**Root cause of O11–O13:** the first report compared Xalgorix's *code* against HuntMCP's *planning
documents*. It read `XYZ.md` and `CLAUDE.md` and did not read `mcp-servers/cem_engine.py`,
`case_store.py`, or `case-mcp/server.py`. That is a methodological failure, and it produced a systematic
bias in one direction: **HuntMCP was made to look less complete than it is.**

---

# 19. Valid Findings That Survive

After adversarial pressure, these stand:

**About Xalgorix's architecture (high confidence):**

1. The 22-phase methodology is prompt content, not a state machine. (§5)
2. Phase progress in the UI is a monotonic keyword inference over command lines. (§5)
3. There is no engagement-scope enforcement in an active scan; the only host gate protects the operator's
   own machine. (§12)
4. Pause kills the agent; resume is a new agent seeded with a text briefing. (§9)
5. Continuous mode is cron; no cross-run state, dedup explicitly per-run. (§10)
6. The verifier is conversation-isolated but not environment-isolated. (§6)
7. The verifier's verdict is model-narrated; its observations are real. (§6, §11)
8. The reporting boundary does not consume the captured evidence the confirmers produce. (§11)
9. There is no cross-run, cross-target, or cross-engagement learning. (§10)
10. Source analysis is regex; the source→runtime *pipeline* is nonetheless real and well-designed. (§14)
11. Sub-agents share one mutable `ScanContext` including the browser. (§4)
12. The finish gate is a threshold cascade with a 15-attempt escape hatch. (§4)
13. No database; flat JSON with atomic replacement. (§4)
14. Ledger `Schedulable`/`ClaimNext` are advisory tools, not a dispatcher. (§7.3)

**About Xalgorix's genuine strengths (high confidence):**

15. Deterministic differential confirmers — baseline/perturbed/control in code — are the strongest idea
    in the codebase. (§8)
16. Verification placed at the mandatory reporting choke point is architecture that makes the correct
    behaviour the only available behaviour. (§6)
17. The three-valued verdict with rejection-requires-disproof and fail-safe-to-inconclusive. (§6)
18. Canonical assistant-turn rewriting to prevent few-shot format drift — the most original idea found.
19. The benchmark's 15/35 negative controls and precision-as-a-scorecard-line. (§15.4)
20. `hookBenchmarkIsolationGuard` — research integrity enforced at runtime. (§15.4)
21. Typed abort reasons; refusing to record an abort as "completed." (§4)
22. The endpoint × class coverage matrix with a depth ratio and explicit anti-gaming rules. (§4)

**Newly added by this review (§17):** scan-identification headers; binary-level rate-limit shims; the
secure-SDLC CI posture; 500-char event truncation; no cross-process scan locking; APK/spec surface
seeding; SSRF-guarded webhook destinations; the untracked XBOW harness; ledger-is-a-map; P1/P2 labelling.

---

# 20. HuntMCP Comparison

Re-done against the **implementation**, which the first report did not read.

## 20.1 What HuntMCP actually has

| Component | Reality |
|---|---|
| `cem_engine.py` (1,706 LOC) | **Implemented.** `SuccessSignature` (validated, non-vacuous oracle), `determinism_gate` (k-trial STABLE/NONDETERMINISTIC), `classify` (3 verdicts), `classify_race` (probabilistic), `minimal_condition_sets` (ddmin), `find_alternate_condition_sets` (alternates + 2 interaction rules), `find_and_necessity_groups`, `minimize_poc`, `assemble_bundle`, `Controls`, `run_intervention`, `apply_control_gate`, `apply_throttle_gate`, non-idempotent method approval. Pure — no network, no MCP, no DB. |
| `case_store.py` (772 LOC) | **Implemented.** SQLite: `hypotheses`, `root_causes`, `findings`, `evidence`, `experiments`, `cem_meta`, `cem_conditions`, `cem_trials`, `cem_verdicts`, with FKs and lifecycle statuses. |
| Evidence integrity | **`add_evidence` SHA-256-hashes content into a content-addressed file store**; `cem_trials` persists `request_evidence_hash`, `response_evidence_hash`, `http_status`, `oracle_hit`, `arm`, `k_index`, `controls`. |
| `case-mcp/server.py` | 14+ tools: `log_hypothesis`, `update_hypothesis`, `add_evidence`, `log_experiment`, `check_experiment_exists`, `create_finding`, `update_finding_status`, `score_finding_confidence`, `group_root_cause`, `suggest_root_cause`, `suggest_next_action`, `case_summary`, `case_export`, plus the CEM wrappers with scope/budget/method gates. |
| `scope_guard.py` + `scope_gate_hook.py` | Deny-by-default allowlist, enforced at the harness hook, at `case-mcp` entry, and **per-trial** inside `run_intervention`. |
| `audit_log.py` | Per-Tier-2-call JSONL: `{ts, tool, args (redacted), returncode, duration_ms, block}`. **No output captured.** |
| `watch-mcp` | Continuous recon **diffing** — the capability Xalgorix's "continuous security" lacks. |
| `chainer-mcp` | DAG-based chain planner — the actual graph structure Xalgorix's ledger does not have. |
| `curl-rl.sh` | Rate-limited curl wrapper, scope-gated by name in `TIER2_BASH_TOOLS`. |
| `memory-mcp`, `writeup-mcp`, `lessons-mcp` | Cross-run memory, RAG, feedback loop. Xalgorix has none of these. |

## 20.2 Corrected comparison table

| Xalgorix idea | First report said | **Review verdict** | Reason |
|---|---|---|---|
| Durable hypothesis object | B → F, **ADAPT** | **A — NO CHANGE** | `case_store` hypotheses/findings/evidence/experiments already implemented with FKs and lifecycle |
| Content-addressed evidence | "HuntMCP captures but doesn't cite" | **A — HuntMCP is ahead** | `add_evidence` SHA-256 → content store; `cem_trials` hashes request *and* response per trial |
| Bind reports to `audit_log` | L2, top-3 recommendation | **REJECT the mechanism** | `audit_log` has no output. Correct target is `case_store.evidence` / `cem_trials` |
| Verification as a code gate | B → F, ADAPT | **B — INVESTIGATE (narrow)** | Real gates exist on the CEM path (`_confirmed_or_error` et al.); the drafting path is where convention still rules |
| Deterministic differential confirmers | B → F, **LEARN** | **B — INVESTIGATE (narrow)** | CEM's verdict machinery already dominates. The gap is `SuccessSignature`'s oracle expressiveness only (§8) |
| Endpoint × class coverage matrix | D → F, LEARN | **D — INVESTIGATE** | Genuinely absent. `case_store` has findings but no coverage object. Survives as the cleanest new idea |
| Three-valued verdict | A (convergence) | **A — NO CHANGE** | `classify()` already returns `inconclusive`; CEM adds `probabilistic` and `interacting` |
| Enforced engagement scope | A, HuntMCP stronger | **A — HuntMCP much stronger** | Deny-by-default allowlist at 3 layers vs. no scope enforcement at all |
| Cross-run memory | A, HuntMCP stronger | **A — confirmed** | `memory-mcp` / `writeup-mcp` / `lessons-mcp` vs. nothing |
| Continuous diffing | A, HuntMCP stronger | **A — confirmed** | `watch-mcp` vs. cron |
| Scan-identification headers | **not mentioned** | **D — new, INVESTIGATE** | `internal/scanheaders`; bounty programs often require it (§17 M1) |
| Binary-level rate-limit shims | **not mentioned** | **B — KEEP AS INSIGHT** | HuntMCP's `curl-rl.sh` solves it by convention; shims solve it structurally (§17 M2) |
| Negative-control benchmark corpus | B → F, LEARN | **B — INVESTIGATE** | `benchmarks.md` is stricter methodologically; the *corpus shape* (15/35 negative, in-process, injected `ScanFunc`) is the transferable part |
| Resource-aware admission | B → C | **G — DEFER** | Standard practice; cost (`budget_guard`) is HuntMCP's binding axis, not RAM |
| Hypothesis "graph" | implied graph | **REJECT** | It is a map. HuntMCP's `chainer` is the graph |
| Typed abort reasons | B, LEARN | **B — KEEP AS INSIGHT** | Cheap; matters for benchmark reproducibility |

## 20.3 The one place where the comparison genuinely bites

Both systems have **two evidence paths with different integrity properties, and the strong path is gated
behind confirmation:**

| | Xalgorix | HuntMCP |
|---|---|---|
| **Captured path** | `verify_*` → ledger `Evidence{Request, Response}` | `run_intervention` → `cem_trials{request_evidence_hash, response_evidence_hash, oracle_hit}` |
| **Gate on captured path** | Only runs when the model invokes a `verify_*` tool | `_confirmed_or_error` — the finding must already be CONFIRMED |
| **Narrated path** | `report_vulnerability(exploitation_proof=str)` | `case_store.add_evidence(content=str)` — hashed *after* the model types it |
| **What the hash proves** | n/a | Tamper-evidence, **not** provenance |

**This is the finding worth carrying forward.** HuntMCP's hashing makes evidence *immutable once
recorded*; it does not make it *attributable to an observation*. A model-authored string that is
SHA-256'd is still a model-authored string. The Xalgorix comparison earns its keep by making that
distinction visible — and by showing that the same gap exists in both systems, at the same seam, for the
same reason.

---

# 21. Second-Order Lessons

Derived from evidence that survived review, not from the first report's list.

**L-A. An oracle contract is an architectural boundary, and its expressiveness sets the ceiling on what
can be machine-confirmed.**
`SuccessSignature` accepts only `FetchResult`. That single type decision determines that browser-execution
and OOB-callback observations can never be machine-verdicted by CEM, no matter how good the verdict logic
is. Xalgorix hit the same wall and solved it by writing seven bespoke Go oracles instead of one contract.
Neither approach is obviously right; the lesson is that **the oracle's input type is the decision that
matters most**, and it is easy to pin too narrowly during a Phase-1 scope reduction.

**L-B. Hashing evidence proves integrity, not provenance.**
Both systems content-address evidence. Neither binds it to the tool invocation that produced it. The
missing primitive is not a hash — it is a **capture point**: a place where tool output becomes evidence
without passing through the model. `cem_trials` has this; `add_evidence(content=str)` does not.

**L-C. A "planned program" in commit labels is stronger evidence of intent and weaker evidence of
trajectory than organic drift.**
The P1/P2 labels prove Xalgorix meant to build the ledger. The six subsequent days of prompt work prove
nothing about whether it will continue. **Reading direction-of-travel from a four-day burst is
extrapolation.** Applies symmetrically to HuntMCP's own phase plans.

**L-D. Enforcement placed outside the agent survives the agent.**
HuntMCP's `scope_gate_hook.py` blocks at the harness layer; Xalgorix's rate-limit shims block at the
process layer. Both are enforcement the model cannot argue with. Xalgorix's scope guard, by contrast,
lives *inside* the loop and speaks to the model in prose — and is correspondingly advisory. **Where a
control lives determines whether it is a guarantee or a suggestion.**

**L-E. An over-eager guard is a failure mode too.**
Direct runtime evidence from this session: HuntMCP's scope hook blocked a benign inline Python snippet by
misreading `json.load` as a hostname. A gate that fires on non-targets trains operators to route around
it. Precision matters in both directions.

**L-F. Truncation at the persistence boundary silently destroys the audit trail.**
Xalgorix truncates event output to 500 chars *at save time*. Nothing warns; the log looks complete. Any
system intending its event log to serve as evidence must decide truncation policy explicitly, not
incidentally.

**L-G. A completeness metric needs an anti-gaming clause or it will be gamed.**
Xalgorix's depth ratio requires ≥2 of 3 categories non-zero *specifically* to stop dirbusting inflation.
The clause is more instructive than the metric.

**L-H. "Independent" verification requires environment isolation, not just context isolation.**
A fresh conversation sharing a logged-in browser is not independent. This is the sharpest single
correction the Xalgorix study offers to anyone building a verifier.

---

# 22. High-Impact Findings

Findings material enough to warrant master-roadmap attention. Four, ranked.

**H1 — HuntMCP's evidence integrity has a provenance gap on the discovery path, not on the CEM path.**
`cem_trials` captures request/response hashes machine-side. `case_store.add_evidence(content=str)` hashes
whatever the model typed. The strong path is gated behind `_confirmed_or_error`. Confidence: **high**
(read from both schemas and the MCP wiring). Impact: touches every finding that reaches a report.

**H2 — `SuccessSignature`'s oracle contract cannot express browser-execution or OOB-callback
observations.** Xalgorix demonstrates both as working, deterministic oracles. Two of its seven confirmers
are structurally inexpressible in CEM's current contract. Confidence: **high** (both contracts read).
Impact: bounds which vulnerability classes CEM can ever machine-verdict.

**H3 — The endpoint × class(× role) coverage matrix is genuinely absent from HuntMCP.** It is the one
Xalgorix primitive with no HuntMCP equivalent, it is cheap, and it answers "are we done?" with a
measurable object rather than an agent's opinion. Confidence: **high**. Impact: moderate but broad.

**H4 — Scan-identification headers are absent from HuntMCP.** Bug-bounty programs commonly require an
identifying header; Xalgorix implements it with a correct destination boundary (target-only, never
provider/notification). Confidence: **high**. Impact: narrow, but it is an engagement-compliance item, not
a nice-to-have.

**Explicitly NOT high-impact, contrary to the first report:** the hypothesis ledger (HuntMCP has one),
evidence content-addressing (HuntMCP has it), the three-valued verdict (HuntMCP has it and more), scope
enforcement (HuntMCP is far ahead), continuous diffing (HuntMCP is ahead), and the CEM-equivalence
hypothesis as an *architectural* proposition (§8).

---

# 23. Master-Roadmap Implications

## 23.1 What the evidence supports

The first report positioned Xalgorix as a system HuntMCP should learn substantially from. After
validation, the honest position is narrower:

> **Xalgorix independently converged on several of HuntMCP's existing design decisions, is behind HuntMCP
> on scope enforcement, memory, learning, continuous diffing, evidence machinery, and verdict rigour, and
> is ahead on exactly two things: oracle expressiveness for non-HTTP observations, and a measurable
> coverage object. Plus two operational items HuntMCP lacks (scan-identification headers, process-level
> rate-limit shims).**

## 23.2 Outcome classification

Against the six options in the brief:

- ❌ **(5) Architectural reconsideration** — not supported. The first report's CEM-equivalence framing was
  the only argument for it, and it does not survive §8.
- ❌ **(1) No roadmap change** — too strong. H2, H3, and H4 are real, verified gaps.
- ❌ **(4) Dependency adjustment** — nothing found requires it.
- ✅ **(6) Research-only follow-up** — for H1 and H2.
- ✅ **(3) New work item** — at most, for H3 and H4, both small and self-contained.
- ✅ **(2) Small amendment** — the direction-of-travel and CEM-equivalence framings in
  `XALGORIX-RESEARCH.md` must be corrected before that document is used as an input.

**Composite verdict: (6) + (3), with (2) as a precondition.**

## 23.3 What must be corrected before `XALGORIX-RESEARCH.md` is used downstream

1. §1 / §21 / §26 U1 — the direction-of-travel claim (§16 here).
2. §1 / §24 L1 / §26 U1 — the CEM-equivalence claim, downgrade to analogy (§8 here).
3. §16 F2 / §19.1 — "evidence narrated" → the two-path seam (§11 here).
4. §23 rows for hypothesis ledger, evidence binding, verification gate — all three understated HuntMCP
   (§20 here).
5. §24 L2 — `audit_log` is the wrong store (§20 here).
6. §22 — the MAPTA/XBOW juxtaposition needs the reproducibility caveat (§15 here).

---

# 24. Decision Table

| Finding | Xalgorix Evidence | Review Verdict | HuntMCP Current State | Impact | Confidence | Action |
|---|---|---|---|---|---|---|
| Two-path evidence integrity; strong path gated behind confirmation | `verify_sqli.go:183` captured vs `reporting.go:292` narrated | **A (corrected form)** | Same structure: `cem_trials` hashes vs `add_evidence(content=str)`; strong path behind `_confirmed_or_error` | High | High | **INVESTIGATE** |
| `SuccessSignature` cannot express browser/OOB oracles | `xssverify.go`, `oob_verify.go` vs `cem_engine.py:309` | **A** | `SuccessSignature` matches `FetchResult` only | High | High | **INVESTIGATE** |
| Endpoint × class(× role) coverage matrix | `hooks.go` `EndpointClassCoverage` + `testDepthRatio` | **A** | Absent | Medium-high | High | **INVESTIGATE** |
| Scan-identification headers, target-only | `internal/scanheaders` | **A (missed by pass 1)** | Absent | Medium | High | **INVESTIGATE** |
| Process-level rate-limit shims | `terminal.go:500–530` + `sitecustomize.py` | **A (missed)** | `curl-rl.sh` by convention + hook | Low-medium | High | **KEEP AS INSIGHT** |
| Verifier needs environment isolation, not just context isolation | `verifier.go` shares `ScanContext` | **A** | `second-opinion-mcp` — isolation properties unexamined here | Medium | High | **KEEP AS INSIGHT** |
| Restricted reviewer cannot record what it learns | Verifier lacks `report_vulnerability`/`record_hypothesis` | **A** | `second-opinion-mcp` returns a review only | Low-medium | Medium | **KEEP AS INSIGHT** |
| Three-valued verdict, rejection = disproof | `verifier.go:70–95` | **A** | `classify()` + `probabilistic` + `interacting` — HuntMCP has more | None | High | **NO CHANGE** |
| Durable hypothesis object | `scanctx/ledger.go` | **A** | `case_store` hypotheses/findings/evidence/experiments | None | High | **NO CHANGE** |
| Content-addressed evidence | Ledger `Evidence{Request,Response}` | **A** | SHA-256 content store + `cem_trials` hashes | None | High | **NO CHANGE** |
| Enforced engagement scope | Absent in Xalgorix (§12) | **A** | 3-layer deny-by-default allowlist | None (HuntMCP ahead) | High | **NO CHANGE** |
| Cross-run memory / learning | Absent in Xalgorix | **A** | `memory-mcp`/`writeup-mcp`/`lessons-mcp` | None (ahead) | High | **NO CHANGE** |
| Continuous = cron | `scheduler.go:283` | **A** | `watch-mcp` diffing | None (ahead) | High | **NO CHANGE** |
| Negative-control benchmark corpus shape | 15/35, in-process, injected `ScanFunc` | **A** | `benchmarks.md` stricter; corpus shape differs | Medium | High | **INVESTIGATE** |
| Typed abort reasons | `Event.Aborted`/`AbortReason` | **A** | Partial | Low-medium | High | **KEEP AS INSIGHT** |
| Canonical assistant-turn rewriting | `agent.go:665` | **A** | N/A (MCP native tool calls) | Low | High | **KEEP AS INSIGHT** |
| Resource-aware admission control | `internal/resources` | **G (downgraded)** | `budget_guard.py` on cost axis | Low | High | **DEFER** |
| "Direction of travel: converging on the ledger" | Sept 5–10 commit record | **D — wrong** | — | None | High | **REJECT** |
| "Confirmation **is** CEM with one condition" | §8 analysis | **B/F — analogy only** | — | Superseded by H2 | High | **REJECT as stated** |
| Bind reports to `audit_log` entries | `audit_log.py` stores no output | **D — wrong mechanism** | Correct store is `case_store`/`cem_trials` | — | High | **REJECT** |
| Xalgorix ledger as a "graph" | No inter-hypothesis edges | **G** | `chainer-mcp` is the real DAG | None | High | **REJECT** |
| XBOW ~70/104 vs MAPTA 76.9% | Harness untracked (`51523a2`) | **F** | — | None | High | **REJECT** |
| 22-phase = prompt, not architecture | §5 | **A** | HuntMCP uses modular skills | None | High | **NO CHANGE** (validating) |
| Xalgorix secure-SDLC CI posture | gosec/semgrep/govulncheck/`-race` | **A (missed)** | HuntMCP CI: ruff, py_compile, bash -n | Low-medium | High | **KEEP AS INSIGHT** |

---

# 25. Final Verdict

`XALGORIX-RESEARCH.md` is **usable as a master-roadmap input after six specific corrections** (§23.3).
Its Xalgorix reconstruction is sound; its HuntMCP comparison is not, and the errors run consistently in
one direction — understating HuntMCP.

---

# FINAL VERDICT — CAN WE TRUST XALGORIX-RESEARCH?

**1. What percentage/category of important claims are verified?**
Of 25 adjudicated high-impact claims: **15 fully verified (60%)**, **4 partially verified (16%)**,
**4 materially wrong (16%)**, **3 overstated but directionally right (12%)**, **2 correct-but-minor**
(overlapping tags). Critically, the split is not random: **the Xalgorix-reconstruction claims are ~90%
verified; the HuntMCP-comparison claims are ~50% wrong.**

**2. The 3–5 most trustworthy findings**
- The 22-phase methodology is a prompt constant plus a monotonic keyword-inference progress bar (§5).
- Xalgorix has no engagement-scope enforcement in an active scan — verified by exhaustive call-site trace
  across all 13 guard sites (§12).
- Pause kills the agent; resume is a new agent plus a text briefing; continuous mode is cron with no
  cross-run state (§9, §10).
- The verifier is conversation-isolated but not environment-isolated, and its verdict is model-narrated
  while its observations are real (§6).
- The benchmark's 15/35 negative controls, precision scorecard line, and runtime benchmark-isolation guard
  are the project's strongest methodological assets (§15.4).

**3. The 3–5 most questionable findings**
- "Nearly every feature commit since 09-01 routes evidence into the ledger" — **false** (§16).
- "Confirmation **is** CEM with one condition" — analogy promoted to headline (§8).
- "Evidence is narrated, not captured" — blanket claim; the captured path exists (§11).
- The HuntMCP comparison rows for hypothesis ledger, evidence binding, and verification gating (§20).
- The MAPTA/XBOW juxtaposition (§15.3).

**4. What did the first research get materially wrong?**
Four things. (a) The direction-of-travel claim. (b) The claim that `audit_log.py` could serve as the
evidence-binding store — it stores no output. (c) The classification of the event log as an audit trail —
output is truncated to 500 characters. (d) Most consequentially, it compared Xalgorix's implementation
against HuntMCP's *planning documents*, never opening `cem_engine.py`, `case_store.py`, or
`case-mcp/server.py`, and therefore systematically understated HuntMCP.

**5. What did it completely miss?**
Ten items (§17). The three that matter: `internal/scanheaders` (authorized-scan identification headers
with a correct destination boundary); process-level rate-limit enforcement via executable curl/wget shims
and a Python `sitecustomize` monkeypatch; and Xalgorix's mature secure-SDLC CI (gosec, semgrep OWASP
packs, govulncheck, `-race`) — whose absence made the security section read as an indictment of
carelessness rather than a description of a deliberate trade-off.

**6. Highest potential impact on HuntMCP?**
**H1 — the provenance gap on the discovery path.** `cem_trials` captures machine-side request/response
hashes; `case_store.add_evidence(content=str)` hashes a string the model typed. Hashing proves
tamper-evidence, not provenance. The strong path is gated behind `_confirmed_or_error`, so the evidence
that reaches most reports comes from the weak one. Xalgorix's issue #640 is the empirical demonstration of
what that failure looks like in production.

**7. Does the CEM↔Xalgorix-verifier equivalence survive scrutiny?**
**Partially — as a structural analogy, not a formal equivalence.** The arm mapping is real, and
`classify()` would return `necessary` exactly where `verify_sqli` returns confirmed. But: CEM's entry
contract requires an already-reproducing finding (`determinism_gate` all-k HIT, plus
`_confirmed_or_error`), while Xalgorix's confirmers run pre-confirmation; `SuccessSignature` cannot
express 2 of the 7 confirmers' oracles; and `classify()`'s 2-arm binary form loses `verify_sqli`'s
break/recover composite and `authz_matrix`'s three-identity differential. The claim should be replaced by
its narrow, defensible residue: **CEM's verdict machinery already dominates Xalgorix's; CEM's oracle
contract does not.**

**8. Does Xalgorix have persistent investigation state?**
**Partially — more than the first report's headline allowed, less than its marketing claims.** Findings,
notes, and the hypothesis ledger genuinely persist and the ledger genuinely reloads on resume. The
conversation, the ~70 `ScanState` counters, the coverage matrix, and all runtime state do not. And
`formatResumeBriefing` does not include the ledger, so the best-preserved state is not surfaced to the
resumed agent. **Classification: C (restart-with-summary) with a real but unexploited B component.**

**9. Is its continuous mode truly continuous intelligence?**
**No.** Continuous *execution* — yes, competently (startup catch-up, per-schedule panic containment,
embedded tzdata). Continuous *intelligence* — no. No baseline, no delta, no new/fixed/regressed
classification, and deduplication explicitly forbidden across runs in three separate places.

**10. Is its proof/evidence model materially weaker than HuntMCP's?**
**Yes, but by less than the first report implied, and for a more precise reason.** Both have two paths.
HuntMCP is ahead on the strong path — SHA-256 content-addressing, per-trial `request_evidence_hash` /
`response_evidence_hash`, a deterministic `oracle_hit`, and a persisted `cem_verdicts` table — where
Xalgorix has bounded free-text `Request`/`Response` strings in the ledger. HuntMCP is also ahead on
verdict rigour (k-replication, determinism gate, `inconclusive` on mixed). Xalgorix is ahead on **oracle
reach**: it can machine-verdict browser execution and OOB callbacks, which HuntMCP's oracle contract
cannot express. And both share the same weak path, at the same seam.

**11. What should NOT be carried into the master roadmap?**
The direction-of-travel/convergence narrative; "confirmation is CEM" as an architectural proposition; the
`audit_log` evidence-binding mechanism; the "hypothesis graph" framing (it is a map — HuntMCP's `chainer`
is the graph); the MAPTA/XBOW comparison; the ADAPT ratings on hypothesis ledger, evidence
content-addressing, and three-valued verdicts (all already present in HuntMCP); and resource-aware
admission control as a priority item.

**12. What SHOULD be carried forward?**
Four verified items — H1 (provenance gap on the discovery path), H2 (`SuccessSignature` oracle
expressiveness), H3 (endpoint × class × role coverage matrix), H4 (scan-identification headers) — plus
five insights that need no work item: environment isolation is required for genuine verification;
enforcement placed outside the agent survives the agent; hashing proves integrity, not provenance;
truncation at the persistence boundary silently destroys an audit trail; and a completeness metric needs
an explicit anti-gaming clause.

**13. Does Xalgorix research justify changing the master roadmap?**
**Marginally, and far less than the first report implied.** It justifies research-only follow-up on two
questions and at most two small, self-contained work items. It does **not** justify architectural
reconsideration.

**14. If yes, exactly what kind of change is justified?**
**Outcome (6) research-only follow-up** for H1 and H2 — both are questions about existing HuntMCP
contracts (`case_store.add_evidence`'s provenance, `SuccessSignature`'s input type), not new subsystems.
**Outcome (3) new work item**, small, for H3 and H4 — a coverage object and an engagement-header
capability, both self-contained. **Outcome (2) small amendment** is a *precondition*: the six corrections
in §23.3 must be applied to `XALGORIX-RESEARCH.md` before it is used as a roadmap input, or it will import
one false claim (direction of travel), one overpromoted hypothesis (CEM equivalence), and three
understatements of HuntMCP's existing capability.

**15. If no, why not?**
Not applicable — but the closest thing to a "no" is worth stating plainly: **the single largest finding of
this review is that HuntMCP is further along than the first report portrayed.** `cem_engine.py` implements
C1–C6 with a determinism gate, three-to-five-valued verdicts, ddmin minimization, interaction detection,
and content-addressed per-trial evidence. `case_store.py` implements the hypothesis lifecycle. Scope is
enforced deny-by-default at three layers including a harness hook. Most of what Xalgorix suggests HuntMCP
should build, HuntMCP has already built — frequently better. The correct posture toward Xalgorix is
**validation of existing direction**, not redirection.

---

**End of adversarial review.**

Created: `XALGORIX-REVIEW.md`. Nothing else was written, modified, or committed.
Recommendations are review classifications only — not implementation phases, not authorization.
