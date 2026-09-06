# XYZ.md — Counterfactual Evidence Minimization for Black-Box Security Findings

**A first-principles proposal for HuntMCP's next capability layer**
Status: proposal (concept + architecture + phased plan) — post adversarial review + Phase-1 trustworthiness refinement
Optimizes for: **triager trust / acceptance rate** (chosen priority)
Dependency budget: **moderate** (small pure-Python libs; no heavy ML)

> Central thesis (unchanged): HuntMCP should become a **proof / causal-validation engine**, not merely another
> discovery-throughput engine. The scarce good in 2026 is not *finding* a bug — LLMs flood that — it is
> **proving** one: minimal, provably-necessary, confounder-controlled, hard-to-dismiss evidence.

**End-state architecture this roadmap builds toward:**
`HuntMCP autonomous hunting` + `XBOW-class publicly-disclosed capability baseline` + `independent validation` +
`CEM (counterfactual evidence minimization)` + `causal/evidence minimization` + `variant discovery` +
`knowledge feedback` — with **CEM as the core research differentiator**. Discovery breadth is table stakes we
will match (Phase 2); CEM is the axis we win on.

---

## 0. What this is (and what it is deliberately not)

The core innovation is a **mechanism**, not a platform: **Counterfactual Evidence Minimization (CEM)**.

Given an **already independently-confirmed** finding, CEM answers three questions that decide whether a triager
accepts it:
1. **Which tested conditions are actually load-bearing?** (necessity — but-for / NESS-style)
2. **What is the smallest reproducer?** (minimization — delta debugging over the condition space)
3. **Is the causal conclusion even valid, given nondeterminism and confounders?** (a first-class validity gate)

It emits a **Triager-Proof Bundle**: the minimal condition set(s), the intervention matrix with replication
counts, the controlled confounders, the inconclusive experiments, the minimal PoC, and an explicit
validity/confidence label — all with a complete audit trail.

**Not in the core mechanism (later roadmap phases, clearly marked):** a full autonomous "digital twin," a
planning/orchestration layer driven by a graph, autonomous condition discovery from scratch, autonomous variant
hunting, and XBOW-class discovery-breadth expansion. Those are real and on the roadmap (§5) — they are just not
what Phase 1 proves. CEM stands on its own and delivers value on confirmed findings without any of them.

The supporting substrate (an **evidence-linked observed causal graph**, §3) is exactly that — supporting. It is
**not** claimed to be a Structural Causal Model.

---

## 1. Novelty audit (three honest buckets)

Rule applied: never claim "nobody has done this." Separate what exists, what we recombine, and the narrow
mechanisms we defend as (to our knowledge) underexplored.

### 1.1 Prior art we build ON (existing, cited, not claimed)
- **Delta debugging / test-case minimization** — Zeller & Hildebrandt `ddmin`; C-Reduce, HDD, Perses, ProbDD;
  `DDMIN*` iteration; **validity-preserving DD**; and **DD under flaky/nondeterministic tests** (2026). PoC
  minimization in CEM *is* delta debugging applied to a finding's condition space. Not new; reused.
- **Halpern–Pearl actual causality** — an actual cause is a *minimal sufficient cause* (AC3 minimality); the
  **NESS test** (Necessary Element of a Sufficient Set) and **minimal cut sets** (fault-tree analysis) are the
  formal frame for §2.3's *multiple minimal condition sets*. We **approximate** this empirically over a
  black-box target; we do not build or identify a true causal model.
- **Metamorphic security testing (MST-wi)** — metamorphic relations for security test *input generation* and
  the oracle problem. Adjacent, but aimed at *finding* bugs, not minimizing a confirmed one into evidence.
- **Attack graphs** (CVE/threat-report-derived, hypothetical) and **dynamic evidence graphs** (source-code
  vuln localization). Both are graphs of security facts; neither is a counterfactual-necessity engine over a
  live black-box finding.
- **XBOW-class agentic VAPT** — coordinator/solver swarms, model alloys, headless-browser + OOB harnesses,
  exploit-validation pipelines. They confirm *that* an exploit fires; they do not derive *which conditions are
  necessary*, minimal sets, or variants. We will adopt their discovery breadth (Phase 2) and differentiate on
  CEM.

### 1.2 Novel synthesis (recombination — we claim integration, not invention)
Applying **NESS-style minimal-sufficient-set reasoning + delta-debugging minimization** to the **condition
space of a live black-box web finding**, wrapped in a **determinism-gated confounder-control protocol**, and
packaged as **autonomous triager evidence** inside a bounty workflow with scope/budget/audit guards. Each
ingredient exists; this specific composition, for this purpose, is where the contribution sits.

### 1.3 Genuinely novel mechanisms (defensible, "to our knowledge underexplored")
1. **Determinism-gated, confounder-pinned counterfactual protocol** for black-box web findings, with an
   explicit **`inconclusive`** verdict class (§2.5). The closest cousins — validity-preserving DD and DD for
   flaky tests — handle nondeterminism for program inputs, not for *session/CSRF/cache/rate-limit/time* state
   in HTTP security testing.
2. **Multiple minimal condition sets / causal cut sets as a finding's signature** (§2.3), replacing the naive
   single "root cause," including interaction-only conditions.
3. **Counterfactual variant discovery** (§2.7): a perturbation that *keeps the capability alive under a
   different condition* is an adjacent, often higher-severity finding — a byproduct of necessity testing.
   (Roadmap Phase 4; not Phase 1.)
4. **Structural differentiation evidence** for de-duplication (§2.6) — reframed from the earlier
   "non-duplication proof," which was indefensible. (Roadmap Phase 3+; not Phase 1.)

---

## 2. The core mechanism: Counterfactual Evidence Minimization

### 2.1 The condition model
A **condition** is any independently-perturbable factor present in the reproducing request/flow. Categories:
- **Identity/authz:** auth state (unauth / user-A / user-B / low-priv / admin), object ownership, role, tenant.
- **Request shape:** endpoint, method, a specific parameter/header/body field, content-type, a specific value.
- **Sequence/state:** a prior request that set server-side state, ordering, a consumed one-time token.
- **Environment:** cache state, rate-limit window, timing/TTL, concurrency.

In **Phase 1, candidate conditions are supplied explicitly** to CEM (by the human/agent that confirmed the
finding). Autonomous extraction of conditions from the `audit_log` trace is a later phase (§5). CEM never
perturbs a condition it cannot actually toggle and observe.

### 2.2 Counterfactual necessity via controlled intervention
For a condition `C`, CEM issues the reproducer with **only `C` perturbed** (a do-intervention) and everything
else pinned (§2.5), replicates both arms, and classifies with one of these verdicts:
- **`necessary`** — perturbing `C` reliably kills the capability across replicated arms (but-for necessity
  holds under the held-fixed controls).
- **`apparently_not_necessary`** — capability survives perturbation across replicated arms; `C` can be dropped
  from the PoC. (Named "apparently" on purpose: it is a statement about the *tested* conditions, not proof of
  global irrelevance.)
- **`interacting`** — `C` matters only jointly with some other condition(s) (§2.3).
- **`inconclusive`** — controls could not isolate `C` (nondeterminism / uncontrolled confounder); **no causal
  claim is emitted.**
- **`probabilistic`** — for race/TOCTOU mechanisms where per-request necessity is ill-defined; reported as a
  success rate under controlled parallelism (§2.5.5), never as deterministic necessity.

Every verdict is scoped to the tested experimental design ("under held-fixed set H, k replications").

### 2.3 Multiple minimal condition sets (not a single root cause)
Real findings often have **several minimal sufficient condition sets** (NESS / minimal-cut-set structure) and
**interaction-only** conditions. CEM reports a **family** of minimal sets, not a scalar root cause:
- A **reproducing configuration** is a subset of present conditions that still triggers the capability.
- CEM searches for **1-minimal sets** (no element removable) via delta debugging, then perturbs to surface
  **alternate** minimal sets and **AND-interactions** (conditions necessary only in combination).
- Output is the set family `{ MSC_1, MSC_2, ... }` plus flagged interactions, with a stated **completeness
  bound** ("k sets found; search bounded at N trials by `budget_guard`"). Full boolean minimization over
  conditions is exponential; this is an explicit approximation, and says so.
- Feeds `case-mcp`'s existing `group_root_cause` as a *set family* rather than a single cause.

Phase 1 supports multiple minimal sets and interaction handling **where discoverable within budget**; it does
not promise exhaustive enumeration.

### 2.4 PoC minimization (delta debugging, explicitly) — runs AFTER causal evidence
Minimizing the PoC = running `ddmin` over the condition/step set with the "interestingness" test = "capability
still fires under §2.5 controls." Minimization runs **after** the causal necessity evidence is established, so
the minimal PoC is a *consequence* of the verdicts, not a substitute for them. The deliverable is the
**1-minimal reproducer**, re-validated against the determinism gate before emission (guards against a DD local
optimum dropping a needed step).

### 2.5 Confounders & nondeterminism (the validity protocol — the scientific crux, and a Phase-1 requirement)
A counterfactual conclusion is worthless if the baseline is nondeterministic or a hidden variable moved. This
protocol is **part of the core mechanism and required in Phase 1** — without it the system can confuse
application nondeterminism or state changes with causal necessity.

1. **Determinism / stability gate (run first).** Re-run the *unperturbed* reproducer `k` times (default 5),
   appropriately spaced. If it does not reproduce consistently, the finding is labeled **nondeterministic**:
   necessity testing is suppressed, and race/time/state hypotheses are raised instead of necessity claims.
2. **Pin the confounders (held-fixed set), where feasible.** For every trial, hold identical or explicitly
   reset: session identity & cookie freshness, **CSRF/anti-forgery token** (mint fresh per trial identically),
   auth-token expiry, **request ordering/sequence**, **cache key / cache state** (cache-buster or reset),
   **rate-limit window** (space requests; detect throttling contamination), **time/TTL** effects, server-side
   counters / one-time tokens, concurrency level. Where a confounder cannot be controlled, the affected
   experiment is marked `inconclusive` rather than concluded.
3. **One variable at a time.** Exactly one condition perturbed per trial; all else pinned. Multi-perturbation
   only for confirmed interactions (§2.3), and labeled as such.
4. **Replicated intervention arms.** Both the baseline arm and the perturbed arm are run `k` times; a
   `necessary` verdict requires *consistent* capability-absence in the perturbed arm, not a single miss
   (defends against a throttle/cache masking the bug).
5. **Race/TOCTOU carve-out.** For findings whose *mechanism is* nondeterminism, per-request "necessity" is
   ill-defined. CEM reports a **`probabilistic`** success rate under controlled parallelism (ties into the
   existing race-conditions skill / single-packet technique), never a deterministic necessity verdict.
6. **Explicit verdict labels + scope.** Every result carries a verdict from §2.2, the controls that were held,
   and `k`. No bare "necessary" is ever emitted, and every conclusion references its tested experimental scope.

### 2.6 Structural differentiation evidence (reframed from "non-duplication proof") — Phase 3+
A disclosed report may not expose its true causal conditions, so **non-duplication cannot be proven**. CEM
instead produces **differentiation evidence**: it extracts the *documented* endpoint/parameter/conditions from
`disclosed_reports.py`, compares them to *this* finding's minimal condition set(s), and emits a labeled
argument — "differs from documented report X in conditions {…}; **based on documented details only, not a proof
of independence**." A triager *aid*, explicitly bounded, never an absolute claim. Not in Phase 1.

### 2.7 Variant discovery (byproduct of necessity testing) — Phase 4
When perturbing `C` *keeps* the capability alive under a **different** value/state (e.g. auth user-A→unauth
still leaks), that is a new, usually higher-severity finding. Phase 1 will **record** such an incidental
observation if it falls out of a necessity trial, but **active/autonomous variant hunting is Phase 4** and is
explicitly excluded from Phase 1.

### 2.8 Output: the Triager-Proof Bundle
Per finding, the bundle contains exactly:
- **original baseline** (the confirmed reproducer as executed);
- **baseline replication results** (`k` runs, determinism/stability gate outcome);
- **intervention matrix** (each tested condition × perturbation → observed effect);
- **replication counts** (`k` per arm);
- **controlled / pinned conditions** (the held-fixed confounder set actually enforced);
- **observed confounders** (anything detected but not fully controllable);
- **inconclusive experiments** (with the reason each could not be concluded);
- **identified necessary conditions**;
- **minimal condition sets** (the MSC family + interactions, with completeness bound);
- **minimized reproduction / evidence** (the 1-minimal PoC);
- **complete audit trail** (`audit_log`-linked evidence for every trial).

Redacted via `redact.py`; a human-reviewed draft, never auto-submitted. (Signing / portable-replay packaging
is a formatting nicety, deliberately *not* a headline feature.)

---

## 3. Supporting substrate: an evidence-linked observed causal graph (NOT an SCM)

CEM needs somewhere to record conditions, interventions, and their observed effects. That store is a small
**observed causal graph**, and we are precise about its epistemic status:

- It is **evidence-linked and observed** — nodes are conditions/observations/findings; edges (`depends-on`,
  `enables`, `refutes`) are annotations over *executed* HTTP trials, each citing a real `audit_log` id.
- It is **progressively causalized** — edges start as `observed` correlations and are *promoted* to
  `depends-on` only after the §2.5 protocol supports a necessity/interaction verdict.
- It is **not** a Structural Causal Model: no identifiability guarantees, no latent-variable model, no
  do-calculus completeness. We approximate actual-causality reasoning empirically, and the doc says so.
- **Hard invariant (anti-hallucination):** no `depends-on`/`enables` edge without a citable `audit_log`
  observation. An edge asserted from imagined output is rejected at write time.

In Phase 1 this is a **table + adjacency records inside `case-mcp`**, not a graph server (§4). Graph algorithms
(`networkx`, pathfinding) are only introduced if/when the later chaining/graph phases (§5) are pursued.

---

## 4. Architecture (minimized — extend, don't multiply)

The complexity objection is honored: **no new MCP servers in the core.**

- **Extend `case-mcp`** (already has `log_hypothesis`, `add_evidence`, `log_experiment`, `create_finding`,
  `score_finding_confidence`, `group_root_cause`, `case_export`) with CEM tools:
  - `define_conditions(finding_id, conditions)` — register the supplied perturbable factors.
  - `determinism_gate(finding_id, k)` — replicated baseline stability check (§2.5.1).
  - `run_counterfactual(finding_id, condition_id, k)` — one controlled, replicated intervention (§2.2/§2.5).
  - `minimal_condition_sets(finding_id)` — DD search → MSC family + interactions (§2.3).
  - `minimize_poc(finding_id)` — 1-minimal reproducer, re-validated (§2.4).
  - `evidence_bundle(finding_id)` — assemble the §2.8 Triager-Proof Bundle.
  - *(Phase 3+)* `differentiation_evidence(finding_id, disclosed_ref)` — §2.6.
- **Reuse, don't rebuild:** `scope_guard` (every perturbation in-scope), `budget_guard` (cap the DD/perturbation
  search and replication counts), `audit_log` (record every trial + link edges), `redact.py` (bundle hygiene),
  the race-conditions skill (§2.5.5), `job_runtime.py` (a `k`-replication sweep can outlive a call timeout).
- **The intervention executor** is a thin shared helper (e.g. `mcp-servers/cem_intervention.py`) that re-issues
  a captured request with one condition mutated and confounders pinned — reusing the existing HTTP path,
  `browser-mcp` for JS-execution checks, `oob-mcp` for blind confirmation. No new protocol surface.
- **`report-agent`** gains a Triager-Proof Bundle section. Human-reviewed draft only.

New library footprint for the core: effectively **stdlib + `pydantic`** (typed condition/verdict schemas).
`networkx`, `cryptography` (signing), and any playbook DSL are **deferred** to the later phases and not required
to ship Phase 1 value.

---

## 5. Phased roadmap

### Phase 1 — Smallest **scientifically-trustworthy** end-to-end CEM (FIRST RELEASE GATE)
> Purpose to prove: *"Given a confirmed vulnerability and candidate conditions, HuntMCP can experimentally
> determine which tested conditions are necessary, which appear unnecessary, and which remain inconclusive,
> while detecting uncontrolled nondeterminism and producing reproducible evidence."*

The smallest *useful* experiment is not the smallest *trustworthy* one; the determinism gate and replicated
arms are core scientific mechanism, not later hardening.

**Phase 1 contains:**
1. an already independently-confirmed finding;
2. explicit candidate conditions supplied to CEM;
3. repeated identical baseline executions;
4. determinism / stability gate;
5. detection of obvious nondeterminism;
6. explicit handling / pinning of known confounders where feasible;
7. one-variable-at-a-time counterfactual interventions;
8. replicated intervention arms;
9. comparison of each perturbed arm against the baseline;
10. `necessary` / `apparently_not_necessary` / `inconclusive` verdicts (+ `interacting`, + `probabilistic` for races);
11. support for multiple minimal condition sets where discoverable within budget;
12. interaction-condition handling where feasible;
13. race / TOCTOU cases reported probabilistically, never as deterministic necessity;
14. delta-debugging-style PoC / evidence minimization **after** causal evidence;
15. a **Triager-Proof Bundle** with all §2.8 contents.

**Phase 1 does NOT contain:** autonomous graph planning; autonomous CEM condition discovery from scratch;
sophisticated attack-path planning; a new graph MCP server; a separate playbook MCP server; autonomous variant
hunting; large-scale self-expansion; complex ML; any unnecessary infrastructure.

**Phase 1 failure gates (release blockers — must ALL hold):**
- uncontrolled nondeterminism must **not** produce a `necessary` verdict;
- insufficient replication must **not** produce a `necessary` verdict;
- failed confounder control must produce `inconclusive` where appropriate;
- race / TOCTOU behavior must **not** be mislabeled as deterministic necessity;
- every causal conclusion must reference the tested experimental scope;
- **false-causal-conclusion-rate on the constructed benchmark (§6) must be zero before moving to Phase 2.**

### Phase 2 — XBOW-class autonomous hunting capability expansion
Expand discovery breadth toward the publicly-disclosed capability baseline of XBOW-class systems (coordinator /
parallel-solver breadth, model-alloy selection via the existing `model_gateway`, the headless-browser + OOB +
payload-hosting harness HuntMCP already partly has). This is the discovery axis we treat as table stakes —
built from publicly disclosed capabilities, not proprietary internals.

### Phase 3 — CEM integrated directly after autonomous finding validation
Wire CEM into the autonomous pipeline so that every independently-validated finding automatically flows into
the Phase-1 CEM mechanism, and add §2.6 differentiation evidence against `disclosed_reports.py`.

### Phase 4 — CEM-derived causal signatures driving variant discovery and future hunting
Use minimal-condition-set signatures to actively generate variants (§2.7) and to prioritize where future
hunting looks, feeding results back through the confirm→CEM loop.

### Phase 5 — Uncertainty / coverage-gap-driven experimentation and continuous learning
Uncertainty- and coverage-gap-driven experiment selection; `watch-mcp`-driven patch-bypass regression (re-run a
fixed finding's counterfactual conditions on target change); recurring-condition → scaffolded playbook via
`tool_gaps` (offline, `content_scanner`-checked, human-reviewed); an optional promoted observed-causal-graph +
executable falsifier-gated playbooks by **extending `chainer-mcp`** (not a new server). Only capabilities that
survive the §1 novelty audit are admitted here.

---

## 6. Evaluation & benchmark plan

The proposal is only credible if we can measure whether CEM draws **correct** causal conclusions and **avoids
false ones**. Two tracks.

### 6.1 Constructed testbed (ground truth known) — the Phase-1 gate
Build a small labelled app (or adapt OWASP Juice Shop / crAPI / VAmPI / PortSwigger-style labs) with planted
vulns whose true condition structure we control:
- **Known-necessary condition** (e.g. IDOR where auth *is* required) — CEM must label it `necessary`.
- **Known-unnecessary condition** (a param that looks relevant but isn't) — must be `apparently_not_necessary`
  and dropped from the minimal PoC.
- **Multiple minimal sets** (two independent paths to the same capability) — must recover ≥2 sets within budget.
- **Interaction-only condition** (matters only with another) — must be flagged `interacting`, not `necessary`.
- **Planted nondeterminism red herrings** (a cache/throttle that makes a stable bug *look* conditional, and a
  genuine race) — must be caught by the determinism gate and labeled `inconclusive` / `probabilistic`, **not**
  given a false necessity verdict. This directly exercises the Phase-1 failure gates.

### 6.2 Real-world track
Run CEM over a held-out set of HuntMCP's own **past confirmed findings**; measure PoC-step reduction and manual
agreement of the necessity verdicts by review.

### 6.3 Metrics
- **False-causal-conclusion rate** — % of nondeterminism/confounder red herrings that received a wrong
  necessity verdict. **This is the Phase-1 release gate: it must be zero on the constructed benchmark before
  Phase 2.**
- **Necessity accuracy** on constructed labs (precision/recall vs ground truth).
- **PoC minimality** — steps/conditions in minimal vs original reproducer.
- **Minimal-set recovery** — fraction of planted minimal sets and interactions found within budget.
- **Variant discovery yield** (Phase 4+) — planted variants surfaced per finding.
- **Triager acceptance (primary business metric)** — A/B: findings submitted with vs without the Triager-Proof
  Bundle; acceptance rate, time-to-triage, and duplicate/needs-more-info rate, on real submissions over time.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| **False causal conclusion from uncontrolled confounder** (the central scientific risk) | The §2.5 protocol in Phase 1; the `inconclusive` verdict; the §6.1 red-herring benchmark and the zero-false-causal-conclusion **release gate**. |
| Counterfactual/DD search burns budget | `budget_guard` caps on perturbations and replication `k`; DD is efficient; report search completeness rather than feign exhaustiveness. |
| State-changing perturbations cause harm | Human-in-loop gate on non-idempotent perturbations; default to read/GET-shaped controls; `scope_guard` on every trial. |
| Hallucinated edges/observations | Evidence-required write invariant (§3); edges without a real `audit_log` id are rejected. |
| Over-minimized PoC drops a needed step (DD local optimum) | `DDMIN*`-style re-iteration; re-validate the minimal PoC against the determinism gate before emission (§2.4). |
| Differentiation evidence over-read as proof | Hard-labeled "based on documented details, not a proof of independence" (§2.6); Phase 3+ only. |
| Novelty overclaim | §1 three-bucket audit; DD and actual-causality cited as the basis; no "nobody has done this." |
| Scope creep back into a platform in Phase 1 | Phase-1 exclusion list + failure gates; Phases 2–5 hold the breadth/autonomy/graph work explicitly. |

---

## 8. Positioning: match discovery, win on proof

XBOW-class systems optimize discovery throughput and stop at "the exploit fired." HuntMCP's roadmap **adopts
that discovery breadth** (Phase 2, from publicly disclosed capabilities) so it is not out-hunted — and then
**differentiates on CEM**: telling a triager *which conditions are necessary*, handing over a *minimal*
reproducer, and — critically — **gating every conclusion against nondeterminism**, the trust dimension the 2026
market is punishing. The combined stack is: autonomous hunting + XBOW-class breadth + independent validation +
CEM + causal/evidence minimization + variant discovery + knowledge feedback, with **CEM the core research
differentiator**. It is a proof engine bolted onto a competitive hunter, and proof is what's scarce.

---

## 9. What changed and why

### 9.1 From the first draft → adversarial-review revision
- **Reframed around Counterfactual Evidence Minimization (CEM); demoted "Digital Twin."** (#10, #1)
- **Dropped the "Structural Causal Model" claim** → evidence-linked observed / progressively-causalized graph,
  grounded honestly in Halpern–Pearl actual causality as an approximation. (#1)
- **"Non-duplication proof" → "structural differentiation evidence."** (#2)
- **Single "root cause" → multiple minimal condition sets / causal cut sets + interactions** (NESS / min-cut). (#3)
- **Added the confounder & nondeterminism validity protocol (§2.5) as the scientific crux.** (#4)
- **Architecture minimized: no new MCP servers in the core — extend `case-mcp` + a thin executor.** (#6)
- **Novelty re-audited into three explicit buckets; DD + actual causality cited; "nobody has done this" removed.** (#7)
- **Added a concrete evaluation plan with constructed ground-truth labs + a false-causal-conclusion-rate metric.** (#8)

### 9.2 This refinement → Phase-1 trustworthiness pass
- **Pulled the determinism gate and replicated intervention arms into Phase 1**; the full §2.5 protocol is now a
  Phase-1 requirement, not later hardening. Phase 1 is redefined as the *smallest scientifically-trustworthy*
  CEM, with an explicit 15-item content list, an exclusion list, a purpose-to-prove statement, and **explicit
  failure gates as the first release gate** (including zero false-causal-conclusion-rate on the benchmark).
- **Aligned verdict labels** across §2.2 / §2.5 / §2.8 / Phase 1 to `necessary` / `apparently_not_necessary` /
  `inconclusive` (+ `interacting`, + `probabilistic` for races).
- **Matched the Triager-Proof Bundle (§2.8) to the required 15-field spec.**
- **Re-slotted later phases and explicitly preserved the XBOW-class capability work as Phase 2** (not removed,
  not weakened); Phase 3 integrates CEM after autonomous validation; Phase 4 = causal-signature-driven variant
  discovery; Phase 5 = uncertainty/coverage-gap experimentation, regression, continuous learning, self-expansion.
- **Reframed §8** so XBOW-class discovery is part of the roadmap (match discovery, win on proof), and added the
  combined end-state architecture to the header and §8, keeping **CEM as the core differentiator**.
- **Consistency-checked** the executive thesis, architecture, Phase 1, benchmark, metrics, novelty claims,
  risks, and roadmap against each other; the false-causal-conclusion-rate gate now appears identically in the
  Phase-1 failure gates (§5), the benchmark (§6.1), the metrics (§6.3), and the risks (§7).
