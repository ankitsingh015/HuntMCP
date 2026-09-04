# INTELLIGENCE-ALLOCATION-MEMO.md — Research & Architecture Review (design only, no implementation)

Subject: A **future** security-aware intelligence-allocation layer for HuntMCP.
Status: research/design memo for review. **No code. No changes to [XYZ.md](XYZ.md) or [PHASE1-PLAN.md](PHASE1-PLAN.md).**
Constraint honored throughout: the objective is *"reduce unnecessary expensive reasoning while preserving or
improving security outcomes,"* **not** "make the system cheaper at any cost." Phase 1 (the trustworthy CEM
vertical slice) is untouched and remains the prerequisite.

---

## 1. Executive conclusion

Three honest claims up front:

1. **The routing idea, by itself, is largely prior art.** Cascades (FrugalGPT), learned routers (RouteLLM),
   uncertainty-gated escalation, and value-of-computation metareasoning are mature. "Frontier only when
   necessary" is a *textbook cascade*. Severity/uncertainty/cost/difficulty/info-gain routing are all
   established or trivial engineering instantiations. **We should not claim novelty for security-aware routing
   as such.**
2. **The one defensible, potentially-differentiated element is the CEM→amortization loop:** turning
   *experimentally-supported* causal/evidence signatures (Phase-1 CEM output) into reusable structured
   knowledge that lets future, structurally-similar experiments start from cheap deterministic interventions
   instead of re-invoking frontier reasoning. Even this sits inside the known *skill-reuse / computation-
   amortization* literature — so it is a **reasonable engineering combination with a research-worthy twist**,
   not a clean novelty.
3. **Therefore the right posture is engineering-with-measurement, not a novelty bet.** Build it as a
   quality-constrained efficiency layer, measure it against a frontier-heavy baseline on ground-truth targets,
   and let the CEM-reuse ablation decide whether the "twist" is real. The recommended sharp research question
   is **C** (CEM signatures reduce required expensive reasoning), framed inside vision **D**, with **B** as the
   control it must beat. Reject **A** (weak≈frontier) as the user already suspects — model capability has an
   irreducible component.

**Bottom line:** worth doing as a Phase-5 efficiency layer *only after* the autonomous baseline (Phase 2–3) and
CEM signatures (Phase 4) exist; start **passive measurement** earlier so the later decision is data-driven. Do
not build a router now.

---

## 2. Prior-art findings (with sources)

**Cascades / cost-aware serving.** FrugalGPT (cascade + quality estimator + stop judge, up to ~98% cost
reduction on some benchmarks); "Cluster, Route, Escalate" cascaded cost-aware serving; UCCI (calibrated
uncertainty for cost-optimal cascade routing).
- FrugalGPT (arXiv 2305.05176); [Cluster-Route-Escalate](https://arxiv.org/html/2606.27457); [UCCI](https://arxiv.org/html/2605.18796)

**Learned routing / hybrid selection.** RouteLLM (router learned from preference data; ~85% cost cut at ~95%
GPT-4 quality on MT-Bench); Hybrid LLM; cost-aware contrastive routing; Mixture-of-Models capability routing;
a 2026 survey organizing routers by *decision timing* (pre-request rules cheapest, at-inference cascades most
accurate, post-response retry as safety net).
- RouteLLM (arXiv 2406.18665); [Dynamic Model Routing & Cascading survey](https://arxiv.org/html/2603.04445v2); [Cost-Aware Contrastive Routing](https://arxiv.org/pdf/2508.12491); [Brick / Mixture-of-Models](https://arxiv.org/pdf/2606.13241)

**Uncertainty-based escalation / test-time compute.** Calibrated-confidence gates that escalate uncertain
answers; Plan-and-Budget; TRIAGE (metacognitive control under resource constraints); Uncertainty-Aware Budget
Allocation; "Resample or Reroute" budget-aware test-time selection; MUR momentum-uncertainty reasoning.
- [Plan-and-Budget](https://arxiv.org/pdf/2505.16122); [TRIAGE](https://arxiv.org/pdf/2605.13414); [Uncertainty-Aware Budget Allocation](https://arxiv.org/pdf/2605.26849); [Resample or Reroute](https://arxiv.org/pdf/2607.08665)

**Metareasoning / Value of Computation (the correct theory frame).** Russell & Wefald rational metareasoning;
Value of Computation; "Rational Metareasoning for LLMs" (2024). VOC directly formalizes *spend expensive
computation only when it is expected to change the decision* — exactly the question here.
- [Rational Metareasoning for LLMs](https://arxiv.org/pdf/2410.05563); [Adaptive Metareasoning for Bounded Rational Agents](http://rbr.cs.umass.edu/papers/SZijcaiAEGAP18.pdf)

**Mixture-of-Agents / multi-model allocation.** MoA, MoMA, MOSAIC scheduling, Uno-Orchestra parsimonious agent
routing.
- [MOSAIC](https://arxiv.org/html/2606.03014v1); [Uno-Orchestra](https://arxiv.org/pdf/2605.05007); [Generalized Routing survey](https://arxiv.org/html/2509.07571v1)

**Skill/knowledge reuse for efficiency (the home of the CEM-reuse idea).** "Skill Reuse as Compression in
Agentic RL"; SkillOS / Graph-of-Skills; program-based skill induction; agent-artifact reuse; KV-cache reuse /
ReCache; a survey of efficiency-guided agents. The common thesis: distill recurring expensive reasoning into
reusable procedural units to cut future LLM calls.
- [Skill Reuse as Compression](https://arxiv.org/pdf/2605.31509); [Externalization in LLM Agents review](https://arxiv.org/html/2604.08224v1); [Awesome-Efficient-Agents](https://github.com/yxf203/Awesome-Efficient-Agents)

**Security-specific allocation.** Pentest agents already do *stage-based model specialization* (background vs
reasoning-heavy vs long-context vs web routed to different LLMs) and report per-run costs (PentestGPT ~$1.11/
successful benchmark; HPTSA ~$4.39/run; AutoPentest ~$96/run; ARTEMIS ~$18/hr). PenExpert is an explicit hybrid
LLM–expert multi-agent framework.
- [PenExpert (ScienceDirect)](https://www.sciencedirect.com/science/article/abs/pii/S0957417426021937); [RAG-augmented LLM pentest benchmarking](https://www.sciencedirect.com/science/article/pii/S2667305326000566); [AI pentest agents 2026 catalog](https://appsecsanta.com/research/ai-pentesting-agents-2026)

---

## 3. What is generic vs potentially differentiated (the novelty challenge)

Direct answers to the user's challenge questions:

| Idea | Honest classification |
|---|---|
| Route by **severity** | Generic — severity is just the utility term in any EV/priority router. *Established / trivial.* |
| Route by **uncertainty** | **Established prior art** (calibrated-confidence escalation gates). |
| Route by **cost / expected value** | **Established prior art** (VOC/metareasoning; FrugalGPT; cost-aware routing). |
| Route by **experiment difficulty** | Established (query-difficulty routing). |
| Route by **information gain** | **Established** (VOC; info-gain action selection). |
| Route by **exploit-chain potential** | Reasonable engineering combination (a domain-specific utility term). Not novel, not obvious-trivial. |
| **CEM-derived knowledge reduces future reasoning** | **Potentially research-worthy / unclear — requires validation.** It is a domain instantiation of skill-reuse/amortization, but "experimentally-supported causal/evidence signatures over black-box security findings, feeding an allocation policy under a security-outcome constraint" is a specific composition we did not find pre-existing. Do **not** overclaim. |
| "**Frontier only when necessary**" | **Standard cascade.** Obvious. |

**Verdict:** as a whole, security-aware *routing* is **not sufficiently differentiated** — it is a domain
skin over solved techniques. The stronger formulation is to stop selling "routing" and sell the **amortization
of validated security reasoning**: the research bet is whether CEM signatures measurably shrink the frontier
reasoning budget *without* quality regression, and whether those signatures *transfer* across findings/targets.

---

## 4. Recommended research question

Ranked (honest):

| Formulation | Tech defensibility | Novelty potential | Measurability | Practical value | Prior-art risk |
|---|---|---|---|---|---|
| **A** weak≈frontier via orchestration | Low (irreducible capability gap) | Low | Med | Low | High (and likely false) |
| **B** security-aware routing preserves quality | High | **Low (generic)** | **High** | High | **High** |
| **C** CEM signatures reduce required expensive reasoning | High | **Highest here** | Med-High | Med | **Lowest** |
| **D** adaptive allocation optimizes outcome/compute via evidence+uncertainty+value+CEM | Med-High | Med | Med (broad) | **Highest** | Med |

**Recommendation:** adopt **D as the umbrella vision**, but commit the program to the **sharp, testable
question C**, using **B as the mandatory control baseline C must beat**. Reject A.
> Primary research question (C): *"Can experimentally-supported causal/evidence signatures from CEM measurably
> reduce the frontier-model reasoning required for repeated/related security experimentation, without
> degrading vulnerability-discovery quality?"*

---

## 5. Optimization objective (constrained, not scalarized)

Do **not** optimize raw tokens (they hide HTTP/tool cost and reward doing less). Frame as **constrained
optimization**: minimize cost **subject to a security-quality floor**, never a free tradeoff.

- **Primary metric:** *severity-weighted, unique, independently-validated finding yield per unit total cost*
  — `Σ(severity_weight × validated_unique_finding) / total_cost`, where `total_cost` includes tokens **and**
  HTTP/tool/wall-clock, not tokens alone.
- **Hard constraints (the floor):** high/critical recall ≥ frontier baseline − ε; false-positive rate ≤
  baseline; coverage (surface/class) ≥ baseline; independent-validation success ≥ baseline.
- **Secondary metrics:** frontier-model calls per validated finding; cost per high/critical finding; wall-clock
  per validated finding; HTTP requests per validated finding.

Formally: `max  yield/cost  s.t.  quality_vector ≥ baseline_floor`. Cost improvements are only admissible on the
**Pareto frontier that satisfies the floor**. A configuration that violates the floor is **infeasible**, not a
cheaper point on a curve.

---

## 6. Baseline experiment design

Four arms, everything else held identical (targets, scope, tools, prompts/task definitions, attack/request/time
budgets, validation rules, stopping criteria, seeds where applicable; run on **ground-truth targets with known
findings** so "missed finding" is measurable):

- **A. Frontier-heavy** — strong model broadly. The quality reference the floor is defined against.
- **B. Fixed mixed** — predetermined cheap/medium/frontier stage allocation (no adaptivity). The generic
  control.
- **C. Adaptive security-aware allocation** — model/tool/tier chosen from evidence & experiment state.
- **D. CEM-assisted adaptive** — C plus CEM-derived signatures influencing later experiment/model selection.

**Should D be separate or part of C?** **Separate arm.** The entire hypothesis is that CEM adds value; folding
it into C makes CEM's contribution unattributable. C-vs-D is the ablation that answers research question C.

**Measure:** the full quality vector (§7), the cost vector (tokens + HTTP + wall-clock + frontier-call count),
constraint satisfaction (pass/fail on the floor), and the efficiency-frontier position. Report per-arm and
per-vuln-class (to catch class bias, §9).

---

## 7. Quality constraints & the "failed optimization" policy

**Quality vector tracked:** valid findings; unique findings; high/critical findings; exploit success;
independent-validation success; false-positive rate; regression/missed-finding rate; coverage; attack-path
depth; exploit-chain discovery; variant discovery; triager acceptance (if available).

**Failed-efficiency definition (defensible policy):**
- **Hard fail (experiment rejected):** the adaptive arm **misses any high/critical finding that the frontier
  baseline found**, or exceeds the baseline false-positive rate. No cost saving redeems this. → *A 50% cost cut
  that drops a high-severity finding = FAIL, full stop.*
- **Soft / scored-separately (Pareto):** differences confined to medium/low findings, coverage, or depth are
  scored on the efficiency frontier, not auto-failed — but reported explicitly, never hidden inside an
  aggregate.
- Rationale: severity is asymmetric; a missed critical is a categorical failure of the tool's purpose, whereas
  a slightly shallower low-severity sweep is a legitimate tradeoff. Constraint for critical, tradeoff for
  trivial.

---

## 8. Future intelligence-allocation architecture

**The policy/plumbing separation the user prefers is correct — and is the central design principle.**
Security reasoning policy is auditable security logic; model/provider selection is ops plumbing. Coupling them
would make the security decision provider-dependent and untestable.

Proposed layering (added later, **without touching Phase 1**):
```
Experiment planner / HuntBrain
        │  emits: ExperimentRequest + decision features (§6 state), abstract tier request
        ▼
[NEW] Intelligence Allocation Policy   ← reads case-mcp/CEM state, budget_guard, dedupe, lessons
        │  decides: {deterministic | cheap | medium | strong | frontier} + escalate/stop
        ▼
model_gateway (UNCHANGED)              ← pure plumbing: tier → concrete provider/model
        ▼
provider APIs / local models
```
- The policy module is **provider-agnostic**: it emits an abstract *tier + decision*, never a model id.
  `model_gateway.py` stays exactly the config-driven plumbing it is today (it already separates selection from
  code via env — good foundation).
- **CEM is a knowledge *source* feeding the policy, not coupled to it.** The policy reads CEM signatures the
  same way it reads budget or dedupe state. CEM never imports a model provider; the policy never imports CEM's
  internals — it queries stored signatures.
- Placement: a **standalone `intelligence_allocation` policy module** invoked by the experiment planner, beside
  (not inside) `model_gateway`. This keeps it unit-testable in isolation and swappable.

---

## 9. CEM ↔ intelligence-allocation interaction (the important part)

**What to store (from Phase-1 CEM, unchanged terminology):** per finding — the minimal condition set family;
`apparently_not_necessary` conditions; per-condition intervention outcomes; the success_signature (oracle);
`determinism_status`; k and controls; verdict labels. All already produced by Phase-1 CEM.

**How it should affect routing:** for a *structurally-similar* future experiment, the policy can (a) skip
re-deriving conditions already labeled `apparently_not_necessary` on a matching signature, (b) run cheap
deterministic interventions first (reuse the executor), and (c) **invoke frontier reasoning only if the cheap
interventions disagree with the stored signature or the finding is novel.** This is where expensive reasoning
is amortized.

**Reliability & safety rules (non-negotiable):**
- CEM gives **experimentally-supported** verdicts, **not causal proof** — keep the Phase-1 labels; a reused
  signature lowers the *cost of confirming*, it never *replaces confirmation*. The oracle must still fire on
  the new finding before anything is reported.
- **Never reuse a signature whose `determinism_status` was NONDETERMINISTIC/`probabilistic` as a shortcut** —
  those are explicitly non-cacheable; target-side randomness makes the "necessity" un-reusable.
- **Revalidate on:** target change (via `watch-mcp` in later phases), a staleness TTL, any prior `inconclusive`
  flag, or a mismatch between cheap-intervention result and stored signature.
- **Staleness = missed-finding risk:** a patched/drifted target can make a cached signature wrong (false
  "already known / not-necessary" → skipped test → missed bug). Mitigation: signatures are *hints that must be
  re-confirmed cheaply*, never authoritative skips; the quality floor (§7) catches regressions in evaluation.
- **Aleatoric vs epistemic uncertainty (a genuine CEM synergy):** CEM's determinism gate tells you when
  uncertainty is *target-side* (aleatoric — escalating the model will not help; do not spend frontier tokens)
  vs *model-side* (epistemic — escalation may help). This is the one place CEM meaningfully sharpens allocation
  beyond generic uncertainty routing.

---

## 10. Failure modes & mitigations

| Failure mode | Mitigation |
|---|---|
| Cheap model **prematurely closes** a promising hypothesis | Severity-gated **minimum-effort floor**: a high-severity-potential hypothesis cannot be closed by a cheap tier without an escalation check. |
| Router **confuses uncertainty with difficulty** | Split **aleatoric (target nondeterminism → don't escalate model)** vs **epistemic (→ may escalate)** using CEM determinism signal. |
| **Repeated cheap attempts cost more** than one frontier call | Per-hypothesis **escalation budget cap**: once cheap spend reaches k× a strong call, force escalation or stop. |
| **Frontier escalation too late** | Severity-triggered fast-path: high/critical potential skips the cheap rungs. |
| **CEM knowledge stale** | TTL + revalidation + `watch-mcp` change triggers; signatures are re-confirmed hints, not skips. |
| CEM treats **nondeterminism as necessary** | Already prevented by Phase-1 determinism gate; non-deterministic signatures are non-cacheable. |
| Routing **biases toward easy vuln classes** | **Per-class coverage floor** in the quality vector; report per-class, not aggregate. |
| **Severity / info-gain / P(success) estimators wrong** | Treat estimates as inputs to a *conservative* policy; validate estimator calibration separately; never let an estimate alone suppress a test. |
| **Duplicate detector suppresses useful experiments** | Dedupe lowers priority, never hard-blocks a not-yet-confirmed novel angle; audit suppressed experiments. |
| **Exploit chains under-explored** (steps look individually low-value) | Chain-potential as a first-class utility term; evaluate attack-path depth + chain discovery in the floor. |
| **Token savings hide higher HTTP/tool cost** | Objective counts **total** cost (tokens + requests + wall-clock), never tokens alone. |
| **Lower cost = lower coverage** | Coverage is a hard constraint (§7), not a free variable. |
| **Model specialization → blind spots** | Cross-check: periodically run a frontier pass on a sample to detect systematic misses. |
| **Adaptive routing overfits the benchmark** | Held-out target set; never tune policy on the evaluation targets; report train/test split. |

---

## 11. Phase placement

**Recommendation: Phase 5** (the advanced uncertainty / coverage-gap / adaptive-learning phase), with **passive
measurement instrumentation started as early as Phase 2–3** and the CEM-reuse mechanism gated on **Phase 4**
producing signatures.

Reasoning:
- It **depends on** an autonomous baseline (Phase 2), CEM-in-hunting (Phase 3), and reusable causal signatures
  (Phase 4). It cannot precede them.
- It must **not** touch Phase 1 — no architectural reason to; doing so would risk the trustworthy CEM slice.
- **Split decision from action:** during Phases 2–4, log the §6 decision features + real per-stage cost/quality
  *without changing behavior* (cheap, non-invasive, keeps the hunting hot path unslowed — honoring the "CEM is
  post-validation, don't slow the hot path" constraint). Then in Phase 5, build the policy against real data and
  a real frontier-heavy baseline. **Measure early, decide late.**

---

## 12. Concrete next-step recommendation

**Do not build a router. Before anything:**
1. Ship Phase 1 and stabilize the autonomous baseline (Phases 2–3) — unchanged.
2. Stand up a **ground-truth benchmark target set** (known findings, incl. high/critical) so regression/misses
   are measurable and a frontier-heavy baseline is quantified.
3. Add **passive cost/feature instrumentation** (measurement-only) so allocation decisions can later be
   evaluated on real data — no behavior change, no hot-path slowdown.
4. Once Phase 4 emits CEM signatures, run the **A/B/C/D experiment (§6)** and let the C-vs-D ablation decide
   whether the CEM-reuse twist is real before committing to a policy.

Only if the data shows meaningful redundant frontier reasoning **and** the quality floor holds does the
allocation policy get built.

---

## 13. Open questions that must be experimentally answered

1. What fraction of frontier reasoning in a real hunt is actually **redundant / re-derivable** from prior
   signatures? (If small, the whole premise is weak.)
2. How often do CEM signatures **transfer** across findings and across targets? (Transfer rate is the crux of
   research question C.)
3. Does **target-side nondeterminism** (aleatoric) dominate enough that model escalation rarely helps — making
   the CEM determinism signal the higher-value lever than routing?
4. Can **uncertainty be calibrated** reliably in this domain (security oracles are sparse/expensive)?
5. Can **severity potential** be estimated *before* spending frontier reasoning, or only after? (If only after,
   severity-based routing is largely circular.)
6. What is the real **cost split** between tokens and HTTP/tool/wall-clock? (Determines whether token routing
   even matters.)
7. What is the **staleness half-life** of a CEM signature on an evolving target — how fast does reuse become a
   missed-finding risk?
8. Does adaptive allocation **degrade exploit-chain discovery** (the failure mode where individually-cheap
   steps hide a high-value chain)?

---

*Protect the existing HuntMCP finding capability. This memo proposes measurement and a gated experiment, not a
cost-cutting mechanism. No implementation until this review is approved.*
