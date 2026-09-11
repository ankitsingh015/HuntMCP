# UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH.md — Tool/Capability Policy Layer (research note)

> Status: **research only.** No implementation, no production-code changes, no config changes, no commits, no
> push. This is an input to a *possible* future V4 roadmap item; it does not modify
> [HUNTMCP-NEXT-GEN-PROPOSAL-v3.md](HUNTMCP-NEXT-GEN-PROPOSAL-v3.md) or any existing config.
>
> **The current OpenCode scoping implementation remains the accepted OpenCode baseline and must not be
> changed.** This note only asks whether HuntMCP should *own* capability/tool exposure across runtimes.
>
> Evidence tags: **OBSERVED** (verified in repo) · **SUPPORTED** (external docs/literature) · **INFERRED** ·
> **SPECULATIVE** · **UNVERIFIED**.

---

## 0. TL;DR verdict (stated up front, then justified)

**The premise is half-true and needs correcting.** Per-agent tool scoping is **not** OpenCode-specific — it is
**already implemented independently in both runtimes** and is **already dual-maintained by hand** (OBSERVED,
§2). Both target runtimes (OpenCode and Claude Code) have **native per-agent tool filtering that already
delivers the context reduction** (OBSERVED/SUPPORTED). So a universal layer would add **no new context
reduction**; its value is **drift elimination, dynamic-specialist safety, single-source-of-truth, and
portability to a third runtime.**

**Recommendation: FUTURE V4 ROADMAP ITEM, CONDITIONAL — realized as a config *generator* (Architecture B), with
an optional proxy (Architecture C) only for a runtime that lacks native filtering.** It earns its place **only
when** (a) a genuine third runtime appears, **or** (b) the dynamic-specialist count grows enough that
hand-maintained per-agent scoping becomes a measured drift/error problem. Until then it is **premature
abstraction** for ~6 agents across 2 runtimes and should not be built. **Do not adopt a runtime proxy as the
primary mechanism** — native filtering is strictly better for context reduction and per-agent granularity.

---

## 1. Motivation & the corrected problem statement

The stated motivation: the MCP context optimization "was implemented specifically in OpenCode," and HuntMCP may
also run under Claude Code Desktop or other runtimes, so we want HuntMCP to *own* capability exposure via:

```
HuntMCP Core → Capability Registry → Capability Resolver/Policy → Runtime Adapter → {OpenCode, Claude Code, …}
```

**Corrected problem (OBSERVED, §2):** scoping already exists in *both* runtimes. The real problems are:
1. **Policy duplication / drift** — the same per-agent allowlist is authored twice: `.opencode/agents/*.md`
   (`"server*": true`) **and** `.claude/agents/*.md` (`tools: … mcp__server …`). They can silently diverge.
2. **Dynamic-specialist error surface** — HuntBrain's own instructions require every new dynamic specialist to
   hand-write a `tools:` allowlist, warning that an empty/absent one makes the agent tool-blind and that
   over-scoping must be avoided. This is exactly the kind of hand-copied policy that drifts and errs.
3. **Portability** — a third runtime (direct API, a different harness) would need the policy re-expressed a
   third time.

The universal layer is therefore best understood as a **DRY / single-source-of-truth + safety-consistency**
project, **not** a "add scoping where it's missing" project (it isn't missing) and **not** a "reduce context
further" project (it can't — native filtering already does).

---

## 2. Current-state audit (OBSERVED)

| Surface | What it does today |
|---|---|
| `opencode.jsonc` | Global `tools: {"<server>*": false}` for all 30 servers (hides schemas by default) |
| `.opencode/agents/*.md` | Per-agent `tools: {"<server>*": true}` allowlist re-enables only that agent's servers |
| `.mcp.json` | Claude Code MCP registration for **all 30 servers, no filtering** |
| `.claude/agents/*.md` | Per-agent `tools: Read, …, mcp__memory-mcp, mcp__writeup-mcp, …` — **the same allowlist policy, expressed in Claude Code syntax** (e.g. huntbrain's list matches its OpenCode twin) |
| `.claude/settings.json` | `permissions.deny` (`rm`) + PreToolUse hook → `scripts/hooks/scope_gate_hook.py` |
| `.claude/settings.local.json` | `disabledMcpjsonServers` (a personal/local override) + allow rules |
| `.opencode/plugin/scope-gate.ts` | OpenCode hook → the **same** `scope_gate_hook.py` |

**Two key facts:**
- **Capability policy is already duplicated** across `.opencode/agents/` and `.claude/agents/` and maintained by
  hand. (This is the actual gap.)
- **Safety/scope policy is already unified** — both runtimes call the same `scope_gate_hook.py` at tool-call
  time. (So the "shared enforcement" pattern the universal layer wants *already exists for safety*; only
  capability exposure is duplicated.)

**Implication:** HuntMCP already proves a shared-Python-policy-behind-two-runtime-hooks pattern works. A
universal *capability* layer would extend that proven pattern from safety to tool exposure.

---

## 3. Runtime tool/MCP exposure controls (investigation points 1–3)

### 3.1 OpenCode (OBSERVED)
- Global `tools` map (server-glob → bool) hides schemas by default; per-agent frontmatter `tools` re-enables.
  Servers stay *connected*; only schema exposure to the agent changes → real context reduction.
- Plugin hooks (`tool.execute.before`) for enforcement (used for the `rm`/scope block).

### 3.2 Claude Code / Claude Code Desktop (SUPPORTED, docs 2026 + OBSERVED in repo)
- **Subagent frontmatter:** `tools` allowlist **or** `disallowedTools` denylist; per-subagent `mcpServers`
  (inherit / inline / string-reference); `skills`, `model`, `permissionMode`.
- **Session/policy settings:** `enabledMcpjsonServers` / `disabledMcpjsonServers`, `enableAllProjectMcpServers`;
  as of **v2.1.153**, `allowedMcpServers` / `deniedMcpServers` glob policies also cover servers declared in
  subagent frontmatter.
- **Permissions:** allow/deny/ask, tool-name and `mcp__server__tool` granularity; PreToolUse hooks.
- **Subagents isolate context** (each has its own window) — same property HuntMCP already relies on.
- **Verdict:** Claude Code's native filtering is **as expressive as, arguably more than, OpenCode's.** Context
  reduction is fully achievable natively; **no proxy is needed for Claude Code.**

### 3.3 Direct model / API (SUPPORTED)
- The application constructs the `tools` array **per request** — total programmatic control over exposure. This
  is the *most* flexible surface: HuntMCP would own tool exposure completely, no config files at all.
- **Verdict:** on the API path a "registry → tools array" resolver is trivial and native; again **no proxy
  required** — the app already decides what to send.

**Cross-cutting finding (points 4–5):** the *same capability policy can be enforced across all three surfaces*,
because each supports native filtering. What differs is only the **expression** (OpenCode frontmatter vs Claude
Code frontmatter vs an API tools array). That is a **code-generation / templating** problem, not a runtime-
interception problem.

---

## 4. Is a runtime adapter feasible, and does it need a proxy? (points 5–6)

**Runtime adapter = a config *compiler/generator*, not a runtime interception layer** (the key realization):

- **Feasible and cheap for runtimes with native filtering** (OpenCode, Claude Code, API — all three): the
  adapter reads the registry and **emits** the runtime-native artifacts:
  - OpenCode: the `tools:` blocks in `.opencode/agents/*.md` (+ the global map in `opencode.jsonc`).
  - Claude Code: the `tools:`/`mcpServers` frontmatter in `.claude/agents/*.md` (+ settings).
  - API: a `resolve_tools(agent_role) → tools[]` function.
  This preserves **native context reduction** (best possible) with **zero runtime overhead**, and eliminates
  drift because both files are generated from one source.

- **A HuntMCP-side proxy/router is required ONLY for a runtime that does *not* support native tool filtering**
  (point 6). Such a proxy is a well-trodden pattern (SUPPORTED: MCProxy, Bifrost AI Gateway, mcp-filter,
  mcp-tool-filter, Microsoft mcp-gateway) that filters `tools/list` and routes `tools/call`, cutting context for
  clients that serialize tool schemas. **But** two real limitations:
  - **Per-agent granularity is hard.** A proxy sees a *connection*, not "which subagent is calling" — MCP
    carries no agent identity. Per-agent filtering via a proxy needs either one proxy instance per agent role or
    request-header identity (Bifrost supports header filtering), which the runtime must be willing to send.
    Most runtimes don't pass subagent identity to the MCP server (INFERRED). So a proxy naturally gives
    **per-session**, not **per-agent**, filtering.
  - **It adds a process + failure mode** in front of every tool call (a new thing that can crash/hang/be
    misconfigured), and a bug there could **weaken scope/safety** if not carefully firewalled from the existing
    `scope_gate_hook`.

**Conclusion:** the adapter is feasible as a **generator** for all current/likely runtimes; a **proxy is a
fallback for non-filtering runtimes only**, never the primary mechanism.

---

## 5. Dynamic specialists under a capability layer (point 7)

**Today (OBSERVED):** a dynamic specialist is a new `.opencode/agents/<name>.md` whose `tools:` allowlist
HuntBrain must hand-write, guided by prose ("request/exploitation specialists need chainer/oob/second-opinion/
browser/case + their class tool; discovery specialists need httpx/katana/…"). This is error-prone (forget
`tools:` → tool-blind; over-scope → context bloat + broader blast radius).

**Under a registry (INFERRED, clear improvement):** capability **profiles** (`recon-style`, `scan-style`,
`exploit-style`, plus a required-common set like `writeup-mcp`/`case-mcp`) are declared once in the registry.
A dynamic specialist requests a **profile**, and the resolver materializes the correct tool set for whichever
runtime. This directly attacks problem #2 (§1): it replaces hand-copied lists with a validated lookup, removing
the "tool-blind" and "over-scoped" failure modes. **This is the single most concrete benefit of the whole
idea** and is worth more than the drift fix, because dynamic specialists are the growth axis (the roster is
meant to scale past 100 agents).

---

## 6. Capability policy × safety/scope policy (point 8)

**They must stay separate and layered** (INFERRED, strongly):
- **Capability policy** = *which tools are visible* to an agent (registry/resolver → runtime config). Reduces
  context and blast radius, but is a **convenience/optimization + least-privilege** control.
- **Scope/safety policy** = *which targets/actions are allowed* at call time (`scope_guard`, `budget_guard`,
  the `scope_gate_hook`, the `rm` block). This is the **real security boundary**.
- **Invariant:** a tool being *exposed* never implies a target is *in scope*. The capability layer must **never
  absorb, replace, or be trusted in place of** the call-time scope/safety hooks. Even a perfectly-scoped
  capability set still passes every call through `scope_gate_hook`. If a proxy (C) is ever added, the
  `scope_gate_hook` stays the authority and the proxy must not be a way to bypass it (a proxy that routed calls
  around the hook would be a security regression — explicit non-goal).
- **Good news (OBSERVED):** the shared `scope_gate_hook.py` already gives cross-runtime safety unification, so
  the capability layer can focus purely on exposure and inherit safety as-is.

---

## 7. Architecture comparison A / B / C / D

Dimensions scored qualitatively. "Context/token" = effect on model context across runtimes; "Portability" =
ease of adding a new runtime.

### A. Runtime-specific scoping (status quo)
- **Capability:** full (both runtimes already scoped). **Context/token:** native reduction in each runtime
  (best). **Cost:** none. **Security:** good (least-privilege + shared scope hook). **Complexity:** low per
  runtime, but **O(runtimes × agents) hand-maintenance**. **Portability:** poor (re-author per runtime).
  **Maintainability:** **weak — drift risk between `.opencode/` and `.claude/`; dynamic-specialist errors.**
  **Failure modes:** silent drift; a specialist tool-blind or over-scoped. **Impl difficulty:** already done.
- **Verdict:** correct *today*; its only real flaw is maintainability/drift as agents/runtimes grow.

### B. Universal capability registry + runtime adapters (config generator)
- **Capability:** full (generates the same native filtering). **Context/token:** **same native reduction as A**
  (no new reduction — important honesty). **Cost:** none at runtime. **Security:** good + **more consistent**
  (one policy, less drift; least-privilege enforced uniformly). **Complexity:** MED — a generator + a
  registry + CI check that generated files are in sync. **Portability:** **strong** (add a runtime = add an
  emitter). **Maintainability:** **strong** (single source of truth; profiles for dynamic specialists).
  **Failure modes:** generator bug emits a wrong allowlist (mitigated by a validation/round-trip test + CI
  drift check); staleness if someone edits generated files by hand (mitigate: mark generated, check in CI).
  **Impl difficulty:** MED.
- **Verdict:** the **strongest candidate** — but its benefit is maintainability/portability/safety-consistency,
  **not** context reduction. Worth it when drift/dynamic-specialist cost is real.

### C. HuntMCP-side proxy/router (runtime-agnostic interception)
- **Capability:** full for tool *execution*; **per-agent filtering is hard** (proxy sees connections, not
  subagents). **Context/token:** reduces context **only for runtimes lacking native filtering** (for OpenCode/
  Claude Code it's redundant with, and coarser than, native filtering). **Cost:** a persistent process + a hop
  per call (latency, ops). **Security:** **double-edged** — can add defense-in-depth (central enforcement) but
  is a **new bypass risk** if it ever routes around `scope_gate_hook`; also a new attack/■failure surface.
  **Complexity:** HIGH (a routing daemon, health, restarts, per-connection identity). **Portability:** strong
  for *execution* uniformity; weak for *per-agent context* uniformity. **Maintainability:** MED-HIGH (a live
  service to run). **Failure modes:** proxy down = all tools down; misconfig exposes/hides wrong tools;
  per-agent granularity absent. **Impl difficulty:** HIGH.
- **Verdict:** **not** the primary mechanism. Justified **only** for a runtime with no native filtering, or as
  an *optional* central execution-audit/defense-in-depth layer — and never as a scope-bypass.

### D. Hybrid (registry+adapter for native-filtering runtimes; optional proxy fallback; shared scope hook)
- **Capability:** full. **Context/token:** native reduction everywhere it's available (best), proxy only where
  it isn't. **Cost:** none for A/B path; proxy cost only when used. **Security:** best-consistency (one policy)
  + safety stays in the shared hook. **Complexity:** MED now (just B), HIGH later (if the proxy is ever needed).
  **Portability:** strongest. **Maintainability:** strong. **Failure modes:** union of B (generator bugs) and,
  only-if-used, C (proxy). **Impl difficulty:** MED (B first; C deferred/conditional).
- **Verdict:** the **right long-term shape** — but implemented as **B now-or-later, C only if forced.** D
  collapses to B in practice unless a non-filtering runtime appears.

### Summary table

| Dim | A (status quo) | B (registry+generator) | C (proxy) | D (hybrid) |
|---|---|---|---|---|
| Capability | full | full | full (exec); per-agent weak | full |
| Context/token | native (best) | **native (best), portable** | only for non-filtering runtimes | native + fallback |
| Cost | none | none | process + hop | none unless proxy used |
| Security | good | good + consistent | double-edged (bypass risk) | best + safety in hook |
| Complexity | low/runtime, poor DRY | MED | HIGH | MED→HIGH |
| Portability | poor | strong | strong (exec) | strongest |
| Maintainability | **weak (drift)** | strong | MED-HIGH | strong |
| Failure modes | drift, blind/over-scoped agent | generator bug (CI-catchable) | proxy down / bypass | union (bounded) |
| Impl difficulty | done | MED | HIGH | MED (B) + deferred (C) |

---

## 8. Does it genuinely reduce context/exposure across runtimes? (point 9 — honest answer)

**No new reduction.** Both current target runtimes already achieve the context reduction natively; a universal
layer **preserves and ports** that reduction and **removes drift**, but does not shrink context further than A
already does (OBSERVED/INFERRED). The *only* scenario where the universal layer **adds** context reduction that
wouldn't otherwise exist is a **new runtime that lacks native filtering**, handled by the proxy (C).

Therefore any claim that this architecture "reduces context across multiple runtimes" is **UNVERIFIED/false as
stated** — it makes the existing reduction **maintainable, consistent, and portable**, which is a different
(and real) benefit. Sell it on maintainability + least-privilege consistency + dynamic-specialist safety, never
on token savings.

---

## 9. Does it create unnecessary abstraction/complexity? (point 10)

**Risk: yes, if adopted prematurely.** For the current reality (6 permanent agents, 2 runtimes, a stable
allowlist), a registry + generator is **more machinery than two hand-maintained agent-file sets**, and the drift
risk — while real — is small and CI-catchable even without the abstraction (e.g. a simple test asserting the two
agent-file sets declare matching allowlists would catch drift at ~1% of the cost of a full registry).

**The abstraction earns its place only when one of these becomes true:**
- **A genuine third runtime** must be supported (portability payoff), **or**
- **Dynamic specialists proliferate** (the roster is designed to scale past 100), making hand-scoping a
  measured error/drift source — at which point capability **profiles** (§5) pay for the whole thing.

Absent those, this is textbook premature abstraction and should be **rejected for now** in favor of, at most, a
tiny **drift-check test** (Tier-0, near-zero cost) that asserts `.opencode/agents/*` and `.claude/agents/*`
allowlists agree — capturing 80% of the safety benefit for ~2% of the effort.

---

## 10. Feasibility summary (investigation points, consolidated)

1. OpenCode controls — **feasible, OBSERVED** (global off + per-agent on).
2. Claude Code controls — **feasible, richer, SUPPORTED** (frontmatter tools/mcpServers, allowed/deniedMcpServers, enabledMcpjsonServers, permissions, hooks).
3. Direct API — **feasible, most flexible** (construct tools array per request).
4. Same policy across runtimes — **yes** (all support native filtering; only expression differs).
5. Runtime adapter — **feasible as a config generator** (not a runtime interceptor) for native-filtering runtimes.
6. Proxy required? — **only for non-filtering runtimes**; mature pattern (SUPPORTED) but per-agent-weak + adds a hop/failure/bypass surface.
7. Dynamic specialists — **best served by registry profiles** (the strongest concrete benefit).
8. Safety interaction — **keep separate/layered**; capability ≠ scope; the shared `scope_gate_hook` stays the authority; a proxy must never bypass it.
9. Cross-runtime context reduction — **no new reduction**; preserves/ports/consistency only (except for a non-filtering runtime).
10. Unnecessary abstraction — **yes if premature**; a drift-check test captures most value cheaply until a third runtime or specialist-scale forces the full layer.

---

## 11. Recommendation & disposition

**Classify as: FUTURE V4 ROADMAP ITEM — CONDITIONAL / OPTIONAL. Do not build now.**

- **Now (near-zero cost, optional, not this task):** consider a **drift-check test** asserting the two runtimes'
  per-agent allowlists agree, and a lint that every agent file declares a non-empty `tools:`. This addresses the
  real present-day risk (drift + tool-blind specialists) without any abstraction. *(Noted as an option, not
  proposed for implementation here.)*
- **V4 trigger conditions (build Architecture B, the generator, when either holds):**
  1. a genuine third runtime must be supported, or
  2. dynamic-specialist count/velocity makes hand-scoping a measured drift/error source.
  Then: single **capability registry** (server → tools → which roles/profiles → scope/safety tags) + a
  **resolver** (role/profile → capability set) + **emitters** for each runtime (generate the native configs) +
  a **CI drift/round-trip check**. Capability **profiles** power dynamic specialists.
- **Architecture C (proxy):** deferred/optional — introduce **only** for a runtime lacking native filtering, or
  as an explicitly-firewalled defense-in-depth execution layer that **never** bypasses `scope_gate_hook`.
- **Reject:** adopting a proxy as the primary mechanism (worse context granularity, adds a hop/failure/bypass
  surface); and building the full registry today for 6 agents × 2 runtimes (premature abstraction).

**Hard constraints reaffirmed:** the accepted **OpenCode scoping baseline is unchanged**; the **shared
`scope_gate_hook` remains the safety authority**; capability exposure is least-privilege convenience, **never**
a substitute for scope/budget enforcement; and no token/context-reduction claim is made for this layer beyond
"preserve and port what already exists."

---

## 12. What this would change in the roadmap (if triggered)

- It becomes a **V4 item on the reliability/architecture track** of [v3](HUNTMCP-NEXT-GEN-PROPOSAL-v3.md) — not a
  capability bet, not on the P0-BENCH critical path, not a telemetry item.
- It **interacts with** dynamic-specialist spawning (profiles) and with the existing shared safety hook; it does
  **not** touch CEM, VAL-AUTHZ, DISC-VARIANT, or the benchmark.
- **Exit criteria (if built):** one registry generates both runtimes' agent configs; a CI check fails on drift;
  a dynamic specialist can be spawned by naming a profile; zero change to runtime behavior or context size vs
  the hand-authored baseline (i.e., the generator is behavior-preserving); the scope/safety hook path is
  untouched.
- **Rollback:** delete the generator, keep the last-generated hand-editable agent files (they are just normal
  config) — no runtime dependency introduced.

---

## 13. Open questions

1. Is a third runtime actually planned, or is this hypothetical? (Decides whether B's portability payoff is
   real or speculative — currently **SPECULATIVE**.)
2. How fast will the dynamic-specialist roster actually grow? (Decides whether profiles pay off — the strongest
   benefit hinges on this.)
3. Would a simple cross-runtime **drift-check test** capture enough of the risk to make the full layer
   unnecessary for the foreseeable future? (Likely **yes** — INFERRED.)
4. For any future non-filtering runtime, can it pass subagent identity to a proxy (headers), or would per-agent
   scoping be lost? (Determines whether C can match B's granularity there.)
5. Does the direct-API path ever become a real HuntMCP runtime? (If so, the resolver-as-function is trivial and
   B is even more attractive.)

---

*Bottom line: the universal capability layer is technically feasible and architecturally clean as a config
**generator** (B, inside a hybrid D), but it delivers maintainability/portability/least-privilege consistency —
**not** new context reduction — and is **premature today**. Recommend it as a **conditional V4 item**, gated on a
third runtime or dynamic-specialist scale, with a cheap drift-check test as the interim mitigation. Do not build
now; do not change the OpenCode baseline; keep safety in the shared scope hook.*
