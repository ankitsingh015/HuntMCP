# NEXT-GEN-PLATFORM-RESEARCH.md — Platform / Sandbox / Security / Unknown-Unknown Deep Research

**Status:** research artifact (read-only investigation). No code, production behavior, dependencies, or planning
documents were changed. This is **research + gap analysis + security analysis + architecture options + innovation
analysis + a decision proposal** — *not* a roadmap and *not* an authorization to build.

**Ground truth:** worktree `research/golden-nextgen` @ `fbbf26d`; CEM Phase 1 FROZEN (`#101`). Working tree carries
two unrelated in-progress edits (a temp-mail host allowlist in `scope_guard.py`, a `data/watch.db` blob, an untracked
writeup, a reminder script) — none touched here.

**One-line answer to the primary research question:** The platform hypothesis is **not wrong, but it is over-scoped
for what HuntMCP is today.** The correct classification is **B→C** (a small, additive execution-isolation + evidence-
identity substrate), **not D/E** (a major architectural layer or the strongest long-term architecture). Exactly **one**
platform-adjacent decision is genuinely "expensive to retrofit later" and should be made now; everything else is
either already owned by prior research, an adopt-when-triggered off-the-shelf pattern, or a distraction.

---

## 1. Executive Summary

HuntMCP already has the **state** half of a "workspace" primitive and none of the **execution** half. Per-engagement
directories (`data/engagements/<slug>/`), an active-target pointer, `file_lock` concurrency, content-addressed
SHA-256 evidence, a one-target-per-chat guard, and per-session pointer isolation are all implemented and tested
(`engagement_paths.py`, `case_store.py`, `file_lock.py`; ARCHITECTURE.md rows 1182–1183). What does **not** exist is
any execution isolation: agents and tools run directly on the host under `bash: {"*":"allow"}`, secrets live in a
plaintext `.env` injected as environment variables, and the sole hard safety boundary is a `PreToolUse` scope hook
that the open-source audit itself flags as a single point of failure ("if it silently breaks, the fallback posture
is allow everything", OPEN-SOURCE-AUDIT.md §Agent/MCP/Tool Permission Findings).

The prior research corpus (XYZ, ROADMAP, MASTER-ROADMAP-PROPOSAL, three NEXT-GEN-PROPOSAL revisions + AUDIT,
UNKNOWN-UNKNOWN-RESEARCH, UNIVERSAL-CAPABILITY-EXPOSURE-RESEARCH, INTELLIGENCE-ALLOCATION-MEMO) is almost entirely on
a **different axis** from this prompt: it is about *proof* (CEM), *reasoning* (invariant model, hypothesis
resurrection, info-gain experiment selection), *measurement* (telemetry, benchmark), and *discovery breadth*. That
work is strong and should not be reopened. The **platform / execution-isolation / capability-security / secret /
snapshot-fork-replay / wind-tunnel axis of this prompt is essentially untouched** by all of it, with five narrow,
important exceptions that this document reconciles (capability/tool-exposure layer, parallel fan-out, content-
addressed evidence, target-state snapshots, tool-output-injection sanitization).

**What survives serious filtering (evidence-based):**

1. **Environment-as-Evidence / a reproducible "research-run identity" (RECOMMEND: decide now, build small).** This is
   the single "do-not-regret" primitive. It extends the *already-present* content-addressed evidence store and the
   *already-present* CEM controls-record into a complete, hashed run manifest (target snapshot + tool versions + agent
   + model + policy version + observations), using the existing in-toto attestation format rather than inventing one.
   It is cheap now, expensive to retrofit, and it **compounds directly with CEM's trust thesis** — the scarce good is
   *proof*, and a finding you cannot reproduce months later is proof that decays.
2. **A real execution-isolation boundary for the exploit/tool tier (RECOMMEND: adopt as a security control, not a
   platform).** Framed as fixing a *genuine current security gap* the audit already found, using off-the-shelf
   rootless containers or gVisor — **not** microVMs, **not** a control plane.
3. **Everything else the prompt raises — capability-based authority, secret broker, multi-agent parallel
   investigation, control-plane, cloud migration — is either already-deferred, adopt-when-triggered, or premature.**
   Recommend explicit *deferral with trigger conditions*, not a build.

**The wind tunnel** is worth a small adversarial regression test that reuses the existing benchmark substrate, but as
a *concept* it is prior art (AgentDojo / AgentBeats / adaptive-adversary papers), so it earns no novelty claim.

**Novelty honesty up front:** nothing in this document is a new invention. The two recommended items are *rare
compositions* of established mechanisms (content-addressing + attestation + causal evidence; rootless isolation for an
offensive agent). The genuinely differentiated asset HuntMCP already owns — CEM — is not on this axis, and this
research does **not** recommend diverting from it.

---

## 2. Research Scope

Covered: the full golden-prompt agenda (sections 0–69) against the actual worktree and the full prior-research corpus,
plus targeted prior-art/cross-domain web research (sandbox landscape, agent-security defenses, secretless execution,
supply-chain provenance). Three research loops were run and merged (§ "Loops" below, folded into the relevant
sections). Out of scope by rule: modifying any planning doc, code, or dependency; testing any external target;
resolving material architecture decisions unilaterally (those are surfaced in §59).

**Loop provenance (merged, not concatenated, per prompt §50):**
- **Loop 1 (red-team / sandbox-break)** produced §10–§13, §32, §35, §36, §41, §42, and the invariants in §56.
- **Loop 2 (clean-sheet architecture)** produced §9, §51–§54.
- **Loop 3 (cross-domain)** produced §23 (attestation), §16 (COW/notebook/VCS analogies), §22 (agent-runtime), and the
  adopt-not-invent findings in §30/§32(libs).

---

## 3. Current HuntMCP Baseline (verified against code)

| Layer | What exists (file evidence) |
|---|---|
| Orchestration | HuntBrain (L1) + permanent L2 specialists + dynamic specialists; OpenCode + Claude Code, per-agent tool allowlists (`opencode.jsonc`, `.opencode/agents/*.md`, `.claude/agents/*.md`). |
| Tools | ~30 MCP servers shelling out to security binaries via `tool_resolver.run_tool()` (the single chokepoint). |
| State isolation | **Per-engagement dirs** `data/engagements/<slug>/`; active-target pointer `data/.active-engagement`; per-session pointer via `HUNTMCP_ACTIVE_POINTER` (`engagement_paths.py`, `scripts/new-target-session.sh`). |
| Concurrency | `file_lock.py` (flock on `<path>.lock`) around read-modify-write JSON state; SQLite `PRAGMA journal_mode=WAL` on `case.db`/`session_context.db`/`watch.db`. |
| Evidence | **Content-addressed** SHA-256 bytes under `evidence/`, immutable-by-hash; `update_finding_status()` refuses CONFIRMED with zero evidence (`case_store.py`). |
| CEM | Phase-1 frozen: `cem_engine.py` (1706 L) + `case_store.py` CEM tables (`cem_meta/conditions/trials/verdicts`), controls snapshot recorded per trial. |
| Safety substrate | `scope_guard.py` (+ `scripts/hooks/scope_gate_hook.py` PreToolUse), `budget_guard.py` (500-call breaker), `audit_log.py` (redacted JSONL), `redact.py`, `work_registry.py`, `dedupe_check.py`, `content_scanner.py`, `stuck_detector.py`. |
| Background jobs | `job_runtime.py` (subprocess + thread jobs, start/poll/list). |
| Target state | `watch-mcp` **snapshots table** (recon diffing over time); `session_context.db` (observed IDs). |
| Provider | `model_gateway.py` (multi-provider selection by env key). |
| Secrets | plaintext `.env` (Shodan/VT/Censys/HackerOne/GitHub/Anthropic keys) → `os.getenv` into tool processes. **No broker.** |
| Deployment | `Dockerfile` = single packaging image (tools + Python), **runs as root, `@latest` unpinned tools** (audit P2). Not a per-engagement boundary. |

**The one-sentence baseline:** HuntMCP is a *state-isolated, evidence-disciplined, policy-guarded* multi-agent hunter
running with *zero execution isolation* on a shared host.

---

## 4. Existing Capability Matrix (platform-axis classification)

Using the prompt's A–L scale. Only platform-axis capabilities are classified here (the CEM/reasoning/discovery axis is
classified in the prior docs and not re-litigated).

| Capability | Class | Evidence |
|---|---|---|
| Per-engagement state isolation | **B (implemented)** | `engagement_paths.py`, ARCH rows 1182–83 |
| Concurrent multi-session (different targets) | **B** | per-session pointer, `new-target-session.sh` |
| File-lock + WAL concurrency | **B** | `file_lock.py`, `case_store.py` |
| Content-addressed immutable evidence | **B** | `case_store.py` SHA-256 store |
| Target-state snapshot (recon delta) | **C (implemented, underused)** | `watch-mcp` snapshots table; not wired to CEM revalidation |
| Audit trail (redacted, append) | **B** (but not hash-chained/tamper-evident) | `audit_log.py` |
| Capability / tool-exposure policy layer | **F (planned/deferred V4)** | UNIVERSAL-CAPABILITY-EXPOSURE §11 |
| Parallel-solver / fan-out | **F (design-only backlog)** | UU I.2, "worker_pool.py-informed" |
| Provider gateway / routing | **E (partial) / F (active allocation)** | `model_gateway.py`; memo §8 |
| Tool-output-injection sanitization | **I (important open gap)** | UU-7, Batch 8; ARCH 1155 |
| Exploit-execution sandboxing | **F (narrow backlog note, unbuilt)** | ARCH 216, 1224 (Strix/mantis refs) |
| Execution isolation / namespaces / seccomp | **absent (grep: 0 hits)** | codebase grep |
| Capability-security authority (obj-cap, revocable) | **absent** | codebase grep: 0 |
| Secret broker / secretless execution | **absent** | plaintext `.env` |
| Provenance / taint / info-flow labels | **absent** | grep: taint=2 (unrelated), provenance=0 |
| Environment-as-evidence run manifest | **H (small gap; partial via CEM controls)** | `cem_engine.py` Controls.record |
| Snapshot/fork/replay of *execution env* | **absent** (only target-state snapshots) | grep |
| Agent wind tunnel / adversarial self-test | **absent** | — |

---

## 5. Existing Roadmap Coverage (what prior research already owns — do NOT reclaim)

- **CEM proof engine** — XYZ thesis, frozen. Not this axis.
- **Discovery breadth (XBOW-class), variant discovery, causal signatures, invariant model, hypothesis resurrection,
  info-gain experiment selection, negative knowledge, utilization observability, schema-driven property testing** —
  UNKNOWN-UNKNOWN + MASTER-ROADMAP Phases 2–5. Reasoning/measurement axis.
- **Capability/tool-exposure layer + runtime adapters + optional proxy** — UNIVERSAL-CAPABILITY-EXPOSURE: **conditional
  V4**, config-generator (Arch B), *do not build now*; native per-agent filtering already delivers the context win;
  the shared `scope_gate_hook` stays the safety authority. **Directly overlaps prompt §8/§22/§23** — but only on the
  *tool-visibility* meaning of "capability", not the *security-authority* meaning (see §14).
- **Parallel fan-out** — design-only backlog (worker_pool.py-informed). Overlaps §14/§15/§21.
- **Provider routing / adaptive allocation** — memo: measure-early-decide-late, no router now.
- **Tool-output-injection sanitization** — UU-7 / Batch 8, queued as an immediate security item (MASTER-ROADMAP
  Decision 5). Overlaps §11/§12/§42.
- **Graph DB / SCM / RL router / "more agents / bigger RAG"** — explicitly **rejected** (MASTER-ROADMAP §13).
- **Go backend ↔ agent wiring** — explicitly out of scope (MASTER-ROADMAP Decision 7).
- **Exploit-execution sandboxing** — a *backlog note* citing Strix (Docker) and `google/mantis`
  (`sandboxes/gvisor.py`, `sandboxes/microsandbox.py`) as references to compare "when exploit-agent's sandboxing item
  gets built" (ARCH 216, 1224). **This is the only prior mention of the entire platform axis, and it is narrow,
  unbuilt, and undesigned.**

---

## 6. Existing Implementation Coverage

Verified present and tested (66 test files in `tests/`): per-engagement isolation, file-lock concurrency, content-
addressed evidence, evidence-gated finding confirmation, budget breaker, redacted audit, scope hook, CEM Phase-1,
watch-mcp snapshots, model gateway. The security model is **wired, not aspirational** (audit's own words) — but it is a
*cooperative-agent* model: it assumes the agent is not itself the adversary and the hook process stays alive.

---

## 7. Underused / Unwired Capabilities (leverage without new infra)

- **Target-state snapshots (watch-mcp)** exist but are **not** fed into CEM revalidation or "affected-hypothesis"
  re-hunting. This is the delta-hunting idea (§25), and it is *mostly plumbing between two things that already exist*.
- **CEM `Controls.record()`** already snapshots the pinned confounder set per trial — this is 70% of an
  "environment-as-evidence" manifest; it just doesn't capture tool versions / agent / model / policy version.
- **`audit_log`** is append-only and redacted but **not tamper-evident** (no hash chain). Making it hash-linked is a
  ~30-line change that upgrades forensic integrity (§39, §19).
- **`session_context.db`** records observed IDs but is (per its own docstring) not yet wired into browser/katana tool
  calls — a small integration, already-scoped, unrelated to the platform question but noted for completeness.

---

## 8. New Platform Hypothesis — Evaluation

The hypothesis: HuntMCP evolves into a *local-first, persistent, isolated, multi-session security-research platform*
with a control plane and per-engagement execution environments.

**Verdict: partially true, mostly premature.** The state/persistence/multi-session pieces already exist at the level
HuntMCP actually needs (a solo builder running authorized engagements, per the project memory). The *execution
environment* piece is a real gap but is a **security control**, not a platform. A **control plane** with users /
policies / secret broker / capability leases / lifecycle manager is justified only by *scale HuntMCP does not have*
(multi-tenant, remote, many concurrent hostile agents). Building it now is the textbook trap the prior docs already
named ("premature abstraction", "no router now", "graph DB rejected").

Classification on the prompt's A–F scale: **B (useful as a small deployment/security layer) trending to C (useful as
an additive substrate) for exactly one primitive (evidence identity).** Not D, not E.

---

## 9. Correct Architectural Primitive Analysis

Clean-sheet (Loop 2), the candidate primitives are: *project, engagement, workspace, execution instance, research
case, session, agent, task, machine*. HuntMCP already answered most of this implicitly and correctly:

- The durable primitive is the **engagement** (`data/engagements/<slug>/`) — target + scope + budget + case + audit.
- The concurrency primitive is the **session** (a pointer + a process lifetime).
- The evidence primitive is the **content-addressed artifact**.

The clean-sheet exercise says the *missing* primitive is not "workspace" (a container) but the **research run** — a
single reproducible execution of an investigation, identified by everything that could change its result. This is the
primitive worth adding, because it is the one CEM's trust thesis actually needs and the one that is expensive to
retrofit (§46). "Workspace-as-container" is a *deployment detail* of the engagement, not a new primitive.

**Recommended minimal hierarchy:** `engagement → session → research-run → {experiments, evidence}`. Note this adds
**one** concept (research-run) to what exists; it does not introduce project/user/tenant (those are cloud concerns,
deferred).

---

## 10. Security Threat Model

Actors and boundaries (prompt §5). The realistic model for HuntMCP-today:

**Trusted computing base (TCB) today = the entire host.** Scope hook + budget + audit + evidence gate are all Python
running in the same trust domain as the agent's `bash`. A compromised or prompt-injected agent with shell can: read
`.env` (a plaintext file at repo root — a bare `cat .env` names no host and no Tier-2 tool, so the scope hook does not
gate it; additionally `dotenv_loader.load_dotenv_if_present()` loads the *entire* `.env` into `os.environ` for the four
servers that call it — osint/hackerone/second-opinion/github-security), **overwrite the PreToolUse hook itself** (a
file write via bash is not gated — only `rm` and target-host-touching commands are — and the hook is re-invoked per
call, so an `exit 0` stub takes effect for every subsequent call this session; **verified against
`scripts/hooks/scope_gate_hook.py`, which is deliberately narrow: host-scope only, no file-write / secret / install
gating**), write anywhere under `$HOME`, exfiltrate other engagements' data (all under one `$HOME`), and spawn
persistent processes. **There is no boundary below "the whole machine".**

**Primary threats (ranked by realism for an offensive agent that *intentionally* ingests hostile content):**
1. **Indirect prompt injection from target content** (HTTP responses, DOM, JS, MCP tool output, disclosed writeups) →
   agent takes an attacker-chosen action with its legitimate authority. *This is the top threat and is inverted from
   normal agents: HuntMCP's job is to read hostile pages.* UU-7 already names the tool-output slice; the broader
   surface is untreated.
2. **Secret harvest** — `.env` in process env is one `cat`/`os.environ` away for any code the agent runs (including
   agent-authored PoC scripts and installed packages).
3. **Supply-chain / workspace content** — `@latest` unpinned tool installs (audit P2), agent-run `pip install`, git
   hooks in a cloned target repo, malicious npm postinstall.
4. **Blast radius across engagements** — shared host + shared `$HOME`; state dirs are *separated by path*, not
   *isolated by permission*.
5. **Hook-as-SPOF** — the audit's own finding: hook breaks → allow-all.
6. **`--os-shell` autonomous RCE** — documented escalation with no distinct confirmation tier (audit P2, MASTER-ROADMAP
   Decision 8).

**Key security invariant (the one that must never break):** *no target-controlled data can cause a state-changing or
out-of-scope action without passing a deterministic, out-of-model policy check.* HuntMCP has this **for scope**
(the hook) but **not for actions in general** and **not for secrets**.

---

## 11. Sandbox Architecture Analysis

Prior-art landscape (2026, verified via web research):

| Option | Isolation | Boot / overhead | Snapshot-fork | Local feasibility | Fit for HuntMCP |
|---|---|---|---|---|---|
| Bare host (today) | none | 0 | n/a | trivial | **current gap** |
| Rootless container (Podman/user-ns) | shared kernel, dropped caps, user-ns | ~ms | layer/COW | excellent | **best practical fit** |
| gVisor | user-space kernel, syscall intercept | ~10s ms | via runsc | good (Linux) | strong for tool tier; blocks GPU passthrough |
| Kata / Firecracker microVM | dedicated kernel, HW virt | ~150 ms, <5 MB | 5–30 ms restore + fork (Morph) | heavier; KVM needed | overkill for solo/local |
| Full VM | strongest | seconds | slow | heavy | no |

**Analysis:** the strongest *theoretical* isolation (microVM) is not the strongest *practical* choice here. HuntMCP
runs Linux dev/CI boxes (per `file_lock.py` comment), is single-operator, and needs debuggability and cheap startup
far more than it needs multi-tenant kernel isolation. **Recommendation: rootless container per engagement (or per
exploit-tier tool run) with a dropped-capability, non-root, egress-restricted profile.** This:
- fixes the audit's root-container and blast-radius findings;
- gives a filesystem/PID/mount/user boundary the current design lacks;
- keeps the same binaries and tool paths (`tool_resolver` unchanged);
- is a *deployment/security detail*, reversible, no domain-model change;
- leaves microVM as a **future remote-execution** option behind the same abstraction, not a now-decision.

**Do not** put the *whole agent + control logic* in the sandbox and call it done — the point is to put the *untrusted
execution* (tool subprocess, agent-authored PoC, package installs, hostile-repo checkout) below a boundary the
*policy/evidence/secret* logic sits above (§7 root-of-trust). That separation is the actual security win; the container
tech is interchangeable.

---

## 12. Agent Wind Tunnel

**Concept (prompt §6):** a repeatable adversarial environment that continuously tries to break the sandbox + policy
architecture, with canary secrets, decoy workspaces, malicious MCP servers, hostile pages, and static + adaptive
multi-turn attacks; measuring attack success, containment, time-to-break, blast radius, recovery, and *legitimate-task
utility* (the security/utility frontier, §38).

**Prior-art honesty:** this concept is **not novel**. AgentDojo (97 tasks / 629 security cases, benign-utility +
utility-under-attack + ASR), the *Adaptive Adversaries* multi-turn agent-vs-agent benchmark, and Berkeley's *AgentBeats*
(18k-battle held-out) are exactly this. The field's own gap is "a standardized, defense-aware *adaptive* protocol" —
which is a research gap, not a HuntMCP product.

**What is a rare-composition (not an invention):** applying this eval to **HuntMCP's own control surfaces as the
system-under-test** — its scope hook, budget breaker, evidence gate, engagement isolation, and (if built) the sandbox
and secret broker — using canary API keys in the decoy `.env` and a malicious MCP server as the injection vector.

**Recommendation:** build this as a **small adversarial *regression test*** reusing the P0-BENCH substrate the master
roadmap already commits to — *not* a new benchmark product and *not* a novelty claim. Its highest-value first case is
**tool-output-injection (UU-7)**: can a hostile HTTP response make an agent exfiltrate a canary secret or act out of
scope? That single test is worth more than a general "wind tunnel" today because it exercises threat #1 directly. It
must measure legitimate-task utility alongside containment, or it will reward over-blocking (§38).

---

## 13. Control-Plane Root of Trust

There is no control plane today, so this is a design-forward analysis. **The most important structural rule for any
future substrate: the policy engine, evidence store, secret broker, and audit log must not be reachable *from inside*
the agent's execution environment.** Today they are the same process/host as `bash`, which is why the TCB is the whole
machine.

**Minimum viable separation (buildable incrementally, no god-process):**
- **Execution** (tool subprocess, agent PoC) — untrusted, sandboxed (§11).
- **Policy** (scope/budget/action checks) — out-of-model, out-of-sandbox, mediates every side-effect (the hook is the
  seed of this; harden it from SPOF-allow-all to SPOF-*fail-closed*).
- **Evidence + audit** — append-only, ideally write-only from the execution side (execution can *emit* evidence, cannot
  *rewrite* it).
- **Secrets** — a broker the execution side calls but never reads from (§16).

Blast-radius reduction is achieved by *these four not sharing a trust domain*, not by adding a UI or a database.

---

## 14. Capability-Based Authority

**Two distinct meanings must be separated, because the prior docs already answered one and not the other:**

- **Capability-as-tool-visibility** (which MCP tools an agent can call): **already researched, deferred to conditional
  V4** as a config-generator (UNIVERSAL-CAPABILITY-EXPOSURE). Do not reopen.
- **Capability-as-security-authority** (a narrow, revocable, time-bounded grant to perform a *specific action* on a
  *specific resource*): **untreated**, and this is the real content of prompt §8/§9. Prior art is mature and directly
  applicable — **CaMeL, FIDES, Progent, RTBAS, FORGE** all realize "deterministic policy outside the model, using
  capabilities + information-flow labels + a reference monitor" and report near-elimination of AgentDojo attacks.

**Assessment for HuntMCP:** a full object-capability authority model is **high-value but high-complexity**, and its
biggest payoff (containing a compromised agent) is *also* delivered — more cheaply — by execution isolation (§11) +
a secret broker (§16) + hardening the existing scope hook into a fail-closed action-mediating reference monitor.
**Recommendation: do not build a bespoke capability system now.** Instead, (a) harden the scope hook into a
general fail-closed *action* monitor (not just host-scope), and (b) treat full capability-security as a *deferred item
with a trigger* (multi-agent-with-different-trust, or remote execution). The confused-deputy / approval-laundering /
prompt-injection risks in §9 are real but are mitigated first by "the agent never holds the secret and cannot act
outside the sandbox," which is simpler than leases.

---

## 15. Authority Lifecycle

REQUEST→GRANT→USE→OBSERVE→EXPAND→REVOKE→EXPIRE is the right frame *if* capabilities are built. The pragmatic near-term
version that does not require a capability system: **bind every human approval to (exact action, exact resource, exact
session, policy version, expiry, one-shot)** — this is achievable at the hook layer today and closes the
approval-replay / "allow anything similar forever" hole (§40) without a lease subsystem. Evidence must **never**
auto-escalate authority (prompt asks; answer: no — that is a direct injection-to-privilege path).

---

## 16. Secret Broker / Secretless Execution

**Prior art is mature and off-the-shelf (2026):** Infisical **Agent Vault** (network-layer credential proxy — agent
never sees the secret), **CyberArk Secretless Broker**, the `trustless` credential-broker CLI, **HashiCorp Vault
dynamic secrets** (TTL-bound, auto-revoked, per-request), **Anthropic Workload Identity Federation** (short-lived OIDC,
GA June 2026), **SPIFFE/SPIRE**. The principle everywhere: *no API keys in the process address space to harvest.*

**Assessment for HuntMCP:** the current `.env`→`os.getenv` model is the exact anti-pattern these fix, and it is a real
gap (threat #2). But the payoff scales with *how many secrets* and *how hostile the execution*. Today the highest-value,
lowest-effort move is **not** a broker but **keeping secrets out of the sandbox**: if untrusted execution (tool
subprocess, agent PoC, package installs) runs in a container that simply *does not have the `.env` mounted*, and the
few tools that genuinely need a key (Shodan, HackerOne read) run in a thin trusted shim outside it, most of the broker's
benefit arrives with none of its machinery.

**Recommendation:** (a) **now**: stop injecting the full `.env` into untrusted execution; scope each key to the one
tool that needs it. (b) **adopt-when-triggered** (remote execution, or many keys, or third-party MCP servers you don't
trust): adopt an existing broker (Agent Vault / secretless-broker) — **do not build one.** This is an adopt-not-invent
item with zero novelty.

---

## 17. Data / Instruction / Policy / Authority Separation

This is threat #1's structural fix. The principle (CaMeL-style): untrusted input becomes **tainted data** that can be
*reasoned over* but can never *become an instruction or an authority* without passing a deterministic check. HuntMCP
relies almost entirely on prompting for this today (agent docs say "treat target output as data"), which the adaptive-
attack literature shows is insufficient. The realistic near-term step is the UU-7 **tool-output sanitization/quarantine**
already queued — plus the fail-closed action monitor (§13/§14) so that even a successful injection cannot reach a
side-effect without an out-of-model gate. Full information-flow labelling is the mature-but-heavy version; defer.

---

## 18. Provenance / Taint

Should data carry origin/trust metadata through the system? **Directionally yes, minimally.** The cheapest useful
version: tag evidence and tool output with a **source-trust label** (`target-untrusted` / `tool-derived` /
`operator-supplied`) at the point of capture, carried into the case store. This is a small schema addition to the
already-content-addressed evidence store, and it is the substrate that makes §17's quarantine and §39's forensics real.
Full taint propagation through the LLM context is not tractable and is not recommended. Answer to the prompt's
questions: untrusted content becoming "evidence" is fine; untrusted content becoming *instruction* or *authority* is the
line, and it must be enforced structurally, not by labels alone.

---

## 19. Supply-Chain / Workspace Content Trust

Real gaps today: unpinned `@latest` tool installs (audit P2), agent-run `pip install`, and any cloned target repo's
git hooks / build scripts. The trust transition SOURCE→EXECUTABLE-AUTHORITY happens silently. Near-term, low-cost:
pin tool versions + capture an SBOM (audit already recommends), and **run any workspace-content execution (cloned repo,
installed package, agent-authored code) inside the §11 sandbox** — which is the same control, reused. This is where the
sandbox pays for itself beyond "contain the exploit": it contains the *build/checkout* too.

---

## 20. Multi-Session Architecture

Concurrent sessions on *different* targets are **already solved** (per-session pointer, isolated dirs, ARCH 1183).
The unsolved case is concurrent sessions on the *same* target/case (shared `case.db`). Options (prompt §14):

- **A shared mutable state** — current model; fine for one writer, races beyond `file_lock`'s per-file granularity.
- **B isolated execution + shared *immutable* evidence** — **recommended** — sessions write only append-only evidence;
  conclusions reconcile late.
- **C branch-local state + controlled merge** (git-like) — elegant but heavier; defer.
- **D event log + materialized state** — the master roadmap already rejected event-sourcing-scale complexity for this;
  agree.

**Recommendation: B.** It aligns with the existing content-addressed evidence model and with CEM (independent arms,
late reconciliation) and needs the least new machinery. Do not adopt shared mutable multi-writer state.

---

## 21. Parallel Independent Research

Prior research already owns "parallel fan-out" as a design-only backlog. The genuinely valuable framing (prompt §15) —
*independent hypotheses + isolated execution + shared immutable evidence + late reconciliation*, to reduce anchoring /
confirmation bias — is a **strong conceptual match with CEM** (competing minimal-condition-set hypotheses; adversarial
validator). But it is **not** a platform requirement and it is **not** free: it multiplies token/tool cost. Answer to
the prompt's question: yes, agents *can* investigate competing explanations without seeing each other's conclusions,
and evidence *can* merge without merging contaminated reasoning (that is exactly the immutable-evidence model of §20-B).
**Recommendation: keep it as the existing design-only backlog; gate any build on measured bias/recall improvement
(the master roadmap's measure-first discipline). Not a now-item.**

---

## 22. Persistence / Snapshot / Fork / Replay

Prior art (Firecracker snapshot-restore 5–30 ms; Morph fork; COW filesystems) is mature — so *environment* snapshot/fork
is buy-not-build if ever needed. But the honest question is **what** you snapshot. For HuntMCP the valuable object is
not a VM image; it is the **research-run identity** (§23). Execution-environment fork/replay is a *remote/cloud*
capability with little local payoff for a solo operator and is **deferred**. Target-state snapshots (the useful kind)
already exist in watch-mcp and just need wiring to CEM (§25).

---

## 23. Environment-as-Evidence  ← **the recommended primitive**

**The one item that is cheap now and expensive later.** CEM's entire value is *reproducible proof*. A finding whose
reproduction depends on tool versions, target state, and policy that were never recorded is proof that silently
decays. HuntMCP already records ~70% of this per CEM trial (`Controls.record()` pins session/CSRF/cache/rate-limit/time
and hashes request+response). The gap is the **environment identity**: tool + tool version, agent, model, prompt/policy
version, and a target snapshot reference.

**Cross-domain unlock (Loop 3):** this maps exactly onto **in-toto attestation + SLSA provenance** — the established
format for "record every input, output, and environment measurement" (Kettle does precisely this for builds). HuntMCP
would be applying build-provenance attestation to *security-finding reproducibility* — a **rare cross-domain
composition**, not an invention, and it means adopting a schema (in-toto Statement) rather than designing one.

**Recommendation: build a small `research-run` manifest** = `{engagement, session, target-snapshot-hash, tool
versions, agent, model, policy/prompt version, CEM controls, evidence hashes, verdicts}`, content-addressed like
existing evidence, referenced from the CEM bundle. This is additive, ~a schema + capture hooks at `tool_resolver` and
CEM, and it is the primitive worth deciding on now (§46/§53).

---

## 24. Immutable Evidence Architecture

Already largely present (content-addressed SHA-256, no silent mutation). Two cheap upgrades: (a) **hash-chain the
audit log** (tamper-evidence, §39); (b) **lineage links** (evidence→experiment→CEM-verdict→finding→report) — the case
store already has the FKs; formalizing lineage into the run manifest (§23) closes it. No graph DB needed (the master
roadmap's rejection stands). Verdict: **evidence should stay immutable and content-addressed; add lineage + a hash-
chained audit, nothing more.**

---

## 25. Target Snapshot / Delta Hunting

watch-mcp already snapshots recon state and diffs it. The unrealized value: **delta → affected hypotheses → targeted
re-hunt → CEM revalidation** (patch-bypass regression is even in XYZ Phase 5). **Correction (self-audit §63): this is
NOT mere plumbing.** `watch.db` (recon snapshots/events) and `case.db` (hypotheses/findings/CEM conditions) are
entirely unlinked today (verified: zero cross-reference), and a recon-level delta does not trivially key to a finding's
CEM conditions — the "affected-hypothesis" mapping is genuine new logic (medium effort). It remains high-ROI, low-risk,
requires no platform, and persistent target intelligence does outperform starting from zero — but it is a *build*, not
a wiring exercise. **Recommendation: a strong candidate for a small self-contained win**, aligned with XYZ Phase 5.

---

## 26. Local-First / Cloud-Later

The correct posture is exactly what HuntMCP already does implicitly: **local-first, cloud-shaped-but-not-cloud-built.**
The abstractions that keep cloud *possible* without building it: (1) engagement/run as the unit of work; (2)
content-addressed evidence (already portable/syncable); (3) the §23 run manifest (a natural export/replay package);
(4) an execution abstraction (§11) behind which microVM/remote-worker can later slot. **What must NOT be built now:**
Postgres migration, object storage, workers, queues, multi-tenancy, billing. The master roadmap and memo already say
this; this document concurs and adds only "keep the execution boundary swappable."

---

## 27. Agent Runtime Abstraction

Already dual-runtime (OpenCode + Claude Code) with hand-maintained per-agent configs. UNIVERSAL-CAPABILITY-EXPOSURE
already concluded a runtime-adapter/config-generator is **conditional V4** (trigger: a genuine third runtime, or
specialist-count drift). Nothing here changes that. Do **not** build a lowest-common-denominator session protocol that
strips runtime-specific capability. Answer to prompt §22: the abstraction, if ever built, is a *config generator*
(Arch B), not a runtime proxy (Arch C) as primary.

---

## 28. Provider / API Gateway

`model_gateway.py` already does multi-provider selection by env key. Quotas / spend limits / per-project budgets /
provider isolation are the memo's "active allocation", deferred (measure-first). BYOK and provider isolation become
relevant only with remote/multi-user — deferred with that trigger. No now-build.

---

## 29. Full-Stack Platform Boundary

What security research needs that a generic AI coding IDE does not: **scope/engagement authorization, evidence +
provenance, hypotheses + experiments + CEM, target snapshots, attack chains, retesting, audit, reproducibility,
policy enforcement, human-review-before-submit.** HuntMCP has most of these; a coding IDE has none. The correct product
boundary is therefore **a local security-research tool/application, not a platform and emphatically not an AI IDE**
(prompt §43). The differentiation is the *research object model* (finding/evidence/CEM), not the *editor*.

---

## 30. Competitor / Prior Art

| System | Solves | Isolation | Persistence | Multi-session | What to copy | What NOT to copy |
|---|---|---|---|---|---|---|
| E2B | agent code sandbox | microVM | fs across turns | per-sandbox | swappable exec boundary | microVM as local default |
| Daytona | agent sandbox | Docker + gVisor | yes | yes | gVisor for tool tier | full platform weight |
| Firecracker / Morph | microVM + snapshot-fork | HW virt | snapshot | fork | *what* to snapshot idea | building it locally |
| Strix | offensive agent "graph", per-agent sandbox | Docker | — | agent graph | per-agent exec isolation | live shared-discovery graph (contamination, §21) |
| AgentDojo / AgentBeats | agent-security eval | — | — | attacker/defender | adversarial-regression method | claiming novelty for a wind tunnel |
| CaMeL / FIDES / Progent / RTBAS / FORGE | injection defense | reference monitor | labels | — | deterministic out-of-model action mediation | bespoke full info-flow now |
| Agent Vault / CyberArk Secretless / Vault | secretless exec | credential proxy | — | — | adopt one when triggered | building a broker |
| in-toto / SLSA / Kettle | build provenance | attestation | attested | — | attestation format for run-identity | full CI supply-chain weight |

**Cross-cutting lesson:** every capability the prompt frames as a HuntMCP innovation already exists as a product or
paper on the *general* agent axis. HuntMCP's only defensible differentiation is **the security-research object model
(CEM + evidence + reproducibility)** — which argues for spending the innovation budget on §23/§25 (which *compound with
CEM*), not on re-implementing sandboxes/brokers/benchmarks that mature vendors already ship.

*Sources:* [Spheron sandbox guide](https://www.spheron.network/blog/ai-agent-code-execution-sandbox-e2b-daytona-firecracker/), [amux sandboxing](https://amux.io/guides/ai-agent-sandboxing/), [Northflank Daytona vs E2B](https://northflank.com/blog/daytona-vs-e2b-ai-code-execution-sandboxes), [AgentDojo](https://www.emergentmind.com/topics/agentdojo-benchmark), [Adaptive Adversaries](https://arxiv.org/html/2607.18063), [Agentic Security survey](https://arxiv.org/pdf/2510.06445), [Infisical Agent Vault](https://infisical.com/blog/agent-vault-the-open-source-credential-proxy-and-vault-for-agents), [CyberArk Secretless](https://github.com/cyberark/secretless-broker), [SLSA/in-toto](https://secure-pipelines.com/ci-cd-security/artifact-provenance-attestations-slsa-in-toto/), [Kettle](https://arxiv.org/pdf/2605.08363).

---

## 31. Cross-Domain Research (Loop 3)

- **Reproducible builds / attestation (in-toto, SLSA, Kettle)** → the §23 run-identity primitive (strongest import).
- **Version control / notebooks** → immutable evidence + late reconciliation (§20-B); the analogy is real but a git-DB
  is *not* needed (master roadmap rejection stands).
- **OS capability security (object-capability, seccomp, user-ns)** → §11/§14; adopt mechanisms, defer bespoke model.
- **Incident response / forensics** → hash-chained audit + provenance labels (§39).
- **Active automata learning / stateful property testing (Schemathesis, RESTler)** → already imported by UNKNOWN-UNKNOWN
  Opp-6; noted, not this axis.

No forced novelty. The only cross-domain item that both (a) is underexploited in security-research tooling and (b)
compounds with HuntMCP's actual moat is **provenance-attestation-for-finding-reproducibility**.

---

## 32. Library / Dependency Analysis

| Capability | Library | Maturity | License | Local/offline | Verdict |
|---|---|---|---|---|---|
| Rootless container exec | Podman / runc + user-ns | high | Apache/GPL | yes | **INVESTIGATE** (spike; no Python dep, subprocess) |
| Syscall isolation | gVisor (`runsc`) | high | Apache | yes | **INVESTIGATE** (tool tier) |
| microVM | Firecracker/Kata | high | Apache | KVM only | **REJECT (now)** / gated-remote |
| Provenance format | in-toto (`in-toto` py) or hand-rolled JSON | med/high | Apache | yes | **INVESTIGATE** (or stdlib JSON + sha256 — prefer stdlib first) |
| Secret broker | Infisical Agent Vault / cyberark secretless-broker | high | MIT/Apache | yes | **GATED ADOPT** (do not build) |
| Attestation signing | `sigstore`/`cryptography` | high | Apache/BSD | yes | **OPTIONAL** (XYZ already calls signing a nicety) |
| Info-flow / policy | OPA (rego) | high | Apache | yes | **REJECT (now)** — hook + Python suffices at scale |
| Taint labels | (schema field) | n/a | n/a | yes | **stdlib** — no dep |

**Rule honored:** never add a dependency for popularity. Every "INVESTIGATE" is a subprocess or a schema, not a heavy
runtime dependency; the two real dependencies (broker, in-toto) are both *gated/optional* and both adopt-not-build. The
strongest single unlock is **rootless containers** — a large security capability from an existing OS mechanism with no
new Python dependency.

---

## 33–34. Baseline Capability Composition & Emergent Capabilities

The prompt's most important instruction: search for *emergent* properties, not features. The composites that are real
and cheap because the parts already exist:

- **content-addressed evidence + CEM controls + tool_resolver chokepoint** → **§23 reproducible research-run** (the
  recommended primitive). *A + B + C already exist; only the join is missing.*
- **watch-mcp snapshots + hypothesis/case store + CEM** → **delta-driven causal re-validation / patch-bypass regression**
  (§25). *All parts exist; wire them.*
- **scope hook + budget + audit + (new) sandbox + (scoped) secrets** → **a security-native execution boundary** for an
  offensive agent — the composite the audit's findings point at.
- **audit log + provenance labels + evidence lineage** → **incident forensics** (§39) at near-zero cost.

The genuinely emergent capability is the first one: HuntMCP could become the tool whose findings *stay reproducible*,
which is the market's scarce good (XYZ's own thesis) and which no general agent-sandbox vendor provides because none of
them has the finding/CEM object model.

---

## 35. Lifecycle Security

For any future sandbox/broker, security must survive create→start→run→pause→resume→checkpoint→snapshot→fork→restore→
migrate→upgrade→reconnect→terminate→delete. The near-term relevance: even *without* a full lifecycle, the two
already-real transitions matter — **session start** (does the new session inherit the right scoped secrets and policy
version?) and **termination** (are agent-spawned background processes and temp files reaped? `job_runtime` reaps jobs;
agent-authored PoC processes are *not* tracked). **Recommendation: if a sandbox is adopted, per-run teardown solves most
lifecycle-security concerns for free (ephemeral by construction).** Do not design a full lifecycle state machine now.

---

## 36. Cross-Workspace Covert Channels

Today, "workspaces" share `$HOME`, package caches, `/tmp`, DNS, and the machine — so isolation is by *path convention*,
not enforcement, and covert/side channels are wide open (they are simply not a threat in a single-operator model). This
becomes a real concern *only* with mutually-distrusting concurrent agents or multi-user — deferred with that trigger. If
a per-engagement sandbox is adopted, direct isolation (separate mounts/tmp/caches) is largely free; information-flow
isolation (timing, DNS) is explicitly out of scope for a local single-operator tool.

---

## 37. Identity / Root of Trust

Prompt §33's rule — *possession of an identifier is not authorization* — is currently moot (no network-exposed
handles; everything is local files under one user). It becomes load-bearing only if a control plane or remote workers
appear. **Do-not-regret note:** if the §23 run manifest and evidence are ever synced/shared, their IDs must be
server-bound / capability-owned, not guessable — cheap to design correctly now (content-addressing already helps),
expensive to retrofit. Recorded in §46.

---

## 38. Resource / Cost Isolation

`budget_guard` (call count) is the current resource boundary; it is a *safety* budget, not a per-workspace *resource*
isolation. CPU/RAM/disk/process/FD/egress limits do not exist. With a sandbox, cgroup limits come nearly free and
should be set (a runaway or hostile agent must not exhaust the host). **Distinguish safety budget (already exists) from
research budget (call-count is a proxy) from resource limits (add via cgroups when sandboxing).** Budget authority
being capability-scoped is a deferred (§14) concern.

---

## 39. Failure / Recovery Semantics

Per component, the fail behavior *should* be: policy engine/scope hook → **fail-closed** (today it fails *open* —
audit SPOF finding; this is the single most important fix on this axis after execution isolation); audit store →
fail-closed (do not act unaudited on state-changing ops); secret broker (if adopted) → fail-closed; sandbox runtime →
fail-closed; provider API → degrade/pause (not a safety boundary). **Recommendation: harden the scope hook to
fail-closed and add a CI smoke test that the hook actually blocks (audit already recommends this).** Do not blanket-
fail-closed everything (would break legitimate work); choose per operation class.

---

## 40. Human Approval Security

The current model has approvals (`edit: ask`, human-review-before-submit — a *tested* invariant: `hackerone-mcp` has no
submit call at all). The gap is **binding**: an approval should be scoped to (exact action, resource, session, policy
version, expiry, one-shot). Approval fatigue and misleading summaries are real; the mitigation is *fewer, better-scoped*
prompts (which execution isolation enables — most tool runs need no approval if they cannot escape the sandbox). This is
achievable at the hook layer without a capability system (§15).

---

## 41. Security Policy Versioning

Nothing versions the scope/policy/sandbox/agent config today. When state is restored from a snapshot or an engagement
is resumed weeks later, it runs under *whatever policy is current*, which could be weaker or incompatible. The §23 run
manifest naturally captures policy/prompt version, which is the cheap fix: **record the policy version with the run**,
and refuse to *replay* a run under a mismatched policy without explicit acknowledgement. Recorded in §46.

---

## 42. Compromised Agent vs Compromised Tool

Distinct threats, both currently under-contained:
- **Compromised/injected agent** wielding legitimate tools → contained by §11 sandbox + §16 scoped secrets + §39
  fail-closed monitor.
- **Compromised MCP server / tool output** returning malicious data → contained by §17 quarantine (UU-7) + §18
  provenance labels; the tool itself is contained by §11.
- **Malicious skill / package / hostile repo** → §19 (sandbox the execution + pin/SBOM); `content_scanner.py` already
  scans new skill/MCP content (partial coverage).
- **Malicious provider** → out of scope for now (BYOK deferred).

The unifying observation: **one control (execution isolation) contains four of these threats at once**, which is why it
is the highest-leverage security investment on this axis.

---

## 43. What We Should NOT Build (researched rejections)

- **A control plane with users/projects/tenants/policies/lifecycle-manager** — no scale justifies it; premature (matches
  memo/master-roadmap discipline).
- **microVMs locally** — overkill; rootless/gVisor is the practical boundary; keep microVM behind the exec abstraction
  for future remote only.
- **A bespoke capability-authority / secret-broker system** — mature off-the-shelf; adopt-when-triggered, never build.
- **A graph DB / event-sourcing / SCM** — already rejected by prior research; nothing here changes that.
- **A generic AI IDE / chat app / agent marketplace / provider marketplace** — not the product (§29).
- **A "wind tunnel" as a novel benchmark product** — the concept is prior art; build only a small adversarial regression
  test on the existing benchmark substrate.
- **Cloud/K8s/queues/object-storage/billing** — deferred with explicit triggers (§26).
- **Multi-agent shared mutable live-discovery state (Strix-style)** — reintroduces the contamination CEM/§20-B avoid.

---

## 44. Top Innovation Candidates (survivors of the §28 filter)

Only candidates that (a) compound with CEM, (b) are strengthened by evidence/isolation, (c) are buildable and
benchmarkable, and (d) are not prompt-reproducible survive.

**C1 — Reproducible Research-Run Identity (Environment-as-Evidence).**
*Problem:* findings decay because their reproduction context is unrecorded. *Existing approach:* CEM records controls +
request/response; environment identity is missing. *Closest prior art:* in-toto/SLSA/Kettle (build provenance). *What
HuntMCP does differently:* applies attestation to *security-finding* reproduction, joined to CEM's causal verdicts —
a rare composition no agent-sandbox vendor offers (none has the finding model). *Baseline used:* content-addressed
evidence, CEM controls, tool_resolver chokepoint, watch snapshots. *New required:* a run-manifest schema + capture
hooks. *Security implication:* also captures policy version (§41) and provenance (§18). *Difficulty:* low-medium.
*Failure mode:* manifest completeness drift → treat missing fields as `unknown`, never fabricate. *Counter-hypothesis:*
"a triager doesn't care about tool versions" — test via the A/B acceptance metric XYZ already defines. *Benchmark:*
replay a stored run months later; measure reproduction fidelity. *Novelty confidence:* **rare composition** (not
invention). *Recommendation:* **decide now, build small.**

**C2 — Security-Native Execution Boundary (rootless per-run sandbox + fail-closed monitor + scoped secrets).**
*Problem:* the TCB is the whole host; one injected agent = total compromise. *Existing approach:* policy hook on broad
bash (SPOF-allow-all). *Closest prior art:* Strix Docker isolation; Daytona gVisor; CaMeL reference monitor. *What
HuntMCP does differently:* isolation profile tuned for an *offensive* agent that intentionally ingests hostile content
(inverted threat model) + secrets kept out of the untrusted tier. *New required:* container runtime integration behind
`tool_resolver`; hook hardened to fail-closed. *Difficulty:* medium. *Failure mode:* over-blocking breaks legitimate
tools → measure legitimate-task utility (§38). *Counter-hypothesis:* "single-operator local doesn't need it" — partly
true, but injection (threat #1) applies regardless of operator count. *Benchmark:* the §12 adversarial regression
(canary-secret exfil via hostile tool output; out-of-scope action). *Novelty confidence:* **none** (adopt existing
tech). *Recommendation:* **adopt as a security control (not a platform).**

**C3 — Delta-Driven Causal Re-Validation (target snapshot → affected hypotheses → CEM re-run).**
*Problem:* re-hunting starts from zero; patch-bypass/regression is manual. *Baseline used:* watch-mcp snapshots +
case/hypothesis store + CEM (all exist). *New required:* the join + an "affected hypotheses" query. *Closest prior
art:* XYZ Phase 5 already names it; this is *wiring*, not new research. *Difficulty:* low. *Benchmark:* inject a target
change; measure re-hunt precision vs cold start. *Novelty confidence:* low (it's plumbing) but **high ROI**.
*Recommendation:* **strong small win; aligns with XYZ P5.**

**Rejected/deferred candidates** (did not survive): capability-authority system (prompt-adjacent to deferred V4 layer +
mostly subsumed by C2); secret broker as a build (adopt-not-build); multi-agent parallel investigation (design-only
backlog, cost-unproven); wind tunnel as a product (prior art).

---

## 45. (see §44)  ·  ## 46. "Do Not Regret Later" Register

| Decision | Classification | Why |
|---|---|---|
| **Research-run identity / evidence-env manifest** | **DECIDE NOW** | Retrofitting reproducibility onto un-captured runs is impossible; cheap to capture from the start (C1). |
| Evidence identity = content-addressed | **already decided (keep)** | present; correct. |
| Execution boundary abstraction (swappable) | **DECIDE NOW (shape), defer impl** | so microVM/remote can slot later without a domain change. |
| Secrets scoped-not-global into execution | **DECIDE NOW (posture)** | stop full-`.env` injection; broker itself deferrable. |
| Policy/version stamping on runs | **DECIDE NOW (record it)** | enables §41 without a versioning subsystem. |
| Handle/identity server-binding | **MUST NOT LOCK YET** | only matters with remote; content-addressing already helps. |
| Capability-authority model | **SAFE TO DEFER** | subsumed by C2 near-term; heavy. |
| Control plane / cloud / storage abstraction | **SAFE TO DEFER (with triggers)** | no scale justifies now. |
| Multi-writer shared state | **MUST NOT LOCK YET** | prefer immutable-evidence model (§20-B). |

---

## 47. Counter-Hypotheses (trying to prove the platform direction wrong)

| # | Counter-hypothesis | Evidence for | Evidence against | Decisive experiment |
|---|---|---|---|---|
| A | Current HuntMCP + a deployment sandbox is sufficient | Most value is C1/C2/C3, all small | The scope-hook SPOF + no exec isolation are real gaps | Run the §12 injection test on today's system; measure containment |
| B | Workspace abstraction is unnecessary | engagement/session already suffice | — | none needed — **accepted**; "run" not "workspace" is the primitive |
| C | Persistent state creates more problems than value | more state = more leakage surface | but reproducibility is the moat | measure retest/acceptance uplift from C1 |
| D | Evidence/research-run is the real primitive, not workspace | strongly supported by CEM thesis | — | **accepted** (§9) |
| E | Capability authority is too complex | mature but heavy; subsumed by C2 | injection still needs a monitor | build fail-closed monitor first, measure residual risk |
| F | Secret broker adds too much latency/complexity | scoping secrets gets 80% cheaper | remote needs a real broker | scope secrets; measure |
| G | Local-first becomes a cloud dead-end | risk if domain model leaks host assumptions | run/evidence abstractions are portable | keep exec boundary swappable (§26) |
| H | Agent abstraction reduces model/runtime quality | LCD protocol would | config-generator (Arch B) doesn't | already answered by UNIVERSAL-CAPABILITY |
| I | microVM too expensive locally | true | — | **accepted** — use rootless/gVisor |
| J | Parallel independent research isn't worth the cost | cost multiplies; unproven | could cut bias | measure recall/FP vs cost before building |
| K | The "innovations" are prompt-reproducible → no moat | true for wind tunnel, brokers | C1 needs schema+capture, not a prompt; compounds with CEM | can a prompt alone produce a replayable run months later? no |

**Net:** the platform-as-major-layer hypothesis is **substantially disproven**; the additive-substrate (C1/C2/C3)
hypothesis **survives**.

---

## 48. What We Should NOT Build — see §43.

## 49. Top Innovation Candidates — see §44.

## 50. Innovation Scorecard

Scores 1–5 (5 = best), no inflation.

| Candidate | Novelty | Utility | Security | CEM synergy | HuntMCP synergy | Benchmarkable | Impl. ease | Dep. cost (5=low) | Local | Cloud-ready | Compounding | Confidence | **Total /60** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **C1 Research-run identity** | 3 | 5 | 4 | 5 | 5 | 4 | 4 | 5 | 5 | 4 | 5 | 4 | **53** |
| **C2 Exec boundary** | 1 | 4 | 5 | 3 | 4 | 4 | 3 | 4 | 5 | 4 | 3 | 4 | **44** |
| **C3 Delta re-validation** | 2 | 4 | 2 | 5 | 5 | 4 | 3 | 5 | 5 | 3 | 4 | 4 | **46** |
| Capability authority | 3 | 3 | 5 | 2 | 2 | 3 | 2 | 3 | 4 | 4 | 3 | 3 | 37 |
| Secret broker (build) | 1 | 4 | 5 | 1 | 2 | 3 | 2 | 2 | 4 | 4 | 2 | 3 | 33 |
| Multi-agent parallel | 2 | 3 | 2 | 4 | 3 | 3 | 2 | 4 | 4 | 3 | 3 | 2 | 35 |
| Wind tunnel (product) | 1 | 3 | 4 | 2 | 3 | 5 | 3 | 4 | 5 | 3 | 2 | 3 | 38 |

**Ranking:** C1 (53) > C3 (46) > C2 (44) ≫ others. C2 scores lower on novelty/synergy but is the **security floor** —
recommended not because it's differentiated but because the audit shows it's *needed*. (C3's impl-ease was corrected
5→3 per self-audit §63; ranking unchanged.)

---

## 51. Architecture Options

| | **A — Sandbox as deployment detail only** | **B — Additive persistent+evidence substrate (RECOMMENDED)** | **C — Local-first platform (control plane)** |
|---|---|---|---|
| Change | containerize deployment; nothing else | C1 run-identity + C3 delta + C2 exec boundary + scoped secrets + fail-closed hook | + control plane, capability leases, secret broker, cloud-ready |
| Security | modest (root fixed) | strong (contains 4 threats, reproducible, fail-closed) | strongest (but large TCB to secure) |
| CEM synergy | none | **high** (C1/C3 compound) | high but diluted by infra work |
| Complexity | trivial | moderate, incremental | high |
| Cloud migration | unaffected | swappable exec boundary keeps it open | native |
| Risk | leaves real gaps | low (each item reversible) | premature; distracts from CEM moat |
| Verdict | insufficient | **adopt** | defer (with triggers) |

---

## 52. Smallest High-Leverage Change

**Smallest change unlocking the largest capability:** the **§23 research-run manifest** (C1) — it turns HuntMCP's
existing evidence + CEM into *durable, replayable proof*, which is precisely the market-scarce good XYZ identifies, for
the cost of a schema + a few capture hooks.

**Strongest long-term architecture:** Option B (additive substrate), reached incrementally.

**Are they the same change?** **Partly.** C1 is both the smallest high-leverage change *and* the load-bearing piece of
the long-term architecture — so they point the same direction. C2 (exec boundary) is a *different* change (a security
floor), needed for the long-term architecture but not the highest-leverage capability unlock. **Answer: the smallest
high-leverage change (C1) is a subset of, not identical to, the long-term architecture (B).**

---

## 53. Recommended Long-Term Architecture

**Option B, built in dependency order, with CEM untouched and the reasoning/discovery roadmap (MASTER-ROADMAP)
unchanged.** HuntMCP stays a **local-first security-research application** whose differentiator is a *reproducible
finding/CEM object model*, running untrusted execution below a swappable isolation boundary, with secrets scoped out of
that boundary and a fail-closed policy monitor above it. No control plane, no cloud, no capability subsystem, no broker
build — those are deferred with explicit triggers. The end-state is **not** "a platform"; it is "the hunter whose proofs
don't decay and whose compromised-agent blast radius is bounded."

---

## 54. Migration Strategy (illustrative dependency order — not an authorization to build)

1. **Foundation (no behavior change):** harden scope hook to **fail-closed** + CI smoke test (fixes SPOF); pin tools +
   SBOM (fixes supply-chain). *Stays unchanged:* everything else. *Rollback:* revert config.
2. **C1 run-identity manifest** (additive schema + capture hooks; extends CEM bundle). *Gate:* replay fidelity on stored
   runs.
3. **C3 delta re-validation** (wire watch snapshots → hypotheses → CEM). *Gate:* re-hunt precision vs cold start.
4. **C2 exec boundary** (rootless container per run behind `tool_resolver`; scope secrets out of it; cgroup limits).
   *Gate:* §12 injection regression (containment **and** legitimate-task utility).
5. **Deferred (triggers):** secret broker (remote/many-keys); capability authority (multi-trust agents); parallel
   investigation (measured bias/recall win); remote workers / microVM (cloud demand); control plane (multi-user).

Each stage: what stays / changes / security impact / rollback / benchmark / exit criterion is stated inline; none
requires a rewrite; each is independently reversible.

---

## 55. Benchmark Strategy

Reuse the master roadmap's committed P0-BENCH substrate; add adversarial cases (not friendly demos):
- **C1:** stored-run replay fidelity (does a run reproduce months later from its manifest?).
- **C2:** §12 adversarial regression — canary-secret exfil via hostile HTTP/tool output; out-of-scope action attempt;
  hostile-repo checkout; each measured for containment, blast radius, recovery, **and legitimate-task utility**
  (security/utility frontier, §38). Include a *lifecycle* pass (§58), not only fresh instances.
- **C3:** target-delta → re-hunt precision/recall vs cold start.
- **Static + adaptive** where cheap (a scripted adaptive injection over multiple turns), acknowledging the field lacks a
  standard adaptive protocol (§12).

**Protected-benchmark discipline (per `.claude/rules/benchmarks.md`):** oracles independent of implementation; canary
secrets are the success signature for exfil (explicit, not auto-derived); ground truth (planted target deltas, planted
injections) kept separate from implementation.

---

## 56. Security Gates (invariants that must never regress)

1. No target-controlled data causes a state-changing/out-of-scope action without an out-of-model deterministic check.
2. Scope enforcement fails **closed**, not open.
3. Untrusted execution cannot read the full secret set.
4. Evidence is immutable/content-addressed; audit is append-only (ideally hash-chained).
5. `update_finding_status` evidence-gate and human-review-before-submit stay intact (both currently *tested* controls).
6. Budget/scope/audit are never bypassed by a new feature (matches `.claude/rules/security.md`).
A new capability that conflicts with any of these: **safety wins** (prompt §56).

---

## 57. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Platform work diverts from CEM moat | med | high | This doc recommends *only* CEM-compounding additions (C1/C3) + a security floor (C2); everything else deferred |
| Sandbox over-blocks legitimate tools | med | med | measure legitimate-task utility in every §12 test |
| C1 manifest fabricates missing fields | low | high | `unknown` never fabricated (matches CEM anti-hallucination invariant) |
| Adopting a broker/microVM prematurely | med | med | explicit trigger conditions; adopt-not-build |
| Scope-hook fail-closed breaks workflows | med | low | staged rollout + CI smoke test |
| Novelty overclaim | low | med | §65 honesty; every item labeled rare-composition or adopt |

---

## 58. Security Lifecycle Testing

Benchmarks must exercise create→run→pause→resume→snapshot→restore→terminate→delete, not just fresh instances (§35).
Near-term the two live transitions to test: (a) resumed engagement inherits correct scoped secrets + policy version;
(b) termination reaps agent-spawned processes/temp state. Ephemeral-by-construction sandboxes (per-run teardown) satisfy
most of this for free.

---

## 59. Human Decision Questions

*(2–5 options each; surfaced, not decided — per prompt §59/§60, planning docs are replanned only after explicit human
confirmation.)*

1. **Long-term identity.** A) security-research *engine* (status quo, CEM-only) · B) engine + additive
   evidence/isolation substrate (**this doc's recommendation**) · C) local-first security-research *platform* (control
   plane) · D) hybrid.
2. **Primary primitive.** A) engagement (status quo) · B) engagement + **research-run** (**recommended**) · C) workspace
   (container) · D) full hierarchy (project/user/tenant).
3. **Sandbox.** A) none / deployment-only · B) **rootless container per run** (**recommended**) · C) gVisor · D)
   microVM · E) trust-tiered hybrid (defer).
4. **Execution model.** A) local only · B) **local-first + swappable boundary for future remote** (**recommended**) ·
   C) remote-ready from start.
5. **Secrets.** A) status-quo `.env` · B) **scope secrets out of untrusted execution now** (**recommended**) · C) adopt
   an off-the-shelf broker now · D) build a broker.
6. **Main innovation priority (pick 1–2).** A) **C1 research-run identity** · B) **C3 delta re-validation** · C) C2 exec
   boundary (security floor) · D) capability authority · E) parallel investigation · F) wind tunnel.
7. **Persistence/evidence.** A) status quo · B) **+ run manifest + hash-chained audit + lineage** (**recommended**) · C)
   event log/materialized · D) research recommendation.
8. **Multi-session (same target).** A) shared mutable · B) **isolated exec + shared immutable evidence**
   (**recommended**) · C) branch-local + merge · D) keep single-writer.
9. **Immediate security fixes (independent of the above).** Approve: scope-hook **fail-closed** + CI smoke test; tool
   pinning + SBOM; scope secrets out of untrusted execution; `--os-shell` confirmation tier (audit Decision 8). (These
   are the cheapest, highest-value items and gate nothing.)
10. **Product boundary.** A) CLI/tool · B) **local application** (**recommended**) · C) local-first platform · D) future
    hosted.

---

## 60. Decision-Dependent Replanning Notes

- If Q1=B, Q2=B, Q6∈{A,B}: the next planning task adds a **small "Reproducibility & Isolation" cross-cutting track**
  *alongside* (never inside) the frozen CEM slice and *after* the master roadmap's Phase-2 foundation — it does not
  reorder the CEM/reasoning phases.
- If Q9 approved: those four fixes can proceed as a self-contained security-hardening task independent of any platform
  decision (they are the audit's already-identified items).
- If Q1=C or Q6∈{D,E,F}: a separate feasibility spike is required first; not recommended by this research.
- **No planning document is to be edited until the human answers Q1/Q2/Q6/Q9**; contradictions with XYZ/MASTER-ROADMAP
  (there are none expected — this axis is additive) are resolved in favor of the frozen CEM thesis.

---

## 61. Final Recommendation

**Do not turn HuntMCP into a platform.** Adopt **Option B: an additive persistence + evidence-identity + isolation
substrate**, built smallest-first, with CEM and the reasoning/discovery roadmap untouched.

**Answers to the mandated questions (§64/§67), condensed:**

- **Should HuntMCP become a platform?** No — an *additive substrate*, yes.
- **Sandbox: primitive or deployment detail?** A **security control** (deployment-ish), adopting rootless containers —
  not an architectural primitive.
- **Correct hierarchy?** `engagement → session → research-run → {experiments, evidence}` — adds *one* concept.
- **Security boundary / TCB?** Today the TCB is the whole host; the goal is to shrink it so policy/evidence/secrets sit
  *above* an isolated execution tier.
- **Capability-based authority?** Defer the bespoke model; harden the hook into a fail-closed action monitor instead.
- **Secrets invisible to agents?** Scope them out of untrusted execution now; adopt an off-the-shelf broker only when
  remote/scale triggers hit — never build one.
- **Evidence immutable / environments replayable?** Evidence: already yes, add lineage. Environments: replay the
  *research-run manifest*, not a VM.
- **Sessions share state?** Isolated execution + shared *immutable* evidence.
- **Multiple agents independent?** Only if a measured bias/recall win justifies the cost; design-only for now.
- **Local-first first-class?** Yes; keep the execution boundary swappable for future remote.
- **What must be cloud-ready now?** Only the run/evidence abstractions (they already are). Nothing else.
- **The 2–3 innovations that survive:** **C1 (reproducible research-run identity)** and **C3 (delta-driven causal
  re-validation)** as capability wins; **C2 (security-native execution boundary)** as a required floor. C1 is a rare
  composition; C2/C3 are adopt/plumbing — no novelty overclaimed.
- **What NOT to build:** control plane, microVM-local, bespoke capability/broker, graph DB, AI IDE, wind-tunnel-as-
  product, cloud infra (§43).
- **What makes this different from a generic AI coding environment?** The security-research object model — CEM +
  evidence + reproducibility — which no agent-sandbox vendor has, and which C1/C3 *compound*.

**Truth > novelty:** the strongest result of this research is not a new capability — it is the finding that the
platform hypothesis, taken literally, would divert HuntMCP from its one genuine moat (CEM/proof). The right move is a
small, additive, evidence-compounding substrate plus a security floor the audit already demanded. If the human decides
even that is not worth it now, **Q9's four security fixes alone** are the irreducible, unconditional recommendation.

---

## 62. Decisions Locked (human interaction, 2026-09-13) + Decision-Dependent Replan

The §59 questions were put to the operator and answered. **All ten answers matched the recommended option**, so no
contradiction reconciliation was required.

| # | Question | Locked answer |
|---|---|---|
| 1 | Long-term identity | **Engine + additive substrate** (Option B) |
| 2 | Primary primitive | **Engagement + research-run** (`engagement → session → research-run → {experiments, evidence}`) |
| 3 | Sandbox | **Rootless container per run** |
| 4 | Execution model | **Local-first + swappable boundary** |
| 5 | Secrets | **Scope secrets out of untrusted execution now** (broker deferred) |
| 6 | Innovation priority | **C1 research-run identity + C3 delta re-validation** (both) |
| 7 | Persistence/evidence | **+ run manifest + hash-chained audit + lineage** |
| 8 | Same-target multi-session | **Isolated exec + shared immutable evidence** |
| 9 | Immediate security fixes | **All four approved** (fail-closed hook+CI, pin tools+SBOM, scope secrets out, os-shell confirm tier) |
| 10 | Product boundary | **Local application** |

### 62.1 Preserved invariants (unchanged by these decisions)
- **CEM Phase-1 stays FROZEN.** The new work only *reads* CEM output; it never modifies the frozen slice.
- Scope / budget / audit / evidence-gate / human-review-before-submit remain intact (§56).
- The MASTER-ROADMAP CEM/reasoning/discovery phases are **not reordered**; the new work is an *additive cross-cutting
  track*, in the same shape as the existing Security/Reliability and Benchmark tracks.
- Rejections stand: no control plane, no local microVM, no bespoke capability/broker build, no graph DB, no AI IDE, no
  cloud infra, no live shared-discovery multi-agent state.

### 62.2 Changed assumptions vs prior docs (to reconcile if the roadmap is replanned)
- The MASTER-ROADMAP had **no isolation/reproducibility track**; Track R is new and additive.
- MASTER-ROADMAP §17's "After P2 … replayable" meant *experiment/telemetry lineage*; **R1 gives "replay" a concrete
  environment-run meaning** (superset). Reconcile the wording, not the intent — no contradiction.
- UNIVERSAL-CAPABILITY-EXPOSURE's V4 capability/tool-exposure item is **unchanged**; R4's fail-closed *action monitor*
  is not that capability system.

### 62.3 Proposed additive **Track R (Reproducibility & Isolation)** — dependency-ordered
> *Proposal only. None of this is authorized to build; §62.5 lists what a build/replan requires.*

- **R0 — Unconditional security hardening** *(Q9; self-contained; gates nothing; can proceed as its own authorized
  task):* fail-closed scope hook + CI smoke test; pin tool versions + SBOM; scope secrets out of untrusted execution
  (also satisfies Q5); `sqlmap --os-shell` human-confirmation tier.
- **R1 — Research-run identity manifest (C1)** *(the primitive):* schema + capture hooks at `tool_resolver` and the CEM
  bundle; records target-snapshot hash + tool versions + agent + model + policy/prompt version + CEM controls +
  evidence hashes; content-addressed; **prefer stdlib JSON + sha256 first**, in-toto format optional. Reads CEM, does
  not modify it. *Gate:* stored-run replay fidelity months later.
- **R2 — Evidence integrity (Q7):** hash-chain the audit log; formalize evidence→experiment→verdict→finding→report
  lineage (FKs already exist); add source-trust/provenance labels at capture. Satisfies the Q8 "shared immutable
  evidence" model. *Gate:* tamper-evidence + lineage-completeness tests.
- **R3 — Delta-driven causal re-validation (C3):** wire watch-mcp target snapshots → affected-hypothesis query → CEM
  re-run (patch-bypass regression). Depends on R1 + existing watch/case/CEM. *Gate:* re-hunt precision/recall vs cold
  start.
- **R4 — Execution boundary (C2):** rootless container per run behind `tool_resolver`; cgroup resource limits; boundary
  kept swappable (Q4) for future remote. Depends on R0 (scoped secrets, fail-closed hook). *Gate:* §12 adversarial
  regression — canary-secret exfil via hostile tool output, out-of-scope action, hostile-repo checkout — measuring
  containment + blast radius + recovery **and** legitimate-task utility; include a lifecycle pass (§58).
- **Deferred with explicit triggers:** secret broker (remote/many keys/untrusted third-party MCP); capability authority
  (mutually-distrusting agents); parallel independent investigation (measured bias/recall win); microVM/remote workers
  (cloud demand); control plane (multi-user). Wind tunnel = R4's benchmark, **not** a product.

### 62.4 New dependencies implied (for approval at build time)
- Rootless container runtime (Podman/`runc` + user-ns) — invoked as a subprocess; **no new Python dependency**.
- in-toto attestation library — **optional**; stdlib JSON + `hashlib` is the default first cut.
- Everything else is stdlib / schema fields. No heavy runtime dependency is introduced.

### 62.5 What a real replan of the PROTECTED docs would require (NOT done here)
Editing `ROADMAP.md`, `MASTER-ROADMAP-PROPOSAL.md`, `HUNTMCP-NEXT-GEN-EXECUTION-PLAN.md`, or `XYZ.md` is a
protected-planning-file change and needs a **separate, explicitly-scoped, human-authorized task** (same precedent as
MASTER-ROADMAP Decision 10). If authorized, that task would: (a) add Track R as an additive cross-cutting track in
`ROADMAP.md`; (b) fold R0–R4 into `MASTER-ROADMAP-PROPOSAL.md` §7/§8/§14 and record these 10 answers in §16, plus the
§17 "replay" wording reconciliation; (c) add R0–R4 tasks to `HUNTMCP-NEXT-GEN-EXECUTION-PLAN.md` with the status
legend. `XYZ.md` needs **no** change (CEM is untouched; R3 only consumes it).

---

## 63. Self-Audit (independent skeptical review of this document, 2026-09-13)

Every load-bearing claim was re-verified against code (not against this document's own earlier prose). Findings:

**Confirmed (re-verified against source):**
- Execution-isolation / capability-security / secret-broker / provenance primitives absent in code (grep = 0). ✓
- Content-addressed SHA-256 evidence + evidence-gated CONFIRMED (`case_store.py`). ✓
- Per-engagement + per-session state isolation, `file_lock`, WAL (`engagement_paths.py`, `file_lock.py`). ✓
- `hackerone-mcp` exposes only `sync_program_scope` + `check_my_duplicates` (read-only; explicit "must never submit"
  comment). **Independently verified**, not just cited from the audit. ✓
- Dockerfile has no `USER` directive (root). ✓
- Scope hook is deliberately narrow: gates `rm` + target-host-touching Tier-2/curl/wget only; does **not** gate file
  writes, `pip/go install`, or WebFetch (`scripts/hooks/scope_gate_hook.py`). ✓
- Scorecard arithmetic: all row totals recomputed and correct. ✓

**Corrections applied to this document:**
1. **§10 secret-exposure mechanism was imprecise** (direction right, detail wrong). Fixed: the exposure is the
   plaintext `.env` file at repo root readable by any allowed `bash` (not gated), **plus** a full-`.env` load into
   `os.environ` for the four servers that call `dotenv_loader.load_dotenv_if_present()` — not "all keys in every
   process env." Conclusion unchanged; §16/Q5 recommendation sharpened (two-part fix: per-key loading + file not
   mounted in the sandbox).
2. **§10 hook-tamper was understated.** Verified feasible and effective: bash file-writes are ungated and the hook is
   re-invoked per call, so an agent can neuter it mid-session. This *strengthens* the fail-closed (§39) and
   execution-boundary (C2) case rather than weakening it.
3. **C3 "plumbing" claim was an overstatement (§25/§33-34/§44/§52).** `watch.db` and `case.db` are entirely unlinked;
   the affected-hypothesis mapping is genuine new logic (medium effort), not wiring. Scorecard C3 impl-ease 5→3, total
   48→46. **Ranking (C1 > C3 > C2) and all recommendations unchanged.**

**Honest limitations of this research (not fixed — disclosed):**
- `PHASE1-PLAN.md` / `PHASE1-EXECUTION-PLAN.md` (CEM Phase-1, ~232 KB) were **not** read exhaustively; the claim
  "prior research leaves the platform axis essentially untouched" is well-supported by the docs that *were* read (and
  by an ARCHITECTURE grep that surfaced the one Strix/mantis sandbox note), but is not a 100% exhaustive proof.
- Several 2026 prior-art facts (Firecracker timings; CaMeL/FIDES/Progent/RTBAS/FORGE; Anthropic Workload Identity GA
  date) are **web-search-sourced summaries**, not primary-source-verified; they inform positioning, not any build
  decision.
- Whether a triager values a reproducibility manifest (C1's core bet) is **assumed, not measured**; XYZ's A/B
  acceptance metric is the decisive experiment and has not been run.

**Net audit verdict:** the document's central recommendations (Option B; C1 primitive; C2 security floor; C3 as a real
build; defer capability/broker/parallel/control-plane) **survive the audit**. Two §10 imprecisions were corrected (one
tightened, one strengthened) and one effort estimate (C3) was corrected downward in ease; none changes a decision. The
strongest residual risk is not an error in the analysis but an **unmeasured assumption** — that reproducibility
improves triager acceptance — which must be validated empirically before C1 is treated as proven value.
