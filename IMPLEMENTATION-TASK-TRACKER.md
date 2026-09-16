# IMPLEMENTATION-TASK-TRACKER.md — HuntMCP (from frozen `MASTER-ROADMAP-FINAL-v3.md`)

**Status:** Phase-S Tier-1 (S1–S4) implemented and CI-verified; S5 (Tier-2's rootless per-run execution boundary)
also implemented and verified with real end-to-end sandboxed tool calls (see §3 for per-task evidence). Everything
past that remains a planning artifact only — no Phase 2+ source code, roadmap, architecture, or thesis doc
modified beyond what §3 documents. Planning authority: `MASTER-ROADMAP-FINAL-v3.md` (frozen canonical).

**S5 completion is not an authorization to build past it.** Phase-3 breadth work specifically remains blocked
until Phase-S Tier-2's FULL exit gate (S5 done, S6 hook tamper-resistance, THEN S-GATE's own adversarial
regression across both together) completes — S-GATE has NOT passed. Implementation of anything beyond S5 begins
only when v3 §14 entry conditions are met, task by task, in dependency order.

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
| Scope enforcement | 3-layer + PreToolUse `scope_gate_hook.py` | yes | **[~] fail-closed + CI-verified (S1/S2 done)** | tamper-resist (S6) |
| Secret handling | `dotenv_loader.get_secret()` per-key lookup; env allowlist at every subprocess-spawn chokepoint (`run_tool()`, `job_runtime.start_job()`, `oob-mcp`); scope-hook `.env`-read block (best-effort) | yes | **[x] S3 done ([PR #106](https://github.com/ankitsingh015/HuntMCP/pull/106), merged `b04805d`)** | — |
| Engagement/state isolation | `engagement_paths.py`, `file_lock`, WAL | yes | [x] baseline | — |
| Cross-run memory/knowledge | memory/writeup/lessons-mcp | yes | [x] baseline | — |
| Continuous recon diffing | `watch-mcp` snapshots (⊥ `case.db`) | yes | [~] recon-only | watch↔case link (C3) |
| Authorization testing baseline | `idor-mcp sweep_idor` (single-request, two-account) | yes | [x] baseline | multi-step/role-matrix engine (VAL-AUTHZ) |
| Attack-chain DAG | `chainer-mcp` | yes | [x] baseline | — (this is "the graph"; no graph DB) |
| Human-review-before-submit | `hackerone-mcp` read-only (no submit tool) | — | [x] control | preserve |
| Budget / audit / jobs | `budget_guard.py`, `audit_log.py`, `job_runtime.py` | yes | [x] baseline | — |
| Toolkit-gap capture | `tool_gaps.py` (bounded first step) | yes | [~] capture only | human-gated growth (P5-TOOLKIT) |
| Second-opinion review | `second-opinion-mcp` (cross-model) | yes | [x] baseline | (env-isolation unexamined) |
| CI | `.github/workflows/ci.yml` (ruff, py_compile, bash -n, scope-gate-dispatch) | — | [~] | SAST/dep-audit (P2-SC) |
| Execution isolation / sandbox | `mcp-servers/sandbox_runner.py` (rootless Podman, both real chokepoints) | `test_sandbox_runner.py` + updated `test_tool_resolver.py`/`test_job_runtime.py` | **[x] S5 done** | S6 (hook tamper-resistance) |
| Telemetry / coverage / postmortem / provenance | **none** | — | **[ ]** | P2 work packages |
| schemathesis / discovery amplification | **absent** | — | **[ ]** | P3 |

---

## 3. Phase S — Security Floor (gating prerequisite; two tiers)

*Ordering (frozen, v3 §6/§14): Tier-1 before ANY autonomous breadth; **Tier-2 MUST complete before Phase-3 breadth
begins.** Tier-2 is NOT optional.*

| ID | St | Task · Why | Deps | v3 § |
|---|---|---|---|---|
| **S1** | [x] | Scope hook **fail-closed** for target-touching calls (internal error blocks the *gated call*, not the session). *Why:* current hook fails open; SPOF. | — | §6 Tier-1 |
| **S2** | [x] | CI **scope-gate block-test** — prove an out-of-scope call is actually blocked. *Why:* fail-open registration SPOF. Verified: [PR #103](https://github.com/ankitsingh015/HuntMCP/pull/103), merged `017a2cd` — the `scope-gate-dispatch` job ran green in GitHub Actions alongside the rest of CI, satisfying the §10 "CI run" evidence requirement. | S1 | §6 Tier-1 |
| **S3** | [x] | **Secrets-out** of untrusted execution — per-key injection; env-scrubbed subprocess spawn; best-effort `.env`-read block. *Why:* full-`.env` load is harvestable. `dotenv_loader.get_secret()` per-key lookup replacing the full-file loader across all 4 real call sites + `model_gateway.py`; env-scrub applied at every real subprocess-spawn chokepoint — `tool_resolver.run_tool()`, `job_runtime.start_job()` [the one real scans actually go through], and `oob-mcp`'s detached `Popen` — after code review found the first pass only covered `run_tool()`; `scope_gate_hook.py` blanket `.env`-read block covering `$(...)`/doubled-prefix/copy-command bypasses found in the same review, live-verified against the real PreToolUse hook. **Caveat, not overclaiming:** the Bash-level block is a best-effort heuristic (a `python3 -c` one-liner embedding the filename in a string literal still isn't caught — same class of acknowledged gap as the existing `rm`-block), not a hard boundary; real closure is S5/S6 sandboxing. Verified: [PR #106](https://github.com/ankitsingh015/HuntMCP/pull/106), merged `b04805d` — CI green. | S1 | §6 Tier-1 |
| **S4** | [x] | **`--os-shell` / state-changing confirmation tier** — explicit human confirm. *Why:* persistent RCE, no distinct gate today. `scope_gate_hook.py` blanket-blocks any sqlmap `--os-shell`/`--os-pwn`/`--os-cmd`/`--os-bof` Bash call (same unconditional category as the rm-block/`.env`-block, independent of scope; matches on the flag co-occurring with `sqlmap` anywhere in the sub-command, not just first-word position, closing a `timeout`/`xargs`-wrapper bypass found in review) unless a fresh, single-use confirmation token — **bound to the active engagement's exact target** (a code-review-found gap, corroborated by 5 independent review angles, fixed: `check_and_consume(target)` now refuses a token confirmed for a different target without burning it) — is on file. Token can only come from `scripts/confirm-os-shell.sh` → `rce_confirm.py`, gated on `stdin.isatty()`. Confirmed-and-allowed action is audit-logged (`sqlmap-os-shell-confirmed`, since a raw-Bash sqlmap call has no other audit path). The whole check runs inside its own fail-closed try/except (code-review finding, CONFIRMED: it previously sat outside the fail-closed net — an internal error would have failed *open*, reopening the exact S1 bug class one check later — fixed). Unit tests (`tests/test_rce_confirm.py`, `tests/test_scope_gate_hook.py`) + a real-pty "live prompt" test (`tests/test_confirm_os_shell_live.py`, matching the §10 acceptance table's own "live prompt" test type) + live-fired against the real PreToolUse hook subprocess. **Caveats, not overclaiming (code-review findings, CONFIRMED, deliberately not closed — this is Tier-1's own honest limit, not an oversight):** (1) the `isatty()` check is a speed-bump against accidental/naive self-confirmation, not a hard boundary — an agent with ordinary Bash access can spawn its own pty (stdlib `pty` module, exactly what this PR's own live test does to drive the script) and satisfy it without a human; (2) `check_and_consume()` does no cryptographic/provenance check on the token file — an agent with Write/Edit access can fabricate one directly at the path this module resolves to, bypassing `request_confirmation()` entirely. Both require the agent to actively work *around* its own safety rail using its own execution capability — closing that is S6's job ("hook tamper-resistance"), not a Tier-1 heuristic's; this mirrors the same floor-not-boundary caveat already recorded for S1's rm-block and S3's `.env`-block. Also narrow by design (only sqlmap's 4 named flags, matching the roadmap's own literal wording — not a general state-changing-action classifier for e.g. nuclei RCE templates or a webshell `curl`). Verified: [PR #107](https://github.com/ankitsingh015/HuntMCP/pull/107), merged `a380afb` — CI green (`Scope Gate Dispatch Test` + `Unit Tests` both passed), and re-confirmed green again on [PR #109](https://github.com/ankitsingh015/HuntMCP/pull/109) (unrelated `scope_gate_hook.py` changes for other bugs, same two CI jobs still pass, confirming S4's logic wasn't disturbed). | — | §6 Tier-1 |
| **S5** | [x] | **Rootless per-run execution boundary**, via **rootless Podman containers** (human decision resolved 2026-09-15, §8; Docker/Podman/nsjail/bubblewrap options weighed, Podman chosen — no root daemon, no host-level reconfiguration needed). *Why:* whole-host TCB. `mcp-servers/sandbox_runner.py` is the ONE shared argv-builder both real subprocess chokepoints call — `tool_resolver.run_tool()` and `job_runtime.start_job()` (the PRIMARY path: httpx/nuclei/katana/nmap/dalfox/ffuf/sqlmap/subfinder's real enumeration all go through `start_job()`, not `run_tool()`) — migrated in the same change, so there is no window where one sandboxes and the other doesn't. "Run" = one external tool-binary execution attempt (one `subprocess.run()`/`Popen()` call, including `run_tool()`'s own rate-limit retry as its own independent run) gets a fresh, uniquely-named scratch dir + a fresh `--rm` container from a single pinned, minimal image (`mcp-servers/sandbox/Dockerfile`, versions pinned to what was confirmed working, not `@latest` — the exact class of drift that broke nuclei's `-json` flag live). Approved-tool allowlist (`_TOOL_MAP`) covers every tool actually reachable through these two chokepoints, audited by grepping every real call site rather than assumed from memory: subfinder/httpx/katana/nmap/nuclei/sqlmap/dalfox/ffuf/curl/wget/gitleaks (secrets-mcp) + impacket's Kerberoasting scripts under all 3 host-name variants (ad-recon-mcp) — an unrecognized name raises `UnknownSandboxTool` before any subprocess is attempted, re-raised as `FileNotFoundError` at both chokepoints so every existing caller's own `except FileNotFoundError` handling needed zero changes. Isolation: `--cap-drop=ALL`, `--read-only` root fs (`--tmpfs=/tmp` for incidental scratch writes), `--security-opt=no-new-privileges`, `--pids-limit=50`/`--memory=512m`, env built ONLY from the same `minimal_subprocess_env()` allowlist S3 already uses (never `--env-host`, never a `$HOME` mount) — a second, independent enforcement of S3's guarantee, not a replacement for it. Mounts are **explicit-declaration-only**, never auto-detected: each calling MCP server passes `extra_mounts=` (read-only) / `extra_mounts_rw=` (read-write, opt-in) naming exactly the paths that specific call needs — `sqlmap-mcp`'s `--output-dir`, `httpx-mcp`'s `-l <input_path>`/`-srd <work_dir>`, `secrets-mcp`'s scan target + report dir, `ffuf-mcp`'s resolved wordlist file, `ad-recon-mcp`'s users file — each updated to pass its own real mount, plus a deny-list backstop (`_DENY_MOUNT_PREFIXES`/`_DENY_MOUNT_EXACT`) against a future caller passing something dangerously broad. An earlier version instead auto-detected any existing absolute path found in a tool's own args and mounted it automatically; code review found this was a real security hole (`ffuf-mcp`'s agent-facing, prompt-injection-reachable `wordlist` parameter could point at e.g. `~/.ssh/id_rsa` and have it auto-mounted and permission-widened) and it was removed before landing, not kept as a "known gap." **Caveats, not overclaiming (found live, fixed before landing):** (1) `--userns=keep-id` is required for the sandboxed process to actually write into its own bind-mounted scratch dir at all under rootless Podman's UID remapping — without it every real run failed with a permission error, not a "container works but is slow" issue; (2) `tempfile.mkdtemp()`'s default `0700` mode (used both by this module's own scratch dirs and by real callers like httpx-mcp's `work_dir`) is incompatible with `--userns=keep-id`'s group-based access and needed an explicit chmod (`_ensure_group_accessible()`, adds owner+group rwx/rw, never touches "other") on every declared mount source; (3) the deny-list's first version prefix-matched `$HOME`/the repo root, which blocked sqlmap-mcp's actual real `--output-dir` (a legitimate path living deep under both) on every single real call — fixed to exact-match-only for those two, prefix-matched only for genuine system directories nothing legitimate ever needs; (4) an unconditional `:rw` mount mode caused a real, demonstrated data-loss incident during this feature's own testing (a live run deleted a real git-tracked project wordlist file from the host, recovered via `git checkout`) — fixed by splitting mounts into read-only-by-default (`extra_mounts`) vs. explicit read-write opt-in (`extra_mounts_rw`), with a regression test proving read-only mounts genuinely block writes at the kernel level; (5) `secrets-mcp`'s gitleaks report path was `mkstemp()`+`unlink()`'d before being mountable, so every scan silently reported "no findings" regardless of actual results, until the report path became a real, mountable directory; (6) `ad-recon-mcp` checked the HOST's `PATH` for impacket scripts that only exist inside the sandbox image, so kerberoast/asreproast always failed "not found" on a properly-sandboxed machine — fixed to use fixed canonical in-container tool names; (7) the original bulk `reap_orphans()` force-removed every container sharing the shared label, which a live concurrency test proved would kill a different, healthy, still-running concurrent sandboxed call as collateral damage — replaced with per-run container naming + targeted `remove_container(name)`. All seven were found via a code-review self-audit and closed before this row was marked done, not deferred. **Known, disclosed gaps (not closed here):** `oob-mcp`'s own separate `resolve_tool()` + detached `Popen` for its long-lived `interactsh-client` listener is a THIRD subprocess pattern, explicitly out of scope (S5's mandate named `tool_resolver`/`job_runtime` specifically; a persistent listener doesn't cleanly fit "per-run" anyway) — still runs natively on the host; `httpx-mcp`'s `-screenshot` flag needs a real browser binary this minimal image doesn't include, so that one specific feature fails inside the sandbox (a missing capability, not a broken isolation boundary) until/unless a browser is deliberately added to the image. **Network model (read before assuming otherwise):** V1 provides rootless-privilege, filesystem, credential/environment, process, and resource isolation. It does **NOT** provide per-target network egress ACLs — default rootless networking reaches any destination the host's own networking allows, since every one of these tools must reach a real target. Building a custom per-destination network policy (CNI plugin, iptables) is explicitly OUT OF SCOPE for V1 — new network-control-plane infrastructure is exactly what this Tier-2 floor's own discipline rules out ("must not metastasize into platform engineering"). `scope_gate_hook.py`'s PreToolUse check remains the sole "may this call touch this host at all" boundary, runs BEFORE sandboxing, and is not superseded or duplicated by it. Tests: `tests/test_sandbox_runner.py` (~30 tests — argv construction, allowlist enforcement, mount minimality/safety, HOME override, plus live tests against the real image: network reachability, host-env invisibility, read-only fs, scratch-dir writability, read-only-mount-prevents-writes, orphan-free cleanup on both normal exit and a hard SIGKILL, and concurrency-safety) + `tests/test_tool_resolver.py`/`tests/test_job_runtime.py`/`tests/test_secrets_mcp.py`/`tests/test_ad_recon.py`/`tests/test_ffuf_mcp.py` updated or extended for the new sandboxed, explicit-mount contract. Full suite: 1482 passed, 5 pre-existing xfailed (documented Phase-2-boundary markers in the unrelated CEM benchmark, not S5). Runtime verification: real end-to-end calls through the actual unmodified MCP server code (not synthetic) for `curl` (`tool_resolver.run_tool`), `httpx` (`job_runtime.start_job`+`poll_job`), `gitleaks` (found a real planted AWS key, proving the report-mount fix), `sqlmap` (wrote a real results CSV back to the host through a read-write mount, confirmed present on disk after the run), and `ad-recon-mcp` kerberoast (launched correctly, timed out correctly against a fake DC, zero orphaned containers) all succeeded, proving containment doesn't break legitimate utility. `scripts/verify-sandbox.sh` is the operator-facing readiness check (podman present, rootless, image built, one real sandboxed call succeeds). This satisfies S5's own scope; `S-GATE`'s full adversarial regression (canary-secret exfil, out-of-scope action, hostile-repo checkout, across create→run→pause→resume→terminate) is separate, later, and still blocks Phase-3 breadth until S6 also lands. | S1–S4 | §6 Tier-2 |
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
| (S5 dep) | ~~approve rootless runtime dependency~~ **RESOLVED 2026-09-15: Docker/Podman rootless containers** (over bubblewrap/nsjail; microVM excluded per §6 non-goals) | S5/S6 Tier-2 — unblocked |
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
| Phase S | 5 (S1–S5) | — | 2 (S6, S-GATE) | — | Tier-1 complete; S5 of Tier-2 done, S6+S-GATE remain |
| Phase 2 | — | — | 8 | — | +C1b GATED |
| Phase 3 | — | — | 8 | 1 (P3-DEP) | VAL-AUTHZ GATED; Asset-Graph rejected |
| Phase 4 | — | — | 8 | 1 (P4-M1 on M0) | +VAL-COND deferred |
| Phase 5 | — | 1 (toolkit) | 6 | 3 (A0/ALLOC/AMORT) | gated research program |
| Human blockers | — | — | — | 8 | §8 |

**Phase-S Tier-1 (S1–S4) is `[x]`, CI-verified. S5 (rootless per-run execution boundary, Tier-2) is also `[x]`,
verified with real end-to-end sandboxed calls through unmodified MCP server code (§3).** Nothing in Phase 2 onward
is `[x]` yet — no roadmap capability past Tier-1/S5, no gated item, no human decision is treated as resolved.
**The next actionable work is S6 (hook tamper-resistance), then S-GATE's own full adversarial regression across
BOTH S5 and S6 together — S-GATE must complete before any Phase-3 breadth work begins** (§3, §9 — this ordering
is frozen, not optional; S5 alone does not satisfy S-GATE).

---

## 13. Final Check (per task §17)

- ✅ CEM Phase-1 marked `[x] FROZEN` — **not** decomposed or duplicated.
- ✅ No roadmap capability silently omitted — every v3 §4 matrix item + §10-A older-stream item is represented
  (VAL-AUTHZ present as P3-VALAUTHZ GATED; DISC-SPEC as P3-DISCSPEC; VAL-COND deferred; DISC-VARIANT as P5-VARIANT;
  ARCH-STATE = the P2-TEL/C1a provenance area + a deferred recon/scan-wiring note; LEARN-KG/graph rejected;
  Asset-Graph rejected).
- ✅ No partial/unverified implementation marked `[x]` — S1–S4 are `[x]` only with CI-verified evidence cited per-task
  (§3); evidence-integrity (content-addressed evidence, provenance binding) remains `[~]`/`[ ]` since C1a hasn't
  started.
- ✅ No gated research marked `[x]` (P3-SCHEMA, P3-VALAUTHZ, C1b, P4-M0, P5-A1, P5-T1, C3, P5-VARIANT all GATED/`[ ]`).
- ✅ No human decision treated as resolved (P3-DEP, P4-M0, P5-A0, P5-T1, C1b, ROADMAP-INT, V4 all `[!]`).
- ✅ **VAL-AUTHZ present** (P3-VALAUTHZ, GATED, multi-identity/stateful benchmark).
- ✅ **P2-E1 present** (full analysis-only guardrails).
- ✅ **Security Tier-1 → Tier-2 → Phase-3-breadth ordering present** (§3, §9); Tier-2 not optional.
- ✅ Quality floors + absolute invariants present (§11).
- ✅ Benchmark gates present (§10, §11).
- ✅ P5 remains a gated research program (§7).

*Output file: `IMPLEMENTATION-TASK-TRACKER.md`. This document itself has evolved alongside real implementation work
since its initial planning-only draft — Phase-S Tier-1 (S1–S4) is now `[x]`, CI-verified, with PR/commit evidence
cited per-task in §3. Nothing beyond Tier-1 has been implemented; Phase 2 onward, all gated items, and all human
decision blockers remain exactly as originally scoped.*
