# HuntMCP Open-Source Security & Repository Audit

**Audit date:** 2026-09-11
**Audited by:** Claude Code (read-only static/historical audit — no repository state was changed)
**Worktree audited:** `dazzling-chaum-ef215b`, branch `claude/huntmcp-security-audit-944e9c` (based on `main` @ `15435a8`)
**Method:** Four parallel read-only investigations (secrets/history, Docker/CI/supply-chain, MCP/agent permissions + data separation, docs/license/reproducibility/contributor-safety), synthesized below. No files were edited, moved, deleted, committed, or pushed at any point in this audit.

---

## Executive Summary

HuntMCP is in noticeably better shape than the median security-tooling open-source repo. No real secrets or credentials were found anywhere in the tracked tree or in the full git history. There is no exploitable CI trust boundary (no `pull_request_target`, no secrets referenced in workflows, no shell-injection vectors). Scope enforcement for the actual offensive tooling is implemented as a real technical control (a `PreToolUse` hook plus per-tool budget/audit chokepoints), not just documentation, and the agent permission model is consistently least-privilege — most notably, the report-generation agent has no submission capability anywhere in its tool graph or the underlying HackerOne MCP server, which is a genuine, verified enforcement of "human review before submit," not just a stated policy.

The issues that do exist are release-hygiene and documentation-freshness problems rather than active leaks: a stale `ROADMAP.md` that undersells what's actually built, three documents that disagree on the MCP server count, a per-target SQLite state file (`data/watch.db`) that was tracked in git despite being intended as gitignored local state (currently holding only test-fixture data, not real target data), a docker-compose default that silently enables a hardcoded dev JWT secret if an operator forgets to set env vars, and the absence of a `SECURITY.md`/`CONTRIBUTING.md`/issue templates that a security-tooling project should have.

**Overall: READY WITH FIXES.** Nothing found blocks going public today, but the immediate-action list below should be worked through first, particularly untracking `data/watch.db` and reconciling `ROADMAP.md`.

---

## Audit Scope

- **Current worktree**: full tree inspected — source, docs, tests, config, `data/`, `knowledge/`, `.opencode/`, `mcp-servers/`, `backend/`.
- **Git history**: full-history search (`git log --all -p`, `git log --all --diff-filter=A`) across 241 commits for secrets, credential-shaped strings, and files that were ever added and later removed/gitignored.
- **Configuration surface**: `Dockerfile`, `backend/Dockerfile`, `backend/embedder/Dockerfile.embedder`, `docker-compose.yml`, `opencode.jsonc`, `.env.example`, `.gitignore`, `.github/workflows/ci.yml`, `scripts/*.sh`.
- **Documentation/GitHub-facing surface**: `README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `AGENTS.md`, `PHASE1-EXECUTION-PLAN.md`, `LICENSE`, `.github/` (workflows only — no templates present).
- **MCP/agent surface**: all ~30 `mcp-servers/*/server.py` implementations, the shared enforcement modules (`scope_guard.py`, `budget_guard.py`, `audit_log.py`, `tool_resolver.py`), and all `.opencode/agents/*.md` permission scopes.
- **Not exhaustively verified**: the live public GitHub repository's Issues/Discussions/Wiki (not accessible from this environment — see Audit Limitations), a full CVE-database check of pinned dependency versions, and every one of the ~28 `requirements.txt` files line-by-line (sampled).

---

## Critical Findings

**None.** No P0 findings were identified. No P1 findings were identified in the security/secrets/CI dimensions. Two items are elevated to P1 on documentation-integrity and contributor-safety grounds (see below) — neither is an active security exposure, but both materially affect whether the project is ready for outside contributors.

### [P1 — Documentation] `ROADMAP.md` misrepresents CEM Phase 1 as not started

- **Finding:** `ROADMAP.md` states Phase 1 (CEM) status as "PLANNING COMPLETE, implementation NOT started," while git history (`15435a8` "CEM Phase 1: complete J1-O1 and freeze (#101)", `517dc1c`, `796831a`) and `PHASE1-EXECUTION-PLAN.md` show CEM Phase 1 is substantially implemented, tested, and frozen.
- **Evidence:** `ROADMAP.md` (status line) vs. `docs/cem-phase1.md`, `mcp-servers/cem_engine.py`, `tests/test_cem_*.py`, and the commit log.
- **Risk:** `ROADMAP.md` explicitly bills itself as the resumability source of truth for both humans and future agent sessions. A contributor or future session relying on it will misjudge project state, potentially re-doing completed work or misjudging what's safe to touch.
- **Exposure:** Internal-only impact (misleads readers), not a security exposure.
- **Recommended remediation:** Update `ROADMAP.md`'s Phase 1 status line to reflect the freeze, ideally by whoever owns the CEM freeze so the status reflects an authoritative "done" state, not just doc cleanup.
- **Validation:** Diff `ROADMAP.md` against `PHASE1-EXECUTION-PLAN.md` and the commit log after the update.

### [P1 — OSS Governance] No `SECURITY.md` / vulnerability-reporting channel

- **Finding:** No `SECURITY.md` exists anywhere in the repo. No documented channel (email, GitHub private vulnerability reporting, etc.) for someone who finds a flaw in HuntMCP itself — e.g., a scope-gate bypass, an MCP server that could be induced to touch an out-of-scope host — to report it responsibly.
- **Evidence:** Repo-root and `.github/` file listing; no `SECURITY.md`, no `security@` contact anywhere in README/ARCHITECTURE/CLAUDE.md.
- **Risk:** For a security-testing tool specifically, a scope-gate or budget-guard bypass is a meaningfully sensitive class of bug (it's the control that keeps the tool from attacking unauthorized targets). Without a stated private-disclosure path, a finder's only options are a public issue (bad) or silence (worse).
- **Exposure:** Governance gap, not an active vulnerability.
- **Recommended remediation:** Add a `SECURITY.md` with a private-disclosure contact/process (GitHub's built-in private vulnerability reporting is a low-effort option) and a brief statement of what's in scope (the tool's own controls) vs. out of scope (target findings from using the tool, which aren't HuntMCP vulnerabilities).
- **Validation:** File present, linked from README.

---

## Secret / Credential Findings

**Full-history and current-tree search found no real secrets, currently or historically exposed.**

**CURRENTLY EXPOSED:** None.

**HISTORICALLY EXPOSED (removed but recoverable from git history):** None found. History search for `.env`/`.pem`/`.key`/`*secret*`/`*credential*` additions, AWS key patterns (`AKIA...`), GitHub tokens (`ghp_`, `github_pat_`), Slack tokens, and PEM private-key headers turned up only source files that *implement* secret handling (e.g. `mcp-servers/secrets-mcp/server.py`) or synthetic test fixtures — never real credential material at any point in the 241-commit history.

**REMOVED BUT STILL IN HISTORY:** None. `data/memory.db`, `data/chroma/`, `.env` were checked via `git log --all --diff-filter=A --name-only` and confirmed never committed.

**TEST SECRET / PLACEHOLDER (not real, by design):**
- `tests/test_aws_postexploit.py:32` — `AKIAFAKE`/`fakesecret` (synthetic AWS creds for a detector test).
- `tests/test_audit_log.py:38`, `tests/test_redact.py:47` — `sk_live_abc123` used to test the redaction module itself.
- `tests/test_gcp_postexploit.py:52`, `tests/test_ad_recon.py:28` — synthetic service-account/AD identities.
- `backend/migrations/001_init.sql:70-72` — a commented-out (never-executed) sample `INSERT` with a truncated bcrypt placeholder.
- `backend/internal/service/auth_service.go:27-41` — `devJWTSecret = "huntmcp-dev-secret-change-in-production"`, a deliberately public dev fallback. The Go code itself is well-designed: it `log.Fatal`s at boot unless `HUNTMCP_ALLOW_DEV_SECRET=1` is explicitly set. See the related Docker/config finding below, where the *default* in `docker-compose.yml` undermines this good design.
- `docker-compose.yml:12` — `POSTGRES_PASSWORD: huntmcp`, a local-dev-only password matching the DB name and `backend/Makefile`'s inline `DATABASE_URL`. Convention, not a leak.
- Various post-exploitation MCP servers (`aws/azure-postexploit-mcp`, `second-opinion-mcp`, `model_gateway.py`, `cve_fetch.py`) have function parameters literally named `access_key`/`secret_key`/`client_secret`/`api_key` — these are runtime arguments for tools designed to accept externally-supplied credentials (e.g. a credential found during an engagement), not hardcoded values. **FALSE POSITIVE** on naive secret-scanning.

**`.env.example`** contains only empty-value placeholders (`SHODAN_API_KEY=`, `ANTHROPIC_API_KEY=`, `HACKERONE_API_TOKEN=`, etc.) with comments confirming `.env` itself is gitignored.

---

## Sensitive Data Findings

- **No real target/customer data found.** `data/writeups/*.md` are generic synthetic educational writeups citing placeholder or already-publicly-disclosed HackerOne report URLs. `knowledge/master-pentest-prompt.md` cites real, publicly-disclosed HackerOne report numbers (e.g. Shopify #423541, Automattic #1069561) by way of teaching methodology from already-public sources — appropriate for an educational pentest-methodology document, not a leak of confidential data.
- **`169.254.169.254` (cloud metadata IP) and `93.184.216.34` (example.com's public IP)** appear throughout docs and tests as universally-known reference values for SSRF-detection logic and standard test fixtures. **FALSE POSITIVE** — not real infrastructure.
- **No RFC1918/internal IPs leaking real infrastructure were found.**
- **[P3 / INFO — Privacy] Developer's real local username and home-directory path appear in checked-in docs.** `ARCHITECTURE.md:557,1334-1335` and `PHASE1-EXECUTION-PLAN.md:141` contain the literal path `/home/ankit/HuntMCP/...` and a cron entry naming the user `ankit`. Low severity — this matches the git author identity already public in commit history — but worth a documentation pass replacing the literal home path with a placeholder (`~/HuntMCP` or `$HOME/HuntMCP`) before wider publication, as a matter of hygiene rather than active risk.
- **No real personal names, phone numbers, or genuine customer PII** were found anywhere in tracked files or history. Emails encountered (`admin@huntmcp.dev`, `attacker@test.com`, `ceo@target.com`, etc.) are all synthetic pentest fixtures.
- Raw HTTP request/response samples in `tests/` and `data/writeups/` use placeholder hosts (`target.com`, `attacker.com`) — none look like captured real-target traffic.

---

## Git History Findings

Nothing was ever committed and later removed that constitutes a leak. The one file-tracking issue found (`data/watch.db`, detailed below) is a case of a file being added in the *same commit* that also gitignored it going forward — the ignore entry never retroactively untracked the already-added file, so it has remained tracked ever since (commit `fc6b2da`, 2026-07-10, through the present). Its current content is limited to `testphp.vulnweb.com`, a public intentionally-vulnerable test target, so no real data is currently exposed via this path — but the pattern itself is a repeatable leak vector, since `watch.db`'s entire purpose is per-target continuous-monitoring state.

---

## Configuration / Docker / CI Findings

**Docker:**
- **[P2 — Security]** All three Dockerfiles (`Dockerfile`, `backend/Dockerfile`, `backend/embedder/Dockerfile.embedder`) run as root — no `USER` directive anywhere. Standard container hardening is missing; recommend adding non-root users, particularly for `backend/Dockerfile` which serves production API traffic.
- **[P2 — Supply chain]** `Dockerfile:16-21` installs subfinder, httpx, katana, nuclei, ffuf, and dalfox via `go install .../tool@latest` — unpinned. This is a reproducibility gap (identical Dockerfile → different binaries on different build days) and means a compromised upstream release would be pulled automatically with no version pin or verification step. A code comment explains this is a deliberate trade-off to avoid chasing each tool's own Go-version requirements; recommend pairing this with periodic version/SBOM capture at minimum.
- **[P2 — Security] `docker-compose.yml:39` defaults `HUNTMCP_ALLOW_DEV_SECRET` to `1`.** The Go auth service's fail-closed design (`log.Fatal` unless this flag is explicitly set) is undermined by the compose file defaulting the opt-in flag *on*. Anyone running `docker compose up` without exporting `JWT_SECRET`/`HUNTMCP_ALLOW_DEV_SECRET` gets a server silently signing JWTs with the hardcoded, git-visible dev secret, with port 8080 exposed to the host. Recommend defaulting this to unset/`0` in the checked-in compose file, or moving the dev convenience to a separate override file that isn't the default path.
- **[P3 — Operational]** Default Postgres credentials (`huntmcp`/`huntmcp`) with port 5432 published to the host — fine for local dev (documented as such via the Makefile), but indistinguishable in the file itself from a "real" deployment config; a comment flagging this as dev-only would help.
- No host networking, no privileged containers, no baked-in secrets in image layers, no curl-pipe-shell install patterns were found.

**CI (`.github/workflows/ci.yml`):**
- **[P3 — Security]** No `permissions:` block at workflow or job level, so `GITHUB_TOKEN` inherits the org/repo default (often broader than needed). No jobs currently need more than `contents: read`; recommend adding an explicit top-level `permissions: { contents: read }` as defense-in-depth.
- **[P3 — Release hygiene]** Third-party actions (`actions/checkout@v4`, `actions/setup-python@v5`, `docker/setup-buildx-action@v3`, `docker/build-push-action@v5`) are pinned to mutable version tags rather than commit SHAs. Low actual risk since these are all first-party GitHub/Docker actions, but SHA-pinning is the stronger supply-chain posture.
- **Confirmed safe:** no `pull_request_target` usage anywhere (only `push`/`pull_request`, which run with a safe, secrets-free token for forked PRs); no `${{ github.event.* }}` interpolated directly into shell `run:` steps (no injection vector); no secrets referenced anywhere in the workflow; no release/publish steps (`docker-build` job uses `push: false, load: true` — image never leaves the runner).
- **[INFO]** The ruff-lint and `content_scanner.py` (OWASP Skill/MCP Top 10 scan) steps both run with `|| true`, making them advisory rather than build-blocking. The content-scanner case is explicitly and intentionally documented as advisory (defensible, given false positives on legitimate offensive-technique content); the ruff case isn't commented and is worth confirming is intended.

**`.gitignore` / config files:**
- `.gitignore` correctly implements the push/no-push split documented in `CLAUDE.md`, and goes further — it also excludes `engagement.yaml`, `AGENT-BRIEF.md`, `chat-logs/`, `data/audit.jsonl`, `data/oob-sessions/`, `reports/`, `data/engagements/`, with inline comments explaining *why*, including a note referencing a real prior incident where findings were discovered untracked-but-unprotected (2026-08-26). This is well above typical `.gitignore` hygiene.
- `opencode.jsonc`, `.env.example`, and `scripts/*.sh` were checked and contain no hardcoded secrets and no curl-pipe-shell patterns.

**Dependency/supply chain:**
- `backend/go.mod`/`go.sum` are fully version-pinned with hash verification — correct Go supply-chain posture. A routine `go get -u` pass is worth doing (some deps, e.g. `golang.org/x/crypto v0.24.0`, are not latest), but nothing was confirmed pinned to a known-vulnerable version in this pass.
- **[P3 — Release hygiene]** `mcp-servers/*/requirements.txt` use lower-bound-only specifiers (`chromadb>=0.5.0`, `boto3>=1.34.0`, etc.) with no lockfile anywhere, so two builds at different times can resolve different transitive versions. Recommend a `pip-compile`-style lockfile if reproducible builds matter here.
- No abandoned or typosquat-looking packages were found across the ~28 `requirements.txt` files.

---

## Agent / MCP / Tool Permission Findings

HuntMCP's enforcement architecture is layered and, on inspection, actually wired rather than aspirational:

- **Scope enforcement**: `scope_guard.py` is called both directly by individual servers (e.g. `case-mcp`) and — more importantly — by `scripts/hooks/scope_gate_hook.py`, a `PreToolUse` hook wired via `.opencode/plugin/scope-gate.ts` that inspects every Bash/MCP call's arguments for host-shaped strings and blocks anything out of scope or missing `engagement.yaml`, enforced outside the LLM's own control.
- **Budget**: `budget_guard.py` (default 500-call circuit breaker) is enforced at the shared `tool_resolver.run_tool()` chokepoint, and independently re-implemented at each Tier-2 tool that bypasses that chokepoint (`job_runtime.py`, `browser_confirm.py`, `idor-mcp`, `oob-mcp`, cloud post-exploit servers) — consistently present everywhere checked.
- **Audit log**: `audit_log.py` appends redacted JSON to a gitignored `data/audit.jsonl`.
- **No arbitrary shell-execution primitive was found exposed to the LLM** anywhere across ~30 `server.py` files — no `eval`, no unsanitized `os.system`, no `shell=True` reachable with attacker-controlled input.

**Agent permission scoping — all assessed CORRECT (least-privilege):**
- recon-agent: recon-only tools, no scan/exploit capability.
- scan-agent: scan-only tools, no exploit/post-exploit capability.
- exploit-agent: broadest scope (chainer, oob, browser, case, idor, cloud post-exploit, ad-recon, Burp) — appropriate, since this is the validation/escalation specialist.
- chain-planner: read/plan-only (chainer, memory, writeup).
- **report-agent: writeup + case only.** Its own doc (`report-agent.md:131-137`) explicitly states it has "no submission capability by design" and must never be given one. This was independently verified at the MCP-server layer too: `hackerone-mcp/server.py` implements only `sync_program_scope` and `check_my_duplicates` — no submit/create-report call exists in the file at all. This is genuine defense-in-depth for the "human review before submit" requirement, enforced at two layers, not just stated once.
- huntbrain (orchestrator): orchestration-only MCPs (memory, writeup, lessons, hackerone, case, target-discovery, watch), no direct exploit tools.
- Dynamic specialists: `opencode.jsonc` disables all MCP tools globally by default; agents must explicitly opt in via a `tools:` allowlist — a sound default-deny posture.

**Issues found:**
- **[P2]** `data/watch.db` is tracked in git (see Git History Findings above) despite `watch-mcp`'s state being intended as gitignored local per-target monitoring data. Currently contains only test-fixture data (`testphp.vulnweb.com`), but the tracking gap is a repeatable real-data leak vector if it's ever re-added with live target data.
- **[P2]** `exploit-agent.md:204` documents an autonomous escalation path ("SQLi → data extraction → RCE via `sqlmap --os-shell`") with no confirmation gate beyond ordinary scope/budget checks. `sqlmap-mcp` itself doesn't expose an os-shell tool — an agent following this instruction would invoke raw `sqlmap --os-shell` via Bash, which is scope/budget/audit-gated by the hook, but there's no distinct "this plants a persistent code-exec channel on someone else's system" confirmation tier beyond the standard scope gate. Given `.claude/rules/security.md`'s requirement that state-changing security tests need explicit authorization and appropriate controls, this is worth a closer look: should `--os-shell` genuinely run autonomously without an explicit human check-in, given it establishes a persistent access channel on the target rather than just detecting a vulnerability?
- **[P3 / INFO]** `obscura-mcp` is referenced throughout agent docs and the scope-gate hook's allowlist but does not exist as a registered MCP server or directory in this checkout — a dead/aspirational reference, not itself a vulnerability, but could confuse an operator who expects it to be available.
- **[P3 / INFO]** `opencode.jsonc`'s declarative `bash: {"*": "allow"}` is very permissive on its face; the *real* enforcement is entirely in the PreToolUse hook chain. This is documented and appears deliberate (the declarative glob-deny for `rm **` was reportedly found not to work reliably), but it means the hook registration is a single point of failure — if it silently breaks, the fallback posture is "allow everything." Recommend a periodic smoke test (e.g. in CI) that confirms the hook actually fires and blocks an out-of-scope call, rather than relying on manual verification.

**Notable design strength:** `case-mcp`'s `update_finding_status(finding_id, "CONFIRMED")` structurally refuses the transition when zero evidence is linked — this enforces "nothing becomes confirmed without independent reproduction" as a technical control, not just an instruction to the agent.

---

## Knowledge / Data / Engagement Separation

- `data/chroma/`, `data/memory.db`, `data/engagements/`, `data/reports/`, `data/audit.jsonl`, `data/oob-sessions/`, `data/downloads/` are all correctly gitignored and confirmed untracked (`git check-ignore -v`).
- `data/writeups/*.md` are generic, synthetic/educational writeups with fictional example targets and either placeholder or already-public HackerOne report citations — no real target data.
- `knowledge/lessons-learned-template.md` is explicitly a template using `example-corp.com`; the real filled-in registry (`chat-logs/lessons-learned.md`) is correctly gitignored.
- The one violation of this otherwise-clean separation is `data/watch.db` (see above) — flagged as P2.

---

## Documentation / Open-Source Quality

**Strengths:**
- `ARCHITECTURE.md` maintains an unusually disciplined ✅/🚧/❌ status table per phase, with dated verification notes (e.g., a HackerOne integration marked "confirmed working 2026-08-25 against a real HackerOne account") — evidence-before-claims discipline well above typical OSS documentation rigor.
- `ARCHITECTURE.md`'s "prior art" section explicitly credits external projects by name with notes on what was ported vs. rewritten vs. referenced-only — good attribution discipline.
- Target-authorization messaging is a standout: README has `[!IMPORTANT]`/`[!WARNING]` callouts mandating `engagement.yaml` before any target-touching action, and its only live worked example is `testphp.vulnweb.com` (OWASP's own legal test target) — never a real domain. This is backed by a real technical control (the scope-gate hook), not just a warning banner.
- README/ARCHITECTURE honestly flag structural gaps rather than hiding them — e.g., the Go backend is explicitly marked "not yet wired to the local agent system," and Obscura's calls are disclosed as bypassing the shared budget/audit chokepoint.

**Issues:**
- **[P1]** `ROADMAP.md` stale CEM status (see Critical Findings).
- **[P2]** `AGENTS.md` is a stale snapshot ("Current state (July 2026)") listing 5 agents and an older MCP-server set, inconsistent with `CLAUDE.md`/`README.md`'s current numbers. `CLAUDE.md` is the documented source of truth, but a contributor who opens `AGENTS.md` first gets an outdated picture.
- **[P3]** Three different MCP-server counts appear across the docs: README says "24," `ARCHITECTURE.md` says "22," the actual registered count in `opencode.jsonc` is 31. All are undercounts (not overclaims), so this doesn't create false confidence, but the documents disagree with each other and should be reconciled to one accurate number.
- **[P3]** README's Python install instructions have no root-level `requirements.txt`/lockfile and no guidance on install time or potential dependency conflicts among heavier packages (`chromadb`, `sentence-transformers`, `playwright`) — a minor first-run friction point, honestly described as "install per server you plan to use" rather than hidden.
- **[INFO]** The 52-technique-skill count in the README badge was verified accurate.

---

## License / Dependency / Supply Chain

- **License:** MIT, `LICENSE` file present at repo root, correctly copyrighted "Ankit Singh, 2026," standard unmodified text, clearly surfaced in the README (badge + footer). No red flags.
- **Attribution:** No unattributed vendored/copied third-party source code was found in a spot check; external tooling (subfinder, httpx, nuclei, etc.) is consumed as compiled binaries or via standard package managers, not vendored source. `knowledge/master-pentest-prompt.md` is self-authored/curated content with its own provenance notes, not a verbatim copy.
- **Dependency pinning:** see Configuration/Docker/CI Findings above — Go side is fully pinned and hash-verified; Python side uses lower-bound-only specifiers with no lockfile (P3).

---

## Test / Benchmark / Fixture Hygiene

- No real credentials, real target domains, or non-deterministic live-network test dependencies were found in a spot check of `tests/`. Network-touching test modules (`test_cve_fetch.py`, `test_disclosed_reports.py`, `test_osint_apis.py`, etc.) use mocking rather than live calls, consistent with `tests/CLAUDE.md`'s loopback-only mandate.
- Hardcoded IPs in tests (`93.184.216.34`, `169.254.169.254`, `8.8.8.8`) are all expected, benign reference values for parser/SSRF-detection tests.
- **Strength:** CEM benchmark fixtures (`tests/fixtures/cem_target/`) use `.sha256.lock` integrity locks on `scenarios.py`/`answer_key.py` to detect tampering with protected ground truth, directly satisfying the repo's own benchmark-protection rule (`.claude/rules/benchmarks.md`), with multiple `PHASE1-EXECUTION-PLAN.md` entries explicitly recording "checksums verified unchanged."

---

## Reproducibility

Generally good: every script referenced in the README Quick Start (`setup-db.sh`, `select-model.sh`, `switch-engagement.sh`, `new-target-session.sh`, `connect-burp.sh`, `connect-obscura.sh`, `check-scope.sh`) actually exists in `scripts/`. `.env.example` is well-commented and states that missing keys degrade gracefully rather than crash. `engagement.yaml.example` matches the format the README documents. The main rough edge is the lack of a single root-level dependency manifest (P3, noted above under Documentation).

---

## Public Issue / Discussion Hygiene

Not independently verifiable from this environment — see Audit Limitations. Within the repo itself, `.github/` contains only `workflows/ci.yml`; there are no `ISSUE_TEMPLATE/` or `PULL_REQUEST_TEMPLATE.md` files (P2, below). For a tool whose issue reports will often include target URLs or scan output, a template nudging reporters to redact target-identifying information before filing would materially reduce accidental disclosure risk once the project is public.

---

## Implemented vs. Planned Clarity

Overall strong — the project is unusually careful about marking things ❌ Not started / 🚧 in progress rather than overclaiming, and discloses structural gaps (Go backend not wired up, Obscura bypassing shared budget/audit) rather than hiding them. The one clear exception is `ROADMAP.md`'s stale CEM status line, which is the opposite failure mode (understating completion) but still breaks the "resumable without conversation memory" promise the file makes about itself. The MCP-server-count and test-count discrepancies across README/ARCHITECTURE are minor staleness, not misrepresentation of capability.

---

## What Is Good and Should Stay

- Real, technically-enforced scope gating (`scope_gate_hook.py` + `scope_guard.py`) rather than documentation-only "please stay in scope" guidance.
- Real, technically-enforced "no auto-submission" boundary for report-agent, verified at both the agent-permission layer and the underlying HackerOne MCP server implementation.
- Consistent budget/audit-guard wiring across all Tier-2 (target-touching) tools, including ones that bypass the shared `tool_resolver` chokepoint.
- A `.gitignore` that goes beyond the documented minimum and explains *why* each entry exists, including a note referencing a real prior near-miss.
- Fully pinned and hash-verified Go dependencies.
- Disciplined ✅/🚧/❌ implementation-status tracking in `ARCHITECTURE.md` and `PHASE1-EXECUTION-PLAN.md`, including dated real-world verification notes.
- Genuinely synthetic test fixtures and writeup content — nothing traced back to a real engagement or customer.
- MIT license, clearly and correctly applied, with honest prior-art attribution.
- Strong target-authorization messaging in the README, backed by an actual enforcement mechanism rather than just a warning.
- Open architecture/agent-roster transparency is appropriate here and should **not** be walked back — none of the publicly-documented design (agent roles, MCP server list, scope-gate mechanism) constitutes an exploitable disclosure; understanding how the scope gate works doesn't let anyone bypass it, since the gate is a runtime control, not an obscurity-dependent one.

---

## Recommended Remediation Priority

| Priority | Issue | Area | Why | Recommended Action |
|---|---|---|---|---|
| P1 | `ROADMAP.md` shows CEM Phase 1 as not started when it's complete/frozen | Documentation | Breaks the file's own "resumable source of truth" promise | Update status line to match `PHASE1-EXECUTION-PLAN.md`/commit `15435a8` |
| P1 | No `SECURITY.md` / private vulnerability-reporting channel | OSS Governance | No safe path to report a scope-gate/budget-guard bypass in the tool itself | Add `SECURITY.md` with a private-disclosure contact (e.g. GitHub private vulnerability reporting) |
| P2 | `data/watch.db` tracked in git despite being intended as gitignored local state | Configuration / Privacy | Currently only test data, but the pattern is a repeatable real-target-data leak vector | `git rm --cached data/watch.db` (human decision — not performed by this audit) and confirm `.gitignore` covers it going forward |
| P2 | `docker-compose.yml` defaults `HUNTMCP_ALLOW_DEV_SECRET=1` | Configuration / Security | Silently enables a hardcoded, git-visible JWT secret if an operator forgets env vars | Default the flag to unset/`0` in the checked-in compose file |
| P2 | Dockerfiles run as root (no `USER` directive) | Docker / Security | Missing standard container hardening, especially for the production `backend/Dockerfile` | Add non-root `USER` to all three Dockerfiles |
| P2 | `exploit-agent.md` documents autonomous `sqlmap --os-shell` escalation with no distinct confirmation gate | Agent Permissions / Security | Plants a persistent access channel on a third party's system; benefits from a stronger check-in than ordinary scope gating | Human decision: add an explicit confirmation tier for this specific action, or document why standard scope gating is deemed sufficient |
| P2 | `AGENTS.md` stale snapshot inconsistent with `CLAUDE.md`/README | Documentation | Misleads a contributor who reads it before `CLAUDE.md` | Update or clearly mark as superseded by `CLAUDE.md` |
| P2 | No `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, or issue/PR templates | OSS Governance | Standard OSS onboarding/safety scaffolding missing; issue template especially matters here to prompt redaction of target info | Add minimal versions of each |
| P2 | `Dockerfile:16-21` installs 6 security tools via unpinned `go install ...@latest` | Docker / Supply chain | Reproducibility gap; automatic pull of unverified upstream releases | Pin versions or capture an SBOM/version log at build time |
| P3 | MCP-server-count disagreement across README (24) / ARCHITECTURE (22) / actual (31) | Documentation | Internal inconsistency, though it undercounts (not overclaims) | Reconcile to one accurate number |
| P3 | `ci.yml` missing top-level `permissions:` block | CI/CD | Defense-in-depth; no current exploit path since no secrets are used | Add `permissions: { contents: read }` |
| P3 | GitHub Actions pinned to tags, not commit SHAs | CI/CD / Supply chain | Standard supply-chain hardening | Pin to SHAs if the project wants to tighten further |
| P3 | `mcp-servers/*/requirements.txt` unpinned lower bounds, no lockfile | Supply chain | Build-to-build dependency drift | Consider a `pip-compile`-generated lockfile |
| P3 | Default Postgres creds in `docker-compose.yml` | Configuration | Fine for local dev but visually indistinguishable from a real deployment config | Add an inline comment flagging dev-only use |
| P3 | Developer's real local username/home path in `ARCHITECTURE.md`/`PHASE1-EXECUTION-PLAN.md` | Privacy | Minor personal-path disclosure (low severity — matches public git author identity) | Replace literal `/home/ankit/...` with `~/HuntMCP` or `$HOME/HuntMCP` |
| P3 | `obscura-mcp` referenced in docs/hooks but not present as a registered server | Documentation | Could confuse an operator expecting it to work | Either register it or remove/mark-experimental in the docs that reference it |
| INFO | `ci.yml` ruff and content-scanner steps run as `\|\| true` (advisory only) | CI/CD | Casual readers of the CI badge might assume these block merges | Confirm intentional; document if so |

---

## Release Readiness

**READY WITH FIXES**

Justification: no active secret exposure, no exploitable CI trust boundary, and a genuinely enforced (not just documented) scope/permission architecture for the offensive tooling itself. The items above are release-hygiene, documentation-freshness, and governance-scaffolding gaps rather than active security exposures — with the two P1s being about accuracy/safety-of-reporting rather than a live leak. Addressing the Immediate Action List below before the first public push is recommended; none of it should take long, and none of it requires an architectural change.

---

## Immediate Action List

1. Untrack `data/watch.db` from git (`git rm --cached data/watch.db`) — human decision, not performed by this audit — and verify `.gitignore` prevents recurrence.
2. Fix the `HUNTMCP_ALLOW_DEV_SECRET` default in `docker-compose.yml` so the hardcoded dev JWT secret is never silently active.
3. Update `ROADMAP.md`'s CEM Phase 1 status line to match reality.
4. Add a minimal `SECURITY.md` with a private vulnerability-disclosure channel.
5. Add non-root `USER` directives to the three Dockerfiles.
6. Add basic `.github/ISSUE_TEMPLATE/` (at minimum, a prompt to redact target-identifying info) and a `CONTRIBUTING.md`.
7. Get a human decision on whether `exploit-agent.md`'s autonomous `sqlmap --os-shell` escalation path needs a distinct confirmation gate beyond standard scope enforcement.

## Deferred Improvements

- Reconcile MCP-server-count claims across README/ARCHITECTURE.
- Refresh or retire `AGENTS.md` in favor of `CLAUDE.md`.
- Pin the `go install ...@latest` tool installs in `Dockerfile`, or capture versions/SBOM at build time.
- Add a `permissions:` block to `ci.yml`; consider SHA-pinning third-party Actions.
- Add a Python dependency lockfile across `mcp-servers/*/requirements.txt`.
- Replace the literal `/home/ankit/...` path references in `ARCHITECTURE.md`/`PHASE1-EXECUTION-PLAN.md` with a generic placeholder.
- Clarify or remove the `obscura-mcp` references that don't correspond to a registered server in this checkout.
- Routine `go get -u` pass on `backend/go.mod` to pick up any upstream CVE fixes (none confirmed vulnerable in this pass).

---

## Audit Limitations

- **Public GitHub surface** (Issues, Discussions, Wiki, past PR comments, release notes) was not independently accessible from this environment and was not audited beyond what's checked into the repository itself (workflows, docs). This should be reviewed separately by someone with access to the live GitHub repo before or shortly after going public, particularly for retrospectives or PR discussions that might contain more operational detail than the checked-in docs.
- **No live CVE-database lookup** was performed against pinned dependency versions (Go modules, Python packages); the audit confirmed pinning discipline but did not cross-reference every version against current CVE advisories.
- **Python `requirements.txt` files were sampled, not exhaustively read line-by-line**, across all ~28 files.
- **Legal/license compatibility review** was limited to identifying the license and spot-checking for unattributed vendoring; this is not a substitute for formal legal review if the project has commercial stakes.
- This audit reflects the state of the `dazzling-chaum-ef215b` worktree at the time of the run; other open worktrees in this repository (visible via `git worktree list`) were not in scope and were not inspected.
