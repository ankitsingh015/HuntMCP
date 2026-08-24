# HuntMCP — World-Class Bug Bounty Automation Framework

## Philosophy

HuntMCP is not a script that chains tools in a fixed order. It is a **multi-level AI agent orchestration system** running inside OpenCode that:

1. Uses **Level 1 Orchestrator** (HuntBrain) to decide strategy
2. Spawns **Level 2 Specialist Agents** (Recon, Scan, Exploit, Report + unlimited dynamic specialists)
3. All agents query a **Knowledge Layer** (Writeup RAG + Memory DB) to learn from past hunts and public writeups
4. Tests all 30+ vulnerability classes across the full OWASP WSTG methodology
5. Validates findings via Burp Repeater before reporting
6. Learns continuously — manual ingestion + automated cron feeds keep the RAG database fresh

## Current Implementation Status

This doc describes the target design. As of 2026-08, actual build status (see the full
phase-by-phase "Build Plan" further down for detail):

| Layer | Status | Notes |
|-------|--------|-------|
| Phase 1 — Local system (agents, MCP servers, knowledge base) | ✅ Built | 6 agents (incl. chain-planner), 19 MCP servers, dual OpenCode + Claude Code harness, payloads/wordlists seeded, 53-test pytest suite in CI |
| Phase 2 — Go backend (API, auth, pgvector) | ✅ Built | See `backend/` — Gin + PostgreSQL/pgvector, JWT auth, `/mcp` endpoint. Not yet wired to the local agent system — see "World-project integration map" |
| Phase 2.5-2.7 — Methodology depth, harness/safety hardening, knowledge/model backlog | ✅ Built | Scope gate, reactive rate limiting, model gateway, lessons registry, CVE search index — see Build Plan below |
| Phase 2.8 — claude-bug-bounty-derived backlog | 🔶 High + most Medium priority done | All 4 High-priority items done (scope hook, `oob-mcp`, `waf-bypass-mcp`, `hackerone-mcp` — the last untested against a live account). Medium: secrets scanning, audit log, pytest suite all done; skills-as-Claude-Code-Skills restructuring still open (deliberately — a 59-section mechanical split isn't a "quick" task, see its own note below). Lower priority (SAST, web3, mobile) still open — new domains, larger scope commitment |
| Phase 2.9 — Strix-derived backlog | ✅ Complete | Budget circuit-breaker, duplicate-work check, context-compaction strategy, Caido support all done |
| Phase 2.10 — Full world-research backlog | 🔶 Concrete items done | EPSS+KEV CVE scoring, `AGENT-BRIEF.md`, cross-model second opinion, `mantis-dedupe` finding-level dedup all done. Remaining items are either "cite, don't adopt" references (no code needed), contingent on an unbuilt prerequisite (self-scan needs the self-expanding-toolkit mechanic first), or genuinely large commitments needing live infra (XBOW benchmark run, bloodhound-mcp/ghidra-mcp for domains with no current target) — see Build Plan below |
| Phase 3 — Web platform (Next.js dashboard, community PRs, CI/CD auto-train) | ❌ Not started | Design only, see Build Plan below |
| Self-improvement / lessons registry (`lessons-mcp`) | ✅ Built | Real write-back on every confirmed finding and closed false positive, not a documentation placeholder |

The gap to close next is Phase 3 (web platform) and the still-unpulled-in world-project
integrations below — not agent depth or core infrastructure, both of which are done.

## Scope & Authorization (read before running anything)

HuntMCP executes real, active exploitation attempts (SQLi, SSRF, RCE payloads, auth bypass, etc.) against a live target. This is offensive and can be illegal or damaging if pointed at the wrong host.

- **Never run an audit against a target without explicit written authorization** (a bug bounty program's published scope, a signed pentest agreement, or a target you personally own).
- Findings, payloads, and exploitation evidence are sensitive; treat `data/`, `logs/`, and any `chat-logs/` content as private (already gitignored where it contains target-specific data).

### How the scope gate actually works (validate once, not every call)

Re-confirming scope before every single tool call would burn tokens for no safety benefit — the check only needs to happen once, at the start, then get enforced cheaply for the rest of the run:

1. **Once, at Phase 0**: the user hands HuntBrain the full program/engagement details up front (in-scope domains, out-of-scope exclusions, any rate-limit constraints from the program). HuntBrain does one real analysis pass and writes it to a session-scoped `engagement.yaml` (target list, out-of-scope list, authorization reference).
2. **For the rest of the engagement**: every Tier-2 (execution-capable) tool call does a **cheap, deterministic domain-match check** against the already-parsed in-scope list from step 1 — a plain string/suffix match, not an LLM call, effectively free. This is what actually blocks an out-of-scope request; no re-analysis, no repeated reasoning.
3. If the current target/host isn't in the cached list, the call is refused locally, before any MCP tool runs — cheap enough to run on literally every call without meaningfully affecting cost.

This keeps the hard guarantee (nothing out-of-scope ever executes) while keeping the ongoing cost at effectively zero.

### Rate limiting is reactive, not proactive

A blanket per-request delay slows down recon/scan for a problem that usually isn't happening — so `run_tool()` in `mcp-servers/tool_resolver.py` adds **no delay by default**. It only reacts when the target actually signals a block, and it reacts differently depending on what kind of block it is:

- **Rate limit** (429, "rate limit"/"too many requests" in output): back off 5s and retry exactly once (Phase 21.5's decision tree). A second block after that means something else is wrong — stop retrying blindly.
- **WAF/bot-detection block** (403+block-page text, Cloudflare/Akamai/Imperva signatures): a sleep doesn't fix this. `classify_block()` flags it as `"waf"` so the calling agent escalates to real bypass technique instead — the header/path/method tiers already in `knowledge/master-pentest-prompt.md` Phase 0.6, and, for JS-challenge WAFs that those can't beat, a browser-driven tool (Playwright headless, real JS execution, real TLS/HTTP fingerprint) — planned as a `playwright-mcp` server rather than solved by waiting.

### Self-expanding toolkit

After every engagement, learning isn't just a note in `chat-logs/lessons-learned.md` — when an agent hits a technique with no matching MCP tool, it's expected to actually build one: a new MCP server wrapper (FastMCP pattern, using `resolve_tool()`/`run_tool()`, structured output), not just flag the gap for a human to fix later. This is Phase 32.5/37 ("invent new tests... propose as a new phase addition") taken literally — the toolkit itself grows engagement over engagement, not just the notes about it.

## Multi-Level Architecture

```
LEVEL 0: USER "HuntMCP audit example.com"
              │
              ▼
LEVEL 1: HUNTBRAIN (Orchestrator)
         │  Receives goal → queries Memory DB
         │  → decides strategy → delegates to sub-agents
         │  → merges results → decides next action
         │  → loops until complete → generates report
         │
         ├──→ LEVEL 2: RECON AGENT (permanent)
         │     ├── subfinder MCP (subdomains)
         │     ├── httpx MCP (live hosts + tech)
         │     └── katana MCP (crawl + JS)
         │
         ├──→ LEVEL 2: SCAN AGENT (permanent)
         │     ├── nuclei MCP (template vulns)
         │     ├── sqlmap MCP (SQLi)
         │     ├── dalfox MCP (XSS)
         │     └── Burp Scanner (via Burp MCP)
         │
         ├──→ LEVEL 2: EXPLOIT AGENT (permanent)
         │     ├── Burp Repeater (validation)
         │     ├── Burp Collaborator (OOB/SSRF)
         │     └── sqlmap --os-shell (RCE)
         │
         ├──→ LEVEL 2: REPORT AGENT (permanent)
         │     └── Generates H1/BC/MD reports
         │
         ├──→ LEVEL 2: DYNAMIC SPECIALISTS (spawned on demand)
         │     ├── @graphql-agent (when GraphQL detected)
         │     ├── @jwt-agent (when JWT found)
         │     ├── @oauth-agent (when OAuth detected)
         │     ├── @cloud-agent (when cloud assets found)
         │     ├── @wordpress-agent (when WP detected)
         │     ├── @saml-agent (when SAML found)
         │     └── @llm-agent (when AI endpoints found)
         │
         └──→ KNOWLEDGE LAYER (available to ALL levels)
               ├── WRITEUP RAG MCP (ChromaDB)
               │     └── "What techniques worked on similar targets?"
               └── MEMORY MCP (SQLite)
                     └── "What worked/didn't work on THIS target?"
```

### How 100+ Agent Orchestration Works

It is NOT 100 levels of hierarchy. It is **1 orchestrator + unlimited specialist agents** spawned on demand:

```
Orchestrator (1 file)
  │
  ├── 4 permanent agents (always loaded)
  │     Recon, Scan, Exploit, Report
  │
  ├── 50+ dynamic agents (created as .md files)
  │     Each = one file in .opencode/agents/
  │     Each = specific instructions + specific MCPs
  │     Each = spawned only when HuntBrain detects the need
  │     Examples:
  │     ├── react-agent.md     (React-specific XSS/CSRF tests)
  │     ├── graphql-agent.md   (GraphQL introspection/batching)
  │     ├── jwt-agent.md       (JWT none-alg/cracking/kid)
  │     ├── s3-agent.md        (S3 bucket listing/writing)
  │     └── ... unlimited
  │
  └── 2 knowledge systems (available to all)
        Writeup RAG + Memory DB
```

Each agent is just a **markdown file** with:
- Its own locked-down permissions  
- Its own specialized instructions
- Its own tool access (MCP subset)
- Spawned by HuntBrain when relevant

This scales to **unlimited agents** because they're files, not running processes.

## Methodology Sources Synthesized

| Source | What it contributed |
|--------|---------------------|
| OWASP Web Security Testing Guide (WSTG v4.2) | 12 testing categories, 90+ test cases |
| jhaddix The Bug Hunter's Methodology (TBHM) | Recon depth, content discovery approach |
| r-s0n methodology | Ebb & Flow vulnerability discovery model |
| su6osec HuntBook 2026 | Phase structure, 100+ tool references |
| hexsec 2026 Methodology | Two-eye approach, checklist-driven testing |
| Fino Hunter Workflow | Scope analysis → recon → discovery → testing → PoC → report |
| Carl Sampson 2026 Guide | Business logic chains, modern surface (SAML, WASM, AI/LLM) |
| shuvonsec BB Methodology Skill | Critical thinking framework, 5-minute rule |
| N0RMXL Framework | 10-phase methodology, checkpoint resume |
| bugbounty-hunter (mrch4n725) | Validation pipeline, multi-format reporting |
| BountyGrimoire | Multi-agent approach for authenticated testing |

## Methodology Engine (how agents know what to do)

The phase tables below are a **summary**, not the source of truth. The authoritative, exhaustive technique library lives in a separate file so it can grow without bloating this architecture doc or blowing any agent's context window:

- **[`knowledge/master-pentest-prompt.md`](knowledge/master-pentest-prompt.md)** (✅ added) — the full phase-by-phase methodology (recon → injection → auth → access control → XSS → business logic → infra → reporting), `[PHASE <N>]`-indexed so any agent can `grep` and load only what's relevant to the current target. Its header maps phases directly to `.opencode/agents/*.md` files — this is what those agent files should reference and expand from; they currently only name phases, they don't carry the technique detail inline.
- **`chat-logs/lessons-learned.md`** (gitignored, workstation-private — **never git-tracked, by design**) — a standing registry of confirmed bugs from past engagements, written back after every finding: vuln class, target, method, exact payload, impact chain. Read at the start of every engagement and matched against the current target's fingerprinted tech stack. Real engagement data (target names, client findings) must never enter this repo, even privately — see [`knowledge/lessons-learned-template.md`](knowledge/lessons-learned-template.md) for the schema with sanitized examples, and point `HUNTMCP_LESSONS_PATH` at your real file if you already maintain one outside the repo. Capped in size; old entries roll into `chat-logs/lessons-archive-<year>.md` rather than being deleted.
- **`knowledge/owasp-wstg-skill.md`** (existing) — the structural WSTG v4.2 mapping, unchanged.

This makes the **Knowledge Layer three systems, not two**:

| System | Backend | Answers | Scope |
|--------|---------|---------|-------|
| Writeup RAG | ChromaDB (local) / pgvector (Go backend) | "What technique worked on similar *public* writeups?" | Cross-target, public |
| Memory DB | SQLite (local) / PostgreSQL (Go backend) | "What did *we* find on *this* target before?" | Per-target |
| Lessons Registry | Flat markdown, `rg`-matched by keyword | "What confirmed technique matches *this target's tech stack*, from *our own* past engagements?" | Cross-target, workstation-private |

**No-skip guarantee**: none of these systems ever authorize skipping a test class on a fresh target — they only reorder priority (test the historically-highest-yield classes first) and seed better initial payloads. Every phase still runs in full on every new target.

## Model & Harness Layer (no lock-in, by design)

Two independent axes, and both must stay swappable — neither the runtime nor the model should ever be hardcoded:

### Harness (how agents actually run)

| Harness | What it is | When to use it |
|---------|-----------|-----------------|
| **Claude Code native** (✅ built) | `.claude/agents/*.md` + `.claude/commands/audit.md` + `.mcp.json`, mirroring `.opencode/agents/` — the same dual-install pattern Claude-BugHunter uses across Claude Code/OpenCode/Codex CLI/Hermes | Interactive use, when the operator wants to watch/steer an engagement live, billed through the operator's own Claude Code / Claude API access. Model is always Claude here — picked per-agent via each file's `model:` field, not via the provider gateway below. |
| **OpenCode** (✅ existing, now gateway-wired) | Current `.opencode/agents/` + `opencode.jsonc`. `scripts/select-model.sh` runs the provider gateway and patches `opencode.jsonc`'s `"model"` field before launch — this is the harness the multi-provider chain below actually controls today. | Any run where you want a non-Claude model, or automatic fallback across whichever key you have set |
| **Direct multi-provider API runner** (planned) | Lightweight headless script for scheduled/CI/`watch` mode use with any model | Continuous monitoring, unattended runs, or when the operator wants a non-Claude model driving without OpenCode at all |

All three harnesses read and write the **same** `knowledge/`, `mcp-servers/`, and `chat-logs/` — the harness is just the front door, never the source of truth.

### Model provider (which LLM actually answers)

Ordered fallback chain, one env var per provider — first one with a key set wins unless a per-agent override says otherwise (modeled directly on `claude-bug-bounty`'s `brain.py` pattern):

1. `ANTHROPIC_API_KEY` — preferred for reasoning-heavy agents (Exploit, Report, chain-planner); apply to Anthropic's **Cyber Verification Program** first so authorized offensive work doesn't hit refusal friction
2. `OPENAI_API_KEY`
3. `DEEPSEEK_API_KEY`
4. `GROQ_API_KEY`
5. `OPENROUTER_API_KEY` — catch-all gateway to 100+ more providers/models through one key
6. `OLLAMA_HOST` — local, no key required; also the slot for a purpose-built open-weight security model (e.g. WhiteRabbitNeo) for agents that need to avoid hosted-model refusal friction on legitimate, already-scope-confirmed PoC generation

**Built**: `mcp-servers/model_gateway.py` (`select_provider()`), tested against all six chain entries plus the explicit-override and per-role-override paths. `scripts/select-model.sh` wires it into OpenCode by patching `opencode.jsonc`'s `"model"` field in place (`--apply`, targeted regex replace — never a full JSON round-trip, so `//` comments survive). Run it before `opencode run`; a plain `python3 mcp-servers/model_gateway.py [role]` with no `--apply` is always a dry-run preview, never writes anything.

Per-agent overrides (`HUNTMCP_MODEL_EXPLOIT=whiterabbitneo`, etc.) work in `select_provider()` today, but OpenCode itself only has one *global* model — there's no per-agent model in `opencode.jsonc`. Per-role selection only becomes meaningful once the direct multi-provider API runner exists (each agent's own call would carry its own role). Recommended per-agent assignment once that lands: cheap/fast model for Recon-agent (high call volume, low reasoning need), strongest available model for Exploit-agent/chain-planner/Report-agent (low volume, high stakes).

**The authorization gate never lives in the model.** Regardless of which harness or provider answers a given call, the Scope & Authorization check (target confirmed in-scope, engagement details on file) happens in HuntMCP's own agent logic before any Tier-2 (execution-capable) action — matching the Tier 1/Tier 2 split from `pentest-ai-agents`. A model refusing or not refusing a request is never the control; the scope-guard is.

### World-project integration map

What HuntMCP borrows from each project researched, and current status:

| Project | What we take from it | Status |
|---------|----------------------|--------|
| [`shuvonsec/claude-bug-bounty`](https://github.com/shuvonsec/claude-bug-bounty) | `brain.py` multi-provider fallback pattern (✅ ported as `mcp-servers/model_gateway.py`); JSONL hunt-memory format (informed `lessons-mcp`'s design, though ours is markdown not JSONL); "7-Question Gate" validator (informed exploit-agent's proof-capsule validation step). Re-researched 2026-08-22 (4.3k★, actively maintained, ships its own `docs/CAPABILITY-GAPS.md` self-audit) for concrete next items — see Phase 2.8 below | Model gateway ported; Phase 2.8 tracks the rest as concrete backlog, not just design references |
| [`elementalsouls/Claude-BugHunter`](https://github.com/elementalsouls/Claude-BugHunter) | Patterns embedded directly in per-vuln-class skill files instead of a lookup DB; cross-harness dual-install model | Design reference — informs how `knowledge/master-pentest-prompt.md` should eventually split per vuln class |
| [`0xSteph/pentest-ai-agents`](https://github.com/0xSteph/pentest-ai-agents) | Tier 1 (advisory) / Tier 2 (execution, scope-validated) agent split; `_scope-guard.md` hard-refusal list; defense-paired-with-offense; swarm orchestrator | Design reference — see Scope & Authorization section above |
| [XBOW](https://xbow.com/) | Explorer/validator split; persistent attack-surface manager; thousands of narrow short-lived tasks (not literal agent processes) | Informs the Methodology Engine's planned parallel-fan-out rework |
| [Strix](https://github.com/usestrix/strix) | "Graph of agents" sharing discoveries live; per-agent sandbox isolation | Informs planned Docker/Firecracker sandboxing for exploit execution |
| [PortSwigger `mcp-server`](https://github.com/PortSwigger/mcp-server) | Official Burp MCP integration — already the design behind the `127.0.0.1:9876` reference in AGENTS.md | Kept as an optional enhancement tier, not a hard requirement |
| `mcp-security-hub`, `mcp-for-security`, `awesome-offensive-mcp` | Ready-made MCP servers (Nmap, Ghidra, Nuclei, SQLMap, Hashcat, Masscan) to adopt instead of hand-building more wrappers | Not yet pulled in |
| ReconFTW | 80+-tool orchestrated recon pipeline, wrap as one MCP server | Not yet pulled in — recon-agent still only has 4 tools |
| garak, PyRIT | Purpose-built LLM red-teaming tools for Phase 14.5/14.6 (AI/LLM surface testing) | Not yet pulled in |
| WhiteRabbitNeo | Open-weight security-tuned model, runnable via Ollama, no hosted-model refusal friction | Slot reserved in the fallback chain above |
| Anthropic Cyber Verification Program | The legitimate, official path to authorized-use API access | Apply directly — anthropic.com, not a code change |
| Project Glasswing | Proof-of-ceiling reference only (10,000+ vulns found by Claude at Anthropic's own scale) | Not directly integrated — context/validation that the category works |

## Complete Methodology — All Phases

### Phase 0 — Program Analysis
```
- Read scope (in-scope / out-of-scope / wildcard)
- Check disclosed HackerOne/Bugcrowd reports for patterns
- Identify tech stack (Wappalyzer, BuiltWith)
- Determine bounty tiers (which vulns pay highest)
- Get test accounts if required
- Check auth requirements and consent boundaries
- Query Writeup RAG: what vulns are common for this tech stack?
- Query Memory DB: have we hunted this target before?
```

### Phase 1 — Passive Reconnaissance (Zero interaction with target)

| Technique | Sources | What it finds |
|-----------|---------|---------------|
| Certificate Transparency | crt.sh, CertSpotter, Facebook CT | Subdomains from SSL certs |
| DNS Records | Chaos (ProjectDiscovery), SecurityTrails, DNSDumpster | DNS records, subdomains |
| Search Engines | Google Dorks (site:, inurl:, intitle:, filetype:, ext:) | Exposed configs, dev portals, admin panels, sensitive files |
| Code Repositories | GitHub Dorks, GitLab Dorks | API keys, tokens, secrets, internal endpoints, passwords |
| Archive Data | Wayback Machine, GAU (GetAllUrls), AlienVault OTX | Historical URLs, old endpoints, parameters |
| ASN/IP Ranges | BGP.he.net, whois, ipinfo.io | Target's IP address space |
| Acquisitions | Crunchbase, LinkedIn | New assets from acquired/merged companies |
| Internet Scanning | Shodan, Censys, ZoomEye | Exposed services, open ports, banners |
| WHOIS Records | whois command, whois.domaintools.com | Registrant info, name servers, registrar |
| Social Media | LinkedIn, Twitter, Reddit | Tech stack hints, employees, internal tools |
| DNS Zone Transfer | dig, fierce | Full DNS record dump (rarely works) |
| Email Harvesting | theHarvester, hunter.io | Employee emails, email patterns |
| Technology Stack | Wappalyzer, BuiltWith, WhatWeb | Frameworks, CMS, libraries, version numbers |

### Phase 2 — Active Enumeration (Direct interaction with target)

| Task | Tools | What it finds |
|------|-------|---------------|
| DNS Bruteforce | MassDNS, shuffledns, puredns | Subdomains not in passive sources (10k-1M wordlists) |
| DNS Resolution | dnsx | Which subdomains actually resolve to IPs |
| DNS Permutation | alterx, gotator | Permuted subdomains (dev-api, staging-v2) |
| Port Scanning | naabu (fast) → nmap (deep) | Open ports (top 1000 → all 65535) + service version detection |
| HTTP Probing | httpx | Live hosts, status codes, page titles, tech stack, CDN |
| Screenshots | gowitness, eyewitness | Visual recon — spot unusual pages, admin portals |
| JavaScript Analysis | LinkFinder, JSParser, SecretFinder, jsubfinder | API endpoints, internal routes, access keys, secrets |
| JavaScript Crawling | katana, hakrawler, gospider | All endpoints, forms, query parameters, comments |
| Historical URL Collection | Waybackurls, GAU, Katana, ParamSpider | Every URL ever seen for this domain |
| Parameter Discovery | Arjun, ParamSpider, x8 | Hidden/undocumented parameters |
| Directory Bruteforce | ffuf, dirsearch, gobuster, feroxbuster | Hidden directories, admin panels, backup files |
| Cloud Asset Enum | cloud_enum, S3Scanner, bucket-stream | Open S3 buckets, Azure blobs, Firebase DBs |
| WAF Detection | wafw00f, whatwaf | WAF vendor identification + bypass research |
| Content Discovery | ffuf with custom wordlists (raft, SecLists) | Hidden content, API docs, .git, .env |
| Technology Fingerprinting | WhatWeb, Wappalyzer CLI, nuclei tech detect | CMS, framework, version → known CVEs |
| Certificate Analysis | testssl.sh, sslscan | SSL/TLS misconfigurations, weak ciphers |

### Phase 3 — Vulnerability Testing (All 30+ Classes)

#### 3A — Injection Vulnerabilities

| Class | Sub-types | Test Method | Tools |
|-------|-----------|-------------|-------|
| **SQL Injection** | Error-based, Union, Boolean blind, Time blind, Second-order, NoSQL | Inject `'` `"` `OR 1=1` in every parameter; observe errors; use time delays | sqlmap, Burp Intruder, ghauri, nosqli |
| **XSS** | Reflected, Stored, DOM-based, Blind, Mutation XSS (mXSS) | Inject `<script>alert(1)</script>` in all inputs; test event handlers; test in JS context | dalfox, XSStrike, Burp Repeater, kxss |
| **SSTI** | Jinja2, Twig, Freemarker, Velocity, Jade | Inject `{{7*7}}` `${7*7}` — if output is 49, template injection confirmed | SSTImap, tplmap, Burp |
| **Command Injection** | Blind, Out-of-band (OOB) | Inject `; whoami` `| id` `$(whoami)`` \`whoami\` | commix, Burp Collaborator |
| **LDAP Injection** | AND/OR injection | Inject `)(|(user=*` in login fields | Custom, Burp |
| **XPath Injection** | Boolean, Out-of-band | Inject `' or '1'='1` in XML parameters | Custom |
| **XXE** | In-band, Blind OOB, XInclude | Inject `<!ENTITY xxe SYSTEM "file:///etc/passwd">` in XML | Burp Collaborator, xxeserv |
| **Template Injection** | Server + Client side | Same as SSTI, test in email templates, PDF generators | — |
| **Expression Language** | Spring EL, JBOSS EL, Struts | Inject `${7*7}` in Java framework parameters | — |

**Logic:** If param reflects in response → XSS first. If param in SQL query → SQLi. If error shows template syntax → SSTI. If OS command visible → command injection.

#### 3B — Authentication & Session Attacks

| Class | Test Technique | Tools |
|-------|----------------|-------|
| **Authentication Bypass** | SQLi in login, NoSQL in login, type confusion (array: `[]`), parameter pollution | Burp Repeater |
| **JWT Attacks** | None algorithm (`alg: none`), weak HMAC secret cracking (john/hashcat), kid injection, JKU bypass, JWK confusion | jwt_tool, jwt-cracker, Burp |
| **OAuth 2.0 Abuse** | CSRF on OAuth flow, redirect_uri tampering, state parameter leakage, code replay, token theft | Burp |
| **SAML Abuse** | XML Signature Wrapping, Assertion tampering, Response replay, Recipient check bypass | Burp, samlraider |
| **OTP/2FA Bypass** | Race condition, response manipulation, status code bypass, rate limiting bypass, null code | Burp Intruder, Turbo Intruder |
| **Session Fixation** | Pre-set session cookie, force victim to use known session | Burp |
| **Password Reset Poisoning** | Host header injection in reset link, token leak in URL, token prediction | Burp |
| **Rate Limiting Bypass** | IP rotation (X-Forwarded-For), cookie rotation, distributed attack | ffuf, Burp Intruder |
| **Credential Stuffing** | Test breached passwords, default credentials, weak password policy | hydra, ffuf |
| **Insecure Direct Object Reference** | Change user IDs in params/cookies/headers | Burp Repeater |
| **Registration Poisoning** | Register with admin email patterns, homograph attacks | Burp |
| **WebAuthn Bypass** | Credential ID prediction, policy bypass, cross-origin attestation | Custom |

**Logic:** If login → test bypasses. If JWT → crack. If OAuth → test redirect. If reset → test token.

#### 3C — Authorization Flaws (IDOR / BAC)

| Class | Test Technique | Tools |
|-------|----------------|-------|
| **IDOR (Insecure Direct Object Reference)** | Increment IDs (`1`→`2`→`1000`), UUID prediction, Base64/Hex decode IDs, hash ID analysis | Burp Repeater, Autorize |
| **Mass Assignment** | Add extra params: `role:admin`, `is_admin:true`, `account_type:premium` | Burp |
| **Privilege Escalation** | Lower-priv user accesses admin functions, CSRF token reuse, API rollback | Burp with 2 sessions |
| **API Auth Bypass** | Remove auth header, change to GET, downgrade HTTP version, use unauthenticated alias | Burp |
| **CORS Misconfiguration** | Origin reflection (`Origin: evil.com` → `Access-Control-Allow-Origin: evil.com`), wildcard, null origin | Corsy, Burp |
| **Function-Level Access Control** | Force browse to admin paths `/admin`, `/api/admin` | Burp, ffuf |
| **HTTP Method Tampering** | Change PUT→GET, POST→PATCH, bypass auth on non-standard methods | Burp |
| **GraphQL Bypass** | Field suggestions bypass, field-level auth bypass | graphw00f, Burp |

**Logic:** Every authenticated request with user-specific data → test IDOR. Every POST→test mass assignment.

#### 3D — Business Logic Flaws (Highest Bounty Potential)

| Class | Test Method | Examples |
|-------|-------------|----------|
| **Race Conditions** | Send N simultaneous requests (Turbo Intruder) | Double spend, coupon race, like race, cart inconsistency |
| **Negative/Fractional Values** | Negative price, %1111111111, decimal in integer field | Negative total, fractional inventory |
| **Workflow Bypass** | Skip steps, reorder steps, replay steps | Payment bypass, free shipping without login |
| **Coupon Abuse** | Stack coupons, reuse codes, mass use, create coupons | Unlimited free items |
| **Account Takeover Chains** | Low-prevalence bugs combined for full ATO | Self-XSS + no HttpOnly + IDOR on cookie |
| **Feature Abuse** | Use features beyond intended limits | Unlimited SMS, email bombing, storage abuse |
| **Logic Flaws in State Machines** | Transition to invalid states | Order already delivered → order refund |
| **Multi-tenant Isolation** | Access tenant B's data as tenant A | Shared DB, no row-level security |
| **API Version Downgrade** | Use `/api/v1/` instead of `/api/v2/` | Old vulnerable endpoints |
| **Input Validation in Unexpected Places** | File size limits, upload type bypasses | Zip-slip, SVG XXE |

**Logic:** Think like a developer who trusted the user and made assumptions about how features would be used.

#### 3E — Server-Side Vulnerabilities

| Class | Test Method | Tools |
|-------|-------------|-------|
| **SSRF** | URL params, file uploads, redirect-following, partial URLs | Burp Collaborator, SSRFmap, Interactsh |
| **LFI/RFI** | Path traversal `../../../etc/passwd`, PHP wrappers `php://filter` | dotdotpwn, Burp |
| **File Upload** | Extension bypass (`.php5`, `.phtml`, `.phar`), Content-Type bypass, magic bytes bypass | Burp |
| **Deserialization** | Insecure deserialization in PHP (`serialize`), Java, Python pickle, Ruby Marshal, NodeJS | ysoserial, PHPGGC, Burp |
| **Prototype Pollution** | Client-side via JSON merge, server-side via express merge | Custom, Burp |
| **Host Header Injection** | Cache poisoning, password reset poisoning, SSRF via Host | Burp, Collab |
| **HTTP Request Smuggling** | CL.TE, TE.CL, TE.TE, CL.0 | smuggler, Burp |
| **Cache Poisoning** | Unkeyed headers, Host header, cookie reflection | Burp |
| **Web Cache Deception** | Append `.css` to dynamic endpoint — cache returns sensitive data | Burp |
| **Path Normalization Bypass** | `//`, `../`, URL encoding bypass of WAF | Burp |

#### 3F — Infrastructure & Cloud

| Class | Test Method | Tools |
|-------|-------------|-------|
| **Subdomain Takeover** | CNAME pointing to unclaimed Azure/CDN/GitHub/S3/Heroku | subzy, nuclei takeover |
| **S3 Bucket Misconfig** | List/Read/Write anonymous access | S3Scanner, cloud_enum |
| **Security Header Analysis** | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options | nuclei, custom |
| **CVE Vulnerability Scan** | Known CVEs for detected software/framework versions | nuclei CVE templates |
| **WAF Bypass** | Encoding, case switching, parameter pollution, HTTP version downgrade | wafw00f, custom |
| **DNS Misconfig** | Zone transfer, DNSSEC missing, SPF/DMARC misconfig | dig, dnsrecon |
| **Open Ports Exposure** | Non-standard ports: 3000, 8080, 8443, 9200, 27017 | nmap, naabu |
| **Cloud Metadata SSRF** | `http://169.254.169.254/` — cloud metadata endpoint | Burp |
| **GraphQL Introspection** | `__schema` query enabled on production | graphw00f, Burp |
| **API Gateway IDOR** | Direct-to-service bypassing API gateway auth | Burp |
| **TLS/SSL Issues** | Weak ciphers, outdated protocols, certificate issues | testssl.sh, sslscan |

#### 3G — Modern Web Attack Surface (2026)

| Class | Description | Test Method |
|-------|-------------|-------------|
| **GraphQL Abuse** | Introspection, batching attacks, deep nesting DoS, alias-based rate limit bypass | Craft GraphQL queries |
| **WebSocket Attacks** | No auth on WS upgrade, cross-origin WS hijack, message injection | Burp WebSocket history |
| **WebAssembly (WASM)** | Reverse engineer WASM for hardcoded keys, business logic | wasm-decompile, Chrome devtools |
| **SAML SSO** | XML signature wrapping, assertion tampering, response replay | Burp, samlraider |
| **WebAuthn/Passkey** | Credential ID prediction, policy bypass, cross-origin attestation | Custom |
| **AI/LLM Security** | Prompt injection, training data extraction, prompt leaking, model abuse | Inject adversarial prompts |
| **Serverless Security** | Event injection, cold start manipulation, IAM misconfig | Cloud-specific |
| **Service Mesh / Sidecar** | mTLS bypass, Envoy config exploitation | Custom |
| **API Gateway Routing** | Route smuggling, service bypass | Burp |

### Phase 4 — Exploitation & PoC Creation

| Step | Action | Tools |
|------|--------|-------|
| **1. Reliable Reproduction** | Confirm the bug works 3/3 times | Burp Repeater |
| **2. Severity Escalation** | Make it worse: XSS → cookie theft → ATO; SQLi → RCE; SSRF → full internal network | Burp, sqlmap --os-shell |
| **3. Business Impact** | What data can we extract? Can we pivot? Prove real risk | Custom |
| **4. Chaining** | Chain 2+ low bugs into critical impact: IDOR + XSS = ATO; file upload + LFI = RCE; SSRF + cloud = credential access | Agent decides chains |
| **5. PoC Documentation** | Screenshot (UI bugs), curl commands, HTTP request/response, Burp files | Burp, auto-capture |
| **6. CVSS v3.1 Scoring** | Calculate CVSS with full vector string | Calculator |
| **7. Remediation** | Specific actionable fix, not generic advice | Auto-generated |

### Phase 5 — Reporting

| Section | Content |
|---------|---------|
| **Title** | `[Vuln Type] in [Endpoint] leads to [Impact]` |
| **Severity** | CVSS v3.1 vector + score (Critical/High/Medium/Low) |
| **Affected Component** | Exact URL, parameter, endpoint |
| **Description** | Clear technical explanation of the vulnerability |
| **Steps to Reproduce (2-5 steps)** | Numbered steps — anyone with access can verify |
| **Proof of Concept** | Screenshot(s) + curl command + raw HTTP request/response |
| **Impact** | Business risk: data exposure, account takeover, RCE, etc. |
| **Remediation** | Specific fix recommendation with code examples if possible |
| **References** | OWASP, CWE, CVE, related writeups |

#### Report Formats
- HackerOne-ready format (optimized for triage speed)
- Bugcrowd-ready format
- Markdown (default — export to any platform)
- JSON (for CI/CD integration)

## Complete Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     USER INTERFACE                                │
│  "/audit example.com"  "/ingest https://..."  "/watch example"   │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  LEVEL 1: HUNTBRAIN ORCHESTRATOR AGENT                           │
│  ─────────────────────────────────────                           │
│                                                                   │
│  1. Receive user goal → parse target                              │
│  2. Query MEMORY MCP → "What do we know about this target?"       │
│  3. Query WRITEUP RAG → "What techniques work for this tech?"     │
│  4. Decide strategy → spawn appropriate Level 2 agents           │
│  5. Read results → decide next phase                              │
│  6. Loop until no more attack surface                             │
│  7. Spawn Report Agent → generate submission                      │
│  8. Save findings to MEMORY MCP → "learn for next time"           │
└──────┬───────────────────────────────────────────────────────────┘
       │                    │                    │
       ▼                    ▼                    ▼
┌──────────────┐ ┌──────────────────┐ ┌──────────────────────┐
│ LEVEL 2:     │ │ LEVEL 2:         │ │ LEVEL 2:             │
│ RECON AGENT  │ │ SCAN AGENT       │ │ EXPLOIT AGENT        │
│              │ │                  │ │                      │
│ subfinder    │ │ nuclei           │ │ Burp Repeater        │
│ httpx        │ │ sqlmap           │ │ Burp Collaborator    │
│ katana       │ │ dalfox           │ │ sqlmap --os-shell    │
└──────┬───────┘ │ Burp Scanner     │ └──────────┬───────────┘
       │         └────────┬─────────┘            │
       │                  │                      │
       │    ┌─────────────▼──────────────┐       │
       │    │ DYNAMIC SPECIALISTS        │       │
       │    │ (spawned on demand)        │       │
       │    │                            │       │
       │    │ @graphql-agent             │       │
       │    │ @jwt-agent                 │       │
       │    │ @oauth-agent               │       │
       │    │ @cloud-agent               │       │
       │    │ @wordpress-agent           │       │
       │    │ @saml-agent                │       │
       │    │ @llm-agent                 │       │
       │    │ ... unlimited              │       │
       │    └────────────────────────────┘       │
       │                                         │
       └────────────────┬────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│  KNOWLEDGE LAYER (available to ALL agents at ALL levels)         │
│                                                                   │
│  ┌──────────────────────┐    ┌──────────────────────────────┐    │
│  │  WRITEUP RAG MCP     │    │  MEMORY MCP                  │    │
│  │  ───────────────     │    │  ──────────                  │    │
│  │                      │    │                              │    │
│  │  Query: find similar │    │  Query: what worked before   │    │
│  │  writeups by vuln    │    │  on this target / tech?      │    │
│  │  class / tech / year │    │                              │    │
│  │                      │    │  Stores: findings, chains,   │    │
│  │  Backend: ChromaDB   │    │  failed attempts, profiles   │    │
│  │  + sentence-transform│    │                              │    │
│  │                      │    │  Backend: SQLite             │    │
│  └──────────┬───────────┘    └──────────────┬───────────────┘    │
│             │                               │                    │
│             │    INGESTION PIPELINE          │                    │
│             │    ─────────────────           │                    │
│             │                               │                    │
│             │  Manual: ./ingest-writeup.sh   │  Auto: each hunt  │
│             │  "I found a great writeup!"   │  saves results     │
│             │                               │                    │
│             │  Automated (cron):            │                    │
│             │  ├── H1 Hacktivity RSS → daily│                    │
│             │  ├── GitHub writeup repos→ wk │                    │
│             │  └── Security blogs → weekly  │                    │
│             └───────────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────┘
```

## Knowledge Layer Deep Dive

### How the Writeup RAG System Works

```
                          ┌──────────────────────────────┐
                          │    CHROMADB (vector store)    │
                          │                              │
                          │  Embedding 1 → writeup-1.md  │
                          │  Embedding 2 → writeup-2.md  │
                          │  Embedding 3 → writeup-3.md  │
                          │  ...                         │
                          │  Embedding N → writeup-N.md  │
                          └──────────┬───────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
            ┌──────────────┐              ┌────────────────────┐
            │  MANUAL       │              │  AUTOMATED (CRON)  │
            │  INGESTION    │              │  INGESTION         │
            │               │              │                    │
            │  You find a   │              │  Every day at 6AM: │
            │  writeup →    │              │  ├─ Check H1 feed  │
            │  run script   │              │  ├─ Check RSS      │
            │  with URL     │              │  ├─ Fetch new docs │
            │               │              │  └─ Embed + store  │
            └──────────────┘              └────────────────────┘
```

#### Manual Ingestion (when you find something interesting)

```bash
# You found a great writeup on Medium
./scripts/ingest-writeup.sh \
  --url "https://medium.com/..." \
  --title "IDOR to Account Takeover in XYZ" \
  --vuln-class "IDOR" \
  --target-tech "Node.js, React" \
  --bounty "$2500" \
  --author "jane_doe"

# Or via OpenCode command
/ingest https://medium.com/... --class IDOR --tech React
```

#### Automated Ingestion (cron — runs without you)

```bash
# /etc/cron.d/huntmcp-writeups
0 6 * * * ankit /home/ankit/HuntMCP/scripts/cron-fetch.sh

# What cron-fetch.sh does:
# 1. curl HackerOne Hacktivity RSS → parse new disclosures
# 2. curl GitHub API → check known writeup repos for new commits
# 3. curl Medium RSS feeds → check security blogs
# 4. For each new writeup → download → chunk → embed → store
# 5. Log everything in cron-ingestion.log
# 6. Optionally: send Slack/Discord notification of what was added
```

### How the Memory MCP System Works

```python
# memory-mcp/server.py

# Store hunt results
memory-mcp.save(target="example.com", {
  "findings": ["XSS in search", "IDOR in /api/users"],
  "chains": ["XSS + IDOR = ATO"],
  "tech_stack": ["React", "Node.js", "MongoDB"],
  "subdomains": ["api.example.com", "admin.example.com"],
  "date": "2026-07-06",
  "total_bounty_estimate": "$3000-5000"
})

# Recall before next hunt
memory-mcp.recall("example.com")
→ "Hunted 3 weeks ago. React + Node.js. Found XSS + IDOR. 
   Recommend: check if XSS is fixed, test for SSRF next."

# Search by tech stack (for strategy)
memory-mcp.search_by_tech("React", "Node.js")
→ "3 past hunts on React+Node targets. 
   Common findings: XSS (67%), IDOR (50%), SSTI (33%)"
```

### How Agents Use the Knowledge Layer

```
HuntBrain: "Target uses React + Node.js + MongoDB"

Step 1: Query MEMORY → have we seen this combo?
  → "Yes, 3 past hunts. High XSS probability."

Step 2: Query WRITEUP RAG → any React-specific writeups?
  → "Writeup: 'XSS in React Search Bar — use </> with onfocus=...'
     Writeup: 'IDOR in Node.js REST API — increment user IDs'
     Writeup: 'NoSQL injection in MongoDB — use $ne, $gt'"

Step 3: Use writeup payloads in scan → find bugs faster

Step 4: Save findings → "This target also had SSTI"
  → Memory updated for next time
```

## Git Strategy: How Writeups Flow Through the Repo

### What Gets Pushed to GitHub vs What Stays Local

```
HuntMCP/
├── mcp-servers/           ← YES push to GitHub (your code)
├── .opencode/             ← YES push (agent configs)
├── scripts/               ← YES push (ingestion scripts)
├── knowledge/             ← YES push (payloads, wordlists, skill)
├── backend/               ← YES push (Go API code)
├── opencode.jsonc         ← YES push
├── AGENTS.md              ← YES push
├── README.md              ← YES push
│
├── data/
│   ├── chroma/            ← DO NOT PUSH (.gitignore) — too large, platform-specific
│   ├── memory.db          ← DO NOT PUSH (.gitignore) — local only
│   └── writeups/          ← YES PUSH (raw markdown, small, diffable, PR-able)
│       ├── xss-in-react-search.md     ~5 KB
│       ├── idor-in-node-api.md        ~3 KB
│       └── ssrf-via-collaborator.md   ~4 KB
│
└── .gitignore
    ├── data/chroma/
    ├── data/memory.db
    ├── __pycache__/
    └── *.pyc
```

### Why Raw Writeups (.md) Are Git-Friendly

| Property | Raw .md file | ChromaDB vectors |
|----------|-------------|------------------|
| Size per 1000 writeups | ~50 MB | ~2 GB |
| Diffable | ✅ Yes (text diff) | ❌ Binary gibberish |
| Mergeable | ✅ Yes (no conflicts) | ❌ Impossible |
| Human-readable | ✅ Anyone can review | ❌ Machine only |
| PR reviewable | ✅ Read the payload, verify quality | ❌ Can't review vectors |

### The Contribution Flow

```
CONTRIBUTOR FINDS A WRITEUP
        │
        ▼
./ingest-writeup.sh --url "https://..." --class XSS --tech React
        │
        ├── Creates: data/writeups/2026-07-06-xss-in-react.md
        │             └── Standard format with frontmatter + payload + impact
        │
        ├── Updates: data/chroma/ (local only, NOT staged)
        │
        └── Prints: "✅ Writeup saved! Commit the .md file to share."

CONTRIBUTOR SUBMITS PR
        │
        │  git add data/writeups/xss-in-react.md
        │  git commit -m "Add writeup: XSS in React search"
        │  git push origin main
        │
        ▼
MAINTAINER REVIEWS PR
        │
        │  Opens the .md file → checks:
        │  ├── Valid frontmatter (title, url, vuln_class, tech)
        │  ├── Has a real payload/technique
        │  ├── Has a clear impact description
        │  └── No duplicates
        │
        ▼
PR MERGED → GitHub Action triggers
        │
        ├── Python script runs: chunk → embed → POST to Go API
        │                        OR update local ChromaDB
        │
        └── All users now have access to the new writeup in RAG
```

### .gitignore

```gitignore
# Vector database (rebuilt locally from raw .md files)
data/chroma/

# Local memory database (each user has their own)
data/memory.db

# Python cache
__pycache__/
*.pyc

# Logs
logs/*.log

# Environment
.env
```

---

## Tech Stack Decision: Go vs Python

| Component | Choice | Reason |
|-----------|--------|--------|
| **Backend API** | **Go** (Gin/Echo/Fiber) | Performance, single binary, goroutines for concurrent MCP connections, low memory |
| **Embedding** | **Python** (microservice only) | `sentence-transformers` is the gold standard; runs only in CI/CD, not in live path |
| **Database** | **PostgreSQL + pgvector** | Relational + vector search in one DB; no extra service; battle-tested |
| **Frontend** | **Next.js** (React/TypeScript) | Full-stack framework, easy auth, SSR for SEO, good ecosystem |
| **CI/CD** | **GitHub Actions** | Native to repo, free for public repos, easy to configure |
| **Hosting** | **Railway / Render / Fly.io** | Simple deployment, managed PostgreSQL, auto-scaling, free tier |

### The Only Python Component

```python
# embedder/server.py — 30 lines, runs ONLY during ingestion
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')

@app.post("/embed")
def embed(text: str):
    return {"vector": model.encode(text).tolist()}
```

This tiny service is:
- Called only when a writeup is ingested (PR merge or admin action)
- Never in the hot path of user queries
- Stateless — zero overhead when not in use
- Replaceable with Ollama (pure Go) or OpenAI API if desired

**No future issues with Go.** The Go API handles 100% of production traffic. Python is a build tool, not a runtime dependency.

---

## Project Structure

```
HuntMCP/
│
├── mcp-servers/                           Custom Python MCP servers
│   ├── subfinder-mcp/
│   │   └── server.py                      FastMCP wrapping subfinder
│   ├── httpx-mcp/
│   │   └── server.py                      FastMCP wrapping httpx
│   ├── nuclei-mcp/
│   │   └── server.py                      FastMCP wrapping nuclei
│   ├── ffuf-mcp/
│   │   └── server.py                      FastMCP wrapping ffuf
│   ├── sqlmap-mcp/
│   │   └── server.py                      FastMCP wrapping sqlmap API
│   ├── dalfox-mcp/
│   │   └── server.py                      FastMCP wrapping dalfox
│   ├── katana-mcp/
│   │   └── server.py                      FastMCP wrapping katana
│   ├── nmap-mcp/
│   │   └── server.py                      FastMCP wrapping nmap
│   ├── writeup-mcp/                       KNOWLEDGE LAYER
│   │   ├── server.py                      FastMCP for RAG queries
│   │   ├── chroma_client.py               ChromaDB integration
│   │   ├── embedder.py                    Sentence embeddings
│   │   └── requirements.txt
│   └── memory-mcp/                        KNOWLEDGE LAYER
│       ├── server.py                      FastMCP for memory queries
│       ├── db.py                          SQLite schema + queries
│       └── requirements.txt
│
├── .opencode/
│   ├── agents/
│   │   ├── huntbrain.md                   LEVEL 1: Orchestrator
│   │   ├── recon-agent.md                 LEVEL 2: Recon specialist
│   │   ├── scan-agent.md                  LEVEL 2: Scan specialist
│   │   ├── exploit-agent.md               LEVEL 2: Exploit specialist
│   │   ├── report-agent.md                LEVEL 2: Report specialist
│   │   ├── graphql-agent.md               DYNAMIC: spawned on demand
│   │   ├── jwt-agent.md                   DYNAMIC: spawned on demand
│   │   ├── oauth-agent.md                 DYNAMIC: spawned on demand
│   │   └── cloud-agent.md                 DYNAMIC: spawned on demand
│   │
│   └── commands/
│       ├── audit.md                        /audit <target> [--deep]
│       ├── ingest.md                       /ingest <url> [--class XSS] [--tech React]
│       ├── watch.md                        /watch <target> [--interval 6h]
│       ├── report.md                       /report <scan-id>
│       ├── chain.md                        /chain <scan-id>
│       └── learn.md                        /learn <query> (query writeup DB)
│
├── scripts/
│   ├── ingest-writeup.sh                   Manual writeup ingestion
│   ├── cron-fetch.sh                       Automated feed ingestion
│   ├── setup-tools.sh                      Install all Go/Python tools
│   └── setup-db.sh                         Initialize ChromaDB + SQLite
│
├── knowledge/
│   ├── owasp-wstg-skill.md                 SKILL.md: Full OWASP methodology
│   ├── payloads/
│   │   ├── xss.txt                         XSS payloads (1000+)
│   │   ├── sqli.txt                        SQLi payloads (500+)
│   │   ├── ssti.txt                        SSTI payloads (200+)
│   │   ├── lfi.txt                         LFI paths (100+)
│   │   └── ssrf.txt                        SSRF URLs (50+)
│   └── wordlists/
│       ├── api-endpoints.txt               API endpoint wordlist
│       └── subdomains-top-1m.txt           Subdomain wordlist
│
├── data/
│   ├── chroma/                             ChromaDB persistent storage
│   ├── memory.db                           SQLite memory database
│   └── writeups/                           Raw writeup markdown files
│
├── logs/
│   ├── hunt-*.log                          Per-hunt logs
│   └── cron-ingestion.log                  Writeup ingestion logs
│
├── opencode.jsonc                          Complete MCP config + permissions
├── AGENTS.md                               Project-level instructions
└── README.md                               Full documentation
```

## Evolution Path: Local → Go Backend → Full Platform

HuntMCP is designed to evolve across three phases. The architecture at each phase is compatible with the next — you never rewrite, you add.

```
PHASE 1: LOCAL (Months 1-2)     →    PHASE 2: GO BACKEND (Months 3-4)    →    PHASE 3: FULL PLATFORM (Months 5-6)

┌─────────────────────┐              ┌─────────────────────────┐              ┌──────────────────────────────┐
│  Your local machine  │              │  Go API Server + DB      │              │  Web App + CI/CD + Community │
│                     │              │                         │              │                              │
│  ChromaDB (local)   │              │  PostgreSQL + pgvector   │              │  Multi-user auth             │
│  SQLite (local)     │     ───►     │  Go API (Gin/Echo/Fiber) │    ───►      │  Writeup PR auto-train CI/CD │
│  All MCPs local     │              │  Embedder microservice   │              │  Web dashboard               │
│  Single user        │              │  MCP endpoint             │              │  Public API                  │
└─────────────────────┘              │  Multi-user (team)       │              │  Leaderboard + contributions │
                                      └─────────────────────────┘              └──────────────────────────────┘
```

---

## Go Backend (Implemented)

The Go backend described below is **built**, not planned — see `backend/` and [CLAUDE.md](CLAUDE.md) for the exact file layout. This section only records the design rationale; for current routes/structure read the code.

| Aspect | FastAPI (Python) | Go (Gin) — chosen |
|--------|-----------------|---------------------|
| Performance | ~3k req/s | ~50k req/s |
| Concurrency | Async/await | Goroutines (native) |
| Binary size | ~100MB + runtime | ~15MB single binary |
| Deployment | Needs Python runtime | One binary, no dependencies |

Real endpoints (see `backend/cmd/server/main.go`): `/health`, `/api/v1/auth/{register,login}`, `/api/v1/writeups*`, `/api/v1/query` (RAG), `/api/v1/hunts*`, `/api/v1/stats`, `/api/v1/admin/*`, and `POST /mcp` (MCP protocol bridge). Auth is JWT via `internal/middleware`. There is **no Redis** in the current stack (`docker-compose.yml` runs `postgres`, `api`, `embedder`, plus the `writeup`/`memory` MCP services) — caching was scoped out, not silently dropped; add it back deliberately if query latency becomes a problem.

The embedder (`backend/embedder/server.py`) is a ~30-line `sentence-transformers` microservice used only at ingestion/reindex time — the Go API serves all production read/query traffic.

```sql
-- pgvector schema (see backend/migrations/ for the real, current version)
CREATE EXTENSION vector;
CREATE TABLE writeups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    embedding VECTOR(384),
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_writeups_embedding ON writeups
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
```

### Local MCP servers vs. Go backend — current gap

**Not yet wired up:** the Python MCP servers (`mcp-servers/writeup-mcp`, `mcp-servers/memory-mcp`) currently talk only to local ChromaDB/SQLite — there is no `HUNTMCP_BACKEND_URL`-style dual mode calling the Go API yet. Until that's built, the Go backend and the local OpenCode agent system are two independent, unconnected implementations of the same knowledge layer. Wiring the local MCP servers to optionally call the Go `/api/v1/query` and `/api/v1/hunts` endpoints (falling back to local storage when `HUNTMCP_BACKEND_URL` is unset) is the concrete next step to make Phase 2 actually useful to the Phase 1 agents, rather than a parallel backend nobody calls.

### When to route through the Go backend instead of local storage

| Signal | Trigger |
|--------|---------|
| **Team grows** | 2+ people using HuntMCP → need shared DB |
| **ChromaDB > 2GB** | Local vector DB becomes slow → pgvector is faster |
| **Community contributions** | PRs with writeups → CI/CD auto-train pipeline |
| **Need web access** | Dashboard, API, mobile access |

---

## Phase 3: Full Platform (Months 5-6)

When the Go backend is stable, add the web platform for community contributions and auto-training.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GITHUB REPO                                        │
│                                                                              │
│  data/writeups/*.md   ← Contributors submit PRs with new writeups           │
│                                                                              │
│  PR MERGED → triggers GitHub Action → auto-deploy                           │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CLOUD BACKEND (Go API + PostgreSQL)                  │
│                                                                              │
│  CI/CD (Python embedder) → embeds new writeup → stores in pgvector          │
│                                                                              │
│  Go API serves:                                                              │
│  ├── MCP endpoint for local HuntMCP clients                                  │
│  ├── REST API for web dashboard                                              │
│  └── Admin API for reindexing / management                                   │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
┌──────────────────────────┐  ┌──────────────────────────────┐
│  LOCAL HUNTMCP CLI        │  │  WEB DASHBOARD               │
│  (each user's machine)    │  │  (React / Next.js)            │
│                           │  │                              │
│  Connects to Go API via   │  │  Pages:                      │
│  writeup-mcp (cloud mode) │  │  ├── Dashboard (stats)       │
│  or works offline (local) │  │  ├── Writeups (browse)       │
│                           │  │  ├── Add (submit writeup)    │
│                           │  │  ├── Query (test RAG)        │
│                           │  │  └── Admin (manage)          │
└──────────────────────────┘  └──────────────────────────────┘
```

### CI/CD Auto-Train Pipeline

```yaml
# .github/workflows/auto-train.yml
name: Auto-Train RAG

on:
  pull_request:
    paths: ["data/writeups/*.md"]
    types: [closed]

jobs:
  validate-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Validate writeup files
        run: |
          python scripts/validate-writeups.py data/writeups/
          # Checks: valid frontmatter, required fields, no duplicates

      - name: Build vectors and deploy
        env:
          BACKEND_URL: ${{ secrets.BACKEND_URL }}
          API_KEY: ${{ secrets.API_KEY }}
        run: |
          pip install sentence-transformers chromadb
          python scripts/build-and-deploy.py \
            --input data/writeups/ \
            --api-url $BACKEND_URL \
            --api-key $API_KEY
          # This: chunks → embeds → POSTs to Go API → stored in pgvector

      - name: Notify contributor
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: "✅ Writeup ingested into RAG database! Vector DB updated."
            })
```

### Web Dashboard Frontend

```
frontend/
├── pages/
│   ├── dashboard.tsx         Stats graph, recent writeups, contributor leaderboard
│   ├── writeups.tsx          Browse/search/filter all writeups
│   ├── writeups/[id].tsx     Single writeup detail with payload viewer
│   ├── add.tsx               Form to add writeup (alternative to CLI)
│   ├── query.tsx             Test RAG queries against live vector DB
│   ├── login.tsx             GitHub OAuth login
│   └── admin.tsx             User management, reindex trigger, logs
├── components/
│   ├── WriteupCard.tsx       Reusable writeup preview
│   ├── SearchBar.tsx         With vuln-class / tech / bounty filters
│   ├── StatsChart.tsx        Monthly ingestion chart
│   ├── Navbar.tsx
│   └── Footer.tsx
├── lib/
│   ├── api.ts                API client for Go backend
│   └── auth.ts               Auth helpers
├── package.json
└── next.config.js
```

### Community Contribution Flow

```
CONTRIBUTOR                    GITHUB                      BACKEND
    │                           │                            │
    ├─ Fork repo                │                            │
    ├─ ./ingest-writeup.sh      │                            │
    │  → creates .md file       │                            │
    │  → validates locally      │                            │
    │                           │                            │
    ├─ git add + commit         │                            │
    ├─ git push origin branch   │                            │
    │                           │                            │
    │                    ┌──────▼────────┐                   │
    │                    │  PR SUBMITTED  │                   │
    │                    │  Auto-validate │                   │
    │                    │  Review by     │                   │
    │                    │  maintainers   │                   │
    │                    └──────┬────────┘                   │
    │                           │                            │
    │                    ┌──────▼────────┐                   │
    │                    │  PR MERGED     │                   │
    │                    └──────┬────────┘                   │
    │                           │                            │
    │                    ┌──────▼────────┐                   │
    │                    │  GITHUB ACTION │                   │
    │                    │  ─────────────  │                  │
    │                    │  1. Validate    │                  │
    │                    │  2. Embed       ├────────────────► │
    │                    │  3. Deploy      │                  │
    │                    │  4. Notify      │                  │
    │                    └─────────────────┘                  │
    │                                                         │
    │                                              ┌─────────▼────────┐
    │                                              │  pgvector updated │
    │                                              │  All users now    │
    │                                              │  query the new    │
    │                                              │  writeup in RAG   │
    │                                              └──────────────────┘
    │                                                         │
    │                    ┌────────────────────────────────────┘
    │                    │
    │              GitHub comment:
    │              "✅ Writeup ingested!
    │               Vector DB updated."
```

### Platform Features Summary

| Feature | Phase 1 (Local) | Phase 2 (Go Backend) | Phase 3 (Full Platform) |
|---------|-----------------|---------------------|------------------------|
| **Writeup storage** | ChromaDB (local) | PostgreSQL + pgvector | PostgreSQL + pgvector + backups |
| **Memory storage** | SQLite (local) | PostgreSQL | PostgreSQL |
| **MCP endpoint** | Local process | Go API /mcp endpoint | Go API + load balanced |
| **Multi-user** | ❌ Single user | ✅ Small team | ✅ Unlimited (auth) |
| **Web UI** | ❌ None | ❌ None | ✅ Next.js dashboard |
| **CI/CD auto-train** | ❌ Manual cron | ❌ Manual cron | ✅ Auto on PR merge |
| **Community contributions** | ❌ Manual only | ✅ GitHub PRs | ✅ PRs + Web form |
| **Auth** | ❌ None | ✅ API key or JWT | ✅ GitHub OAuth |
| **Public API** | ❌ None | ❌ Internal | ✅ Documented API |
| **Hosting** | Your machine | VPS (Railway/Render) | Scalable cloud (K8s) |
| **Backups** | ❌ None | ✅ DB dumps | ✅ Automated |
| **Monitoring** | ❌ None | ❌ Basic | ✅ Metrics + alerts |

## Build Plan

### Phase 1: Local System — ✅ Complete

| Sprint | What | Status |
|--------|------|--------|
| 1 | Directory structure + all 5 agent files (HuntBrain, Recon, Scan, Exploit, Report) | ✅ Done — agents are skeletal (see Methodology Engine); depth is the remaining work |
| 2 | Knowledge layer: `writeup-mcp` (ChromaDB) + `memory-mcp` (SQLite) + ingestion scripts | ✅ Done |
| 3-4 | 8 tool MCP wrappers (subfinder, httpx, katana, nmap, nuclei, sqlmap, dalfox, ffuf) | ✅ Done |
| 5 | Chaining engine (`chainer-mcp`) + Watch mode (`watch-mcp`) | ✅ Done |
| — | Docker + GitHub Actions CI | ✅ Done |

### Phase 2: Go Backend — ✅ Complete

| What | Status |
|------|--------|
| Go API server (Gin) — writeups/hunts/auth CRUD | ✅ Done — `backend/internal/handler` |
| PostgreSQL + pgvector integration | ✅ Done — `backend/internal/repository`, `backend/migrations` |
| Python embedder microservice | ✅ Done — `backend/embedder` |
| MCP protocol endpoint in Go | ✅ Done — `POST /mcp` |
| Docker Compose deployment | ✅ Done |
| **Local MCP servers actually calling the Go backend (dual local/cloud mode)** | ❌ Not done — see "Local MCP servers vs. Go backend — current gap" above |

### Phase 2.5: Methodology Depth — ✅ Complete

| What | Status |
|------|--------|
| Add `knowledge/master-pentest-prompt.md` | ✅ Done — redacted, `[PHASE N]`-indexed, HuntMCP-integration header mapping phases to agent files |
| Expand `.opencode/agents/*.md` to reference/apply it | ⚠️ Partial — agents reference it and grep the relevant phases; technique detail is not yet embedded per-vuln-class inline (the Claude-BugHunter pattern from the integration map) |
| Stand up `chat-logs/lessons-learned.md` + write-back flow | ✅ Done — `mcp-servers/lessons-mcp/` (`append_lesson`, `read_lessons`, `check_size`), called automatically by exploit-agent after every validation, not left to memory |
| Add explicit scope-confirmation step to HuntBrain Phase 0 | ✅ Done — `mcp-servers/scope_guard.py` + `scripts/check-scope.sh`, real tested mechanism, not prose |

### Phase 2.6: Harness & Safety Hardening — ✅ Complete

Not originally planned as its own phase, but this is what actually got built once 2.5 exposed the gap between "agents that name phases" and "agents that can safely execute them":

| What | Status |
|------|--------|
| Claude Code native harness (`.claude/agents/*.md`, `.claude/commands/audit.md`, `.mcp.json`) | ✅ Done — verified against the real Claude Code subagent/MCP schema, tool-restricted per role |
| Reactive (not proactive) rate-limiting | ✅ Done — `classify_block()` + single retry in `tool_resolver.run_tool()`, wired into all 9 subprocess-calling MCP servers |
| Model provider gateway, no lock-in | ✅ Done — `mcp-servers/model_gateway.py`, wired into OpenCode via `scripts/select-model.sh` |
| JWT secret fail-fast instead of silent placeholder | ✅ Done — `backend/internal/service/auth_service.go` |
| Fixed pre-existing bugs found while wiring the above | ✅ Done — OpenCode exploit-agent's `bash: deny` contradicting its own instructions; huntbrain's `edit: deny` blocking `engagement.yaml`; `run_tool()`'s `capture_output` kwarg collision with watch-mcp's existing calls |
| `watch-mcp` scope-gate | ✅ Done — recon/scan/exploit rely on the *agent* running `check-scope.sh` before calling their MCP tools, but `watch-mcp` can be triggered unattended by cron (`scripts/setup-watch.sh`) with no agent in the loop to do that. Added `scope_guard` checks directly inside `start_watch()`/`check_target()`, and rewrote the generated cron wrapper to call the real `check_target()` (which now enforces scope) instead of a divergent inline reimplementation that had neither scope-checking nor `tool_resolver`'s rate-limit handling |

### Phase 2.7: Knowledge & Model Backlog — ✅ Complete

| What | Status |
|------|--------|
| Local fine-tuned model as a provider | ✅ Done — `HUNTMCP_LOCAL_MODEL` env var overrides the `ollama` chain entry's model name (defaults to `whiterabbitneo`), so any locally-hosted fine-tune (e.g. a QLoRA'd model) is selectable with zero code changes: `HUNTMCP_MODEL=ollama HUNTMCP_LOCAL_MODEL=my-finetune` |
| CVE search index | ✅ Done — `mcp-servers/writeup-mcp/cve_fetch.py` pulls CVEs from the NVD REST API for a keyword and writes them as writeup-shaped `.md` files (reuses the existing chunk/embed/ChromaDB pipeline rather than a parallel store); exposed as writeup-mcp's `fetch_cves(keyword, limit)` tool and `scripts/fetch-cves.sh`. Idempotent (already-fetched CVEs are skipped) and gitignored (`data/writeups/cve-*.md`) so auto-fetched dumps don't dilute the curated, git-tracked writeup set. scan-agent calls it in Phase 0 when a specific product/version is fingerprinted |

### Phase 2.8: claude-bug-bounty-derived Backlog (High priority done, Medium/Lower not started)

Researched from [`shuvonsec/claude-bug-bounty`](https://github.com/shuvonsec/claude-bug-bounty)
(4.3k★, actively maintained) on 2026-08-22, including its own `docs/CAPABILITY-GAPS.md`
self-audit. Ranked by leverage for *this* project's actual use case (real H1 hunting,
solo operator) rather than raw feature count.

**High priority — directly closes a flagged gap or the user's stated H1 duplicate problem:**

| What | Idea | Notes |
|------|------|-------|
| Scope enforcement via Claude Code hooks | ✅ Done — `scripts/hooks/scope_gate_hook.py`, wired via `.claude/settings.json`'s `PreToolUse` hook. Runs `scope_guard.is_in_scope()` before every `Bash` call whose invoked binary is one of the actual Tier-2 tools (`subfinder`/`httpx`/`katana`/`nmap`/`nuclei`/`sqlmap`/`dalfox`/`ffuf`) and every Tier-2 MCP tool call (`subfinder-mcp`, `httpx-mcp`, `katana-mcp`, `nmap-mcp`, `nuclei-mcp`, `sqlmap-mcp`, `dalfox-mcp`, `ffuf-mcp`, `watch-mcp`, `waf-bypass-mcp`), blocking (exit 2) any real-looking target host that isn't in `engagement.yaml`'s `in_scope` list. `example.com`/`localhost`/RFC1918/loopback are always allowed with no `engagement.yaml` needed — ordinary MCP-server dev/testing (like this session's own httpx screenshot testing) stays unaffected, only real-looking non-test hosts require a written engagement. Knowledge-layer MCP servers (`writeup-mcp`, `memory-mcp`, `lessons-mcp`, `chainer-mcp`) and any Bash command not invoking a Tier-2 binary (`git`, `go install`, `pip install`, etc.) are exempt so this can't break normal repo development. Tested against 11 scenarios (safe-host allow, real-target block with/without `engagement.yaml`, in-scope allow, explicit out-of-scope block, non-Tier-2 server exemption, malformed-input fail-open) — strictly stronger than the previous instruction-only design: an LLM can no longer skip `check-scope.sh` by simply not calling it | Strictly stronger than the previous design: today, scope compliance depended on each agent's system-prompt instruction to run `check-scope.sh` first — an LLM could in principle skip it. A hook makes it structurally unskippable instead of instructed |
| HackerOne MCP server | ✅ Done — `mcp-servers/hackerone-mcp/server.py`. `sync_program_scope(handle)` pulls a program's structured scope from H1's official v1 API and formats it as an engagement.yaml-ready snippet (never writes the file itself — HuntBrain still owns that write, once, at Phase 0). `check_my_duplicates(handle, keyword)` searches the *authenticated hunter's own accessible reports* for likely self-duplicates before writing one up. **Honest scope note**: H1's API does not expose other hunters' private/pending reports to you — that's a deliberate platform privacy boundary, not a gap here, so this is a self-duplicate check, not a full program-wide one; the original idea's "check for existing/duplicate reports" framing overstated what's actually achievable, corrected here. **Read-only by design, no exceptions** — no submit/create-report call exists in this file; report-agent's local-draft-only design remains the actual submission boundary. **Caveat unlike every other tool built this session: NOT functionally tested against a live HackerOne account** (no test API credentials were available) — request-building and JSON-parsing logic were verified against mocked responses matching H1's documented API shape, and the no-credentials error path was tested for real, but the exact endpoint paths/field names need a real-account pass before being fully trusted | Directly targets the user's stated problem: reducing HackerOne duplicates, without ever letting an unreviewed AI-drafted report reach a program |
| OOB interaction listener | ✅ Done — `mcp-servers/oob-mcp/server.py` wraps `interactsh-client`. `generate_payload_url(label)` starts a detached, session-persistent listener (`start_new_session=True` so it survives independently of whatever short-lived call spawned it) and returns a real callback URL; `check_interactions(url)` reads the accumulated DNS/HTTP/SMTP hits; `list_listeners()` / `stop_listener(url)` manage the registry (`data/oob-sessions/registry.json`, gitignored). Counted once against the Phase 2.9 budget circuit-breaker per listener started. Wired into `opencode.jsonc`/`.mcp.json` and granted to exploit-agent in both harnesses, referenced directly from the Phase 1.5 SSRF rationalization check. Functionally tested end-to-end against the real interactsh public infrastructure: generated a live `*.oast.fun` URL, confirmed the background process survives after its launching process exits, fired a real `curl` at the callback, and confirmed both the DNS and HTTP interactions were correctly captured and reported | Was the #1 highest-leverage gap in claude-bug-bounty's own audit. Previously HuntMCP's only OOB path was optional Burp Collaborator — this removes that dependency |
| WAF bypass tooling | ✅ Done — `mcp-servers/waf-bypass-mcp/server.py`'s `attempt_bypass(url, baseline_status, tiers, delay)`. Automates Tiers 1-4 of `knowledge/master-pentest-prompt.md`'s Phase 0.6 403/WAF bypass guide (24 variants: 9 header/UA spoofs, 8 path manipulations, 6 method switches, 3 HTTP-version tricks) via direct curl calls, reports every variant whose status differs from the observed block code. Tier 5 (CDN/origin-IP bypass) needs external OSINT (Shodan/Censys/CT logs) rather than a retry loop, so it's intentionally left manual, per the master prompt. Scope-gated like the other Tier-2 MCP servers (its `url` arg is covered by the Phase 2.8 scope-gate hook above); counts once against the Phase 2.9 budget circuit-breaker per call, not per variant. Functionally tested against a real target (all 24 variants execute correctly, exact `%61dmin`-style encoding matches the master prompt's own example, malformed `tiers` input handled) | Closes a gap flagged and left open during Phase 2.6: reactive rate-limiting detects a WAF block and surfaces it, but nothing automated actually attempts a bypass yet |

**Medium priority — real coverage gaps, no dependency conflicts:**

| What | Idea | Notes |
|------|------|-------|
| Secrets/credential scanning | ✅ Done — `mcp-servers/secrets-mcp/server.py`'s `scan_directory(path, redact)` wraps `gitleaks` over local files (katana-crawled JS, a downloaded `.git`/`.env`). Local-file-only, not a live-target action, so not scope-gated. Granted to recon-agent, called right after a katana crawl in both harnesses. Functionally tested: correctly ignores AWS's well-known EXAMPLE key (gitleaks' own allowlist) but flags a real-shaped Stripe token with file/line/redacted-match output | HuntMCP has zero secrets-scanning capability today |
| Structured audit log | ✅ Done — `mcp-servers/audit_log.py`, wired into `tool_resolver.run_tool()`'s shared chokepoint (same pattern as `budget_guard`). One JSON line per Tier-2 call to gitignored `data/audit.jsonl`: timestamp, tool, args, returncode, duration, WAF/rate-limit classification | No audit trail exists today; matters for reviewing/debugging a real engagement after the fact, and for eventual Cyber Verification Program review |
| Visual triage / screenshot gallery | `httpx -screenshot` (already available in the underlying httpx binary, not yet exposed by `httpx-mcp`) into a self-contained HTML gallery, doubling as report PoC evidence | Cheap — no new dependency, `httpx-mcp` just needs one more flag exposed |
| Methodology as Claude Code Skills | ✅ Done, and now actively growing past the original scope — `.claude/skills/writing-great-skills/SKILL.md` (meta-skill, conventions) plus 47 content skills: all 59 original phases (Phase 0-37) plus 3 genuinely new phases (38 CI/CD & supply chain, 39 Kubernetes & container security, 40 race conditions/TOCTOU) sourced from a private GitHub-survey research pass (`RESEARCH-TODO.md`, gitignored) that identified real coverage gaps against comparable open-source offensive-AI-agent skill catalogs — written directly as both a new `[PHASE N]` section in `master-pentest-prompt.md` and a matching skill, not converted from pre-existing content. `master-pentest-prompt.md` stays the source of truth for OpenCode (unchanged, still grep-able) — `.claude/skills/` is an additional Claude-Code-only front door, not a replacement; see its own header for the exact phase→skill mapping rather than duplicating that list here. Deliberately grouped by testing concern, not 1:1 with phase numbers. Content-preservation checked per batch by spot-verifying specific technique strings (CVE IDs, exact bypass syntax, tool names) survived the conversion. **Location correction** (caught via the user's "research to optimize" instruction, before more phases piled onto the wrong spot): the first two batches were initially written to a bare top-level `skills/` — Claude Code only discovers project skills at `.claude/skills/<name>/SKILL.md`, verified against the real docs; moved and all path references fixed. Three skills (`auth-and-session`, `access-control-and-idor`, `injection-and-rce`) now cite real, WebSearch-verified disclosed HackerOne report numbers as concrete precedent (report titles cross-checked against the search index before citing; full report bodies aren't fetchable — HackerOne's report pages are a JS-rendered SPA that returns no content to a plain fetch — so citations are scoped to what the indexed title itself states, nothing embellished beyond that) — this and the MFA-bypass research earlier were both folded into existing skills in place rather than filed as new Writeup RAG entries: durable, cross-cutting technique knowledge goes into a skill; high-volume per-writeup/per-target material keeps flowing into the existing Writeup RAG / Memory DB pipeline unchanged. Meta-skill/validator ideas from the same research pass (false-positive rationalizations-to-reject table, cross-model second-opinion validation, confidence calibration, duplicate-finding check) turned out to already be implemented — `exploit-agent.md`'s Phase 1.5 and `mcp-servers/second-opinion-mcp`/`dedupe_check.py` — confirming rather than adding. Future new phases (or fresh research) get folded in the same way, per the meta-skill's conventions, rather than reopening this as a phased backlog item | Cleaner than one big grep-able file; skills load progressively instead of requiring agents to grep line ranges |
| Automated test suite | ✅ Done — `tests/` (47 tests): `scope_guard`, `budget_guard`, `audit_log`, `work_registry`, `tool_resolver.classify_block`/`resolve_tool`, and `scope_gate_hook`'s host-extraction + end-to-end `main()` decision logic (safe-host allow, real-target block, in/out-of-scope, non-Tier-2 exemption, malformed-input fail-open). Wired into CI as a new `unit-tests` job. Found and fixed a real testability gap while writing these: `audit_log.log_call()` had no `path` param (unlike every other guard module), hardcoding `data/audit.jsonl` — fixed to accept an optional `path`, matching `scope_guard`/`budget_guard`/`work_registry`'s existing pattern | claude-bug-bounty has 60+ test files; HuntMCP had none |

**Lower priority — coverage expansion, larger scope commitment:**

| What | Idea | Notes |
|------|------|-------|
| SAST source audit | `semgrep`-based source scanning for JS pulled during recon | Adds source-level static analysis alongside HuntMCP's current pure black-box/DAST approach — a philosophy shift worth confirming before building |
| Web3/smart-contract auditing | Slither/Aderyn/Echidna/Mythril wrapper + a `web3-auditor` specialist | Whole new domain, not a small addition — only worth it if in-scope for actual target programs |
| Mobile (Android/iOS) testing | APK decompile, Frida/objection scripting, MobSF | Also a new domain; HuntMCP is currently web-only |

### Phase 2.9: Strix-derived Backlog (✅ Complete)

Researched from [`usestrix/strix`](https://github.com/usestrix/strix) (57k★, actively
maintained — pushed the same day this was researched, 2026-08-22) via its actual source, not
just the README: `strix/core/hooks.py`, `strix/tools/agents_graph/tools.py`,
`strix/llm/compaction.py`/`context_budget.py`, `strix/tools/proxy/caido_api.py`. Strix's
orchestration model is architecturally different from HuntMCP's (any agent can spawn any
other agent into a shared live graph, vs. HuntBrain's fixed Level 1 → Level 2 hierarchy) —
most items below are deliberately scoped to take the *specific mechanism* worth having
without adopting that broader philosophy shift, consistent with [[feedback-speed-vs-accuracy]]
and the earlier single-vs-multi-orchestrator discussion (coordination/locking cost of a full
agent graph isn't worth it at HuntMCP's current scale).

| What | Idea | Notes |
|------|------|-------|
| Budget circuit-breaker | ✅ Done — `mcp-servers/budget_guard.py`, wired into `tool_resolver.run_tool()`'s single shared chokepoint (every Tier-2 MCP server routes through it). Tracks **cumulative Tier-2 tool-call count**, not literal LLM $ cost — no MCP server has visibility into the orchestrating agent's own token spend (that number lives inside whichever harness is driving the session, not exposed to a subprocess-launching tool server), so call volume is used as an honest, directly-observable proxy for "is something burning unbounded spend" instead of pretending to meter dollars it can't see. Graduated stderr warnings at 70/85/95% of `HUNTMCP_MAX_TOOL_CALLS` (default 500), hard stop (`BudgetExceeded`, subprocess never runs) at 100%. State in gitignored `budget.json`, reset by HuntBrain at Phase 0 alongside `engagement.yaml`; `scripts/check-budget.sh` for an on-demand status read. Functionally tested end-to-end with a low cap (10 calls): warnings fired at exactly 7/9/10 calls, call 10 onward correctly raised and blocked before the subprocess ran | HuntMCP had *no* cost/volume guardrail before this — a stuck loop or an unexpectedly large attack surface could burn unlimited API spend with nothing noticing. Small, self-contained, no dependency on adopting the agent-graph model |
| Duplicate-work check before spawning a specialist | ✅ Done — `mcp-servers/work_registry.py` (`start_work`/`complete_work`/`list_active_work`/`list_all_work`), CLI via `scripts/check-work.sh {start,complete,active,all}`. State in gitignored `work-registry.json`, reset by HuntBrain at Phase 0 alongside `engagement.yaml`/`budget.json`. HuntBrain checks `active <host>` before every specialist spawn (including retries and future dynamic specialists) and records `start`/`complete` around each — deliberately on disk rather than relying on HuntBrain's own conversation context, since a long engagement getting context-compacted mid-run (a real thing that happened in this repo's own development) can otherwise lose track of what's already running. Functionally tested: two specialists tracked on the same host, one completed, active-list correctly narrows to the other, a different host's active-list correctly returns empty, bad work_id fails loudly | Take *only* the dedup-check idea, not Strix's full dynamic any-agent-spawns-any-agent graph — gets the "don't redo work" benefit without taking on shared-coordinator locking complexity for a fixed 5-specialist roster that doesn't need it |
| Multi-target hunting without state mixing | ✅ Done — `mcp-servers/engagement_paths.py` resolves `engagement.yaml`/`budget.json`/`work-registry.json`/`findings-seen.json`/`audit.jsonl` against the currently ACTIVE target's own `data/engagements/<slug>/` directory instead of a single shared flat file, via `scope_guard.py`/`budget_guard.py`/`work_registry.py`/`dedupe_check.py`/`audit_log.py`'s `DEFAULT_PATH` now routing through it (explicit `HUNTMCP_*_PATH` env overrides still win, for tests/advanced use). Active target tracked via a gitignored pointer file (`data/.active-engagement`), not an env var — env vars exported inside one Bash tool call do not persist to the next call in either harness, but a file on disk does. CLI/wrapper: `scripts/switch-engagement.sh {check,set,complete,current,list}`. On-disk isolation is only half the problem — nothing stops a single CHAT from narrating two targets even with per-target directories, so `check <target>` (run before `set`, at Phase 0) warns and defers to the user when a different, not-yet-`complete` target is already active in that same conversation, recommending a fresh chat session for the new target; `complete` (run at Phase 6, once an engagement genuinely wraps up) clears that warning for future chats. HuntBrain's Phase 0 in both `huntbrain.md` files now runs `switch-engagement.sh check <target>` then `set <target>` before writing `engagement.yaml`, and only resets that target's `budget.json`/`work-registry.json`/`findings-seen.json` when it's a genuinely fresh start for that target (checked via whether its directory already had an `engagement.yaml`) — resuming a paused target is just switching the pointer back, with its state exactly as it was left. A single-target workflow that never calls `set` keeps using the legacy flat repo-root files unchanged (`resolve()`'s fallback), so this is purely additive. Unit tested (`tests/test_engagement_paths.py`, 15 cases including "switching to target B never touches target A's files and resuming A restores its exact prior state" and the full `check`/`complete` conflict-warning matrix) | Confirmed real gap, not previously tracked anywhere: `engagement.yaml`/`budget.json`/`work-registry.json` were single flat files with the reset step (`rm -f budget.json work-registry.json findings-seen.json`) written for exactly one engagement at a time — pausing a hunt on target A to start target B, then coming back to A, would have silently reset or overwritten A's scope/budget/dedup state with B's. `mcp-servers/memory-mcp`'s SQLite `hunts` table was already safely per-target (keyed on `target`) and needed no change; this closes the same gap for the engagement-scoped guard files. Known remaining limitation, not addressed here: `watch-mcp`'s unattended cron-triggered scope check resolves against whichever target is active *at cron-fire time*, so continuous `watch` monitoring and interactive multi-target hunting can still interact in a confusing way if both are used at once — fine for the common case (one long-running watch target, hunted interactively elsewhere), a real follow-up if watch is ever run on multiple targets concurrently |
| Context budget / compaction strategy | ✅ Done — both `huntbrain.md` files now save to `mcp-servers/memory-mcp` incrementally (after recon, again after scan, not only once at Phase 6) instead of only at the very end. `save()` upserts on `target`, so repeated calls are safe; findings/chains are plain inserts, so each incremental call only includes what's new since the last one. Also instructs HuntBrain not to carry large raw tool output (full subdomain lists, JSON dumps) forward verbatim once the next phase's inputs are extracted — same "state that must survive compaction lives on disk, not in conversation memory" principle already established for `work-registry.json`/`budget.json` | A long engagement can hit context compaction mid-run — this repo's own development already has. Previously HuntBrain only wrote to memory-mcp once, at the very end, so mid-engagement compaction could lose everything not yet on disk |
| Caido proxy support alongside Burp | ✅ Done, at the same tier Burp already gets — `AGENTS.md`'s runtime dependencies now document Caido as an equally-valid, free/open-source alternative for the same optional Repeater/proxy-replay validation role, since (like Burp's own MCP Server extension at `127.0.0.1:9876`) that connection is the operator's own local MCP config, not something this repo registers in `opencode.jsonc`/`.mcp.json` — so a `caido-mcp` HuntMCP would build and maintain isn't actually the right shape here; documenting the existing equivalence is | Caido is a real open-source Burp alternative; lowers the barrier for anyone who doesn't have a Burp Pro license. Low priority — Burp is already optional, this just adds a second optional option |

**Explicitly not recommending from Strix:** its Go-based custom TUI (`strix/interface/tui/`) —
a large engineering investment disproportionate to a solo-operator tool, when OpenCode's and
Claude Code's own interfaces already work; and its opt-in telemetry (`strix/telemetry/`,
posthog/scarf) — even opt-in, a tool that processes real target/engagement data warrants extra
caution before wiring in any outbound analytics, and it isn't solving a problem HuntMCP
actually has.

### Phase 2.10: Full World-Research Backlog (Concrete items done, rest is references/contingent/large-scope)

Everything else distilled from the 2026-08-22 100+-repo survey (`RESEARCH-TODO.md`, private/
gitignored — 227 repos surveyed, 22 deep-dived) that isn't already covered by Phase 2.7/2.8/2.9
above. Grouped by kind, not priority-ranked — treat this as the full menu, not a sequence.

**Also done, not from the research pass — user-requested:** `mcp-servers/target-discovery-mcp/`
(`check_security_txt`/`add_candidate`/`list_candidates`) — finds real, explicitly-authorized-but-
unlisted targets via RFC 9116 `security.txt` discovery (a company doesn't need a HackerOne listing
to have a valid disclosure policy) and catalogs validated ones in a local gitignored DB
(`data/candidate-targets.db`) for human triage. Deliberately does NOT test unauthorized domains —
security.txt is a publicly-published policy file, reading it is not a Tier-2 action, and a domain
without one is not added as a candidate. Functionally tested against a real domain (github.com).

**Validation & quality — extends the Phase 2.9 confidence-calibration work:**

| What | Idea | Source |
|------|------|--------|
| Cross-model second opinion | ✅ Done — `mcp-servers/second-opinion-mcp/server.py`'s `get_second_opinion(finding_summary, primary_role)`. Uses `model_gateway.py`'s existing `PROVIDER_CHAIN`/`select_provider()` to find the current primary provider, then picks the first *different* one with a key actually set (ollama requires `OLLAMA_HOST` set, same check `select_provider()` itself uses — not treated as unconditionally available, a real bug caught and fixed while testing this). Implements the three real API request/response shapes needed (Anthropic Messages API, OpenAI-compatible chat/completions for openai/deepseek/groq/openrouter, Ollama's local API). Granted to exploit-agent as an optional extra check on MEDIUM-confidence or high-severity findings, explicitly not a required step or an override of exploit-agent's own judgment. **Caveat, same as `hackerone-mcp`: NOT tested against a live API call for any provider** (no API keys available) — provider-selection logic (including the ollama-availability bug) and each provider's request-building/response-parsing were verified against mocked HTTP calls matching each API's documented shape, not a real call | `trailofbits/skills` `second-opinion` |
| `mantis-dedupe` style dedup check | ✅ Done — `mcp-servers/dedupe_check.py` (`check_and_record()`, CLI via `scripts/check-dedupe.sh`). Fingerprints on `vuln_class+endpoint+parameter` (case-insensitive, sha256-truncated), state in gitignored `findings-seen.json`, reset by HuntBrain at Phase 0 alongside `budget.json`/`work-registry.json`. exploit-agent runs it right before finalizing a CONFIRMED verdict in both harnesses — a duplicate fingerprint gets noted against the earlier finding instead of a second report. 6 tests (new/duplicate/different-param/different-class/case-insensitivity/no-parameter). `mantis-threat-model` (what's actually at risk, not just what's technically true) not built separately — already covered by Phase 1.5's rationalizations-to-reject check plus the confidence tag, which already force that judgment explicitly rather than leaving it implicit | `google/mantis` |
| Sandbox abstraction reference | `sandboxes/gvisor.py` / `sandboxes/microsandbox.py` in `google/mantis`'s `reference/` — a second concrete implementation to compare against Strix's Docker sandboxing (Phase 2.9) when exploit-agent's sandboxing item gets built | `google/mantis` |
| LLM-guided traversal for future static-analysis skill | Instead of a fixed AST/regex ruleset, let the LLM decide what code to inspect next by walking the actual call graph — relevant if the Phase 2.8 SAST idea (`semgrep`) ever grows a custom analysis pass | `protectai/vulnhuntr` (project itself is stale/dead, technique is not) |

**Self-scanning HuntMCP's own agent-generated surface:**

| What | Idea | Source |
|------|------|--------|
| Scan agent-generated skills/tools before trusting them | Once the "self-expanding toolkit" mechanic exists (an agent authoring new MCP servers/skills when it hits a technique gap — already in the Methodology Engine design), those files are a real, unreviewed attack surface (prompt injection, supply-chain risk) the moment they're agent-authored rather than human-reviewed. A lightweight CI-style check against the OWASP Skill/MCP Top 10 patterns, run on any new/changed `.claude/skills/*/SKILL.md` or `mcp-servers/*`, closes this before it's a problem instead of after | `NVIDIA/SkillSpector`, `snyk/agent-scan`, `Tencent/AI-Infra-Guard` — three independent projects converging on the same category confirms it's a real, not speculative, gap |

**Benchmarking — a real number instead of "seems to work":**

| What | Idea | Source |
|------|------|--------|
| Score exploit-agent against a standardized benchmark | XBOW's `validation-benchmarks` suite is public even though XBOW itself is closed-source; `straylabs-ai/deadend-cli` already demonstrates 81% on it in full black-box mode using only open/self-hosted models. Running HuntMCP's exploit-agent against the same suite gives an apples-to-apples effectiveness number instead of only real-engagement anecdote | `xbow-engineering/validation-benchmarks`, `straylabs-ai/deadend-cli` |

**Concrete tool/source additions to already-known backlog items:**

| What | Idea | Source |
|------|------|--------|
| `bloodhound-mcp` for Active Directory | AD attack-path analysis — HuntMCP currently has zero AD coverage; adds specificity to the existing "mcp-security-hub not yet pulled in" item | `FuzzingLabs/mcp-security-hub` |
| `ghidra-mcp` / `radare2-mcp` for binary analysis | Zero current coverage for any binary-format target; same catalog as above | `FuzzingLabs/mcp-security-hub` |
| EPSS + CISA KEV as CVE prioritization signals | ✅ Done — `mcp-servers/writeup-mcp/cve_fetch.py` now fetches FIRST.org's EPSS score (exploit-probability, batch-fetched for the whole new-CVE set in one call) and checks CISA's KEV catalog (confirmed-actively-exploited) for every new CVE, adding both to the writeup markdown alongside CVSS/CWE. Best-effort — an unreachable EPSS/KEV feed degrades to "not scored"/"not listed" rather than failing the whole fetch. Verified against real APIs: log4j-keyword CVEs correctly showed EPSS scores differentiating the critical deserialization CVEs (89.8%, 69.1%) from the low-severity info-leak ones (0.3%, 0.6%); CVE-2021-44228 (Log4Shell) directly confirmed EPSS 99.999% and `in KEV: True` | `mukul975/cve-mcp-server` (21-source catalog — a checklist, not a dependency to adopt wholesale) |
| Config-profile pattern for `--quick`/`--deep` modes | `reconftw_full.cfg` / `reconftw_quick.cfg` / `reconftw_stealth.cfg` — worth comparing against HuntMCP's own quick-mode tool selection for gaps once ReconFTW (already a known "not yet pulled in" item) is actually wrapped | `six2dez/reconftw` |

**Skills to add (formalizing the earlier candidate-skills list):**

| What | Idea | Source |
|------|------|--------|
| Playbooks cite real disclosed H1 reports as precedent | 🔶 Demonstrated, not yet done everywhere — `.claude/skills/access-control-and-idor/SKILL.md` now cites 5 real disclosed reports (HackerOne #2122671, Yelp #391092, Mozilla #3154983, PayPal #415081, Automattic #915114) as concrete precedent for its four-mechanism IDOR framework, sourced from a user-supplied third-party analysis of the top 20 disclosed IDOR reports on HackerOne rather than re-derived from scratch. Extend the same pattern to other vuln-class skills as they're written/revisited, rather than doing a separate pass to retrofit all of them at once | `MyuriKanao/src-hunter-skill` (2,887 disclosed reports pre-organized by weakness class) |
| Skill-with-checked-in-eval-file | Any HuntMCP skill beyond a static reference doc gets a small `evals/evals.json` alongside it — cheap regression check when the skill file is edited later | `wgpsec/AboutSecurity` |
| `writing-great-skills` meta-skill | A skill about how to write HuntMCP's own future skills consistently (frontmatter conventions, when-to-use/when-not-to-use sections) — write this *before* the skills-restructuring work (Phase 2.8) starts, not after | `GreyDGL/PentestGPT` |
| `AGENT-BRIEF.md` pairing per engagement | ✅ Done, as a single companion file rather than two — `AGENT-BRIEF.md.example` (gitignored real copy). HuntBrain writes it right after `engagement.yaml` at Phase 0 in both harnesses (OpenCode's `edit` permission extended to allow it). Explains *why* each out-of-scope entry is excluded, not just that it is, plus any verbal/out-of-band constraint `engagement.yaml`'s structured fields can't hold — `engagement.yaml` stays the sole *enforced* source of truth, this is for human re-review and HuntBrain's own mid-engagement reference | `GreyDGL/PentestGPT` `.agents/skills/triage/` |
| GraphQL, JWT/OAuth/SAML, request smuggling, prototype pollution, SSTI, CI/CD & dependency-confusion, Kubernetes/container escape, Active Directory, race conditions, WebSocket, mobile SSL pinning | Clear vuln-class coverage gaps vs. current `master-pentest-prompt.md` — see the ~95-topic catalog | `yaklang/hack-skills` |

**Architecture references (cite, don't necessarily adopt):**

| What | Idea | Source |
|------|------|--------|
| `plan → loop → memory → trace → audit` module split | Cleaner decomposition than HuntBrain's current single-file orchestration, worth comparing against if HuntBrain is ever refactored | `GreyDGL/PentestGPT` |
| `worker_pool.py` | A concrete reference implementation to read before designing HuntMCP's own parallel-fan-out rework (already a known backlog item, previously design-only) | `GH05TCREW/pentestagent` |
| `Flow → Task → SubTask → Action → {Artifact, Memory}` data model | Cleaner formalization of the Flow/Task/Action decomposition HuntBrain already does informally — worth a look only if the Memory DB schema is revisited. **Explicitly not adopting the rest of this project** (React UI, Neo4j, Grafana/VictoriaMetrics/Jaeger/Loki stack) — team-scale SaaS infra, wrong shape for a solo operator | `vxcontrol/pentagi` (user-confirmed: data model only, reject the multi-team stack) |
| Agent-pattern naming vocabulary | `agents_as_tools`, `deterministic`, `forcing_tool_use`, `input_guardrails`/`output_guardrails`, `llm_as_a_judge`, `handoffs` — useful shared terminology, not a dependency (project is archived/discontinued, folded into a paid successor) | `aliasrobotics/cai` |
| `.planning/` spec-driven process | `PROJECT.md`/`REQUIREMENTS.md`/`ROADMAP.md`/`STATE.md` plus per-phase `PLAN.md`/`SUMMARY.md` — a lighter-weight planning convention worth considering for smaller features instead of a full `ARCHITECTURE.md` rewrite each time | `six2dez/burp-ai-agent` |
| Telemetry-off-by-default privacy bar | If HuntMCP ever adds any usage telemetry (e.g. for the lessons registry, or a future hosted backend), this is the bar to match: off by default, explicit opt-in, respects `DO_NOT_TRACK`, "raw prompts/targets/credentials/tool output never transmitted" even when on | `PurpleAILAB/Decepticon`'s `TELEMETRY.md` |
| Topic-coverage checklist | 817 skill topics mapped to MITRE ATT&CK/NIST CSF/ATLAS/D3FEND — use to spot HuntMCP methodology gaps by skimming topic names, not as a content source (bulk/unverified, size makes hand-review of each one impractical) | `mukul975/Anthropic-Cybersecurity-Skills` (star count itself is anomalous — see `RESEARCH-TODO.md`'s caveat — judged on content only) |

**Confirmed, no action needed:** `garak`/`PyRIT` remain the right picks for Phase 14.5/14.6 (AI/LLM
surface testing) when that gets built — this survey found no credible newer competitor to either.

### Phase 3: Full Platform (Not started)

| Sprint | What | Deliverable |
|--------|------|-------------|
| 11 | CI/CD pipeline (GitHub Action auto-train) | Writeup PR → auto-embed → auto-deploy |
| 12 | Web dashboard (Next.js) | Browse, search, add writeups |
| 13 | GitHub OAuth + user management | Multi-user with permissions |
| 14 | Public API docs + rate limiting | Community-facing API |
| 15 | Monitoring + backups + release | Production-ready platform |

## Tool Installation Requirements

```bash
# Go tools (for MCP wrappers)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest

# Python (for RAG system)
pip install chromadb sentence-transformers

# Python (for exploitation)
pip install sqlmap

# Already configured:
# - Burp Suite MCP (27 tools) ✅
# - security-mcp (40+ OWASP tools) ✅
```

## Writeup Ingestion — Manual + Automated

### Manual (when YOU find something interesting)

```bash
# One writeup
./scripts/ingest-writeup.sh \
  --url "https://medium.com/..." \
  --title "How I found XSS in..." \
  --vuln-class XSS \
  --tech React \
  --bounty 500

# Or from the OpenCode prompt
/ingest https://medium.com/... --class XSS --tech React
```

### Automated (cron — runs daily)

```cron
# /etc/cron.d/huntmcp-ingest
0 6 * * * ankit /home/ankit/HuntMCP/scripts/cron-fetch.sh
0 12 * * * ankit /home/ankit/HuntMCP/scripts/cron-fetch.sh --refresh
```

The cron script:
1. Fetches HackerOne Hacktivity RSS → parses new disclosed reports
2. Fetches GitHub → scans known writeup repos for new commits
3. Fetches RSS feeds from security blogs (Medium, PortSwigger Research)
4. For each new writeup: download → chunk → embed → store in ChromaDB
5. Logs everything to `logs/cron-ingestion.log`

### What the Agent Does With Writeup Knowledge

```
Agent hunts a React + Node.js target
  → Queries Writeup RAG → "React XSS techniques"
  → Gets: 5 writeups with specific payloads
  → Uses those payloads during scan
  → Finds XSS faster because it knew what to test

Next day: a new writeup is published about GraphQL abuse
  → Cron picks it up at 6AM
  → Next GraphQL target: agent already knows the techniques
```

## Summary

```
SCOPE ANALYSIS → PASSIVE RECON → ACTIVE ENUM → VULN TESTING (30+ classes)
→ VALIDATION → CHAINING → REPORT

SUPPORTED BY:
  ├── Multi-level agent orchestration (HuntBrain + specialists)
  ├── Writeup RAG (learn from everything, both manual + automated)
  ├── Memory DB (remember past hunts, improve over time)
  └── Continuous learning (cron feeds keep knowledge fresh)
```

**Built with OpenCode. Powered by MCP. Designed for the world's best bug hunters.**
