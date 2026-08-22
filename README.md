<div align="center">

[![CI](https://github.com/ankitsingh015/HuntMCP/actions/workflows/ci.yml/badge.svg)](https://github.com/ankitsingh015/HuntMCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Harness](https://img.shields.io/badge/harness-OpenCode%20%2B%20Claude%20Code-purple)
![MCP Count](https://img.shields.io/badge/MCP-13%20servers-orange)
![Model Providers](https://img.shields.io/badge/models-no%20lock--in-yellow)

# 🐾 HuntMCP

**Multi-level AI agent orchestration for authorized bug bounty hunting and pentesting.**

</div>

A single orchestrator (HuntBrain) delegates to specialist agents — Recon, Scan, Exploit,
Chain-Planner, Report, plus unlimited dynamic specialists spawned on demand — that drive
real security tools through MCP, validate their own findings before calling anything
"confirmed," and write back what they learn after every engagement. Runs on
[OpenCode](https://opencode.ai) or native [Claude Code](https://claude.com/claude-code).
Any model provider, no lock-in.

---

> **For authorized security testing only.** Every engagement is bound to an `engagement.yaml`
> scope file — see [Scope & Authorization](#scope--authorization) before pointing this at anything.

## Table of Contents
- [Why HuntMCP](#why-huntmcp)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Scope & Authorization](#scope--authorization)
- [How It Works](#how-it-works)
- [Model Providers](#model-providers)
- [Vulnerability Coverage](#vulnerability-coverage)
- [Project Structure](#project-structure)
- [License](#license)

---

## Why HuntMCP

Most agentic pentest tooling picks one of two extremes: a fixed scan-and-report pipeline
with no real judgment, or a single do-everything LLM loop with no guardrails. HuntMCP is
built on three decisions that fall in between:

- **A validator, not a self-grader.** Scan agent output is always a *candidate* — nothing
  is "confirmed" until exploit-agent independently reproduces it. No hallucinated finding
  reaches a report.
- **Safety that's structurally enforced, not prompted.** Scope is validated once against
  `engagement.yaml` and then checked deterministically (no LLM call) before every tool
  invocation — it can't be reasoned away mid-engagement.
- **It gets better with every engagement.** Confirmed findings *and* closed false
  positives both write back to a Lessons Registry, so the next hunt on a similar stack
  starts smarter than the last one did.

## Features

- **🤖 Multi-Level AI Orchestration** — Level 1 HuntBrain delegates to Level 2 specialists (Recon, Scan, Exploit, Chain-Planner, Report). Not a fixed pipeline — the AI decides what to run next based on what recon actually finds.
- **🔀 Dual Harness, Zero Lock-In** — Run the exact same agent roster two ways: [OpenCode](https://opencode.ai) (`.opencode/agents/`, any model provider) or native [Claude Code](https://claude.com/claude-code) subagents (`.claude/agents/`, `.mcp.json`). Same MCP servers, same knowledge layer, pick your harness.
- **🌐 No Model Lock-In** — `model_gateway.py` resolves a provider per agent role from an explicit override or an automatic fallback chain: Anthropic → OpenAI → DeepSeek → Groq → OpenRouter → local Ollama. Bring whichever API key you have.
- **🔒 Scope-Gated by Design** — Authorization is validated once per engagement against `engagement.yaml`, then every Tier-2 tool call runs a cheap, deterministic (non-LLM) domain check via `scripts/check-scope.sh` before touching a host. No token spent re-verifying scope on every action; no way to silently drift out of scope either.
- **⚡ Reactive Rate Limiting** — No blanket per-request delay. `tool_resolver.run_tool()` only reacts when it actually detects a block: a genuine rate limit gets one backoff-and-retry, a WAF/bot-detection block is surfaced to the agent to escalate with real bypass tooling instead of just sleeping.
- **🧠 Three-Part Knowledge Layer** — Writeup RAG (ChromaDB + sentence-transformers, learns from public writeups), Memory DB (SQLite, per-target hunt history), and a self-improving Lessons Registry (`lessons-mcp`, structured technique write-back after every confirmed finding *and* every closed false positive).
- **🔗 Vulnerability Chaining** — `chainer-mcp` runs a DAG-based planner across 15 chain templates (IDOR+XSS→ATO, SSRF+cloud→credential access, upload+LFI→RCE...) and escalates severity when a chain lands.
- **📚 Curated Payload Library** — 11 hand-reviewed payload sets (`knowledge/payloads/`) and matching wordlists (`knowledge/wordlists/`) for when nuclei/sqlmap/dalfox's automated pass comes back clean and a human-style bypass is needed.
- **📝 Auto-Reporting** — Generates H1/Bugcrowd-ready reports: PoC, CVSS v3.1 vector, business impact, remediation.
- **📡 Continuous Monitoring** — `watch-mcp` diffs subdomains/endpoints over time and flags what's new.
- **🌐 Hosted Backend (optional)** — A Go + Postgres/pgvector backend (`backend/`) for teams that want the writeup RAG and hunt memory served centrally instead of local ChromaDB/SQLite.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      HUNTBRAIN (Level 1)                         │
│  Receives goal → validates engagement.yaml ONCE → queries        │
│  Memory DB + Writeup RAG + Lessons Registry → spawns specialists │
│  → merges results → loops until surface exhausted → reports      │
└───────────────────────────┬────────────────────────────────────┘
                             │
        ┌──────────┬────────┼────────┬─────────────┐
        ▼          ▼        ▼        ▼             ▼
   ┌────────┐ ┌────────┐┌────────┐┌─────────┐ ┌──────────────┐
   │ RECON  │ │  SCAN  ││EXPLOIT ││  CHAIN  │ │   REPORT     │
   │ Agent  │ │ Agent  ││ Agent  ││ PLANNER │ │   Agent      │
   └────────┘ └────────┘└────────┘└─────────┘ └──────────────┘
        │          │        │          │
        │   ┌──────┴────────┴──────┐   │
        │   │  DYNAMIC SPECIALISTS  │   │      each Tier-2 call:
        │   │  (spawned on demand:  │   │      check-scope.sh → run
        │   │  GraphQL, JWT, OAuth) │   │      → classify_block()
        │   └───────────────────────┘   │      → retry or escalate
        └──────────────┬────────────────┘
                        ▼
        ┌───────────────────────────────────────────┐
        │              KNOWLEDGE LAYER                │
        │  ┌───────────┐ ┌──────────┐ ┌────────────┐ │
        │  │ Writeup   │ │ Memory   │ │  Lessons   │ │
        │  │ RAG       │ │ DB       │ │  Registry  │ │
        │  │ (Chroma)  │ │ (SQLite) │ │  (write-   │ │
        │  │           │ │          │ │   back md) │ │
        │  └───────────┘ └──────────┘ └────────────┘ │
        └───────────────────────────────────────────┘
```

Both harnesses (OpenCode and Claude Code) drive the same MCP servers and knowledge layer —
only the orchestration layer on top differs. See [ARCHITECTURE.md](ARCHITECTURE.md) for the
full design, WSTG methodology mapping, and phase-by-phase build status.

## Quick Start

### Prerequisites
- Python 3.10+ (3.12 used in CI)
- Go tools: `subfinder`, `httpx`, `nuclei`, `katana`, `ffuf`, `dalfox`, plus `nmap`
- At least one model provider API key (Anthropic, OpenAI, DeepSeek, Groq, OpenRouter) — or a local Ollama install
- [OpenCode](https://opencode.ai) v1.17+ **or** [Claude Code](https://claude.com/claude-code) — pick one harness, or install both

### Installation

```bash
git clone https://github.com/ankitsingh015/HuntMCP.git
cd HuntMCP

# Python deps — install per MCP server you plan to use, e.g.:
python3 -m venv .venv && source .venv/bin/activate
for req in mcp-servers/*/requirements.txt; do pip install -r "$req"; done

# Security tools (Go)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
# nmap via your OS package manager (apt/brew/...)

# Initialize local databases
./scripts/setup-db.sh

# Pick a model provider (writes into opencode.jsonc)
export ANTHROPIC_API_KEY=sk-...   # or OPENAI_API_KEY / DEEPSEEK_API_KEY / etc.
./scripts/select-model.sh

# Define your engagement — REQUIRED before any agent touches a target
cp engagement.yaml.example engagement.yaml
$EDITOR engagement.yaml   # set target, in_scope, program_url, authorized_on

# Verify setup (OpenCode)
opencode run "HuntMCP audit testphp.vulnweb.com --quick"

# ...or verify with Claude Code
claude
> /audit testphp.vulnweb.com
```

## Usage

### OpenCode
```bash
opencode run "HuntMCP audit example.com"                # full autonomous audit
opencode run "HuntMCP audit example.com --quick"          # recon + nuclei only
opencode run "HuntMCP watch example.com --interval 6h"    # continuous monitoring
opencode run "HuntMCP report <scan-id>"
opencode run "HuntMCP chain <scan-id>"                    # vulnerability chaining analysis
opencode run "HuntMCP ingest <url> --class XSS --tech React"
opencode run "HuntMCP learn --query 'XSS in React apps'"
```

### Claude Code
```bash
claude
> /audit example.com        # requires engagement.yaml to already match the target
```
HuntBrain and every Level 2 specialist are registered as native subagents
(`.claude/agents/*.md`) with locked-down tool allowlists — Claude Code will spawn them
automatically as the engagement progresses.

## Scope & Authorization

Nothing runs against a target without `engagement.yaml` at the repo root (gitignored — this
file names a real target and stays local). HuntBrain validates it **once** at the start of an
engagement; every subsequent Tier-2 action (recon/scan/exploit) then runs the cheap,
deterministic `scripts/check-scope.sh <host>` before touching that host — no LLM call, no
per-action re-validation, no way to silently wander out of scope either. See
`engagement.yaml.example` for the format.

## How It Works

### The HuntBrain Decision Loop

```
1. TARGET IN        → parse target, load + validate engagement.yaml (once)
2. LESSONS + MEMORY  → read_lessons() + query Memory DB for this target/stack
3. RAG QUERY         → what techniques work for this tech stack?
4. RECON             → subfinder → httpx → katana → nmap → subdomains, live hosts, endpoints
5. SCAN              → nuclei → sqlmap → dalfox → ffuf → candidate findings
6. VALIDATE          → exploit-agent independently re-runs each candidate (proof capsule);
                        writes CONFIRMED or CLOSED (false positive) to the Lessons Registry
                        immediately, not batched
7. CHAIN             → chain-planner + exploit-agent detect exploitable combinations
8. REPORT            → generate HackerOne/Bugcrowd-ready submission
```

Rate limiting and blocking are handled reactively inside `tool_resolver.run_tool()`, not as a
separate loop step — a detected rate limit gets one backoff-and-retry; a WAF/bot-detection
block is surfaced to the agent instead of just waiting it out.

### Learning from Writeups (RAG)

No model fine-tuning. Retrieval-Augmented Generation instead:

| Method | Frequency | Source |
|--------|-----------|--------|
| Manual | On-demand | `scripts/ingest-writeup.sh --url ...` or `/ingest` command |
| Cron | Configurable | `scripts/cron-fetch.sh` — HackerOne Hacktivity, GitHub writeup repos, blogs |

Each writeup is chunked, embedded via `sentence-transformers`, and stored in ChromaDB. Agents
query this before testing any vulnerability class, retrieving proven techniques from similar
targets — plus whatever the Lessons Registry has learned from *this* project's own past
engagements.

### Multi-Level Agent System

| Level | Agent | Responsibility | MCP Tools |
|-------|-------|----------------|-----------|
| 1 | **HuntBrain** | Orchestrator — delegates, merges, decides | memory-mcp, writeup-mcp, lessons-mcp |
| 2 | **Recon Agent** | Asset discovery | subfinder-mcp, httpx-mcp, katana-mcp, nmap-mcp |
| 2 | **Scan Agent** | Vulnerability detection | nuclei-mcp, sqlmap-mcp, dalfox-mcp, ffuf-mcp, writeup-mcp |
| 2 | **Exploit Agent** | Validation + chaining | chainer-mcp, lessons-mcp |
| 2 | **Chain Planner** | DAG-based chain analysis | chainer-mcp, memory-mcp, writeup-mcp |
| 2 | **Report Agent** | Report generation | writeup-mcp |
| 2 | **Dynamic specialists\*** | GraphQL, JWT, OAuth, Cloud, etc. | Spawned on demand, scoped per-task |

*\*Spawned when HuntBrain detects relevant technology (e.g. a GraphQL agent when `/graphql` is
found). This is the scaling mechanism past a handful of agents — plain markdown files with
locked-down tool access, not persistent processes.*

Burp Suite integration (Repeater/Collaborator validation) is designed as an optional
enhancement tier in `ARCHITECTURE.md`, not a hard requirement — the built agents above run
entirely on the open-source tool chain.

## Model Providers

Set an explicit override, or let the fallback chain pick automatically:

```bash
# Global override — every agent role uses this
export HUNTMCP_MODEL=deepseek/deepseek-chat

# Per-role override — only the exploit agent uses this
export HUNTMCP_MODEL_EXPLOIT=anthropic/claude-opus-5

# No override set → model_gateway.py walks the chain:
# Anthropic → OpenAI → DeepSeek → Groq → OpenRouter → local Ollama
./scripts/select-model.sh
```

Claude Code subagents pin their own model in each `.claude/agents/*.md` file's frontmatter
(`model: sonnet` / `opus` / `inherit`) since that harness always runs on Claude — the gateway
above applies to the OpenCode harness, where every provider is fair game.

## Vulnerability Coverage

HuntMCP tests 30+ vulnerability classes across the OWASP Web Security Testing Guide (WSTG)
methodology:

| Category | Classes | Primary Tooling |
|----------|---------|-----------------|
| **Injection** | SQLi, XSS, SSTI, Command Injection, LDAP, XPath, XXE | sqlmap, dalfox, nuclei |
| **Authentication** | Auth Bypass, JWT Attacks, OAuth Abuse, SAML, OTP Bypass, Session Fixation, Password Reset Poisoning | nuclei templates, curated payload library |
| **Authorization** | IDOR, Mass Assignment, Privilege Escalation, API Auth Bypass, CORS, GraphQL Bypass | ffuf, custom checks, curated payload library |
| **Business Logic** | Race Conditions, Negative Values, Workflow Bypass, Coupon Abuse | manual verification, exploit-agent |
| **Server-Side** | SSRF, LFI/RFI, File Upload, Deserialization, Prototype Pollution, HTTP Smuggling, Cache Poisoning | nuclei, curated payload library |
| **Infrastructure** | Subdomain Takeover, S3/Cloud Buckets, Security Headers, CVE Scan, WAF Bypass, TLS/SSL | nuclei, subfinder, nmap |
| **Chained** | Any combination the chain-planner's 15 DAG templates recognize | chainer-mcp |

## Project Structure

```
HuntMCP/
├── mcp-servers/               13 FastMCP servers (one per tool) + shared libs:
│   ├── tool_resolver.py         binary resolution + reactive rate-limit/WAF handling
│   ├── scope_guard.py           engagement.yaml scope checks
│   └── model_gateway.py         multi-provider model selection
├── .opencode/
│   ├── agents/                 Multi-level agent files (OpenCode harness)
│   └── commands/                /ingest, /learn, /chain, /watch
├── .claude/
│   ├── agents/                 Same agent roster, native Claude Code subagents
│   └── commands/                /audit
├── .mcp.json                   MCP server registration for Claude Code
├── scripts/                    setup, scope-check, model-select, ingestion, cron
├── knowledge/
│   ├── master-pentest-prompt.md  Phase-mapped WSTG methodology reference
│   ├── payloads/                 Curated payload lists per vulnerability class
│   └── wordlists/                Directories, API endpoints, subdomains
├── data/
│   ├── chroma/                  Vector DB (local, gitignored)
│   ├── memory.db                 Hunt memory (local, gitignored)
│   └── writeups/                 Raw writeup markdown (git-tracked)
├── backend/                     Optional Go + Postgres/pgvector hosted backend
├── engagement.yaml.example      Scope file format (real engagement.yaml is gitignored)
├── opencode.jsonc                MCP configuration + permissions (OpenCode)
├── docker-compose.yml / Dockerfile
├── CLAUDE.md / AGENTS.md         Coding-agent guidance for this repo
└── ARCHITECTURE.md               Full system design + phase-by-phase build status
```

## License

[MIT](LICENSE) — use freely, adapt for your project, no attribution required.

---

*Built on MCP · Runs on OpenCode or Claude Code · For authorized security testing only*
