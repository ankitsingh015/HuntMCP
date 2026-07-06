<p align="center">
  <img src="https://img.shields.io/badge/HuntMCP-v1.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/built%20with-OpenCode-purple" alt="OpenCode">
  <img src="https://img.shields.io/badge/MCP-11%20servers-orange" alt="MCP Count">
</p>

<h1 align="center">🐾 HuntMCP</h1>
<p align="center">
  <em>Multi-level AI agent orchestration for autonomous bug bounty hunting.</em><br>
  Built on OpenCode + MCP. Covers 30+ vulnerability classes across the full OWASP WSTG methodology.
</p>

---

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Vulnerability Coverage](#vulnerability-coverage)
- [Project Structure](#project-structure)
- [License](#license)

---

## Features

- **🤖 Multi-Level AI Orchestration** — Level 1 HuntBrain delegates to Level 2 specialist agents (Recon, Scan, Exploit, Report). Not a fixed pipeline — the AI decides what to do next.
- **🧠 Writeup RAG** — Learns from public writeups via ChromaDB vector search. Manual ingestion + automated cron feeds from HackerOne, GitHub, and blogs keep knowledge fresh.
- **💾 Memory System** — SQLite-powered hunt memory. Reminds you what worked (and what didn't) on past targets. Improves with every hunt.
- **🔗 Vulnerability Chaining** — Automatically detects chainable bug combinations: IDOR + XSS → ATO, SSRF + cloud → credential access. Escalates severity.
- **📝 Auto-Reporting** — Generates HackerOne/Bugcrowd-ready reports with cURL PoC, CVSS v3.1 vector, impact analysis, and remediation steps.
- **📡 Continuous Monitoring** — Watch mode detects new subdomains, endpoints, and vulnerabilities via daily diff-based scanning.
- **🔄 100+ Agent Scaling** — Add unlimited specialist agents (GraphQL, JWT, OAuth, Cloud, SAML, etc.) as individual markdown files. Each with locked-down permissions and specific tool access.
- **🌐 Enterprise Ready** — Designed to scale from local ChromaDB → Go backend with PostgreSQL + pgvector → full web platform with CI/CD auto-training.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HUNTBRAIN (Level 1)                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Receives goal → queries Memory DB → queries RAG    │    │
│  │  → spawns specialists → merges → reports            │    │
│  └──────────────────┬──────────────────────────────────┘    │
│                     │                                       │
│     ┌───────────────┼───────────────┐                      │
│     ▼               ▼               ▼                       │
│  ┌────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ RECON  │  │  SCAN    │  │ EXPLOIT  │  │  REPORT  │     │
│  │ Agent  │  │  Agent   │  │  Agent   │  │  Agent   │     │
│  └────────┘  └──────────┘  └──────────┘  └──────────┘     │
│     │               │               │                      │
│     │    ┌──────────┴──────────┐    │                      │
│     │    │ DYNAMIC SPECIALISTS │    │                      │
│     │    │ (spawned on demand) │    │                      │
│     │    └─────────────────────┘    │                      │
│     └──────────┬───────────────────┘                      │
│                ▼                                           │
│  ┌─────────────────────────────────────────────────┐      │
│  │              KNOWLEDGE LAYER                      │      │
│  │  ┌──────────────┐       ┌──────────────────┐     │      │
│  │  │ Writeup RAG  │       │   Memory DB      │     │      │
│  │  │ (ChromaDB)   │       │   (SQLite)        │     │      │
│  │  └──────────────┘       └──────────────────┘     │      │
│  └─────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- OpenCode v1.17+
- Burp Suite with MCP Server extension running on `127.0.0.1:9876`
- Python 3.10+ & Go tools (subfinder, httpx, nuclei, katana, ffuf, dalfox)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/HuntMCP.git
cd HuntMCP

# Install dependencies
pip install chromadb sentence-transformers
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest

# Initialize the database
./scripts/setup-db.sh

# Verify setup
opencode run "HuntMCP audit testphp.vulnweb.com --quick"
```

## Usage

```bash
# Full-depth autonomous audit
opencode run "HuntMCP audit example.com"

# Quick recon + nuclei scan only (5 min)
opencode run "HuntMCP audit example.com --quick"

# Continuous monitoring (runs daily)
opencode run "HuntMCP watch example.com --interval 6h"

# Report generation
opencode run "HuntMCP report <scan-id>"

# Vulnerability chaining analysis
opencode run "HuntMCP chain <scan-id>"

# Ingest a writeup for the RAG database
opencode run "HuntMCP ingest https://medium.com/... --class XSS --tech React"

# Query the writeup database
opencode run "HuntMCP learn --query 'XSS in React apps'"
```

## How It Works

### The HuntBrain Decision Loop

```
1. TARGET IN → Parse target, check program scope
2. MEMORY CHECK → Have we hunted this target before?
3. RAG QUERY → What techniques work for this tech stack?
4. RECON → subfinder → httpx → katana → subdomains, live hosts, endpoints
5. SCAN → nuclei → sqlmap → dalfox → Burp Scanner → vulnerabilities
6. VALIDATE → Burp Repeater confirms each finding with PoC
7. CHAIN → AI detects exploitable vulnerability combinations
8. REPORT → Generate HackerOne/Bugcrowd-ready submission
9. LEARN → Save findings to Memory DB for future hunts
```

### Learning from Writeups (RAG)

The system never needs model fine-tuning. It uses Retrieval-Augmented Generation:

| Method | Frequency | Source |
|--------|-----------|--------|
| Manual | On-demand | `./ingest-writeup.sh --url ...` or `/ingest` command |
| Cron (daily) | 6 AM | HackerOne Hacktivity RSS feed |
| Cron (weekly) | Sunday | GitHub writeup repos, security blogs |

Each writeup is chunked, embedded via `sentence-transformers`, and stored in ChromaDB. The agent queries this database before testing any vulnerability class, retrieving proven techniques and payloads from similar targets.

### Multi-Level Agent System

| Level | Agent | Responsibility | Tools |
|-------|-------|----------------|-------|
| 1 | **HuntBrain** | Orchestrator — delegates, merges, decides | All MCPs |
| 2 | **Recon Agent** | Asset discovery | subfinder, httpx, katana |
| 2 | **Scan Agent** | Vulnerability detection | nuclei, sqlmap, dalfox, Burp Scanner |
| 2 | **Exploit Agent** | Validation + chaining | Burp Repeater, Collaborator |
| 2 | **Report Agent** | Report generation | None (reads findings) |
| 2 | **GraphQL Agent*** | GraphQL-specific testing | curl, Burp |
| 2 | **JWT Agent*** | JWT attacks | jwt_tool, Burp |
| 2 | **Cloud Agent*** | Cloud misconfigurations | S3Scanner, cloud_enum |

*\*Dynamic specialists — spawned on demand when HuntBrain detects relevant technology.*

## Vulnerability Coverage

HuntMCP tests 30+ vulnerability classes across the OWASP Web Security Testing Guide (WSTG v4.2) methodology:

| Category | Classes | Detection Method |
|----------|---------|-----------------|
| **Injection** | SQLi, XSS, SSTI, Command Injection, LDAP, XPath, XXE, Expression Language | sqlmap, dalfox, nuclei + Burp Repeater validation |
| **Authentication** | Auth Bypass, JWT Attacks, OAuth Abuse, SAML, OTP Bypass, Session Fixation, Password Reset Poisoning | Burp Repeater, jwt_tool, custom techniques |
| **Authorization** | IDOR, Mass Assignment, Privilege Escalation, API Auth Bypass, CORS, GraphQL Bypass | Burp Repeater, Autorize, custom scripts |
| **Business Logic** | Race Conditions, Negative Values, Workflow Bypass, Coupon Abuse, Feature Abuse | Burp Turbo Intruder, manual verification |
| **Server-Side** | SSRF, LFI/RFI, File Upload, Deserialization, Prototype Pollution, HTTP Smuggling, Cache Poisoning | Burp Collaborator, custom scripts |
| **Infrastructure** | Subdomain Takeover, S3 Buckets, Security Headers, CVE Scan, WAF Bypass, TLS/SSL | nuclei, subzy, nmap, testssl.sh |
| **Modern (2026)** | GraphQL, WebSocket, WASM, SAML, WebAuthn, AI/LLM Security, API Gateway | Burp + custom agent files |

## Project Structure

```
HuntMCP/
├── mcp-servers/          Python MCP wrappers for security tools
├── .opencode/
│   ├── agents/           Multi-level agent files (HuntBrain + specialists)
│   └── commands/         Custom OpenCode commands
├── scripts/              Ingestion, cron, and setup scripts
├── knowledge/
│   ├── payloads/         Curated payload lists per vulnerability class
│   └── wordlists/        API endpoints, subdomains
├── data/
│   ├── chroma/           Vector database (local, .gitignored)
│   ├── memory.db         Hunt memory (local, .gitignored)
│   └── writeups/         Raw writeup markdown files (git-tracked)
├── logs/                 Per-hunt and ingestion logs
├── opencode.jsonc        MCP configuration + permissions
├── AGENTS.md             Project-level agent instructions
└── ARCHITECTURE.md       Complete system architecture and build plan
```

## License

MIT — use freely, adapt for your project, no attribution required.

---

<p align="center">
  <em>Built with OpenCode · Powered by MCP · Designed for the world's best bug hunters</em>
</p>
