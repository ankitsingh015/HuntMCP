# HuntMCP — Agent Instructions

## What this is

Multi-level AI agent orchestration for bug bounty hunting, built on OpenCode + MCP.

One Level 1 orchestrator (HuntBrain) delegates to Level 2 specialists (Recon, Scan, Exploit, Report + unlimited dynamic agents).

## Current state (July 2026)

Sprint 1 (Foundation) — Days 1-6 complete. Sprint 1 done.

| Path | Status |
|------|--------|
| `.opencode/agents/` | ✅ 5 agents: HuntBrain, Recon, Scan, Exploit, Report |
| `.opencode/commands/` | ✅ `/ingest` and `/learn` commands |
| `mcp-servers/writeup-mcp/` | ✅ ChromaDB RAG server with 4 tools |
| `mcp-servers/memory-mcp/` | ✅ SQLite memory server with 5 tools |
| `mcp-servers/subfinder-mcp/` | ✅ subdomain enumeration |
| `mcp-servers/httpx-mcp/` | ✅ HTTP probing + tech detection |
| `mcp-servers/katana-mcp/` | ✅ endpoint crawling |
| `mcp-servers/nmap-mcp/` | ✅ port scanning |
| `mcp-servers/nuclei-mcp/` | ✅ vulnerability scanning |
| `mcp-servers/sqlmap-mcp/` | ✅ SQL injection testing |
| `mcp-servers/dalfox-mcp/` | ✅ XSS scanning |
| `mcp-servers/ffuf-mcp/` | ✅ directory/content fuzzing |
| `scripts/` | ✅ setup-db.sh, ingest-writeup.sh, cron-fetch.sh |
| `knowledge/payloads/` | ✅ 11 payload files (XSS, SQLi, SSTI, LFI, SSRF, GraphQL, JWT, Prototype Pollution, HTTP Smuggling, Race Condition, Cloud Enum) |
| `knowledge/wordlists/` | ✅ 4 wordlists (API endpoints, subdomains, directories, params) |
| `knowledge/owasp-wstg-skill.md` | ✅ Full WSTG v4.2 methodology mapped to MCP tools |
| `data/writeups/` | ✅ 9 seed writeups (all major vuln classes) |
| `mcp-servers/chainer-mcp/` | ✅ DAG-based chain planner with 15 chain templates |
| `mcp-servers/watch-mcp/` | ✅ Continuous recon monitoring with state diffing |
| `.opencode/commands/watch.md` | ✅ `/watch` command for continuous monitoring |
| `scripts/setup-watch.sh` | ✅ Cron setup for periodic watch checks |
| `.opencode/agents/chain-planner.md` | ✅ Dynamic chain planner subagent |
| `.opencode/commands/chain.md` | ✅ `/chain` command for attack chain analysis |
| `opencode.jsonc` | ✅ 12 MCP servers registered with permissions |
| `Dockerfile` | ✅ Multi-stage with Go tools + Python deps |
| `.dockerignore` | ✅ Optimized build context |
| `docker-compose.yml` | ✅ Writeup MCP + Memory MCP + Dev service |
| `.github/workflows/ci.yml` | ✅ CI pipeline: lint, validate, Docker build, summary |

## Do before writing code

1. Read **README.md** and **ARCHITECTURE.md** — the canonical design docs.
2. Check which files exist at the paths above. Many are stubs.

## Directory conventions

- `.opencode/agents/` — one `.md` file per agent. Each gets its own tools and permissions.
- `.opencode/commands/` — one `.md` file per custom slash command (`/audit`, `/ingest`, etc.).
- `mcp-servers/<tool-name>/server.py` — each tool gets its own subdirectory with a FastMCP server.
- `scripts/` — shell scripts only (no `.py` or other languages).
- `data/writeups/` — writeup `.md` files with frontmatter (title, url, vuln_class, tech, bounty).

## Developer commands (inferred from README)

```bash
# Install Python deps
pip install chromadb sentence-transformers

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest

# Initialize database
./scripts/setup-db.sh

# Docker development
docker compose build        # Build the HuntMCP image
docker compose run --rm dev # Interactive dev shell with all tools

# Verify with a quick audit
opencode run "HuntMCP audit testphp.vulnweb.com --quick"
```

## Required runtime dependencies

- OpenCode v1.17+
- Burp Suite with MCP Server extension on `127.0.0.1:9876`
- Python 3.10+
- Go toolchain (for security tools)

## Architecture essentials

- **HuntBrain** is the single orchestrator. It queries Memory DB + Writeup RAG before each decision, spawns specialists, and loops until no more attack surface.
- **Dynamic agents** are spawned when HuntBrain detects relevant tech (e.g., GraphQL agent on `/graphql`, JWT agent on `Bearer eyJ...`).
- **Knowledge layer** has two systems: Writeup RAG (ChromaDB + sentence-transformers) for public writeups, and Memory DB (SQLite) for per-target hunt history.
- **Writeup flow**: raw `.md` files are git-tracked in `data/writeups/`. ChromaDB vectors are `.gitignore`d and rebuilt locally. This keeps contributions PR-able and diffable.

## Git rules (from ARCHITECTURE.md)

| Push | Do not push |
|------|-------------|
| `mcp-servers/`, `.opencode/`, `scripts/`, `knowledge/`, `data/writeups/` | `data/chroma/`, `data/memory.db`, `logs/*.log`, `.env` |

## Style conventions

- MCP servers use **FastMCP** (Python). One subdirectory per tool.
- Shell scripts in `scripts/` — no Python scripts outside `mcp-servers/`.
- Agent files are markdown with locked-down tool permissions per agent.
- Embedding uses `sentence-transformers` (Python), but only at ingestion time. Go handles all production traffic.
