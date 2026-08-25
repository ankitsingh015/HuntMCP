# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

HuntMCP is a multi-level AI agent orchestration system for autonomous bug bounty hunting, built on **OpenCode + MCP**. A single Level 1 orchestrator (`HuntBrain`) delegates to Level 2 specialist agents (Recon, Scan, Exploit, Report, plus unlimited dynamic specialists spawned on demand) which drive security tools through MCP servers, validate findings, and generate reports.

There are two mostly-independent parts of this repo:
1. **The OpenCode agent system** (`.opencode/`, `mcp-servers/`, `knowledge/`, `data/writeups/`) — Python-based, orchestrates security tools via MCP.
2. **The Go backend** (`backend/`) — a REST + MCP-protocol API server backing a hosted version of the writeup RAG and hunt-memory system, with PostgreSQL + pgvector.

Read [README.md](README.md) and [ARCHITECTURE.md](ARCHITECTURE.md) first — they are the canonical design docs and go deeper than this file on philosophy, the WSTG methodology mapping, and the full agent roster.

## Commands

### Go backend (`backend/`)

Run from inside `backend/`, or `make -C backend <target>`:

```bash
make build          # go build -o bin/huntmcp-server ./cmd/server
make run            # run locally against local Postgres (DATABASE_URL is set inline in the Makefile)
make test           # go test ./... -v -count=1
make lint           # golangci-lint run ./...
make vendor         # go mod tidy && go mod vendor
make dev            # docker compose up --build -d postgres api embedder
make db-up          # start only Postgres via docker compose
make embedder-run   # cd embedder && python3 server.py
```

Run a single Go test:
```bash
go test ./internal/service/... -run TestName -v
```

### Python MCP servers (`mcp-servers/`)

Each tool subdirectory is an independent FastMCP server (`server.py` + its own `requirements.txt`), invoked by OpenCode via the config in `opencode.jsonc` using the repo's `.venv` interpreter. There's no single top-level Python package/build step — install deps per-server as needed, or `pip install chromadb sentence-transformers` for the RAG stack referenced in the README.

Syntax/lint checks used in CI (useful to run locally before pushing):
```bash
ruff check mcp-servers/ --ignore E402,F811 --target-version py312
python -m py_compile mcp-servers/<server>/server.py
bash -n scripts/*.sh
```

### Docker / full stack

```bash
docker compose build          # build the HuntMCP image
docker compose run --rm dev   # interactive dev shell with all tools installed
docker build -t huntmcp-api:latest .   # production Go API image (backend/Dockerfile-driven multi-stage build)
```

### Running the agent system

```bash
opencode run "HuntMCP audit example.com"              # full autonomous audit
opencode run "HuntMCP audit example.com --quick"       # recon + nuclei only
opencode run "HuntMCP watch example.com --interval 6h" # continuous monitoring
opencode run "HuntMCP report <scan-id>"
opencode run "HuntMCP chain <scan-id>"                 # vulnerability chaining analysis
opencode run "HuntMCP ingest <url> --class XSS --tech React"
opencode run "HuntMCP learn --query 'XSS in React apps'"
```

## Architecture

### Agent orchestration (`.opencode/`)

- **HuntBrain** (`.opencode/agents/huntbrain.md`) is the single Level 1 orchestrator: receives a goal, queries Memory DB + Writeup RAG, delegates to specialists, merges results, loops until attack surface is exhausted, then reports.
- **Permanent Level 2 specialists**: Recon (subfinder → httpx → katana), Scan (nuclei, sqlmap, dalfox, Burp Scanner), Exploit (Burp Repeater/Collaborator validation + chaining), Report (H1/Bugcrowd-ready output). One `.md` file each in `.opencode/agents/`.
- **Dynamic specialists** are spawned on demand when HuntBrain detects relevant tech (e.g. a GraphQL agent when `/graphql` is found, a JWT agent when a `Bearer eyJ...` token appears). This is how the system scales past 100 agents — they're markdown files with locked-down tool/permission scopes, not persistent processes.
- Custom slash commands (`/ingest`, `/learn`, `/chain`, `/watch`) live in `.opencode/commands/`.
- `opencode.jsonc` registers all MCP servers, sets the default agent, and controls permission prompts (bash/edit ask-by-default with a small allowlist).

### Knowledge layer

Two independent systems, both queried by agents before acting on a target:
- **Writeup RAG** (`mcp-servers/writeup-mcp/`) — ChromaDB + sentence-transformers. Source writeups are git-tracked markdown in `data/writeups/` (YAML frontmatter with `title`, `url`, `vuln_class` required — CI validates this). Vectors in `data/chroma/` are gitignored and rebuilt locally at ingestion time via `chunker.py` / `embedder.py` / `chroma_client.py`.
- **Memory DB** (`mcp-servers/memory-mcp/`) — SQLite (`db.py`), per-target hunt history: what worked, what didn't, on THIS target specifically. `data/memory.db` is gitignored.

### MCP servers (`mcp-servers/`)

One subdirectory per tool, each a small FastMCP (Python) server exposing `@app.tool()` functions that shell out to a security binary and return formatted text. Current servers: `subfinder`, `httpx`, `katana`, `nmap`, `nuclei`, `sqlmap`, `dalfox`, `ffuf`, `chainer` (DAG-based chain planner, 15 templates), `watch` (continuous recon diffing), `oob` (interactsh-client wrapper for blind SSRF/XXE/SQLi/RCE callback confirmation), `waf-bypass` (automated Tier 1-4 WAF-bypass variants), `browser` (real headless-Chromium JS/DOM execution confirmation via Playwright — closes exploit-agent's "reflected vs. actually executed" XSS confirmation gap), `hackerone` (read-only scope-sync + self-duplicate check), `target-discovery` (security.txt-based unlisted-target discovery, plus credential-free aggregated-scope lookup across HackerOne/Bugcrowd/Intigriti/Federacy/YesWeHack via `bounty_scope.py`), `secrets` (gitleaks over local files), `second-opinion` (cross-model independent review of a finding), `writeup` (RAG over ingested writeups, CVE fetch, and `disclosed_reports.py`-backed real-report-citation search), `memory`, `lessons`. Shared, non-server modules also live directly in `mcp-servers/`: `tool_resolver.py` (binary resolution + rate-limit/WAF detection), `scope_guard.py` (scope enforcement), `budget_guard.py` (Tier-2 call-count circuit breaker), `engagement_paths.py` (per-target engagement state + one-target-per-chat guard), `audit_log.py` (per-call JSON audit trail), `work_registry.py` (duplicate-spawn check), `dedupe_check.py` (duplicate-finding check), `bounty_scope.py` (aggregated bounty-program scope cache/lookup/diff), `disclosed_reports.py` (disclosed-vulnerability-report cache/search), `content_scanner.py` (OWASP Skill/MCP Top 10-style safety scan for new/changed skill and MCP-server content), `tool_gaps.py` (global tool-gap capture — the bounded first step of the self-expanding-toolkit idea), `model_gateway.py` (multi-provider selection) — all covered by `tests/` (pytest, wired into CI).

`mcp-servers/tool_resolver.py` is shared by these servers to resolve external binary paths — it exists specifically to prefer Go/system binaries over same-named Python packages that shadow them on `PATH` (e.g. ProjectDiscovery's `httpx` vs the Python `httpx` HTTP client). Use `resolve_tool()`/`run_tool()` from it rather than calling `subprocess` with a bare tool name.

### Go backend (`backend/`)

Standard layered Gin service, entrypoint at [backend/cmd/server/main.go](backend/cmd/server/main.go):
- `internal/model/` — data structs (writeup, user, hunt)
- `internal/repository/` — Postgres + pgvector data access (`postgres.go` owns the connection and runs `migrations/*.sql` on startup)
- `internal/service/` — business logic (currently `auth_service.go`: register/login/JWT validate)
- `internal/handler/` — HTTP handlers, including `mcp.go` which exposes an MCP-protocol-compatible endpoint at `POST /mcp` alongside the REST API
- `internal/middleware/` — auth (JWT), admin gating, CORS, rate limiting

Route shape: `GET /health`, `POST /api/v1/auth/{register,login}` (public), everything else under `/api/v1` behind `AuthMiddleware`, `/api/v1/admin/*` additionally behind `AdminMiddleware`, and `POST /mcp` for the MCP protocol bridge. The `embedder/` directory is a separate Python (sentence-transformers) microservice the Go backend calls out to for embeddings — Go handles all other production traffic. `docker-compose.yml` wires together `postgres`, `api`, `embedder`, plus `writeup`/`memory` MCP services and a `dev` shell.

## Conventions

- MCP servers: FastMCP (Python), one subdirectory per tool under `mcp-servers/`, each with its own `requirements.txt`.
- Shell scripts live only in `scripts/` — no Python scripts outside `mcp-servers/`.
- Agent files (`.opencode/agents/*.md`) require YAML frontmatter with `description` and `mode` (`primary` or `subagent`) — CI (`validate-agent-files` job) enforces this.
- Writeup files (`data/writeups/*.md`) require YAML frontmatter with `title`, `url`, `vuln_class` — CI enforces this too.
- Embedding happens via `sentence-transformers` (Python) but only at ingestion time; the Go backend serves all production read/query traffic.

## Git rules

| Push | Do not push |
|------|-------------|
| `mcp-servers/`, `.opencode/`, `scripts/`, `knowledge/`, `data/writeups/`, `backend/` | `data/chroma/`, `data/memory.db`, `logs/*.log`, `.env` |

## Runtime dependencies

- OpenCode v1.17+
- Python 3.10+ (3.12 used in CI)
- Go toolchain 1.23+, plus the security tools themselves: subfinder, httpx, nuclei, katana, ffuf, dalfox (all `go install`-able; see README for exact module paths)
- Burp Suite with the MCP Server extension expected on `127.0.0.1:9876` (used by Exploit agent for Repeater/Collaborator validation)
- PostgreSQL with pgvector (backend only)
