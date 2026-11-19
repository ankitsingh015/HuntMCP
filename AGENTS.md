# HuntMCP — Agent Instructions

HuntMCP is a multi-level AI agent orchestration system for authorized bug
bounty hunting, built on **Claude Code + MCP**.

**The canonical agent instructions live in [`CLAUDE.md`](CLAUDE.md)** — it is the
single source of truth for what this project is, the build/test commands, the
architecture (`.claude/agents/`, `.mcp.json`, `mcp-servers/`, the knowledge
layer), the runtime dependencies, the git rules, and the engineering rules
under `.claude/rules/`.

This file exists only so tools that look for a repo-root `AGENTS.md` find a
pointer; it intentionally carries no instructions of its own, so there is
nothing here to drift out of sync with `CLAUDE.md`.
