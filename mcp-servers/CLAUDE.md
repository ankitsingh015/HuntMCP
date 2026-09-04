# MCP Servers — Scoped Rules

## Scope
These rules apply to MCP server code under `mcp-servers/`.

## Before modifying
Read the root `CLAUDE.md` and applicable `.claude/rules/*` files first.

Inspect the existing server implementation, tests, configuration, and registration before adding new behavior.

## MCP boundaries
Preserve:
- tool schemas;
- input validation;
- scope enforcement;
- rate limits;
- timeouts;
- error semantics;
- audit logging;
- engagement isolation.

Do not bypass a scope gate simply because an MCP tool is called internally.

## Network tools
Network-capable MCP servers must preserve target validation and safe defaults.

Do not add unrestricted network access when an existing scoped primitive can be reused.

## Dependencies
Prefer the existing project/runtime dependencies.

Do not add a dependency when the standard library or existing project abstraction is sufficient.

Any new dependency requires explicit task authorization.

## Testing
Add focused tests for changed MCP behavior.

Where a server touches targets, prefer controlled local fixtures and black-box request/response verification.

## Compatibility
Avoid unrelated MCP server changes.

Preserve existing tool names and contracts unless the task explicitly changes them.
