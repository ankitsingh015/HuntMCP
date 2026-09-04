# Backend — Scoped Rules

## Scope
These rules apply to Go backend code under `backend/`.

## Before modifying
Read the root `CLAUDE.md` and applicable `.claude/rules/*` files.

Inspect existing packages, migrations, interfaces, configuration, and tests before changing behavior.

## Go conventions
Follow existing project Go conventions and package structure.

Prefer small, explicit changes over broad refactors.

## Database safety
- Use parameterized queries.
- Preserve transaction and locking semantics.
- Do not silently change migrations or schema behavior.
- Preserve engagement and tenant isolation.

## API behavior
Preserve existing authentication, authorization, validation, error handling, and resource limits.

Security-sensitive behavior requires focused tests.

## Dependencies
Do not introduce new Go dependencies unless explicitly authorized.

## Verification
Run the repository's documented Go tests and relevant checks after changes.

Do not claim backend behavior is correct from compilation alone.
