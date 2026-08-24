---
name: api-security-top10
description: OWASP API Security Top 10 as a dedicated API-only checklist -- BOLA, BFLA, broken object-property-level authz/mass assignment, unrestricted resource consumption, unsafe business-flow access, security misconfiguration, improper inventory management (shadow/zombie APIs), unsafe third-party API consumption, plus GraphQL/gRPC/SOAP/WebSocket coverage. Converted from master-pentest-prompt.md Phase 33. Use on API-only targets (no traditional web UI) as the dedicated checklist -- for mixed web+API targets the vuln-class skills already cover most of this ground per-endpoint.
---

# OWASP API Security Top 10 (dedicated -- API yes, plain web no)

## When to use

API-only targets, run per endpoint and per HTTP method, both
authenticated and unauthenticated. On a mixed web+API target, the
individual vuln-class skills (`access-control-and-idor`, `ssrf`, etc.)
already cover most of this per-endpoint -- this skill is for treating
the API surface as its own dedicated pass, and for the API-specific
items (schema extraction, inventory management) those skills don't
otherwise name.

## The ten items

- **BOLA (Broken Object Level Authorization)**: object IDs accessible
  across users via UUID, sequential ID, or enum -- check nested objects
  and deep-linked resources too, not just the top-level ID.
- **BFLA (Broken Function Level Authorization)**: a lower-privilege role
  successfully calling an admin-only function.
- **Broken Object Property Level Authorization**: mass assignment or
  read-only field tampering (`role: admin`, `balance: 0`, `verified:
  true`) sent in a request body the client shouldn't be able to set.
- **Unrestricted Resource Consumption**: no rate limit, no size limit,
  no query-depth limit, no pagination cap, multi-query DoS via a single
  expensive request.
- **Broken Function Level Auth**: missing authentication entirely on
  endpoints that should require it.
- **Unrestricted access to sensitive business flows**: change, transfer,
  or refund operations executable without proper step-up verification.
- **SSRF** (see the `ssrf` skill for the general technique) and
  server-side XSS via API responses that get rendered into HTML
  somewhere downstream.
- **Security misconfiguration**: default or overly permissive CORS,
  verbose error bodies, unnecessary HTTP methods left enabled, missing
  TLS on an API subdomain specifically.
- **Improper Inventory Management**: old/unversioned endpoints still
  live, shadow APIs shipped from stale code paths, non-production
  endpoints reachable publicly.
- **Unsafe consumption of APIs**: the target calling third-party APIs
  without validating their responses, letting an upstream compromise
  become the target's own vulnerability.

## Protocol-specific coverage

GraphQL (introspection left enabled, batching abuse -- see
`deep-cut-surfaces` for the fuller GraphQL list), gRPC (see
`microservices-and-internal-api` for reflection/proto-leak detail),
SOAP/XML (XXE -- see the `xxe` skill), WebSocket subscriptions with no
auth check, and importer/webhook features that follow an
attacker-supplied URL.

## Schema-driven fuzzing

Pull the OpenAPI/Swagger schema (see `misc-deep-cuts` for exposure paths
like `/swagger-ui`, `/redoc`) and fuzz every defined operation from it.
Test both idempotent and non-idempotent verbs, and check any endpoint
touching PII specifically for its inter-consumer-security (ICS) logic.
