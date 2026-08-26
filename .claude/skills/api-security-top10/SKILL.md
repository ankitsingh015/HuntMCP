---
name: api-security-top10
description: OWASP API Security Top 10 as a dedicated API-only checklist -- BOLA, BFLA, broken object-property-level authz/mass assignment, unrestricted resource consumption, unsafe business-flow access, security misconfiguration, improper inventory management (shadow/zombie APIs), unsafe third-party API consumption, plus GraphQL/gRPC/SOAP/WebSocket/OData coverage. Converted from master-pentest-prompt.md Phase 33. Use on API-only targets (no traditional web UI) as the dedicated checklist -- for mixed web+API targets the vuln-class skills already cover most of this ground per-endpoint.
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
  successfully calling an admin-only function. Check sibling-function verb
  drift too -- a route with solid GET-only auth checks often still accepts
  POST/PUT/DELETE on that same route with weaker or missing checks, since
  the auth review only covered the verb the UI actually uses. Also probe
  route-shadowing prefixes (`/v0/`, `/beta/`, `/internal/`) on the same
  resource path -- these frequently carry different, older, or entirely
  absent authorization compared to the production route.
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

On GraphQL specifically, also check the REST/GraphQL dual-write desync:
when an app exposes the same underlying data model through both a REST
API and a GraphQL API, authorization is frequently enforced inconsistently
between the two paths -- one gets hardened over time while the other, added
later as "the new way," skips checks the original accumulated. GitLab's
`runnerUpdate` mutation (CVE-2023-2478) is a concrete precedent: it let any
authenticated user attach a malicious runner to another project because the
mutation never verified Maintainer access on the target project the way the
REST equivalent did. Separately, GraphQL query-complexity/cost rate
limiting can be bypassed with a negative query cost -- passing a negative
value for a `first`/`limit`-style argument that the cost calculator doesn't
floor at zero, so each call subtracts from (rather than adds to) the
consumed rate-limit budget and effectively refills it.

## Schema-driven fuzzing

Pull the OpenAPI/Swagger schema (see `misc-deep-cuts` for exposure paths
like `/swagger-ui`, `/redoc`) and fuzz every defined operation from it.
Test both idempotent and non-idempotent verbs, and check any endpoint
touching PII specifically for its inter-consumer-security (ICS) logic.

## OData coverage

OData is the query layer behind SharePoint, Microsoft Dynamics 365/Power
Platform, SAP NetWeaver Gateway/Fiori, and any ASP.NET WebAPI project built
on `Microsoft.AspNetCore.OData` -- look for `OData-Version`/`DataServiceVersion`
response headers and paths like `/_api/`, `/odata/`, `/api/data/v9.x/`. Its
query operators (`eq`, `and`, `substringof`, `startswith`, `tolower`) look
SQL-ish but aren't SQL, so keyword-blacklist WAFs routinely wave them
through -- treat `$filter`, `$orderby`, and `$batch` as their own injection
class rather than assuming existing SQLi coverage applies. `$filter`
supports boolean-blind extraction (`$filter=startswith(<field>,'a')`,
narrowing the guessed prefix and reading the result cardinality as the
oracle) with no quotes or SQL keywords involved -- this is precisely how a
Dynamics 365/Power Apps Portals disclosure extracted `adx_identity_passwordhash`
and other PII a character at a time. `$orderby` deserves a separate check
even where `$select` is properly ACL'd: sorting on a column the caller has
no read permission for still leaks its values via response ordering, since
column-level ACLs are commonly enforced only on the projection, not on
`$orderby`/`$filter`. `$batch` accepts a `multipart/mixed` body containing
several sub-operations -- WAFs that only scan the outer request (or don't
parse `multipart/mixed` at all) miss every operation packed inside. When an
OData layer string-concatenates a filter into a backend SQL query instead
of using its ORM, it becomes ordinary SQLi; the XML-parsing side of the
same surface produced **CVE-2019-17554** (Apache Olingo OData, XXE via a
`<!DOCTYPE>`/external-entity payload in an `application/xml` `$batch` body).
