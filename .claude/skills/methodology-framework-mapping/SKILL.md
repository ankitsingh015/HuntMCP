---
name: methodology-framework-mapping
description: How to map every finding to industry-standard frameworks for the final report -- MITRE ATT&CK tactic/technique IDs, PTES phase alignment, OWASP WSTG test-case numbering, CVSS 3.1 vector scoring, CWE IDs, and CISA KEV catalog cross-referencing. Converted from master-pentest-prompt.md Phase 36. Use while writing up each finding, not during active testing.
---

# Methodology frameworks -- map the report to industry standards

## When to use

While writing up each finding for the report, not during active
testing -- this is a scoring/classification pass applied after a
vulnerability is already confirmed.

## MITRE ATT&CK

Map each finding to its ATT&CK tactic and technique ID (e.g. Initial
Access TA0001 for an unauthenticated RCE, chaining forward through
whatever privilege-escalation tactic the finding enables). This gives
the report a standard vocabulary that security teams already use
internally.

## PTES phase alignment

Frame the report's narrative in PTES's own phase order -- pre-engagement
interactions, intelligence gathering, threat modeling, vulnerability
analysis, exploitation, post-exploitation, reporting -- which
conveniently doubles as a reasonable execution order for the engagement
itself, not just a reporting structure.

## OWASP WSTG numbering

Tag each test performed with its WSTG identifier: `WSTG-INFO`
(information gathering), `WSTG-CONF` (configuration), `WSTG-IDNT`
(identity management), `WSTG-ATHN` (authentication), `WSTG-ATHZ`
(authorization), `WSTG-SESS` (session management), `WSTG-INPV` (input
validation), `WSTG-ERRH` (error handling), `WSTG-CRYP` (cryptography),
`WSTG-BUSL` (business logic), `WSTG-CLNT` (client-side), `WSTG-DCVR`
(discovery).

## Scoring

CVSS 3.1 vector string for every finding's severity score; the relevant
CWE ID(s); and a note in the CISA KEV catalog if the underlying CVE is
already known to be exploited in the wild -- KEV membership is a
concrete signal for report prioritization, not just a nice-to-have
citation.

## OWASP WSTG coverage checklist

The section above tags each *finding* with its WSTG ID for the report.
This checklist is different: it's a coverage-tracking pass over the full
WSTG test-case list itself, run near the end of an engagement, to answer
"did I actually touch every WSTG category" independent of whether any
given category produced a finding. Check off each sub-item that was
tested (even if it came back clean) -- an unchecked item is a gap, not
an assumed pass.

**WSTG-INFO -- Information Gathering:** search-engine discovery ·
fingerprint web server · review metafiles (robots.txt, sitemap.xml,
security.txt) · attack-surface discovery · resolve and probe live hosts
· review page content for info leaks · identify entry points ·
fingerprint framework/tech stack · map application architecture

**WSTG-CONF -- Configuration and Deployment:** network infrastructure ·
application-platform configuration · file extensions handling · backup
and unreferenced files · admin interfaces · HTTP methods (verb
tampering, TRACE/XST) · HSTS · subdomain takeover · cloud storage
(S3/GCS buckets) · Content-Security-Policy · path confusion · security
headers

**WSTG-IDNT -- Identity Management:** role definitions · user
registration process · account enumeration (timing, password-reset
oracle)

**WSTG-ATHN -- Authentication:** credentials over encrypted channel ·
default credentials · weak lockout mechanism · bypass authentication
schema (forced browsing, parameter tampering) · weak authentication
methods · password-reset flow · multi-factor authentication

**WSTG-ATHZ -- Authorization:** directory traversal/file include ·
bypass authorization schema · privilege escalation · insecure direct
object references (IDOR) · OAuth weaknesses

**WSTG-SESS -- Session Management:** session-token schema · cookie
attributes (`HttpOnly`/`Secure`/`SameSite`) · session fixation · CSRF ·
logout functionality · session timeout · JWT testing

**WSTG-INPV -- Input Validation:** reflected XSS · stored XSS · HTTP
verb tampering · SQL injection · code injection/file inclusion ·
command injection · HTTP request smuggling · Host header injection ·
SSTI · SSRF · mass assignment · prototype pollution

**WSTG-ERRH -- Error Handling:** improper error handling · stack traces

**WSTG-CRYP -- Cryptography:** weak TLS configuration · padding oracle
· unencrypted channels · weak cryptographic primitives

**WSTG-BUSL -- Business Logic:** data validation (negative
quantity/price) · forge requests (tamper signed values) · integrity
checks · process timing/race conditions · circumvent workflows (skip
steps) · file-upload logic

**WSTG-CLNT -- Client-side Testing:** DOM XSS · client-side redirects ·
CSS injection · CORS configuration · clickjacking · WebSocket testing ·
browser-storage inspection (localStorage/sessionStorage)

**WSTG-API (WSTG-APIT) -- API Testing:** API reconnaissance
(documentation/schema discovery) · broken object-level authorization ·
excessive data exposure · broken function-level authorization ·
GraphQL-specific testing (introspection, batching, field suggestion)

This checklist structure mirrors, and should be cross-checked against,
the deeper per-class technique content already covered by
`injection-and-rce`, `xss`, `ssrf`, `access-control-and-idor`,
`auth-and-session`, `csrf-cors-origin`, `information-disclosure`, and
`api-security-top10` -- use it to spot an uncovered WSTG category, then
go to the matching skill for the actual technique list, not as a
replacement for those skills.
