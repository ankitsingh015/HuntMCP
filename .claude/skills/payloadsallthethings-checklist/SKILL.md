---
name: payloadsallthethings-checklist
description: The full PayloadsAllTheThings category checklist (60+ vuln classes) as a final coverage sweep. Converted from master-pentest-prompt.md Phase 22. Use as a closing checklist near the end of an engagement to catch any category that wasn't explicitly covered by another skill.
---

# PayloadsAllTheThings full directory list (check every box)

## When to use

Late in an engagement, as a coverage sweep against the
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
category list -- cross-check this against what's actually been tested and
chase down anything that fell through the gaps between the other skills.

## The checklist

API Key Leaks · Account Takeover · Brute Force Rate Limit · Business
Logic Errors · CORS Misconfiguration · CRLF Injection · CSS Injection ·
CSV Injection · CVE Exploits · Clickjacking · Client Side Path Traversal
· Command Injection · CSRF · DNS Rebinding · DOM Clobbering · Denial of
Service · Dependency Confusion · Directory Traversal · Encoding
Transformations · External Variable Modification · File Inclusion ·
Google Web Toolkit · GraphQL Injection · HTTP Parameter Pollution ·
Headless Browser · Hidden Parameters · Insecure Deserialization · IDOR ·
Insecure Management Interface · Insecure Randomness · Insecure Source
Code Management · JWT · Java RMI · LDAP Injection · LaTeX Injection ·
Mass Assignment · NoSQL Injection · OAuth Misconfiguration · ORM Leak ·
Open Redirect · Prompt Injection · Prototype Pollution · Race Condition ·
Regular Expression (ReDoS) · Request Smuggling · Reverse Proxy
Misconfigurations · SAML Injection · SQL Injection · SSI (Server Side
Include) Injection · SSRF · SSTI · Tabnabbing · Type Juggling · Upload
Insecure Files · Virtual Hosts · Web Cache Deception · Web Sockets ·
XPATH Injection · XS-Leak (cross-site leaks) · XSLT Injection · XSS ·
XXE · Zip Slip

Most of these are already covered in depth by a dedicated skill
(`injection-and-rce`, `xss`, `ssrf`, `xxe`, `access-control-and-idor`,
`request-smuggling`, `open-redirect`, `csrf-cors-origin`, and others) --
treat this list as the final "did I actually hit every category" check,
not a first-pass technique reference.
