# HuntMCP — World-Class Bug Bounty Automation Framework

## Philosophy

HuntMCP is not a script that chains tools in a fixed order. It is a **multi-level AI agent orchestration system** running inside OpenCode that:

1. Uses **Level 1 Orchestrator** (HuntBrain) to decide strategy
2. Spawns **Level 2 Specialist Agents** (Recon, Scan, Exploit, Report + unlimited dynamic specialists)
3. All agents query a **Knowledge Layer** (Writeup RAG + Memory DB) to learn from past hunts and public writeups
4. Tests all 30+ vulnerability classes across the full OWASP WSTG methodology
5. Validates findings via Burp Repeater before reporting
6. Learns continuously — manual ingestion + automated cron feeds keep the RAG database fresh

## Multi-Level Architecture

```
LEVEL 0: USER "HuntMCP audit example.com"
              │
              ▼
LEVEL 1: HUNTBRAIN (Orchestrator)
         │  Receives goal → queries Memory DB
         │  → decides strategy → delegates to sub-agents
         │  → merges results → decides next action
         │  → loops until complete → generates report
         │
         ├──→ LEVEL 2: RECON AGENT (permanent)
         │     ├── subfinder MCP (subdomains)
         │     ├── httpx MCP (live hosts + tech)
         │     └── katana MCP (crawl + JS)
         │
         ├──→ LEVEL 2: SCAN AGENT (permanent)
         │     ├── nuclei MCP (template vulns)
         │     ├── sqlmap MCP (SQLi)
         │     ├── dalfox MCP (XSS)
         │     └── Burp Scanner (via Burp MCP)
         │
         ├──→ LEVEL 2: EXPLOIT AGENT (permanent)
         │     ├── Burp Repeater (validation)
         │     ├── Burp Collaborator (OOB/SSRF)
         │     └── sqlmap --os-shell (RCE)
         │
         ├──→ LEVEL 2: REPORT AGENT (permanent)
         │     └── Generates H1/BC/MD reports
         │
         ├──→ LEVEL 2: DYNAMIC SPECIALISTS (spawned on demand)
         │     ├── @graphql-agent (when GraphQL detected)
         │     ├── @jwt-agent (when JWT found)
         │     ├── @oauth-agent (when OAuth detected)
         │     ├── @cloud-agent (when cloud assets found)
         │     ├── @wordpress-agent (when WP detected)
         │     ├── @saml-agent (when SAML found)
         │     └── @llm-agent (when AI endpoints found)
         │
         └──→ KNOWLEDGE LAYER (available to ALL levels)
               ├── WRITEUP RAG MCP (ChromaDB)
               │     └── "What techniques worked on similar targets?"
               └── MEMORY MCP (SQLite)
                     └── "What worked/didn't work on THIS target?"
```

### How 100+ Agent Orchestration Works

It is NOT 100 levels of hierarchy. It is **1 orchestrator + unlimited specialist agents** spawned on demand:

```
Orchestrator (1 file)
  │
  ├── 4 permanent agents (always loaded)
  │     Recon, Scan, Exploit, Report
  │
  ├── 50+ dynamic agents (created as .md files)
  │     Each = one file in .opencode/agents/
  │     Each = specific instructions + specific MCPs
  │     Each = spawned only when HuntBrain detects the need
  │     Examples:
  │     ├── react-agent.md     (React-specific XSS/CSRF tests)
  │     ├── graphql-agent.md   (GraphQL introspection/batching)
  │     ├── jwt-agent.md       (JWT none-alg/cracking/kid)
  │     ├── s3-agent.md        (S3 bucket listing/writing)
  │     └── ... unlimited
  │
  └── 2 knowledge systems (available to all)
        Writeup RAG + Memory DB
```

Each agent is just a **markdown file** with:
- Its own locked-down permissions  
- Its own specialized instructions
- Its own tool access (MCP subset)
- Spawned by HuntBrain when relevant

This scales to **unlimited agents** because they're files, not running processes.

## Methodology Sources Synthesized

| Source | What it contributed |
|--------|---------------------|
| OWASP Web Security Testing Guide (WSTG v4.2) | 12 testing categories, 90+ test cases |
| jhaddix The Bug Hunter's Methodology (TBHM) | Recon depth, content discovery approach |
| r-s0n methodology | Ebb & Flow vulnerability discovery model |
| su6osec HuntBook 2026 | Phase structure, 100+ tool references |
| hexsec 2026 Methodology | Two-eye approach, checklist-driven testing |
| Fino Hunter Workflow | Scope analysis → recon → discovery → testing → PoC → report |
| Carl Sampson 2026 Guide | Business logic chains, modern surface (SAML, WASM, AI/LLM) |
| shuvonsec BB Methodology Skill | Critical thinking framework, 5-minute rule |
| N0RMXL Framework | 10-phase methodology, checkpoint resume |
| bugbounty-hunter (mrch4n725) | Validation pipeline, multi-format reporting |
| BountyGrimoire | Multi-agent approach for authenticated testing |

## Complete Methodology — All Phases

### Phase 0 — Program Analysis
```
- Read scope (in-scope / out-of-scope / wildcard)
- Check disclosed HackerOne/Bugcrowd reports for patterns
- Identify tech stack (Wappalyzer, BuiltWith)
- Determine bounty tiers (which vulns pay highest)
- Get test accounts if required
- Check auth requirements and consent boundaries
- Query Writeup RAG: what vulns are common for this tech stack?
- Query Memory DB: have we hunted this target before?
```

### Phase 1 — Passive Reconnaissance (Zero interaction with target)

| Technique | Sources | What it finds |
|-----------|---------|---------------|
| Certificate Transparency | crt.sh, CertSpotter, Facebook CT | Subdomains from SSL certs |
| DNS Records | Chaos (ProjectDiscovery), SecurityTrails, DNSDumpster | DNS records, subdomains |
| Search Engines | Google Dorks (site:, inurl:, intitle:, filetype:, ext:) | Exposed configs, dev portals, admin panels, sensitive files |
| Code Repositories | GitHub Dorks, GitLab Dorks | API keys, tokens, secrets, internal endpoints, passwords |
| Archive Data | Wayback Machine, GAU (GetAllUrls), AlienVault OTX | Historical URLs, old endpoints, parameters |
| ASN/IP Ranges | BGP.he.net, whois, ipinfo.io | Target's IP address space |
| Acquisitions | Crunchbase, LinkedIn | New assets from acquired/merged companies |
| Internet Scanning | Shodan, Censys, ZoomEye | Exposed services, open ports, banners |
| WHOIS Records | whois command, whois.domaintools.com | Registrant info, name servers, registrar |
| Social Media | LinkedIn, Twitter, Reddit | Tech stack hints, employees, internal tools |
| DNS Zone Transfer | dig, fierce | Full DNS record dump (rarely works) |
| Email Harvesting | theHarvester, hunter.io | Employee emails, email patterns |
| Technology Stack | Wappalyzer, BuiltWith, WhatWeb | Frameworks, CMS, libraries, version numbers |

### Phase 2 — Active Enumeration (Direct interaction with target)

| Task | Tools | What it finds |
|------|-------|---------------|
| DNS Bruteforce | MassDNS, shuffledns, puredns | Subdomains not in passive sources (10k-1M wordlists) |
| DNS Resolution | dnsx | Which subdomains actually resolve to IPs |
| DNS Permutation | alterx, gotator | Permuted subdomains (dev-api, staging-v2) |
| Port Scanning | naabu (fast) → nmap (deep) | Open ports (top 1000 → all 65535) + service version detection |
| HTTP Probing | httpx | Live hosts, status codes, page titles, tech stack, CDN |
| Screenshots | gowitness, eyewitness | Visual recon — spot unusual pages, admin portals |
| JavaScript Analysis | LinkFinder, JSParser, SecretFinder, jsubfinder | API endpoints, internal routes, access keys, secrets |
| JavaScript Crawling | katana, hakrawler, gospider | All endpoints, forms, query parameters, comments |
| Historical URL Collection | Waybackurls, GAU, Katana, ParamSpider | Every URL ever seen for this domain |
| Parameter Discovery | Arjun, ParamSpider, x8 | Hidden/undocumented parameters |
| Directory Bruteforce | ffuf, dirsearch, gobuster, feroxbuster | Hidden directories, admin panels, backup files |
| Cloud Asset Enum | cloud_enum, S3Scanner, bucket-stream | Open S3 buckets, Azure blobs, Firebase DBs |
| WAF Detection | wafw00f, whatwaf | WAF vendor identification + bypass research |
| Content Discovery | ffuf with custom wordlists (raft, SecLists) | Hidden content, API docs, .git, .env |
| Technology Fingerprinting | WhatWeb, Wappalyzer CLI, nuclei tech detect | CMS, framework, version → known CVEs |
| Certificate Analysis | testssl.sh, sslscan | SSL/TLS misconfigurations, weak ciphers |

### Phase 3 — Vulnerability Testing (All 30+ Classes)

#### 3A — Injection Vulnerabilities

| Class | Sub-types | Test Method | Tools |
|-------|-----------|-------------|-------|
| **SQL Injection** | Error-based, Union, Boolean blind, Time blind, Second-order, NoSQL | Inject `'` `"` `OR 1=1` in every parameter; observe errors; use time delays | sqlmap, Burp Intruder, ghauri, nosqli |
| **XSS** | Reflected, Stored, DOM-based, Blind, Mutation XSS (mXSS) | Inject `<script>alert(1)</script>` in all inputs; test event handlers; test in JS context | dalfox, XSStrike, Burp Repeater, kxss |
| **SSTI** | Jinja2, Twig, Freemarker, Velocity, Jade | Inject `{{7*7}}` `${7*7}` — if output is 49, template injection confirmed | SSTImap, tplmap, Burp |
| **Command Injection** | Blind, Out-of-band (OOB) | Inject `; whoami` `| id` `$(whoami)`` \`whoami\` | commix, Burp Collaborator |
| **LDAP Injection** | AND/OR injection | Inject `)(|(user=*` in login fields | Custom, Burp |
| **XPath Injection** | Boolean, Out-of-band | Inject `' or '1'='1` in XML parameters | Custom |
| **XXE** | In-band, Blind OOB, XInclude | Inject `<!ENTITY xxe SYSTEM "file:///etc/passwd">` in XML | Burp Collaborator, xxeserv |
| **Template Injection** | Server + Client side | Same as SSTI, test in email templates, PDF generators | — |
| **Expression Language** | Spring EL, JBOSS EL, Struts | Inject `${7*7}` in Java framework parameters | — |

**Logic:** If param reflects in response → XSS first. If param in SQL query → SQLi. If error shows template syntax → SSTI. If OS command visible → command injection.

#### 3B — Authentication & Session Attacks

| Class | Test Technique | Tools |
|-------|----------------|-------|
| **Authentication Bypass** | SQLi in login, NoSQL in login, type confusion (array: `[]`), parameter pollution | Burp Repeater |
| **JWT Attacks** | None algorithm (`alg: none`), weak HMAC secret cracking (john/hashcat), kid injection, JKU bypass, JWK confusion | jwt_tool, jwt-cracker, Burp |
| **OAuth 2.0 Abuse** | CSRF on OAuth flow, redirect_uri tampering, state parameter leakage, code replay, token theft | Burp |
| **SAML Abuse** | XML Signature Wrapping, Assertion tampering, Response replay, Recipient check bypass | Burp, samlraider |
| **OTP/2FA Bypass** | Race condition, response manipulation, status code bypass, rate limiting bypass, null code | Burp Intruder, Turbo Intruder |
| **Session Fixation** | Pre-set session cookie, force victim to use known session | Burp |
| **Password Reset Poisoning** | Host header injection in reset link, token leak in URL, token prediction | Burp |
| **Rate Limiting Bypass** | IP rotation (X-Forwarded-For), cookie rotation, distributed attack | ffuf, Burp Intruder |
| **Credential Stuffing** | Test breached passwords, default credentials, weak password policy | hydra, ffuf |
| **Insecure Direct Object Reference** | Change user IDs in params/cookies/headers | Burp Repeater |
| **Registration Poisoning** | Register with admin email patterns, homograph attacks | Burp |
| **WebAuthn Bypass** | Credential ID prediction, policy bypass, cross-origin attestation | Custom |

**Logic:** If login → test bypasses. If JWT → crack. If OAuth → test redirect. If reset → test token.

#### 3C — Authorization Flaws (IDOR / BAC)

| Class | Test Technique | Tools |
|-------|----------------|-------|
| **IDOR (Insecure Direct Object Reference)** | Increment IDs (`1`→`2`→`1000`), UUID prediction, Base64/Hex decode IDs, hash ID analysis | Burp Repeater, Autorize |
| **Mass Assignment** | Add extra params: `role:admin`, `is_admin:true`, `account_type:premium` | Burp |
| **Privilege Escalation** | Lower-priv user accesses admin functions, CSRF token reuse, API rollback | Burp with 2 sessions |
| **API Auth Bypass** | Remove auth header, change to GET, downgrade HTTP version, use unauthenticated alias | Burp |
| **CORS Misconfiguration** | Origin reflection (`Origin: evil.com` → `Access-Control-Allow-Origin: evil.com`), wildcard, null origin | Corsy, Burp |
| **Function-Level Access Control** | Force browse to admin paths `/admin`, `/api/admin` | Burp, ffuf |
| **HTTP Method Tampering** | Change PUT→GET, POST→PATCH, bypass auth on non-standard methods | Burp |
| **GraphQL Bypass** | Field suggestions bypass, field-level auth bypass | graphw00f, Burp |

**Logic:** Every authenticated request with user-specific data → test IDOR. Every POST→test mass assignment.

#### 3D — Business Logic Flaws (Highest Bounty Potential)

| Class | Test Method | Examples |
|-------|-------------|----------|
| **Race Conditions** | Send N simultaneous requests (Turbo Intruder) | Double spend, coupon race, like race, cart inconsistency |
| **Negative/Fractional Values** | Negative price, %1111111111, decimal in integer field | Negative total, fractional inventory |
| **Workflow Bypass** | Skip steps, reorder steps, replay steps | Payment bypass, free shipping without login |
| **Coupon Abuse** | Stack coupons, reuse codes, mass use, create coupons | Unlimited free items |
| **Account Takeover Chains** | Low-prevalence bugs combined for full ATO | Self-XSS + no HttpOnly + IDOR on cookie |
| **Feature Abuse** | Use features beyond intended limits | Unlimited SMS, email bombing, storage abuse |
| **Logic Flaws in State Machines** | Transition to invalid states | Order already delivered → order refund |
| **Multi-tenant Isolation** | Access tenant B's data as tenant A | Shared DB, no row-level security |
| **API Version Downgrade** | Use `/api/v1/` instead of `/api/v2/` | Old vulnerable endpoints |
| **Input Validation in Unexpected Places** | File size limits, upload type bypasses | Zip-slip, SVG XXE |

**Logic:** Think like a developer who trusted the user and made assumptions about how features would be used.

#### 3E — Server-Side Vulnerabilities

| Class | Test Method | Tools |
|-------|-------------|-------|
| **SSRF** | URL params, file uploads, redirect-following, partial URLs | Burp Collaborator, SSRFmap, Interactsh |
| **LFI/RFI** | Path traversal `../../../etc/passwd`, PHP wrappers `php://filter` | dotdotpwn, Burp |
| **File Upload** | Extension bypass (`.php5`, `.phtml`, `.phar`), Content-Type bypass, magic bytes bypass | Burp |
| **Deserialization** | Insecure deserialization in PHP (`serialize`), Java, Python pickle, Ruby Marshal, NodeJS | ysoserial, PHPGGC, Burp |
| **Prototype Pollution** | Client-side via JSON merge, server-side via express merge | Custom, Burp |
| **Host Header Injection** | Cache poisoning, password reset poisoning, SSRF via Host | Burp, Collab |
| **HTTP Request Smuggling** | CL.TE, TE.CL, TE.TE, CL.0 | smuggler, Burp |
| **Cache Poisoning** | Unkeyed headers, Host header, cookie reflection | Burp |
| **Web Cache Deception** | Append `.css` to dynamic endpoint — cache returns sensitive data | Burp |
| **Path Normalization Bypass** | `//`, `../`, URL encoding bypass of WAF | Burp |

#### 3F — Infrastructure & Cloud

| Class | Test Method | Tools |
|-------|-------------|-------|
| **Subdomain Takeover** | CNAME pointing to unclaimed Azure/CDN/GitHub/S3/Heroku | subzy, nuclei takeover |
| **S3 Bucket Misconfig** | List/Read/Write anonymous access | S3Scanner, cloud_enum |
| **Security Header Analysis** | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options | nuclei, custom |
| **CVE Vulnerability Scan** | Known CVEs for detected software/framework versions | nuclei CVE templates |
| **WAF Bypass** | Encoding, case switching, parameter pollution, HTTP version downgrade | wafw00f, custom |
| **DNS Misconfig** | Zone transfer, DNSSEC missing, SPF/DMARC misconfig | dig, dnsrecon |
| **Open Ports Exposure** | Non-standard ports: 3000, 8080, 8443, 9200, 27017 | nmap, naabu |
| **Cloud Metadata SSRF** | `http://169.254.169.254/` — cloud metadata endpoint | Burp |
| **GraphQL Introspection** | `__schema` query enabled on production | graphw00f, Burp |
| **API Gateway IDOR** | Direct-to-service bypassing API gateway auth | Burp |
| **TLS/SSL Issues** | Weak ciphers, outdated protocols, certificate issues | testssl.sh, sslscan |

#### 3G — Modern Web Attack Surface (2026)

| Class | Description | Test Method |
|-------|-------------|-------------|
| **GraphQL Abuse** | Introspection, batching attacks, deep nesting DoS, alias-based rate limit bypass | Craft GraphQL queries |
| **WebSocket Attacks** | No auth on WS upgrade, cross-origin WS hijack, message injection | Burp WebSocket history |
| **WebAssembly (WASM)** | Reverse engineer WASM for hardcoded keys, business logic | wasm-decompile, Chrome devtools |
| **SAML SSO** | XML signature wrapping, assertion tampering, response replay | Burp, samlraider |
| **WebAuthn/Passkey** | Credential ID prediction, policy bypass, cross-origin attestation | Custom |
| **AI/LLM Security** | Prompt injection, training data extraction, prompt leaking, model abuse | Inject adversarial prompts |
| **Serverless Security** | Event injection, cold start manipulation, IAM misconfig | Cloud-specific |
| **Service Mesh / Sidecar** | mTLS bypass, Envoy config exploitation | Custom |
| **API Gateway Routing** | Route smuggling, service bypass | Burp |

### Phase 4 — Exploitation & PoC Creation

| Step | Action | Tools |
|------|--------|-------|
| **1. Reliable Reproduction** | Confirm the bug works 3/3 times | Burp Repeater |
| **2. Severity Escalation** | Make it worse: XSS → cookie theft → ATO; SQLi → RCE; SSRF → full internal network | Burp, sqlmap --os-shell |
| **3. Business Impact** | What data can we extract? Can we pivot? Prove real risk | Custom |
| **4. Chaining** | Chain 2+ low bugs into critical impact: IDOR + XSS = ATO; file upload + LFI = RCE; SSRF + cloud = credential access | Agent decides chains |
| **5. PoC Documentation** | Screenshot (UI bugs), curl commands, HTTP request/response, Burp files | Burp, auto-capture |
| **6. CVSS v3.1 Scoring** | Calculate CVSS with full vector string | Calculator |
| **7. Remediation** | Specific actionable fix, not generic advice | Auto-generated |

### Phase 5 — Reporting

| Section | Content |
|---------|---------|
| **Title** | `[Vuln Type] in [Endpoint] leads to [Impact]` |
| **Severity** | CVSS v3.1 vector + score (Critical/High/Medium/Low) |
| **Affected Component** | Exact URL, parameter, endpoint |
| **Description** | Clear technical explanation of the vulnerability |
| **Steps to Reproduce (2-5 steps)** | Numbered steps — anyone with access can verify |
| **Proof of Concept** | Screenshot(s) + curl command + raw HTTP request/response |
| **Impact** | Business risk: data exposure, account takeover, RCE, etc. |
| **Remediation** | Specific fix recommendation with code examples if possible |
| **References** | OWASP, CWE, CVE, related writeups |

#### Report Formats
- HackerOne-ready format (optimized for triage speed)
- Bugcrowd-ready format
- Markdown (default — export to any platform)
- JSON (for CI/CD integration)

## Complete Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     USER INTERFACE                                │
│  "/audit example.com"  "/ingest https://..."  "/watch example"   │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  LEVEL 1: HUNTBRAIN ORCHESTRATOR AGENT                           │
│  ─────────────────────────────────────                           │
│                                                                   │
│  1. Receive user goal → parse target                              │
│  2. Query MEMORY MCP → "What do we know about this target?"       │
│  3. Query WRITEUP RAG → "What techniques work for this tech?"     │
│  4. Decide strategy → spawn appropriate Level 2 agents           │
│  5. Read results → decide next phase                              │
│  6. Loop until no more attack surface                             │
│  7. Spawn Report Agent → generate submission                      │
│  8. Save findings to MEMORY MCP → "learn for next time"           │
└──────┬───────────────────────────────────────────────────────────┘
       │                    │                    │
       ▼                    ▼                    ▼
┌──────────────┐ ┌──────────────────┐ ┌──────────────────────┐
│ LEVEL 2:     │ │ LEVEL 2:         │ │ LEVEL 2:             │
│ RECON AGENT  │ │ SCAN AGENT       │ │ EXPLOIT AGENT        │
│              │ │                  │ │                      │
│ subfinder    │ │ nuclei           │ │ Burp Repeater        │
│ httpx        │ │ sqlmap           │ │ Burp Collaborator    │
│ katana       │ │ dalfox           │ │ sqlmap --os-shell    │
└──────┬───────┘ │ Burp Scanner     │ └──────────┬───────────┘
       │         └────────┬─────────┘            │
       │                  │                      │
       │    ┌─────────────▼──────────────┐       │
       │    │ DYNAMIC SPECIALISTS        │       │
       │    │ (spawned on demand)        │       │
       │    │                            │       │
       │    │ @graphql-agent             │       │
       │    │ @jwt-agent                 │       │
       │    │ @oauth-agent               │       │
       │    │ @cloud-agent               │       │
       │    │ @wordpress-agent           │       │
       │    │ @saml-agent                │       │
       │    │ @llm-agent                 │       │
       │    │ ... unlimited              │       │
       │    └────────────────────────────┘       │
       │                                         │
       └────────────────┬────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────────────┐
│  KNOWLEDGE LAYER (available to ALL agents at ALL levels)         │
│                                                                   │
│  ┌──────────────────────┐    ┌──────────────────────────────┐    │
│  │  WRITEUP RAG MCP     │    │  MEMORY MCP                  │    │
│  │  ───────────────     │    │  ──────────                  │    │
│  │                      │    │                              │    │
│  │  Query: find similar │    │  Query: what worked before   │    │
│  │  writeups by vuln    │    │  on this target / tech?      │    │
│  │  class / tech / year │    │                              │    │
│  │                      │    │  Stores: findings, chains,   │    │
│  │  Backend: ChromaDB   │    │  failed attempts, profiles   │    │
│  │  + sentence-transform│    │                              │    │
│  │                      │    │  Backend: SQLite             │    │
│  └──────────┬───────────┘    └──────────────┬───────────────┘    │
│             │                               │                    │
│             │    INGESTION PIPELINE          │                    │
│             │    ─────────────────           │                    │
│             │                               │                    │
│             │  Manual: ./ingest-writeup.sh   │  Auto: each hunt  │
│             │  "I found a great writeup!"   │  saves results     │
│             │                               │                    │
│             │  Automated (cron):            │                    │
│             │  ├── H1 Hacktivity RSS → daily│                    │
│             │  ├── GitHub writeup repos→ wk │                    │
│             │  └── Security blogs → weekly  │                    │
│             └───────────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────┘
```

## Knowledge Layer Deep Dive

### How the Writeup RAG System Works

```
                          ┌──────────────────────────────┐
                          │    CHROMADB (vector store)    │
                          │                              │
                          │  Embedding 1 → writeup-1.md  │
                          │  Embedding 2 → writeup-2.md  │
                          │  Embedding 3 → writeup-3.md  │
                          │  ...                         │
                          │  Embedding N → writeup-N.md  │
                          └──────────┬───────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
            ┌──────────────┐              ┌────────────────────┐
            │  MANUAL       │              │  AUTOMATED (CRON)  │
            │  INGESTION    │              │  INGESTION         │
            │               │              │                    │
            │  You find a   │              │  Every day at 6AM: │
            │  writeup →    │              │  ├─ Check H1 feed  │
            │  run script   │              │  ├─ Check RSS      │
            │  with URL     │              │  ├─ Fetch new docs │
            │               │              │  └─ Embed + store  │
            └──────────────┘              └────────────────────┘
```

#### Manual Ingestion (when you find something interesting)

```bash
# You found a great writeup on Medium
./scripts/ingest-writeup.sh \
  --url "https://medium.com/..." \
  --title "IDOR to Account Takeover in XYZ" \
  --vuln-class "IDOR" \
  --target-tech "Node.js, React" \
  --bounty "$2500" \
  --author "jane_doe"

# Or via OpenCode command
/ingest https://medium.com/... --class IDOR --tech React
```

#### Automated Ingestion (cron — runs without you)

```bash
# /etc/cron.d/huntmcp-writeups
0 6 * * * ankit /home/ankit/HuntMCP/scripts/cron-fetch.sh

# What cron-fetch.sh does:
# 1. curl HackerOne Hacktivity RSS → parse new disclosures
# 2. curl GitHub API → check known writeup repos for new commits
# 3. curl Medium RSS feeds → check security blogs
# 4. For each new writeup → download → chunk → embed → store
# 5. Log everything in cron-ingestion.log
# 6. Optionally: send Slack/Discord notification of what was added
```

### How the Memory MCP System Works

```python
# memory-mcp/server.py

# Store hunt results
memory-mcp.save(target="example.com", {
  "findings": ["XSS in search", "IDOR in /api/users"],
  "chains": ["XSS + IDOR = ATO"],
  "tech_stack": ["React", "Node.js", "MongoDB"],
  "subdomains": ["api.example.com", "admin.example.com"],
  "date": "2026-07-06",
  "total_bounty_estimate": "$3000-5000"
})

# Recall before next hunt
memory-mcp.recall("example.com")
→ "Hunted 3 weeks ago. React + Node.js. Found XSS + IDOR. 
   Recommend: check if XSS is fixed, test for SSRF next."

# Search by tech stack (for strategy)
memory-mcp.search_by_tech("React", "Node.js")
→ "3 past hunts on React+Node targets. 
   Common findings: XSS (67%), IDOR (50%), SSTI (33%)"
```

### How Agents Use the Knowledge Layer

```
HuntBrain: "Target uses React + Node.js + MongoDB"

Step 1: Query MEMORY → have we seen this combo?
  → "Yes, 3 past hunts. High XSS probability."

Step 2: Query WRITEUP RAG → any React-specific writeups?
  → "Writeup: 'XSS in React Search Bar — use </> with onfocus=...'
     Writeup: 'IDOR in Node.js REST API — increment user IDs'
     Writeup: 'NoSQL injection in MongoDB — use $ne, $gt'"

Step 3: Use writeup payloads in scan → find bugs faster

Step 4: Save findings → "This target also had SSTI"
  → Memory updated for next time
```

## Git Strategy: How Writeups Flow Through the Repo

### What Gets Pushed to GitHub vs What Stays Local

```
HuntMCP/
├── mcp-servers/           ← YES push to GitHub (your code)
├── .opencode/             ← YES push (agent configs)
├── scripts/               ← YES push (ingestion scripts)
├── knowledge/             ← YES push (payloads, wordlists, skill)
├── backend/               ← YES push (Go API code)
├── opencode.jsonc         ← YES push
├── AGENTS.md              ← YES push
├── README.md              ← YES push
│
├── data/
│   ├── chroma/            ← DO NOT PUSH (.gitignore) — too large, platform-specific
│   ├── memory.db          ← DO NOT PUSH (.gitignore) — local only
│   └── writeups/          ← YES PUSH (raw markdown, small, diffable, PR-able)
│       ├── xss-in-react-search.md     ~5 KB
│       ├── idor-in-node-api.md        ~3 KB
│       └── ssrf-via-collaborator.md   ~4 KB
│
└── .gitignore
    ├── data/chroma/
    ├── data/memory.db
    ├── __pycache__/
    └── *.pyc
```

### Why Raw Writeups (.md) Are Git-Friendly

| Property | Raw .md file | ChromaDB vectors |
|----------|-------------|------------------|
| Size per 1000 writeups | ~50 MB | ~2 GB |
| Diffable | ✅ Yes (text diff) | ❌ Binary gibberish |
| Mergeable | ✅ Yes (no conflicts) | ❌ Impossible |
| Human-readable | ✅ Anyone can review | ❌ Machine only |
| PR reviewable | ✅ Read the payload, verify quality | ❌ Can't review vectors |

### The Contribution Flow

```
CONTRIBUTOR FINDS A WRITEUP
        │
        ▼
./ingest-writeup.sh --url "https://..." --class XSS --tech React
        │
        ├── Creates: data/writeups/2026-07-06-xss-in-react.md
        │             └── Standard format with frontmatter + payload + impact
        │
        ├── Updates: data/chroma/ (local only, NOT staged)
        │
        └── Prints: "✅ Writeup saved! Commit the .md file to share."

CONTRIBUTOR SUBMITS PR
        │
        │  git add data/writeups/xss-in-react.md
        │  git commit -m "Add writeup: XSS in React search"
        │  git push origin main
        │
        ▼
MAINTAINER REVIEWS PR
        │
        │  Opens the .md file → checks:
        │  ├── Valid frontmatter (title, url, vuln_class, tech)
        │  ├── Has a real payload/technique
        │  ├── Has a clear impact description
        │  └── No duplicates
        │
        ▼
PR MERGED → GitHub Action triggers
        │
        ├── Python script runs: chunk → embed → POST to Go API
        │                        OR update local ChromaDB
        │
        └── All users now have access to the new writeup in RAG
```

### .gitignore

```gitignore
# Vector database (rebuilt locally from raw .md files)
data/chroma/

# Local memory database (each user has their own)
data/memory.db

# Python cache
__pycache__/
*.pyc

# Logs
logs/*.log

# Environment
.env
```

---

## Tech Stack Decision: Go vs Python

| Component | Choice | Reason |
|-----------|--------|--------|
| **Backend API** | **Go** (Gin/Echo/Fiber) | Performance, single binary, goroutines for concurrent MCP connections, low memory |
| **Embedding** | **Python** (microservice only) | `sentence-transformers` is the gold standard; runs only in CI/CD, not in live path |
| **Database** | **PostgreSQL + pgvector** | Relational + vector search in one DB; no extra service; battle-tested |
| **Frontend** | **Next.js** (React/TypeScript) | Full-stack framework, easy auth, SSR for SEO, good ecosystem |
| **CI/CD** | **GitHub Actions** | Native to repo, free for public repos, easy to configure |
| **Hosting** | **Railway / Render / Fly.io** | Simple deployment, managed PostgreSQL, auto-scaling, free tier |

### The Only Python Component

```python
# embedder/server.py — 30 lines, runs ONLY during ingestion
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')

@app.post("/embed")
def embed(text: str):
    return {"vector": model.encode(text).tolist()}
```

This tiny service is:
- Called only when a writeup is ingested (PR merge or admin action)
- Never in the hot path of user queries
- Stateless — zero overhead when not in use
- Replaceable with Ollama (pure Go) or OpenAI API if desired

**No future issues with Go.** The Go API handles 100% of production traffic. Python is a build tool, not a runtime dependency.

---

## Project Structure

```
HuntMCP/
│
├── mcp-servers/                           Custom Python MCP servers
│   ├── subfinder-mcp/
│   │   └── server.py                      FastMCP wrapping subfinder
│   ├── httpx-mcp/
│   │   └── server.py                      FastMCP wrapping httpx
│   ├── nuclei-mcp/
│   │   └── server.py                      FastMCP wrapping nuclei
│   ├── ffuf-mcp/
│   │   └── server.py                      FastMCP wrapping ffuf
│   ├── sqlmap-mcp/
│   │   └── server.py                      FastMCP wrapping sqlmap API
│   ├── dalfox-mcp/
│   │   └── server.py                      FastMCP wrapping dalfox
│   ├── katana-mcp/
│   │   └── server.py                      FastMCP wrapping katana
│   ├── nmap-mcp/
│   │   └── server.py                      FastMCP wrapping nmap
│   ├── writeup-mcp/                       KNOWLEDGE LAYER
│   │   ├── server.py                      FastMCP for RAG queries
│   │   ├── chroma_client.py               ChromaDB integration
│   │   ├── embedder.py                    Sentence embeddings
│   │   └── requirements.txt
│   └── memory-mcp/                        KNOWLEDGE LAYER
│       ├── server.py                      FastMCP for memory queries
│       ├── db.py                          SQLite schema + queries
│       └── requirements.txt
│
├── .opencode/
│   ├── agents/
│   │   ├── huntbrain.md                   LEVEL 1: Orchestrator
│   │   ├── recon-agent.md                 LEVEL 2: Recon specialist
│   │   ├── scan-agent.md                  LEVEL 2: Scan specialist
│   │   ├── exploit-agent.md               LEVEL 2: Exploit specialist
│   │   ├── report-agent.md                LEVEL 2: Report specialist
│   │   ├── graphql-agent.md               DYNAMIC: spawned on demand
│   │   ├── jwt-agent.md                   DYNAMIC: spawned on demand
│   │   ├── oauth-agent.md                 DYNAMIC: spawned on demand
│   │   └── cloud-agent.md                 DYNAMIC: spawned on demand
│   │
│   └── commands/
│       ├── audit.md                        /audit <target> [--deep]
│       ├── ingest.md                       /ingest <url> [--class XSS] [--tech React]
│       ├── watch.md                        /watch <target> [--interval 6h]
│       ├── report.md                       /report <scan-id>
│       ├── chain.md                        /chain <scan-id>
│       └── learn.md                        /learn <query> (query writeup DB)
│
├── scripts/
│   ├── ingest-writeup.sh                   Manual writeup ingestion
│   ├── cron-fetch.sh                       Automated feed ingestion
│   ├── setup-tools.sh                      Install all Go/Python tools
│   └── setup-db.sh                         Initialize ChromaDB + SQLite
│
├── knowledge/
│   ├── owasp-wstg-skill.md                 SKILL.md: Full OWASP methodology
│   ├── payloads/
│   │   ├── xss.txt                         XSS payloads (1000+)
│   │   ├── sqli.txt                        SQLi payloads (500+)
│   │   ├── ssti.txt                        SSTI payloads (200+)
│   │   ├── lfi.txt                         LFI paths (100+)
│   │   └── ssrf.txt                        SSRF URLs (50+)
│   └── wordlists/
│       ├── api-endpoints.txt               API endpoint wordlist
│       └── subdomains-top-1m.txt           Subdomain wordlist
│
├── data/
│   ├── chroma/                             ChromaDB persistent storage
│   ├── memory.db                           SQLite memory database
│   └── writeups/                           Raw writeup markdown files
│
├── logs/
│   ├── hunt-*.log                          Per-hunt logs
│   └── cron-ingestion.log                  Writeup ingestion logs
│
├── opencode.jsonc                          Complete MCP config + permissions
├── AGENTS.md                               Project-level instructions
└── README.md                               Full documentation
```

## Evolution Path: Local → Go Backend → Full Platform

HuntMCP is designed to evolve across three phases. The architecture at each phase is compatible with the next — you never rewrite, you add.

```
PHASE 1: LOCAL (Months 1-2)     →    PHASE 2: GO BACKEND (Months 3-4)    →    PHASE 3: FULL PLATFORM (Months 5-6)

┌─────────────────────┐              ┌─────────────────────────┐              ┌──────────────────────────────┐
│  Your local machine  │              │  Go API Server + DB      │              │  Web App + CI/CD + Community │
│                     │              │                         │              │                              │
│  ChromaDB (local)   │              │  PostgreSQL + pgvector   │              │  Multi-user auth             │
│  SQLite (local)     │     ───►     │  Go API (Gin/Echo/Fiber) │    ───►      │  Writeup PR auto-train CI/CD │
│  All MCPs local     │              │  Embedder microservice   │              │  Web dashboard               │
│  Single user        │              │  MCP endpoint             │              │  Public API                  │
└─────────────────────┘              │  Multi-user (team)       │              │  Leaderboard + contributions │
                                      └─────────────────────────┘              └──────────────────────────────┘
```

---

## Phase 2: Go Backend Architecture (Months 3-4)

When the local system works and you want to scale to a team or the community, migrate the knowledge layer to a Go backend.

### Why Go for the Backend

| Aspect | FastAPI (Python) | Go (Gin/Echo/Fiber) |
|--------|-----------------|---------------------|
| Performance | ~3k req/s | ~50k req/s (10x faster) |
| Concurrency | Async/await | Goroutines (native) |
| Binary size | ~100MB + runtime | ~15MB single binary |
| Deployment | Needs Python runtime | One binary, no dependencies |
| Memory | ~200MB idle | ~10MB idle |
| Team scaling | Good | Excellent for microservices |

### Go Backend Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     GO BACKEND API                             │
│  ┌────────────────────────────────────────────────────────┐   │
│  │  Go Server (Gin/Echo/Fiber)                             │   │
│  │                                                         │   │
│  │  Endpoints:                                             │   │
│  │  ├── POST /api/v1/writeups       (add writeup)          │   │
│  │  ├── POST /api/v1/writeups/batch (bulk import)          │   │
│  │  ├── GET  /api/v1/writeups       (list/search)          │   │
│  │  ├── POST /api/v1/query          (RAG search)           │   │
│  │  ├── POST /api/v1/hunts          (save hunt results)    │   │
│  │  ├── GET  /api/v1/hunts/:target  (recall past hunts)    │   │
│  │  ├── POST /api/v1/reindex        (trigger rebuild)      │   │
│  │  ├── GET  /api/v1/stats          (dashboard data)       │   │
│  │  ├── POST /api/v1/auth/*         (user management)      │   │
│  │  └── GET  /mcp                   (MCP protocol endpoint)│   │
│  └────────────────────────────────────────────────────────┘   │
│                           │                                    │
│         ┌─────────────────┼─────────────────┐                  │
│         ▼                 ▼                  ▼                  │
│  ┌────────────┐   ┌──────────────┐   ┌──────────────┐         │
│  │ PostgreSQL  │   │  Redis Cache │   │  File Storage│         │
│  │ + pgvector  │   │  (optional)  │   │  (writeup.md)│         │
│  │             │   │              │   │              │         │
│  │ - writeups  │   │  - hot query │   │  - raw .md   │         │
│  │ - users     │   │    cache      │   │  - reports   │         │
│  │ - hunts     │   │  - sessions  │   │  - exports   │         │
│  │ - vectors   │   │              │   │              │         │
│  └────────────┘   └──────────────┘   └──────────────┘         │
└──────────────────────────────────────────────────────────────┘
         │                          │
         │                          │
         ▼                          ▼
┌──────────────────┐   ┌──────────────────────────────┐
│  Python Embedder  │   │  MCP Clients (local machines)│
│  (microservice)    │   │                              │
│                   │   │  Each user's HuntMCP connects │
│  POST /embed      │   │  via:                         │
│  → returns vector │   │  - writeup-mcp (cloud mode)   │
│                   │   │  - memory-mcp (cloud mode)    │
│  Only needed for  │   │  - OR local mode (offline)    │
│  ingestion/rebuild│   │                              │
└──────────────────┘   └──────────────────────────────┘
```

### Why Python Embedder Exists (and Why It's Tiny)

The embedding step converts text to vectors. Python's `sentence-transformers` is the gold standard:

```python
# embedder/server.py — ~30 lines
from sentence_transformers import SentenceTransformer
from fastapi import FastAPI

model = SentenceTransformer('all-MiniLM-L6-v2')
app = FastAPI()

@app.post("/embed")
async def embed(text: str):
    return {"vector": model.encode(text).tolist()}
```

**This runs only during writeup ingestion** (CI/CD or admin action), NOT in the live API path. The Go API handles all production traffic. The Python microservice is:
- Stateless (scales to zero when not ingesting)
- Called only on PR merge or manual reindex
- Replaceable with Ollama or OpenAI API if desired

### Go Backend Project Structure

```
backend/
├── cmd/
│   └── server/
│       └── main.go                      Entry point
├── internal/
│   ├── handler/
│   │   ├── writeups.go                  CRUD handlers
│   │   ├── query.go                     RAG search handler
│   │   ├── hunts.go                     Memory handlers
│   │   ├── auth.go                      Auth handlers
│   │   ├── stats.go                     Dashboard stats
│   │   └── mcp.go                       MCP protocol handler
│   ├── model/
│   │   ├── writeup.go                   Writeup struct
│   │   ├── user.go                      User struct
│   │   └── hunt.go                      Hunt result struct
│   ├── repository/
│   │   ├── postgres.go                  PostgreSQL + pgvector
│   │   ├── writeup_repo.go             Writeup queries
│   │   └── hunt_repo.go                Hunt memory queries
│   ├── service/
│   │   ├── writeup_service.go          Business logic
│   │   ├── rag_service.go              RAG search logic
│   │   └── auth_service.go             Auth logic
│   └── middleware/
│       ├── auth.go                      JWT middleware
│       └── rate_limit.go                Rate limiting
├── embedder/                            Python microservice
│   ├── server.py                        Embedding endpoint
│   └── requirements.txt                 sentence-transformers, fastapi
├── migrations/
│   ├── 001_create_writeups.sql
│   ├── 002_add_pgvector.sql
│   └── 003_create_hunts.sql
├── Dockerfile
├── docker-compose.yml                   Go API + Postgres + Redis + Embedder
├── go.mod
├── go.sum
└── Makefile
```

### Installing pgvector on PostgreSQL

```sql
-- Enable the pgvector extension
CREATE EXTENSION vector;

-- Store writeups with vectors
CREATE TABLE writeups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    url TEXT,
    vuln_class TEXT NOT NULL,
    target_tech TEXT[],
    bounty INTEGER,
    author TEXT,
    content TEXT NOT NULL,
    embedding VECTOR(384),  -- 384-dim vector from all-MiniLM-L6-v2
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    source_type TEXT DEFAULT 'manual'  -- 'manual', 'cron', 'pr'
);

-- Store hunt memory
CREATE TABLE hunts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    tech_stack TEXT[],
    findings JSONB,
    chains JSONB,
    report_url TEXT,
    hunted_at TIMESTAMPTZ DEFAULT NOW(),
    user_id UUID REFERENCES users(id)
);

-- Vector similarity search index
CREATE INDEX idx_writeups_embedding ON writeups
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- Similarity search query (Go will run this)
-- SELECT content, title, vuln_class, 1 - (embedding <=> $1) AS similarity
-- FROM writeups
-- WHERE 1 - (embedding <=> $1) > 0.7
-- ORDER BY similarity DESC
-- LIMIT 5;
```

### How Local MCP Connects to Go Backend

```python
# writeup-mcp/server.py — Dual mode (local-first, cloud-optional)

import os
import requests
from chromadb import PersistentClient

BACKEND_URL = os.getenv("HUNTMCP_BACKEND_URL")  # Optional
CHROMA_DIR = os.getenv("CHROMA_DIR", "./data/chroma")

class WriteupMCPServer:
    def __init__(self):
        self.local_db = PersistentClient(path=CHROMA_DIR)
        self.cloud_mode = bool(BACKEND_URL)

    def query(self, query_text: str, top_k: int = 5):
        if self.cloud_mode:
            # Query Go backend with pgvector
            resp = requests.post(
                f"{BACKEND_URL}/api/v1/query",
                json={"query": query_text, "top_k": top_k}
            )
            return resp.json()
        else:
            # Query local ChromaDB
            results = self.local_db.query(query_texts=[query_text], n_results=top_k)
            return results
```

### When to Migrate from Local to Go Backend

| Signal | Trigger |
|--------|---------|
| **Team grows** | 2+ people using HuntMCP → need shared DB |
| **ChromaDB > 2GB** | Local vector DB becomes slow → pgvector is faster |
| **Community contributions** | PRs with writeups → CI/CD auto-train pipeline |
| **Need web access** | Dashboard, API, mobile access |
| **CI/CD integration** | GitHub Action security gate |

---

## Phase 3: Full Platform (Months 5-6)

When the Go backend is stable, add the web platform for community contributions and auto-training.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GITHUB REPO                                        │
│                                                                              │
│  data/writeups/*.md   ← Contributors submit PRs with new writeups           │
│                                                                              │
│  PR MERGED → triggers GitHub Action → auto-deploy                           │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CLOUD BACKEND (Go API + PostgreSQL)                  │
│                                                                              │
│  CI/CD (Python embedder) → embeds new writeup → stores in pgvector          │
│                                                                              │
│  Go API serves:                                                              │
│  ├── MCP endpoint for local HuntMCP clients                                  │
│  ├── REST API for web dashboard                                              │
│  └── Admin API for reindexing / management                                   │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
┌──────────────────────────┐  ┌──────────────────────────────┐
│  LOCAL HUNTMCP CLI        │  │  WEB DASHBOARD               │
│  (each user's machine)    │  │  (React / Next.js)            │
│                           │  │                              │
│  Connects to Go API via   │  │  Pages:                      │
│  writeup-mcp (cloud mode) │  │  ├── Dashboard (stats)       │
│  or works offline (local) │  │  ├── Writeups (browse)       │
│                           │  │  ├── Add (submit writeup)    │
│                           │  │  ├── Query (test RAG)        │
│                           │  │  └── Admin (manage)          │
└──────────────────────────┘  └──────────────────────────────┘
```

### CI/CD Auto-Train Pipeline

```yaml
# .github/workflows/auto-train.yml
name: Auto-Train RAG

on:
  pull_request:
    paths: ["data/writeups/*.md"]
    types: [closed]

jobs:
  validate-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Validate writeup files
        run: |
          python scripts/validate-writeups.py data/writeups/
          # Checks: valid frontmatter, required fields, no duplicates

      - name: Build vectors and deploy
        env:
          BACKEND_URL: ${{ secrets.BACKEND_URL }}
          API_KEY: ${{ secrets.API_KEY }}
        run: |
          pip install sentence-transformers chromadb
          python scripts/build-and-deploy.py \
            --input data/writeups/ \
            --api-url $BACKEND_URL \
            --api-key $API_KEY
          # This: chunks → embeds → POSTs to Go API → stored in pgvector

      - name: Notify contributor
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: "✅ Writeup ingested into RAG database! Vector DB updated."
            })
```

### Web Dashboard Frontend

```
frontend/
├── pages/
│   ├── dashboard.tsx         Stats graph, recent writeups, contributor leaderboard
│   ├── writeups.tsx          Browse/search/filter all writeups
│   ├── writeups/[id].tsx     Single writeup detail with payload viewer
│   ├── add.tsx               Form to add writeup (alternative to CLI)
│   ├── query.tsx             Test RAG queries against live vector DB
│   ├── login.tsx             GitHub OAuth login
│   └── admin.tsx             User management, reindex trigger, logs
├── components/
│   ├── WriteupCard.tsx       Reusable writeup preview
│   ├── SearchBar.tsx         With vuln-class / tech / bounty filters
│   ├── StatsChart.tsx        Monthly ingestion chart
│   ├── Navbar.tsx
│   └── Footer.tsx
├── lib/
│   ├── api.ts                API client for Go backend
│   └── auth.ts               Auth helpers
├── package.json
└── next.config.js
```

### Community Contribution Flow

```
CONTRIBUTOR                    GITHUB                      BACKEND
    │                           │                            │
    ├─ Fork repo                │                            │
    ├─ ./ingest-writeup.sh      │                            │
    │  → creates .md file       │                            │
    │  → validates locally      │                            │
    │                           │                            │
    ├─ git add + commit         │                            │
    ├─ git push origin branch   │                            │
    │                           │                            │
    │                    ┌──────▼────────┐                   │
    │                    │  PR SUBMITTED  │                   │
    │                    │  Auto-validate │                   │
    │                    │  Review by     │                   │
    │                    │  maintainers   │                   │
    │                    └──────┬────────┘                   │
    │                           │                            │
    │                    ┌──────▼────────┐                   │
    │                    │  PR MERGED     │                   │
    │                    └──────┬────────┘                   │
    │                           │                            │
    │                    ┌──────▼────────┐                   │
    │                    │  GITHUB ACTION │                   │
    │                    │  ─────────────  │                  │
    │                    │  1. Validate    │                  │
    │                    │  2. Embed       ├────────────────► │
    │                    │  3. Deploy      │                  │
    │                    │  4. Notify      │                  │
    │                    └─────────────────┘                  │
    │                                                         │
    │                                              ┌─────────▼────────┐
    │                                              │  pgvector updated │
    │                                              │  All users now    │
    │                                              │  query the new    │
    │                                              │  writeup in RAG   │
    │                                              └──────────────────┘
    │                                                         │
    │                    ┌────────────────────────────────────┘
    │                    │
    │              GitHub comment:
    │              "✅ Writeup ingested!
    │               Vector DB updated."
```

### Platform Features Summary

| Feature | Phase 1 (Local) | Phase 2 (Go Backend) | Phase 3 (Full Platform) |
|---------|-----------------|---------------------|------------------------|
| **Writeup storage** | ChromaDB (local) | PostgreSQL + pgvector | PostgreSQL + pgvector + backups |
| **Memory storage** | SQLite (local) | PostgreSQL | PostgreSQL |
| **MCP endpoint** | Local process | Go API /mcp endpoint | Go API + load balanced |
| **Multi-user** | ❌ Single user | ✅ Small team | ✅ Unlimited (auth) |
| **Web UI** | ❌ None | ❌ None | ✅ Next.js dashboard |
| **CI/CD auto-train** | ❌ Manual cron | ❌ Manual cron | ✅ Auto on PR merge |
| **Community contributions** | ❌ Manual only | ✅ GitHub PRs | ✅ PRs + Web form |
| **Auth** | ❌ None | ✅ API key or JWT | ✅ GitHub OAuth |
| **Public API** | ❌ None | ❌ Internal | ✅ Documented API |
| **Hosting** | Your machine | VPS (Railway/Render) | Scalable cloud (K8s) |
| **Backups** | ❌ None | ✅ DB dumps | ✅ Automated |
| **Monitoring** | ❌ None | ❌ Basic | ✅ Metrics + alerts |

## Build Plan (Complete)

### Phase 1: Local System (Months 1-2)

#### Sprint 1: Foundation (Week 1)

| Day | What | Deliverable |
|-----|------|-------------|
| 1-2 | Create directory structure | All folders exist |
| 3-4 | Create all 5 agent files | HuntBrain + Recon + Scan + Exploit + Report |
| 5-6 | Create writeup-mcp server.py | RAG MCP with ChromaDB |
| 7 | Create memory-mcp server.py | Memory MCP with SQLite |

#### Sprint 2: Knowledge Layer (Week 2)

| Day | What | Deliverable |
|-----|------|-------------|
| 1-2 | Write ingestion scripts | `ingest-writeup.sh` + `cron-fetch.sh` |
| 3-4 | Write cron configuration | Daily H1/GitHub/blog feeds |
| 5-6 | Seed database with ~50 writeups | Populated ChromaDB |
| 7 | Create `/ingest` + `/learn` commands | User can query and add writeups |

#### Sprint 3: Tool MCPs (Week 3-4)

| Week | What | Deliverable |
|------|------|-------------|
| 3 | Build 4 MCP wrappers | subfinder + httpx + katana + nmap |
| 4 | Build 4 MCP wrappers | nuclei + sqlmap + dalfox + ffuf |

#### Sprint 4: Agent Logic (Week 5-6)

| Week | Focus | Deliverable |
|------|-------|-------------|
| 5 | Phase 0-1-2 in agents | Recon agent runs full passive + active enum |
| 6 | Phase 3-4-5 in agents | Scan + Exploit + Report agents work end-to-end |

#### Sprint 5: Intelligence (Week 7-8)

| Week | Focus | Deliverable |
|------|-------|-------------|
| 7 | Chaining engine + Watch mode | AI chains findings, continuous monitoring |
| 8 | Final polish + testing | Docker, GitHub Action, full smoke test |

### Phase 2: Go Backend (Months 3-4)

| Sprint | What | Deliverable |
|--------|------|-------------|
| 6 | Go API server (Gin/Echo/Fiber) — core CRUD endpoints | Writeups + hunts + auth |
| 7 | PostgreSQL + pgvector integration | Database schema working |
| 8 | Python embedder microservice | Embedding endpoint for CI/CD |
| 9 | MCP endpoint in Go | Local HuntMCP connects in cloud mode |
| 10 | Migration scripts + deployment (Docker/Railway) | Production-ready backend |

### Phase 3: Full Platform (Months 5-6)

| Sprint | What | Deliverable |
|--------|------|-------------|
| 11 | CI/CD pipeline (GitHub Action auto-train) | Writeup PR → auto-embed → auto-deploy |
| 12 | Web dashboard (Next.js) | Browse, search, add writeups |
| 13 | GitHub OAuth + user management | Multi-user with permissions |
| 14 | Public API docs + rate limiting | Community-facing API |
| 15 | Monitoring + backups + release | Production-ready platform |

## Tool Installation Requirements

```bash
# Go tools (for MCP wrappers)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest

# Python (for RAG system)
pip install chromadb sentence-transformers

# Python (for exploitation)
pip install sqlmap

# Already configured:
# - Burp Suite MCP (27 tools) ✅
# - security-mcp (40+ OWASP tools) ✅
```

## Writeup Ingestion — Manual + Automated

### Manual (when YOU find something interesting)

```bash
# One writeup
./scripts/ingest-writeup.sh \
  --url "https://medium.com/..." \
  --title "How I found XSS in..." \
  --vuln-class XSS \
  --tech React \
  --bounty 500

# Or from the OpenCode prompt
/ingest https://medium.com/... --class XSS --tech React
```

### Automated (cron — runs daily)

```cron
# /etc/cron.d/huntmcp-ingest
0 6 * * * ankit /home/ankit/HuntMCP/scripts/cron-fetch.sh
0 12 * * * ankit /home/ankit/HuntMCP/scripts/cron-fetch.sh --refresh
```

The cron script:
1. Fetches HackerOne Hacktivity RSS → parses new disclosed reports
2. Fetches GitHub → scans known writeup repos for new commits
3. Fetches RSS feeds from security blogs (Medium, PortSwigger Research)
4. For each new writeup: download → chunk → embed → store in ChromaDB
5. Logs everything to `logs/cron-ingestion.log`

### What the Agent Does With Writeup Knowledge

```
Agent hunts a React + Node.js target
  → Queries Writeup RAG → "React XSS techniques"
  → Gets: 5 writeups with specific payloads
  → Uses those payloads during scan
  → Finds XSS faster because it knew what to test

Next day: a new writeup is published about GraphQL abuse
  → Cron picks it up at 6AM
  → Next GraphQL target: agent already knows the techniques
```

## Summary

```
SCOPE ANALYSIS → PASSIVE RECON → ACTIVE ENUM → VULN TESTING (30+ classes)
→ VALIDATION → CHAINING → REPORT

SUPPORTED BY:
  ├── Multi-level agent orchestration (HuntBrain + specialists)
  ├── Writeup RAG (learn from everything, both manual + automated)
  ├── Memory DB (remember past hunts, improve over time)
  └── Continuous learning (cron feeds keep knowledge fresh)
```

**Built with OpenCode. Powered by MCP. Designed for the world's best bug hunters.**
