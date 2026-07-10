---
description: "Complete OWASP Web Security Testing Guide (WSTG v4.2) methodology for HuntMCP agents. Covers 12 testing categories, 90+ test cases, and integration with all HuntMCP MCP tools."
---

# OWASP WSTG Methodology for Bug Bounty

This skill provides the complete OWASP Web Security Testing Guide methodology, adapted for autonomous agent-driven bug bounty hunting with HuntMCP's MCP tools.

## Phase 0: Information Gathering (WSTG-INFO)

### WSTG-INFO-01: Search Engines
- Google Dork: `site:target.com intitle:"index of"` → exposed directories
- Google Dork: `site:target.com ext:log | ext:txt | ext:conf` → config files
- Google Dork: `site:target.com inurl:admin | inurl:backup` → admin/backup paths
- Google Dork: `site:target.com filetype:pdf "confidential"` → sensitive PDFs
- Google Dork: `site:target.com intitle:phpinfo` → PHP info exposure
- Shodan: `hostname:target.com` → exposed services
- Shodan: `ssl:target.com` → related SSL certs

### WSTG-INFO-02: Web Server Fingerprinting
- Headers: `curl -I https://target.com` → Server, X-Powered-By
- Tool: `httpx -sc -td -title -tech-detect -u https://target.com`
- Tool: `whatweb https://target.com`
- Tool: `wappalyzer-cli https://target.com`

### WSTG-INFO-03: Review Webpage Comments & Metadata
- View page source for HTML comments: `<!-- TODO: remove debug endpoint -->`
- Check meta tags: `<meta name="generator" content="WordPress 5.8">`
- Check JavaScript source maps: `/static/js/main.js.map`

### WSTG-INFO-04: Identify Application Entry Points
- Endpoint discovery: `ffuf -w api-endpoints.txt -u https://target.com/FUZZ`
- Parameter discovery: `katana -u https://target.com -js -d 3`
- Historical URLs: `gau https://target.com | grep -E '\?.+='`
- Parameter analysis: `arjun -u https://target.com/api/v1/users`

### WSTG-INFO-05: Map Execution Paths
- JavaScript analysis: search for API endpoints in JS files
- Burp + LinkFinder: extract endpoints from JS
- Hidden parameters: `x8 -u "https://target.com/api/search?q=test" -w params.txt`

### WSTG-INFO-06: Application Fingerprint
- Check /robots.txt, /sitemap.xml, /favicon.ico hash
- Nuclei tech detection: `nuclei -u https://target.com -t technologies/`
- WAF detection: `wafw00f https://target.com`

### WSTG-INFO-07: Map 3rd Party Hosted Content
- Check CNAME records: `dig CNAME sub.target.com`
- Check for external CDN links in source
- Identify analytics, tracking, and widget scripts

### WSTG-INFO-08: Identify Attack Surface
- Subdomain discovery: `subfinder -d target.com` then `httpx -l subdomains.txt`
- Port scanning: `nmap -sC -sV target.com -p 1-10000`
- Content discovery: `ffuf -w directories.txt -u https://target.com/FUZZ`

## Phase 1: Configuration & Deployment Testing (WSTG-CONF)

### WSTG-CONF-01: SSL/TLS Testing
- `testssl.sh https://target.com`
- Check: weak ciphers, outdated protocols (SSLv2/v3, TLS 1.0/1.1), certificate issues

### WSTG-CONF-02: DB Listener Testing
- Check exposed database ports: 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB)
- SSRF to internal DB services

### WSTG-CONF-03: Infrastructure Config Testing
- Check for default credentials: admin:admin, root:root
- Check for exposed /phpinfo.php, /info.php, /server-status

### WSTG-CONF-04: Application Config Testing
- Check /.git/config, .env, config.php exposure
- Check CORS: `curl -H "Origin: https://evil.com" -I https://target.com`

### WSTG-CONF-05: File Extension Handling
- Upload tests: .php, .php5, .phtml, .phar, .asp, .aspx, .jsp, .war
- Path traversal in upload filename

### WSTG-CONF-06: Backup/Outdated Files
- Check for: index.php.bak, config.php.old, .swp, .swo files
- Common backup extensions: .bak, .old, .backup, ~, .save, .swp

### WSTG-CONF-07: Admin Interfaces
- ffuf admin wordlist against target
- Check common admin ports on non-standard paths

### WSTG-CONF-08: HTTP Methods Testing
- `curl -X OPTIONS -I https://target.com` → check for PUT/DELETE
- `curl -X PUT -d "test" https://target.com/test.txt` → file upload via PUT

### WSTG-CONF-09: Subdomain Takeover
- `subzy run --target target.com`
- Check CNAMEs pointing to unclaimed cloud services
- `nuclei -t takeovers/ -l target.com`

### WSTG-CONF-10: Cloud Metadata Testing
- SSRF to 169.254.169.254 (AWS, Azure, GCP, DO, OCI)
- SSRF to 100.100.100.200 (Alibaba)
- Check kubernetes.default.svc for K8s metadata

## Phase 2: Identity & Auth Testing (WSTG-IDNT & WSTG-ATHN)

### Identity Management
- WSTG-IDNT-01: Role definitions testing
- WSTG-IDNT-02: User registration testing
- WSTG-IDNT-03: Account provisioning testing
- WSTG-IDNT-04: Account enumeration via response timing, error messages

### Authentication
- WSTG-ATHN-01: Credential transport over encrypted channel
- WSTG-ATHN-02: Default credentials testing (admin:admin, root:root)
- WSTG-ATHN-03: Weak lockout / rate limit mechanism
- WSTG-ATHN-04: Bypass authentication via SQLi, NoSQLi
- WSTG-ATHN-05: Remember password / session persistence
- WSTG-ATHN-06: Browser cache weakness (Pragma, Cache-Control headers)
- WSTG-ATHN-07: Weak password policy
- WSTG-ATHN-08: OTP / MFA bypass testing
- WSTG-ATHN-09: Insecure password reset (token in URL, token prediction)

## Phase 3: Session Management Testing (WSTG-SESS)

- WSTG-SESS-01: Session management scheme analysis (cookie attributes)
- WSTG-SESS-02: Cookie attributes (Secure, HttpOnly, SameSite, Path, Domain)
- WSTG-SESS-03: Session ID predictability (entropy analysis)
- WSTG-SESS-04: Session fixation
- WSTG-SESS-05: CSRF (check anti-CSRF tokens, SameSite cookies)
- WSTG-SESS-06: Session logout / timeout
- WSTG-SESS-07: Session ID in URL / referer leakage
- WSTG-SESS-08: CSRF token validation (missing, weak random, tied to session)
- WSTG-SESS-09: JWT analysis (none alg, weak secret, algorithm confusion)

## Phase 4: Authorization Testing (WSTG-ATHZ)

- WSTG-ATHZ-01: Directory traversal / force browsing
- WSTG-ATHZ-02: Privilege escalation (vertical)
- WSTG-ATHZ-03: IDOR (horizontal)
- WSTG-ATHZ-04: Insecure direct object references (UUID/guesable IDs)

## Phase 5: Input Validation Testing (WSTG-INPV)

- WSTG-INPV-01: Reflected XSS
- WSTG-INPV-02: Stored XSS
- WSTG-INPV-03: DOM XSS
- WSTG-INPV-04: SQL Injection
- WSTG-INPV-05: LDAP Injection
- WSTG-INPV-06: ORM Injection
- WSTG-INPV-07: XML Injection / XXE
- WSTG-INPV-08: SSRF
- WSTG-INPV-09: Path Traversal / LFI
- WSTG-INPV-10: Command Injection
- WSTG-INPV-11: SSTI
- WSTG-INPV-12: Format String
- WSTG-INPV-13: HTTP Splitting / Request Smuggling
- WSTG-INPV-14: HTTP Parameter Pollution
- WSTG-INPV-15: Mass Assignment
- WSTG-INPV-16: Server-Side Includes
- WSTG-INPV-17: Prototype Pollution (client + server-side)

## Phase 6: Error Handling Testing (WSTG-ERRH)

- WSTG-ERRH-01: Error codes (custom error pages, stack traces)
- WSTG-ERRH-02: Stack traces (debug mode in production)

## Phase 7: Cryptography Testing (WSTG-CRYP)

- WSTG-CRYP-01: Weak encryption / hashing algorithms
- WSTG-CRYP-02: Padding oracle (CBC-MAC)
- WSTG-CRYP-03: Predictable random numbers
- WSTG-CRYP-04: JWT algorithm confusion / none algorithm

## Phase 8: Business Logic Testing (WSTG-BUSL)

- WSTG-BUSL-01: Business logic data validation
- WSTG-BUSL-02: Ability to forge requests (skip steps)
- WSTG-BUSL-03: Integrity checks
- WSTG-BUSL-04: Process timing (race conditions)
- WSTG-BUSL-05: Number limits (negative values, overflow)
- WSTG-BUSL-06: Use of malicious input
- WSTG-BUSL-07: Workflow bypass
- WSTG-BUSL-08: Upload of unexpected file types
- WSTG-BUSL-09: Payment / coupon abuse

## Phase 9: Client-Side Testing (WSTG-CLNT)

- WSTG-CLNT-01: DOM-based XSS
- WSTG-CLNT-02: JavaScript execution (eval, setTimeout, innerHTML)
- WSTG-CLNT-03: HTML injection
- WSTG-CLNT-04: Client-side URL redirect
- WSTG-CLNT-05: CSS injection
- WSTG-CLNT-06: Client-side resource manipulation
- WSTG-CLNT-07: Cross-origin resource sharing (CORS)
- WSTG-CLNT-08: WebSocket hijacking
- WSTG-CLNT-09: PostMessage XSS
- WSTG-CLNT-10: Local storage / session storage analysis (sensitive data)
- WSTG-CLNT-11: DOM clobbering
- WSTG-CLNT-12: Prototype pollution (client-side)

## Tool Mapping (HuntMCP MCP Tools)

| WSTG Phase | HuntMCP MCP Tool | Technique |
|------------|------------------|-----------|
| INFO/CONF | subfinder-mcp | Subdomain enumeration |
| INFO/CONF | httpx-mcp | HTTP probing, tech detection, status codes |
| INFO/CONF | katana-mcp | JS crawling, endpoint discovery, parameter extraction |
| INFO/CONF | nmap-mcp | Port scanning, service detection |
| INPV | nuclei-mcp | Template-based vulnerability scanning (XSS, SQLi, SSRF, etc.) |
| INPV | sqlmap-mcp | Automated SQL injection detection + exploitation |
| INPV | dalfox-mcp | XSS scanning with WAF bypass |
| INPV/CONF | ffuf-mcp | Directory fuzzing, parameter fuzzing, content discovery |
| All | writeup-mcp | Query RAG for similar vulns + payloads |
| All | memory-mcp | Recall/remember hunt state, findings, chains |
