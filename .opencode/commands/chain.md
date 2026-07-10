---
description: Analyze findings for chainable attack chains, plan execution steps, and save chain results.
---

# Chain Command — Attack Chain Analyzer

Chain vulnerabilities together for maximum severity impact.

## Usage

```
/chain <findings-json>              Analyze findings and find chainable combinations
/chain <chain-key> <findings-json>  Get detailed exploitation plan for a specific chain
/chain templates                     List all available chain templates
/chain save <chain-json>            Save a completed chain to memory
```

## How it works

1. Spawn @chain-planner agent with the findings
2. chainer-mcp analyzes findings against known chain templates
3. Returns ranked list of possible attack chains
4. HuntBrain integrates the top chain into the exploitation phase

## Example findings JSON format

```json
[
  {
    "vulnerability_class": "XSS",
    "affected_endpoint": "https://target.com/search?q=test",
    "confidence": "HIGH",
    "payload": "<script>alert(1)</script>"
  },
  {
    "vulnerability_class": "IDOR",
    "affected_endpoint": "https://target.com/api/users/123",
    "confidence": "HIGH"
  }
]
```

## Chain templates available

| Chain Key | Name | Severity |
|-----------|------|----------|
| idor_xss_ato | IDOR + XSS → Account Takeover | Critical (9.0+) |
| ssrf_cloud_creds | SSRF + Cloud Metadata → Credential Access | Critical (9.0+) |
| fileupload_lfi_rce | File Upload + LFI → Remote Code Execution | Critical (9.0+) |
| sqli_xss_stored | SQLi + XSS → Stored XSS in Admin Panel | Critical (8.0+) |
| lfi_logpoisoning_rce | LFI + Log Poisoning → Remote Code Execution | Critical (9.0+) |
| sqli_data_exfil | SQL Injection → Full Data Exfiltration | Critical (9.0+) |
| ssrf_internal_portscan | SSRF → Internal Network Port Scan | High (7.0+) |
| openredirect_oauth_token | Open Redirect + OAuth → Token Theft | High (8.0+) |
| template_ssti_rce | SSTI → Remote Code Execution | Critical (9.0+) |
| deserialization_rce | Insecure Deserialization → RCE | Critical (9.0+) |
| graphql_batching_idor | GraphQL Batching + IDOR → Mass Data Leak | Critical (8.0+) |
| jwt_none_auth_bypass | JWT None Algorithm → Admin Access | Critical (9.0+) |
| subdomain_takeover_xss | Subdomain Takeover → XSS/Phishing | High (8.0+) |
| prototype_pollution_xss | Prototype Pollution + XSS → Universal XSS | High (8.0+) |
| race_condition_doublespend | Race Condition → Double Spend | High (8.0+) |
