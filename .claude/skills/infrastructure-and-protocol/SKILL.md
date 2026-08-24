---
name: infrastructure-and-protocol
description: HTTP/2/3 protocol attacks, TLS/security-header audits, WebSocket transport issues, cache poisoning/deception, exposed container/orchestration surfaces (K8s/Docker), serverless misconfig, and log-poisoning-to-RCE. Converted from master-pentest-prompt.md Phase 12. Use during infrastructure-level recon on any target, especially ones fronted by a proxy/CDN or running on Kubernetes/serverless.
---

# Infrastructure & protocol

## When to use

Infrastructure-level testing on any target -- protocol behavior, TLS
config, caching layer, and container/orchestration exposure are worth
checking regardless of the application layer above them.

## Protocol-level

- HTTP/2 current attacks: downgrade, rapid reset, HPACK-related issues.
- HTTP/3/QUIC behaviors and proxy bypass.
- TLS: weak ciphers, full SSL Labs-style checks, missing HSTS, mixed
  content, certificate issues, CN/SAN mismatches.
- Security headers audit: CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP.
- WebSocket over `ws://` (insecure transport), missing auth on the
  upgrade.

## Cache

Cache key manipulation, cache poisoning, web cache deception (path
rules, appending `.css`/other static extensions to a dynamic endpoint so
the cache treats it as static), `PURGE` verb abuse.

## Container / orchestration exposure

- K8s/Docker: exposed `2375`/`6443`, privileged containers, exposed
  Docker socket, service-account token readable inside a pod, exposed
  dashboard, exposed `etcd` on `2379`.
- Serverless: Lambda environment variables, IAM role reuse, the
  Denonia-class of serverless-specific malware/misconfig patterns.

## Log poisoning

Log poisoning escalating to LFI, cron-based RCE, or exposure of
debug/admin consoles reachable through poisoned log content.
