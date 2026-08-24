---
name: request-smuggling
description: HTTP request smuggling and desync technique list, including the 2025-26 "HTTP/1.1 must die" desync-endgame classes (0.CL, CL.0, H2.TE, TE.TE chunk extensions, response queue poisoning, dangling-byte, browser-powered desyncs). Converted from master-pentest-prompt.md Phase 4. Use when a target sits behind a reverse proxy/CDN/load balancer and front-end/back-end parsing discrepancies are worth probing.
---

# HTTP request smuggling / desync

## When to use

Any target behind a reverse proxy, CDN, or load balancer -- the entire
category depends on a front-end/back-end parser discrepancy existing,
which is common in exactly that architecture. Worth a dedicated pass
whenever `httpx-mcp`'s recon shows a CDN/proxy signature (`CF-RAY`,
`X-Served-By`, etc.).

## Core techniques

- CL.TE, TE.CL, TE.TE, H2.CL, H2.TE downgrade smuggling.
- Front-end/back-end parser discrepancy detection.
- Client-side desync (CSD) -- browser-level poisoning.
- Response queue poisoning (steal victim responses).
- CRLF in HTTP/2 header values (request splitting, CVE-2025-57804-class).
- Chained: smuggling -> cache poisoning -> stored XSS served to all
  users.
- Tools: Burp HTTP Request Smuggler v3.0 (Kettle), Turbo Intruder, Param
  Miner.

## 2025-26 desync-endgame classes (Kettle, "HTTP/1.1 must die")

- **0.CL desync**: a request with zero body before Content-Length, plus
  the obfuscated `Expect` variant.
- **CL.0** (Content-Length without Transfer-Encoding) via `Expect`
  header, HEAD gadget, or 403-triggered CL.0.
- **V-H discrepancy**: verify hops, defer to Host; **H-V**: trust Host,
  verify.
- **H2.TE** (HTTP/2 -> HTTP/1.1 Transfer-Encoding conversion) and
  **TE.0** dechunking.
- **TE.TE chunk extensions** (obfuscating transfer-encoding).
- **Exotic desync triggers**: `Transfer-Encoding: gzip`,
  `multipart/byteranges`, `Range: ,,` (comma), `Expect:\t100-continue`,
  `Upgrade: websocket`, `CONNECT`, `Max-Forwards: 0`, `Early-data: 1`
  (TLS 1.3 early-data smuggling).
- **Response Queue Poisoning (RQP)**: poison the shared HTTP/1.1 queue.
- **Dangling-byte technique**: a single trailing byte, race-free, fully
  reliable.
- **CRLF-powered desync**: behead HTTP streams, desync worms
  (browser-compatible, self-replicating, no server cooperation needed),
  request splitting.
- **Browser-powered desyncs** (fetch-compatible), connection-locked and
  IP-locked desyncs (use same-IP hosts to beat locking).
- **HTTP request tunnelling**: blind desync into back-end tunnels.
- **Range Cache Poisoning + HEAD gadget**: poison the cache of
  HEAD-only resources.
- **Automated discovery**: HTTP Request Smuggler v3.0 / HTTP Terminator
  (Kettle/PortSwigger) for novel-class discovery on any target.

## Working order

Start with single-request variants (no race needed), then move to RQP
(targeted: send one queued victim request, observe queue replay).
