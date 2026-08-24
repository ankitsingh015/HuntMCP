---
name: information-disclosure
description: Version-control and backup exposure (.git/.svn/.hg dumps), API/debug endpoint leaks (Swagger, source maps, actuator heapdumps), cloud metadata and datastore exposure (AWS/GCP/Firebase/Mongo/Redis/Elasticsearch), secrets scanning, and user/UUID enumeration oracles. Converted from master-pentest-prompt.md Phase 13. Use during recon and throughout the engagement whenever a new endpoint or exposed path is found.
---

# Information disclosure

## When to use

Recon-time and continuously -- new endpoints found in later phases are
worth re-checking against this list, not just the initial pass.

## Exposed source / version control

`.git`/`.svn`/`.hg` exposure (git-dumper-style reconstruction), exposed
`.env`, backup files, old/forgotten deployments left reachable.

## API and debug surfaces

Swagger/OpenAPI docs, JS source maps, Spring Boot Actuator heapdumps
(`/actuator/heapdump` alongside `/env`), debug endpoints, stack traces,
verbose error messages.

## Cloud and datastore exposure

AWS metadata endpoint, GCP service-account credentials/cloud functions,
Firebase read access, open Firestore rules, exposed Mongo/Redis/
Elasticsearch instances with no auth.

## Secrets

TruffleHog-style scanning of public repos, S3 object enumeration, JS
credential scanning for `aws:Cognito`, `google:apiKey`, `sentry:dns`,
Firebase config -- `secrets-mcp` automates the local-file version of this
scan once files are downloaded.

## Enumeration oracles

- **User enumeration**: login timing differences, different response
  bodies, forgot-password message differences between valid and invalid
  accounts.
- **UUID/GUID enumeration**: prediction via date-based or base64-encoded
  generation patterns rather than assuming UUIDs are unguessable.
