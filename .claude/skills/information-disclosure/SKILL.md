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

Prometheus `/metrics` (plus `/actuator/prometheus` on Spring Boot) is
commonly left unauthenticated on Go/Java/Node/.NET backends and leaks the
entire operational profile, not just app data: grep the text-format output
for `ai_`/`model`/`llm` metric families to see which AI models are in use
and at what volume, `db_pool`/`connection` gauges for connection-pool
exhaustion risk, and `circuit_breaker_state{client=...}` for third-party
dependency health (Stripe, SendGrid, etc). Metric labels sometimes carry
tenant-identifying values (customer/org IDs), turning an operational leak
into a data leak.

## Cloud and datastore exposure

AWS metadata endpoint, GCP service-account credentials/cloud functions,
Firebase read access, open Firestore rules, exposed Mongo/Redis/
Elasticsearch instances with no auth.

Concrete probes: `curl "https://TARGET-NAME.s3.amazonaws.com/?max-keys=10"`
and `aws s3 ls s3://bucket-name --no-sign-request` for S3 listing, swept
across common bucket-name permutations (`target`, `target-backup`,
`target-prod`, `target-staging`, `target-assets`); `curl
"https://TARGET-APP.firebaseio.com/.json"` for a Firebase Realtime
Database read, and a `PUT` to the same URL to check for open write rules.

**Cognito Identity Pool "credential-vending" chain**: AWS CloudWatch RUM's
client-side telemetry snippet embeds a public `identityPoolId` and
`guestRoleArn` by design -- grep JS bundles for `identityPoolId`,
`guestRoleArn`, or a `cwr('init', ...)`/`new AwsRum(...)` call. If the
Cognito Identity Pool's unauthenticated (guest) role is scoped wider than
the documented minimum (`rum:PutRumEvents` only), anyone can turn the
public pool ID into real, usable AWS credentials with zero authentication:

```bash
aws cognito-identity get-id --identity-pool-id "us-east-1:abcd1234-..." \
  --region us-east-1 --no-sign-request
aws cognito-identity get-credentials-for-identity \
  --identity-id "<returned-id>" --region us-east-1 --no-sign-request
aws sts get-caller-identity   # confirm the vended role before enumerating further
```

A misconfigured Cognito Identity Pool tied to a public RUM app monitor is
the whole finding -- see below for what to enumerate once you have
credentials in hand.

**Post-credential privilege escalation**: any leaked or vended cloud
credential (SA key, IAM access key, Cognito guest creds) is step one, not
the finding -- enumerate what it can actually do before moving on.
`iam:PassRole` paired with a privileged Lambda function or EC2 instance
profile lets a low-privilege identity hand a powerful role to a resource
it controls; an over-permissioned instance profile attached to a
compromised function is a direct escalation path. On GCP, exchange a
service-account key for an access token and check `getIamPolicy` for
`roles/owner`/`roles/editor` bindings on the project. On Azure, check the
role assignments on whatever managed identity the credential belongs to.
Tools like `enumerate-iam`/Pacu automate this permission enumeration once
`aws sts get-caller-identity` confirms the credential is live.

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

## NTLM Type-2 challenge disclosure

Any endpoint that offers `WWW-Authenticate: NTLM`/`Negotiate` to an
anonymous request -- not just Exchange/OWA (see the Exchange-specific
`X-OWA-Version`/CVE-matching version of this in `cms-and-framework-specific`)
but IIS generally, SharePoint (`/_api/web/CurrentUser`, `/_vti_bin/*.asmx`),
VPN/SSO gateways, WSUS, and Tomcat-behind-IIS -- leaks internal Active
Directory topology with zero credentials and zero shell. Send a standard
NTLMSSP Type-1 Negotiate message over a keep-alive connection (one-shot
`curl`/`requests` calls usually close before the Type-2 arrives; use raw
sockets or Burp Repeater with `Connection: keep-alive`):

```
Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
```

Base64-decode the `WWW-Authenticate: NTLM <base64>` Type-2 response and
parse the `TargetInfo` `AV_PAIRS` (per MS-NLMP): AvId `2` = NetBIOS domain,
`4` = DNS domain, `5` = DNS forest/tree name, `3`/`1` = computer name, `7`
= server timestamp. A default `WIN-XXXXXXXXXXX` hostname signals lazy
provisioning; a DNS Tree Name like `customer.parent-corp.example` reveals
the target is a child domain inside a larger corporate AD forest rather
than an isolated tenant. Usually Low/Informational on its own -- the value
is in feeding the disclosed UPN format and domain name into a credential-
spray or auth-bypass chain.
