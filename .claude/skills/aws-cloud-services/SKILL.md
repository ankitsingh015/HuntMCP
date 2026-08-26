---
name: aws-cloud-services
description: AWS-specific cloud attack surface -- IAM privilege-escalation paths from a leaked credential, S3 bucket misconfiguration beyond basic public-read, IMDSv2 SSRF bypass mechanics, Lambda function-URL and environment-variable exposure, API Gateway resource-policy/authorizer bypass, and STS cross-account role-assumption abuse. Use whenever a target is AWS-hosted (CloudFront/ALB hostnames, *.amazonaws.com references, an execute-api.*.amazonaws.com URL, a Lambda Function URL, or any AWS access key/secret found via secrets-mcp or JS mining) -- this is what to do once you have an AWS credential or AWS-fronted endpoint, not how to find one.
---

# AWS cloud services

## When to use

`information-disclosure` and `ssrf` already cover *finding* an AWS
credential or reaching the `169.254.169.254` metadata endpoint in the
first place -- this skill is what to do next, once you have a credential
(an access key pair, a vended STS token, an IMDS response) or you're
looking at an AWS-fronted endpoint (API Gateway, a Lambda Function URL,
an S3 bucket). Recognize an AWS-hosted target from: `*.amazonaws.com` in
DNS/JS/error messages, `X-Amz-*` response headers, CloudFront (`Server:
CloudFront` / `x-amz-cf-id` header) or ALB (`awselb/2.0` cookie) in front
of the app, an `execute-api.<region>.amazonaws.com` URL, or a
`*.lambda-url.<region>.on.aws` Function URL.

**A found access key is not the finding by itself** -- same principle as
`baas-security`'s Supabase/Firebase credentials. `aws sts
get-caller-identity` confirms a key is live; the actual severity is
whatever that key's IAM policy actually permits, which is what the rest
of this skill enumerates.

## IAM privilege escalation from any credential

Once any credential is live (`aws sts get-caller-identity` succeeds), the
next step is always the same regardless of how you got it: enumerate what
it can actually do, then check for an escalation path to something more
privileged. `aws iam get-user` / `aws iam list-attached-user-policies` /
`aws iam list-user-policies` (or the `-role` equivalents for an
assumed-role credential) if permitted; if `iam:Get*`/`iam:List*` itself is
denied, brute-force permission discovery by attempting the actions below
directly and reading the `AccessDenied` messages, which name the exact
action that was denied.

The privesc paths that show up most often in real engagements, roughly by
frequency:

- **`iam:PassRole` + a compute service that assumes it**: if the
  credential can `iam:PassRole` an existing role AND create a resource
  that assumes it, you inherit that role's permissions. Concretely:
  `lambda:CreateFunction` + `iam:PassRole` (create a function with a more
  privileged execution role, invoke it), `ec2:RunInstances` +
  `iam:PassRole` (launch an instance with a privileged instance profile,
  reach its credentials via IMDS once it's up), or
  `glue:CreateDevEndpoint`/`glue:UpdateDevEndpoint` + `iam:PassRole` (a
  Glue dev endpoint gives an SSH-reachable Python/Scala REPL running as
  the passed role). Check `iam:PassRole`'s own resource-level condition
  first -- it's frequently scoped to `iam:PassedToService` for exactly
  one service, which narrows which of these actually work.
- **`iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion`**: if the
  credential can create a new version of a policy already attached to
  itself (or to a role it can assume), set that new version to
  `{"Effect":"Allow","Action":"*","Resource":"*"}` and mark it default --
  full account admin from a single existing policy-management permission,
  no other resource needed.
- **`iam:AttachUserPolicy` / `iam:AttachRolePolicy` / `iam:AttachGroupPolicy`**:
  same end state, reached by attaching `AdministratorAccess` (or any
  more-privileged managed policy) directly to the current principal
  instead of editing an existing policy's version.
- **`iam:CreateAccessKey`**: if the credential can create access keys for
  another IAM user, mint a key for a known-more-privileged user directly
  -- a straight identity swap, not a policy edit.
- **`sts:AssumeRole` into an over-broadly-trusted role**: `aws iam
  list-roles` (or guess common role names -- `Admin`, `DevOps`,
  `CrossAccount*`, anything referencing a known SaaS vendor for a
  third-party-integration role) and check each role's trust policy
  (`AssumeRolePolicyDocument`) for a `Principal` that includes the
  current account/user with no `Condition` (especially a missing
  `sts:ExternalId` check on a cross-account trust -- the confused-deputy
  pattern: any AWS customer who knows or guesses the external ID can
  assume a role meant only for one specific SaaS vendor's own account).
- **Lambda-based escalation without `PassRole`**: `lambda:UpdateFunctionCode`
  against an *existing* function that already has a privileged execution
  role -- overwrite its code with something that exfiltrates its own
  environment's temporary credentials (available via the Lambda runtime's
  own metadata, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/
  `AWS_SESSION_TOKEN` env vars), then invoke it. No `PassRole` needed
  since the role is already attached to the function.
- **`ssm:SendCommand` / `ssm:StartSession`** against an EC2 instance with
  an attached instance profile -- Systems Manager access to a running
  instance is equivalent to code execution as that instance's IAM role,
  same end state as the `RunInstances` path above but against
  infrastructure that already exists.

`aws sts get-caller-identity` after every successful escalation step to
confirm the new effective identity before continuing -- don't assume a
policy edit succeeded just because the API call returned `200`.

## S3 bucket misconfiguration beyond public-read

`information-disclosure` covers the basic `curl
"https://TARGET.s3.amazonaws.com/?max-keys=10"` public-listing check.
Beyond that:

- **ACL and bucket policy are two independent, additively-OR'd
  mechanisms** -- a bucket can deny public access at the bucket-policy
  level while an individual object's ACL still grants
  `http://acs.amazonaws.com/groups/global/AllUsers` read, or vice versa.
  A bucket-level "no public access" finding doesn't rule out a
  specific object being independently public
  (`aws s3api get-object-acl --bucket <b> --key <k> --no-sign-request`).
- **Write access without read**: a bucket can allow anonymous `PutObject`
  while blocking `ListBucket`/`GetObject` -- this looks "safe" from a
  read-only probe but allows planting content. If the bucket is also
  configured for static website hosting
  (`GetBucketWebsite` succeeds, or the app serves content from
  `<bucket>.s3-website-<region>.amazonaws.com`), an anonymous write is a
  stored-XSS/defacement primitive on whatever origin serves that bucket.
- **Presigned URL scope creep**: a presigned URL is valid for exactly the
  object/method/expiry it was signed for -- but check whether the
  application's presigning logic actually constrains the *key* the client
  can request a signature for (a common bug: the server presigns
  whatever `key` parameter the client sends, with no ownership check,
  letting one user get a presigned PUT for another user's object path).
- **Bucket takeover via dangling reference**: distinct from
  `subdomain-takeover`'s DNS-CNAME mechanism -- here the dangling
  reference is inside application config/JS (`s3.amazonaws.com/<old-bucket-name>`
  hardcoded as an asset host) rather than DNS. If the referenced bucket
  no longer exists, creating it under your own account (bucket names are
  globally unique and first-come) lets you serve content at that
  already-trusted URL.
- **Versioning/replication as a data-leak vector**: if versioning is
  enabled and an old, since-"deleted" object version is still readable
  (`GetObjectVersion` with the version ID present in an old JS bundle,
  Wayback Machine snapshot, or API response), a "delete" the developer
  believed removed sensitive data may not have -- only a delete marker
  was added, the prior version persists.

## IMDS SSRF -- IMDSv2 hardening and its actual bypass conditions

`ssrf` already flags `169.254.169.254` as the target and notes "IMDSv2
header-bypass techniques" in passing -- the mechanics:

- **IMDSv1** answers a plain `GET` with no headers -- if reachable at
  all via SSRF, credentials are one request away
  (`GET /latest/meta-data/iam/security-credentials/<role-name>`, role
  name from the parent-less `GET .../security-credentials/`).
- **IMDSv2 requires a session token**: `PUT
  http://169.254.169.254/latest/api/token` with header
  `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then that token as
  `X-aws-ec2-metadata-token` on the actual metadata `GET`. This is
  specifically designed to defeat classic SSRF, because most SSRF
  primitives (URL-fetcher, image-from-URL, webhook, PDF-generator) only
  let the attacker control the target URL, not the HTTP method or
  add arbitrary headers -- a GET-only SSRF genuinely cannot complete the
  IMDSv2 handshake.
- **Where IMDSv2 doesn't actually help**: (1) if the SSRF primitive is a
  full request-forging one (an XXE-based SSRF using `<!ENTITY % xxe SYSTEM
  ...>` chained through a protocol handler, or any SSRF where the
  attacker's payload is itself raw HTTP, e.g. via CRLF injection into the
  request) that can send a `PUT` with a custom header, the token dance
  completes fine; (2) many EC2 instances are launched with `HttpTokens`
  still set to `optional` (IMDSv1 still simultaneously accepted) rather
  than `required` -- always try the plain IMDSv1 `GET` first, since it's
  strictly less request-shape-dependent and a large fraction of
  real-world instances haven't been hardened; (3) a redirect-following
  SSRF (server-side fetch that follows `3xx`) can sometimes be walked from
  an attacker-controlled initial URL through a redirect chain that ends at
  the metadata IP with a method the fetcher preserves across the
  redirect -- worth testing even when the metadata IP itself isn't
  directly reachable as the first hop.
- **ECS task role metadata is a different endpoint**: containers running
  under ECS don't use `169.254.169.254` for task-role credentials --
  the URI is in the `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` environment
  variable, fetched against `169.254.170.2<that-path>`. If SSRF lands
  inside an ECS-hosted container rather than a raw EC2 instance, check
  for that env var (via a separate info-disclosure/RCE primitive, not
  SSRF itself) before assuming the classic `169.254.169.254` IMDS path
  applies.

## Lambda-specific attack surface

- **Function URLs** (`https://<url-id>.lambda-url.<region>.on.aws/`) can
  be configured with `AuthType: NONE` -- a Lambda meant for
  internal/API-Gateway-only invocation, given a Function URL for
  convenience during development and left with no auth, is directly
  internet-invokable. Check the function's actual logic for what
  privilege that invocation carries (does it perform actions as its
  execution role with no further authorization check of its own?).
- **Environment variables as a secrets store**: `lambda:GetFunctionConfiguration`
  (or `GetFunction`) returns a function's environment variables in
  plaintext unless they're specifically KMS-encrypted with the "encrypt
  at rest" option *and* the caller lacks `kms:Decrypt` on that key --
  many teams set env vars with real API keys/DB passwords assuming IAM
  alone protects them, not realizing any principal with
  `lambda:GetFunctionConfiguration` reads them directly.
- **Event-source injection through API Gateway proxy integration**: when
  API Gateway is configured as a `AWS_PROXY` integration, the entire raw
  request (headers, query string, body) is passed through to the
  Lambda's `event` object largely unvalidated at the gateway layer --
  standard injection classes (`injection-and-rce`, `ssrf`) apply directly
  inside the function's own parsing of `event['headers']`/`event['queryStringParameters']`,
  and a function that trusts `event['headers']['X-Forwarded-For']` or
  similar for authorization logic is spoofable by any caller.

## API Gateway

- **Resource policy vs. Lambda authorizer are separate gates**: a
  resource policy can restrict which source IPs/VPCs/AWS accounts may
  invoke a stage at all, independent of whatever custom/Lambda
  authorizer validates the caller's identity -- test both layers
  separately; a misconfigured resource policy (e.g. `"Principal": "*"`
  with no `Condition`) can expose a stage that the authorizer alone was
  relied on to protect.
- **Stage variables in the integration URI**: `${stageVariables.foo}`
  substitution inside a backend integration URI, if a stage variable's
  value is influenceable by a caller-controlled header/path parameter
  the gateway maps into it, is an SSRF-via-configuration primitive
  distinct from application-level SSRF.
- **Custom authorizer caching**: API Gateway can cache a Lambda
  authorizer's decision by the configured identity source (commonly just
  the `Authorization` header) for up to an hour -- if the authorizer's
  policy changed (e.g. a user's role downgraded, a token revoked) the
  cached `Allow` can outlive the change; worth checking for a
  permission-persists-after-revocation window if the identity source and
  caching TTL are known or guessable from response timing.

## RDS / DynamoDB / other datastores reachable directly

Same category as `information-disclosure`'s generic Mongo/Redis/
Elasticsearch exposure checks, AWS-specific instances:

- **RDS with a public endpoint and a default/weak master credential**
  found via the same secrets-scanning/JS-mining paths as any other DB
  credential -- `mysql`/`psql` connect directly to the
  `*.rds.amazonaws.com` hostname if the security group allows the
  testing source IP.
- **DynamoDB with an overly-broad IAM policy on a found credential**:
  `dynamodb:Scan` on every table the credential's policy allows (`aws
  dynamodb list-tables` then `scan` each) is frequently missed because
  DynamoDB doesn't have an equivalent to "public bucket" -- the entire
  exposure surface is IAM policy scope, so this folds into the IAM
  enumeration above rather than being a separate network-level check.
- **ElastiCache/OpenSearch/Neptune** reachable on their default ports
  from outside the VPC (rare, but occurs when a security group is
  mistakenly opened to `0.0.0.0/0` instead of a VPC CIDR) -- a plain port
  scan against the target's known IP ranges catches this; no
  authentication exists on many of these by default.

## Related skills

- `information-disclosure` -- generic cloud-metadata/datastore exposure
  detection and the Cognito credential-vending chain; this skill
  specializes what to do once an AWS credential is confirmed live.
- `ssrf` -- the general SSRF injection-point list and basic
  `169.254.169.254` targeting; this skill's IMDS section is the deeper
  IMDSv2-specific mechanics.
- `cicd-and-supply-chain` -- `configure-aws-credentials`/OIDC
  trust-policy abuse and exposed Terraform state overlap directly with
  this skill's STS cross-account and IAM-escalation sections.
- `kubernetes-and-container-security` -- for an EKS target specifically,
  combine that skill's generic K8s RBAC/pod-escape coverage with this
  skill's IAM-privesc paths (EKS pods commonly assume IAM roles via
  IRSA, so a pod-escape finding there often chains directly into IAM
  enumeration here).
- `access-control-and-idor` -- presigned-URL scope-creep and DynamoDB
  cross-tenant exposure are instances of the same broken-authorization
  taxonomy, enforced via AWS-specific mechanisms instead of application
  code.
