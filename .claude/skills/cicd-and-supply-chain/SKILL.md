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

## Poisoned Pipeline Execution (PPE)

A workflow that runs untrusted code — a PR's own scripts or tests — with
access to repo secrets or write permissions. Direct PPE: attacker code
runs directly inside the privileged job. Indirect PPE: attacker-controlled
code runs via a config file or script the pipeline reads and trusts
without running it directly in the job definition.

## Runner compromise

A self-hosted runner (`runs-on: self-hosted`) that also accepts jobs
triggered by `pull_request` from forks is effectively an open RCE
target — any fork's PR can execute arbitrary code on that runner.

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
