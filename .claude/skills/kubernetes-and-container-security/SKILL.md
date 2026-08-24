---
name: kubernetes-and-container-security
description: Kubernetes-specific attack techniques -- anonymous API server access, RBAC misconfiguration, pod escape via privileged/hostPath/hostNetwork/mounted Docker socket, kubelet API abuse, etcd exposure, service-account token theft, ingress/admission-controller misconfiguration, container-runtime escape CVEs, and exposed registries. Converted from master-pentest-prompt.md Phase 39 (new -- not in the original 59-phase set, added from research into currently-uncovered high-value bounty classes). Use once a target is confirmed Kubernetes-based (API server, kubelet, or etcd port reachable), as deeper coverage beyond the general Docker-port checklist.
---

# Kubernetes & container security

## When to use

A Kubernetes API server, kubelet, or container-runtime socket is
reachable, or recon shows Kubernetes-specific ports (6443 for the API
server, 10250 for the kubelet, 2379/2380 for etcd). Distinct from the
general Docker-port exposure checklist already in the
`infrastructure-and-protocol` skill — this is K8s-specific depth for
once that general checklist has confirmed Kubernetes is actually in
play, not a replacement for it.

## Anonymous API server access

Try `kubectl` or a raw `curl` against `:6443`/`:443` with no credentials
at all. A meaningful number of real clusters still allow at least
read-level anonymous access, which alone can leak the entire cluster
topology.

## RBAC misconfiguration

Every pod gets a ServiceAccount token mounted by default unless
explicitly disabled — once inside any container, check what that
mounted token can actually do (`kubectl auth can-i --list` using the
pod's own token). An over-permissioned ServiceAccount granting more than
the workload actually needs is the single most common K8s privilege-
escalation path.

## Pod escape

Any of the following gives a path from container compromise to node
compromise: `securityContext.privileged: true`, a `hostPath` mount to a
sensitive host directory, `hostNetwork`/`hostPID` enabled, or a mounted
Docker/containerd socket inside the pod.

## kubelet API abuse

An exposed, unauthenticated kubelet API on port 10250 lets an attacker
run arbitrary commands inside any pod scheduled on that node via its
exec/run endpoints — no access to the cluster API server required at
all, a direct node-level compromise path.

## etcd exposure

An unauthenticated etcd (port 2379) is effectively the entire cluster's
secrets store, readable directly. Don't assume Kubernetes Secrets are
protected by default — they're only base64-encoded, not encrypted,
unless encryption-at-rest is explicitly configured, so etcd access is
equivalent to reading every Secret in the cluster in plaintext.

## Service account token theft

A token exfiltrated from one compromised pod can be replayed directly
against the API server to enumerate or access resources far beyond that
pod's own namespace, if RBAC bindings are loose enough.

## Ingress / admission-controller misconfiguration

An Ingress rule that unintentionally exposes an internal-only Service to
the public internet, or an admission webhook configured to fail open
(allow the request through) when the webhook itself is unreachable —
turning an availability problem into a bypassed security control.

## Container-runtime escape CVEs

Check the runtime version (`runc`, `containerd`, `CRI-O`) against known
container-escape CVEs (e.g. CVE-2019-5736) rather than assuming
containerization itself is a hard security boundary.

## Registry exposure

An exposed, unauthenticated container registry lets an attacker pull
private images (which frequently bake in secrets across their layers)
or push a poisoned image that an unattended CI/CD pipeline later
deploys — see the `cicd-and-supply-chain` skill for the pipeline side of
that specific chain.
