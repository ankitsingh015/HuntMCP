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

## Enumerating your own effective RBAC (`SelfSubjectRulesReview`)

`kubectl auth can-i --list` is a convenience wrapper — the actual API
primitive it calls is `SelfSubjectRulesReview`
(`POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews`), and
it's the correct way to enumerate what a token can do before
attempting any privesc, since a `200` on a `list`/`get` call can return
an RBAC-filtered empty result rather than proof of access. Pass the
pod's own namespace in the request body and read the returned
`resourceRules`/`nonResourceRules` for the verbs that actually matter
(`create`/`patch` on `pods`, `secrets`, `pods/exec`, `nodes/proxy`)
rather than assuming a `200` response means broad access. For a single
targeted check instead of the full rule list,
`SelfSubjectAccessReview` answers "can I do this one specific
verb/resource" directly. Don't claim privilege escalation from an
anonymous `200` alone — confirm it against one of these two APIs
first, then prove it by actually reading a Secret or creating the
resource.

## Pod escape

Any of the following gives a path from container compromise to node
compromise: `securityContext.privileged: true`, a `hostPath` mount to a
sensitive host directory, `hostNetwork`/`hostPID` enabled, or a mounted
Docker/containerd socket inside the pod.

## Docker-socket and capability-based container escape

Beyond the general "mounted Docker/containerd socket" note above, the
concrete escape from inside a container follows a small number of
repeatable techniques. A mounted `/var/run/docker.sock` (check with
`ls -la /var/run/docker.sock`, or reach it via SSRF/LFI if it's exposed
indirectly) gives full Docker Engine API access from inside the
container — create a new container with `HostConfig.Binds` mapping the
host's `/` into the new container and `Privileged: true`, start it, and
read/write anything on the host filesystem through the mount
(`docker run --rm --privileged -v /:/host alpine chroot /host`). Docker
group membership (`id | grep docker`) is equivalent to this even
without the socket already mounted, since group members can talk to
the socket directly. Detect an already-`--privileged` container by
attempting a host-only operation a normal container can't do, such as
`ip link add dummy0 type dummy` succeeding, or by checking `CapEff` in
`/proc/self/status` for capabilities a default container shouldn't
have. `CAP_SYS_ADMIN` specifically enables the cgroups v1
`release_agent` escape (CVE-2022-0492): a container holding that
capability can mount cgroupfs and write a `release_agent` script that
the host executes outside the container's namespace on the next cgroup
event, without needing `--privileged` or the socket at all. Confirm
impact by reading a host-only artifact (the node's `/etc/hostname`,
distinct from the container's own) rather than inferring escape from
capability presence alone.

## kubelet API abuse

An exposed, unauthenticated kubelet API on port 10250 lets an attacker
run arbitrary commands inside any pod scheduled on that node via its
exec/run endpoints — no access to the cluster API server required at
all, a direct node-level compromise path.

## Kubelet exec mechanics: `/run` vs `/exec`

The kubelet's two command-execution endpoints on port 10250 are not
interchangeable and don't behave the same under a plain `curl`.
`/run/<namespace>/<pod>/<container>` (`POST` with a `cmd=` body param)
returns command output directly in the response body — the simple
primitive, and the one to try first. `/exec/<namespace>/<pod>/<container>`
is a SPDY/WebSocket *streaming* endpoint: a plain `POST` to it returns a
`302` redirect to a stream location rather than command output, and
that stream has to be read with a SPDY3.1/WebSocket-capable client
(`kubeletctl`, or `websocat`/`wscat` against the `Location` header's
path) before any output appears. A bare POST to `/exec` that comes back
empty is not proof the kubelet is patched — it means the stream was
never followed. Also distinct: read-only port 10255 (`/pods`, `/stats`,
`/metrics`) has no exec/run capability at all and is
information-disclosure only — don't conflate a 10255 hit with kubelet
RCE.

## API-server-mediated kubelet RCE via `nodes/proxy`

When 10250 itself is firewalled off but a held token (even a
low-privileged pod ServiceAccount token) is bound to a role granting
the `nodes/proxy` subresource, the same kubelet `/run` primitive is
reachable indirectly through the API server:
`POST /api/v1/nodes/<node>/proxy/run/<namespace>/<pod>/<container>`
with `cmd=` in the body, authenticated with
`Authorization: Bearer <token>` against the API server (port 6443/443)
rather than the kubelet directly. Command output comes back in the
response the same way `/run` does. `nodes/proxy` granted in any RBAC
binding is effectively node-wide RCE for whoever holds that token, and
it's a materially different exposure than direct kubelet access since
it only requires API-server reachability plus an over-permissioned
role — check for it explicitly during RBAC enumeration rather than
assuming `nodes/proxy` is a low-risk verb.

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

## Runc working-directory breakout (CVE-2024-21626, "Leaky Vessels")

A specific, currently-relevant addition to the runtime-escape CVE list
above: CVE-2024-21626 affects runc <= 1.1.11 and stems from a leaked
host file descriptor exposed at `/proc/self/fd/<n>` during container
startup. A malicious image that sets its `WORKDIR` (or a `runc exec`
call that sets its working directory) to that leaked fd path breaks
out of the container's filesystem view into the host's, because
working-directory resolution follows the fd rather than staying jailed
inside the container root — yielding host filesystem access without
needing a privileged container or any capability grant. This only
applies where an attacker controls the image or exec target (a CI/CD
pipeline that builds and runs untrusted third-party images, or a
shared multi-tenant build system), so gate this against the actual
runc version before claiming it — version alone is a lead, the escape
output is the proof.

## Registry exposure

An exposed, unauthenticated container registry lets an attacker pull
private images (which frequently bake in secrets across their layers)
or push a poisoned image that an unattended CI/CD pipeline later
deploys — see the `cicd-and-supply-chain` skill for the pipeline side of
that specific chain.
