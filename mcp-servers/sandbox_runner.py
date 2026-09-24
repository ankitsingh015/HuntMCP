"""S5 (IMPLEMENTATION-TASK-TRACKER.md): rootless per-run execution boundary
for the Tier-2 tool binaries tool_resolver.run_tool()/job_runtime.start_job()
invoke, via rootless Podman containers.

## What this provides (V1)

Per run (one external tool-binary execution attempt -- one call to
run_tool(), one call to start_job(), or one independent retry attempt
inside run_tool()'s own rate-limit retry): a freshly created, ephemeral
(`--rm`) container with no Linux capabilities, a read-only root filesystem,
no new-privilege escalation, resource caps (pids/memory), and exactly one
mount -- a fresh scratch directory unique to that run. The container's
environment is built from the SAME allowlist tool_resolver.minimal_subprocess_env()
already uses (imported, not re-implemented) -- nothing else is ever passed
in, and nothing from the host filesystem is ever mounted beyond that one
scratch directory (no repo root, no $HOME, no .env, no engagement
directory).

This is a SECOND, independent enforcement layer on top of S3's existing
env-scrub -- even if S3's host-side scrub were ever bypassed, a sandboxed
process still has no filesystem path to a host credential, because none
is ever mounted.

## What this does NOT provide (V1) -- read before assuming otherwise

**No per-target network egress ACL.** Containers use rootless Podman's
default user-mode networking (slirp4netns) and can reach any network
destination the host's own networking allows -- required, since every one
of these tools has to reach a real target over the internet to do its job.
Building a custom per-destination network policy (a dedicated CNI plugin,
iptables rules keyed to the active engagement's scope) is explicitly OUT
OF SCOPE for S5 V1 -- it would be new network-control-plane infrastructure,
which IMPLEMENTATION-TASK-TRACKER.md's own Tier-2 discipline lists as a
non-goal ("must not metastasize into platform engineering").

scripts/hooks/scope_gate_hook.py's PreToolUse check is what enforces "may
this call touch this host at all" -- it runs BEFORE this module is ever
invoked, is architecturally separate from it, and is NOT superseded or
duplicated by anything here. Do not describe this module as providing
network-level scope enforcement; it doesn't.

## Tool allowlist, not arbitrary execution

run_sandboxed()/build_argv() only ever run a binary looked up by exact
logical name in _TOOL_MAP below -- an unrecognized name raises
UnknownSandboxTool immediately, before any subprocess is attempted. There
is no code path that accepts an arbitrary host path/binary name and runs
it in the sandbox; every tool this image can execute is named here,
explicitly, matching what's actually baked into the image built from
mcp-servers/sandbox/Dockerfile.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import uuid

# Deliberately does NOT import tool_resolver (which imports this module to
# sandbox run_tool()'s own execution) -- that would be a circular import.
# Callers (tool_resolver.run_tool(), job_runtime.start_job()) already
# compute tool_resolver.minimal_subprocess_env() themselves and must pass
# it in explicitly via build_argv()'s `env` parameter.

# Bump this only alongside a corresponding, deliberate
# mcp-servers/sandbox/Dockerfile version/tag change -- never silently.
SANDBOX_IMAGE = "localhost/huntmcp-sandbox:2026-09-15"

# In-container path for each approved logical tool name. Impacket's
# ad-recon-mcp callers resolve to one of 3 possible on-host binary names
# depending on how impacket was installed there (pip console-script vs a
# raw .py invocation) -- all 3 map to the SAME in-container script, since
# they're the same underlying tool.
_TOOL_MAP: dict[str, str] = {
    "subfinder": "/opt/tools/subfinder",
    "httpx": "/opt/tools/httpx",
    "katana": "/opt/tools/katana",
    "nuclei": "/opt/tools/nuclei",
    "ffuf": "/opt/tools/ffuf",
    "dalfox": "/opt/tools/dalfox",
    "gitleaks": "/opt/tools/gitleaks",
    "nmap": "/usr/bin/nmap",
    "curl": "/usr/bin/curl",
    "wget": "/usr/bin/wget",
    "sqlmap": "/usr/local/bin/sqlmap",
    "impacket-getuserspns": "/usr/local/bin/GetUserSPNs.py",
    "impacket-GetUserSPNs": "/usr/local/bin/GetUserSPNs.py",
    "GetUserSPNs.py": "/usr/local/bin/GetUserSPNs.py",
    "impacket-getnpusers": "/usr/local/bin/GetNPUsers.py",
    "impacket-GetNPUsers": "/usr/local/bin/GetNPUsers.py",
    "GetNPUsers.py": "/usr/local/bin/GetNPUsers.py",
}

# Every container this module launches carries this label -- informational/
# discoverability only (e.g. `podman ps --filter label=...` for a human to
# see what's sandboxed right now). NOT used for any bulk cleanup: an
# earlier version of this module had a reap_orphans() that swept and
# force-removed every container matching this label, which is unsafe by
# construction -- confirmed live: a container survives a SIGKILL to its
# `podman run` wrapper process (conmon keeps supervising it independently;
# it shows "Up N seconds", i.e. still RUNNING, indefinitely, never
# "exited") indistinguishably from a container belonging to a completely
# different, healthy, concurrent run that merely shares the same generic
# label. A bulk sweep filtered on label+"still running" cannot tell those
# apart, and status=exited never matches the actual orphan case at all --
# it would either kill an unrelated in-progress scan or silently reap
# nothing, depending on which filter was used. See remove_container()
# below for the actual, precise, per-run mechanism this uses instead.
_CONTAINER_LABEL = "huntmcp-sandbox=1"

WORKDIR_IN_CONTAINER = "/workspace"

# Must be a path that is actually WRITABLE inside the container. It is
# deliberately NOT the Dockerfile's `useradd -m` home (/home/sandboxuser,
# uid 10001): the container runs --read-only together with
# --userns=keep-id (see build_argv()), which remaps the container's
# effective uid to the invoking host uid, so the image-owned
# /home/sandboxuser is not writable by the process at all. Every
# ProjectDiscovery tool creates $HOME/.config/<tool>/ on startup and dies
# without it -- confirmed live on this engagement (2026-09-17): katana
# failed even on `katana -version` with `Could not read flags ... no such
# file or directory`, subfinder with `open .../.config/subfinder/config.yaml:
# no such file or directory`, nuclei with `failed to create config
# directory`, ffuf with `open .../.config/ffuf/scraper`.
# /tmp is a container-private, size-capped, ephemeral tmpfs (see the
# --tmpfs=/tmp flag in build_argv()) -- writable, and unlike a $HOME mount
# it exposes no host path whatsoever.
CONTAINER_HOME = "/tmp"


class UnknownSandboxTool(Exception):
    """Raised when a caller asks to sandbox-run a tool name not present in
    _TOOL_MAP -- fail closed rather than ever guessing at an arbitrary
    host path to execute inside the sandbox."""


class UnsafeBenchNetwork(Exception):
    """Raised when HUNTMCP_BENCH_NETWORK is set to a value that doesn't
    match SandboxedBenchApp's own generated-name convention (see
    build_argv()'s own comment on this variable). Defense in depth: this
    variable is never agent- or target-controlled, but a stray/typo'd/
    leftover-debug value of "host" (or Podman's other special values --
    none/bridge/container:x) would otherwise silently grant every
    subsequent real Tier-2 tool call in that process full host
    networking, defeating S5 entirely -- fail closed rather than splice
    an unvalidated value into --network=."""


class UnsafeSandboxMount(Exception):
    """Raised when a path that would be auto-mounted (see
    _detect_path_mounts) resolves to something dangerously broad. Every
    path considered here originates from this codebase's OWN MCP-server
    call sites (never from attacker-controlled target data), so this is a
    backstop against a future caller passing something too broad by
    mistake, not a defense against a hostile argument."""


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# System directories where NOTHING legitimate should ever be mounted from --
# prefix-denied, so a path anywhere under one of these is refused. Deliberately
# does NOT include /home or /root: see _DENY_MOUNT_EXACT below for why those
# two need narrower treatment.
_DENY_MOUNT_PREFIXES = {"/", "/etc", "/usr", "/var", "/boot", "/bin", "/sbin"}

# Denied only as an EXACT match, never as a prefix -- every real
# per-engagement scratch/output directory legitimately lives deep under
# $HOME and the repo root on an ordinary single-user dev machine (found
# live: sqlmap-mcp's real _output_dir() resolves to
# .../HuntMCP/data/engagements/<slug>/tmp-sqlmap/<job>, which IS under
# both $HOME and the repo root -- a prefix-deny on either blocked every
# real sqlmap call on this exact, ordinary, non-broad path). Mounting
# $HOME, /home, /root, or the repo root WHOLESALE would still be too
# broad, so each stays denied as its own exact entry; a narrow
# subdirectory deep inside any of them is exactly the kind of
# purpose-built path this mechanism exists to allow instead of blocking.
_DENY_MOUNT_EXACT = {os.path.expanduser("~"), _REPO_ROOT, "/home", "/root"}


def _validate_mount_path(path: str) -> str:
    """Resolve `path` and raise UnsafeSandboxMount if it's dangerously
    broad. Callers must pass this only paths THEY explicitly, deliberately
    chose to share with the sandbox (see build_argv()'s `extra_mounts` and
    `cwd` params) -- never a path scraped generically out of a tool's own
    argument list.

    An earlier version of this module auto-detected ANY existing absolute
    path already present as a literal argument and mounted it -- found in
    review to be a real security hole: ffuf-mcp's `wordlist` MCP parameter
    is agent-chosen and passed through unvalidated
    (mcp-servers/ffuf-mcp/server.py's _resolve_wordlist: any string
    starting with "/" is returned as-is), so a target that steers the
    calling agent via prompt injection into passing e.g.
    wordlist="/home/<user>/.ssh/id_rsa" would have had that file
    bind-mounted read-write AND permanently chmod'd more permissive on the
    host (see _ensure_group_accessible) -- entirely automatically, no
    container escape needed. Requiring every mount to be an explicit,
    named choice by this codebase's OWN calling code (never a value taken
    directly from an agent-facing tool parameter) closes that: a caller
    that WANTS to mount something must say so specifically, at a specific
    call site that can be reviewed for exactly this risk."""
    resolved = os.path.realpath(path)
    if resolved in _DENY_MOUNT_EXACT:
        raise UnsafeSandboxMount(
            f"Refusing to mount {path!r} into the sandbox -- mounting it "
            f"WHOLESALE is too broad, even though a subdirectory of it is "
            f"fine. This should never happen from this codebase's own "
            f"call sites; check the caller."
        )
    for prefix in _DENY_MOUNT_PREFIXES:
        # "/" itself needs its own exact check -- prefix.rstrip("/") is ""
        # for it, and resolved.startswith("" + "/") matches EVERY absolute
        # path (found live: this blocked a completely ordinary /tmp/...
        # scratch dir before this fix).
        prefix_stripped = prefix.rstrip("/")
        is_denied = (
            resolved == prefix
            or (prefix_stripped and resolved.startswith(prefix_stripped + "/"))
        )
        if is_denied:
            raise UnsafeSandboxMount(
                f"Refusing to mount {path!r} (resolves under {prefix!r}) into "
                f"the sandbox -- too broad. This should never happen from "
                f"this codebase's own call sites; check the caller."
            )
    return resolved


def _ensure_group_accessible(path: str) -> None:
    """Add owner+group rwx (dirs) or rw (files) to `path` without removing
    any existing bits, and never touching "other" -- --userns=keep-id (see
    build_argv()) gives the sandboxed process the invoking host user's
    GROUP as a supplementary group, not a matching uid (the container
    still reports its own fixed uid from the Dockerfile's `USER
    sandboxuser`). A path created the ordinary way -- tempfile.mkdtemp()'s
    own default is 0700, owner-only, no group access at all -- left the
    container unable to write into it at all (confirmed live: curl exit
    23, "Failed writing received data to disk", for BOTH this module's own
    new_scratch_dir() output and an auto-detected mount like httpx-mcp's
    `-srd <work_dir>`, which is also a bare tempfile.mkdtemp() result).
    This is applied to every mount source -- this module's own scratch
    dirs AND every path _detect_path_mounts() picks up from a caller --
    since the caller can't be expected to know sandboxing needs this."""
    try:
        st = os.stat(path)
        if stat.S_ISDIR(st.st_mode):
            os.chmod(path, st.st_mode | stat.S_IRWXG)
        else:
            os.chmod(path, st.st_mode | stat.S_IRGRP | stat.S_IWGRP)
    except OSError:
        pass


# Only values matching this prefix (SandboxedBenchApp's own generated
# name, see tests/fixtures/bench_target/bench_sandboxed_app.py) are
# accepted by the HUNTMCP_BENCH_NETWORK check in build_argv() -- see
# UnsafeBenchNetwork's own docstring for why a bare allow-anything splice
# would be dangerous.
_BENCH_NETWORK_PREFIX = "huntmcp-bench-net-"


def _validate_bench_network(value: str) -> str:
    if not value.startswith(_BENCH_NETWORK_PREFIX):
        raise UnsafeBenchNetwork(
            f"HUNTMCP_BENCH_NETWORK={value!r} does not match the expected "
            f"{_BENCH_NETWORK_PREFIX!r} prefix -- refusing to join it. This "
            f"variable must only ever hold a name generated by "
            f"SandboxedBenchApp; a stray value like 'host' would otherwise "
            f"defeat S5's per-run network isolation for every real Tier-2 "
            f"tool call in this process."
        )
    return value


def new_scratch_dir() -> str:
    """One fresh, uniquely-named scratch directory per run -- the default
    mount every sandboxed container gets. Caller is responsible for
    removing it (in a finally:) once the run is done; see
    tool_resolver.run_tool()/job_runtime.start_job()'s own call sites."""
    d = tempfile.mkdtemp(prefix="huntmcp-sbx-")
    _ensure_group_accessible(d)
    return d


def build_argv(tool_name: str, args: list[str], scratch_dir: str, *,
                env: dict[str, str],
                cwd: str | None = None,
                extra_mounts: list[str] | None = None,
                extra_mounts_rw: list[str] | None = None,
                container_name: str | None = None) -> list[str]:
    """Build the `podman run ...` argv that executes `tool_name` with
    `args` inside a fresh, isolated, ephemeral container. Does not launch
    anything itself -- callers still own their own subprocess.run()/Popen()
    call (and therefore their own timeout/stdout/stderr/retry handling),
    exactly as they did with a bare [binary, *args] before S5.

    `env` is REQUIRED (no default) and used verbatim for the container's
    --env flags -- callers must pass tool_resolver.minimal_subprocess_env()
    themselves (this module can't import it directly: tool_resolver
    imports sandbox_runner to sandbox its own execution, so the reverse
    import would be circular). This module never silently falls back to
    "compute something reasonable" for env -- an empty/wrong env passed in
    is the caller's bug to fix, not something to paper over here.

    `cwd`, if given, is mounted (same path, read-write) and set as the
    container's own --workdir, matching what a native
    subprocess.Popen(cwd=...) call would have done -- see httpx-mcp's
    screenshot_hosts(), which passes cwd=work_dir to job_runtime.start_job().

    `extra_mounts`, if given, is a list of additional host paths (each
    ALREADY a real, specific, purpose-built file/dir a caller created and
    deliberately wants the sandboxed process to read) mounted READ-ONLY at
    the SAME path inside the container -- e.g. httpx-mcp's own domains
    file, ad-recon-mcp's users_file, or ffuf-mcp's resolved wordlist.
    `extra_mounts_rw` is the same, mounted READ-WRITE, for the rarer case
    where the sandboxed process must also write there -- e.g. sqlmap-mcp's
    `--output-dir <tmpdir>` or secrets-mcp's gitleaks report directory.
    Read-only is the default and should be preferred whenever the
    sandboxed process only needs to read: found live, in review-driven
    testing of this very module, that a `:rw` mount lets the sandboxed
    process modify or DELETE the real host file -- an early version of
    ffuf-mcp's own wordlist mount used `:rw` unnecessarily and a test run
    against it silently deleted a real, git-tracked project wordlist file
    from the host (recovered via `git checkout`, but it demonstrated the
    risk is real, not theoretical).

    Every entry in either list must be a path the CALLER explicitly names,
    never something derived generically from `args` -- see
    _validate_mount_path()'s own docstring for why blanket auto-detection
    from arbitrary argument strings was removed as a real security hole
    (an agent-controlled tool parameter like ffuf-mcp's `wordlist` could
    otherwise get an arbitrary host path, e.g. under $HOME, silently
    bind-mounted and permission-widened).

    `container_name`, if given, is used as the container's --name instead
    of an auto-generated one -- callers that need to force-remove THEIR
    OWN specific container later (see remove_container()) should generate
    one via new_container_name() and pass it here, so cleanup never has to
    guess or sweep by a shared label.

    Raises UnknownSandboxTool if `tool_name` isn't in _TOOL_MAP -- callers
    must not catch this and silently fall back to native host execution;
    that would defeat the sandboxing boundary for exactly the tool whose
    name wasn't recognized. Raises UnsafeSandboxMount if `cwd` or an
    `extra_mounts` entry is dangerously broad.
    """
    if tool_name not in _TOOL_MAP:
        raise UnknownSandboxTool(
            f"{tool_name!r} is not an approved sandboxed tool (see "
            f"mcp-servers/sandbox_runner.py's _TOOL_MAP). Refusing to run it "
            f"-- add it to _TOOL_MAP and mcp-servers/sandbox/Dockerfile "
            f"first if this is a genuinely new Tier-2 tool."
        )
    in_container_binary = _TOOL_MAP[tool_name]

    # Resolve every mount source to its canonical, `..`-free real path --
    # found live in review-driven testing: a caller-supplied path
    # containing an UNRESOLVED ".." component (e.g. ffuf-mcp's
    # PROJECT_WORDLIST_DIR = os.path.join(__file__, "..", "..",
    # "knowledge", "wordlists"), never normalized before this point)
    # produced a `--volume=X/../../Y:X/../../Y:rw` flag whose SOURCE side
    # Podman does not resolve the way a shell or a Go program's own stat()
    # call does -- the bind mount silently lands somewhere other than the
    # intended directory, and the tool then fails with "no such file or
    # directory" for a wordlist/path that objectively exists on the host.
    # Discarding _validate_mount_path()'s returned resolved value here (an
    # earlier version of this function did exactly that -- validated the
    # resolved path but then mounted the ORIGINAL, unresolved one) was the
    # actual bug; using the resolved value for the mount, and for `cwd`'s
    # own --workdir, is the fix.
    # (path, mode) pairs -- mode is "rw" or "ro". Read-only is the default
    # for extra_mounts (see this function's own docstring for why: a
    # sandboxed process only needs READ access to most of what a caller
    # shares with it, and ":rw" when unnecessary is a real, demonstrated
    # data-loss risk, not just a theoretical over-permission).
    mount_paths: list[tuple[str, str]] = []
    resolved_cwd = None
    if cwd:
        resolved_cwd = _validate_mount_path(cwd)
        _ensure_group_accessible(resolved_cwd)
        mount_paths.append((resolved_cwd, "rw"))
    for p in (extra_mounts or []):
        resolved_p = _validate_mount_path(p)
        _ensure_group_accessible(resolved_p)
        mount_paths.append((resolved_p, "ro"))
    for p in (extra_mounts_rw or []):
        resolved_p = _validate_mount_path(p)
        _ensure_group_accessible(resolved_p)
        mount_paths.append((resolved_p, "rw"))

    workdir = resolved_cwd if resolved_cwd else WORKDIR_IN_CONTAINER
    name = container_name if container_name else new_container_name()
    bench_network = os.environ.get("HUNTMCP_BENCH_NETWORK") or None
    if bench_network:
        bench_network = _validate_bench_network(bench_network)

    argv = [
        "podman", "run",
        "--rm",
        # --userns=keep-id: rootless Podman remaps the container's UID
        # through a user-namespace by default, so the Dockerfile's fixed
        # `USER sandboxuser` (uid 10001) does NOT correspond to the HOST
        # uid that owns a bind-mounted directory (confirmed live: without
        # this, writing into the run's own scratch mount failed with
        # "Failed writing received data to disk", curl exit 23 -- a
        # permission mismatch, not a real read-only-fs block). keep-id
        # maps the container's effective uid to the SAME uid invoking
        # podman, so every bind mount (scratch dir + auto-detected paths)
        # keeps correct read/write permissions. This does not weaken
        # isolation: that host uid is already the unprivileged operator
        # account rootless Podman itself is namespaced under -- it was
        # never "root" in the first place.
        "--userns=keep-id",
        # -i: keep stdin open and forward it into the container. Safe
        # unconditionally -- when the caller's own subprocess.run() passes
        # stdin=DEVNULL (the default, see tool_resolver.run_tool()'s own
        # comment on why), that's simply an immediately-EOF stdin forwarded
        # through, identical in effect to not having -i for a tool that
        # never reads stdin. When the caller passes real input= data (e.g.
        # ad-recon-mcp piping a Kerberoast password), -i is what lets it
        # actually reach the containerized process at all.
        "--interactive",
        f"--label={_CONTAINER_LABEL}",
        f"--name={name}",
        # Filesystem: read-only root, plus exactly the run's own scratch
        # dir and whatever specific paths the caller explicitly named via
        # cwd/extra_mounts -- nothing else from the host is ever visible.
        "--read-only",
        f"--volume={scratch_dir}:{WORKDIR_IN_CONTAINER}:rw",
        *[f"--volume={p}:{p}:{mode}" for p, mode in sorted(set(mount_paths))],
        f"--workdir={workdir}",
        # tmpfs for /tmp: several of these tools (sqlmap especially) write
        # small scratch files to /tmp by default: --read-only alone would
        # make that an immediate write-failure rather than a contained,
        # ephemeral write.
        "--tmpfs=/tmp:rw,size=64m",
        # Benchmark-only network join, dormant by default: if the process
        # environment sets HUNTMCP_BENCH_NETWORK, join that Podman network
        # instead of the default per-container isolated network. This
        # exists solely for P2-BENCH's own real-tool fixture-proof tests
        # (tests/fixtures/bench_target/) to reach their own throwaway,
        # --internal (no host/internet route), test-harness-owned target
        # container -- never set by any production launch config
        # (opencode.jsonc), so every real Tier-2 tool invocation is
        # unaffected. Deliberately read from the process environment, not
        # a build_argv()/start_job() parameter or any MCP tool argument:
        # there is no code path from an agent's tool-call input to this
        # variable. An empty string is treated as unset. The value itself
        # is validated (_validate_bench_network, resolved once into
        # bench_network above) rather than spliced in verbatim -- found
        # in adversarial review that an unvalidated splice would accept
        # Podman's own special values (e.g. "host"), silently granting
        # full host networking on a typo/leftover-debug env var; only
        # SandboxedBenchApp's own generated-name shape is accepted,
        # everything else fails closed.
        *([f"--network={bench_network}"] if bench_network else []),
        # Privilege/process isolation.
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=50",
        "--memory=512m",
        # Environment: only the same allowlisted keys run_tool()/start_job()
        # already pass on the host -- never --env-host, never a $HOME mount.
        # HOME is the one key deliberately overridden rather than passed
        # through verbatim: `env` is the same dict used for the OUTER
        # podman-launching process too, where HOME correctly means the
        # real host user's home -- but INSIDE the container that value
        # (e.g. "/home/ankit") doesn't exist at all, so CONTAINER_HOME
        # (a writable tmpfs -- see its definition) is used instead.
        # The Dockerfile's own `useradd -m` home is NOT usable for this:
        # --read-only plus --userns=keep-id leave the image-owned
        # /home/sandboxuser unwritable, and every tool that writes
        # $HOME/.config/<tool>/ on startup then dies. Confirmed live for
        # katana, subfinder, nuclei AND ffuf alike -- an earlier version
        # of this comment claimed ffuf worked with that value; it did not.
        *[f"--env={k}={v}" for k, v in sorted(env.items()) if k != "HOME"],
        f"--env=HOME={CONTAINER_HOME}",
        SANDBOX_IMAGE,
        in_container_binary,
        *args,
    ]
    return argv


def new_container_name() -> str:
    """One fresh, unique container name per run. Callers that need to
    force-remove THEIR OWN specific container later (see remove_container())
    must generate one here and pass it to build_argv()'s `container_name`
    -- this is what makes cleanup precise instead of a blind sweep."""
    return f"huntmcp-sbx-{uuid.uuid4().hex[:12]}"


def remove_container(name: str) -> None:
    """Force-remove exactly the ONE container named `name` -- best-effort,
    silently a no-op if it's already gone (normal --rm already handled a
    graceful exit; this is only for the path where the `podman run`
    wrapper was SIGKILLed and might have left its container running,
    supervised independently by conmon).

    Deliberately targets a single, caller-known container by exact name,
    never a bulk sweep by label: an earlier version of this module had a
    reap_orphans() that force-removed EVERY container sharing the generic
    huntmcp-sandbox=1 label, found in review to be unsafe -- confirmed
    live, a container survives SIGKILL to its wrapper process and shows
    status 'Up N seconds' (running) indefinitely, never 'exited', making
    it indistinguishable via label+status filtering from a completely
    different, healthy, concurrent run's container that merely shares the
    same label. Naming and tracking each run's own container explicitly
    (see build_argv()'s `container_name` param) closes that: this can
    never touch a container it didn't itself create."""
    import subprocess

    try:
        subprocess.run(["podman", "rm", "-f", name], capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def cleanup_scratch_dir(scratch_dir: str) -> None:
    """Best-effort removal of a run's scratch directory -- call in a
    finally: block regardless of how the run ended. Sandboxed processes
    run as a non-root uid (see the Dockerfile), so files they create can
    have unfamiliar ownership from the host's point of view; ignore_errors
    tolerates that rather than raising during cleanup."""
    shutil.rmtree(scratch_dir, ignore_errors=True)


def podman_available() -> bool:
    return shutil.which("podman") is not None
