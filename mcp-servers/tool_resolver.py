"""Resolve tool binary paths for MCP servers.

MCP servers call external tools (subfinder, httpx, etc.) via subprocess.
This module ensures they find the correct binary even when Python packages
shadow the Go/system binary names (e.g., Python httpx vs ProjectDiscovery httpx).
"""

import os
import re
import shutil
import subprocess
import time

import sandbox_runner
from audit_log import log_call as _log_call
from budget_guard import enforce as _enforce_budget

GO_BIN = os.path.expanduser("~/go/bin")
GO_BIN_CANDIDATES = [
    GO_BIN,
    "/usr/local/go/bin",
    "/usr/lib/go/bin",
    "/snap/go/current/bin",
]

# Reactive-only signals. run_tool() never adds a delay unless one of these
# actually shows up in the tool's output — full speed by default, back off
# only when the target signals it. Deliberately NOT a proactive per-request
# sleep: that trades away real recon/scan speed for a problem that mostly
# never happens.
_RATE_LIMIT_PATTERNS = [
    re.compile(r"\b429\b"),
    re.compile(r"too many requests", re.I),
    re.compile(r"rate.?limit", re.I),
    # Added 2026-08-29 after a real engagement's own API rate-limiter used
    # one of these instead of a bare "429"/"rate limit" string -- a tool's
    # stdout/stderr can carry the human-readable header/body text without
    # ever literally saying "429" (e.g. a JSON body of
    # {"error": "retry after 30 seconds"} with a 200-shaped wrapper status).
    re.compile(r"retry.?after", re.I),
    re.compile(r"try again (later|in \d+)", re.I),
    re.compile(r"slow down", re.I),
]
_WAF_BLOCK_PATTERNS = [
    re.compile(r"\b403\b.*(forbidden|blocked)", re.I),
    re.compile(r"cloudflare|akamai|imperva|incapsula", re.I),
    re.compile(r"access denied|request blocked|attack detected", re.I),
]

# S3 (IMPLEMENTATION-TASK-TRACKER.md -- "secrets scoped out of untrusted
# execution"): subprocess.run()/Popen() inherit the FULL parent environment
# by default. This process's own os.environ can carry a real credential --
# dotenv_loader.get_secret() callers hold one locally, or the operator has
# one genuinely exported in their shell -- and without an explicit env=,
# every external tool binary this codebase spawns (subfinder, httpx, katana,
# nmap, nuclei, sqlmap, dalfox, ffuf) would inherit all of it, even though
# none of them need any HuntMCP credential to do their job. Allowlist, not
# denylist: only these survive into the child by default, so a new secret
# added to .env.example later is excluded automatically instead of
# requiring someone to remember to add it to a blocklist.
#
# Includes standard proxy/TLS-trust vars (found in code review, S3): an
# operator running these tools behind a corporate proxy or a TLS-inspecting
# network relies on HTTP_PROXY/HTTPS_PROXY/NO_PROXY/SSL_CERT_FILE/etc. being
# inherited the way they always were before this allowlist existed --
# dropping them silently turns a working, proxied scan into an opaque
# connection/TLS failure. These aren't secrets (no .env.example entry,
# nothing HuntMCP itself ever writes here), so including them doesn't
# reopen the leak this allowlist exists to close.
#
# Public (no leading underscore): shared by every subprocess-spawning
# chokepoint in this codebase, not just run_tool() below -- see
# job_runtime.start_job() and oob-mcp/server.py's own Popen call, both of
# which import minimal_subprocess_env() directly rather than duplicating
# this allowlist a second (or third) time.
SUBPROCESS_ENV_ALLOWLIST = {
    "PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR",
    "GOPATH", "GOROOT",  # Go-toolchain binaries (subfinder/httpx/...) may consult these
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
}


def minimal_subprocess_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k in SUBPROCESS_ENV_ALLOWLIST}


def classify_block(output: str) -> str | None:
    """Inspect tool stdout/stderr for a blocking signal. Returns 'rate_limit',
    'waf', or None. This is the only thing that should ever trigger a delay —
    never a blanket per-request sleep."""
    if not output:
        return None
    for pattern in _RATE_LIMIT_PATTERNS:
        if pattern.search(output):
            return "rate_limit"
    for pattern in _WAF_BLOCK_PATTERNS:
        if pattern.search(output):
            return "waf"
    return None


def resolve_tool(name: str) -> str:
    """Resolve a tool binary path, preferring Go/system binaries over Python wrappers."""
    # First check ~/go/bin directly (fast path)
    go_path = os.path.join(GO_BIN, name)
    if os.path.isfile(go_path) and os.access(go_path, os.X_OK):
        return go_path

    # Use shutil.which but exclude Python wrappers
    result = shutil.which(name)
    if result:
        return result

    # Search Go bin candidates
    for candidate in GO_BIN_CANDIDATES:
        candidate_path = os.path.join(candidate, name)
        if os.path.isfile(candidate_path) and os.access(candidate_path, os.X_OK):
            return candidate_path

    return name


def run_tool(
    name: str,
    args: list[str],
    retry_on_rate_limit: bool = True,
    **kwargs,
) -> subprocess.CompletedProcess:
    """Run a tool with the resolved binary path. No artificial delay is added
    up front. If the output signals an actual rate limit (429 / "rate limit"
    text), back off 5s and retry exactly once, per the master prompt's Phase
    21.5 decision tree — never more than one silent retry, since a second
    block means something else is wrong.

    If the output signals a WAF/bot-detection block instead of a rate limit,
    this does NOT sleep-and-hope: it returns as-is so the calling MCP server
    or agent can escalate to real bypass tooling (header/path tricks, or a
    browser-driven tool like Playwright for JS-challenge WAFs) rather than
    silently waiting on something a sleep won't fix. Use classify_block() on
    the result to check which case happened.

    Every call is recorded against the per-engagement budget circuit-breaker
    (mcp-servers/budget_guard.py) BEFORE the subprocess runs -- this is the
    single chokepoint all Tier-2 MCP servers share, so it's where a stuck
    loop or runaway attack surface actually gets caught. Raises
    BudgetExceeded instead of running the tool once the hard cap is hit.
    """
    _enforce_budget(name)
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    # S3: scrub secrets out of the child's environment by default -- see
    # minimal_subprocess_env()'s own comment. A caller that has a genuine
    # reason to pass a specific env (kwargs already supports env=) is not
    # overridden here. Deliberately NOT kwargs.setdefault("env", ...): that
    # only fills in an ABSENT key, but subprocess.run(env=None) means
    # "inherit the full parent environment" per Python's own documented
    # semantics -- an explicit env=None would silently skip this scrub
    # entirely (found in code review). Treating "absent" and "None" the
    # same way closes that: nothing in this codebase currently needs
    # "inherit everything," and safe-by-default is the right call here.
    if kwargs.get("env") is None:
        kwargs["env"] = minimal_subprocess_env()
    # Without this, the child inherits OUR stdin file descriptor. That's
    # harmless when this process's own stdin is a terminal or already
    # closed, but every one of these servers normally runs as an MCP
    # server over stdio -- its stdin is a live pipe to the MCP client that
    # never sends EOF. Several of these binaries (httpx, subfinder,
    # katana, nuclei -- standard ProjectDiscovery CLI convention) detect
    # "stdin is not a terminal" and treat it as an ADDITIONAL target-list
    # input source regardless of -l/-d being passed, so the child blocks
    # forever trying to read hosts from a pipe that will never write or
    # close -- a genuine deadlock, not a slow call (confirmed live:
    # httpx-mcp's probe_hosts hung 160+s on a call that completes in <2s
    # once stdin is closed). DEVNULL tells the child "no stdin input,
    # ever" up front, matching what every one of these tools actually
    # wants here (target list always comes via -l/-d/a real arg, never
    # via interactively-piped stdin).
    #
    # Skip this when the caller already passed input= (watch-mcp's
    # run_httpx(), ad-recon-mcp's kerberoast() piping a password) --
    # subprocess.run() raises ValueError if both stdin and input are set,
    # and input= already fully replaces stdin with controlled, finite
    # data (Python sets stdin=PIPE internally for it), so it was never
    # vulnerable to the live-pipe-inheritance deadlock this default
    # exists for in the first place. Confirmed live: this collision broke
    # watch-mcp's httpx step silently (swallowed by a broad except) and
    # crashed ad-recon-mcp's password-authenticated Kerberoast loudly.
    if "input" not in kwargs:
        kwargs.setdefault("stdin", subprocess.DEVNULL)

    # S5 (rootless per-run execution boundary): every subprocess.run() call
    # below runs inside a fresh, ephemeral, isolated container rather than
    # directly on the host -- see sandbox_runner.py's own module docstring
    # for exactly what this does and does NOT provide (notably: no
    # per-target network egress restriction in V1). "Per-run" = one fresh
    # container per subprocess.run() attempt, including the rate-limit
    # retry below (its own independent run, not a resumption of the first
    # container -- a --rm container that already exited can't be resumed).
    cwd = kwargs.pop("cwd", None)
    # extra_mounts/extra_mounts_rw: host paths a caller explicitly,
    # deliberately wants bind-mounted at the same path -- read-only vs
    # read-write, e.g. secrets-mcp's own scan target directory (read-only)
    # and its gitleaks report directory (read-write). Not real
    # subprocess.run() kwargs, so popped here the same way cwd already is.
    # See sandbox_runner.build_argv()'s own docstring for why this must
    # always be an explicit, named choice, never scraped from `args`, and
    # why read-only is the safer default (a real, demonstrated data-loss
    # risk was found live from an unnecessary :rw mount).
    extra_mounts = kwargs.pop("extra_mounts", None)
    extra_mounts_rw = kwargs.pop("extra_mounts_rw", None)
    run_env = kwargs.get("env")
    container_name = sandbox_runner.new_container_name()

    def _sandboxed_argv() -> list[str]:
        if not sandbox_runner.podman_available():
            raise FileNotFoundError(
                "podman not found -- S5 sandboxing requires it. Install with: "
                "sudo apt install podman (see IMPLEMENTATION-TASK-TRACKER.md S5)."
            )
        try:
            return sandbox_runner.build_argv(
                name, args, scratch_dir, cwd=cwd, env=run_env,
                extra_mounts=extra_mounts, extra_mounts_rw=extra_mounts_rw,
                container_name=container_name,
            )
        except sandbox_runner.UnknownSandboxTool as e:
            # Re-raised as FileNotFoundError (not the original type) so
            # every existing caller's own `except FileNotFoundError:`
            # handling (the same shape as "binary not found on host" used
            # to raise) keeps working completely unchanged -- see this
            # module's own migration notes in IMPLEMENTATION-TASK-TRACKER.md.
            raise FileNotFoundError(str(e)) from e

    scratch_dir = sandbox_runner.new_scratch_dir()
    try:
        start = time.monotonic()
        result = subprocess.run(_sandboxed_argv(), **kwargs)

        block = None
        if retry_on_rate_limit:
            combined = (result.stdout or "") + (result.stderr or "")
            block = classify_block(combined)
            if block == "rate_limit":
                time.sleep(5)
                sandbox_runner.cleanup_scratch_dir(scratch_dir)
                scratch_dir = sandbox_runner.new_scratch_dir()
                container_name = sandbox_runner.new_container_name()
                result = subprocess.run(_sandboxed_argv(), **kwargs)
                # Re-classify the retry's own output rather than assuming it
                # succeeded -- the retry can still be rate-limited (or now hit a
                # WAF), and logging block=None unconditionally here made the
                # audit trail claim it wasn't.
                combined = (result.stdout or "") + (result.stderr or "")
                block = classify_block(combined)
    finally:
        sandbox_runner.cleanup_scratch_dir(scratch_dir)
        # Safety net: a caller-supplied timeout=... firing here makes
        # Python's own subprocess.run() SIGKILL the `podman run` process
        # directly, which can skip its normal --rm cleanup-on-exit. Targets
        # ONLY this run's own, precisely-named container (never a blind
        # sweep -- see remove_container()'s own docstring for why that's
        # unsafe) -- a cheap no-op if it already exited normally.
        sandbox_runner.remove_container(container_name)

    _log_call(name, args, result.returncode, (time.monotonic() - start) * 1000, block)
    return result
