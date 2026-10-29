import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import job_runtime  # noqa: E402
import scope_guard  # noqa: E402
from engagement_paths import resolve_dir  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("schemathesis-mcp")

_jobs: dict = {}
_meta: dict[str, dict] = {}

# Validated against the real schemathesis==4.30.1 CLI's own --help output
# (not guessed). "stateful" is deliberately excluded from _ALLOWED_PHASES:
# unlike examples/coverage/fuzzing (which each send one request per
# declared operation), stateful chases links between operations into
# multi-step, write-chasing chains -- a materially more aggressive mode
# than this tool's own fixture-validated default, and security.md's own
# rule ("state-changing security tests require explicit authorization")
# means a tool parameter alone should not unlock it. "all" is deliberately
# excluded from _ALLOWED_CHECKS: it is an unbounded shortcut that would
# silently pull in whatever checks a future schemathesis version adds,
# never vetted here -- every check this tool permits must be named
# explicitly. Every sibling scanner in this repo confines its own
# aggressiveness knob the same way (sqlmap-mcp hardcodes --threads 5;
# nuclei-mcp resolves `templates` through a pinned allow-list) rather than
# trusting a caller-supplied string outright.
_ALLOWED_PHASES = frozenset({"examples", "coverage", "fuzzing"})
_ALLOWED_CHECKS = frozenset({
    "not_a_server_error", "status_code_conformance", "content_type_conformance",
    "response_headers_conformance", "response_schema_conformance",
    "negative_data_rejection", "positive_data_acceptance", "missing_required_header",
    "unsupported_method", "allow_header_conformance", "use_after_free",
    "ensure_resource_availability", "ignored_auth",
})
# A small fixed set rather than a numeric parser: "auto" backs off
# automatically on a target's own Retry-After header (the most
# conservative option, always permitted); the two numeric options are
# deliberately pre-chosen rather than letting a caller supply an arbitrary
# "<N>/<unit>" string, since rate_limit is the one parameter whose entire
# purpose is to be a safety control -- it must not itself be the thing an
# attacker-steered call disables.
_ALLOWED_RATE_LIMITS = frozenset({"auto", "10/s", "60/m"})
_MAX_EXAMPLES_CEILING = 1000
_TIMEOUT_CEILING = 1800


def _output_dir() -> str:
    return resolve_dir("tmp-schemathesis", override_env="HUNTMCP_SCHEMATHESIS_TMP",
                        legacy_default="/tmp/huntmcp-schemathesis")


def _resolve_engagement():
    """Mirrors case-mcp's own _resolve_engagement: NoEngagementFile -> an
    empty Engagement (a safe test host still passes via is_in_scope's
    is_safe_test_host branch; a real host does not)."""
    try:
        return scope_guard.load_engagement()
    except scope_guard.NoEngagementFile:
        return scope_guard.Engagement(target="(no engagement.yaml)")


def _scope_or_error(label: str, value: str, engagement) -> str | None:
    """Checks ONE value against both the outbound SSRF policy and the
    active engagement's scope. Returns an error string, or None if
    permissible. Called independently for `url` and `target` -- either
    one failing refuses the whole call. `engagement` is resolved ONCE by
    the caller and passed in -- resolving it separately per value meant
    run_schema_test did two full file-read-and-YAML-parse passes over the
    identical engagement.yaml for data that can't change within one call."""
    if not isinstance(value, str) or not value:
        return f"Error: {label} must be a non-empty string."
    policy = scope_guard.outbound_policy_error(value)
    if policy:
        return f"BLOCKED by outbound policy: {label} {value!r} -- {policy}."
    try:
        in_scope = scope_guard.is_in_scope(value, engagement)
    except Exception as e:  # noqa: BLE001 - any resolution/parse failure -> refuse
        return (f"BLOCKED by scope gate: could not verify {label} {value!r} is in "
                f"scope ({e.__class__.__name__}: {e}); refusing to run.")
    if not in_scope:
        return (f"BLOCKED by scope gate: {label} {value!r} is not in the active "
                "engagement's in_scope list -- refusing to run.")
    return None


def _validate_run_params(phases: str, checks: str, max_examples: int,
                          rate_limit: str, timeout: int) -> str | None:
    """Validates the non-host parameters that still reach the real
    subprocess argv -- found in security review: a prompt-injected agent
    (steered by hostile content on the target) could otherwise set
    max_examples/rate_limit/phases/checks to defeat the one control
    (rate_limit) whose entire purpose is to throttle traffic against a
    live, in-scope target, since the scope check alone only verifies
    WHICH host is hit, never how aggressively. Returns an error string,
    or None if every value is permitted."""
    phase_list = [p.strip() for p in phases.split(",") if p.strip()]
    bad_phases = sorted(set(phase_list) - _ALLOWED_PHASES)
    if not phase_list or bad_phases:
        return (f"Error: phases must be a non-empty comma-separated list drawn "
                f"only from {sorted(_ALLOWED_PHASES)} (got {phases!r}, "
                f"unsupported: {bad_phases}). 'stateful' is deliberately excluded "
                "-- it chains multi-step, write-seeking requests, a materially "
                "more aggressive mode than this tool's fixture-validated default.")
    check_list = [c.strip() for c in checks.split(",") if c.strip()]
    bad_checks = sorted(set(check_list) - _ALLOWED_CHECKS)
    if not check_list or bad_checks:
        return (f"Error: checks must be a non-empty comma-separated list drawn "
                f"only from {sorted(_ALLOWED_CHECKS)} (got {checks!r}, "
                f"unsupported: {bad_checks}). 'all' is deliberately excluded -- "
                "it would silently pull in whatever checks a future schemathesis "
                "version adds, never vetted here.")
    if not (1 <= max_examples <= _MAX_EXAMPLES_CEILING):
        return f"Error: max_examples must be between 1 and {_MAX_EXAMPLES_CEILING} (got {max_examples})."
    if rate_limit not in _ALLOWED_RATE_LIMITS:
        return f"Error: rate_limit must be one of {sorted(_ALLOWED_RATE_LIMITS)} (got {rate_limit!r})."
    if not (1 <= timeout <= _TIMEOUT_CEILING):
        return f"Error: timeout must be between 1 and {_TIMEOUT_CEILING} seconds (got {timeout})."
    return None


@app.tool()
def run_schema_test(url: str, target: str, phases: str = "examples",
                     checks: str = "not_a_server_error,status_code_conformance,response_schema_conformance",
                     max_examples: int = 100, rate_limit: str = "60/m",
                     timeout: int = 300) -> str:
    """Start a schemathesis run against an OpenAPI spec in the background,
    returning immediately with a job_id. `url` is where to fetch the
    OpenAPI spec from. `target` is the REAL base URL every generated
    request is sent to (required -- schemathesis is never allowed to use
    the spec's own declared `servers[]` host instead; see this tool's own
    design spec, docs/superpowers/specs/2026-10-20-schemathesis-mcp-design.md,
    section 3, for why). Both `url` and `target` must be in the active
    engagement's scope, and both hosts are resolved and DNS-pinned for the
    run's duration (see `scope_guard.pin_hosts_or_error`). `phases`/`checks` are
    restricted to a vetted allow-list (no `stateful` phase, no `all`
    checks-shortcut); `max_examples`/`rate_limit`/`timeout` are bounded --
    see `_validate_run_params`. Defaults are the combination already
    verified live against a real planted bug (see
    tests/fixtures/schema_target/). Poll check_scan(job_id) for the
    result."""
    url = url.strip() if isinstance(url, str) else url
    target = target.strip() if isinstance(target, str) else target

    param_err = _validate_run_params(phases, checks, max_examples, rate_limit, timeout)
    if param_err:
        return param_err

    engagement = _resolve_engagement()
    for label, value in (("url", url), ("target", target)):
        err = _scope_or_error(label, value, engagement)
        if err:
            return err

    extra_hosts, pin_err = scope_guard.pin_hosts_or_error(url, target)
    if pin_err:
        return f"BLOCKED by scope gate: {pin_err}"

    scratch_dir = tempfile.mkdtemp(dir=_output_dir())
    args = [
        "run", url,
        "--url", target,
        "--phases", phases,
        "--checks", checks,
        "--max-examples", str(max_examples),
        "--rate-limit", rate_limit,
        # Security review finding: `target`'s own HTTP responses could
        # otherwise redirect generated requests to an arbitrary, unchecked
        # host (e.g. a cloud metadata endpoint) -- resolve_and_pin() only
        # ever validated url/target's OWN hosts, never a host a redirect
        # might point at. --max-redirects 0 closes that vector entirely by
        # never following any redirect, matching this repo's own existing
        # precedent (http_probe.fetch's allow_redirects=False for CEM).
        # Not exposed as a tunable -- like rate_limit, this is a safety
        # control, not something a caller should be able to loosen.
        "--max-redirects", "0",
        "--report", "json",
        "--report-dir", scratch_dir,
    ]
    try:
        result = job_runtime.start_job("schemathesis", args, timeout, _jobs,
                                        extra_mounts_rw=[scratch_dir],
                                        extra_hosts=extra_hosts or None)
    except FileNotFoundError:
        shutil.rmtree(scratch_dir, ignore_errors=True)
        return ("Error: schemathesis not found. The sandbox image must be rebuilt "
                "with schemathesis installed -- see mcp-servers/sandbox/Dockerfile.")
    except Exception as e:  # noqa: BLE001
        shutil.rmtree(scratch_dir, ignore_errors=True)
        return f"Error: {e}"
    job_id = result["job_id"]
    _meta[job_id] = {"url": url, "target": target, "scratch_dir": scratch_dir}
    return (f"Started schemathesis run (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a run started by run_schema_test(). Returns "status: running
    (Xs elapsed)" while schemathesis is still working. Once done, returns
    the falsifier report (see Task 4 of this tool's implementation plan
    for the real report-parsing behavior this placeholder body will be
    replaced with)."""
    result = job_runtime.poll_job(job_id, _jobs)
    if "status" not in result:
        return result["error"]
    if result["status"] == "running":
        return f"Still running -- {result['elapsed_s']}s elapsed so far. Poll again shortly."

    meta = _meta.pop(job_id, None)
    scratch_dir = meta["scratch_dir"] if meta else None
    if scratch_dir:
        shutil.rmtree(scratch_dir, ignore_errors=True)
    if result["status"] == "timeout":
        return result["error"]
    if meta is None:
        return "schemathesis finished, but this job's metadata was already collected."

    # Placeholder body -- Task 4 replaces this with real JSON-report parsing.
    return (f"{job_runtime.block_prefix(result)}schemathesis finished "
            f"(exit code {result['returncode']}). Report parsing not yet implemented.")


@app.tool()
def list_scans() -> str:
    """List schemathesis runs still running in this session."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No schemathesis runs currently running."
    lines = ["Running schemathesis runs:", ""]
    for j in jobs:
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)
