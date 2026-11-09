import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fanout  # noqa: E402
import job_runtime  # noqa: E402
import scan_headers  # noqa: E402
import scope_guard  # noqa: E402
import templates_pin  # noqa: E402

from mcp.server.fastmcp import FastMCP

app = FastMCP("nuclei-mcp")

# See dalfox-mcp/server.py for the full rationale -- same background-job
# pattern, same per-process-only job storage. _targets carries (target,
# no_findings_message) so check_scan() reproduces the exact "no
# vulnerabilities" wording each tool used to return directly, without
# job_runtime needing to know anything about nuclei's own message shapes.
_jobs: dict = {}
_targets: dict[str, tuple[str, str]] = {}

# P3-FANOUT: fanout.start_batch()/check_batch()'s required per-process
# `batches` dict, scoped exactly like `_jobs` above. `_batch_no_findings`
# is this server's own side table (fanout's _Batch has no room for a
# nuclei-specific message) mapping batch_id -> the single
# no_findings_message shared by every target in that one
# scan_batch_target()/scan_batch_with_templates() call -- same role
# `_targets` plays per job_id for the single-target tools.
_batches: dict = {}
_batch_no_findings: dict[str, str] = {}


def _format_findings(target: str, no_findings_message: str, stdout: str, returncode: int, stderr: str) -> str:
    if returncode != 0 and not stdout:
        return f"nuclei failed (exit {returncode}): {stderr.strip()}"

    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        findings.append({
            "template": data.get("template-id", "?"),
            "name": data.get("info", {}).get("name", "?"),
            "severity": data.get("info", {}).get("severity", "?"),
            "matched": data.get("matched-at", data.get("host", "?")),
            "type": data.get("type", "?"),
        })

    if not findings:
        return no_findings_message

    lines = [f"nuclei found {len(findings)} issue(s) on {target}:", ""]
    for f in findings:
        lines.append(f"  [{f['severity'].upper()}] {f['name']}")
        lines.append(f"    Template: {f['template']}")
        lines.append(f"    Target:   {f['matched']}")
        lines.append(f"    Type:     {f['type']}")
        lines.append("")
    return "\n".join(lines)


def _resolve_templates_arg(templates: str) -> str:
    """Resolve each comma-separated entry of a caller-supplied -t value
    against the pinned templates snapshot, same way nuclei itself resolves
    a relative -t value against ITS OWN default template directory --
    except nuclei's own default directory is deliberately left unpopulated
    now (see templates_pin.py's module docstring: auto-update is disabled
    to avoid refilling the 64MB /tmp tmpfs), so a relative value like
    "http/exposed-panels" must be joined onto TEMPLATES_DIR here instead,
    or nuclei would silently fail to find it.

    Each entry is stripped of surrounding whitespace and empty entries are
    dropped -- found live (code review): an un-stripped "a, b" (the
    natural way to write a comma list) left a leading space baked into the
    second path, and a trailing comma produced an EMPTY entry that
    os.path.join(TEMPLATES_DIR, "") resolves to TEMPLATES_DIR itself,
    silently adding the entire pinned template library as a second -t
    entry. Raises ValueError if nothing usable remains after that -- an
    all-empty templates argument (e.g. "" or ",") is a caller mistake, not
    "scan everything".

    Every entry -- relative or absolute -- is only ever usable if it
    resolves INSIDE TEMPLATES_DIR: _start() only ever bind-mounts
    TEMPLATES_DIR into the sandbox (see its own extra_mounts= call), never
    an arbitrary caller-supplied path, so anything outside it could never
    actually be found by nuclei running in the read-only container.
    Raises ValueError otherwise, rather than silently building a -t
    argument nuclei can never resolve -- do NOT widen this to mount
    arbitrary host paths. The containment check is applied to the fully
    resolved (realpath'd) candidate for BOTH branches, not just absolute
    entries: os.path.join() does not collapse ".." components, so a
    relative entry like "../../../../etc/passwd" would otherwise skip the
    check entirely by taking the "not absolute" path -- adversarial
    review caught this exact gap in an earlier version of this function
    that only validated the isabs() branch."""
    entries = [e.strip() for e in templates.split(",") if e.strip()]
    if not entries:
        raise ValueError(f"{templates!r} contains no usable template path/ID")

    root = os.path.realpath(templates_pin.TEMPLATES_DIR)
    resolved = []
    for entry in entries:
        candidate = entry if os.path.isabs(entry) else os.path.join(templates_pin.TEMPLATES_DIR, entry)
        real = os.path.realpath(candidate)
        if real != root and not real.startswith(root + os.sep):
            raise ValueError(
                f"{entry!r} resolves outside the approved template root "
                f"({templates_pin.TEMPLATES_DIR}) -- only the pinned nuclei-templates "
                "snapshot is mounted into the sandbox, so a path escaping it (via a "
                "leading \"/\" or a \"..\" traversal) can never actually be found there. "
                "Pass a path relative to the snapshot instead (e.g. \"http/exposed-panels\")."
            )
        resolved.append(real)
    return ",".join(resolved)


def _prepare(target: str, args: list[str], no_findings_message: str, timeout: int) -> dict:
    """Scope/template-validation half of what used to be _start() itself,
    factored out so fanout.start_batch()'s per-target prepare() callback
    can reuse the exact same checks a single-target scan already runs --
    `_start()` below calls this too, so the single-target tools'
    behavior is unchanged. `no_findings_message` plays no role in these
    specific error paths (today's errors are all scope/template
    failures, not "no findings") but is accepted here so every caller --
    `_start()` and fanout's prepare() lambda alike -- shares one call
    shape.

    Returns {"error": ...} on a scope/template failure, or the exact
    kwargs job_runtime.start_job() needs (args/max_wall_seconds/
    extra_mounts/extra_hosts) on success -- the same shape
    fanout.start_batch()'s prepare() contract requires."""
    # DNS-rebinding/numeric-IP-encoding defense (see
    # scope_guard.pin_hosts_or_error's own docstring): nuclei resolves and
    # connects on its own, never through this repo's http_probe.fetch(),
    # so this closes the same TOCTOU window schemathesis-mcp already has.
    extra_hosts, pin_err = scope_guard.pin_hosts_or_error(target)
    if pin_err:
        return {"error": f"BLOCKED by scope gate: {pin_err}"}

    if not templates_pin.templates_available():
        return {"error": templates_pin.missing_templates_error()}

    # -duc: without it nuclei still attempts an outbound network update
    # check on every run even though -t already points at a local,
    # non-default directory -- see templates_pin.py's module docstring.
    # P3-H4: the scan-identification header, if the active engagement
    # configures one for this exact target (scan_headers.py enforces the
    # destination boundary itself -- [] for anything out of scope).
    full_args = [*args, "-duc", *scan_headers.get_scan_header_args(target)]
    return {
        "args": full_args,
        "max_wall_seconds": timeout,
        "extra_mounts": [templates_pin.TEMPLATES_DIR],
        "extra_hosts": extra_hosts or None,
    }


def _start(target: str, args: list[str], timeout: int, no_findings_message: str) -> str:
    prepared = _prepare(target, args, no_findings_message, timeout)
    if "error" in prepared:
        return prepared["error"]

    try:
        result = job_runtime.start_job(
            "nuclei", prepared["args"], prepared["max_wall_seconds"], _jobs,
            extra_mounts=prepared["extra_mounts"],
            extra_hosts=prepared["extra_hosts"],
        )
    except FileNotFoundError:
        return ("Error: nuclei not found. Install with: "
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    except Exception as e:
        return f"Error: {e}"
    job_id = result["job_id"]
    _targets[job_id] = (target, no_findings_message)
    return (f"Started nuclei scan of {target} (job_id=\"{job_id}\"). "
            f"Poll check_scan(\"{job_id}\") until it reports status=done "
            f"(allow up to {timeout}s).")


def _split_targets(targets: str) -> list[str]:
    """Same splitting convention httpx-mcp's probe_hosts()/_split_domains()
    uses for its own multi-host string argument -- comma- OR
    newline-separated, blank entries dropped -- so a batch tool's
    `targets` argument behaves identically to that established
    convention rather than inventing a second one."""
    return [t.strip() for t in targets.replace(",", "\n").splitlines() if t.strip()]


def _format_batch_entry(target: str, entry: dict, no_findings_message: str) -> str:
    """Format one target's fanout result -- a terminal job_result the
    same way check_scan() formats a single-target result (findings +
    block_prefix()), a prepare_error by surfacing its error string
    directly, and a skipped_in_flight dedupe hit by saying so."""
    kind = entry.get("kind")
    if kind == "prepare_error":
        return f"  {target}: {entry['error']}"
    if kind == "skipped_in_flight":
        return f"  {target}: skipped -- already in progress elsewhere"
    if kind == "job_result":
        if entry.get("status") == "timeout":
            return f"  {target}: {entry.get('error', 'nuclei timed out')}"
        formatted = _format_findings(
            target, no_findings_message, entry.get("stdout", ""),
            entry.get("returncode", -1), entry.get("stderr", ""),
        )
        return f"  {job_runtime.block_prefix(entry)}{target}: {formatted}"
    return f"  {target}: {entry}"


def _format_batch_start(snapshot: dict, no_findings_message: str) -> str:
    batch_id = snapshot["batch_id"]
    lines = []
    if snapshot["status"] == "done":
        lines.append(f'Batch complete (batch_id="{batch_id}") -- every target resolved immediately.')
    else:
        n_running = len(snapshot["in_flight"])
        n_pending = len(snapshot["pending"])
        lines.append(
            f'Started nuclei batch scan (batch_id="{batch_id}"): {n_running} running, '
            f'{n_pending} pending. Poll check_batch("{batch_id}") until status is done.'
        )
    for target, entry in snapshot["results"].items():
        lines.append(_format_batch_entry(target, entry, no_findings_message))
    return "\n".join(lines)


def _format_batch_check(batch_id: str, snapshot: dict, no_findings_message: str) -> str:
    lines = []
    for target, entry in snapshot["results"].items():
        lines.append(_format_batch_entry(target, entry, no_findings_message))
    if snapshot["status"] == "running":
        n_in_flight = len(snapshot["in_flight"])
        n_pending = len(snapshot["pending"])
        lines.append(
            f"Still running -- {n_in_flight} in flight, {n_pending} pending. Poll again shortly."
        )
    else:
        lines.insert(0, f'Batch {batch_id} complete:')
    return "\n".join(lines)


def _start_batch(targets: str, build_args, no_findings_message: str, timeout: int) -> str:
    target_list = _split_targets(targets)
    if not target_list:
        return f"Error: {targets!r} contains no usable targets"

    def prepare(target: str) -> dict:
        return _prepare(target, build_args(target), no_findings_message, timeout)

    snapshot = fanout.start_batch("nuclei", target_list, prepare, _batches, _jobs)
    batch_id = snapshot["batch_id"]
    if snapshot["status"] == "running":
        _batch_no_findings[batch_id] = no_findings_message
    return _format_batch_start(snapshot, no_findings_message)


@app.tool()
def scan_target(target: str, severity: str = "medium,high,critical", timeout: int = 300) -> str:
    """Start nuclei's full default template set against `target`, filtered
    to `severity` (comma-separated: info,low,medium,high,critical --
    default "medium,high,critical"), in the background -- returns
    immediately with a job_id since a full-template run can take longer
    than an MCP client's own per-call timeout. Poll check_scan(job_id) for
    the result. Runs the complete pinned nuclei-templates library (see
    templates_pin.py) -- use scan_with_templates() instead to run a
    specific template/category rather than everything at that severity."""
    args = ["-u", target, "-severity", severity, "-silent", "-jsonl",
            "-t", templates_pin.TEMPLATES_DIR]
    return _start(target, args, timeout, f"No vulnerabilities found on {target} (severity: {severity}).")


@app.tool()
def scan_with_templates(target: str, templates: str, timeout: int = 300) -> str:
    """Run specific nuclei template(s) against `target` instead of the full
    default set. `templates` is nuclei's own -t syntax: a path relative to
    the pinned nuclei-templates snapshot (e.g. "http/exposed-panels" or
    "http/cves/2021"), or an absolute path -- but only if it resolves
    INSIDE that same pinned snapshot (only the snapshot is mounted into
    the sandbox, so an absolute path outside it can never actually be
    found there); or a comma-separated list of either. Also backgrounded
    -- poll check_scan(job_id) for the result."""
    try:
        resolved = _resolve_templates_arg(templates)
    except ValueError as e:
        return f"Error: {e}"
    args = ["-u", target, "-t", resolved, "-silent", "-jsonl"]
    return _start(target, args, timeout, "No vulnerabilities found with the specified templates.")


@app.tool()
def scan_batch_target(targets: str, severity: str = "medium,high,critical", timeout: int = 300) -> str:
    """Like scan_target(), but against several targets at once. `targets`
    is a single string of one or more hosts, comma- or newline-separated
    (e.g. "a.example.com,b.example.com" or "a.example.com\\nb.example.com")
    -- NOT a list, same convention as httpx-mcp's probe_hosts(domains,
    ...). Runs are bounded and backgrounded via fanout -- only a handful
    of targets scan concurrently at once (the rest queue), and each
    target is still individually scope-gated and deduped against any
    other in-progress work on it. Returns immediately with a batch_id;
    poll check_batch(batch_id) until it reports status=done."""
    def build_args(target: str) -> list[str]:
        return ["-u", target, "-severity", severity, "-silent", "-jsonl",
                "-t", templates_pin.TEMPLATES_DIR]
    no_findings_message = f"No vulnerabilities found (severity: {severity})."
    return _start_batch(targets, build_args, no_findings_message, timeout)


@app.tool()
def scan_batch_with_templates(targets: str, templates: str, timeout: int = 300) -> str:
    """Like scan_with_templates(), but against several targets at once --
    the same specific template(s) run against every target in `targets`
    (a single comma/newline-separated string, same convention as
    scan_batch_target() and httpx-mcp's probe_hosts()). Bounded and
    backgrounded the same way scan_batch_target() is -- poll
    check_batch(batch_id) for results."""
    try:
        resolved = _resolve_templates_arg(templates)
    except ValueError as e:
        return f"Error: {e}"

    def build_args(target: str) -> list[str]:
        return ["-u", target, "-t", resolved, "-silent", "-jsonl"]
    no_findings_message = "No vulnerabilities found with the specified templates."
    return _start_batch(targets, build_args, no_findings_message, timeout)


@app.tool()
def check_batch(batch_id: str) -> str:
    """Poll a batch started by scan_batch_target()/
    scan_batch_with_templates(). Returns "Still running" with how many
    targets are still in flight/pending while the batch is incomplete, or
    each target's findings (formatted the same way check_scan() formats a
    single-target result) once every target in the batch has a terminal
    result. Keep polling every ~10-15s until it stops saying "running"."""
    no_findings_message = _batch_no_findings.get(batch_id, "No vulnerabilities found.")
    snapshot = fanout.check_batch(batch_id, _batches, _jobs)
    if "error" in snapshot:
        return snapshot["error"]
    text = _format_batch_check(batch_id, snapshot, no_findings_message)
    if snapshot["status"] == "done":
        _batch_no_findings.pop(batch_id, None)
    return text


@app.tool()
def check_scan(job_id: str) -> str:
    """Poll a scan started by scan_target()/scan_with_templates(). Returns
    "status: running (Xs elapsed)" while nuclei is still working, or the
    same findings-formatted text those tools used to return directly once
    it's done. Keep polling every ~10-15s until it stops saying
    "running"."""
    result = job_runtime.poll_job(job_id, _jobs)
    if "status" not in result:
        # Only the true "no such job" case has no status key at all --
        # a "timeout" status also carries an "error" key (alongside
        # stdout/stderr/elapsed_s), and must fall through to the
        # cleanup below rather than returning early and leaking it.
        return result["error"]

    if result["status"] == "running":
        return f"Still running -- {result['elapsed_s']}s elapsed so far. Poll again shortly."

    target, no_findings_message = _targets.pop(job_id, ("target", "No vulnerabilities found."))
    if result["status"] == "timeout":
        return result["error"]
    formatted = _format_findings(target, no_findings_message, result["stdout"], result["returncode"], result["stderr"])
    # C1a: invocation-level provenance -- "which tool ran, against what"
    # is honestly claimable here even though the real HTTP exchange
    # happened inside nuclei's own process, invisible to this server.
    # Unlike wire-level provenance (method+url of a real request this
    # process itself made), class="invocation" only requires "tool" per
    # case_store._validate_provenance() -- "target" is additional, still
    # honest context already tracked in _targets, not a fabricated claim.
    provenance = {"class": "invocation", "tool": "nuclei", "target": target}
    return f"{job_runtime.block_prefix(result)}{formatted}\n\nProvenance (for case-mcp add_evidence): {json.dumps(provenance)}"


@app.tool()
def list_scans() -> str:
    """List nuclei scans still running in this session -- job_id, target,
    elapsed time, and whether a scan has been running long enough
    (30+ min) that it's likely been abandoned rather than genuinely still
    busy."""
    jobs = job_runtime.list_jobs(_jobs)
    if not jobs:
        return "No nuclei scans currently running."
    lines = ["Running nuclei scans:", ""]
    for j in jobs:
        target, _ = _targets.get(j["job_id"], ("?", ""))
        marker = " [LIKELY ABANDONED]" if j["likely_abandoned"] else ""
        lines.append(f"  {j['job_id']}  {target}  {j['elapsed_s']}s{marker}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("nuclei-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
