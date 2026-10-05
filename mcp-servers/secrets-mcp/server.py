"""Secrets/credential scanning (Phase 2.8 backlog).

Wraps gitleaks over a local directory -- katana-crawled JS, a downloaded
.git/.env, any files already pulled to disk by recon/scan -- to find
exposed API keys, tokens, and credentials. Operates on local files only,
no live network requests of its own, so it isn't a Tier-2 (target-
touching) action itself -- whatever crawled the files into that directory
already went through the scope gate.

Also exposes extract_endpoints() (added 2026-08-29, js_endpoints.py) --
the same local-directory scan, but for API route candidates instead of
credentials. Complementary, not overlapping: run both against the same
downloaded-JS directory, one for what the app talks to, one for what
secrets it's leaking while doing it.
"""

import base64
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tool_resolver import run_tool  # noqa: E402

import js_endpoints
import source_map
from mcp.server.fastmcp import FastMCP

app = FastMCP("secrets-mcp")

# Frontend build tools inline env vars carrying one of these prefixes
# straight into the shipped JS bundle BY DESIGN -- they're intentionally
# public (feature flags, allowlisted IDs, publishable-only keys), not
# leaked secrets. gitleaks has no framework awareness and flags them at a
# high rate on any Vite/CRA/Next/Gatsby/Expo target (confirmed live: 17/17
# "secrets" on one real engagement were VITE_-prefixed public constants).
# Never dropped outright -- just labeled and sorted last, so a real high-
# confidence secret in the same scan isn't buried under this noise.
_PUBLIC_BUILD_ENV_PREFIXES = re.compile(
    r"\b(VITE_|NEXT_PUBLIC_|REACT_APP_|GATSBY_|EXPO_PUBLIC_|PUBLIC_)[A-Z0-9_]*\s*=",
)


@app.tool()
def scan_directory(path: str, redact: bool = True) -> str:
    """Scan a local directory (e.g. katana-mcp's crawl output, a saved
    .git/.env dump) for exposed secrets with gitleaks. Not a live-target
    action -- operates on files already on disk."""
    if not os.path.isdir(path):
        return f"Error: {path!r} is not a directory."

    # S5 (rootless sandboxing): gitleaks now runs inside an ephemeral
    # container that sees NOTHING from the host by default -- both `path`
    # (the directory being scanned, read-only via extra_mounts=) and the
    # report file's directory (read-write via extra_mounts_rw=, since
    # gitleaks must WRITE its report there) must be explicitly declared,
    # or gitleaks can neither read the target directory nor have its
    # output survive the container's teardown.
    #
    # The report is written into a real, pre-existing DIRECTORY (mkdtemp),
    # not a single mkstemp()'d-then-unlinked file -- a path that doesn't
    # exist yet can't be usefully declared as a mount target ahead of
    # time. (Found in review: the previous mkstemp()+unlink() version
    # relied on the sandbox layer auto-detecting report_path as an
    # existing file at build_argv() time, which it never was -- gitleaks
    # silently wrote its report inside the container's own private tmpfs
    # instead, and every scan_directory() call reported "No findings"
    # regardless of what gitleaks actually found.)
    report_dir = tempfile.mkdtemp(prefix="huntmcp-gitleaks-")
    report_path = os.path.join(report_dir, "report.json")

    args = [
        "detect", "--no-git", "--source", path,
        "--report-format", "json", "--report-path", report_path,
        "--exit-code", "0",
    ]
    if redact:
        args.append("--redact")

    try:
        try:
            result = run_tool(
                "gitleaks", args, retry_on_rate_limit=False, timeout=120,
                extra_mounts=[path], extra_mounts_rw=[report_dir],
            )
        except FileNotFoundError:
            return "Error: gitleaks not found. Install with: go install github.com/zricethezav/gitleaks/v8@latest"
        except Exception as e:
            return f"Error: {e}"

        if result.returncode != 0:
            return f"gitleaks failed (exit {result.returncode}): {result.stderr.strip()[:500]}"

        if not os.path.isfile(report_path):
            return "No findings (gitleaks produced no report)."
        with open(report_path) as f:
            findings = json.load(f)
    finally:
        shutil.rmtree(report_dir, ignore_errors=True)

    if not findings:
        return f"No secrets found in {path!r}."

    def _fmt(f: dict) -> str:
        return (
            f"  [{f.get('RuleID', '?')}] {f.get('File', '?')}:{f.get('StartLine', '?')} "
            f"-- {f.get('Match', f.get('Secret', '(redacted)'))[:80]}"
        )

    likely_public, real = [], []
    for f in findings:
        needle = f.get("Match") or f.get("Secret") or ""
        (likely_public if _PUBLIC_BUILD_ENV_PREFIXES.search(needle) else real).append(f)

    lines = [f"{len(findings)} potential secret(s) found in {path!r}:"]
    if real:
        lines.append(f"\n{len(real)} to actually investigate:")
        lines.extend(_fmt(f) for f in real)
    if likely_public:
        lines.append(
            f"\n{len(likely_public)} likely PUBLIC build-time env var(s) "
            "(VITE_/NEXT_PUBLIC_/REACT_APP_/etc. -- shipped to the client "
            "by design, verify manually before treating as a leak):"
        )
        lines.extend(_fmt(f) for f in likely_public)
    return "\n".join(lines)


@app.tool()
def extract_endpoints(path: str, max_results: int = 500) -> str:
    """Scan a local directory (e.g. recon-agent's own downloaded-JS
    directory, data/engagements/<slug>/downloads/) for API-route
    candidates -- every "/api/...", "/v1/...", "/graphql", etc.-shaped
    string literal found across all .js/.ts/.jsx/.tsx files, deduped,
    with route-parameter names extracted (":id"/"{id}"/"[id]" style) and
    the source file(s) each one was found in. Regex-based candidate
    extraction, not verified ground truth -- treat results the same way
    subfinder/httpx/katana's own output is treated, as a list worth
    checking, not a guarantee every entry is a real, reachable endpoint.
    Not a live-target action -- operates on files already on disk, same
    as scan_directory()."""
    if not os.path.isdir(path):
        return f"Error: {path!r} is not a directory."

    inventory = js_endpoints.scan_directory_for_endpoints(path, max_results=max_results)
    if not inventory:
        return f"No API-route-shaped string literals found in {path!r}."

    lines = [f"{len(inventory)} candidate endpoint(s) found in {path!r}:"]
    for endpoint in sorted(inventory):
        params = js_endpoints.extract_params(endpoint)
        sources = inventory[endpoint]
        param_note = f" (params: {', '.join(params)})" if params else ""
        source_note = sources[0] if len(sources) == 1 else f"{sources[0]} +{len(sources) - 1} more"
        lines.append(f"  {endpoint}{param_note} -- {source_note}")
    return "\n".join(lines)


@app.tool()
def find_source_map_reference(js_file_path: str) -> str:
    """Check an already-downloaded JS bundle (e.g. recon-agent's own
    curl'd file under data/engagements/<slug>/downloads/) for a
    sourceMappingURL comment. Returns the fetchable URL/filename to curl
    next, the conventional ".map"-appended guess if no comment was found
    at all, or a note that the map is embedded inline (data: URI, no
    second fetch needed -- pass the JS file itself to recover_source_map()
    instead). Not a live-target action -- reads the already-downloaded
    file, same contract as scan_directory()/extract_endpoints() above;
    fetching the map file itself is an ordinary curl call, already
    Tier-2 scope-gated."""
    if not os.path.isfile(js_file_path):
        return f"Error: {js_file_path!r} is not a file."
    with open(js_file_path, errors="replace") as f:
        text = f.read()

    inline = source_map.find_inline_data_uri_map(text)
    if inline is not None:
        return (
            "Source map is embedded INLINE (data: URI) in this file itself -- "
            f"no second fetch needed. Pass {js_file_path!r} directly to "
            "recover_source_map()."
        )

    found = source_map.find_source_mapping_url(text)
    if found is not None:
        return f"sourceMappingURL found: {found}"

    return (
        "No sourceMappingURL comment found. Conventional guess (verify by "
        f"fetching, may 404): {js_file_path}.map"
    )


@app.tool()
def recover_source_map(map_file_path: str, output_dir: str) -> str:
    """Parse an already-downloaded .map file (or a JS file carrying an
    inline data: URI map, per find_source_map_reference()'s own note) and
    write every recovered source file under output_dir -- then run
    scan_directory()/extract_endpoints() on THAT directory to get the
    same secret/endpoint scanning this file already provides, over the
    full unminified source instead of the minified bundle alone. Not a
    live-target action -- operates on an already-downloaded file, same
    contract as every other tool in this file. Every recovered path is
    confirmed to resolve inside output_dir before writing (source_map.py's
    own path-confinement check) -- a source map's own "sources" array is
    attacker-influenced content the target served, never trusted as a
    literal filesystem path."""
    if not os.path.isfile(map_file_path):
        return f"Error: {map_file_path!r} is not a file."
    with open(map_file_path, errors="replace") as f:
        raw = f.read()

    # Accept either a real .map file's raw JSON, or a JS file whose
    # sourceMappingURL comment held an inline data: URI -- decode that
    # case down to the same raw JSON parse_source_map() expects.
    inline = source_map.find_inline_data_uri_map(raw)
    if inline is not None:
        header, _, encoded = inline.partition(",")
        try:
            # Code-review finding #8: a data: URI's non-base64 form (no
            # `;base64` token in the header, per RFC 2397) is
            # PERCENT-encoded, not raw JSON -- using `encoded` directly
            # silently lost every inline map that wasn't base64.
            raw = (base64.b64decode(encoded).decode(errors="replace")
                   if ";base64" in header else urllib.parse.unquote(encoded))
        except (ValueError, TypeError) as e:
            return f"Error: could not decode inline data: URI map: {e}"

    parsed = source_map.parse_source_map(raw)
    if "error" in parsed:
        return f"Error: {parsed['error']}"
    if not parsed["recovered"]:
        return "Source map parsed, but sourcesContent had nothing recoverable."

    written = source_map.write_recovered_sources(parsed, output_dir)
    return (
        f"Recovered {len(written)} source file(s) to {output_dir!r}. "
        f"Run scan_directory({output_dir!r}) and extract_endpoints({output_dir!r}) "
        "next for secrets/endpoints over the full unminified source."
    )


if __name__ == "__main__":
    print("secrets-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
