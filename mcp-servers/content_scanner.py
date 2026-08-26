"""Lightweight safety scan for agent-authored (or human-authored) skill and
MCP-server content, run against any new/changed `.claude/skills/*/SKILL.md`
or `mcp-servers/**/*.py` (ARCHITECTURE.md's "Scan agent-generated skills/
tools before trusting them" backlog item).

Why this exists now, ahead of full autonomous tool-authoring: the moment
any content in this repo can be authored by an agent rather than reviewed
by a human before being trusted (see tool_gaps.py for the bounded first
step toward that), it becomes a real, unreviewed attack surface -- prompt
injection hidden in a skill file, a supply-chain-risk pattern in a new MCP
server's code. This is deliberately a curated set of concrete, checkable
patterns (OWASP Skill/MCP Top 10-inspired), not a claim of exhaustive
coverage -- a lightweight net that catches the highest-confidence red
flags cheaply, not a substitute for actually reading new content before
trusting it.

Two scan targets, each with its own pattern set:
- scan_skill_file(path): plain-English markdown content -- checks for
  hidden/invisible Unicode (a known prompt-injection-smuggling technique),
  explicit prompt-injection-style phrasing, suspiciously large
  base64-looking blobs, and frontmatter hygiene (name matches directory,
  required fields present).
- scan_python_file(path): MCP-server/shared-module code -- checks for
  eval/exec/os.system/shell=True (rarely legitimate in this codebase's
  existing style -- tool_resolver.py's run_tool() always uses the list
  form, never a shell string), network calls to a literal hostname
  outside a small known-good allowlist, and env-var reads outside this
  repo's HUNTMCP_*/documented-provider-key naming convention.

CLI usage:
    python3 mcp-servers/content_scanner.py <path-or-glob> [<path-or-glob> ...]
    exit 0 -> no HIGH-severity findings (MEDIUM findings are printed but
              don't fail the exit code -- they're for human review, not an
              auto-reject)
    exit 1 -> at least one HIGH-severity finding
"""

from __future__ import annotations

import glob
import os
import re
import sys

# Hidden/invisible Unicode with no legitimate reason to appear in a plain
# English skill doc -- a documented technique for smuggling instructions
# that render invisibly to a human reviewer. Explicit \uXXXX escapes
# throughout, deliberately -- a literal invisible character inside this
# file's own source would be exactly as unreviewable as the thing this
# check exists to catch.
HIDDEN_UNICODE_RE = re.compile(
    "["
    "\u200b"  # zero-width space
    "\u200c"  # zero-width non-joiner
    "\u200d"  # zero-width joiner
    "\u200e"  # left-to-right mark
    "\u200f"  # right-to-left mark
    "\u202a-\u202e"  # bidi embedding/override controls
    "\u2060-\u2064"  # word joiner, invisible math operators
    "\ufeff"  # zero-width no-break space / BOM
    "]"
)

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+\w+.{0,40}(unrestricted|jailbroken|dan)", re.IGNORECASE),
    re.compile(r"new\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"do\s+not\s+(tell|inform|mention|alert)\s+the\s+user", re.IGNORECASE),
    re.compile(r"this\s+is\s+not\s+a\s+drill.{0,60}(execute|run|send)", re.IGNORECASE),
]

BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")

# Known-legitimate external hosts this codebase actually talks to (from the
# real MCP servers as of this scanner's writing) -- anything else literal
# gets flagged for review, not auto-rejected.
KNOWN_GOOD_HOSTS = {
    "raw.githubusercontent.com", "api.github.com", "github.com",
    "bug-bounty-disclosures.vercel.app",
    "services.nvd.nist.gov", "nvd.nist.gov",
    "api.hackerone.com", "hackerone.com",
    "hooks.slack.com",
}

NETWORK_CALL_RE = re.compile(
    r"(?:urllib\.request\.urlopen|requests\.(?:get|post|put|delete)|httpx\.(?:get|post))\s*\(\s*(['\"])([^'\"]+)\1"
)

DANGEROUS_CALL_RE = re.compile(
    # (?<!\.) excludes method calls like Java's Runtime.exec(...) or a
    # payload string describing one -- this repo's own chainer-mcp
    # legitimately contains example payload text like that. A bare
    # eval(/exec( (not preceded by a dot) is what Python's actual builtins
    # look like when really called.
    r"(?<!\.)\b(eval|exec)\s*\(|os\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True"
)

ENV_VAR_RE = re.compile(r"os\.(?:getenv|environ(?:\.get)?)\(\s*['\"]([A-Z0-9_]+)['\"]")
KNOWN_GOOD_ENV_PREFIXES = ("HUNTMCP_",)
KNOWN_GOOD_ENV_EXACT = {
    "HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY",
    "DATABASE_URL", "PATH", "HOME", "DISPLAY",
}


def _finding(severity: str, path: str, message: str) -> dict:
    return {"severity": severity, "path": path, "message": message}


def scan_skill_file(path: str) -> list[dict]:
    findings = []
    if not os.path.isfile(path):
        return [_finding("HIGH", path, "file not found")]

    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()

    hidden = HIDDEN_UNICODE_RE.findall(content)
    if hidden:
        findings.append(_finding(
            "HIGH", path,
            f"{len(hidden)} hidden/invisible Unicode character(s) found -- "
            "no legitimate reason for these in a plain-English skill doc",
        ))

    for pattern in PROMPT_INJECTION_PATTERNS:
        m = pattern.search(content)
        if m:
            findings.append(_finding(
                "HIGH", path,
                f"prompt-injection-style phrasing matched: {m.group(0)!r}",
            ))

    for m in BASE64_BLOB_RE.finditer(content):
        findings.append(_finding(
            "MEDIUM", path,
            f"large base64-looking blob ({len(m.group(0))} chars) -- review "
            "before trusting; may be a legitimate example payload/token",
        ))

    # Frontmatter is only a contract for the actual SKILL.md entry point --
    # supporting material next to it (references/*.md, a skill's own
    # README.md) legitimately has none, per this repo's own convention
    # (.claude/skills/<name>/{SKILL.md, references/}) and the same
    # convention observed in every other SKILL.md-based skill library
    # reviewed so far. Checking every *.md for frontmatter produced 27
    # false positives out of 33 findings when this scanner was first
    # pointed at an external repo with a references/ subdirectory
    # (2026-08-26) -- real signal (prompt-injection phrasing, hidden
    # Unicode, base64 blobs) still applies to those files above; only the
    # frontmatter-specific checks are scoped to SKILL.md itself.
    if os.path.basename(path) == "SKILL.md":
        fm_match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
        if not fm_match:
            findings.append(_finding("HIGH", path, "no YAML frontmatter found"))
        else:
            fm_text = fm_match.group(1)
            if "description:" not in fm_text:
                findings.append(_finding("HIGH", path, "frontmatter missing required 'description' field"))
            name_match = re.search(r"^name:\s*(\S+)", fm_text, re.MULTILINE)
            if name_match:
                dirname = os.path.basename(os.path.dirname(os.path.abspath(path)))
                if name_match.group(1).strip("'\"") != dirname:
                    findings.append(_finding(
                        "MEDIUM", path,
                        f"frontmatter name {name_match.group(1)!r} does not match directory name {dirname!r}",
                    ))

    return findings


def scan_python_file(path: str) -> list[dict]:
    findings = []
    if not os.path.isfile(path):
        return [_finding("HIGH", path, "file not found")]

    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()

    if DANGEROUS_CALL_RE.search(content):
        findings.append(_finding(
            "HIGH", path,
            "eval()/exec()/os.system()/subprocess(shell=True) found -- this "
            "codebase's convention is subprocess.run([binary, *args]), no "
            "shell string; review before trusting",
        ))

    for m in NETWORK_CALL_RE.finditer(content):
        url = m.group(2)
        host_match = re.match(r"https?://([^/]+)", url)
        host = host_match.group(1) if host_match else url
        if host not in KNOWN_GOOD_HOSTS and not url.startswith("http://127.0.0.1") \
                and not url.startswith("http://localhost") and "{" not in url:
            findings.append(_finding(
                "MEDIUM", path,
                f"network call to host not in the known-good allowlist: {host!r} -- "
                "review; may be a legitimate new integration",
            ))

    for m in ENV_VAR_RE.finditer(content):
        name = m.group(1)
        if name.startswith(KNOWN_GOOD_ENV_PREFIXES) or name in KNOWN_GOOD_ENV_EXACT:
            continue
        findings.append(_finding(
            "MEDIUM", path,
            f"reads env var {name!r} outside the HUNTMCP_*/known-provider-key "
            "convention -- review why this file needs it",
        ))

    return findings


# The scanner's own pattern definitions (this file) legitimately contain
# the substrings the DANGEROUS_CALL_RE pattern matches -- scanning itself
# would always self-flag on its own regex source, not a real risk.
SELF_EXCLUDE_BASENAME = "content_scanner.py"


def scan_path(path: str) -> list[dict]:
    if os.path.basename(path) == SELF_EXCLUDE_BASENAME:
        return []
    if path.endswith(".md"):
        return scan_skill_file(path)
    if path.endswith(".py"):
        return scan_python_file(path)
    return []


def _cli() -> None:
    if len(sys.argv) < 2:
        print("usage: content_scanner.py <path-or-glob> [<path-or-glob> ...]", file=sys.stderr)
        sys.exit(2)

    paths: list[str] = []
    for arg in sys.argv[1:]:
        matched = glob.glob(arg, recursive=True)
        paths.extend(matched if matched else [arg])

    all_findings = []
    for path in sorted(set(paths)):
        all_findings.extend(scan_path(path))

    if not all_findings:
        print(f"Scanned {len(paths)} file(s). No findings.")
        sys.exit(0)

    high = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] == "MEDIUM"]

    for f in all_findings:
        print(f"[{f['severity']}] {f['path']}: {f['message']}")

    print(f"\n{len(high)} HIGH, {len(medium)} MEDIUM finding(s) across {len(paths)} file(s).")
    sys.exit(1 if high else 0)


if __name__ == "__main__":
    _cli()
