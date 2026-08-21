"""Read/write chat-logs/lessons-learned.md — the private, gitignored,
cross-target Lessons Registry. This is deliberately NOT a database: it's a
flat, rg-able markdown file so any model can grep a class instead of loading
the whole thing (see the CONTEXT BUDGET rules in
knowledge/master-pentest-prompt.md).

Real content here is target-specific and never belongs in version control —
see knowledge/lessons-learned-template.md for the schema this mirrors.
"""

from __future__ import annotations

import os
import re
from datetime import date

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
LESSONS_PATH = os.getenv(
    "HUNTMCP_LESSONS_PATH",
    os.path.join(REPO_ROOT, "chat-logs", "lessons-learned.md"),
)

SIZE_CAP_LINES = 400

_HEADER = """# Lessons Learned — Confirmed-Finding Registry (Self-Improving)

> Real, private engagement data. NEVER commit this file — see .gitignore
> and knowledge/lessons-learned-template.md for why. Read at the start of
> every engagement (Phase 0.8 of knowledge/master-pentest-prompt.md);
> appended to after every confirmed finding or closed false positive.
>
> Format per entry:
> VULN | CWE | target | method-that-found-it | key request/payload |
> impact chain | bypasses | result (paid/confirmed/closed-FP)
>
> Severity honesty rule: record the REAL severity a strict triager would
> assign -- never inflate. Cap ~{cap} lines; when exceeded, move oldest/
> duplicate entries to chat-logs/lessons-archive-<YYYY>.md (archive, never
> delete).

---
""".format(cap=SIZE_CAP_LINES)


def _ensure_file() -> None:
    os.makedirs(os.path.dirname(LESSONS_PATH), exist_ok=True)
    if not os.path.isfile(LESSONS_PATH):
        with open(LESSONS_PATH, "w") as f:
            f.write(_HEADER)


def list_class_headers() -> list[str]:
    """Just the '## Class N — ...' headers -- the cheap skim the CONTEXT
    BUDGET rules call for before deciding what to load in full."""
    _ensure_file()
    with open(LESSONS_PATH) as f:
        content = f.read()
    return re.findall(r"^## .+$", content, re.MULTILINE)


def append_lesson(
    vuln_class: str,
    target: str,
    method: str,
    result: str,
    payload: str = "",
    impact: str = "",
    severity: str = "",
    bypasses: str = "",
    cwe: str = "",
) -> str:
    """Append one confirmed finding (or closed false positive) under the
    matching '## <vuln_class>' section, creating it if it doesn't exist yet.
    This is the write-back step from Phase 0.8/PERSISTENCE rules -- it must
    be an actual tool call, not something an agent remembers to hand-edit,
    or it silently gets skipped under time pressure.
    """
    _ensure_file()
    with open(LESSONS_PATH) as f:
        content = f.read()

    today = date.today().isoformat()
    sev_tag = f", {severity}" if severity else ""
    cwe_tag = f"{cwe} | " if cwe else ""

    lines = [
        f"- **{vuln_class}**",
        f"  {cwe_tag}{target} ({today}{sev_tag})",
        f"  Method: {method}",
    ]
    if payload:
        lines.append(f"  Payload: {payload}")
    if bypasses:
        lines.append(f"  Bypasses: {bypasses}")
    if impact:
        lines.append(f"  Impact: {impact}")
    lines.append(f"  Result: {result}")
    entry = "\n".join(lines) + "\n"

    # find an existing section whose header contains this vuln_class (case-insensitive)
    headers = list(re.finditer(r"^## (.+)$", content, re.MULTILINE))
    target_section = None
    for h in headers:
        if vuln_class.lower() in h.group(1).lower():
            target_section = h
            break

    if target_section:
        # insert right after the section header (and its blurb line, if any),
        # before the next "## " header or the TOOLS/SCRIPTS separator
        insert_at = target_section.end()
        next_header = re.search(r"\n## ", content[insert_at:])
        insert_at = insert_at + next_header.start() if next_header else len(content)
        new_content = content[:insert_at].rstrip() + "\n" + entry + "\n" + content[insert_at:].lstrip("\n")
    else:
        next_class_num = len(headers) + 1
        new_content = (
            content.rstrip()
            + f"\n\n## Class {next_class_num} — {vuln_class}\n\n"
            + entry
        )

    with open(LESSONS_PATH, "w") as f:
        f.write(new_content)

    line_count = new_content.count("\n") + 1
    warning = ""
    if line_count > SIZE_CAP_LINES:
        warning = (
            f"\n\nWARNING: {LESSONS_PATH} is now {line_count} lines, over the "
            f"{SIZE_CAP_LINES}-line cap. Move oldest/duplicate entries to "
            f"chat-logs/lessons-archive-<YYYY>.md before the next engagement "
            f"(archive, never delete)."
        )
    return f"Appended to {LESSONS_PATH} under '{vuln_class}'.{warning}"


def read_lessons(keyword: str = "") -> str:
    """No keyword -> return just the class headers (cheap skim). With a
    keyword -> return only the matching class block(s), never the whole
    file -- matches the Phase 0.8.1 keyword-lookup rule."""
    _ensure_file()
    with open(LESSONS_PATH) as f:
        content = f.read()

    if not keyword:
        headers = list_class_headers()
        if not headers:
            return "Lessons registry is empty — no engagements recorded yet."
        return "Class headers (call read_lessons(keyword=...) to load one):\n" + "\n".join(headers)

    sections = re.split(r"(?=^## )", content, flags=re.MULTILINE)
    matches = [s for s in sections if keyword.lower() in s.lower()]
    if not matches:
        return f"No lessons match keyword {keyword!r}."
    return "\n---\n".join(m.strip() for m in matches)


def check_size() -> str:
    _ensure_file()
    with open(LESSONS_PATH) as f:
        line_count = sum(1 for _ in f)
    status = "OVER CAP — archive oldest entries" if line_count > SIZE_CAP_LINES else "OK"
    return f"{LESSONS_PATH}: {line_count} lines (cap {SIZE_CAP_LINES}) — {status}"
