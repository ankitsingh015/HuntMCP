"""State reader for the HuntMCP dev-runner.

Parses the persistent project-state documents into typed objects:

* ``parse_plan`` / ``load_plan`` -> a :class:`Plan` of :class:`Task` objects,
  derived from the ``PHASE1-EXECUTION-PLAN.md`` task table.
* ``parse_project_state`` -> the ROADMAP ``PROJECT STATE`` block as a dict.

The reader is deliberately tolerant of the two field styles the real plan mixes
(``| deps: none | files: ... |`` and bare ``| A4 | file.py |``) and of dependency
ranges like ``C3..C7``. It performs **no** interpretation of what to do next --
that is the resolver's job. This module only reads; it never writes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Marker char -> human-readable status name.
_MARKER_TO_STATUS = {
    " ": "pending",
    "x": "complete",
    "~": "in_progress",
    "!": "blocked",
}

# A task line looks like:  - [x] **C6** — description | dep | file | verify: v | accept: a. **DONE ...**
# Only lines that start (after optional whitespace) with "- [<marker>] **ID**" are tasks;
# legend / prose lines that merely mention `[ ]` inside backticks are ignored.
_TASK_RE = re.compile(r"^\s*-\s*\[([ x~!])\]\s*\*\*([A-Za-z][A-Za-z0-9]*)\*\*\s*(.*)$")

# Task-id token, and a same-letter range like C3..C7.
_ID_RE = re.compile(r"[A-Za-z]\d+")
_RANGE_RE = re.compile(r"([A-Za-z])(\d+)\s*\.\.\s*([A-Za-z]?)(\d+)")


class PlanNotFoundError(FileNotFoundError):
    """Raised when the plan file cannot be read. Callers treat this as BLOCKED."""


@dataclass
class Task:
    id: str
    marker: str
    status: str
    title: str
    deps: list[str]
    files: list[str]
    verify: str
    accept: str
    line_no: int
    raw: str
    has_done_note: bool
    deps_all: bool = False


@dataclass
class Plan:
    tasks: list[Task] = field(default_factory=list)
    duplicate_ids: list[str] = field(default_factory=list)
    source_path: str | None = None

    def get(self, task_id: str) -> Task | None:
        for t in self.tasks:
            if t.id == task_id:
                return t
        return None


def _expand_deps(dep_field: str) -> list[str]:
    """Turn a raw deps field into an ordered, de-duplicated list of task ids.

    Handles ``none``/``-``/empty, checkmarks, comma lists, and same-letter
    ranges (``C3..C7`` -> C3,C4,C5,C6,C7).
    """
    txt = dep_field.strip()
    if not txt or txt.lower() in {"none", "-", "n/a"}:
        return []

    result: list[str] = []

    def _add(tid: str) -> None:
        if tid not in result:
            result.append(tid)

    # Expand ranges first, recording their positions so we don't double-count
    # the endpoints via the plain-id scan.
    consumed_spans: list[tuple[int, int]] = []
    for m in _RANGE_RE.finditer(txt):
        letter, lo, rletter, hi = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        end_letter = rletter or letter
        if end_letter == letter and hi >= lo:
            for n in range(lo, hi + 1):
                _add(f"{letter}{n}")
            consumed_spans.append(m.span())

    def _in_range(pos: int) -> bool:
        return any(s <= pos < e for s, e in consumed_spans)

    for m in _ID_RE.finditer(txt):
        if _in_range(m.start()):
            continue
        _add(m.group(0))
    return result


def _split_files(files_field: str) -> list[str]:
    txt = files_field.strip()
    if not txt or txt in {"-", "—"} or txt.lower() in {"none", "n/a", "this doc"}:
        # "this doc" / "-" carry no actionable file target.
        return []
    return [p.strip() for p in txt.split(",") if p.strip()]


def _strip_label(value: str, label: str) -> str:
    v = value.strip()
    low = v.lower()
    if low.startswith(label + ":"):
        return v[len(label) + 1 :].strip()
    return v


def _parse_task_line(marker: str, task_id: str, rest: str, line_no: int, raw: str) -> Task:
    # Separate the trailing completion note (bold **DONE ...** / **... DONE ...**).
    has_done_note = bool(re.search(r"\*\*[^*]*\b(DONE|COMPLETE)\b", rest))

    # Split into pipe fields. The first field is the human description; the
    # remaining fields are metadata (deps/files/verify/accept), each optionally
    # label-prefixed.
    parts = [p.strip() for p in rest.split("|")]
    # Title: strip a leading em/en dash the plan uses after the id.
    title = parts[0].lstrip("—-–").strip()
    # Remove any trailing bold completion note from the title itself.
    title = re.split(r"\s\*\*", title)[0].strip()

    meta = parts[1:]

    deps_field = ""
    files_field = ""
    verify = ""
    accept = ""

    deps_all = False
    positional: list[str] = []
    for f in meta:
        low = f.lower()
        if low.startswith("deps:"):
            deps_field = _strip_label(f, "deps")
        elif low.startswith("files:"):
            files_field = _strip_label(f, "files")
        elif low.startswith("verify:"):
            verify = _strip_label(f, "verify")
        elif low.startswith("accept:"):
            # accept may itself carry the trailing **DONE** note; drop it.
            acc = _strip_label(f, "accept")
            accept = re.split(r"\s\*\*", acc)[0].strip()
        else:
            positional.append(f)

    # Assign unlabeled positional fields: first -> deps, second -> files
    # (only if not already provided by a labeled field).
    if not deps_field and positional:
        deps_field = positional.pop(0)
    if not files_field and positional:
        files_field = positional.pop(0)

    if deps_field.strip().lower() == "all":
        deps_all = True

    return Task(
        id=task_id,
        marker=marker,
        status=_MARKER_TO_STATUS[marker],
        title=title,
        deps=_expand_deps(deps_field),
        files=_split_files(files_field),
        verify=verify.strip(),
        accept=accept.strip().rstrip("."),
        line_no=line_no,
        raw=raw.rstrip("\n"),
        has_done_note=has_done_note,
        deps_all=deps_all,
    )


def parse_plan(text: str) -> Plan:
    plan = Plan()
    seen: dict[str, int] = {}
    for i, raw in enumerate(text.splitlines(), start=1):
        m = _TASK_RE.match(raw)
        if not m:
            continue
        marker, task_id, rest = m.group(1), m.group(2), m.group(3)
        task = _parse_task_line(marker, task_id, rest, i, raw)
        if task_id in seen and task_id not in plan.duplicate_ids:
            plan.duplicate_ids.append(task_id)
        seen[task_id] = i
        plan.tasks.append(task)

    # Second pass: a task whose deps field was the literal "all" depends on
    # every other task in the plan (real plan uses this for final gate tasks
    # O1/P1). Resolve it now that every id is known so it never looks
    # prematurely actionable.
    all_ids = [t.id for t in plan.tasks]
    for t in plan.tasks:
        if t.deps_all:
            t.deps = [tid for tid in all_ids if tid != t.id]
    return plan


def load_plan(path: str) -> Plan:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (FileNotFoundError, IsADirectoryError) as exc:
        raise PlanNotFoundError(str(path)) from exc
    plan = parse_plan(text)
    plan.source_path = path
    return plan


_PROJECT_STATE_HDR_RE = re.compile(r"^#+\s*PROJECT STATE\s*$", re.IGNORECASE | re.MULTILINE)


def parse_project_state(roadmap_text: str) -> dict[str, str]:
    """Return the ROADMAP ``PROJECT STATE`` fenced block as ``{FIELD: value}``.

    Returns ``{}`` when no such block exists.
    """
    hdr = _PROJECT_STATE_HDR_RE.search(roadmap_text)
    if not hdr:
        return {}
    after = roadmap_text[hdr.end():]
    fence = re.search(r"```(.*?)```", after, re.DOTALL)
    if not fence:
        return {}
    body = fence.group(1)
    result: dict[str, str] = {}
    current_key: str | None = None
    for line in body.splitlines():
        m = re.match(r"^([A-Z][A-Z /()a-z0-9]+?):\s*(.*)$", line)
        if m:
            current_key = m.group(1).strip()
            result[current_key] = m.group(2).strip()
        elif current_key and line.strip():
            # continuation line for a multi-line value
            result[current_key] = (result[current_key] + " " + line.strip()).strip()
    return result


def set_task_status(text: str, task_id: str, marker: str) -> str:
    """Return ``text`` with ``task_id``'s status marker replaced by ``marker``.

    This is the plan-write a **session** performs to record its own progress
    (e.g. flipping ``[ ]``/``[~]`` to ``[x]`` after completing a task). The
    supervisor never calls this -- it only reads and independently verifies. The
    rest of the task line (deps/files/verify/accept/notes) is preserved verbatim.

    Raises ``ValueError`` for an invalid marker or a duplicate task id, and
    ``KeyError`` when the task id is absent.
    """
    if marker not in _MARKER_TO_STATUS:
        raise ValueError(f"invalid marker {marker!r}; expected one of {list(_MARKER_TO_STATUS)}")

    lines = text.splitlines(keepends=True)
    matches = []
    for i, raw in enumerate(lines):
        m = _TASK_RE.match(raw)
        if m and m.group(2) == task_id:
            matches.append(i)
    if not matches:
        raise KeyError(task_id)
    if len(matches) > 1:
        raise ValueError(f"duplicate task id {task_id!r}; refusing ambiguous status write")

    idx = matches[0]
    # Replace only the first "[<marker>]" occurrence on the line.
    lines[idx] = re.sub(r"\[[ x~!]\]", f"[{marker}]", lines[idx], count=1)
    return "".join(lines)
