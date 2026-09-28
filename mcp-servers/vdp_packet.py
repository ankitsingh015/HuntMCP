"""VDP submission-packet helper -- shapes one finding's report content into
a per-finding, character-limited, unambiguously-labeled summary for a
self-run vulnerability-disclosure-program form (no API, arbitrary
character/upload constraints, one finding submitted at a time by hand).

Why this exists: report-agent's normal output is a long markdown package
assuming a structured platform submission (HackerOne/Bugcrowd), but a
self-run VDP's own web form often imposes a hard character limit on the
description field -- reported live in an engagement retrospective: several
candidate descriptions were over a 1000-character limit and had to be
manually trimmed and re-checked multiple times, and with three separate
per-finding submissions, the operator mis-paired one finding's text with
another finding's form during manual handling.

This module is deliberately scoped to what's buildable without a new
dependency: character-limited summarization (stdlib only) and
unambiguous, deterministic per-finding labeling (the filename_stub AND the
summary text itself both carry the finding id + vuln class, so a mix-up is
detectable at a glance even if a filename gets lost/renamed in transit --
e.g. pasted into a web form). It deliberately does NOT generate a PDF --
that needs an actual conversion tool/library, and picking one (a new
dependency, or relying on a system binary like pandoc that isn't a
documented runtime dependency of this repo) is a decision for a human to
make explicitly, not something to silently bolt on here. Converting the
resulting markdown to PDF/print is a well-understood manual step (or a
follow-up task with an explicit tool choice) once this half exists.

Uses only the standard library -- no new dependency.
"""

from __future__ import annotations

import os
import re
import sys
import textwrap
from dataclasses import dataclass

try:
    from redact import redact_text
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from redact import redact_text

DEFAULT_CHAR_LIMIT = 1000
TRUNCATION_MARKER = " [...truncated, full report attached separately]"


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "finding"


@dataclass
class VdpPacket:
    finding_id: str
    vuln_class: str
    filename_stub: str
    short_summary: str
    truncated: bool


def build_vdp_packet(finding_id: str, vuln_class: str, title: str, description: str,
                      impact: str, char_limit: int = DEFAULT_CHAR_LIMIT) -> VdpPacket:
    """Every summary is labeled with `[#<finding_id> <vuln_class>]` up
    front, so the finding it belongs to is unambiguous even if pasted bare
    into a form with no filename attached. If the full text exceeds
    `char_limit`, it's cut at the last whole word boundary that still
    leaves room for TRUNCATION_MARKER, so the result never exceeds
    char_limit and never ends mid-word.

    title/description/impact pass through redact.redact_text() before
    anything else (code-review finding: this content is destined to leave
    the toolchain entirely -- pasted into a public, self-run VDP web form
    -- and previously wasn't redacted at all, unlike every other report-
    shaped output in this repo, e.g. postmortem.py's own per-field
    redaction of the same class of content)."""
    title = redact_text(title)
    description = redact_text(description)
    impact = redact_text(impact)

    filename_stub = f"finding-{finding_id}-{_slugify(vuln_class)}"
    label = f"[#{finding_id} {vuln_class}]"
    full_text = f"{label} {title}\n{description}\nImpact: {impact}"

    if len(full_text) <= char_limit:
        return VdpPacket(finding_id=finding_id, vuln_class=vuln_class, filename_stub=filename_stub,
                          short_summary=full_text, truncated=False)

    # The label must NEVER itself be truncated away or chopped mid-word
    # (code-review finding, reproduced directly): the whole point of this
    # module is that the label survives even if a filename gets lost/
    # renamed in transit, so reserve room for it (plus the separating
    # space and TRUNCATION_MARKER) BEFORE shortening the rest of the
    # content, rather than handing the whole labeled string to
    # textwrap.shorten() and letting its break_long_words behavior chop
    # whatever token happens to land first when the budget is tiny.
    reserved = len(label) + 1 + len(TRUNCATION_MARKER)
    body_budget = char_limit - reserved
    if body_budget < 0:
        # char_limit too small even for label+marker alone -- best effort:
        # the label survives intact (unambiguous finding identity is the
        # one thing this module must never sacrifice), everything else,
        # marker included, is dropped rather than corrupted.
        return VdpPacket(finding_id=finding_id, vuln_class=vuln_class, filename_stub=filename_stub,
                          short_summary=label[:char_limit], truncated=True)

    # textwrap.shorten collapses whitespace and cuts at a word boundary,
    # reserving room for placeholder -- exactly the "don't chop mid-word"
    # behavior needed for the BODY, reusing stdlib rather than hand-rolling
    # it. The label itself never passes through this.
    rest = f"{title}\n{description}\nImpact: {impact}"
    shortened_rest = textwrap.shorten(rest, width=body_budget, placeholder="").rstrip()
    short_summary = f"{label} {shortened_rest}{TRUNCATION_MARKER}"
    return VdpPacket(finding_id=finding_id, vuln_class=vuln_class, filename_stub=filename_stub,
                      short_summary=short_summary[:char_limit], truncated=True)


def build_vdp_packet_set(findings: list[dict], char_limit: int = DEFAULT_CHAR_LIMIT) -> list[VdpPacket]:
    """findings: a list of {finding_id, vuln_class, title, description,
    impact} dicts (report-agent's own per-finding fields). Returns one
    VdpPacket per finding; filename_stub collisions are structurally
    impossible since every finding_id is unique within an engagement."""
    return [
        build_vdp_packet(
            finding_id=f["finding_id"], vuln_class=f["vuln_class"], title=f["title"],
            description=f["description"], impact=f["impact"], char_limit=char_limit,
        )
        for f in findings
    ]
