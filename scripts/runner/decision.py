"""Human-decision gate for the HuntMCP dev-runner.

When the runner encounters an ambiguity or safety boundary it will not cross, it
renders a concise, structured decision request -- the same shape used for the
C1/C3/C4/C5 rulings -- and STOPs. It does not continue until a human supplies the
decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DecisionRequest:
    task_id: str
    ambiguity: str
    contract: str
    options: list[str] = field(default_factory=list)
    recommendation: str | None = None
    downstream: list[str] = field(default_factory=list)
    stop_codes: list[str] = field(default_factory=list)


def format_decision_request(dr: DecisionRequest) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("HUMAN DECISION REQUIRED — runner STOPPED")
    lines.append("=" * 60)
    if dr.stop_codes:
        lines.append(f"STOP CODES: {', '.join(dr.stop_codes)}")
    lines.append("")
    lines.append(f"TASK:        {dr.task_id}")
    lines.append(f"AMBIGUITY:   {dr.ambiguity}")
    lines.append(f"CONTRACT:    {dr.contract}")
    lines.append("")
    lines.append("OPTIONS:")
    if dr.options:
        for i, opt in enumerate(dr.options, start=1):
            lines.append(f"  {i}. {opt}")
    else:
        lines.append("  (none enumerated)")
    lines.append("")
    if dr.recommendation:
        lines.append(f"RECOMMENDATION: {dr.recommendation}")
    else:
        lines.append("RECOMMENDATION: none — human judgement required.")
    lines.append("")
    lines.append("DOWNSTREAM (tasks that depend on this decision):")
    if dr.downstream:
        for d in dr.downstream:
            lines.append(f"  - {d}")
    else:
        lines.append("  none identified.")
    lines.append("")
    lines.append("STOP: the runner will not proceed until a decision is supplied.")
    lines.append("=" * 60)
    return "\n".join(lines)
