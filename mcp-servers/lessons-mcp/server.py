import sys
from mcp.server.fastmcp import FastMCP

from lessons_store import append_lesson as _append_lesson
from lessons_store import check_size as _check_size
from lessons_store import list_class_headers as _list_class_headers
from lessons_store import read_lessons as _read_lessons

app = FastMCP("lessons-mcp")


@app.tool()
def append_lesson(
    vuln_class: str,
    target: str,
    method: str,
    result: str,
    payload: str = "",
    impact: str = "",
    bypasses: str = "",
    severity: str = "",
    cwe: str = "",
) -> str:
    """Write back one confirmed finding OR one closed-false-positive to the
    private Lessons Registry (chat-logs/lessons-learned.md). Call this
    immediately after every validation outcome in exploit-agent's Phase 1,
    win or lose -- both a confirmed bug and a closed FP make the registry
    smarter. result should be one of: CONFIRMED, CONFIRMED <severity>,
    CLOSED-FP.
    """
    return _append_lesson(
        vuln_class=vuln_class,
        target=target,
        method=method,
        payload=payload,
        impact=impact,
        bypasses=bypasses,
        result=result,
        severity=severity,
        cwe=cwe,
    )


@app.tool()
def read_lessons(keyword: str = "") -> str:
    """No keyword: return just the class headers (cheap skim, per the
    CONTEXT BUDGET rules). With a keyword (e.g. a tech-stack signal from
    recon like 'laravel' or 'wordpress'): return only the matching class
    block(s) -- never paste the whole registry into context."""
    return _read_lessons(keyword)


@app.tool()
def list_classes() -> str:
    """Just the class headers already in the registry."""
    headers = _list_class_headers()
    return "\n".join(headers) if headers else "Lessons registry is empty."


@app.tool()
def check_size() -> str:
    """Report the registry's current line count against the ~400-line cap.
    Call this at the end of an engagement; if over cap, move oldest/
    duplicate entries to chat-logs/lessons-archive-<YYYY>.md before the
    next one starts."""
    return _check_size()


if __name__ == "__main__":
    print("lessons-mcp starting...", file=sys.stderr)
    app.run(transport="stdio")
