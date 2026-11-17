"""Signature-driven precedent ranking for the knowledge-map layer.

Given the Chroma query results for a feature/flow phrase, rank the vulnerability
classes that real disclosed reports found in *things like it* -- including
classes an agent would not have proposed from its own hypothesis. Pure: takes an
already-fetched results dict (no embed/chroma deps) so it is unit-testable in
isolation. server.py's @app.tool() plan_feature does embed+query, then calls
build_plan() here.
"""

from __future__ import annotations


def rank_classes(results: dict, limit: int) -> list[dict]:
    """Tally vuln classes across the results, ranked by how often they appear
    (ties broken by best similarity score). Returns up to `limit` entries:
    {class, count, best_score, examples:[{title,url}]}.
    """
    ids = (results or {}).get("ids") or [[]]
    if not ids or not ids[0]:
        return []
    metas = results["metadatas"][0]
    dists = results.get("distances", [[0.0] * len(metas)])[0]
    agg: dict[str, dict] = {}
    for i, meta in enumerate(metas):
        cls = (meta or {}).get("vuln_class") or "unknown"
        score = round(1 - (dists[i] if i < len(dists) else 0.0), 4)
        entry = agg.setdefault(
            cls, {"class": cls, "count": 0, "best_score": 0.0, "examples": []}
        )
        entry["count"] += 1
        entry["best_score"] = max(entry["best_score"], score)
        url = (meta or {}).get("url", "N/A")
        seen_urls = {ex["url"] for ex in entry["examples"]}
        if url not in seen_urls and len(entry["examples"]) < 3:
            entry["examples"].append(
                {"title": (meta or {}).get("title", "Untitled"), "url": url}
            )
    # named classes rank above the meaningless "unknown" bucket, then by count
    ranked = sorted(
        agg.values(),
        key=lambda e: (e["class"] != "unknown", e["count"], e["best_score"]),
        reverse=True,
    )
    return ranked[:limit]


def build_plan(feature: str, results: dict, limit: int = 6) -> str:
    """Format the ranked classes into an agent-facing precedent plan."""
    ranked = rank_classes(results, limit)
    if not ranked:
        return (
            f"No precedent found for '{feature}'. Nothing like this feature "
            f"is in the knowledge base yet -- test it from first principles."
        )
    lines = [
        f"Precedent for '{feature}' -- vulnerability classes real reports found "
        f"in features like this, most common first:",
        "",
    ]
    for n, e in enumerate(ranked, 1):
        lines.append(
            f"{n}. {e['class']} ({e['count']} report(s), best match {e['best_score']})"
        )
        for ex in e["examples"]:
            lines.append(f"     - {ex['title']} -> {ex['url']}")
    lines.append("")
    lines.append(
        "Test each of these against the feature -- including any class you would "
        "not have proposed yourself. Use get_testing_playbook/query_rag for depth."
    )
    return "\n".join(lines)
