"""Offline unit tests for writeup-mcp's plan_feature core.

Imports the lightweight plan_feature module in isolation (no embed/chroma
stack), mirroring test_h1_fetch.py. The @app.tool() wrapper in server.py that
does embed+query is covered by the Task 4 runtime verification, not here.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(__file__)
MOD = os.path.join(HERE, "..", "mcp-servers", "writeup-mcp", "plan_feature.py")

spec = importlib.util.spec_from_file_location("plan_feature", MOD)
pf = importlib.util.module_from_spec(spec)
sys.modules["plan_feature"] = pf
spec.loader.exec_module(pf)


def _results(rows):
    """Build a Chroma-shaped results dict from (vuln_class, title, url, doc)."""
    return {
        "ids": [[f"id{i}" for i, _ in enumerate(rows)]],
        "metadatas": [[{"vuln_class": c, "title": t, "url": u, "tech": ""}
                       for (c, t, u, _d) in rows]],
        "documents": [[d for (_c, _t, _u, d) in rows]],
        "distances": [[0.4 for _ in rows]],
    }


def test_build_plan_returns_classes_for_feature():
    results = _results([
        ("Server-Side Request Forgery", "SSRF in screenshot", "https://h1/1", "fetched url"),
        ("Server-Side Request Forgery", "SSRF in webhook", "https://h1/2", "internal svc"),
        ("Cross-site Scripting (XSS)", "XSS in name", "https://h1/3", "reflected"),
    ])
    out = pf.build_plan("screenshot url fetch", results, limit=6)
    assert "Server-Side Request Forgery" in out
    assert "https://h1/1" in out
    # the class seen twice ranks above the one seen once
    assert out.index("Server-Side Request Forgery") < out.index("Cross-site Scripting (XSS)")


def test_build_plan_empty_is_graceful():
    empty = {"ids": [[]], "metadatas": [[]], "documents": [[]], "distances": [[]]}
    out = pf.build_plan("obscure feature", empty, limit=6)
    assert "no precedent" in out.lower()


def test_examples_deduped_by_url():
    # the RAG returns multiple chunks of the SAME report -> same url repeats
    results = _results([
        ("SSRF", "same report", "https://h1/1", "chunk a"),
        ("SSRF", "same report", "https://h1/1", "chunk b"),
        ("SSRF", "same report", "https://h1/1", "chunk c"),
    ])
    ranked = pf.rank_classes(results, limit=6)
    assert len(ranked[0]["examples"]) == 1


def test_unknown_class_ranks_below_named():
    results = _results([
        ("unknown", "u1", "https://h1/1", "x"),
        ("unknown", "u2", "https://h1/2", "x"),
        ("unknown", "u3", "https://h1/3", "x"),
        ("unknown", "u4", "https://h1/4", "x"),
        ("Server-Side Request Forgery", "s1", "https://h1/5", "x"),
        ("Server-Side Request Forgery", "s2", "https://h1/6", "x"),
    ])
    out = pf.build_plan("feature", results, limit=6)
    assert out.index("Server-Side Request Forgery") < out.index("unknown")
