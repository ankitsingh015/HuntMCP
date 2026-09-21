"""EVALUATOR-ONLY answer key. `verification_tool` is read ONLY by the
fixture self-test files (tests/test_p2_bench_fixture.py) to prove each
planted bug is genuine at BUILD time -- bench_evaluator.evaluate() never
reads this field when scoring an actual hunt run (spec principle 4)."""
from __future__ import annotations

from types import MappingProxyType

EXPECTED_BY_MODE = MappingProxyType({
    "case_sqli": MappingProxyType({
        "vuln_class": "sql_injection", "severity": "high", "verification_tool": "sqlmap-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_xss": MappingProxyType({
        "vuln_class": "reflected_xss", "severity": "medium", "verification_tool": "dalfox-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_idor": MappingProxyType({
        "vuln_class": "idor", "severity": "high", "verification_tool": "idor-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_backup_file": MappingProxyType({
        "vuln_class": "information_disclosure", "severity": "medium", "verification_tool": "ffuf-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_misconfig": MappingProxyType({
        "vuln_class": "misconfiguration", "severity": "medium", "verification_tool": "nuclei-mcp",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
    "case_open_redirect": MappingProxyType({
        "vuln_class": "open_redirect", "severity": "low", "verification_tool": "curl",
        "vulnerable": MappingProxyType({"confirmed": True}),
        "patched": MappingProxyType({"confirmed": False}),
    }),
})
