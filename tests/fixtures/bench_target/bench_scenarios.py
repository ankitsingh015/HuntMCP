"""BLIND case index -- endpoint/method only. NEVER imported by any
mcp-servers/* production code and NEVER handed to a hunting tool call --
a real hunt only ever receives the target's base URL, exactly like a
real engagement. This file exists purely as the evaluator's own
bookkeeping (which path maps to which case_id) and as the future home of
P4-COVMATRIX's endpoint x class x role index. See
docs/superpowers/specs/2026-09-17-p2-bench-design.md section 5."""
from __future__ import annotations

from types import MappingProxyType

SCENARIOS = MappingProxyType({
    "case_sqli": MappingProxyType({"endpoint": "/bench/products", "method": "GET"}),
    "case_xss": MappingProxyType({"endpoint": "/bench/search", "method": "GET"}),
    "case_idor": MappingProxyType({"endpoint": "/bench/orders", "method": "GET"}),
    "case_backup_file": MappingProxyType({"endpoint": "/backup.sql.bak", "method": "GET"}),
    "case_misconfig": MappingProxyType({"endpoint": "/bench/status", "method": "GET"}),
    "case_open_redirect": MappingProxyType({"endpoint": "/bench/login", "method": "GET"}),
})

# Fields that must NEVER appear in this manifest.
FORBIDDEN_ANSWER_FIELDS = (
    "vuln_class", "severity", "verification_tool", "confirmed", "expected",
)
