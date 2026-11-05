"""BLIND case index -- endpoint/method only. NEVER imported by any
mcp-servers/* production code and NEVER handed to a hunting tool call.
Case ids are deliberately neutral (no class or conclusion in the name);
see .claude/rules/benchmarks.md "Blindness"."""
from __future__ import annotations

from types import MappingProxyType

SCENARIOS = MappingProxyType({
    "case_authz_01": MappingProxyType({"endpoint": "/authz/carts", "method": "GET"}),
    "case_authz_02": MappingProxyType({"endpoint": "/authz/orders", "method": "GET"}),
    "case_authz_03": MappingProxyType({"endpoint": "/authz/catalog", "method": "GET"}),
    "case_authz_04": MappingProxyType({"endpoint": "/authz/profiles", "method": "GET"}),
    "case_authz_05": MappingProxyType({"endpoint": "/authz/notes", "method": "GET"}),
    "case_authz_06": MappingProxyType({"endpoint": "/authz/reports", "method": "GET"}),
    "case_authz_07": MappingProxyType({"endpoint": "/authz/statements", "method": "GET"}),
    "case_authz_08": MappingProxyType({"endpoint": "/authz/drafts", "method": "GET"}),
    "case_authz_09": MappingProxyType({"endpoint": "/authz/receipts", "method": "GET"}),
    "case_authz_10": MappingProxyType({"endpoint": "/authz/ledger", "method": "GET"}),
    "case_authz_11": MappingProxyType({"endpoint": "/authz/teamdocs", "method": "GET"}),
})

# Fields that must NEVER appear in this manifest.
FORBIDDEN_ANSWER_FIELDS = (
    "vuln_class", "severity", "verification_tool", "confirmed", "expected",
)
