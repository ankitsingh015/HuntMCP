import importlib.util
import os
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "sqlmap_mcp_server", os.path.join(ROOT, "mcp-servers", "sqlmap-mcp", "server.py")
)
sqlmap_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sqlmap_server)


@dataclass
class _FakeResult:
    stdout: str
    stderr: str = ""
    returncode: int = 0


SQLMAP_OUTPUT = """\
sqlmap identified the following injection point(s):
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
"""


def test_injection_type_not_truncated_to_one_char(monkeypatch):
    # sqlmap prints Type:/Title:/Payload: on separate lines, never combined
    # on one line -- the old lazy-quantifier-plus-optional-groups regex
    # captured just the first character ("b") of the type instead of the
    # full "boolean-based blind" string.
    monkeypatch.setattr(sqlmap_server, "run_tool", lambda *a, **k: _FakeResult(stdout=SQLMAP_OUTPUT))
    out = sqlmap_server.test_injection("https://example.com/?id=1")
    assert "Type: boolean-based blind" in out
    assert "Type: b\n" not in out
