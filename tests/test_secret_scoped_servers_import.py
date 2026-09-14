"""S3 regression: osint-mcp/hackerone-mcp/github-security-mcp/second-opinion-mcp
each used to call dotenv_loader.load_dotenv_if_present() at import time.
Migrating dotenv_loader.py to the per-key get_secret() API (S3) removed
that function -- these tests prove each server module still imports
cleanly afterward, i.e. every real call site was actually migrated, not
just some of them."""

import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_SERVERS = [
    "osint-mcp",
    "hackerone-mcp",
    "github-security-mcp",
    "second-opinion-mcp",
]


@pytest.mark.parametrize("server_dir", _SERVERS)
def test_server_module_imports_without_error(server_dir, monkeypatch):
    server_path = os.path.join(ROOT, "mcp-servers", server_dir, "server.py")
    monkeypatch.syspath_prepend(os.path.join(ROOT, "mcp-servers", server_dir))
    spec = importlib.util.spec_from_file_location(f"{server_dir}_server", server_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # raises on any ImportError/AttributeError
