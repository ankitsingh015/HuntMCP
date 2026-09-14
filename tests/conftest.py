import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "scripts", "hooks"))

import dotenv_loader  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_from_real_dotenv(monkeypatch, tmp_path):
    """No test in this suite should ever be able to see this developer
    machine's real repo-root .env file (gitignored -- CI never has one,
    but a real local checkout very well might, with real keys filled in).
    dotenv_loader.get_secret() falls back to it by default whenever a
    requested key isn't already a real env var, so without this, a test
    that does monkeypatch.delenv("SOME_KEY") to simulate "not configured"
    could still see a real value read back from disk -- passing today only
    by accident of whatever happens to be blank in this machine's own
    .env. Point the default lookup path at a guaranteed-nonexistent file
    for every test; anything that wants to test the real fallback-to-file
    behavior passes an explicit path= to get_secret() instead (see
    test_dotenv_loader.py), bypassing this override entirely."""
    monkeypatch.setattr(dotenv_loader, "_ENV_PATH", str(tmp_path / ".env-isolated-for-tests"))
    dotenv_loader._cache.clear()
    yield
    dotenv_loader._cache.clear()
