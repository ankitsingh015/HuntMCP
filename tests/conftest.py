import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "mcp-servers"))
sys.path.insert(0, os.path.join(ROOT, "scripts", "hooks"))

import dotenv_loader  # noqa: E402
import engagement_paths  # noqa: E402
import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_engagement_paths(monkeypatch, tmp_path):
    """No test may resolve engagement state against the developer's REAL
    active engagement. Without this, any test that hits a default-resolution
    path (engagement_paths.resolve()/get_active_target() with no explicit
    pointer and no HUNTMCP_*_PATH override) reads the live
    data/.active-engagement pointer and writes into the live
    data/engagements/<slug>/ directory -- observed live (#130, Manatal
    2026-11-05): 15 state-change-pending-*.json files and matching audit
    entries left inside a real engagement's evidence/audit trail by localhost
    test runs. That previously depended on every test author remembering to
    monkeypatch engagement_paths.ACTIVE_POINTER themselves; this makes the
    isolation structural and automatic for the whole suite.

    Redirects BOTH:
      * the in-process module globals ACTIVE_POINTER / ENGAGEMENTS_ROOT, and
      * the HUNTMCP_ACTIVE_POINTER / HUNTMCP_ENGAGEMENTS_ROOT env vars a
        spawned subprocess re-reads at import time (it gets fresh globals from
        env, not this process's monkeypatched attributes),
    to a fresh tmp location, and points the pointer at an ACTIVE throwaway
    target under it (see the inline comment for why an active target, not
    "no active target", is the safe default). Every default resolution then
    lands in tmp/engagements/<slug>/..., reaching neither the live engagement
    dir nor the repo tree.

    A test that specifically exercises the real pointer/root logic still
    passes explicit pointer_path=/engagements_root= args or its own
    monkeypatch (both override this default and remain visible in a diff);
    those tests are unaffected because this only changes the DEFAULT."""
    isolated = tmp_path / "engagement-isolated"
    root = isolated / "engagements"
    pointer = isolated / ".active-engagement"

    # Point the default at an ACTIVE throwaway target under tmp, not at "no
    # active target". With no active target, engagement_paths.resolve() falls
    # back to the BARE relative filename for any caller that passes no
    # legacy_default (e.g. budget_guard/fanout resolve "budget.json" /
    # "fanout-backoff.json"), and file_lock would then create the sidecar
    # <name>.lock in the repo root (the process cwd) -- trading the live-dir
    # leak for a repo-root one. An active isolated target makes every default
    # resolution land in tmp/engagements/<slug>/..., so a default-path write
    # reaches neither the live engagement dir nor the repo tree. A test that
    # specifically wants "no active target" (or any other state) still passes
    # its own explicit pointer_path=/engagements_root= or monkeypatch, which
    # overrides this default and stays visible in a diff.
    slug = "pytest-isolated-target"
    (root / slug).mkdir(parents=True)
    pointer.write_text(slug)

    monkeypatch.setattr(engagement_paths, "ACTIVE_POINTER", str(pointer))
    monkeypatch.setattr(engagement_paths, "ENGAGEMENTS_ROOT", str(root))
    monkeypatch.setenv("HUNTMCP_ACTIVE_POINTER", str(pointer))
    monkeypatch.setenv("HUNTMCP_ENGAGEMENTS_ROOT", str(root))
    yield


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
