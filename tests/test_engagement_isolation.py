"""Regression for #130: a local test run must NEVER resolve engagement state
against the developer's REAL active engagement.

Observed live (Manatal engagement, 2026-11-05): localhost pytest runs left
15 `state-change-pending-*.json` files and matching audit entries inside a
real engagement directory, because `state_change_confirm` resolved paths
through `engagement_paths` globals that still pointed at the live
`data/.active-engagement` pointer. That pollutes a live engagement's
evidence/audit trail -- a direct hit to the "evidence integrity" requirement
for a security tool.

The fix makes isolation STRUCTURAL rather than per-test-author discipline:
the suite-wide autouse fixture `_isolate_engagement_paths` in conftest.py
redirects `engagement_paths.ACTIVE_POINTER` / `ENGAGEMENTS_ROOT` -- and the
`HUNTMCP_ACTIVE_POINTER` / `HUNTMCP_ENGAGEMENTS_ROOT` env vars a subprocess
re-reads at import time -- to a throwaway tmp location for EVERY test. These
tests prove that isolation is actually in force, so a single test module
that forgets to monkeypatch can no longer leak into a live engagement.
"""
import os

import engagement_paths
import state_change_confirm as scc

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REAL_DATA = os.path.join(_REPO_ROOT, "data")

FP = "0123456789abcdef0123456789abcdef"


def _within(child: str, parent: str) -> bool:
    child = os.path.realpath(child)
    parent = os.path.realpath(parent)
    return child == parent or child.startswith(parent + os.sep)


def test_the_suite_redirects_engagement_paths_away_from_the_live_repo_data():
    """In-process globals AND the env vars a subprocess re-reads must both
    resolve outside the repo's real data/ directory."""
    assert not _within(engagement_paths.ACTIVE_POINTER, _REAL_DATA), (
        f"ACTIVE_POINTER still resolves inside the live repo data dir: "
        f"{engagement_paths.ACTIVE_POINTER!r}")
    assert not _within(engagement_paths.ENGAGEMENTS_ROOT, _REAL_DATA), (
        f"ENGAGEMENTS_ROOT still resolves inside the live repo data dir: "
        f"{engagement_paths.ENGAGEMENTS_ROOT!r}")
    for var in ("HUNTMCP_ACTIVE_POINTER", "HUNTMCP_ENGAGEMENTS_ROOT"):
        val = os.environ.get(var)
        assert val is not None, f"{var} must be set by the isolation fixture (subprocesses re-read it)"
        assert not _within(val, _REAL_DATA), f"{var} still points inside the live repo data dir: {val!r}"


def test_a_default_path_engagement_write_cannot_reach_the_live_dir():
    """Exercise the exact code path that leaked live -- write_pending ->
    token_path -> _engagement_slug_dir -> ACTIVE_POINTER/ENGAGEMENTS_ROOT,
    with NO HUNTMCP_STATE_CHANGE_CONFIRM_PATH override -- and prove the file
    lands in the isolated root, not the live engagement directory.

    Guard first: if the suite is not isolating engagement_paths, abort BEFORE
    any write so a red-phase (unfixed) run fails here WITHOUT polluting a
    live engagement dir."""
    assert not _within(engagement_paths.ENGAGEMENTS_ROOT, _REAL_DATA), (
        "engagement_paths is not isolated -- refusing to run the write probe")
    assert not _within(engagement_paths.ACTIVE_POINTER, _REAL_DATA), (
        "engagement_paths is not isolated -- refusing to run the write probe")

    # A throwaway target is active by default (the suite isolation fixture),
    # so this default-path write resolves into the isolated engagements root.
    slug = engagement_paths.get_active_target()
    assert slug, "the isolation fixture should leave a throwaway target active by default"
    scc.write_pending("isolation-probe.example", ["POST"], FP, "leak probe")

    written = os.path.join(engagement_paths.ENGAGEMENTS_ROOT, slug, f"state-change-pending-{FP}.json")
    assert os.path.exists(written), "write_pending did not resolve into the (isolated) active-engagement dir"
    assert not _within(written, _REAL_DATA), f"pending file leaked into the live repo data dir: {written!r}"
