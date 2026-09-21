"""Single source of truth for the host-side pinned nuclei-templates
snapshot mounted read-only into the sandbox for every real nuclei scan.

Why a pinned, host-side snapshot at all: CONTAINER_HOME was moved to /tmp
(a 64MB, ephemeral, per-container tmpfs -- see sandbox_runner.py's own
CONTAINER_HOME comment) to fix subfinder/katana/nuclei/ffuf all being
unable to write their startup config dirs under a read-only $HOME. That
fix alone left nuclei still broken for any REAL scan: nuclei's default
behavior is to auto-download/update its full template set (tens of MB)
into $HOME on first use, which now fills the 64MB tmpfs and fails with
"no space left on device" -- confirmed live, reproduced against
https://example.com, 2026-09-17. Bumping the tmpfs size would only trade
one failure for another (every fresh, ephemeral container would then
re-download the entire template set from GitHub on every single scan --
slow, network-heavy, and still finite), and baking the full template
repo into the sandbox image would mean every template update requires an
image rebuild. A host-side snapshot, fetched once via
scripts/fetch-nuclei-templates.sh and mounted read-only at a fixed,
non-$HOME path (see sandbox_runner.build_argv()'s existing extra_mounts=
mechanism -- no new mount machinery needed), avoids all three: no tmpfs
pressure, no image rebuild, and the pinned commit makes exactly which
templates a scan ran against reproducible.

`-duc` (nuclei's own --disable-update-check flag) is REQUIRED alongside
this on every real invocation -- without it, nuclei still attempts an
outbound network check for template updates even when -t already points
at a local, non-default directory, which both wastes a request and risks
the exact same tmpfs-fill failure this module exists to avoid.

FUTURE PREREQUISITE (not applicable today, no such test exists yet):
scripts/fetch-nuclei-templates.sh is now bounded (a `timeout 60s` per
fetch attempt, 5 retries, plus a `timeout-minutes: 6` CI step-level
backstop in .github/workflows/ci.yml) so a network stall can no longer
hang the shared unit-tests job -- but a hard kill mid-fetch (the CI
timeout firing, or a local SIGKILL) can still leave data/nuclei-templates/
in a partial/corrupted checkout state that a NAIVE freshness check might
mistake for valid. templates_available() here only checks for a handful
of expected top-level directories (a cheap sanity check, not an integrity
check) -- good enough for today's use (a real scan fails loudly and
obviously on missing/garbage template files if the check is wrong), but
NOT sufficient ground truth for a benchmark's own build-time self-test.
If/when a real-tool fixture-proof test drives an actual sandboxed nuclei
scan against this snapshot as evidence for a benchmark (e.g. a future
misconfiguration-class fixture-proof task), that test's own setup should
verify the snapshot is genuinely at TEMPLATES_PINNED_SHA with a clean
`git status` (not just templates_available()'s directory-shape check)
before trusting a scan result run against it -- do not build that
verification now; there is nothing yet that would consume it.
"""

import os

TEMPLATES_REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"

# Pinned exactly, not "latest" -- see this module's own docstring for why
# reproducibility matters here. Bump deliberately (re-run
# scripts/fetch-nuclei-templates.sh after editing this) when a newer
# template set is wanted; never silently follow upstream HEAD.
TEMPLATES_PINNED_SHA = "59482fcca6411533562f533cbf0318b0577e734f"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Deliberately under data/ (gitignored, fetched content -- same convention
# as data/chroma/: rebuilt locally by a script, never committed) and
# deliberately NOT under $HOME or the sandbox's CONTAINER_HOME -- the whole
# point is this directory is independent of, and unaffected by, the
# per-container ephemeral /tmp.
TEMPLATES_DIR = os.path.join(_REPO_ROOT, "data", "nuclei-templates")

# A handful of the pinned repo's own top-level protocol directories (its
# actual layout as of TEMPLATES_PINNED_SHA) -- used only as a cheap sanity
# check that TEMPLATES_DIR looks like a real checkout and not an empty or
# half-finished clone, not as an exhaustive listing.
_EXPECTED_SUBDIRS = ("http", "dns", "network", "ssl")


def templates_available() -> bool:
    """True iff TEMPLATES_DIR looks like a real, populated checkout of the
    pinned nuclei-templates repo. Callers must check this BEFORE
    launching a real scan and fail closed with a clear, actionable error
    if it's False -- never silently fall back to letting nuclei attempt
    its own network auto-download (that's the exact failure mode this
    whole mechanism exists to replace)."""
    if not os.path.isdir(TEMPLATES_DIR):
        return False
    return any(os.path.isdir(os.path.join(TEMPLATES_DIR, d)) for d in _EXPECTED_SUBDIRS)


def missing_templates_error() -> str:
    return (
        f"nuclei-templates snapshot not found at {TEMPLATES_DIR!r}. Run "
        "scripts/fetch-nuclei-templates.sh once to fetch the pinned "
        f"snapshot (commit {TEMPLATES_PINNED_SHA}) before running a real "
        "nuclei scan."
    )
