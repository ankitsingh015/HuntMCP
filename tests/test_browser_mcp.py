import asyncio
import importlib.util
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "browser_mcp_confirm",
    os.path.join(ROOT, "mcp-servers", "browser-mcp", "browser_confirm.py"),
)
browser_confirm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(browser_confirm)


def test_normalize_links_resolves_relative_hrefs():
    links = browser_confirm._normalize_links(
        "https://target.com/products",
        [{"text": "Item A", "href": "/products/item-a"}],
        max_links=200,
    )
    assert links == [{"text": "Item A", "href": "https://target.com/products/item-a"}]


def test_normalize_links_keeps_absolute_hrefs_unchanged():
    links = browser_confirm._normalize_links(
        "https://target.com/products",
        [{"text": "External", "href": "https://other.com/page"}],
        max_links=200,
    )
    assert links == [{"text": "External", "href": "https://other.com/page"}]


def test_normalize_links_drops_non_navigable_hrefs():
    raw = [
        {"text": "JS action", "href": "javascript:void(0)"},
        {"text": "Email", "href": "mailto:x@example.com"},
        {"text": "Call", "href": "tel:+15551234567"},
        {"text": "Fragment only", "href": "#"},
        {"text": "Empty", "href": ""},
    ]
    assert browser_confirm._normalize_links("https://target.com/", raw, max_links=200) == []


def test_normalize_links_dedupes_by_text_and_href():
    raw = [
        {"text": "Item A", "href": "/a"},
        {"text": "Item A", "href": "/a"},
    ]
    links = browser_confirm._normalize_links("https://target.com/", raw, max_links=200)
    assert len(links) == 1


def test_normalize_links_respects_max_links_cap():
    raw = [{"text": f"Item {i}", "href": f"/{i}"} for i in range(10)]
    links = browser_confirm._normalize_links("https://target.com/", raw, max_links=3)
    assert len(links) == 3


def test_normalize_links_strips_whitespace_from_text_and_href():
    raw = [{"text": "  Item A  ", "href": "  /a  "}]
    links = browser_confirm._normalize_links("https://target.com/", raw, max_links=200)
    assert links == [{"text": "Item A", "href": "https://target.com/a"}]


# ---- Manual intervention: pure logic, no real browser/display needed -------
# start_manual_intervention()'s collision check and finish_manual_intervention()'s
# "not open" check both run BEFORE anything Playwright-related, so they're
# testable by pre-populating/inspecting _live_interventions directly --
# same "test what doesn't need a real browser" boundary as _normalize_links
# above, just for the new module-level dict instead of a pure function.

def test_start_manual_intervention_refuses_when_already_open(monkeypatch):
    monkeypatch.setattr(browser_confirm, "_enforce_budget", lambda name: None)
    sf = "/tmp/does-not-matter.json"
    browser_confirm._live_interventions[sf] = browser_confirm._LiveIntervention(
        None, None, None, None, time.monotonic()
    )
    try:
        result = asyncio.run(browser_confirm.start_manual_intervention("https://example.com", sf))
        assert "error" in result
        assert "already open" in result["error"]
    finally:
        browser_confirm._live_interventions.pop(sf, None)


def test_finish_manual_intervention_errors_when_nothing_open():
    result = asyncio.run(browser_confirm.finish_manual_intervention("/tmp/never-started.json"))
    assert "error" in result
    assert "no open manual intervention" in result["error"]


def test_finish_manual_intervention_errors_when_still_pending():
    # Regression: the reservation placeholder (_PENDING, written
    # synchronously before start_manual_intervention's first await to
    # close the TOCTOU race) must never be mistaken for a real, finishable
    # intervention by finish_manual_intervention.
    sf = "/tmp/still-launching.json"
    browser_confirm._live_interventions[sf] = browser_confirm._PENDING
    try:
        result = asyncio.run(browser_confirm.finish_manual_intervention(sf))
        assert "error" in result
        assert "still starting up" in result["error"]
        # Must NOT have been popped -- the real start_manual_intervention
        # call that's still in flight needs to find its own reservation
        # still there when it finishes.
        assert browser_confirm._live_interventions[sf] is browser_confirm._PENDING
    finally:
        browser_confirm._live_interventions.pop(sf, None)


def test_list_open_interventions_reports_elapsed_time():
    sf = "/tmp/some-session.json"
    browser_confirm._live_interventions[sf] = browser_confirm._LiveIntervention(
        None, None, None, None, time.monotonic() - 5
    )
    try:
        items = asyncio.run(browser_confirm.list_open_interventions())
        assert len(items) == 1
        assert items[0]["session_file"] == sf
        assert items[0]["open_seconds"] >= 5
        assert items[0]["likely_abandoned"] is False
    finally:
        browser_confirm._live_interventions.pop(sf, None)


def test_list_open_interventions_flags_likely_abandoned_past_threshold():
    sf = "/tmp/forgotten-session.json"
    stale_opened_at = time.monotonic() - browser_confirm.INTERVENTION_STALE_AFTER_SECONDS - 1
    browser_confirm._live_interventions[sf] = browser_confirm._LiveIntervention(
        None, None, None, None, stale_opened_at
    )
    try:
        items = asyncio.run(browser_confirm.list_open_interventions())
        assert items[0]["likely_abandoned"] is True
    finally:
        browser_confirm._live_interventions.pop(sf, None)


def test_list_open_interventions_reports_pending_as_starting():
    sf = "/tmp/reserved-not-yet-launched.json"
    browser_confirm._live_interventions[sf] = browser_confirm._PENDING
    try:
        items = asyncio.run(browser_confirm.list_open_interventions())
        assert len(items) == 1
        assert items[0]["session_file"] == sf
        assert items[0]["status"] == "starting"
    finally:
        browser_confirm._live_interventions.pop(sf, None)


def test_list_open_interventions_empty_when_nothing_open():
    sf = "/tmp/a-session-not-actually-open.json"
    browser_confirm._live_interventions.pop(sf, None)  # ensure a clean slate for this key
    items = asyncio.run(browser_confirm.list_open_interventions())
    assert sf not in {i["session_file"] for i in items}
