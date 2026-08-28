import importlib.util
import os

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
