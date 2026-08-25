"""Parse a Burp Suite HTTP History export (native XML format, from Proxy
or Target > right-click a request/selection > "Save selected items" >
XML) into structured endpoint records.

Why this exists: automated recon (subfinder/katana) can't see behind a
login wall -- it doesn't know how to authenticate. A human hunter who
already explored the authenticated area manually through Burp's proxy
has that traffic sitting in their HTTP history, session cookies and all.
This imports it instead of making HuntMCP re-derive authenticated
endpoints from scratch.

Kept dependency-free (stdlib only, xml.etree.ElementTree) -- Burp's own
export format is simple enough not to need lxml, and stdlib's expat
backend doesn't resolve external entities by default (unlike some XML
parser configurations), so this is safe to point at a file without
extra XXE hardening.
"""

import base64
import xml.etree.ElementTree as ET


def _parse_raw_headers(raw_request: bytes) -> tuple[dict[str, str], bool, bool]:
    """Split a raw HTTP request's header block into a dict, and flag
    whether it carries a Cookie or Authorization header -- the signal
    that this endpoint needs an authenticated session to reach, which is
    the whole point of importing Burp traffic instead of just crawling."""
    text = raw_request.decode("utf-8", errors="replace")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    headers: dict[str, str] = {}
    has_cookie = False
    has_auth = False
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        value = value.strip()
        headers[name] = value
        if name.lower() == "cookie" and value:
            has_cookie = True
        if name.lower() == "authorization" and value:
            has_auth = True
    return headers, has_cookie, has_auth


def parse_burp_xml(xml_content: str) -> list[dict]:
    """Parse Burp's native HTTP-history XML export. Returns one dict per
    <item> with method/url/host/path/status/headers/has_cookie/
    has_auth_header. Skips malformed <item> entries individually rather
    than aborting the whole import -- a large real-world export can have
    a few odd/truncated entries."""
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise ValueError(f"Invalid Burp XML export: {e}")

    entries = []
    for item in root.findall("item"):
        try:
            url = (item.findtext("url") or "").strip()
            host_el = item.find("host")
            host = (host_el.text or "").strip() if host_el is not None else ""
            method = (item.findtext("method") or "").strip()
            path = (item.findtext("path") or "").strip()
            status_text = item.findtext("status")
            status = int(status_text) if status_text and status_text.strip().isdigit() else None
            mimetype = (item.findtext("mimetype") or "").strip()

            headers: dict[str, str] = {}
            has_cookie = False
            has_auth = False
            req_el = item.find("request")
            if req_el is not None and req_el.text:
                is_b64 = req_el.get("base64") == "true"
                raw = base64.b64decode(req_el.text) if is_b64 else req_el.text.encode("utf-8")
                headers, has_cookie, has_auth = _parse_raw_headers(raw)

            if not url and not host:
                continue

            entries.append({
                "url": url,
                "host": host,
                "method": method or "GET",
                "path": path,
                "status": status,
                "mimetype": mimetype,
                "headers": headers,
                "has_cookie": has_cookie,
                "has_auth_header": has_auth,
            })
        except Exception:
            continue

    return entries


def parse_burp_xml_file(path: str) -> list[dict]:
    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    return parse_burp_xml(content)
