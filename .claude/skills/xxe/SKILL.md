---
name: xxe
description: XXE/XML technique list -- classic, blind OOB, error-based, parameter entities, billion laughs, XInclude, XSLT, and XXE in SVG/DOCX/XLSX/PPTX/RSS/SOAP formats -- plus the SSRF/file-read/port-scan escalations XXE enables. Converted from master-pentest-prompt.md Phase 11. Use on any endpoint that parses XML, or any file format that's secretly XML internally (SVG, Office Open XML documents, RSS/Atom, SOAP).
---

# XXE / XML (never assume not applicable)

## When to use

Any endpoint that explicitly accepts XML, and -- easy to miss -- any file
upload accepting a format that's XML under the hood: SVG, DOCX/XLSX/PPTX
(Office Open XML), RSS/Atom feeds, SOAP requests. "This API only takes
JSON" doesn't rule out an XXE-capable upload feature elsewhere in the
same app.

## Techniques

- Classic in-band XXE.
- Blind out-of-band (DTD fetched via HTTP/FTP -- `oob-mcp` for the
  callback).
- Error-based XXE (forcing a parser error that leaks file content).
- Parameter entities (for cases where the classic general-entity approach
  is filtered).
- Billion laughs / entity expansion DoS.
- XInclude (works even when external DTDs are blocked).
- XSLT-based attacks.
- Format-specific: SVG, DOCX/XLSX/PPTX, RSS/Atom, SOAP.

## Escalations

- SSRF via XXE (see the `ssrf` skill for the full SSRF technique list once
  the XML parser is confirmed to fetch external entities).
- File read via XXE.
- Port scan via XXE response-timing differences.

## Parser hardening by default (2026)

Fingerprint the target's XML stack before investing time -- most mainstream
parsers no longer expand external entities out of the box. Probe with an
inline general entity (`<!ENTITY hello "world!">` / `&hello;`) first: if
`hello!` doesn't echo back, entity expansion is disabled and SYSTEM file://
won't work either.

- **Still vulnerable by default**: Java SAX/DOM/JAXB/JAX-WS without explicit
  hardening, PHP `DOMDocument`/`simplexml_load_*` with `LIBXML_NOENT` set,
  .NET `XmlDocument`/`XmlReader` with `XmlResolver` explicitly assigned,
  Ruby Nokogiri with `ParseOptions::DTDLOAD` explicitly enabled, older
  Apache Struts, and most embedded/IoT/firmware XML processors.
- **Hardened by default (verify before claiming exploitable)**: Python
  `xml.etree.ElementTree` >= 3.7.1, Python `lxml` (drops SYSTEM file
  content even with `resolve_entities=True`), Python
  `xml.dom.minidom`/`defusedxml`, Ruby Nokogiri's default config, .NET
  since 4.5.2 (`DtdProcessing.Prohibit` throws on any DOCTYPE).

## Precedent

- Adobe Commerce/Magento "CosmicSting" (CVE-2024-34102, CVSS 9.8, exploited
  in the wild): a REST API endpoint's nested deserialization reached
  `simplexml_load_string()` on an attacker-controlled body without
  `LIBXML_NOENT` protections. The resulting XXE loaded an external
  parameter-entity DTD that read `app/etc/env.php` (the admin crypt-key)
  and exfiltrated it via HTTP callback; the leaked key was then used to
  forge an admin authentication token, escalating to full RCE. Concrete
  precedent for XXE-to-RCE reached through a nominally-JSON API that
  internally re-parses XML -- don't rule out XXE just because the outer
  content type is `application/json`.
