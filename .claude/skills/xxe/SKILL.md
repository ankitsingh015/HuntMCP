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
