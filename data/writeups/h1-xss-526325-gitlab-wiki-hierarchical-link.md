---
title: "Stored XSS in GitLab Wiki pages via hierarchical link Markdown"
url: "https://hackerone.com/reports/526325"
vuln_class: "Cross-site Scripting (XSS) - Stored"
tech: "GitLab, Ruby, Markdown, Banzai"
bounty: 0
program: "GitLab"
severity: "high"
votes: 629
cve: "CVE-2019-5467"
content_quality: "full"
source: "HackerOne disclosed report"
date: 2019-09-02
---

## Summary
Stored XSS using Wiki-specific hierarchical link Markdown in GitLab Wiki pages.

## Steps to reproduce
1. Sign in to GitLab.
2. Open a project whose Wiki you can edit.
3. Open a Wiki page and click "New page".
4. Set "Page slug" to `javascript:`.
5. Title: `javascript:` / Format: Markdown / Content: `[XSS](.alert(1);)`.
6. Click "Create page".
7. Click the "XSS" link -> the alert dialog fires.

## Root cause
GitLab converts the Markdown string `.alert(1);` into the href attribute
`javascript:alert(1);`. The Wiki-specific Markdown string `.` is converted to
`javascript:`. The `..` variant also converts to `javascript:`, and scheme-like
titles such as `JavaScript::SubClassName.function_name` are likewise affected, so
`data:`, `vbscript:` and other schemes can be used.

## Expected behaviour
The dangerous `javascript:` href should be filtered; a safe http/https link rendered instead.

## Impact
If a public project's Wiki visibility is "Everyone With Access", a large number of
GitLab users/visitors can be served the malicious link. CVE-2019-5467.
