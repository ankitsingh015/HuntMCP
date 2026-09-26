---
title: "Stored XSS via Kroki diagram (GitLab)"
url: "https://hackerone.com/reports/1731349"
vuln_class: "Cross-site Scripting (XSS) - Stored"
tech: "GitLab, Ruby, Banzai, Kroki, Nokogiri"
bounty: 13950
program: "GitLab"
severity: "high"
votes: 295
content_quality: "full"
source: "HackerOne disclosed report"
date: 2023-06-02
---

## Summary
If Kroki is enabled, a `pre` block can be crafted so that arbitrary attributes are
injected into the resulting `img` tag.

## Root cause
The CSS selector matches either `pre[lang="<type>"] > code` or `pre > code[lang="<type>"]`,
but the diagram type is then taken from `node.parent['lang'] || node['lang']`. If the
`code` block has a valid lang (e.g. `wavedrom`) the selector matches, yet a `lang`
attribute on the parent `pre` overrides it and can be an arbitrary value. That value is
used verbatim in `create_image_src` and concatenated into `<img src="#{image_src}" />`,
so a `"` allows arbitrary attributes (except `class`, which is replaced just below).

## Steps to reproduce
1. On a self-hosted GitLab, enable Kroki (`/admin/application_settings/general`).
2. Create an issue with a payload such as:
   `<a><pre lang='f/" onerror=alert(1) onload=alert(1) '><code lang="wavedrom">xss</code></pre></a>`
3. Reload the issue — the alert fires (or a CSP violation is logged).

## CSP bypass
Use a `data-` based gadget instead of inline handlers. `data-diff-for-path` (from
`single_file_diff.js`) is used as the path to load and jQuery executes the returned
`data.html`, allowing an arbitrary JSON file to bypass CSP. Inject `style` to make the
Kroki overlay cover the page so the "expand diff" chevron is clickable.

## Impact
Arbitrary JavaScript executes when a victim views a comment.
