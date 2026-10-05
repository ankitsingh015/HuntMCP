---
title: "Stealing HttpOnly cookies with the cookie sandwich technique"
url: "https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique"
vuln_class: "Cookie Security / XSS (HttpOnly bypass)"
tech: "Apache Tomcat, Python frameworks, CORS"
bounty: 0
source: "PortSwigger Research"
content_quality: "full"
date: 2025-01-22
---

## Cookie sandwich
Manipulate how servers parse cookie headers with special characters + legacy cookies, so the server
misinterprets cookie structure and exposes HttpOnly cookies to JS.

Because Chrome doesn't support legacy cookies, an attacker can create a cookie starting with `$`
(e.g. `$Version`) from JavaScript, and quotes are allowed inside any cookie value:
```js
document.cookie = `$Version=1;`;
document.cookie = `param1="start`;   // anything between here gets swallowed into param1 server-side
document.cookie = `param2=end";`;
```
Resulting header:
```
Cookie: $Version=1; param1="start; sessionId=secret; param2=end"
=>  Set-Cookie: param1="start; sessionId=secret; param2=end";
```

## Framework behaviour
- **Apache Tomcat** defaults to legacy RFC2109 parsing when a string starts with `$Version`; a value
  starting with `"` is read until the next unescaped `"`, and `\` is unescaped. Tomcat 8.5.x/9.0.x/
  10.0.x default to RFC2109.
- **Python frameworks** support quoted strings by default (no `$Version` needed) and encode special
  chars as `/` + 3-digit octal: `Set-Cookie: param1="start\073 sessionId=secret\073 param2=end";`

## Real-world: stealing an HttpOnly PHPSESSID
1. **XSS**: reflected link/meta attributes; WAF bypassed via
   `<link rel="canonical" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">`
2. **Exposed cookie param**: a tracking endpoint (`/json?session=`) reflects the cookie value and
   allows cross-origin (ACAO + ACAC:true) from the vulnerable domain.
3. **Cookie downgrade**: use `$Version=1` to switch to RFC2109, control cookie order via `path`
   (`path=/json`), then sandwich `PHPSESSID` between `session="deadbeef;` and `dummy=qaz"`.
```
GET /json?session=ignored
Host: tracking.example.com
Origin: https://www.example.com
Cookie: $Version=1; session="deadbeef; PHPSESSID=secret; dummy=qaz"
```
4. Combine: XSS sets the cookies + makes the credentialed CORS request -> response leaks PHPSESSID.

Final exploit JS: create an iframe to the tracking `target`, set `$Version=1`, `session="deadbeef`,
`dummy=qaz"` with matching `domain`/`path`, then `fetch(target, {credentials:'include'})` and read
the reflected session from the JSON.

## Recommendation
Understand cookie encoding/parsing per framework + browser. Tomcat supports RFC2109 by default.

## Follow-on
Bypassing WAFs with the phantom `$Version` cookie; Cookie Chaos (`__Host`/`__Secure` bypass).
