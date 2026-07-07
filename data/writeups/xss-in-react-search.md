---
title: "Reflected XSS in React Search Component"
url: "https://hackerone.com/reports/1234567"
vuln_class: "XSS"
tech: "React"
bounty: 1500
date: 2026-06-15
---

## Summary

A reflected cross-site scripting vulnerability was found in the search component of a React-based web application. The search query parameter was reflected in the page without proper sanitization, bypassing React's built-in XSS protection due to the use of dangerouslySetInnerHTML.

## Steps to Reproduce

1. Navigate to the application's search page
2. Inject the following payload in the search parameter: `"><img src=x onerror=alert(1)>`
3. Observe that the payload executes in the browser

## Root Cause

The application used `dangerouslySetInnerHTML` to render search suggestions that included the user's search term with bold formatting. While React normally escapes JSX output, `dangerouslySetInnerHTML` bypasses all sanitization.

Vulnerable code pattern:
```jsx
function SearchResults({ query }) {
  return (
    <div dangerouslySetInnerHTML={{
      __html: `Showing results for <b>${query}</b>`
    }} />
  );
}
```

## Payloads Tested

Basic:
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
```

React-specific:
```
{{constructor.constructor('alert(1)')()}}
```

## Impact

An attacker can craft a malicious link that, when clicked by an authenticated user, executes arbitrary JavaScript in the context of the victim's session. This enables session hijacking, credential theft, and internal network scanning.

## Remediation

Replace `dangerouslySetInnerHTML` with React's JSX interpolation. If HTML rendering is necessary, use DOMPurify to sanitize input:
```jsx
import DOMPurify from 'dompurify';
function SearchResults({ query }) {
  return (
    <div dangerouslySetInnerHTML={{
      __html: DOMPurify.sanitize(`Showing results for <b>${query}</b>`)
    }} />
  );
}
```
