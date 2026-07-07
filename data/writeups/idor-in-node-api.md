---
title: "IDOR in Node.js User Profile API"
url: "https://bugcrowd.com/submissions/..."
vuln_class: "IDOR"
tech: "Node.js, Express, MongoDB"
bounty: 2500
date: 2026-07-01
---

## Summary

An Insecure Direct Object Reference vulnerability was discovered in the user profile API endpoint. The endpoint `GET /api/users/:id` returned full user details without verifying that the requesting user was authorized to access the specified user's data.

## Steps to Reproduce

1. Register two accounts (User A and User B)
2. Authenticate as User A and get your JWT token
3. Make a GET request to `/api/users/123` (User B's ID)
4. Observe that User B's email, phone number, and address are returned

## Vulnerable Endpoint

```
GET /api/users/:id
Authorization: Bearer <token>
```

## Vulnerable Code

```javascript
router.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);
  // Missing: check that req.user.id === req.params.id
});
```

## Impact

An attacker can enumerate all user IDs and extract Personally Identifiable Information (PII) including email addresses, phone numbers, and physical addresses. This is a GDPR/CCPA violation.

## Remediation

Add authorization checks to verify the requester owns the resource or has admin privileges:

```javascript
router.get('/api/users/:id', authenticate, async (req, res) => {
  if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = await User.findById(req.params.id);
  res.json(user);
});
```

Use UUIDs instead of sequential ObjectIds for user IDs to make enumeration harder.
