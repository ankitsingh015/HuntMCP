---
title: "Race Condition in Coupon Redemption — Unlimited Usage"
url: "https://hackerone.com/reports/6789012"
vuln_class: "Race Condition"
tech: "Node.js, MongoDB, Express"
bounty: 3500
date: 2026-07-05
---

## Summary

A race condition in the coupon redemption endpoint allowed applying the same coupon multiple times. By sending concurrent requests, the usage-count check was bypassed, enabling unlimited discounts.

## Steps to Reproduce

1. Get a single-use coupon code: `SAVE50`
2. Send 20 concurrent POST requests to `/api/cart/apply-coupon` with `code=SAVE50`
3. Observe that 15-18 requests succeed — each applies the 50% discount
4. Repeat with more threads for higher success rate

## Vulnerable Code Pattern

```javascript
app.post('/api/cart/apply-coupon', async (req, res) => {
    const coupon = await Coupon.findOne({ code: req.body.code });
    if (coupon.used_count >= coupon.max_uses) {
        return res.status(400).json({ error: 'Coupon exhausted' });
    }
    // Race window: multiple requests pass the check simultaneously
    await Cart.applyDiscount(req.user.id, coupon.discount);
    await Coupon.updateOne({ _id: coupon._id }, { $inc: { used_count: 1 } });
});
```

## Impact

Unlimited discount application — attacker can get 100% off orders or cause significant revenue loss.

## Remediation

- Use atomic operations: `Coupon.updateOne({ _id: id, used_count: { $lt: max_uses } }, { $inc: { used_count: 1 } })`
- Evaluate result — if `matchedCount === 0`, reject
- Use database-level optimistic locking
- Implement idempotency keys per coupon request
