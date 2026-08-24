---
name: dos-and-resilience
description: Denial-of-service and resilience testing techniques -- rate-limit batching bypass, ReDoS, unbounded input, decompression bombs, HPP-based DoS, and resource-exhaustion probing. Converted from master-pentest-prompt.md Phase 15. Use to check whether rate limits and input validation actually hold up, not just whether they exist.
---

# DoS & resilience

## When to use

Any target with rate limits worth verifying, or regex-based validation
whose complexity is unknown. Keep in mind HuntMCP's own rate-limit
policy from the `engagement-setup` skill (1s delay by default, back off
on 429) applies to how *you* send requests here too -- resilience testing
is not a license to hammer a target harder than the engagement's own
rate-limit policy allows.

## Techniques

- **Batching bypass of rate limits**: array-based batch requests,
  GraphQL aliases used to smuggle many effective requests inside one
  rate-limited call.
- **ReDoS**: crafted input against a regex-validated field; billion-laughs
  style entity expansion (see the `xxe` skill for the XML-specific
  variant).
- **Unbounded input**: field length limits, multiple-file upload limits,
  zip-decompression bombs.
- **HPP DoS**: HTTP Parameter Pollution used to amplify processing cost.
- Header amplification.
- Slowloris-style connection exhaustion, general resource-exhaustion
  probing, expensive-route probing (endpoints doing heavy computation per
  request).
