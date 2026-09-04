# Testing Rules

## Testing hierarchy

Use the strongest applicable validation:

1. unit tests;
2. integration tests;
3. controlled black-box tests;
4. behavioral/security tests;
5. regression suite;
6. independent evaluation where required.

Do not treat static inspection as sufficient proof of runtime behavior.

## Black-box validation
When behavior is externally observable, test through the public boundary where practical.

For security behavior, validate real request/response effects rather than relying only on internal function results.

## Human-like behavior
Security workflows should validate the logical sequence:

Observe → baseline → hypothesize → perturb → repeat/replicate → compare evidence → handle uncertainty → conclude.

Avoid tests that only exercise an idealized internal call sequence.

## Mutation testing
Where applicable, validate both:
- vulnerable behavior;
- patched/non-vulnerable behavior.

The system should distinguish them reliably.

## Tests must be meaningful
Do not:
- weaken assertions;
- remove failing cases without justification;
- broaden tolerances solely to pass;
- mock away the behavior under test;
- alter ground truth to match implementation output.

Ordinary tests may be corrected when objectively incorrect, but not merely to make an implementation pass.

## Test isolation
Tests must:
- avoid real external targets unless explicitly authorized;
- clean up resources;
- avoid persistent side effects;
- use deterministic fixtures where possible;
- avoid leaking credentials or sensitive data.

## Regression
Run focused tests after each change, followed by the relevant broader suite.

When a phase has a defined verification script, use it.

## Failure handling
A failing test is evidence requiring diagnosis, not an obstacle to bypass.

Record the cause and verification result before marking the task complete.
