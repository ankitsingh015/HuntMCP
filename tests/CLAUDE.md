# Tests — Scoped Rules

## Scope
These rules apply to tests under `tests/`.

## Test purpose
Tests must validate real intended behavior, not implementation convenience.

Prefer deterministic, isolated fixtures.

## Security tests
Security tests should exercise the actual security boundary where practical.

Use loopback/local controlled targets for target-touching tests unless explicit authorization says otherwise.

## Ground truth
Protected benchmark ground truth and evaluator logic must remain independent from implementation conclusions.

Do not change expected labels simply because a test fails.

## Test modifications
Before modifying a test, determine whether the failure is:
1. an implementation defect;
2. a test defect;
3. an environment problem;
4. an intentional contract change.

Only correct objectively incorrect tests.

## Cleanup
Tests must clean up servers, temporary files, processes, and other resources they create.

Do not leave real external state behind.

## Verification
Run focused tests first, then the relevant regression suite.

Use phase-specific verification scripts when provided.
