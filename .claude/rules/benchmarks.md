# Benchmark Rules

## Protected benchmark principle
Benchmark methodology, ground truth, labels, oracles, and evaluator logic are protected research assets.

Do not modify them merely to make the implementation pass.

## Ground truth
Ground truth must remain independent from implementation conclusions.

The implementation must never be able to derive the expected answer from evaluator-only material.

## Oracle integrity
Security-effect or success signatures must be explicit and independently justified.

Do not auto-derive a success oracle from the implementation's own output when the benchmark requires an independent oracle.

## Blindness
Where a benchmark is intended to be blind:
- implementation code must not access answer keys;
- semantic scenario names must not leak expected conclusions;
- evaluator-only artifacts must remain separated.

## Causal benchmarks
For causal/CEM evaluation:
- preserve planted labels;
- preserve independent evaluation;
- measure false causal conclusion rate;
- distinguish necessary, apparently-not-necessary, and inconclusive outcomes;
- treat inconclusive as distinct from an incorrect causal conclusion.

## Quality gates
A cost or efficiency improvement is not valid if it reduces required security quality.

In particular:
- missing a high/critical finding that the required baseline finds is a hard quality failure;
- false causal conclusions are hard failures where the acceptance criteria require zero;
- coverage regressions must be investigated.

## Benchmark changes
Any change to protected benchmark methodology requires explicit human approval.

Do not silently update expected labels because implementation behavior changed.

## Reproducibility
Record:
- benchmark version;
- test configuration;
- relevant seeds;
- target mode;
- request counts;
- verdicts;
- failures;
- verification results.

Claims must be reproducible from recorded evidence.
