"""DEPRECATED / TRIPWIRE. The old combined ground_truth structure has been split into a
BLIND scenario manifest (scenarios.py, CEM-facing) and an EVALUATOR-ONLY answer key
(answer_key.py). Importing this module is a bug: it means something is reaching for the
old combined structure that leaked answers alongside inputs. It raises on import so any
such path fails loudly rather than silently leaking the answer key to CEM.
"""
raise ImportError(
    "tests/fixtures/cem_target/ground_truth.py is retired. Use scenarios.py (blind, "
    "CEM-facing) and answer_key.py (evaluator-only). See PHASE1-EXECUTION-PLAN.md."
)
