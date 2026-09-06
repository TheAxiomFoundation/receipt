# Progress: receipt 0.7 M1 PR1

## State

Implementing migration step 1 only: compatibility fixtures and an unused policy
shell. Work is serial and offline, using the existing .venv. No version,
changelog, production caller, or existing refusal changes are authorized.
The pre-existing untracked issue-62.md is an input and is left untouched.
No -o argument was supplied; final report destination: M1-PR1-REPORT.md.

## Done

- Read the approved record, 0.6.1/0.6.0 changelog, CONTRIBUTING, applicable
  agent rules, and located the existing tests using git ls-files tests.
- Identified harness filename correction: test_brier_witness_equivalence.py
  is the actual witness harness (the prompt calls it test_witness_equivalence.py).
- Established this committed state/done/next log before implementation.

## Next

- Read the cited compatibility tests and measure the non-harness baseline.
- Capture actual outputs, add census goldens, and commit.
- Port D1–D12; commit. Add precedence/swap controls; commit.
- Add consumer import smoke tests; commit. Add frozen unused shell; commit.
- Run new files separately and under both fixture ignoreCase settings, run
  the expanded non-harness suite, inspect scope, and write the final report.
