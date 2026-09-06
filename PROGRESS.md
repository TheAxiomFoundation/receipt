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
- Baseline: 1,471 passed, zero skips, 328.36 s (four harnesses excluded).
- Added raw-object fixture builder and 300 census golden tests; captured all
  strings from actual runs and verified 300 passed in 46.27 s.
- Physical reader/serialization defenses include fault injections for races,
  permission failures, and JSON-key collision; no production changes.
- mount reports APFS; diskutil is unavailable inside this sandbox.
- D1–D12: 55 tests passed in 35.25 s. Exact values cover the CLI and
  chain names/materialization/binding/base/append preflight on identical trees,
  plus caller anchors, direct-directory reads, gate-only success, and D12 28/40.
- Disabled Git core.precomposeUnicode in fixtures after detecting NFD collapse;
  now assert both Unicode spellings actually exist in the raw tree.
- Reproduced F1 in a standalone probe before writing assertions: both swapped
  winners and both single-fault controls match the record exactly.

## Next

- Capture and verify precedence/swap controls; commit.
- Add consumer import smoke tests; commit. Add frozen unused shell; commit.
- Run new files separately and under both fixture ignoreCase settings, run
  the expanded non-harness suite, inspect scope, and write the final report.
