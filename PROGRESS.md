# Progress: receipt 0.7 M1 PR1

## State

Migration step 1 is complete: compatibility fixtures and an unused policy
shell. Work was serial and offline, using the existing .venv. No version,
changelog, production caller, or existing refusal changes are authorized.
The pre-existing untracked issue-62.md is an input and is left untouched.
No -o filename was supplied. Final report destination:
/tmp/receipt-07-m1-pr1-output.md (outside the implementation diff).

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
- Precedence and append census controls: 36 passed in 15.34 s, including
  signed malformed-journal versus binding-only names, zero early attribute
  reads, real base-wrapper classes, state mode equality and manifest modes.
- Record qualification: an empty tree at a .json manifest child passes
  pre-genesis; only a nonempty tree gives the R2-L1 changed-release refusal.
  Both cases now have permanent full-string/class/outcome controls.

- Consumer import census: 85 checks pass, including Chronicle private helpers,
  sign-only adopters, retained values/types and all harness import surfaces.
- Added unused frozen policy shell with contracts and exact PR2 sentinel;
  12 shell tests pass, including both fresh-process import orders.
- Literal grep requested by the assignment also finds the pre-existing
  _screen_protected_tree_names helper in append_gate/release_chain/verify.
  Retained those symbols; AST import audit plus whole-word grep proves that
  no production caller imports the shell.
- Host: macOS 26.6.2 arm64, APFS; case probe resolves CaseProbe/caseprobe
  to the same inode (case-insensitive).

- Completed retained spec-path, redirecting-environment and bounded-quote
  goldens (9 tests). Split captured expectations by census/D identifier; every
  Python test and JSON expectation file is below 1,500 lines.

- Every new test file has passed alone: golden 247, directory 32, budgets 21,
  inputs 9, D fixtures 55, precedence 36, consumer imports 85, shell 12.
  Total additions: 497 tests.
- Both fixture settings pass all 497 additions with zero skips: ignoreCase=true
  in 115.10 s and ignoreCase=false in 103.31 s. Same goldens in both runs.
- Scope inspection: only src/receipt/protected_tree.py differs under src;
  CHANGELOG.md, package version and existing source/tests are unchanged.

- Final expanded non-harness suite: 1,968 passed, zero skips, 396.40 s;
  baseline was 1,471. Exactly 497 tests were added. All existing tests pass.
- Final report written to /tmp/receipt-07-m1-pr1-output.md with every added
  file/line count, isolated/whole/ignoreCase results, all D test names, verbatim
  swaps, record/request qualifications, filesystem and excluded gates.
- Final diff and trailer checks pass. Existing production source/tests,
  version and changelog remain unchanged. No network operations or installs.

## Next

No PR1 implementation work remains. The maintainer runs the 108 excluded
harness cases and any independent review before merge on a networked host.
Later migration steps remain out of scope. Nothing was pushed or opened as a PR.
