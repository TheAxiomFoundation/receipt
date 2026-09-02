# Progress: five review findings on `receipt` PR #38

Branch `fix/append-gate-confinement`, worktree
`_worktrees/receipt-fix-append-gate-confinement`. Baseline at a8dbd41: offline
suite 267 passed, 94 deselected.

## State

Starting. Read `append_gate.py`, `release_chain.py`, both test modules, the
differential harness, and the PR body. Confirmed the harness never mutates a
file mode and never leaves an index/worktree mode disagreement, so the F2
index check cannot fire there.

## Done

- (nothing yet)

## Next

1. F4: `_git_environment()` in `release_chain`, used by every git subprocess in
   both modules; `git replace` test.
2. F5: resolve the base first, then the checkout guard; narrow the module
   docstring; invalid-ref-under-`core.fileMode=false` test.
3. F1: run the checkout guard on the no-base path too; push-path test helper.
4. F2: `assert_index_agrees_with_tree`, called from `check_state_modes` and
   `verify_release_history_immutable`; existing mode tests must stage their
   mode change (the index check runs before the base comparison by design).
5. F3: snapshot reader for both state files; re-read after the last consumer.
6. PR body + lane report.
