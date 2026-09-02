# Progress: five review findings on `receipt` PR #38

Branch `fix/append-gate-confinement`, worktree
`_worktrees/receipt-fix-append-gate-confinement`. Baseline at a8dbd41: offline
suite 267 passed, 94 deselected.

## State

All five findings are implemented, tested, and committed. What is left is the
PR body and the lane report.

The differential harness never mutates a file mode and never leaves an
index/worktree mode disagreement, so the F2 index check cannot fire there.
Through the gate it does fire on an unstaged chmod, so the four existing
mode-change tests now stage their change (`stage()` helper) the way a real
proposal does; their asserted messages are unchanged.

## Done

- F4 (c8c5fcd): `_git_environment()` with `GIT_NO_REPLACE_OBJECTS=1` on every
  git subprocess in both modules; `git replace` test plus a control.
- F1 + F5 (50cad6f): the checkout guard runs once at entry to
  `verify_append_gate`, after base resolution, for the push path too; the
  release-history pass resolves its base before its own guard; the module
  docstring states the one ordering exception. Push-path helper and tests.
- F2 (65f76bd): `release_chain.assert_index_agrees_with_tree`, called for
  both state files in `check_state_modes` and for every compared release file
  in `verify_release_history_immutable`.
- F3 (this commit): `_read_state_snapshot` reads each state file once
  (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, lstat before / fstat after, recorded
  identity); every consumer in `append_gate` is fed those bytes, and
  `_assert_state_unchanged` re-reads both files after the last consumer.

## Next

1. Update the PR body file and write the lane report.
