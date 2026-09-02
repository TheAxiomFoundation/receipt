# Progress: five review findings on `receipt` PR #38

Branch `fix/append-gate-confinement`, worktree
`_worktrees/receipt-fix-append-gate-confinement`. Baseline at a8dbd41: offline
suite 267 passed, 94 deselected.

## State

F4, F1, F5, and F2 are implemented, tested, and committed. F3 (the state-file
snapshot reader) is next, then the PR body and the lane report.

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
- F2 (this commit): `release_chain.assert_index_agrees_with_tree`, called for
  both state files in `check_state_modes` and for every compared release file
  in `verify_release_history_immutable`.

## Next

1. F3: read each state file once through a snapshot reader
   (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, lstat before / fstat after, recorded
   identity), feed every `append_gate` consumer from those bytes, and re-read
   after the last consumer; FIFO and swapped-ledger tests.
2. Update the PR body file and write the lane report.
