# Progress: five review findings on `receipt` PR #38

Branch `fix/append-gate-confinement`, worktree
`_worktrees/receipt-fix-append-gate-confinement`. Baseline at a8dbd41: offline
suite 267 passed, 94 deselected. Now 288 passed, 94 deselected.

## State

Done. All five round-4 findings are implemented, tested, and committed; the PR
body file and the lane report are written. The worktree is clean and nothing
is pushed.

The differential harness never mutates a file mode and never leaves an
index/worktree mode disagreement, so the F2 index check cannot fire there; the
four network harnesses need cloning and were not run in this lane.

## Done

- F4 (c8c5fcd): `_git_environment()` with `GIT_NO_REPLACE_OBJECTS=1` on every
  git subprocess in both modules; a `git replace` test plus a control.
- F1 + F5 (50cad6f): the checkout guard runs once at entry to
  `verify_append_gate`, after base resolution, for the push path too; the
  release-history pass resolves its base before its own guard; the module
  docstring states the ordering exception. Push-path helper and tests.
- F2 (65f76bd, 8d17cf8): `release_chain.assert_index_agrees_with_tree`, called
  for both state files in `check_state_modes` and for every compared release
  file in `verify_release_history_immutable`. The four existing mode-change
  tests stage their change, as a real proposal does.
- F3 (b42079d): `_read_state_snapshot` reads each state file once
  (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, lstat before / fstat after, recorded
  identity); every consumer in `append_gate` is fed those bytes, and
  `_assert_state_unchanged` re-reads both files after the last consumer.
- Docstrings and precedence (bf46a4a, e8ef3af): every new test names the
  finding it binds; the stated ordering exception covers both guards that say
  a comparison cannot be made, each pinned by a test.

## Next

Nothing in this lane. For the orchestrator: re-run the four network
differential harnesses on this head, and drop this file if it should not ship.
