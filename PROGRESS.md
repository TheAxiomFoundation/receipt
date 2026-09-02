# Progress: seven review findings on `receipt` PR #39

Branch `fix/corpus-closed-world`, worktree
`_worktrees/receipt-fix-corpus-closed-world`. Scope is limited to
`src/receipt/corpus.py`, one bounded change in `src/receipt/cli.py`,
`tests/test_corpus.py`, and one end-to-end test in `tests/test_cli.py`.

## State

Baseline measured: **247 passed, 94 deselected** (`-k "not equivalence"`) at
78b902d. Module read; every pinned refusal message inventoried.

## Findings

| # | What | Status |
|---|------|--------|
| F1 | native lstat of the tombstoned spelling; Win32 alias shapes refused in declared paths | todo |
| F2 | `_assert_assigned` applied to every tree entry name examined | todo |
| F3 | shared per-verification directory index, one `MAX_TOMBSTONE_WORK` entry budget | todo |
| F4 | every tree-derived path in a refusal goes through `_quoted`; CLI end-to-end test | todo |
| F5 | every producer-controlled value quoted in a refusal goes through `_quoted` | todo |
| F6 | content-root membership compares fold keys; aliasing root components refuse | todo |
| F7 | the intermediate-component `lstat` probe moves inside the OSError handler | todo |

## Next

1. F7 then F1 (same function, smallest first).
2. F3 (restructures the fold search).
3. F2, F5, F4, F6.
4. Rewrite the PR body paragraphs; write the lane report.
