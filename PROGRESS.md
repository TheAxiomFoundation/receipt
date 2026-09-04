# Lane D progress

## State

- Branch: `feat/0.6-lane-d` at baseline `145f3db93d745ddc43aeb47f6b7bd8b30aa331a3`.
- Phase: shared name-policy screen complete; immutable-tree corpus rewrite next.
- Scope: immutable-tree corpus verification, shared name-policy additions, corpus fixture commit helpers, and focused tests.
- Network is sandbox-disabled; local work, tests, commits, and a complete draft PR body remain possible. Push/PR creation will be attempted only after all gates pass.

## Done

- Read PLAN-0.6 sections 3.1, 2, 3.3, 3.6, 3.9, 4, and section 5's final paragraph in the required order.
- Read `receipt.snapshot`'s contract and the required `TreeSnapshot` APIs.
- Read `receipt._names`; the Win32 reserved-device table is already present and exported, while the 8.3 extension screen still needs a stable shared export.
- Confirmed the worktree is clean and starts at the requested merged Lane A/Lane E baseline.
- Recorded the non-negotiable implementation shape: one whole-tree listing, per-directory ASCII-fold screens, listing-derived membership/tombstones, exact attested entry lookups, and `TreeSnapshot.digests` for every content digest.
- Baseline focused suite: 272 passed (`tests/test_corpus.py` plus `tests/test_snapshot_names.py`).
- Added stable `_names.py` exports for the established 8.3 extension operation: `ALIAS_CAPABLE_SUFFIX_RE`, `SHORT_NAME_PUNCTUATION`, `short_name_extension`, and `short_name_carries_pinned_suffix`.
- Added focused tests freezing operation order and alias-capable-pin filtering; name suite: 68 passed.

## Next

1. Finish the caller/refusal/test census from the parallel read-only inventories.
2. Replace the filesystem corpus subject with `TreeSnapshot`, preserve retained refusals, and commit deletion/feature groups separately.
3. Rework the corpus tests around committed trees, add repertoire/tree-shape/property coverage, and update fixture commit helpers.
4. Run focused, offline, and equivalence gates; prepare the required PR body and final report with exact totals and OIDs.

## Findings

- None yet against `snapshot.py`; it remains out of scope and will not be changed.
