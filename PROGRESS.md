# Lane D progress

## State

- Branch: `feat/0.6-lane-d` at baseline `145f3db93d745ddc43aeb47f6b7bd8b30aa331a3`.
- Phase: obsolete filesystem implementation removed; corpus test migration is next.
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
- Added defaulted `CorpusSpec.name_repertoire` and `CorpusVerification.name_repertoire`, with closed-value and `posix-bytes` spec coverage.
- Changed the public corpus binding API to require an entered `TreeSnapshot`; a `Path` now refuses with explicit `TreeSnapshot.select` guidance.
- Implemented the required pass order over one whole-tree listing: shared per-directory name screens, listing-derived content and tombstone indexes, exact attested lookups, then one streamed `snapshot.digests` pass.
- Preserved the content membership, digest, required-attested, tombstone, root-alias, and 8.3 refusal texts in the new path; added explicit symlink and gitlink diagnostics for tree modes.
- Snapshot smoke battery: 7 targeted corpus cases passed (happy path, Path refusal, digest/membership failures, and repertoire construction).
- Deleted the private worktree verifier and all subjectless filesystem machinery: directory listing/generations, sweep/spelling/tombstone work indexes, symlink component walks, file identity/digest reads, closing re-sweep/re-checks, the POSIX ctime precondition, and their three superseded tree-work constants.
- Replaced the 485-line filesystem/pass-order module narrative with the immutable-tree claim and checkout-fidelity boundary.
- Production source now has no worktree read, stat call, per-blob process, or second tree pass; 75 targeted corpus/name cases pass after the deletion.

## Next

1. Delete the 57 subjectless host/race/budget tests and convert retained tests to committed snapshots.
2. Add repertoire/tree-shape/property coverage and update fixture commit helpers.
3. Run focused, offline, and equivalence gates; prepare the required PR body and final report with exact totals and OIDs.

## Findings

- No defect found in `snapshot.py`; it remains out of scope and unchanged.
- `src/receipt/verify.py` still passes a `Path` to the intentionally breaking API. Lane C owns and is concurrently changing that caller; this branch's full offline suite will retain that expected integration failure until Lane C is merged or its change is available.
- Baseline census: 199 corpus test functions / 206 collected cases. Exactly 57 current functions have vanished filesystem/race/index subjects (43 host/race, 14 obsolete budget/index); replacement tree-shape/property cases will restore the required coverage, not those subjects.
