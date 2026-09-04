# Lane D progress

## State

- Branch: `feat/0.6-lane-d` at baseline `145f3db93d745ddc43aeb47f6b7bd8b30aa331a3`.
- Phase: subjectless corpus tests removed; retained-test conversion and replacement cases are in progress.
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
- Added default-on commits to `build_corpus` and `append_release`, with bounded Git setup, validated returned OIDs, and an explicit `commit=False` opt-out. `BuiltCorpus.commit_oid` adds the build OID without moving its existing spec/path positions.
- Corrected the immutable listing screen to flatten the authenticated `TreeListing` exactly once before validating entry names and directory sibling sets. This avoids charging every full path twice against the reader's shared path-byte budget and keeps snapshot failures translated to `CorpusError`.
- Restored the pre-existing `CorpusSpec content root` portable-name diagnostic while allowing `posix-bytes` roots through the general repertoire-aware path screen.
- Production review smoke: five focused binding/spec cases pass after the single-flattening correction.
- Deleted exactly 57 tests whose host-filesystem, race, re-sweep, ctime, identity, or superseded work-index subject no longer exists, plus four fake-directory-listing collision tests that the committed-tree shape matrix replaces. Nineteen test-only filesystem scaffolds went with them.
- Retained focused battery after that deletion: 198 passing cases and 18 expected migration failures. Those failures are confined to stale Unicode-normalization assertions, host-conditional spelling assertions, fake `os.scandir` entries, and removed private instrumentation; no parser, digest, membership, or declaration regression appears.

## Next

1. Convert the 18 retained host-shaped assertions to immutable committed-tree assertions.
2. Add repertoire/tree-shape/property coverage.
3. Run focused, offline, and equivalence gates; prepare the required PR body and final report with exact totals and OIDs.

## Findings

- No defect found in `snapshot.py`; it remains out of scope and unchanged.
- `src/receipt/verify.py` still passes a `Path` to the intentionally breaking API. Lane C owns and is concurrently changing that caller; this branch's full offline suite will retain that expected integration failure until Lane C is merged or its change is available.
- `tests/test_cli.py` has one `committed_repo` fixture that initializes and commits a second time; default fixture commits make that second commit empty. The CLI file belongs to Lane C, so this lane records the integration point and does not edit it.
- Section 3.6's final `verify_declarations` step remains the separate pass that `run_verification` already performs after binding. Calling it inside `verify_corpus_binding` would collapse the public binding/declaration pass boundary and make Lane C's unchanged call duplicate the check.
- Baseline census: 199 corpus test functions / 206 collected cases. Exactly 57 current functions have vanished filesystem/race/index subjects (43 host/race, 14 obsolete budget/index); replacement tree-shape/property cases will restore the required coverage, not those subjects.
