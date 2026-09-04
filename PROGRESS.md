| # | Mechanism | 0.6 |
|---|---|---|
| 1 | Partial staging, index versus working tree versus commit | CLOSE: one subject, tree T |
| 3 | A writer during the run | CLOSE for the commit-addressed entry points (`verify_append_gate`, `run_verification`, `verify_corpus_binding`) against any writer outside this process's ownership: objects are content-addressed and rehashed, and the only pathname read is the private materialization, which carries row 15's same-uid assumption; STATE for a same-owner writer to the repository's configuration files, which every git process re-reads — detected by the closing re-audit (3.2), not excluded; STATE for a direct `verify_release_chain` caller on a live directory (section 3.5) |
| 6 | Object store or alternate substituting content under a named OID | CLOSE by rehash to the reach of plain SHA-1's collision resistance (row 13 states what lies beyond it); an unavailable object fails closed |
| 8 | Submodules at or under protected paths and content roots | CLOSE: `160000` refuses |
| 9 | Attributes and filters | CLOSE for the commit-addressed entry points (they read raw blob bytes; `filter`, `ident`, `working-tree-encoding` refused on protected paths); STATE for checkouts and for a direct `verify_release_chain` caller (`text`, `eol`, `core.autocrlf`, LFS pointers, whatever the checkout applied) |
| 11 | Symlinked components | CLOSE for the commit-addressed entry points: `120000` is an entry, not a redirection; for a direct `verify_release_chain` caller the retained component walks refuse a link as today (section 3.5) |
| 12 | Name folding and Win32 aliases | CLOSE the verdict's half (screens over tree names, fold-merge siblings refused under every repertoire); STATE the checkout's half (repertoire named in the verdict) |
| 13 | Snapshot identity | CLOSE naming (commit, tree, object format printed; `--expect-commit` and `--expect-tree`); STATE binding (the journal cannot bind the tree that holds the manifest; #35 is the later closure); collision substitution, STATE by default and CLOSE to the reach of git's own detector under `--verify-objects`: the rehash is `hashlib.sha1`, plain SHA-1, and would accept a colliding pair substituted under one OID; `--verify-objects` runs the store-wide `fsck` of 3.3 step 4b (heads given, `--full`, no refs, no index, no commit graph, alternates refused at entry, object and byte counts, output and wall-clock bounds, the configuration boundary with `fsck.*` keys refused, and a preflight that the build's SHA-1 is `SHA1_DC` — measured on this build with `git version --build-options`; `fsck --full` over rulespec-us, 79,890 objects, takes 6.4 seconds, measured), which detects objects produced by the known SHA-1 collision constructions; it is off by default because its subject is the store, not the tree (3.1). What its test can be is stated plainly and put to the peer: a known-collision fixture cannot exist as git objects (the SHAttered pair collide on their raw bytes, and git's `blob <size>\0` header precedes them, so as objects they hash apart; and git's own single-file detection fixture does not fire through an object read either, because the object header shifts the block alignment the detector keys on — measured by the peer in round 3 — which is why the build-options preflight is the only attestation the option has), so the option's test corrupts one byte inside a pack after `git repack`, past the first packed object, and shows the option refuses on `fsck`'s nonzero exit (measured this session), which exercises the integrity path every SHA-1 build shares and not SHA1DC's detection itself — that detection is git's, attested only by the build-options preflight; the plan asks the peer to accept that test and that preflight in place of a collision test, and to accept the default as a stated residual; SHA-256 repositories are refused at `select()` with a stated message until a SHA-256 fixture covering commit, tree and blob parsing and corruption exists, at which point the refusal is lifted in its own gated change |

## Lane D disposition by residual

- Row 1: `verify_corpus_binding` now accepts only an entered `TreeSnapshot`. One authenticated tree listing supplies the closed-world set, and the #44 property proves rewrite, insertion, and rename operations in the index-independent working tree cannot change the verdict or selected OIDs.
- Row 3: corpus binding performs no worktree pathname read, `stat`, directory walk, or live-tree recheck. It reads immutable entries and authenticated streamed digests from the selected object. Repository-configuration re-audit belongs to the surrounding snapshot/verdict lanes.
- Row 6: every selected blob reaches the Lane A reader's object-name rehash through `TreeSnapshot.digests`; unavailable or malformed entries fail closed as `SnapshotError` translated to `CorpusError`.
- Row 8: every `160000` entry below a content root refuses explicitly under both repertoires. Exact attested paths must resolve to a regular blob. The wider protected-path scan remains Lane B's append-gate responsibility.
- Row 9: corpus binding hashes raw blob bytes and never invokes checkout filters. Attribute refusal and the final claim wording remain the surrounding Lane B/C integration responsibility.
- Row 11: a `120000` entry is classified from the tree mode and never followed. A suffix-bearing content symlink gets the retained regular-file refusal under both repertoires.
- Row 12: every tree component must decode as UTF-8 before it can be quoted or ASCII-folded, and every tree directory refuses ASCII-fold-equal siblings under both repertoires. `portable` additionally applies the existing repertoire, Win32 device-name table, and shared 8.3 extension screen. `CorpusVerification.name_repertoire` records the verdict-side choice.
- Row 13: this lane consumes the commit/tree identity already selected by `TreeSnapshot`; the #44 property preserves both OIDs across checkout mutation. Rendering the identity, expectation pins, object-format reporting, and the stated collision residual remain Lane A/C work.

## Implementation

`verify_corpus_binding(snapshot: TreeSnapshot, journal_bytes, *, spec) -> CorpusVerification` has no directory mode. Passing a `Path` refuses exactly with `verify_corpus_binding requires a TreeSnapshot; select one with TreeSnapshot.select`.

The immutable pass order is:

1. Parse the journal with the unchanged #39 byte, row, text, evidence, and rendering budgets and screens.
2. Reject content/attested aliases at every prefix depth.
3. Ask `snapshot.entries("")` once, flatten the authenticated listing once, screen every entry through the selected shared name repertoire, and run the shared ASCII-fold sibling check for every tree directory.
4. Derive content membership from that listing, apply pinned suffix and portable-only 8.3 screens, and require `100644`/`100755` blobs while naming symlinks and gitlinks precisely.
5. Ask exact and ASCII-fold indexes from the same listing once for every tombstone.
6. Resolve every attested path exactly with `snapshot.entry` and require a regular blob.
7. Stream all bound entries once through `snapshot.digests(..., per_blob=MAX_CONTENT_BLOB_BYTES, total=MAX_CONTENT_BYTES_TOTAL)` and compare the yielded SHA-256 values without retaining any payload.
8. Keep `verify_declarations` unchanged as the explicit next verifier pass. `run_verification` already invokes it immediately after corpus binding; Lane C's snapshot migration preserves that public pass boundary and avoids running the same declaration check twice.

The module docstring now states that the listing is an immutable tree object and that checkout fidelity is outside the claim. The old filesystem pass-order and ctime narrative is gone. `src/receipt/snapshot.py` is unchanged; no reader defect was found.

## Name repertoire and API handoff

- `CorpusSpec.name_repertoire: Literal["portable", "posix-bytes"] = "portable"` keeps every existing consumer spec valid.
- `CorpusVerification.name_repertoire` is the Python verdict field. Lane C should copy it to `VerifyResult.name_repertoire` and render `nameRepertoire`; a `posix-bytes` binding therefore reports `nameRepertoire: "posix-bytes"`.
- Under both repertoires, undecodable names and ASCII-fold-merge siblings refuse. No NFC normalization or Unicode `casefold` model was reintroduced.
- Only `portable` applies `assert_portable_name`, the existing exported `WIN32_RESERVED_DEVICE_NAMES`, and the 8.3 extension screen.
- Stable shared exports added for Lane B are `SHORT_NAME_PUNCTUATION`, `ALIAS_CAPABLE_SUFFIX_RE`, `short_name_extension`, and `short_name_carries_pinned_suffix`.
- `tests.corpus_fixture.build_corpus(..., commit=True)` and `append_release(..., commit=True)` now return the created commit OID directly; `commit=False` returns `None` and leaves the generated tree uncommitted.

## Deleted because its subject no longer exists

The deletion commit states the reason directly: its subject no longer exists. Removed production machinery is `_list_directory`, `_directory_generation`, `_DirectoryGenerations`, `_TombstoneIndex`, the filesystem half of `_fold_survivor`, `_assert_spelled_by_its_directory`, `_SpellingWork`, `_assert_no_symlinked_component`, the stat side of `_assert_no_aliasing_root_component`, `_regular_file_digest`, `_FileIdentity`, the closing membership re-sweep, identity re-check, second tombstone pass, POSIX change-time precondition, and the "tree changed during verification" refusals. The superseded `MAX_TOMBSTONE_WORK` and `MAX_SPELLING_WORK` budgets are gone; immutable tree width is bounded by `MAX_TREE_ENTRIES` in the reader.

## Refusal text retained by the immutable binding

The following binding/declaration templates retain their exact released wording (braced names stand for bounded rendered values):

- `declared paths visit more than {MAX_PATH_COMPONENTS_TOTAL} prefixes; the corpus cannot be bound safely`
- `two declared paths would alias on a case- or normalization-insensitive filesystem, so the closed-world set is ambiguous: {first} and {second}`
- `two declared paths would alias at a directory: {first} and {second}`
- `declared paths name more than {MAX_ALIAS_INDEX_NODES} distinct directories; declared paths exceed the alias index budget`
- `{label} is not a portable name (ASCII letters, digits, '.', '_' and '-', not ending in '.', not a Win32 device name): {value}`
- `directory holds two entries a case-insensitive filesystem would merge: {first} and {second}`
- `tree entry {name} aliases the pinned content root component {component} on a case- or normalization-insensitive filesystem`
- `pinned content root is absent from the tree: {root}`
- `pinned content root is not a directory: {root}`
- `content root contains a file whose short-name alias would carry a pinned suffix: {path}`
- `content root contains a non-regular file: {path}`
- `{count} content file(s) in the tree are not bound by the witnessed journal, starting with {path}`
- `{count} content file(s) bound by the journal are missing from the tree, starting with {path}`
- `removed path is still present in the tree: {path}`
- `removed path is still present in the tree under a spelling that aliases it on a case- or normalization-insensitive filesystem: {path} ({survivor})`
- `the witnessed journal does not attest a path the pinned spec requires: {path}`
- `bound file is missing or not a regular file: {path}`
- `bound file is not a regular file: {path}`
- `content file {path} does not match its witnessed digest: tree has {actual}, journal binds {expected}`
- `attested file {path} does not match its witnessed digest: tree has {actual}, journal binds {expected}`
- `the witnessed journal does not declare a gate the pinned spec requires: {gate}`

The tree-addressed API adds only the subject/mode diagnostics its old filesystem subject could not express:

- `verify_corpus_binding requires a TreeSnapshot; select one with TreeSnapshot.select`
- `content root contains a gitlink: {path}`
- `content root contains a symlink where a regular file was recorded: {path}`
- `tree entry name is not valid UTF-8 for folding`

All parser/spec refusal templates and all reader-level `SnapshotError` diagnostics continue unchanged.

## Test census

Baseline focused census was 272 cases: 206 corpus and 66 shared snapshot/name cases. Final focused census is 231 cases: 163 corpus and 68 shared snapshot/name cases. The corpus function census moves from 199 to 145: 65 old names leave, comprising 58 deletions whose subject no longer exists, four tree-shape replacements, and three semantic renames; 11 new names enter. Nineteen test-only filesystem support helpers leave with their subjects.

The 58 deleted tests are:

- Filesystem timing, race, identity, sweep, and platform subjects (28): `test_a_bound_path_unlinked_between_two_syscalls_refuses_by_name`, `test_refuses_a_content_file_inserted_after_first_enumeration`, `test_hashing_opens_non_blocking_and_no_follow`, `test_a_fifo_raced_in_after_the_name_check_refuses_without_blocking`, `test_refuses_a_file_swapped_between_lstat_and_open`, `test_an_appender_cannot_make_hashing_chase_the_live_eof`, `test_a_sparse_extension_after_fstat_is_probed_not_hashed`, `test_a_short_read_before_the_captured_size_refuses_as_shrinkage`, `test_refuses_a_bound_file_rewritten_in_place_after_hashing`, `test_refuses_a_bound_file_replaced_after_hashing_even_with_identical_bytes`, `test_refuses_an_attested_file_removed_after_hashing`, `test_a_content_file_inserted_during_the_tombstone_pass_refuses`, `test_a_bound_file_rewritten_during_the_tombstone_pass_refuses`, `test_a_survivor_planted_after_a_shared_parent_was_cached_refuses`, `test_a_removed_file_written_back_after_the_first_pass_refuses`, `test_a_tombstone_entry_that_vanishes_after_the_listing_is_not_a_survivor`, `test_a_survivor_planted_inside_the_second_tombstone_pass_refuses`, `test_a_content_file_inserted_during_the_second_tombstone_pass_refuses`, `test_a_content_file_created_and_removed_between_the_sweeps_refuses`, `test_an_untouched_tree_still_verifies_through_the_same_wrapper`, `test_a_bound_file_rewritten_during_the_second_tombstone_pass_refuses`, `test_an_attested_file_replaced_during_the_second_tombstone_pass_refuses`, `test_a_bound_file_rewritten_in_place_with_its_mtime_restored_refuses`, `test_refuses_to_verify_at_all_off_posix`, `test_a_directory_changed_after_its_own_re_read_is_caught_going_back`, `test_stamps_an_attested_ancestor_before_its_spelling_is_walked`, `test_the_closing_walk_re_asks_an_attested_path_for_its_spelling`, and `test_the_second_tombstone_pass_screens_the_strip_alias_as_well`.
- Host directory, link, permission, special-file, and reparse subjects (15): `test_refuses_a_symlinked_directory_of_unwitnessed_rules`, `test_refuses_a_symlink_with_a_non_content_name`, `test_refuses_a_directory_it_cannot_enumerate`, `test_an_unreadable_tree_root_is_not_called_a_directory_under_a_content_root`, `test_an_unreadable_ancestor_of_a_pinned_root_is_named_as_an_ancestor`, `test_a_component_that_cannot_be_stat_ed_refuses_by_name`, `test_refuses_a_bound_path_behind_a_symlinked_parent`, `test_refuses_a_fifo_named_like_content`, `test_refuses_an_empty_content_root_behind_a_symlinked_parent`, `test_refuses_a_fifo_at_an_attested_path_without_blocking`, `test_refuses_a_removed_path_the_verifier_cannot_look_for`, `test_refuses_a_removed_path_under_a_symlinked_parent`, `test_a_tombstoned_path_the_listing_hides_but_the_host_resolves_refuses`, `test_a_tombstone_entry_that_cannot_be_stat_after_the_listing_refuses`, and `test_refuses_a_directory_reparse_point_under_a_content_root`.
- Superseded filesystem work-index subjects (14): `test_ancestor_stamping_builds_one_path_per_distinct_prefix`, `test_ancestor_stamping_stops_at_the_first_absent_prefix`, `test_the_tombstone_budget_counts_entries_not_listings`, `test_the_tombstone_index_is_shared_across_removed_paths`, `test_the_tombstone_scan_stops_reading_a_directory_wider_than_its_budget`, `test_many_tombstones_over_one_cached_bucket_exceed_the_budget`, `test_the_content_sweep_stops_reading_a_directory_wider_than_its_budget`, `test_an_ordinary_corpus_sweeps_far_under_the_sweep_budget`, `test_a_wide_static_corpus_verifies_within_the_real_tombstone_budget`, `test_the_two_tombstone_passes_charge_one_budget`, `test_the_tombstone_index_keys_two_case_varied_directories_apart`, `test_a_stamp_the_recorder_never_took_is_not_a_mutation`, `test_the_attested_spelling_walk_is_bounded_by_one_work_budget`, and `test_an_ordinary_corpus_is_far_inside_the_spelling_budget`.
- The positive POSIX control `test_the_same_corpus_verifies_on_posix`, whose platform gate no longer exists.

Four fake-`scandir` cases were replaced by committed raw-tree coverage: `test_refuses_two_directories_a_case_insensitive_checkout_would_merge`, `test_refuses_a_directory_that_would_merge_with_a_content_file`, `test_refuses_two_merging_entries_beside_a_pinned_root_component`, and `test_refuses_a_directory_holding_two_spellings_of_a_bound_component`.

Three old names were semantic migrations, not coverage deletions: `test_the_fixture_spends_twenty_six_units_from_one_shared_prefix_budget` became `test_the_fixture_spends_nineteen_units_from_the_alias_prefix_budget`; `test_the_suffix_predicate_folds_a_decomposed_spelling_onto_its_pin` became `test_the_suffix_predicate_does_not_normalize_unicode`; and `test_two_paths_varied_in_case_and_normalization_at_once_still_alias` became `test_unicode_case_and_normalization_are_not_folded`.

New/replacement coverage includes:

- The required eight-case raw-tree matrix: gitlink, `120000`, non-UTF-8 name, and ASCII-fold-equal siblings, each under `portable` and `posix-bytes`.
- Portable-only 8.3 screening across ordinary blobs, symlinks, and directory entries, with `posix-bytes` controls.
- The #44 property across both content roots and `.axiom`: rewrite, insert, and rename the working tree, then prove the same verdict, commit OID, and tree OID.
- One-listing path charging, direct `Path` refusal, default/closed repertoire values, a positive `posix-bytes` verdict field, and default/opt-out fixture OID behavior.

## Gate results

- Focused final: `tests/test_corpus.py tests/test_snapshot_names.py` — **231 passed** in 56.47s (163 + 68).
- Static: `/opt/homebrew/bin/ruff check` over all five touched Python files — **passed**; `compileall` — **passed**; `git diff --check` — **passed**.
- Required equivalence census at final implementation HEAD `40fa646`: **94 collected, 94 passed** in 223.95s: append gate 21, attest 20, Brier witness 17, ledger 36. The authenticated local Brier and ledger tree overrides were used because sandbox networking is disabled.
- Final non-equivalence isolation: **1,319 passed, 44 failed, 94 deselected, 9 errors** in 257.32s. No Lane D corpus/name failure occurred.
- Required combined `uv run pytest -q`, using the same authenticated overrides and a pre-existing environment because `UV_FROZEN=1` plus the repository's absent `uv.lock` prevents a normal sync: **1,413 passed, 44 failed, 9 errors** in 399.70s. All 94 equivalence cases passed within this run.

The 44 full-suite failures are 43 `tests/test_cli.py` cases and `tests/test_release_chain.py::test_verify_result_exposes_the_anchor_set`; all reach Lane C's old `run_verification` caller, which still passes a `Path` to the intentionally breaking snapshot-only binding API. The nine `tests/test_cli.py` setup errors are its `committed_repo` fixture trying to create a redundant second commit after `build_corpus(commit=True)`. The build brief assigns `src/receipt/verify.py`, `src/receipt/cli.py`, `src/receipt/release_chain.py`, and their integration migrations to Lane C, so this lane records the handoff and does not edit those files.

## Lane progress

### State

- Branch: `feat/0.6-lane-d`, based exactly on `145f3db93d745ddc43aeb47f6b7bd8b30aa331a3`.
- Phase: implementation, focused acceptance, static review, exact equivalence census, and full-suite diagnosis are complete.
- Draft PR title: `Verify the corpus from the tree snapshot; name repertoire (0.6 Lane D)`.
- Network: `CODEX_SANDBOX_NETWORK_DISABLED=1`; `git ls-remote origin HEAD` fails with `Could not resolve host: github.com`. The branch is local-only and the complete draft body is this committed file.
- Draft PR URL: unavailable in this sandbox. Push/creation remain for the integrated, networked handoff.

### Done

- Read the governed plan sections and source contracts in the required order before implementation.
- Committed each coherent implementation, migration, test, and review step separately.
- Completed independent final code review with no remaining in-scope blocker.
- Kept `src/receipt/snapshot.py` unchanged and did not touch any Lane B/C/F-owned production file.
- Ran the requested focused, static, full, and exact 94-case equivalence gates and recorded exact results above.
- Confirmed the remote is unreachable without mutating it; no push or draft PR was attempted after the full gate exposed the expected Lane C integration cluster.

### Next

1. Merge Lane C's `run_verification` snapshot caller and CLI fixture adaptation, then rerun the full combined gate to remove the 44/9 integration cluster.
2. Merge Lane B against these stable `_names.py` exports and scan protected release-root names.
3. Once the integrated gates are green in a networked environment, push `feat/0.6-lane-d` and open the draft PR with the title above and this file as its body.

### Findings

- No `snapshot.py` defect was found.
- `verify_declarations` remains deliberately separate and unchanged; the caller-level pass order is binding then declaration, matching the existing result-stage boundary.
- A normal `uv run` cannot sync here because the inherited `UV_FROZEN=1` requires a missing `uv.lock`, and the default uv cache is outside the writable sandbox. The recorded combined command used `UV_NO_SYNC=1`, the existing project test environment, and a writable temporary cache while still invoking `uv run pytest -q`.
- Network-disabled fixture resolution was closed by authenticated local extraction overrides, not by skipping equivalence cases.
- The offline stop rule applies: all work and the draft body are committed locally, while GitHub DNS resolution is unavailable.
- The requested host report path `/Users/maxghenis/chief-of-staff/state/receipt-052/lanes/build-06-lane-d/out.md` is outside the sandbox's writable roots; its write was rejected by policy. The final report is therefore mirrored to the permitted `/private/tmp/receipt-06-lane-d-out.md` fallback.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
