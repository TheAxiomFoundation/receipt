# Receipt 0.6 Lane C progress

## State

In progress on `feat/0.6-lane-c`, based at `145f3db93d745ddc43aeb47f6b7bd8b30aa331a3`.

## Done

- Read PLAN-0.6 sections 3.1, 3.3, 3.5, 3.7, 3.8 step two, 3.9, 4, and section 5's final paragraph in the required order.
- Read the `receipt.snapshot` module contract and the complete `TreeSnapshot` and `Materialization` implementations without changing them.
- Confirmed the branch is clean and starts at the requested Lane E merge.
- Added and validated the defaulted `ChainSpec.name_repertoire` and `VerificationSpec.anchor_set_sha256` fields; focused tests pass (2 passed).
- Wired the cached OpenSSL 3.0 preflight into `verify_release_chain` and made every RFC 3161 `-CAfile` a 0600 private byte-for-byte copy, including unpinned/unobserved calls; focused tests pass (2 passed).
- Reworked `verify_release_chain` as a directory-as-read verifier: argument validation and OpenSSL preflight precede the anchor/path/manifest-shape/enumeration ladder, every input routes through the bounded lstat-plus-`O_NOFOLLOW` reader, and the docstring states the breaking concurrent-writer precondition. `tests/test_release_chain.py` is green (61 passed).
- Replaced release-history inspection with a comparison of two entered `TreeSnapshot`s, re-exported `snapshot.GitEntry`, and made base-chain verification materialize its entered base. The three existing immutability messages remain exact and candidate links retain the live-directory refusal. `tests/test_release_chain.py` is green (67 passed).
- Deleted the descriptor-holding and cross-run root/state race helpers. Their working-tree race subject no longer exists for commit-addressed callers; their private support functions' callers are deleted. The directory verifier retains its one bounded `O_NOFOLLOW` read.
- Added frozen, loader-constructed `LoadedSpec`; `load_spec` now hashes its single source read and enforces an optional expected digest before `compile` or `exec`. Existing callers consume the record explicitly, and focused tests pass (4 passed).
- Deleted the complete obsolete Git/index/history helper closure (`WORKING_TREE_SCAN_OPTIONS`, index guards, base-ref resolution, `git_tree_entries`, file/blob reads, and their private support). Its checkout/index subject no longer exists or its caller is deleted; `TreeSnapshot` now owns the object reads. The retained live-directory release tests are green (63 passed).
- Re-pinned the 8 ledger base-ref cases to entered candidate/base snapshots and a private candidate materialization; added 7 port-only tree-object cases for the intended dirty-checkout divergence, working-tree/index/environment/replace invariance, and loose-object corruption. The authenticated ledger harness collects and passes 43 cases with zero skips.
- Added `receipts/repin-0.6-tree-object.md` with the Lane E fixture change, genuine ledger divergence, 26 re-pinned / 68 unchanged / 94 prior / 101 integrated census, and the two narrow snapshot diagnostic adapters.
- Merged Lane D through `4e6070c`: the corpus binder now consumes an entered immutable snapshot, shared name-policy screens and both repertoire fields are present, generated corpus fixtures commit by default, and subjectless filesystem tests are removed. Lane D's remaining retained-test conversions will be merged when committed.
- Corrected the OpenSSL preflight cache so an unsupported-version refusal, as well as an acceptance, executes `openssl version` only once per process; the focused 11-case version-gate slice passes.
- Extended that cache to retain the missing/failing-command refusal as well; repeated unsupported and missing-binary preflights each execute the version command once (2 focused cases pass).
- Adapted the release-tree test commit helper to Lane D's now-committed corpus fixture; the six history/base materialization tests pass without manufacturing an empty commit.
- Added an exact-filename fast path so `run_verification` can hand the same normalized `ChainSpec` object to materialization and the directory verifier without a second normalization; stateful direct-caller filenames still normalize once (4 focused cases pass).
- Implemented commit-addressed `run_verification` over entered candidate/base snapshots, exact candidate expectations and ancestry, optional object-store verification, private five-prefix materialization, anchor-set pinning before OpenSSL, the mandatory journal rehash, snapshot corpus binding, and declaration verification. `VerifyResult` and JSON carry the selected/base identities, object format, repertoire, object-store report, dynamic custody/binding claims, checkout limitation, and spec/anchor trust limitations; all 17 focused verifier tests pass.
- Removed the module-level `LoadedSpec` construction helper and validate expected spec digests as exact lowercase SHA-256 strings before comparison, closing callable/equality-object forge paths found in peer review.
- Corrected the port-only deliberate divergence to authenticate and invoke the pinned append oracle from the ledger harness itself: its exact `change rewrites existing line 129 ...` refusal now contrasts with acceptance of the unchanged selected commit (1 focused case passes), without editing Lane B's append harness or either oracle.
- Closed runner peer-review gaps: redirecting Git environment keeps priority over a simultaneous pin conflict; the post-crypto anchor equality, commit-before-tree expectation ladder, object-store failure/report state, and repertoire mismatch now have focused coverage; trust/declaration docstrings no longer call an unpinned producer policy auditor-pinned. `tests/test_verify.py` passes all 20 cases.
- Implemented the complete CLI flag surface, pre-load parser dependency rules, top-level root/default walk, LoadedSpec forwarding, selected/base/name/object text lines, new JSON identity/store fields, and trust-sensitive PASS prose. The re-pinned tree-addressed CLI battery now has 158 passing cases, including real object-store reporting, requested-failure wording, exact expectation refusals, root shape, output fields, checkout/index invariance, and a real coordinated anchors/signed-content/spec substitution ladder.
- Merged Lane D through `40fa646`: all retained corpus tests now target committed trees, checkout independence and the complete name/mode matrix are covered, portable short-name screening applies to every entry kind, and fixture commit-return semantics are final.
- Final merged corpus suite: 227 passed. Final authenticated ledger harness: 43 passed in 19.56 seconds with zero skips.

## Decisions

- `PROGRESS.md` is committed because the standing order at the start of the brief explicitly requires a committed salvage record.
- Preserve `src/receipt/snapshot.py` exactly; any reader defect will be recorded here and worked around.
- Keep Lane B files out of this lane. Although Lane D's `CorpusSpec.name_repertoire` is now merged, retain the brief's one-line `getattr(spec.corpus, "name_repertoire", "portable")` compatibility read; Lane B removes it after integration.
- Use `Co-Authored-By: OpenAI Codex <noreply@openai.com>` on every lane commit.

## Lane D integration record

- Branch: `feat/0.6-lane-d` at baseline `145f3db93d745ddc43aeb47f6b7bd8b30aa331a3`.
- Phase: Lane D implementation and focused acceptance coverage are complete; integration/offline gates are next.
- Scope: immutable-tree corpus verification, shared name-policy additions, corpus fixture commit helpers, and focused tests.
- Network is sandbox-disabled; local work, tests, commits, and a complete draft PR body remain possible. Push/PR creation will be attempted only after all gates pass.

### Lane D work completed

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
- Deleted exactly 58 tests whose host-filesystem, platform, race, re-sweep, ctime, identity, or superseded work-index subject no longer exists, plus four fake-directory-listing collision tests that the committed-tree shape matrix replaces. Nineteen test-only filesystem scaffolds went with them.
- Retained focused battery after that deletion: 198 passing cases and 18 expected migration failures. Those failures are confined to stale Unicode-normalization assertions, host-conditional spelling assertions, fake `os.scandir` entries, and removed private instrumentation; no parser, digest, membership, or declaration regression appears.
- Converted all 18 retained migration failures to immutable-tree semantics. Raw index fixtures now express names the checkout cannot, exact attested and membership spelling no longer branches on host case behavior, and tests explicitly freeze ASCII-only folding rather than the deleted Unicode normalization/casefold model.
- Retained corpus plus shared-name battery: 216 passed.
- Added the required committed-tree matrix: gitlink, `120000`, non-UTF-8 component, and fold-equal siblings, each under `portable` and `posix-bytes`.
- Added #44's working-tree-independence property across two content roots and `.axiom`: rewrite, insert, and rename mutations leave the verified verdict, commit OID, and tree OID unchanged.
- Added a path-work regression proving the whole-tree flat listing charges each path once, with only the required exact attested lookup adding its own charge.
- Focused corpus plus shared-name battery with replacements: 227 passed.
- Final review found and closed one entry-kind gap: the portable 8.3 suffix screen now runs before mode classification, so a suffix-bearing alias cannot hide behind a symlink or directory; four portable/`posix-bytes` mode cases cover the boundary.
- `build_corpus` now follows the plan literally by returning its commit OID directly (`str | None` with `commit=False`), matching `append_release`; a default build-plus-append smoke returned two distinct OIDs.
- Added end-to-end fixture coverage: both default returns equal `HEAD`, the two release OIDs differ, `append_release(commit=False)` leaves `HEAD` unchanged and the tree dirty, and `build_corpus(commit=False)` creates no repository.

## Findings

- `tsa._require_supported_openssl()` was already present and cached on the starting head; Lane C only needs to wire it into `verify_release_chain` and map its refusal into `ReleaseChainError`.
- Integration dependency: the 0.5.2 `append_gate.py` imports most release-chain guards section 3.5 requires Lane C to delete. The standalone Lane C tree cannot both remove them and collect the append-gate suite until Lane B replaces those callers; keep this visible rather than silently retaining dead compatibility code.
- Final full-equivalence attempt stops at collection in `tests/test_append_gate_equivalence.py`: the unmerged 0.5.2 `append_gate.py` imports deleted `release_chain._git_environment`. Lane B owns that required caller replacement; no Lane B branch is present locally yet. This is the predicted integration dependency, not a verifier/oracle divergence.
- Snapshot diagnostic surface: `TreeSnapshot.select` reports an unresolvable base as `cannot resolve commit ...` without the old Git stderr, and `assert_ancestor` names an explicit candidate OID rather than `HEAD`. The ledger differential wrapper uses narrow message adapters so the pre-existing moved-case outputs stay pinned; `snapshot.py` remains unchanged.
- The exact append-only deliberate-divergence refusal belongs to the append oracle rather than the ledger release oracle. The ledger harness now authenticates that pinned script separately for this single port-only input-class test; its ordinary differential baseline remains the release verifier.
- Peer review of the release-chain and loader surface found three implementation gaps (unsupported OpenSSL exceptions were not cached, `LoadedSpec` had a callable forge helper/non-exact expectation, and an exact normalized spec was replaced again); each is now fixed with focused regression coverage. The rest of the release-chain deletion, refusal-order, regular-read, CA-copy, and tree-history contract reviewed clean.

### Lane D recorded integration actions

1. Run formatting/static checks, the full offline suite, and the 94-case equivalence gate.
2. Resolve in-scope failures; record Lane C/B integration points separately.
3. Prepare the required PR body and final report with exact totals and OIDs.

## Next

- Merge Lane D's final three commits, then run the ledger, full equivalence, and offline suites.
- Re-run the ledger harness after the final verifier/CLI integration, then run the complete 101-case equivalence census.

## Lane D handoff findings

- No defect found in `snapshot.py`; it remains out of scope and unchanged.
- `src/receipt/verify.py` still passes a `Path` to the intentionally breaking API. Lane C owns and is concurrently changing that caller; this branch's full offline suite will retain that expected integration failure until Lane C is merged or its change is available.
- `tests/test_cli.py` has one `committed_repo` fixture that initializes and commits a second time; default fixture commits make that second commit empty. The CLI file belongs to Lane C, so this lane records the integration point and does not edit it.
- Section 3.6's final `verify_declarations` step remains the separate pass that `run_verification` already performs after binding. Calling it inside `verify_corpus_binding` would collapse the public binding/declaration pass boundary and make Lane C's unchanged call duplicate the check.
- The stable pre-review offline run reached 1,315 passes with 94 equivalence cases deselected; its 44 failures are all the expected Lane C `verify.py` Path caller, and its 9 setup errors are the Lane C-owned CLI fixture's now-redundant second commit. A post-review focused/full rerun remains required for final totals.
- Baseline census: 199 corpus test functions / 206 collected cases. Exactly 57 current functions have vanished filesystem/race/index subjects (43 host/race, 14 obsolete budget/index); replacement tree-shape/property cases will restore the required coverage, not those subjects.

## Next

- Run the non-append equivalence modules and offline suite while waiting for Lane B's caller migration; merge it if it becomes available, then rerun the complete census.
- Resolve only in-scope failures, then prepare the draft PR body and final report.
