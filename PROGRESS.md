# Receipt 0.6 Lane C progress

## State

Implementation is complete on `feat/0.6-lane-c`. All Lane C unit surfaces, the authenticated ledger harness, every equivalence module that does not depend on Lane B, and the independently collectable offline suite are green. The exact integrated equivalence/offline commands cannot collect until Lane B replaces the 0.5.2 append gate's imports and calls to release-chain helpers this lane was required to delete.

The sandbox has no network access. The branch remains local and no PR has been opened. Even with network, the standing push gate would remain closed until Lane B is merged and the complete 101-case equivalence plus exact offline commands pass.

## Done

- Read the governing plan sections and the immutable snapshot contract in the required order; kept `src/receipt/snapshot.py` unchanged.
- Added the defaulted `ChainSpec.name_repertoire` and `VerificationSpec.anchor_set_sha256` policy fields.
- Made `verify_release_chain` a documented directory-as-read verifier with the required validation/preflight/path/manifest/enumeration order, all external file reads through the bounded `lstat` plus one `O_NOFOLLOW` open, and the retained live-directory symlink refusal.
- Added the cached OpenSSL 3.0 preflight at the public verifier boundary. Successful, unsupported-version, and command-failure outcomes each run `openssl version` once per process.
- Made every release-chain OpenSSL `-CAfile` a private mode-0600, `O_EXCL`, byte-for-byte copy.
- Replaced checkout/index/base Git inspection with entered `TreeSnapshot` comparisons and private materializations. `verify_base_release_chain` includes anchors even when `anchor_relative` is outside `release_root_relative`; `GitEntry` is re-exported from `release_chain`.
- Added frozen, loader-owned `LoadedSpec`; `load_spec` reads and hashes source once and rejects a mismatching expectation before compile or exec.
- Implemented commit-addressed `run_verification`, including exact candidate/base identities, expectation ladder, object-store option, one normalized chain spec, pre-crypto and post-crypto anchor equality, mandatory journal rehash, immutable corpus binding, narrowed trust claims, and the expanded `VerifyResult`.
- Required direct anchor expectations to be exact lowercase SHA-256 values and selected them by presence, so an explicitly empty pin cannot be ignored.
- Implemented the complete `receipt verify` flag surface, dependency parser errors, top-level root enforcement, and text/JSON identity, repertoire, base, and object-store reporting.
- Re-pinned the eight ledger base-ref cases to entered snapshots and a candidate materialization. Added seven port-only cases: deliberate dirty-checkout divergence, later worktree/index invariance, foreign Git environment invariance, replace-ref invariance, and loose-object corruption refusal.
- Added `receipts/repin-0.6-tree-object.md` with the fixture change, intended divergence, diagnostic adapters, and 94-to-101 census.
- Merged Lane D's immutable corpus work through `40fa646`; retained the requested one-line `getattr` compatibility note for Lane B to remove.
- Completed three independent read-only peer audits and fixed every in-scope finding.

## Decisions

- `PROGRESS.md` is committed because the brief explicitly requires a committed salvage record.
- No compatibility stubs remain for deleted checkout/index helpers: their subjects no longer exist or their callers are deleted. Keeping them only to make the old append gate import would violate the lane contract.
- The ledger deliberate-divergence test authenticates the pinned append oracle for that one input class; ordinary ledger cases retain the authenticated release-verifier oracle.
- The local Brier extraction at `/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/brier-4b9e7be` was used because sandboxed DNS prevents cloning. Its authenticated pins still gate the harness.

## Findings

- No defect was found in `snapshot.py`; it is unchanged from the lane baseline.
- The two narrow snapshot diagnostic adapters remain necessary: an unresolvable ref is reported by `TreeSnapshot.select` without Git's old stderr, and explicit candidate ancestry names the candidate OID instead of `HEAD`.
- Integration blocker: `src/receipt/append_gate.py` on the lane baseline imports deleted `release_chain._git_environment` first, then other deleted helpers, and calls the old history/base signatures. The exact full equivalence and exact `-k "not equivalence"` commands therefore stop during append-gate collection. Lane B owns those files and the caller migration; this lane did not edit them.
- Final review found and closed two edge cases: a malformed direct anchor pin could be ignored through truthiness, and standalone base anchors were omitted from base materialization.

## Test record

- Lane C direct surfaces: `408 passed in 85.57s` (`test_release_chain.py`, `test_tsa.py`, `test_verify.py`, `test_cli.py`).
- Authenticated ledger command exactly as briefed: `43 passed in 15.75s`, zero skips.
- CLI collection: 158; verify collection: 24.
- Immutable corpus and shared name-policy suite: 231 passed (163 corpus plus 68 shared-name cases).
- Authenticated non-Lane-B equivalence: 80/80 passed, zero skips (ledger 43, attest 20, Brier witness 17).
- Independently collectable offline suite (the three Lane B append modules excluded): `1164 passed, 80 deselected in 168.93s`.
- Baseline equivalence census: 94 = 26 re-pinned + 68 unchanged. Lane C adds seven, so the integrated target is 101; the 21 Lane B append cases are the unavailable part of the current collection.
- `python -m compileall -q src tests` passes; `git diff --check` passes.
- The protected boundaries are clean relative to `145f3db9`: no diff in `src/receipt/snapshot.py`, `src/receipt/append_gate.py`, or any append-gate test.

## Next

1. Merge Lane B's append-gate caller migration.
2. Run the exact complete `tests/test_*_equivalence.py` census and require 101/101 with zero skips; stop and record any forbidden oracle/port divergence.
3. Run the exact offline `-k "not equivalence"` command without exclusions.
4. If both are green, push `feat/0.6-lane-c` and open the requested draft PR from the body preserved below.

## Draft PR body

| Row | PLAN-0.6 residual (verbatim) | What Lane C does |
| --- | --- | --- |
| 3 | A writer during the run — CLOSE for the commit-addressed entry points (`verify_append_gate`, `run_verification`, `verify_corpus_binding`) against any writer outside this process's ownership: objects are content-addressed and rehashed, and the only pathname read is the private materialization, which carries row 15's same-uid assumption; STATE for a same-owner writer to the repository's configuration files, which every git process re-reads — detected by the closing re-audit (3.2), not excluded; STATE for a direct `verify_release_chain` caller on a live directory (section 3.5) | `run_verification` selects entered immutable candidate/base snapshots, rehashes selected objects including the journal, and verifies a private five-prefix materialization with pre/post anchor equality. Checkout and index writers are irrelevant. `verify_release_chain` deliberately remains directory-as-read and states the concurrent-writer residual as a breaking precondition. The snapshot's closing config re-audit retains the same-owner configuration boundary. |
| 9 | Attributes and filters — CLOSE for the commit-addressed entry points (they read raw blob bytes; `filter`, `ident`, `working-tree-encoding` refused on protected paths); STATE for checkouts and for a direct `verify_release_chain` caller (`text`, `eol`, `core.autocrlf`, LFS pointers, whatever the checkout applied) | The commit path reads raw blobs and calls `candidate.refuse_transforming_attributes(materialized.entries.values())`. Protected `filter`, `ident`, and `working-tree-encoding` attributes refuse; `text` and `eol` remain accepted. The stated checkout/direct-caller residual remains. |
| 11 | Symlinked components — CLOSE for the commit-addressed entry points: `120000` is an entry, not a redirection; for a direct `verify_release_chain` caller the retained component walks refuse a link as today (section 3.5) | The commit path treats `120000` as a tree entry and prevents materialization redirection. The public directory verifier walks all three configured paths, binds exact leaf spelling, and reads with `O_NOFOLLOW`. A retained live test pins `release root path traverses a symlink at 'releases/journal': releases/journal/manifests`. |
| 13 | Snapshot identity — CLOSE naming (commit, tree, object format printed; `--expect-commit` and `--expect-tree`); STATE binding (the journal cannot bind the tree that holds the manifest; #35 is the later closure); collision substitution, STATE by default and CLOSE to the reach of git's own detector under `--verify-objects`: the rehash is `hashlib.sha1`, plain SHA-1, and would accept a colliding pair substituted under one OID; `--verify-objects` runs the store-wide `fsck` of 3.3 step 4b (heads given, `--full`, no refs, no index, no commit graph, alternates refused at entry, object and byte counts, output and wall-clock bounds, the configuration boundary with `fsck.*` keys refused, and a preflight that the build's SHA-1 is `SHA1_DC` — measured on this build with `git version --build-options`; `fsck --full` over rulespec-us, 79,890 objects, takes 6.4 seconds, measured), which detects objects produced by the known SHA-1 collision constructions; it is off by default because its subject is the store, not the tree (3.1). What its test can be is stated plainly and put to the peer: a known-collision fixture cannot exist as git objects (the SHAttered pair collide on their raw bytes, and git's `blob <size>\0` header precedes them, so as objects they hash apart; and git's own single-file detection fixture does not fire through an object read either, because the object header shifts the block alignment the detector keys on — measured by the peer in round 3 — which is why the build-options preflight is the only attestation the option has), so the option's test corrupts one byte inside a pack after `git repack`, past the first packed object, and shows the option refuses on `fsck`'s nonzero exit (measured this session), which exercises the integrity path every SHA-1 build shares and not SHA1DC's detection itself — that detection is git's, attested only by the build-options preflight; the plan asks the peer to accept that test and that preflight in place of a collision test, and to accept the default as a stated residual; SHA-256 repositories are refused at `select()` with a stated message until a SHA-256 fixture covering commit, tree and blob parsing and corruption exists, at which point the refusal is lifted in its own gated change | Results, text, and JSON name the full candidate commit, root tree, object format, optional base commit/tree, and repertoire; `--expect-commit` and `--expect-tree` bind them. `--verify-objects` verifies exactly the selected heads and returns an `ObjectStoreReport`. The default collision residual and the journal's inability to bind its containing tree remain exactly as stated. |
| 16 | Trusted anchors — Append gate: STATE, `trusted_code_root` unchanged, at the trust level of the gate's own imported code; a commit-addressed `trusted_anchor_commit` is a later non-breaking addition. `receipt verify`: CLOSE when the pin is the auditor's — `--expect-anchor-set`, or the spec field under a matching `--expect-spec-sha256` — since the candidate's anchors are then compared to it before any OpenSSL call; STATE otherwise (a spec field alone is the producer's proposal), with the custody claim narrowed to "under the anchor set the verified tree carries" and `notEstablished` saying trust in that set is not established (section 3.7) | One normalized `ChainSpec` feeds both the materialized anchor digest and release crypto. `--expect-anchor-set`, or the spec field only under a pinned `LoadedSpec`, compares before OpenSSL. An unpinned spec field is only a producer proposal; custody says `custody under the anchor set {digest} the verified tree carries`, and `notEstablished` adds `that the anchor set is one the auditor trusts`. |
| 17 | git and OpenSSL version semantics — CLOSE by preflight, floors measured and pinned by test: the git floor at the reader's entry, the OpenSSL floor at the top of `verify_release_chain` itself (Lane C carries #47's preflight there, so a direct caller gets it too) | Lane C calls cached `tsa._require_supported_openssl()` after argument validation and before path access. Acceptance, unsupported version, and missing/failing command are cached once per process with the existing OpenSSL 3.0 refusal. The Git floor remains at snapshot entry. |
| 18 | OpenSSL pathname reads — CLOSE for the commit-addressed entry points: manifests, signatures and receipts are read from the materialization, `-CAfile` from the private copy per #47; STATE for a direct `verify_release_chain` caller on a live directory, where OpenSSL still reads receipt paths in that directory (section 3.5) | Commit verification invokes the directory verifier only over a private materialization. Every `-CAfile` is a private mode-0600, `O_EXCL`, byte-for-byte copy even when pinning/observation are off. The direct-live-directory residual remains; #40's receipt snapshots are retained. |
| 19 | Producer-controlled spec code — STATE unless the spec is pinned: `load_spec` executes the spec module (`verify.py` lines 216 to 222 on main) before any check, so without `--expect-spec-sha256` arbitrary code from the verified repository runs inside the verifier and can defeat every other row; under a pin a mismatching spec never runs; the verdict carries `LoadedSpec.pinned`, and an unpinned run's `notEstablished` says that the spec's code was trusted | `load_spec` reads once, hashes once, and validates/compares an expected lowercase digest before compile/exec. Frozen loader-owned `LoadedSpec` carries verification, path, SHA-256, and pinned status. An unpinned verdict adds exact text `that the spec's code was trusted` to `notEstablished`. |
| 20 | Release identity — CLOSE by tagging the reviewed head OID itself under a merge-commit merge (criterion (g)); STATE that the exact-target checks are recorded evidence in the release notes, reviewed by the release peer rather than re-run by it | Tagging is outside Lane C. This lane emits and pins commit/tree identities so the exact-target evidence can be recorded; exact-head tag/merge closure remains the release peer's criterion-(g) action. |

### Deletions and why

Deleted because their working-tree/descriptor subject no longer exists: `assert_secure_descent_supported`, `hold_release_root`, `assert_release_root_unchanged`, `confined_state_descriptor`, `read_state_descriptor`, `_working_release_files`, `assert_file_modes_authoritative`, `WORKING_TREE_SCAN_OPTIONS`, `assert_index_carries_no_protected_alias`, `assert_index_hides_no_working_tree_change`, `assert_state_path_tracked`, `assert_index_agrees_with_tree`, `assert_release_file_still_indexed`, `assert_index_content_bound`, `assert_release_root_index_regular`, and `git_tree_entries`.

Deleted because their callers are deleted: `_blob_id`, `resolve_base_commit`, `materialize_base_tree`, `git_file_entry`, `git_blob_bytes`, `SEARCH_ONLY_DIRECTORY_FLAG`, `DIRECTORY_OPEN_FLAGS`, `DESCENT_REQUIRES_DIRECTORY_READ`, `unreadable_directory_error`, `_is_symlink_at`, `ConfinedState`, `PATHSPEC_ENVIRONMENT`, release-chain `_git_environment`/`_git_run`, `_git_bool`, `_observed_git_category`, `CE_INTENT_TO_ADD`, `CE_VALID`, `CE_SKIP_WORKTREE`, `INDEX_DEBUG_LINES`, `_IndexRecord`, `_split_index_debug`, `_parse_index_records`, `_index_entries`, `_all_index_entries`, `_fold_component`, `_folded_parts`, `_surface_alias_paths`, `_exact_relative`, and `_assert_no_symlinked_release_component`.

`GitEntry` moved to `snapshot.py` in Lane A and is re-exported from `release_chain`; it was not removed.

### Retained refusal messages

Release-history and live-directory forms retained exactly (braces identify the runtime value):

- `existing release file was deleted relative to {base_commit}: {path}`
- `existing release file mode changed relative to {base_commit}: {path} ({old_mode} -> {new_mode})`
- `existing release file bytes changed relative to {base_commit}: {path}`
- `release path is a symlink: {path}`
- `base release entry has non-regular git mode {mode}: {path}`
- `releases must be a real directory, not a symlink`
- `release root path traverses a symlink at 'releases/journal': releases/journal/manifests`
- `path component releases/manifests is not spelled by its directory: releases/manifests`
- `state path traverses a symlink at {component!r}: {relative}`
- `required state file is missing or non-regular: {path}`
- `state files cannot be read with secure descent on this platform (os.open lacks dir_fd support); receipt requires a POSIX platform`
- `{GIT_*} is set in the environment and would redirect git reads; unset it`

The two narrow diagnostic adapters preserve the baseline's exact forms `cannot resolve base ref 'no-such-ref' to a commit: fatal: Needed a single revision` and `base commit {oid} is not an ancestor of HEAD` while leaving `snapshot.py` unchanged.

The authenticated 26-case `--full` battery still compares complete normalized messages byte-for-byte (only the documented OpenSSL error-queue token is masked). Its retained branches/messages are:

- `producer keys are not closed-world`
- `state keys are not closed-world`
- `producer Ed25519 signature verification failed for {stem}.producer.sig`
- `producer signature for {stem}.producer.sig must be exactly 64 raw bytes; found=63`
- `producer public-key SPKI is not code-pinned: {digest}`
- `cannot decode producer Ed25519 public key: {detail}`
- `producer public key is not Ed25519: {type}`
- `manifest {stem}.json is missing its producer signature {stem}.producer.sig`
- `orphan producer signatures for manifest stems: ['9999-deadbeefdeadbeef']`
- `cannot inspect RFC 3161 receipt {path} (exit {status}): {detail}`
- `RFC 3161 verification failed for {stem}.digicert.tsr (exit {status}): {detail}`
- `manifest {stem}.json must have exactly freetsa and digicert receipts; found=['digicert']`
- `orphan release receipts for manifest stems: ['9999-deadbeefdeadbeef']`
- `unknown file in closed release manifest directory: junk.txt`
- `unknown file in closed release manifest directory: {stem}.real` or `release manifest directory contains a non-regular entry` (filesystem enumeration order; both legs must still match in full)
- `release manifest directory contains a non-regular entry`
- `duplicate release index 1: {first}, {second}`
- `release indices are not contiguous from 0: expected 0002, found 0003`
- `manifest filename hash does not match exact file bytes: 0001-0000000000000000.json`
- `manifest releaseIndex 2 does not match filename index 1`
- `manifest releaseIndex 1 does not match filename index 2`
- `release 1 previousManifestSha256 does not match the previous manifest file bytes`
- `release 0 state.jsonlSha256 does not match the exact historical JSONL prefix`
- `HEAD release lineCount 147 does not match working-tree line count 148`
- `release 0 immutablePrefixSha256 does not match ledger/immutable_prefix.json`
- `production TSA anchor bytes are not code-pinned for freetsa: {digest}`

New ladder messages (not described as retained) are `spec {digest} is not the expected spec {expected}`, `base_ref requires expect_commit`, `an anchor pin requires a pinned spec`, `spec declares two name repertoires`, `expected anchor-set SHA-256 must be a lowercase 64-character hex digest`, `anchor pins disagree: command expects {direct}, spec expects {declared}`, `anchor set {actual} is not the pinned anchor set {expected}`, `verified anchor set {verified} is not the materialized anchor set {materialized}`, `commit {actual} is not the expected commit {expected}`, and `tree {actual} is not the expected tree {expected}`. CLI dependency errors are `--base-ref requires --expect-commit` and `--expect-anchor-set requires --expect-spec-sha256`.

### API and CLI

- `ChainSpec.name_repertoire: Literal["portable", "posix-bytes"] = "portable"`; `VerificationSpec.anchor_set_sha256: str | None = None`.
- `load_spec(path, *, expect_sha256=None) -> LoadedSpec`; loader-owned frozen fields: `verification`, `path`, `sha256`, `pinned`.
- `run_verification(root, spec: LoadedSpec, *, base_ref=None, commit="HEAD", expect_commit=None, expect_tree=None, expect_anchor_set=None, verify_objects=False) -> VerifyResult`; the old split `spec_path`/`spec_sha256` inputs are removed.
- `VerifyResult` adds `commit`, `tree`, `object_format`, `base_commit`, `base_tree`, `name_repertoire`, and `object_store`.
- `verify_release_history_immutable(spec, *, candidate, base)` compares two entered snapshots; `verify_base_release_chain(spec, *, base)` materializes an entered base.
- CLI adds `--expect-spec-sha256`, `--commit`, `--expect-commit`, `--expect-tree`, `--expect-anchor-set`, and `--verify-objects`; root resolves to the repository top level. Text/JSON now report candidate/base identity, repertoire, and object-store state. Binding says `binding of the witnessed journal to tree {tree[:12]}`.

### Harness census and suites

- Before: 94 equivalence cases. Re-pinned: 26 (8 ledger and 18 append). Unchanged: 68.
- Added here: seven port-only tree-object cases. Integrated target: 101.
- Current authenticated ledger: 43/43, zero skips. Current non-Lane-B equivalence: 80/80, zero skips.
- Lane C direct surfaces: 408 passed. Corpus/shared-name suite: 231 passed.
- The independently collectable offline suite passes 1,164 cases with 80 equivalence cases deselected; it excludes only the three Lane B append modules that cannot import yet.
- The 21 append cases cannot collect until Lane B migrates its callers; consequently neither the complete 101-case command nor the exact offline command is reported green here.
- Source/test compilation and whitespace checks pass; no protected Lane A/B file changed.

Network is sandbox-disabled, so the branch is committed locally and this complete draft body is the handoff. Push and draft PR creation remain gated on the Lane B merge and the two complete green commands.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
