# receipt 0.6 Lane B progress

## State

- Branch: `feat/0.6-lane-b`
- Recorded starting OID: `e3af1950ff39f1eaa5ff3aad60e89b18e73a943c`
- Phase: snapshot unit suite green; adding verdict and harness coverage
- Network status: sandbox-disabled; GitHub API access fails immediately

## Done

- Recorded the Lane C tip from which this worktree was created.
- Confirmed the worktree began clean.
- Read PLAN-0.6 sections 3.1, 3.3, 3.4, 3.5, 3.8 step two, 3.9,
  section 4, and section 5's closing prohibition list in the required order.
- Recovered the complete Lane D/#55 draft body from
  `0c2ef064330e1499b305291e50f4517ea6987cb7:PROGRESS.md` and the Lane C/#56
  draft body from `53d0035122328ca3a22d88c93752d365648390fd:PROGRESS.md`; the GitHub API
  is unavailable, so server-side edits cannot be checked.
- Read the selected-tree APIs in `snapshot.py`, the entered-snapshot release
  helpers and directory verifier in `release_chain.py`, and the Lane C
  composition in `verify.py`.
- Refreshed the local GitNexus index at this lane's starting commit. Its
  upstream impact scan finds five direct append-gate callers and 148 affected
  test symbols, confirming the rewrite's high test-surface risk.
- Rebuilt `append_gate.py` around nested entered `TreeSnapshot` objects. The
  public string API now delegates to `verify_append_gate_verdict`, state and
  base reads use authenticated blobs, surface classification uses tree diffs,
  release verification uses private materializations, and the old checkout,
  index, root-descriptor, re-read, and writer-race machinery is deleted.
- Kept the retained semantic-check order and exact success rendering, added
  the full-candidate-OID contract for base comparisons, and preserved the
  push-path release-mode refusal wording before materialization.
- Verified the new module with `py_compile`, Ruff, and `git diff --check`.
- Removed Lane C's temporary `CorpusSpec.name_repertoire` compatibility read;
  the merged Lane D field is now read directly.
- Rebased the local append fixture on committed candidate trees: ordinary
  helpers commit each proposal and pass its full OID, while symbolic-base
  tests retain a separate moving base name.
- Deleted the legacy diagnostic module because every test targeted
  `_set_root`, `_resolve_base_commit`, or `_manifest_at_ref`; those callers
  and their working-tree subject no longer exist.
- Removed append tests by obsolete subject class: ignored/untracked and
  unreadable checkout enumeration; checkout authority and cache settings;
  index reconciliation, aliases, pathspecs, conflicts, intent-to-add, and
  hidden entries; FIFO/state re-read/root/release-root concurrent writers;
  descriptor lifetime; and live-filesystem spelling/folding/confinement.
- Retained and ported the semantic refusal battery over committed objects,
  including surface separation, append/prefix/row/binding rules, tree modes,
  release history, manifest shapes, specs, environment entry refusals, and
  the exact #46 missing-repository wording. The resulting unit suite is 84/84
  green under the cached Python 3.13 environment.

## Next

- Add the full-OID, verdict-field, pushed-commit, and immutable-snapshot
  invariance cases.
- Thread the committed candidate OID through the append equivalence harness.
- Run the focused, equivalence, and full offline suites; perform the pinned production-tree differential.
- Prepare the complete no-network PR handoff; pushing and opening the draft PR
  will require a networked environment unless connectivity becomes available.

## Findings

- Lane C's `verify_base_release_chain(spec, *, base)` materializes and trusts
  the base tree's anchor prefix. That conflicts with the append-gate contract
  that anchors always come from `trusted_code_root`. A helper-level
  reproduction using the pinned tree with `releases/anchors/freetsa-root.pem`
  poisoned in the committed base returns
  `ReleaseChainError: production TSA anchor bytes are not code-pinned for freetsa: a8c8894a3e09c5504651b9d2092e477fb041e53c96b84d391f3bf8267d37853f`;
  the retained append harness case
  `test_candidate_base_anchor_bytes_do_not_replace_trusted_anchors` requires
  both legs to accept with `thesis-facts append check OK: 147 rows, immutable
  prefix 128, +2 appended vs base, release 2`. The append gate will work
  around this out-of-scope helper defect by materializing the entered base
  itself and supplying the trusted anchor directory; `release_chain.py` will
  not be changed.
- The brief simultaneously requires keeping
  `assert_no_redirecting_git_environment` at public entry and invariance under
  foreign `GIT_DIR`/`GIT_INDEX_FILE`. The retained helper necessarily refuses
  variables present at entry. The new invariance tests will inject them only
  after that guard runs, proving the snapshot's Git children remain bound to
  the selected repository without weakening the retained entry refusal.
- The required candidate materialization prefix set includes
  `release_root_relative`; Chronicle's anchors are descendants of that root,
  so `TreeSnapshot.materialize` deduplicates the nested prefixes and
  necessarily writes and name-screens those anchor blobs. This contradicts
  the plan's claim that candidate anchors are not written or screened. They
  are still never used cryptographically because every chain call receives
  the caller-owned `anchor_dir`; excluding a descendant would require an
  out-of-scope snapshot API change.
- The local GitNexus analysis completed, but its global-registry write is
  sandbox-blocked; a task-local registry was used to query the fresh index.
