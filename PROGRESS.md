# receipt 0.6 Lane B progress

## State

- Branch: `feat/0.6-lane-b`
- Recorded starting OID: `e3af1950ff39f1eaa5ff3aad60e89b18e73a943c`
- Phase: latest target integrated; final verification and handoff
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
  the exact #46 missing-repository wording. The resulting unit suite is 87/87
  green under the cached Python 3.13 environment.
- Added unit coverage for the exact full-candidate-OID refusal, every
  `AppendGateVerdict` identity/repertoire field, and a push verdict remaining
  bound to the explicitly supplied commit after `HEAD` advances.
- Threaded each committed candidate OID through `run_port` and both legs of
  every moved append differential case. The existing harness is 21/21 green
  against the pinned production tree: all 18 verifier cases retain names,
  markers, messages, and two legs; the three oracle-authentication cases
  remain unmoved.
- Added all seven port-only snapshot cases: deliberate baseline/port
  divergence after an unstaged row rewrite; later working-tree and index
  invariance; late `GIT_DIR` and `GIT_INDEX_FILE` invariance; effective
  `refs/replace` immunity; and an exact rehash refusal after a logical byte
  flip in a loose candidate-tree object. The append differential is now 28/28
  green against the pinned tree with zero skips.
- Ran all four authenticated harnesses in one offline process with explicit
  Ledger and Brier extraction paths: exactly 108 cases collected and 108/108
  passed with zero skips in 235.98 seconds. A prior diagnostic run used an
  uninstalled cached interpreter, causing only the Brier oracle subprocess to
  report that `receipt` was unavailable; the project venv supplies the package
  to that subprocess while pytest still prepends this worktree's `src`.
- Re-ran the #38-body port-only production differential using the authenticated
  `9dafe81` tree and a new committed scratch repository per input: both exact
  acceptance texts and all 15 retained mutation markers matched, 17/17 with
  zero skips. Recorded the fixture shape, deliberate divergence, 26 re-pinned
  + 68 unchanged + 14 additions = 108 census, commands, and outcomes in
  `receipts/repin-0.6-tree-object.md`.
- Ran the complete offline repository suite in the project venv with both
  authenticated extraction paths: 1,359/1,359 passed with zero skips in
  487.99 seconds.
- Ran `ruff check .`, bytecode compilation over `src` and `tests`, and
  `git diff --check`; all passed. The three Lane B Python files are also clean
  under `ruff format --check`.
- Reconciled the base-ref diagnostics at the reader boundary: invalid base
  selection has a narrow adapter to the append gate's old `rev-parse`
  diagnostic without running Git again, while a failed ancestry walk names
  the explicitly selected candidate OID as PLAN 3.3 requires. Added
  exact-message unit coverage for both paths and removed the invalid-ref
  test's obsolete checkout-guard setup and name.
- Tightened the initial base-chain integration so it always used the
  caller-owned trusted anchor directory and respected custom-anchor pin
  policy. Added a post-genesis chain test where committed anchor bytes equal
  the custom trusted directory but production pins differ.
- Kept `release path is a symlink` / `release path is not regular` for
  non-regular release leaves. A release root or interior manifest ancestor is
  instead a mandated section 3.3 reader-shape refusal, while the exact manifest
  leaf still reaches `_enumerate_manifest_files`'s wording. Added regressions
  for each boundary on the push and base paths.
- Kept the base-ref path's pre-genesis chain predicate distinct from the new
  push predicate: only a direct `*.json` child marks the candidate chain as
  initialized. A committed blob at the manifest path therefore retains the
  legacy `legacy pre-genesis proposal must not change releases/` refusal;
  added an exact-message regression.
- Kept the push manifest probe's specified `bool(TreeListing)` semantics: only
  non-tree manifest entries initialize a chain, while a canonical empty
  subtree remains pre-genesis. A non-tree exact manifest leaf remains truthy
  and reaches its established directory-verifier refusal.
- Re-ran the complete append unit module after the audit fixes: 91/91 passed.
- Completed the reader-preflight audit. State entry shapes, every protected
  ancestor, whole-tree folded aliases, and transforming attributes now run
  before surface classification without fetching state or release payloads.
  Base release modes remain in release history; push release-leaf modes remain
  after row and manifest decisions. Release history still precedes candidate
  materialization.
- Added regressions for gate-only transforming attributes, state paths omitted
  from declared surfaces, a folded gate alias, a blob at a gate-path ancestor,
  state-shape ordering, and an invalid UTF-8 tree name translated into the
  append gate's exception vocabulary. The focused append module is now 99/99
  green.
- Corrected the committed re-pin receipt to identify the current Lane B
  worktree and the project virtual-environment interpreter for the standalone
  append harness command.
- Completed the portable release-root name screen using Lane D's shared 8.3
  suffix predicate. Under `portable`, non-content names whose generated short
  aliases would end `.sig` or `.tsr` refuse before entry modes for blobs,
  links, and trees; `posix-bytes` retains the exact-byte policy. Restored a
  direct exact-message test for release-history deletion. The append unit
  module is now 109/109 green.
- Merged target tip `4a4f86062f6b5e3773a67fb749f35266b61e2eb2`,
  which includes Lane C's completed trusted-anchor parameters and base
  transforming-attribute screen. Replaced Lane B's temporary local base
  materialization with the required `verify_base_release_chain` call.

## Next

- Re-run all verification on the integrated head and record fresh totals.
- Finish the obsolete-narrative and exact-contract audit for the PR handoff.
- Prepare the complete no-network PR handoff; pushing and opening the draft PR
  will require a networked environment unless connectivity becomes available.

## Findings

- The starting Lane C helper `verify_base_release_chain(spec, *, base)` had no
  trusted-anchor or pin-policy parameters, so Lane B initially reproduced and
  worked around candidate/base anchor substitution locally. The target branch
  later fixed that out-of-scope helper at `31f51cd`/`1872709`; after integrating
  it, Lane B removed its workaround and calls the helper with the caller-owned
  `anchor_dir` and selected pin policy. The regression remains in place to
  bind the cross-lane contract.
- The brief simultaneously requires keeping
  `assert_no_redirecting_git_environment` at public entry and invariance under
  foreign `GIT_DIR`/`GIT_INDEX_FILE`. The retained helper necessarily refuses
  variables present at entry. The new invariance tests inject them only
  after that guard runs, proving the snapshot's Git children remain bound to
  the selected repository without weakening the retained entry refusal.
- `TreeSnapshot.select` intentionally normalizes every revision-resolution
  failure to `cannot resolve commit`. Lane B's narrow adapter restores the
  retained nonexistent-base diagnostic, but cannot reconstruct Git's
  additional first line when an existing blob OID is supplied as `base_ref`
  without an out-of-scope second Git resolution. The common harness text is
  exact; this rarer diagnostic remains a Lane C API limitation.
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
- Repository-wide `ruff format --check .` reports 29 pre-existing files from
  the Lane C/D base that it would reformat. Lane B did not mechanically rewrite
  those unrelated modules; `ruff check .` is clean and every Lane B Python file
  passes the formatter check individually.
