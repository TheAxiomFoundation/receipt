# receipt 0.6 Lane B progress

## State

- Branch: `feat/0.6-lane-b`
- Recorded starting OID: `e3af1950ff39f1eaa5ff3aad60e89b18e73a943c`
- Phase: append-gate and test inventory before implementation
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

## Next

- Complete the append-gate caller/test and equivalence-harness inventories.
- Implement the selected-tree gate in coherent deletion and feature commits.
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
  either variable. This lane interprets invariance as an invariant, early
  refusal independent of the foreign target, preserving the explicitly bound
  0.5.2 call and message.
- The local GitNexus analysis completed, but its global-registry write is
  sandbox-blocked; a task-local registry was used to query the fresh index.
