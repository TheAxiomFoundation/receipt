# Receipt 0.6 lane A progress

## State

The immutable reader and name-policy modules are implemented and passing the
first isolated core battery plus the pre-existing offline suite. Feature,
budget, and hostile-environment tests remain in progress.

The brief contains incompatible instructions about this file: the standing
order requires it to be committed from the start, while a later ground rule
forbids committing it. The standing order is being followed because it is
explicitly labeled as such; the final report will list this procedural
deviation.

The frozen floor requirements also conflict: Git 2.36.0 introduced
`cat-file --batch-command`, but the mandatory `fsck --no-references` option
arrived in Git 2.50.0. The reader floor remains 2.36.0 as explicitly directed;
the optional object-store pass fails closed below 2.50.0. This is documented
in the module and will be listed in the final report.

## Done

- Verified `PLAN-0.6.md` against the adjacent SHA-256 record.
- Verified the worktree branch, base commit, and clean starting state.
- Read the frozen reader contract, refusal order, harness fixture procedure,
  residuals, sequencing, and lane prohibitions.
- Implemented the two name repertoires, raw-name validation, portable host
  screen, and fold-collision screen in `receipt/_names.py`.
- Implemented selection, batch framing, rehash/type-role binding, canonical
  commit and raw-tree parsing, hierarchical listings, ancestry, bounded Git
  commands, configuration audits, store verification, attributes, streaming
  digests, and materialization in `receipt/snapshot.py`.
- Passed 53 isolated core reader tests and 951 existing offline tests (94
  equivalence tests deselected) on the worktree's default interpreter.

## Next

- Add attributes, materialization, store-verification, hostile-environment,
  per-budget, and generated acceptance-fixture tests.
- Run the permitted focused, offline, and equivalence selections on the
  available interpreters, then push and open a draft PR.
