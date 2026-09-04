# Receipt 0.6 lane A progress

## State

The frozen plan has been checksum-verified and implementation is beginning on
`feat/0.6-snapshot-reader` at base `e80cc5e82e22d74c24d36860c949138c472ec97c`.

The brief contains incompatible instructions about this file: the standing
order requires it to be committed from the start, while a later ground rule
forbids committing it. The standing order is being followed because it is
explicitly labeled as such; the final report will list this procedural
deviation.

## Done

- Verified `PLAN-0.6.md` against the adjacent SHA-256 record.
- Verified the worktree branch, base commit, and clean starting state.
- Read the frozen reader contract, refusal order, harness fixture procedure,
  residuals, sequencing, and lane prohibitions.

## Next

- Add the self-contained snapshot reader contract, constants, data types, and
  portable-name support.
- Add object selection, framing, rehashing, canonical commit/tree parsing, and
  ancestry tests.
- Add environment/configuration preflights, attributes, materialization,
  object-store verification, budgets, cleanup, and hostile-environment tests.
- Run the permitted focused, offline, and equivalence selections on the
  available interpreters, then push and open a draft PR.
