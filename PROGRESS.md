# Receipt 0.6 lane A progress

## State

The immutable reader and name-policy modules are implemented. The reader's
process lifecycle, entry provenance, repository-control re-audits, bounded
fsck heads, and byte accounting have received a second hardening pass. Feature,
budget, hostile-environment, object-corruption, and name-boundary coverage are
complete. A fresh read-only audit and the final interpreter matrix remain.

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
- Hardened abandoned batch-child teardown, bounded batch reads and stderr,
  independent closing audits, one-snapshot entry binding, cumulative ancestry,
  exact fsck heads, and per-write materialization accounting.
- Added the fail-closed attribute differential, Chronicle's eight quoted
  rules, comments and blank-line grammar, materialization and anchor-digest
  coverage, all six cleanup paths, verification-wide candidate/base budget
  sharing, and one refusal for every frozen ceiling.
- Added a per-family configuration deny matrix, a per-name hostile `GIT_*`
  matrix, exact default and `--verify-objects` child-command recorders, linked
  worktree sentinel checks, and the SHA1DC and optional Git-floor preflights.
- Added loose-object and packed-object corruption fixtures. The loose-object
  fixture proves `cat-file` exits zero on forged bytes and only the requested
  store-wide verification catches the unreachable corruption; the packed
  fixture flips a byte inside an object after the first packed object.
- Tightened ancestry to accept an entered base `TreeSnapshot` only, so the
  candidate and base necessarily share the cumulative verification budgets.
- Added exact-byte `posix-bytes` lookup coverage and the full portable alphabet,
  Win32-device, UTF-8 quote/fold, host-materialization, and raw-name matrices.
- Passed the generated 20,000-entry, exactly 128 MiB acceptance fixture. Its
  principal counters are 60,000 tree entries (20,000 maximum in one walk),
  860,185 tree bytes, 600,000 path bytes, and 134,217,728 bytes each streamed
  and materialized, all below their ceilings.
- Passed all 328 snapshot tests and 951 existing offline tests (94 equivalence
  tests deselected) on the worktree's default interpreter.

## Next

- Resolve any finding from the final read-only audit.
- Run the permitted focused, offline, and equivalence selections on Python
  3.11 and the worktree's default interpreter, then push and open a draft PR.
