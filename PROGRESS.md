# Receipt 0.6 lane A progress

## State

The immutable reader and name-policy modules are implemented and locally
verified. Two independent read-only audits have been applied across process
lifecycle, parser allocation bounds, entry provenance, iterator ownership,
repository-control re-audits, bounded fsck heads, matching complexity, and byte
accounting. Snapshot tests pass on Python 3.11 through 3.14, the complete
offline suite passes on the worktree's default interpreter and Python 3.13,
and the permitted seven-case equivalence selection passes against a locally
extracted, hash-authenticated copy of the pinned ledger commit. Only remote
delivery remains.

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
- Corrected the canonical commit parser to treat LF as its only physical-line
  delimiter and precomputed accepted globstar shapes without relying on tuple
  identity.
- Completed all six named cleanup cases, including a mid-frame digest failure
  and an OpenSSL-shaped exception nested inside both context managers.
- Replaced the approximate Chronicle attribute fixture with the frozen eight
  physical lines (two comments, one blank, five rules); its matcher work is
  309 steps against the 67,108,864-step ceiling.
- Added exact-byte `posix-bytes` lookup coverage and the full portable alphabet,
  Win32-device, UTF-8 quote/fold, host-materialization, and raw-name matrices.
- Made cached listings and objects retain their entered-context guard; bound
  public entries to their exact mode, type, OID and path; and validated auditor
  expectations without invoking caller-defined equality.
- Made logical Git paths UTF-8-plus-surrogateescape on every host, moved tree,
  commit-parent, and attribute-rule ceilings into their parsers, and made a
  live digest iterator own the batch stream until natural exhaustion.
- Replaced linear tree-name lookup and quadratic prefix deduplication with
  canonical binary lookup and adjacent lexicographic prefix elimination. The
  attribute matcher now uses the specified two-pointer algorithm; independent
  checks found no mismatch across 500,000 exact-model cases or 43,200 hermetic
  Git-oracle cases.
- Hardened both long-lived and short-lived Git child cleanup against injected
  request, read, wait, join, and pipe failures, with one shared graceful-close
  deadline for the batch child.
- Added `PurePosixPath` materialization prefixes for the later `ChainSpec`
  consumers and deterministic raw-byte ordering in sibling collision screens.
- Passed the generated 20,000-entry, exactly 128 MiB acceptance fixture. Its
  principal counters are 60,000 tree entries (20,000 maximum in one walk),
  860,185 tree bytes, 900,000 path bytes, and 134,217,728 bytes each streamed
  and materialized, all below their ceilings.
- Passed the exact focused command on the worktree's default CPython 3.14.4:
  81 tests in 4.52 seconds.
- Passed all 385 split snapshot tests on CPython 3.14.4 in 40.33 seconds,
  CPython 3.11.15 in 70.26 seconds, CPython 3.12.13 in 48.07 seconds, and
  CPython 3.13.12 in 48.23 seconds.
- Passed the exact focused command on CPython 3.11.15: 81 tests in 6.75
  seconds.
- Passed the complete offline suite on CPython 3.14.4: 1,336 passed and 94
  equivalence cases deselected in 194.08 seconds. The same suite passed on
  CPython 3.13.12: 1,336 passed and 94 deselected in 193.77 seconds.
- Passed the sole permitted equivalence selection, seven of seven, in 2.23
  seconds. Its fixture was generated under a private temporary directory from
  the local Chronicle object database at ledger pin
  `9dafe8174f42a06c00817fe596d5a8e686cb17b7`; both oracle source hashes matched
  the pins before the tests ran, and the directory was removed on exit.
- A CPython 3.11 offline attempt was interrupted after 787 passing tests and
  94 deselections when concurrent interpreter matrices stopped progressing;
  an isolated retry emitted no output for 12 minutes and was interrupted.
  CPython 3.12's concurrent offline attempt likewise had no failure before it
  was interrupted after 1,258 passing tests. These inconclusive diagnostic
  runs do not replace the completed CPython 3.14 and 3.13 offline passes.

## Next

- Push `feat/0.6-snapshot-reader` to `origin` and open a draft pull request.
  The local GitHub CLI credential currently reports invalid and outbound
  GitHub connectivity is unavailable; both delivery operations will still be
  attempted after this progress commit so their exact outcome is recorded.
