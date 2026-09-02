# Closing the corpus closed-world gaps

Branch `fix/corpus-closed-world`, base `origin/main` d542d59 (receipt 0.5.1).
Two files changed: `src/receipt/corpus.py` (+118/-10) and
`tests/test_corpus.py` (+301), 12 tests added.

**Offline suite: 234 passed** (baseline 222).

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -c 'import receipt; print(receipt.__file__)'
/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-fix-corpus-closed-world/src/receipt/__init__.py

$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider tests \
    --ignore=tests/test_ledger_equivalence.py --ignore=tests/test_append_gate_equivalence.py \
    --ignore=tests/test_attest_equivalence.py --ignore=tests/test_brier_witness_equivalence.py
234 passed in 10.60s
```

Provenance, stated plainly: commits a41323f, 55a6215, c60606c, 8beb73d and
dbc6b4a — the code for all four findings — were already on this branch when
this session opened the worktree. I did not author them. What I did was audit
each one against its finding, reconstruct the before-state to confirm every
test genuinely fails without its fix, measure the behaviour changes none of
them tested, and then add what was missing: three coverage tests (0d26003) and
one further fix to finding 3 (cf90e46). Everything below is measured output,
not description of intent.

## How before/after was measured

The base source was materialized out of git rather than by editing the
worktree:

```
$ git archive d542d59 src | tar -x -C $SP/base
$ git show d542d59:src/receipt/corpus.py | shasum -a 256
a4b3ae814c99097ab82b58932930dcc8300829ab43579a1f600ce9a4a6613d09
```

One line was appended to that base copy — `MAX_EVIDENCE_TEXT = 1024` — because
the HEAD test module imports that name at module scope, and without it the
whole file fails at collection instead of per test. The constant is inert: no
base code reads it. Before-runs use `PYTHONPATH=$SP/base/src`, after-runs use
`PYTHONPATH=$PWD/src`. Both resolve `receipt` ahead of the venv's editable
install, which points at the main clone.

## Finding 1 — a case-varied content suffix escaped the sweep

**Changed** (a41323f): both suffix predicates now compare `_path_fold(path)`
against `_path_fold(suffix)` — `CorpusSpec.is_content_path` at
`src/receipt/corpus.py:185-188`, and the tree walk in `_tree_content_paths` at
`src/receipt/corpus.py:645-649`. The module docstring's closed-world sentence
now states the sweep is suffix-scoped after folding
(`src/receipt/corpus.py:22-28`).

**Tests**: `test_refuses_an_unlisted_content_file_whose_suffix_differs_only_by_case`
(`tests/test_corpus.py:942`),
`test_refuses_an_unlisted_content_file_whose_suffix_differs_only_by_normalization`
(`tests/test_corpus.py:963`), and — added by me, see "Beyond the four
findings" — `test_refuses_a_case_varied_content_path_bound_as_attested`
(`tests/test_corpus.py:1128`).

```
----- BEFORE -----
FFF                                                                      [100%]
FAILED tests/test_corpus.py::test_refuses_an_unlisted_content_file_whose_suffix_differs_only_by_case
FAILED tests/test_corpus.py::test_refuses_an_unlisted_content_file_whose_suffix_differs_only_by_normalization
FAILED tests/test_corpus.py::test_refuses_a_case_varied_content_path_bound_as_attested
3 failed, 56 deselected in 0.26s

----- AFTER -----
3 passed, 56 deselected in 0.05s
```

Both tests refuse deterministically on a case-sensitive filesystem too: the
fold happens in Python, so `.YAML` enters the closed-world set regardless of
what the host filesystem thinks. Confirmed the fold arithmetic directly —
`NFC(".YAML").casefold() == ".yaml"`, and NFD and NFC spellings of `.café`
fold equal.

The fold widens `is_content_path`, which decides row kind, so it moves two
cases in opposite directions. Measured on base vs HEAD:

| input | base d542d59 | HEAD |
| --- | --- | --- |
| content row `rules/tax/smuggled.YAML`, file present | refused at parse ("not under a pinned content root with a pinned suffix") | accepted |
| attested row `rules/tax/smuggled.YAML` | accepted | refused ("must be swept closed-world") |

The second is the smuggling vector's sibling and is the one that matters: a
producer could previously exempt a case-varied rule file from the sweep by
labelling it attested. The first is the necessary cost of making the two
predicates agree — the alternative, folding only the sweep, would make such a
file impossible to bind at all.

## Finding 2 — the verdict sanitiser missed format controls and had no length bound

**Changed** (55a6215): `_reject_control_characters`
(`src/receipt/corpus.py:240`) now also refuses every code point in Unicode
category Cf (`:269`) and U+2028/U+2029 (`:273`), each with its own message; the
existing control-character message is untouched. New `_reject_oversized_text`
(`src/receipt/corpus.py:280`) bounds evidence keys and values at
`MAX_EVIDENCE_TEXT = 1024` (`:100`), and `_validate_gate` calls it before the
character screen (`:420-423`) so refusing a flood does not print the flood.

Verified the Unicode facts the code and comments rest on rather than assuming
them: U+202E, U+200B, U+200D, U+00AD and U+FEFF are all category Cf, while
U+2028 is Zl and U+2029 is Zp — which is exactly why the two line separators
need their own explicit check and are not covered by the Cf test.

**Tests**: `test_refuses_a_bidi_override_in_gate_evidence` (`:985`),
`test_refuses_a_line_separator_in_gate_evidence` (`:1009`),
`test_refuses_gate_evidence_longer_than_the_bound` (`:1029`),
`test_accepts_gate_evidence_exactly_at_the_bound` (`:1049`), plus my
`test_refuses_a_zero_width_joiner_in_a_journal_path` (`:1158`).

```
----- BEFORE -----
FFF.F                                                                    [100%]
FAILED tests/test_corpus.py::test_refuses_a_bidi_override_in_gate_evidence
FAILED tests/test_corpus.py::test_refuses_a_line_separator_in_gate_evidence
FAILED tests/test_corpus.py::test_refuses_gate_evidence_longer_than_the_bound
FAILED tests/test_corpus.py::test_refuses_a_zero_width_joiner_in_a_journal_path
4 failed, 1 passed, 54 deselected in 0.05s

----- AFTER -----
5 passed, 54 deselected in 0.04s
```

The one passing before is `test_accepts_gate_evidence_exactly_at_the_bound`,
which asserts 1,024 characters are accepted — it should pass on both sides, and
does.

Blast radius, measured: `_reject_control_characters` is shared with
`_validate_relative_path` (`src/receipt/corpus.py:312`), so extending it
reaches journal paths as well as gate evidence. A path containing U+200D is
accepted by base and refused by HEAD. That is a new refusal in the right
direction — a zero-width joiner makes two rows binding two different files
print as one name — but it is wider than "gate evidence", so it now has a test
of its own. The 1,024-character bound is scoped to evidence keys and values
only, as specified.

## Finding 3 — a tombstoned path could remain on disk

**Changed** (c60606c, extended by cf90e46): after binding,
`verify_corpus_binding` lstats every removed path, content and attested alike,
and refuses one that is still there — `src/receipt/corpus.py:896-923`, message
`removed path is still present in the tree: …`.

**Tests**: `test_refuses_a_removed_attested_path_that_is_still_in_the_tree`
(`:1070`) and `test_a_removed_attested_path_absent_from_the_tree_verifies`
(`:1100`), plus my `test_a_removed_content_path_still_in_the_tree_is_refused_as_unlisted`
(`:1174`) and `test_refuses_a_removed_path_the_verifier_cannot_look_for`
(`:1201`).

```
----- BEFORE -----
F..                                                                      [100%]
FAILED tests/test_corpus.py::test_refuses_a_removed_attested_path_that_is_still_in_the_tree
1 failed, 2 passed, 56 deselected in 0.04s

----- AFTER -----
3 passed, 56 deselected in 0.04s
```

The two that pass before are the guards: the same journal with the file deleted
verifies and reports the path in `removed_paths`, and a removed *content* path
still on disk is caught earlier by the closed-world sweep as unlisted. That
second one pins a claim the new code comment makes; I checked it rather than
taking the comment's word, and the sweep's message is unchanged on both sides.

## Finding 4 — content file mode is unbound

**Changed** (8beb73d): no schema change. The module docstring
(`src/receipt/corpus.py:13-17`) now states that a binding covers the bytes and
the regular-file type but not the permission bits — a content file that gained
the execute bit after witnessing still matches its digest and still verifies —
and that release-object modes are covered by `receipt verify --base-ref`.

I verified the `--base-ref` half against the code rather than repeating the
docstring's claim: `verify_release_history_immutable`
(`src/receipt/release_chain.py:1545-1574`) derives a candidate mode of
`100755`/`100644` from `st_mode & 0o111` and refuses a mismatch against the git
entry mode, then compares bytes, for every release file present at the base
ref. `verify.py:333` states the same thing in the verdict. The claim holds. I
also confirmed the other half: `_regular_file_digest` checks `S_ISREG` and the
digest, never the mode bits.

No test — the finding asks for documentation of an accepted bound, and there is
no behaviour change to test.

## Beyond the four findings

Two commits, both separable if you want the branch to be exactly the four
findings.

**0d26003 — three coverage tests.** CONTRIBUTING requires a test per behaviour
change, and this branch changed three behaviours nothing asserted: the attested
relabelling now refused by finding 1, the journal-path refusal now caused by
finding 2's shared helper, and the content-path half of finding 3's tombstone
comment. Before/after for these is folded into the finding sections above; the
third passes on both sides by design.

**cf90e46 — a tombstone the verifier could not check.** Finding 3 as first
implemented swallowed every `lstat` error as absence:

```python
except OSError:
    continue
```

`lstat` raises EACCES, not ENOENT, when a parent directory is readable but not
searchable. Measured at c60606c: a tombstoned attested file sitting on disk
under a `0600` directory was **accepted**, and the verdict reported the path as
removed on the strength of a permission error — finding 3's own threat, reached
by a different errno. The module already holds the opposite rule for the same
class of failure: `_list_directory` refuses a directory it cannot enumerate
because "enumeration failure must be a refusal, not an empty result", with a
test that chmods `0111`.

Now `FileNotFoundError` and `NotADirectoryError` mean absent; every other
`OSError` refuses with `cannot check whether a removed path is still in the
tree, so the tombstone is unverifiable: …` (`src/receipt/corpus.py:904-923`).
Test `test_refuses_a_removed_path_the_verifier_cannot_look_for` (`:1201`)
mirrors the existing chmod test, including restoring the mode in `finally`.

```
----- BEFORE (at c60606c, finding 3 as first implemented) -----
E   Failed: DID NOT RAISE CorpusError
FAILED tests/test_corpus.py::test_refuses_a_removed_path_the_verifier_cannot_look_for
1 failed, 59 deselected in 0.06s

----- AFTER -----
4 passed, 56 deselected in 0.07s
```

Reachability, stated honestly: a fresh `git clone` will not produce an
unsearchable directory, since git tracks only the executable bit on files. The
scenario needs a working tree whose directory modes were set some other way.
That is the same reachability as the `0111` case the module already refuses,
which is why I closed it rather than filing it.

## Invariants held

- **Every existing refusal message is preserved verbatim.** Compared by AST —
  every message shape raised by a `CorpusError`, f-string holes normalized — 64
  in base, 64 of 64 still present at HEAD, 5 added (`removed path is still
  present in the tree`, `Unicode format control`, `Unicode line separator`, `is
  longer than N characters`, `tombstone is unverifiable`).
- **Row-kind schemas unchanged**: `_ROW_KEYS` is untouched; no row kind gained
  a field.
- **Order of existing refusals unchanged**: the tombstone sweep runs after all
  pre-existing checks, so anything previously refused still refuses with the
  same message. The evidence length check runs *before* the character screen —
  deliberate, and only reachable by input longer than 1,024 characters, which
  base accepted outright.
- **Only `corpus.py` and `test_corpus.py` changed.** `canonical.py` untouched;
  nothing outside the worktree touched.

## What I did not do, and why

- **The four network equivalence modules were not run**, per the ground rules
  (`test_ledger_equivalence`, `test_append_gate_equivalence`,
  `test_attest_equivalence`, `test_brier_witness_equivalence`). The changes are
  equivalence-safe by construction: they are confined to `receipt.corpus`,
  which is not one of the differentially gated surfaces, and they preserve
  every existing message and ordering as shown above.
- **No push, no PR, no `git worktree` commands, no network.**
- **No PROGRESS.md**, per the task instruction — which overrides the standing
  order to keep one.
- **A long journal path can still flood the verdict.** Finding 2 bounds evidence
  keys and values; paths are unbounded. Measured: a content row whose path is
  200,000 characters produces a 200,093-character refusal message ("content
  file(s) bound by the journal are missing from the tree, starting with
  'rules/aaa…'"). It refuses rather than passing, so this is a legibility
  failure of the same family as the evidence bound, not a false verdict. Fixing
  it means bounding path length, which is a schema-adjacent decision beyond
  this finding's stated scope — flagging rather than taking it.
- **`content_root_of` still matches roots byte-exactly**, while the suffix now
  folds. I tested the escape this suggests instead of reasoning about it: on
  this case-insensitive filesystem (verified as such), an unwitnessed file
  written through `RULES/tax/` and bound as attested under that spelling is
  refused — the sweep enumerates it under the pinned spelling and it is
  unlisted. On a case-sensitive filesystem `RULES/` is a genuinely different
  directory outside the pinned content root, so binding it as attested is a
  legitimate binding of a different file. No false pass in either case, so I
  left the root matching alone.

## Commits on this branch

```
cf90e46 Refuse a tombstone the verifier could not check
0d26003 Cover the two refusals these fixes widened, and the one they did not
dbc6b4a Drop review provenance this branch cannot vouch for
8beb73d State that a binding does not cover permission bits
c60606c Refuse a tombstoned path that is still present in the tree
55a6215 Refuse invisible and unbounded text in gate evidence
a41323f Refuse a content file whose suffix escapes the sweep by case
```
