# Receipt 0.6 tree-object harness re-pin

This re-pin changes the subject handed to the extracted verifier and retains
the authenticated baseline and each pinned mutation's exact comparison.
[Lane E (#54)](https://github.com/TheAxiomFoundation/receipt/pull/54) first
committed each mutated custody surface and bound its candidate OID. In 0.6,
the port leg now selects that OID and the base ref as two entered
`TreeSnapshot`s, proves
ancestry, compares release history from their entries, and runs the retained
directory verifier over a private candidate materialization. The oracle still
reads a checkout of the same commit. The detached-checkout leg therefore tests
both that the checkout of C equals C and that the port does not need a
checkout.

## Fixture change

Lane E landed the fixture change against 0.5.2 before changing verifier code.
The shared `commit_candidate(root, name)` runs `git add -A`, commits when the
index differs from HEAD, and otherwise returns HEAD. `base_unresolvable_ref`
changes no tree and `base_not_ancestor` only writes a detached commit object,
so both reuse HEAD. After every moved case's mutation, the helper asserts
that `git status --porcelain --ignore-submodules=none` and
`git ls-files --others --ignored --exclude-standard` are empty, and that
`git write-tree` equals the candidate's `HEAD^{tree}`. The copy assertion
allows only `ledger/` and `releases/` and refuses a `.gitattributes` anywhere
under them. Files added by a mutation, including the gate-only script, are
committed afterward.

Each of the 26 moved cases has two legs: first, the oracle reads the main
worktree's clean candidate checkout; second, the oracle reads an independent
detached checkout of the same candidate. The harness creates that checkout
with `git worktree add --detach`, asserts its HEAD equals the candidate OID,
and removes that checkout with `git worktree remove --force` in `finally`.
The port uses the main repository in both legs. The independent detached
checkout is the consumer's CI shape; at the oracle pin its workflow uses
`git clone --no-checkout` and `git checkout --detach` to produce it, as
[Lane E's review response](https://github.com/TheAxiomFoundation/receipt/pull/54#issuecomment-5542695250)
records.

The fixture capability probe runs once per session and checks `core.fileMode`
and `core.symlinks`: `base_mode_change` must commit `100755`, and
`base_worktree_symlink` must commit `120000`. In Lane E it used the 0.5.2
port's configuration reader; after that reader's deletion, it uses the
fixture's isolated Git configuration. A false capability skips the moved
cases with the reason named. A harness run counts only at zero skips.

Lane E recorded 57 passing cases across the two changed harnesses and 94
across all four, with both legs retaining the 0.5.2 verdicts. The
`LEDGER_PIN`, `BASELINE_AUTHENTICATED_FILES` and
`receipts/ledger-pin-source-hashes.txt` authentication contract is retained.
The comparison remains exit status, complete refusal text after surrounding
whitespace and OpenSSL error-queue-ID normalization, exact success text, and
library silence. The blob-OID diagnostic exception below is outside the
pinned battery.

## Differential census

The tagged 0.5.2 differential census is 94 cases:

- 26 cases are re-pinned from checkout input to commit-object input: the 8
  ledger base-ref cases (one clean acceptance and 7 mutations) and the 18
  append-gate cases (3 acceptances and 15 mutations). Lane E committed their
  fixtures; Lane C and Lane B changed their port legs to object reads.
- 68 cases are unchanged: the ledger 26-case `--full` battery and its clean and
  authentication cases, the 3 append-gate authentication cases, all 20 attest
  cases, and all 17 brier cases.
- 7 Lane C port-only cases are added, taking the integrated census to 101:
  deliberate dirty-checkout divergence, later working-tree mutation, later
  index mutation, foreign `GIT_DIR`, foreign `GIT_INDEX_FILE`, `refs/replace`,
  and a flipped reachable loose object under object-store verification.
- 7 Lane B port-only cases are added, taking the integrated census to 108:
  the same deliberate input-class divergence; later working-tree and index
  mutations; `GIT_DIR` and `GIT_INDEX_FILE` injected after the retained entry
  guard; an effective candidate `refs/replace`; and a logical byte flip in a
  loose candidate-tree object that reaches the reader's exact rehash refusal.

The ledger module therefore collects 43 cases: its prior 36 plus its 7
port-only additions. The append module collects 28: its prior 21 plus its 7
port-only additions. Together with 20 attest and 17 brier cases, the total is
108: **26 re-pinned + 68 unchanged + 7 Lane C + 7 Lane B**. No prior case was
renamed, no branch marker was weakened, and neither authenticated oracle was
edited. The [Lane B review](https://github.com/TheAxiomFoundation/receipt/pull/57#issuecomment-5547500164)
independently confirmed this collection and the retained two-leg wiring.

## Deliberate divergence

After `commit_candidate`, an unstaged edit to existing ledger line 129 makes
the separately authenticated append-only baseline refuse:

```text
change rewrites existing line 129 (statcan.cpi.all_items_annual_rate.canada.may_2026.first_print); the ledger is append-only — supersede instead
```

The object-backed port, explicitly given the candidate OID, accepts because
the selected commit did not change. Both the ledger composition harness and
the append-gate harness bind this result. This is the one input class on which
the directory oracle and tree-object port are meant to disagree.

The ledger harness authenticates `scripts/check_thesis_facts_append.py` at its
pinned SHA-256 for this one deliberate divergence and invokes it unchanged.
All ordinary ledger differential cases remain comparisons with the
authenticated release-chain oracle; the append-gate harness compares against
the authenticated append oracle.

## Port-only invariants

The added cases bind these object-reader properties independently of checkout
equivalence:

- changing the working tree or index after the candidate commit is selected
  does not change the verdict;
- inherited `GIT_DIR` and `GIT_INDEX_FILE` values do not redirect discovery or
  object reads; the append cases inject them after its retained entry refusal,
  so they exercise the reader without weakening that public guard;
- a candidate `refs/replace` mapping does not change the selected commit;
- Lane C's flipped reachable loose object refuses under requested whole-store
  verification, and Lane B's valid-but-misnamed loose tree object refuses at
  the reader's per-object rehash.

## Snapshot diagnostic adapters

Two byte-equivalent legacy cases expose information that is not present in
the immutable `TreeSnapshot` public surface:

- failed `TreeSnapshot.select(root, base_ref)` reports only `cannot resolve
  commit '<ref>'`; it does not retain Git's stderr or the caller's base-ref
  role, while the pinned oracle says `cannot resolve base ref '<ref>' to a
  commit: fatal: Needed a single revision`;
- `candidate.assert_ancestor(base)` names `candidate commit <oid>` when the
  candidate was selected by OID, while the pinned oracle names the same
  selected commit `HEAD`.

The ledger harness adapts those two `SnapshotError` strings to the pinned
legacy messages. Each adapter first asserts the reader's exact diagnostic;
an unexpected string fails that assertion. Neither adapter resolves a ref
again or runs another Git command.
The ancestry adapter calls the candidate `HEAD`, so that particular message
comparison would mask a wrongly selected candidate OID; a wrong base OID
would remain in the message and fail comparison. This limit is stated in
`run_port_base_ref`'s docstring.

[Lane B round 1 finding F3 and its accepted response](https://github.com/TheAxiomFoundation/receipt/pull/57#issuecomment-5547639410)
record one exception to the exact-refusal-text requirement: when `base_ref`
is an existing blob OID, `TreeSnapshot.select`
normalizes the resolution failure and the append entrypoint's adapter omits
Git's first diagnostic line, `error: <oid>^{commit}: expected commit type, but
the object dereferences to blob type`. A clean committed scratch fixture
measured refusal status 1 from both the authenticated baseline and the port;
removing only that first line made their messages identical, with `fatal:
Needed a single revision` retained. This is a wording exception, with no
behavior change or second Git resolution. It lies outside the pinned
differential cases, whose exact comparisons remain unchanged.

## Recorded Lane B verification

[Lane B's merged PR body](https://github.com/TheAxiomFoundation/receipt/pull/57)
records the following integrated run from its build worktree, using the
authenticated Ledger extraction at
`9dafe8174f42a06c00817fe596d5a8e686cb17b7`, the authenticated Brier extraction,
and the project virtual environment. All four harnesses ran in one pytest
process and reported 108 passing cases with zero skips:

```console
RECEIPT_LEDGER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/ledger-9dafe81 RECEIPT_BRIER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/brier-4b9e7be /Users/maxghenis/TheAxiomFoundation/receipt/.venv/bin/python -m pytest -q tests/test_append_gate_equivalence.py tests/test_ledger_equivalence.py tests/test_attest_equivalence.py tests/test_brier_witness_equivalence.py
108 passed in 235.98s
```

Lane B also re-ran the #38-body port-only production differential. An
offline scratch driver used the authenticated `9dafe81` tree, created a fresh
Git repository and committed candidate for each case, passed each candidate
OID to `run_port`, required library silence, and checked the two exact success
texts plus every mutation's retained branch marker. Its complete result was:

```text
PORT-ONLY PRODUCTION TREE: 17/17 expected verdicts; committed scratch fixtures; zero skips
accept:clean
accept:gate_only
refuse:altered_new_release_manifest
refuse:base_release_file_changed
refuse:binding_presence_xor_empty_hash_only
refuse:duplicate_without_supersedes
refuse:empty_source_binding_projection
refuse:frozen_prefix_rewrite
refuse:historical_non_append
refuse:invalid_target_content_hash
refuse:missing_assertion_version
refuse:missing_new_release_manifest
refuse:mixed_data_and_gate
refuse:non_dict_source_binding_projection
refuse:prefix_manifest_changed
refuse:projection_without_target_hash
refuse:release_only_proposal
```
