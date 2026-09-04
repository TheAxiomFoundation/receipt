# Receipt 0.6 tree-object harness re-pin

This re-pin changes the subject handed to the extracted verifier, not the
authenticated baseline or its verdict vocabulary. Lane E first committed each
mutated custody surface and bound its candidate OID. In 0.6, the port leg now
selects that OID and the base ref as two entered `TreeSnapshot`s, proves
ancestry, compares release history from their entries, and runs the unchanged
directory verifier over a private candidate materialization. The oracle still
reads a checkout of the same commit. The detached-checkout leg therefore tests
both that the checkout of C equals C and that the port does not need a
checkout.

## Differential census

The tagged 0.5.2 differential census is 94 cases:

- 26 cases are re-pinned from checkout input to commit-object input: the 8
  ledger base-ref cases in Lane C and the 18 append-gate cases owned by Lane B.
- 68 cases are unchanged: the ledger 26-case `--full` battery and its clean and
  authentication cases, the 3 append-gate authentication cases, all 20 attest
  cases, and all 17 brier cases.
- 7 Lane C port-only cases are added, taking the integrated census to 101:
  deliberate dirty-checkout divergence, later working-tree mutation, later
  index mutation, foreign `GIT_DIR`, foreign `GIT_INDEX_FILE`, `refs/replace`,
  and a flipped reachable loose object under object-store verification.

The ledger module therefore collects 43 cases after this change: its prior 36
plus the 7 port-only additions. No case was renamed, no branch marker was
weakened, and neither authenticated oracle was edited.

## Deliberate divergence

After `commit_candidate`, an unstaged edit to existing ledger line 129 makes
the separately authenticated append-only baseline refuse:

```text
change rewrites existing line 129 (statcan.cpi.all_items_annual_rate.canada.may_2026.first_print); the ledger is append-only — supersede instead
```

The object-backed port, explicitly given the candidate OID, accepts because
the selected commit did not change. This is the intended directory-versus-tree
input-class divergence.

The ledger harness authenticates `scripts/check_thesis_facts_append.py` at its
pinned SHA-256 for this one deliberate divergence and invokes it unchanged.
All ordinary differential cases remain comparisons with the authenticated
release-chain oracle, and Lane B retains ownership of the append-gate harness.

## Port-only invariants

The added cases bind these object-reader properties independently of checkout
equivalence:

- changing the working tree or index after the candidate commit is selected
  does not change the verdict;
- inherited `GIT_DIR` and `GIT_INDEX_FILE` values do not redirect discovery or
  object reads;
- a candidate `refs/replace` mapping does not change the selected commit;
- flipping a byte in a reachable loose object refuses when whole-store
  verification is requested.

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

The harness adapts only those two exact `SnapshotError` strings to the pinned
legacy messages. It does not run another Git command, resolve a ref again,
weaken comparison, edit either oracle, or change `snapshot.py`. Any other
reader diagnostic passes through unchanged and still fails byte comparison.

## Verification

Run from the Lane C worktree with the authenticated local extraction at
`9dafe8174f42a06c00817fe596d5a8e686cb17b7`:

```console
RECEIPT_LEDGER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/ledger-9dafe81 /Users/maxghenis/TheAxiomFoundation/receipt/.venv/bin/python -m pytest -q tests/test_ledger_equivalence.py
43 passed in 15.60s
```

Collection is 43 with zero skips: all prior 36 cases plus all 7 additions.
