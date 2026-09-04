# Lane E progress — commit the differential harness fixtures (receipt 0.6)

Branch `feat/0.6-lane-e-fixture-commits`, worktree
`/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-06-lane-e`, from
`origin/main` at d8c6cf4 (v0.5.2 + merged 0.6 tree reader).

This committed file is the salvage record. The continuation's top-level
standing order to commit it supersedes the inherited brief's later sentence
that says not to commit it.

## State

Implementation and final local verification are complete. The two harness
commits are clean and every required suite is green. Push and draft PR are
next; the plan-mandated named-model reviews were attempted but are unavailable
in this sandbox (details under Findings).

## Done

- Read `PLAN-0.6.md` §3.8 "Step one, Lane E" (the governing paragraph). No
  `CLAUDE.md` in the repo; org `CLAUDE.md` read.
- Read both harnesses in full, the pinned upstream oracles
  (`.extraction/ledger-9dafe81/scripts/{check_thesis_facts_append,verify_release_chain}.py`)
  and the port's `verify_release_history_immutable`,
  `assert_index_content_bound`, `assert_index_agrees_with_tree` and
  `assert_file_modes_authoritative`.
- **cedc997** — ledger harness: `commit_candidate`, `detached_oracle_checkout`,
  `committed_fixture_filesystem`, `assert_copied_surface`, two legs on the
  eight base-ref cases, module docstring.
- **82669c3** — append-gate harness: the same contract on the eighteen cases
  that run a verifier, module docstring, plus memoizing the filesystem probe
  in the ledger harness (see "Findings", item 2).
- Recovered and independently audited the interrupted diff against every §3.8
  requirement before retaining it; no correctness blocker was found.

## Runs

Pinned venv `/Users/maxghenis/TheAxiomFoundation/receipt/.venv/bin/python` and
authenticated local trees `ledger-9dafe81` and `brier-4b9e7be`.

| run | before (d8c6cf4) | after (82669c3) |
| --- | --- | --- |
| the two Lane E harnesses | 57 passed (32.9s) | 57 passed (38.13s; 38.31s wall) |
| all four equivalence harnesses | 94 passed (4:24) | 94 passed (221.55s; 221.67s wall) |
| offline suite (`-k "not equivalence"`) | 1413 passed, 94 deselected (4:36) | 1413 passed, 94 deselected (196.01s; 196.19s wall) |

Same case count, every case passing, both legs. No skips: the filesystem under
test reports `core.fileMode` and `core.symlinks` true.

## Census (confirmed twice: by collection, and by the sabotage run below)

| module | cases | moved | unmoved |
| --- | --- | --- | --- |
| `test_append_gate_equivalence.py` | 21 | 18 (3 acceptances + 15 mutations) | 3 (`test_each_oracle_source_is_authenticated`) |
| `test_ledger_equivalence.py` | 36 | 8 (clean base-ref + 7 `BASE_REF_MUTATIONS`) | 28 (26 `--full` battery, 1 authentication, 1 clean chain) |

## Leg two is load-bearing (measured, not assumed)

Pointing leg two's detached checkout at the candidate's parent instead of the
candidate fails **exactly** the moved cases and no others:

- append gate: 18 failed, 3 passed — the three that failed to fail are the
  three authentication cases, which is the census.
- ledger: 8 failed, 28 passed — likewise.

Reverted immediately; the branch carries no trace of it. This is what rules out
a leg two that runs but asserts nothing.

## Why the moved cases stay green (read, not assumed)

- Oracle `check_surface_separation` classifies from `git diff <base> --`
  (base tree vs **working tree**) unioned with `git ls-files --others`.
  Committing moves a path from the untracked half to the diff half; the union
  is unchanged.
- Oracle `verify_release_history_immutable` compares the base tree's blobs and
  modes against the **working tree** (`current.read_bytes()`, `current.stat()`).
  Committing does not touch the working tree.
- Port `assert_index_content_bound` accepts `I == B` **or** `I == H` (the blob
  id of the bytes this run verified). Today's fixtures give `I == B`; after the
  change they give `I == H`. Both are accepted, and the check runs after the
  comparisons it qualifies.
- Port `assert_index_agrees_with_tree` / `assert_index_hides_no_working_tree_change`
  are satisfied trivially once index, tree and HEAD agree.
- Port `assert_file_modes_authoritative` already refuses `core.fileMode=false`
  and `core.symlinks=false` in its own words, which the oracle would not
  produce — so the harness skips, not fails, on such a filesystem.

## Findings

1. **No divergence.** Every moved case is green on both legs. Nothing about
   0.5.2 was found that the brief's stop rule would catch, and no verifier code
   was touched to get there: `git diff d8c6cf4..HEAD --stat` is the two test
   files and nothing else.
2. **A false mechanism claim, caught and fixed before push.** The append-gate
   harness's import comment claimed that importing `committed_fixture_filesystem`
   "keeps the probe it makes to one per session across both harnesses". Counting
   probe directories under a fixed `--basetemp` showed **two** — requesting the
   session fixture from two modules ran its body twice. The probe is now
   memoized in a module-level global in the ledger harness, re-measured at one,
   and both comments say what is true. Harmless in effect (a `git init` in a
   temp directory), but the claim was wrong and would have shipped in a
   docstring.
3. **The two review models are unavailable here.** A read-only Fable-main
   dispatch found no enrolled keychain lane; a read-only Opus-peer dispatch
   likewise found no enrolled lane and reported its earliest scoped reset as
   2026-09-04 11:04:03 -0400. Direct Claude is not logged in. No review is
   claimed; the draft PR remains the handoff for that required gate.
4. **The progress instructions conflict.** A concurrent revive process dropped
   the first progress commit to honor the inherited "do not commit" sentence.
   This continuation instead follows the newer, explicitly labeled standing
   order to maintain a committed `PROGRESS.md`; neither harness commit is
   rewritten to do so.
5. **One discarded run had the wrong scope.** A punctuation dot was passed to
   pytest as a repository target, collecting all 1,507 tests, and its brier
   setup then hit the sandboxed network. The exact 94-case command was rerun
   with both authenticated local tree overrides and passed; the discarded run
   is not an implementation finding.

## Next

1. `git push -u origin feat/0.6-lane-e-fixture-commits`.
2. Draft PR "Commit the differential harness fixtures (0.6 Lane E)".
3. Record the PR URL and final head, push that progress-only checkpoint, and
   write the final report to the task runner's output target.

## Note on method

The harness diff received an independent read-only audit in addition to the
pinned differential and the sabotage run above. The named Fable/Opus gate was
not substituted with that audit; its unavailability is recorded explicitly.
