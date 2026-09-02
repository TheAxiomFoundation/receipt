# Append-gate confinement: what changed

Branch `fix/append-gate-confinement`, from `origin/main` d542d59 (receipt 0.5.1).
Six commits, one per finding, plus one width-only cleanup.

All five findings are implemented. Every new refusal is for an input the
upstream battery never presents; no existing refusal message or refusal order
changed, and nothing previously refused is now accepted. That is not only
reasoned — it is measured; see **Equivalence check** below.

Line numbers are the post-change ones in this worktree unless marked "at
d542d59".

---

## 1. A gate-only proposal that also rewrites an unclassified file

**What changed.** `src/receipt/append_gate.py:180-228` — `check_surface_separation`
now returns the unclassified remainder (`changed - data_changes - gate_changes`)
as a third element. `src/receipt/append_gate.py:231-259` — new
`check_gate_only_confinement` refuses a gate-only proposal that also changes an
unclassified path under `spec.chain.release_root_relative`, and returns the rest.
`src/receipt/append_gate.py:940-951` — `verify_append_gate` calls it before the
gate-only early return and names any surviving unclassified paths in the success
text.

The docstrings state the threat: the early return happens before the ledger is
read, so the frozen prefix, the append-only diff, the row bindings, and the
release history are all skipped for whatever else the proposal touched.

Refusal message: `gate-only proposal changes unclassified release path(s): [...]`.
Success text gains `; unclassified changes=[...]` only when the set is non-empty,
so a clean gate-only proposal keeps its exact baseline text.

**Tests** (`tests/test_append_gate.py`, a local git repository built from
scratch — no network, no witnesses, no signatures; the equivalence module is
untouched):

- `test_a_gate_only_proposal_cannot_rewrite_the_release_tree` (:273) — gate script
  + `releases/README.md` rewrite refuses.
- `test_an_unclassified_change_outside_the_release_tree_is_named` (:296) — gate
  script + top-level `NOTES.md` is accepted and named in the text.
- `test_a_clean_gate_only_proposal_keeps_its_baseline_verdict` (:314) — the pin
  that the oracle-identical case is unchanged.
- `test_an_ordinary_append_is_accepted` (:262) — fixture baseline.

**Before/after.** With `src/` at d542d59:

```
FAILED tests/test_append_gate.py::test_a_gate_only_proposal_cannot_rewrite_the_release_tree
  E  Failed: DID NOT RAISE AppendError
FAILED tests/test_append_gate.py::test_an_unclassified_change_outside_the_release_tree_is_named
  E  - append.py']; unclassified changes=['NOTES.md']
  E  + append.py']
2 failed, 2 passed
```

i.e. the release-README rewrite returned `thesis-facts append check OK: gate-only
proposal; ...`. After: `4 passed`.

---

## 2. A symlinked `ledger/` parent supplying accepted state

**What changed.** `src/receipt/release_chain.py:993-1023` — new
`assert_no_symlinked_state_component`, a per-component walk from the root
refusing symlinks and reparse points (`st_reparse_tag`), mirroring
`corpus._assert_no_symlinked_component` and the anchor-path walk already inside
`verify_release_chain`. `src/receipt/release_chain.py:1026-1039` —
`_regular_file_bytes` runs it *after* its existing final-component check, so
every input that reader already rejected keeps that refusal and its exact
message; the walk only ever fires for a path the reader used to accept.
`_verify_state_history` (:1041) reads both the ledger and the immutable prefix
through `_regular_file_bytes`, so both are covered there — I did not add a
second call site, because putting the walk ahead of `_regular_file_bytes` would
have let it preempt that reader's existing refusal.

`src/receipt/append_gate.py:262-279` — `_confine_state_path` wraps the walk and
re-raises as `AppendError`, preserving the message text.
Applied at `append_gate.py:959` (before the candidate ledger read) and
`append_gate.py:382` (in `check_prefix`, before the prefix read).

New refusal message: `state path traverses a symlink at '<component>': <relative>`.

**Tests** (`tests/test_append_gate.py`):

- `test_a_symlinked_ledger_parent_cannot_serve_state_from_outside_the_tree` (:342)
- `test_an_in_tree_symlinked_ledger_parent_is_refused` (:363)
- `test_a_symlinked_state_file_itself_is_refused` (:381)
- `test_a_symlinked_prefix_parent_is_refused` (:400)
- `test_the_state_reader_refuses_a_symlinked_parent` (:421) — the release-chain
  reader directly.
- `test_the_state_reader_keeps_its_message_for_a_symlinked_state_file` (:440) —
  pins the pre-existing final-component message `required state file is missing
  or non-regular: <path>` unchanged.
- `test_the_state_reader_accepts_an_ordinary_regular_file` (:460), plus the
  ordinary-append baseline at :262.

**Before/after.** Reproduction on the fixture with `src/` at d542d59:

```
external symlink -> thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base
in-tree symlink  -> thesis-facts append check OK: 3 rows, immutable prefix 1, +1 appended vs base
```

After:

```
receipt.append_gate.AppendError: state path traverses a symlink at 'ledger': ledger/official_observations.jsonl
```

Test run before: `5 failed, 6 passed`. After: `11 passed`.

---

## 3. `base_ref` resolved by name at three points

**What changed.** `src/receipt/append_gate.py:101-115` — new frozen `_BaseCommit`
carrying `ref` (what the caller named) beside `commit` (the OID it resolved to at
entry). `append_gate.py:936-940` — `verify_append_gate` resolves once via the
unchanged `_resolve_base_commit` (its `merge-base --is-ancestor` check is intact)
and threads the object to every consumer:

- `check_surface_separation` (:180) — no longer resolves internally; diffs `base.commit`.
- `check_append_only` (:601) — `git show {base.commit}:...`.
- `_manifest_at_ref` (:628) — `git show {base.commit}:...`.
- `check_prefix_anchored_to_base` (:643).
- `check_release_proposal` (:765) — passes `base.commit` to
  `verify_release_history_immutable`.

Every refusal keeps interpolating `base.ref`, so no message text changed. The git
call sequence is unchanged: resolution happens at entry, immediately before the
surface check, which is exactly where it happened before.

**Success text.** `append_gate.py:1007-1013` appends ` <ref> (<oid>)` after
`vs base` **when the caller named something other than that OID**. See
*Deviation* below for why it is conditional.

**Tests** (`tests/test_append_gate.py`), on a fixture with two commits (2 rows,
then 3) and a four-row worktree, so the two commits give different verdicts:

- `test_the_success_text_names_the_commit_a_symbolic_base_resolved_to` (:494)
- `test_a_base_named_by_its_own_commit_keeps_the_baseline_text` (:507)
- `test_the_moved_branch_alone_would_change_the_verdict` (:521) — the control.
- `test_a_branch_that_moves_mid_verdict_is_still_read_at_one_commit` (:535) —
  monkeypatches `check_surface_separation` to move the branch after the surface
  check, then asserts the verdict still names the original commit and its `+2`.

**Before/after.** With `src/` at d542d59, the mid-run branch move produced:

```
E  assert 'thesis-facts...ended vs base' == 'thesis-facts...445d7e42a201)'
E    - refix 1, +2 appended vs base moving (58208f2ee9f38919a8b45bcecf8c445d7e42a201)
E    + refix 1, +1 appended vs base
```

That `+1` is the bug reproduced directly: the surfaces were classified against
the commit that makes it `+2`, while the append-only diff read the moved branch.
`3 failed, 12 passed` before; `15 passed` after.

---

## 4. Mode-only changes to the ledger or prefix

**What changed.** `src/receipt/append_gate.py:670-696` — new `check_state_modes`
compares the base `git ls-tree` mode (via `git_file_entry`) against the candidate
`stat` for both `spec.chain.state_relative` and `spec.chain.prefix_relative`, in
the executable category git actually records. Called at `append_gate.py:980`,
after `check_prefix_anchored_to_base` and `check_append_only`, so every refusal
that existed before it still fires first and in its own words.

Refusal message: `state file mode changed relative to base: <path>`.

**Tests** (`tests/test_append_gate.py`):

- `test_the_ledger_cannot_be_made_executable_by_a_proposal` (:562)
- `test_the_frozen_prefix_cannot_be_made_executable_by_a_proposal` (:580)
- `test_a_ledger_executable_at_the_base_may_stay_executable` (:598) — the
  invariant is "keeps the base's category", not "must be 644".

**Before/after.** With `src/` at d542d59, `chmod +x` on either state file:

```
E  Failed: DID NOT RAISE AppendError
FAILED ...::test_the_ledger_cannot_be_made_executable_by_a_proposal
FAILED ...::test_the_frozen_prefix_cannot_be_made_executable_by_a_proposal
2 failed, 1 passed
```

After: `3 passed`.

---

## 5. Post-cutover binding values checked for presence only

**What changed.** `src/receipt/append_gate.py:520-541`, inside the
`number > prefix_count` block of `check_rows`, after every existing presence
refusal:

- `responseArchive.sha256` must be 64 lowercase hex — `appended line N (id)
  responseArchive.sha256 is not a SHA-256 hex digest`
- `ledgerRepoSha` must be 40 lowercase hex — `appended line N (id) ledgerRepoSha
  is not a full 40-character commit id`
- `retrievedAt` must be RFC 3339 with a time zone — `appended line N (id)
  retrievedAt is not an RFC 3339 timestamp with a time zone`

`append_gate.py:412-431` — `_is_rfc3339_with_zone` pins the shape by pattern
(so `fromisoformat`'s wider grammar — bare date, space separator, missing
offset — cannot slip through), then hands it to the parser, which is what
rejects a February 30th that matches the pattern. Non-UTC offsets are accepted:
this adds a shape, not a policy about which zone a resolver reports from.

`append_gate.py:435-444` — `check_rows` gained a docstring stating that what the
values MEAN is untouched, and specifically that the `assertionVersion` projection
stays exactly as it is because it must remain byte-identical to the Brier
writer's; changing it is a coordinated schema migration on both sides, not a gate
fix. (`expected_assertion_version_id` is unchanged.)

**Tests** (`tests/test_append_gate.py`):

- `test_a_response_archive_digest_that_is_not_a_digest_is_refused` (:621)
- `test_an_uppercase_response_archive_digest_is_refused` (:638)
- `test_an_abbreviated_ledger_repo_sha_is_refused` (:660)
- `test_a_symbolic_ledger_repo_sha_is_refused` (:675) — `"HEAD"`
- `test_a_retrieved_at_without_a_time_zone_is_refused` (:690)
- `test_a_retrieved_at_that_is_not_a_timestamp_is_refused` (:706) — `"yesterday"`
- `test_a_retrieved_at_naming_an_impossible_day_is_refused` (:722)
- `test_a_retrieved_at_with_a_non_utc_offset_is_accepted` (:738)

**Before/after.** With `src/` at d542d59: `7 failed, 1 passed`
(every malformed value returned `thesis-facts append check OK`). After: `8 passed`.

---

## 6. stderr capture left to the spec lane

I did have to touch `check_append_only` and `_manifest_at_ref` (d542d59 lines
454-465 and 481-491) for finding 3 — both `git show` invocations now take
`base.commit` and both refusals now interpolate `base.ref`. **No `stderr=`
argument was added to either `subprocess.check_output` call, and no diagnostic
was added to either refusal.** Verified:

```
$ grep -n "subprocess.check_output" -A 5 src/receipt/append_gate.py
605:        base_text = subprocess.check_output(
606-            ["git", "show", f"{base.commit}:{relative}"],
607-            cwd=candidate.root,
608-            text=True,
609-        )
630:        text = subprocess.check_output(
631-            ["git", "show", f"{base.commit}:{relative}"],
632-            cwd=candidate.root,
633-            text=True,
634-        )
```

The spec lane's change applies on top with no conflict beyond the one-line
argument each.

---

## Equivalence check (measured, not just reasoned)

I did not run the four network-cloning equivalence modules — they are the
orchestrator's step, and this session has no network. Instead I ran two offline
checks against the pinned production tree cached at
`.extraction/ledger-9dafe81` (read-only; `git status --porcelain` there is empty
afterwards):

**a. Binding-value formats on the real rows.** All 19 post-cutover rows
(129-147, the boundary `replay_release_two` produces) satisfy the finding-5
formats: response digests are 64 lowercase hex, every `ledgerRepoSha` is exactly
40 lowercase hex, and every `retrievedAt` is `…Z`. So finding 5 refuses nothing
the battery accepts.

**b. A port-only differential.** A scratch script drives this package's
`verify_append_gate` over the same pinned tree, the same two acceptance fixtures
(`replay_release_two`, `gate_only_candidate`) and all 15 mutations that
`test_append_gate_equivalence.MUTATIONS` defines — no oracle subprocess, no
clone. Running it twice, once with `src/` from d542d59 and once with this
branch, and masking the fixture's per-run commit id:

```
IDENTICAL after masking the fixture's per-run commit id — 17/17 verdicts unchanged
```

Both acceptance texts come out byte-identical to the strings the harness pins:

```
accept:clean      thesis-facts append check OK: 147 rows, immutable prefix 128, +2 appended vs base, release 2
accept:gate_only  thesis-facts append check OK: gate-only proposal; DATA_SURFACE unchanged; GATE_SURFACE changes=['scripts/check_thesis_facts_append.py']
```

Since the package at d542d59 is the one the differential gate already certifies
against the unmodified upstream oracle, 17/17 identical verdicts is direct
evidence that this branch stays equivalent. The orchestrator's run against the
live oracle remains the authority.

---

## Deviation: the OID in the success text is conditional

The finding asked for the OID in the success text as `… vs base <ref> (<oid>)`.
Unconditionally, that breaks the differential gate, which the ground rules make
binding and which I was told to keep safe by construction:

- `tests/test_append_gate_equivalence.py:372` asserts the port's acceptance
  summary equals the unmodified upstream CLI's stdout **byte for byte**.
- `tests/test_append_gate_equivalence.py:429-433` pins that string as
  `"…, +2 appended vs base, release 2"` — no OID.
- `commit_tree` (:257-263) returns `git rev-parse HEAD`, so the battery always
  passes a full 40-hex OID as `base_ref`. An unconditional suffix would render
  `vs base <oid> (<oid>)` and diverge from the oracle.

So the suffix appears when `base.ref != base.commit` — i.e. whenever the caller
named something that could move, which is the whole case the finding is about.
A caller who passed the OID already named the commit, and that verdict keeps its
exact baseline text. This matches the repo's existing idiom for adding
information without disturbing gated text (finding 1's conditional `unclassified
changes=` suffix; `compute_anchor_set_digest` being off by default).

If the orchestrator would rather have it unconditional, it is a two-line change
at `append_gate.py:1007-1013` plus a matching edit to those two equivalence
assertions — but that edit is to the module I was told to leave untouched, so I
did not make the call.

The test for finding 3 does not depend on this: it uses the option the finding
itself offered ("a post-resolution branch move does not change the verdict"),
with a control test proving the two commits genuinely disagree.

## Nothing else was left undone

Findings 1-5 are complete, each with tests that fail before and pass after.
Finding 6 is a non-action and is documented above.

---

## Suite

```
$ PYTHONPATH=$PWD/src ./.venv/bin/python -m pytest -q -p no:cacheprovider tests \
    --ignore=tests/test_ledger_equivalence.py \
    --ignore=tests/test_append_gate_equivalence.py \
    --ignore=tests/test_attest_equivalence.py \
    --ignore=tests/test_brier_witness_equivalence.py
248 passed in 187.98s (0:03:07)
```

(An earlier identical run finished in 19.60s; the final one shared the machine
with other work. Same 248 tests, same result.)

**248 passed**, up from the 222 baseline: 26 new tests in
`tests/test_append_gate.py`. Running that module alone against `src/` at
d542d59 gives `19 failed, 7 passed` (the 7 are the baseline, control, and
message-pin tests, which must pass on both sides); against this branch,
`26 passed`.

Import precedence confirmed at the start:
`/Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-fix-append-gate-confinement/src/receipt/__init__.py`.

## Commits

```
7150711 Wrap the lines this branch stretched past the file's width
6925030 Validate the post-cutover binding values, not just their presence
b6b3bb8 Refuse a state file whose mode changed against the base
39912dd Resolve the base commit once for the whole verdict
fb58371 Untrack the local interpreter symlink
3c20531 fixup! Refuse a state path that traverses a symlinked component
ce39fcf Refuse a state path that traverses a symlinked component
0dc4827 Confine a gate-only proposal to the surfaces it speaks for
```

Two of those are not mine and predate my later work: `3c20531` added the local
`.venv` symlink to the index and `fb58371` removed it again, widening
`.gitignore` from `.venv/` to `.venv` so a symlink matches. Net effect on the
tree is that one `.gitignore` character; `git ls-files` shows no tracked venv. I
did not squash them, because rebasing is off-limits under the ground rules.
