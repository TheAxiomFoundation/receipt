# Shared context for the probe agents (read fully before starting)

You are one of four adversarial probe agents working for the independent
reviewer of TheAxiomFoundation/receipt PR #84 (branch fix/crash-to-refusal,
HEAD f8b1ddc, base origin/release/0.6.x = 9c47a3d). Your findings decide
whether it merges. Verify everything by executing code; do not trust the
author's commit messages, docstrings, CHANGELOG or PR body.

## Workspace and trees

- Worktree (read-only for you except your scratch dir):
  /Users/maxghenis/TheAxiomFoundation/_worktrees/receipt-crash-refusal-review
- Python: `.venv/bin/python` in that worktree (CPython 3.14t, pytest, hypothesis).
- Extracted trees, side by side:
  - base: `scratch-review/trees/9c47a3d/{src,tests,pyproject.toml}`
  - head: `scratch-review/trees/f8b1ddc/{src,tests,pyproject.toml}`
  To import one tree, start a fresh process and put `<tree>/src` (and, for
  fixtures, `<tree>/tests`) first on `sys.path`; print `receipt.__file__` to
  prove which tree you loaded. Never import both trees in one process.
  For a differential, run the same driver twice (one process per tree) and
  diff JSONL outputs.
- Read the diff: `git -C <worktree> diff 9c47a3d..f8b1ddc -- src/` and
  `git -C <worktree> log -p 9c47a3d..f8b1ddc`.
- Test fixtures that build real inputs: `tests/corpus_fixture.py`
  (local OpenSSL TSAs: build_local_tsa, stamp, stamp_with_clock_precision),
  `tests/test_tsa.py` (build_witness_tree, LocalAnchor, local_anchors),
  `tests/test_append_gate.py` (base_repository, append_one_row, run_gate,
  run_push_gate, observation_row, write_prefix_manifest, PREFIX_LINE_COUNT),
  `tests/test_release_chain.py`, `tests/test_snapshot.py`. Import them as
  modules from the tree's tests dir.
- Prior work (read for what was already hunted; do not redo it blindly):
  `/Users/maxghenis/chief-of-staff/state/receipt-07/crash-refusal/sweep/RESULT.json`
  and its subdirectories (the author's own sweep over an earlier head
  fd6e91c; scripts are reusable). Lane findings (read-only):
  `/Users/maxghenis/chief-of-staff/state/receipt-07/review-062/{L2,L3,L6}/findings.md`
  and each lane's `scratch/` scripts. Copy and adapt scripts into your scratch
  dir; do not edit them in place.

## Rules

- Write ONLY under your own `scratch-review/<your-dir>/`. Do not commit, push,
  or edit tracked files. Do not touch other agents' dirs.
- Machine load is very high (load average 80-130 on 18 cores; other sessions
  are running). Run one heavy process at a time, bound Hypothesis
  (`max_examples` <= 3000, `deadline=None`), and wrap every subprocess and
  long run in `timeout` (<= 600 s per command). CPU timings: use
  `time.process_time()` (CPU), not wall clock, and compare ratios.
- No whole-tree `find`/`rg` rooted at `~`, `/tmp`, or big parents; use
  `git ls-files` or scoped paths with `-maxdepth`.
- Write temp repositories and files under your scratch dir, not /tmp.

## The contract the change must meet (from the maintainer)

1. Every refusal is the module's own error type (TsaError, AppendError,
   ReleaseChainError, SnapshotError) with a named reason, raised before any
   signature is trusted. No interpreter exception escapes a public entry
   point for these inputs.
2. Every refusal text that existed before is unchanged. Any input that
   verified, or was refused, before this branch gets the same verdict and the
   same text afterwards. The only permitted exceptions: (a) the corrected
   rendering of fractional instants inside refusal texts; (b) a genTime finer
   than a microsecond, now refused; (c) JSON nested more than 128 deep, now
   refused everywhere, including JSON 0.6.1 accepted.
3. One commit per finding, each with regression tests that fail before and
   pass after, plus Hypothesis totality properties.

## Already known (do not re-report; you may cite)

- K1 (found by the reviewer): `append_gate.check_prefix` changed the
  cumulative prefix hash for `prefixLineCount: 0`: base hashes b"\n"
  (`"\n".join([]) + "\n"`), head hashes b"" (`b"".join(...)`). A zero-line
  frozen prefix written by the fixture's own writer passes the gate at
  9c47a3d and is refused "immutable prefix cumulative hash mismatch" at
  f8b1ddc (scratch-review/repro/empty_prefix_gate.py).
- The documented behavior changes (a), (b), (c) above.
- Out of scope (another branch owns them): naive `now` in tsa; `_path_fold`;
  the `verify_witness` IndexError for a bare filename; append_gate
  `check_binding_shapes`, `check_prefix_anchored_to_base`, bool or non-ASCII
  row values, duplicate JSON keys, exact-int `prefixLineCount`;
  `corpus.parse_journal`; `attest`; `canonical.py` itself. Also queued
  separately by the author: `physical_path` quadratic on ~100k-component
  tokenPath; malformed caller arguments to `verify_timestamp_token`,
  `trusted_bundles`, `prior_pending_updates`; `-attime` rounding at the 1970
  and 9999 edges; an out-of-range aware `now`.
  If you find something only in out-of-scope code, list it separately under
  "out of scope" with one line; do not spend time on it.

## What to return (your final message is data for the reviewer)

1. Findings, most severe first. For each: title; severity (high = verdict
   change on real-world-shaped input or a security-relevant acceptance;
   medium = contract violation reproducible through a public entry point;
   low = contract violation needing contrived input or a direct private call;
   nit = doc/claim inaccuracy with no behavior impact); entry point; exact
   input; observed output at 9c47a3d and at f8b1ddc (quote); the script path
   and output file path under your scratch dir; why it violates the contract;
   a suggested fix. Only report what you reproduced by execution.
2. Claims audited: each claim you checked, verdict (holds / wrong / partly),
   and the evidence (command + output file).
3. What you executed, with counts, and what held.
