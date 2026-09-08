# Defensive correctness and completeness audit: receipt 0.7 M3 PR1

## State

Completed the defensive correctness and completeness audit of PR #74 at `0f47e917854fb66a7aac19891d6ed659e1b52788` in one local pass, without subagents, background tasks, installations, or network access. Verdict: **approve, no findings**. Final output: committed `review-full.md`; the supplied state directory is outside the writable roots. Review artifacts are separate from the frozen PR revision.

## Done

- Confirmed the worktree began clean and HEAD matches the requested PR commit using `git status --short` and `git rev-parse HEAD`.
- Ran `git diff 44baaedf7f27219a5c65a9f65728f1c8863c2014 --stat`: 13 new files under `tests`, 8,644 insertions.
- Located the design record and M3 tests using `git ls-files`.
- Initial ordinary `git add PROGRESS.md` refused because `.gitignore:26` ignores the file. Added a narrow root exception to honor the explicit committed-progress requirement without force-adding; this is an audit artifact, not part of the reviewed PR.
- Scope checks pinned to the original PR SHA show only 13 additions under `tests`; `src`, `docs`, existing M1 fixtures, goldens, and compatibility/precedence assertions are unchanged.
- Independently extracted and hashed all 239 function spans (102 protected-tree, 118 snapshot, 19 verify), checked all 15 source-module hashes against `git show 9dc1f85:...`, and printed 24 matching sample records.
- Verified all 19 M1 golden files byte-for-byte against the supplied main base and PR head. The local `main` ref is stale (`d542d592...`) and lacks these files; the attempted local-main check failed, so all authoritative comparisons use the supplied full base SHA.
- Instrumented authentication: all 15 `git show` calls finish before frozen module execution. Independent source/hash mutations are rejected. The actual pytest authentication test fails during fixture setup on a tampered oracle, as required.
- Ran `.venv/bin/pytest -q tests/test_m3_legacy.py`: 5 passed in 1.02s, including distinct-body, early-refusal, isolated-global, and identical-live-leg negative controls.
- Reviewed all D1–D18 probe implementations and counted 761 characterization cases plus 5 oracle cases. Every stored account observation contains all 15 `SnapshotWork` fields (3,369 account observations across the matrices).
- Measured macOS 26.6.2 arm64, APFS with case-insensitive and normalization-insensitive lookup; Python 3.14.4, Git 2.53.0, OpenSSL 3.6.3. Independently constructed raw A/a and decomposed-Unicode names under both `core.ignoreCase` settings with `core.precomposeUnicode=false`.
- Required offline suite completed: **3,955 passed in 1053.42s (0:17:33), zero skips, exit 0**. Command: `.venv/bin/pytest -q --ignore=tests/test_ledger_equivalence.py --ignore=tests/test_append_gate_equivalence.py --ignore=tests/test_brier_witness_equivalence.py --ignore=tests/test_attest_equivalence.py` (foreground output captured with `tee /private/tmp/receipt-m3-pr1-review-suite.log` and `pipefail`). This includes all D1–D18 cases and all unchanged M1 assertions.
- Independent view after scope, source, matrix, and full-suite checks: no blocking finding. The build report has not yet been read.
- Alternate configuration run: `RECEIPT_M1_IGNORECASE=true .venv/bin/pytest -q` followed by the six explicit M3 test files: **766 passed in 455.71s (0:07:35), zero skips, exit 0**. The full-suite run used the fixture default `false`; live imports resolve to this worktree.
- After both runs, read the supplied build report. Its counts, scope, source hashes, filesystem observations and substitution qualifications agree with the independent review.
- A final expected-exception scan exposed a pre-existing D18 `NameError` in `release_chain._base_shape_error`. Independently traced both authenticated historical and live source to `release_chain.py:2398`; the freeze accurately records the production defect. This is not a PR finding, and no production fix was made.
- Wrote `review-full.md` with scope commands, 24 hash samples, authentication/tamper evidence, D1–D18 and public-entry-point mappings, all-field accounting, host facts, suite results, decision-voice review and the required final JSON verdict.

## Next

- No audit work remains. The maintainer runs the four explicitly excluded harnesses on a networked host. D1/A7 approval and later context implementation remain outside this freeze review.
