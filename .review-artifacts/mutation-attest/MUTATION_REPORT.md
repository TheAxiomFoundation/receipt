Attest mutation review of 1b6cbd08e41a50d04215f64528fa6ffa09014152.

No blocking attest defect identified. Original tracked source/test files were never mutated.

The current tests against `origin/release/0.6.x:src/receipt/attest.py` produced 14 failures and 2 passing controls (55 deselected). The new shallow-equivalence case separately produced 1 failure using the authenticated three-file pinned upstream oracle. Two targeted current-source mutants turned the passing controls red. This covers all 17 added/changed parameterized cases.

Old-source expected failures:
- `test_enforcement_epoch_command_and_refusals`
- `test_records_commits_uses_full_history_and_consumer_prefix`
- `test_commit_scope_branch_outcomes[0-False]`
- `test_commit_scope_branch_outcomes[1-True]`
- `test_a_shallow_clone_refuses_before_it_is_swept[1]`
- `test_a_shallow_clone_refuses_before_it_is_swept[2]`
- `test_a_graft_file_refuses_before_it_is_swept`
- `test_a_replace_ref_does_not_hide_a_commit`
- `test_a_commit_graph_entry_does_not_hide_a_commit`
- `test_an_inherited_git_variable_does_not_move_the_sweep[GIT_DIR]`
- `test_an_inherited_git_variable_does_not_move_the_sweep[GIT_GRAFT_FILE]`
- `test_an_inherited_git_variable_does_not_move_the_sweep[GIT_REPLACE_REF_BASE]`
- `test_option_shaped_arguments_are_read_as_revisions`
- `test_the_sweep_is_invariant_under_ambient_git_state_exhaustively`

Old-source controls:
- `test_commit_scope_merge_base_error_is_verbatim`
- `test_a_full_history_sweep_reaches_the_unattested_commit`

Control mutants: append a replacement `records_commits` returning `[]` (full-history test fails); prefix the merge-base refusal message with `MUTANT ` (verbatim refusal test fails). `controls-tests.xml` records 2 failures.

Exhaustive pre-fix count in `count-base.json`: 6 passed, 58 failed, 64 total; verifies the PR's 6/64 statement. Script `count_sweeps.py` reproduces both histories, all 16 inherited-variable subsets and both replace-ref states, and continues after each failed invariant.

Pinned upstream oracle: `oracle-brier/scripts/{verify_records_attestations.py,attest_subject.py,canonical_json.py}` fetched at `4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f`; all three SHA-256 digests match `BASELINE_AUTHENTICATED_FILES` in the current checkout. The differential fixture authenticates them again. Old candidate returns code 0 for the shallow clone instead of expected code 1, failing `test_attest_equivalence.py:1101`.

Commands, run from `.review-artifacts/mutation-attest` unless stated:

```sh
../../.venv/bin/python -m pytest -q --basetemp tmp-base --junitxml base-tests.xml tests/test_attest.py -k 'enforcement_epoch_command_and_refusals or records_commits_uses_full_history_and_consumer_prefix or commit_scope_branch_outcomes or commit_scope_merge_base_error_is_verbatim or a_full_history_sweep or a_shallow_clone or a_graft_file or a_replace_ref or a_commit_graph or an_inherited_git_variable or option_shaped or the_sweep_is_invariant'
../../.venv/bin/python count_sweeps.py count-base-temp > count-base.json 2> count-base.err
env RECEIPT_BRIER_TREE="$PWD/oracle-brier" /Users/maxghenis/TheAxiomFoundation/_worktrees/hub-review-receipt-79-r2/.venv/bin/python -m pytest -q --basetemp tmp-equivalence-oracle --junitxml equivalence-oracle-tests.xml tests/test_attest_equivalence.py::test_the_port_refuses_a_shallow_clone_the_pinned_upstream_accepts
```

Control command from `.review-artifacts/mutation-attest-controls`:

```sh
/Users/maxghenis/TheAxiomFoundation/_worktrees/hub-review-receipt-79-r2/.venv/bin/python -m pytest -q --basetemp tmp-controls --junitxml controls-tests.xml tests/test_attest.py::test_a_full_history_sweep_reaches_the_unattested_commit tests/test_attest.py::test_commit_scope_merge_base_error_is_verbatim
```

Additional attempted ordinary-fixture clone was interrupted (exit 2; no tests ran). `ps` progress inspection was sandbox-denied (`operation not permitted`); scoped `pkill` failed because sysmond was unavailable (`Cannot get process list`, exit 3). Neither was a test/check result.

After restoring scratch `attest.py` to exact HEAD, both controls and the new equivalence divergence passed: 3 passed in 53.49s
