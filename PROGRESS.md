# Progress: 0.7 M1 protected-tree policy design

## State

Round-1 fold in progress, starting from `2144f07`. Incorporate F1–F8 from
`docs/design/REVIEW-r1-m1.md`, reproduce both new probes, and rerun the
embedded drivers and both test suites. The existing record is committed at
`docs/design/0.7-m1-protected-tree-policy.md` on
`design/0.7-m1-protected-tree-policy`, based on
`e404d59298c972993b268494c726472a2613f3b3`. The final round-1 report will use
`/tmp/receipt-07-m1-output.md` unless a different `-o` path is supplied.
Source, tests and CONTRIBUTING remain byte-identical to v0.6.0.
The supplied `issue-62.md` remains an untracked input. Nothing was pushed.

## Done

- Read issue #62, CONTRIBUTING and applicable agent rules.
- Maintained committed progress tracking from the start; committed the census,
  complete design, and final reviewed corrections as coherent steps.
- Completed every named screen-site census, exact refusal expressions,
  existing text-test pins/gaps, direct-directory guards, raw-payload guards,
  materialized-anchor guards and budget ownership.
- Read Chronicle only through Git objects at the requested remote ref; recorded
  all shim imports and byte-transparency dependencies. Independently checked
  axiom-encode and thesis signing-only imports at their 0.6 adoption refs.
- Executed 43 fixture/CLI cases, eight public-contract controls, two payload
  comparisons, full historical-package empty-tree controls and repeated-budget
  controls. The embedded consolidated reproducer ran successfully and matched
  all 43 baseline case results exactly.
- Passed all 1,466 non-harness tests and 108 authenticated harness cases, with
  zero skips. Independently verified all oracle source hashes.
- Specified one policy module and immutable protected views, explicit partial
  topology/obligations, shared facts, legacy refusal ordering/admission,
  PR-sized migration steps, consumer compatibility and ranked settling probes.
- Completed two independent final reviews and incorporated every correction.
- Mirrored the original record to the output file and verified identical bytes.
- Used the requested co-author trailer on all design-lane commits.
- Read the round-1 review and approval requirements. Delegated an independent
  source-locator audit and suite/F2 validation while folding the record.

## Next

1. Reproduce F1's append interleave and F2's exact exhaustion counter.
2. Fold F1–F8: schedules, migration gates, boundary ownership, import direction,
   benefits, precise locators and review provenance.
3. Rerun the updated drivers and 1,466 + 108 tests with zero skips; commit each
   coherent step with the requested co-author trailer.
4. Write the final report with new record line numbers and F1/F2 output.
   Do not push. Implementation and consumer upgrades remain future PR work.
