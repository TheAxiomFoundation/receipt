# Progress: 0.7 M1 protected-tree policy design

## State

Round-1 fold complete, starting from `2144f07`. Incorporated F1–F8 from
`docs/design/REVIEW-r1-m1.md`, reproduced both new probes, and reran the
embedded drivers and both test suites. The updated record is committed at
`docs/design/0.7-m1-protected-tree-policy.md` on
`design/0.7-m1-protected-tree-policy`, based on
`e404d59298c972993b268494c726472a2613f3b3`. The final round-1 report is
`/tmp/receipt-07-m1-output.md`, containing finding-by-finding new record
line numbers and F1/F2 output. This reuses the prior output path because no
different `-o` path was supplied; it now holds the report rather than a record copy.
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
- Reproduced F1's four interleave cases: late bad-byte path loses to alias;
  early bad-byte path wins with UTF-8 fold refusal. Added the executable appendix,
  nested caller schedules, permanent PR1 fixture and same-stage risk probe.
- Reproduced F2: reduced ceiling 40 gives work 28 on call 1 and refusal at
  work 40 on call 2 (path bytes 27/40, attribute bytes/rules 22/1). Specified
  exact-step replay for the single exhausting rule; normal work is 28/56.
- Folded F3–F8: PR3a/3b with counter gates; Chronicle per-PR gates; four
  retained/converted boundary rows and append selector ownership; explicit
  import-cycle resolution and late monkeypatch seams; concrete consolidation
  benefits; corrected locators, fixture identifiers and harness normalization.
- Added the review's smaller compatible-reuse control and case-sensitive plus
  case-insensitive PR3b gate. Independent audit refined materializer parent
  insertion order and attribute reading/rule/state-step ordering.
- Preserved `committed_fixture_filesystem` at its actual `def` line 1135;
  explicitly identified 1134 as its decorator, correcting the review's nit.
- Retained the round artifact in the repository and replaced the narrated
  validation row with its findings and the changes they caused.
- Reran the edited record's three embedded drivers: 43 matrix cases, eight
  contract cases, four historical controls, four repeat-charge rows and four
  interleave cases; also reran both isolated payload-reader controls. Matrix
  outcomes, refusal strings and phase statuses match the review's run; only
  generated commit IDs and successful custody signing/time metadata were
  excluded from comparison. Interleave output matches the independent rerun.
- Reran non-harness tests: 1,466 passed, zero skips, exit 0, 348.80 seconds.
  Reran all authenticated harnesses: 108 passed, zero skips, exit 0, 284.48
  seconds. Reconfirmed 43/28/17/20 collection and all 11 source SHA-256 checks.
  Logs and reproduction summaries are under `/tmp/receipt-m1-fold-r1/`.
- Final independent audit found no blockers against F1–F8 or the review's
  five approval requirements. This is a fold audit, not new Opus approval.
- Wrote the final report and committed validation evidence. Rechecked that
  source, tests and CONTRIBUTING still match v0.6.0; nothing was pushed.

## Next

No work remains in this design-only fold. Implementation, permanent test
fixtures and consumer upgrade runs belong to the future PRs in the record.
