# receipt.attest equivalence and 0.4.0 progress

## State

The extraction audit is in progress on `extract-tsa-attest` at the verified
starting commit `9950307`. The TSA and attestation ports and the authenticated
brier witness differential are committed and green. The offline attestation
equivalence harness is the active slice.

## Done

- Verified the requested branch and starting head exactly:
  `extract-tsa-attest` at `9950307d96b0e0d2213e2657275a20300c974f0d`.
- Confirmed the worktree was clean before resuming.
- The spec-parameterized RFC 3161 verifier is committed in `receipt.tsa` with
  12 focused tests.
- The authenticated pinned-upstream brier witness equivalence audit is
  committed with 17 clean-tree/divergence cases.
- The spec-parameterized workflow-provenance verifier is committed in
  `receipt.attest` with focused unit coverage.
- Confirmed the GitNexus repository index exists but is stale relative to the
  requested starting head; repository-native dependency inspection remains
  available while it is refreshed.

## Next

1. Authenticate and inspect the pinned attestation reference and its imports.
2. Build and commit the offline deterministic attestation equivalence audit.
3. Move the package/version/docs pin group to `0.4.0` and remove this
   build-scratch progress file in that release commit.
4. Run the full suite and Ruff, cross-audit the TSA/attestation merge result,
   and write the final report to the requested output file.
