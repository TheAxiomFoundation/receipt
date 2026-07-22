# receipt.attest equivalence and 0.4.0 progress

## State

The extraction audit is in progress on `extract-tsa-attest`. The TSA and
attestation ports, authenticated brier witness differential, and offline
attestation equivalence harness are implemented and green. Packaging and
documentation for `0.4.0` are the active slice.

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
- Confirmed the GitNexus repository index is stale; its refresh was blocked by
  the sandboxed user-level registry, so dependency inspection used direct
  import/call-site searches and authenticated source comparison instead.
- Re-verified the resumed baseline: `155 passed` on the requested starting
  tree. The only output was six pre-existing pytest temporary-cleanup warnings.
- Authenticated the attestation reference entry point and both transitive
  imports against `receipts/brier-pin-source-hashes.txt` at every load boundary.
- Added the offline attestation differential: representative canonical bytes,
  direct helper refusal equality, constructed zero/one/two epoch histories,
  a convergent side-branch full-history canary through the final scope filter,
  the exact brier certificate regex, and a stateful identical `gh` stub.
- Bound old accept/refuse, fresh retry-accept/exhaustion, stderr-last-line,
  stdout-fallback, and no-detail outcomes with a fixed clock and no live sleep.
- Cross-checked both extracted families against authenticated upstream source;
  no TSA or attestation merge-resolution divergence was found.
- Focused attestation differential verification: `20 passed`; installed Ruff:
  `All checks passed!`.

## Next

1. Move the package/version/docs pin group to `0.4.0` and remove this
   build-scratch progress file in that release commit.
2. Run the full suite and Ruff, inspect the final committed diff, and write the
   self-audit report to `.git/sol-attest-diff-OUT.md`.
