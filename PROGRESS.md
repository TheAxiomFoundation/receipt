# TSA and attestation extraction progress

## State

The extraction is in progress on `extract-tsa-attest`. The spec-parameterized
TSA library port is implemented and its focused tests pass. The authenticated
brier witness differential is the next active slice.

## Done

- Read the design note and the pinned brier witness and attestation sources in
  the requested order.
- Read the existing ledger differential harness and package house-style
  modules.
- Confirmed the branch starts at the `0.3.0` release head and the existing
  brier source-hash receipt is present.
- Mapped the extraction boundary: `receipt.tsa` owns token, trust-bundle, and
  witness behavior; harness-local code owns brier's chain walk and composes
  `receipt.sign`; `receipt.attest` owns the deterministic git/`gh` provenance
  surface.
- Added frozen `TrustBundleSpec`, `TsaIdentitySpec`, and `TsaSpec` objects with
  no package-side trust defaults.
- Ported OpenSSL token verification, the DER walk, creation-claim time checks,
  trust-bundle transitions, supplemental outcomes, and v1/v2 witness evidence.
- Added focused TSA spec, lifecycle, time-refusal, and dependency-direction
  tests: 12 passed.
- Re-ran the unchanged package/ledger/append-gate tests: 60 passed.

## Next

1. Build the authenticated witness differential and bind its mutation battery.
2. Review and commit the frozen attestation specs and provenance port.
3. Build the offline attestation differential and `gh` stub coverage.
4. Move packaging and documentation to `0.4.0`, run the full suite, and write
   the final self-audit report.
