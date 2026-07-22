# TSA and attestation extraction progress

## State

The extraction is in progress on `extract-tsa-attest`. Required design and
pinned-source reading is complete. The brier oracle pin and all five runtime
source hashes are identified; the package implementation has not yet changed.

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

## Next

1. Add frozen, validated TSA specs and the mechanical witness port.
2. Build the authenticated witness differential and bind its mutation battery.
3. Add frozen, validated attestation specs and the mechanical provenance port.
4. Build the offline attestation differential and `gh` stub coverage.
5. Move packaging and documentation to `0.4.0`, run the full suite, and write
   the final self-audit report.
