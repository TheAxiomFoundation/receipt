# Progress

## State

`release_chain` now delegates producer-key reading and verification to `vidimus.sign` through exception-translating compatibility wrappers. Both pinned differential harnesses pass after the extraction.

## Done

- Confirmed the checkout is clean and on `extract-sign` tracking `origin/main`.
- Read the `vidimus.sign` design rationale.
- Indexed the repository locally for refactoring analysis; the global GitNexus registry write is sandbox-blocked, so caller mapping will be cross-checked with repository search.
- Read the release-chain implementation, both differential harnesses, and the pinned upstream oracle.
- Confirmed the clean baseline: 57 tests pass.
- Added `SignError`, `ProducerKeySpec`, producer-key reading, exact input validation, cryptography verification, and the OpenSSL fallback to `vidimus.sign`.
- Preserved the old `release_chain` producer helper signatures and its importable cryptography gate/names while replacing their implementations with one-way delegation.
- Preserved input-check ordering and full anchor-path diagnostics; every `SignError` crossing the boundary is re-raised as `ReleaseChainError(str(exc)) from exc`.
- Confirmed 54 release-chain and append-gate equivalence tests pass with byte-identical verdicts after the existing normalizations.

## Next

- Add sign-side key generation/signing and its round-trip/OpenSSL tests.
- Add the three producer-public-key differential mutations.
