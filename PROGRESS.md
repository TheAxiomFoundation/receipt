# Progress

## State

Refactor audit initialized on `extract-sign` at upstream commit `9349d2f`. The design note has been read, and dependency/oracle inspection is in progress before implementation changes.

## Done

- Confirmed the checkout is clean and on `extract-sign` tracking `origin/main`.
- Read the `vidimus.sign` design rationale.
- Indexed the repository locally for refactoring analysis; the global GitNexus registry write is sandbox-blocked, so caller mapping will be cross-checked with repository search.

## Next

- Read the release-chain implementation, both equivalence harnesses, and pinned upstream oracle.
- Map the frozen producer-signature API and its callers.
- Extract Layer 1 into `src/vidimus/sign.py`, then delegate from `release_chain`.
