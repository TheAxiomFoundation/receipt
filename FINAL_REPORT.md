# Receipt 0.6 Lane C — Astra review fold

F1 and F2 are fixed in separate commits on top of
`a1ec2eed5bc000015b0f29a10fbf08b0c8f6238d`. F4 and F5 retain behavior under
the brief's rulings. F3 uses the explicitly allowed stop outcome and awaits
the maintainer's portability/trust-boundary decision. F6 belongs to Lane D.

Only `src/receipt/release_chain.py`, `src/receipt/verify.py`, and
`tests/test_release_chain.py` changed. No Lane B or other protected source
file changed. Each finding has an imperative commit subject, measured
verification in its body, and a GPT-6 Astra co-author trailer. F3/F4 are
record-only empty commits because their answers belong in the required
untracked `PROGRESS.md`. Both progress and this output remain untracked.

- **F1 — fixed, `31f51cdbe4e025d6e951fe579273f12db1a5255b`.** The base helper
  normalizes its ChainSpec once and binds configured tree anchors through
  Materialization.anchor_set_sha256 before OpenSSL. It passes that exact
  normalized spec to release verification. Restored `anchor_dir`,
  `enforce_production_pins`, and `clock_skew_seconds` match 0.5.2's keyword
  defaults. Explicit caller trust skips the tree anchor digest and uses the
  caller's directory even when tree anchors are absent or invalid.
- **F2 — fixed, `1872709c5751270c156c0bb26bf8abde8eb5e2cd`.** The base helper
  refuses transforming attributes over every materialized protected entry
  before anchor binding or extracted release verification.
- **F3 — deferred, `6a3613f45931032931f6d9a27a2e705d93156357`.** O_NOFOLLOW
  remains required. The shared regular-file reader serves six routes and
  reads external caller trust as well as private materializations. A blanket
  ownership flag would waive the requirement for anchors the process did not
  materialize; a root-scoped waiver adds a path-authority boundary and leaves
  Lane B's external anchors nonportable. This exceeds the narrow flag's
  ownership claim, so the maintainer must choose that boundary. Existing
  platform docs/tests remain accurate. Future tests must inspect actual open
  flags because STATE_OPEN_FLAGS currently captures O_NOFOLLOW at import.
- **F4 — answered, `790ba6722a982976d0842ac70960a863a6dce578`.** Preserve
  argument validation → OpenSSL preflight → anchor probe → release-root guard
  → manifest-shape guard → enumeration. Plan 3.3 preflights first, and
  3.5/residual 17 place OpenSSL preflight at the top; the review's competing
  ordering came from the dispatch brief. Existing commit 6099095 and three
  passing ordering tests already pin the behavior.
- **F5 — answered/documented, `1beab18edb5d2055daf24062644638d14caadce9`.**
  Retain the deliberate 0.5.2 public redirecting-environment refusal.
  Plan 3.9 does not remove it. The run_verification docstring now explicitly
  states both that retained refusal and the underlying TreeSnapshot reader's
  invariance through a frozen environment and explicit repository selection.
- **F6 — no Lane C action.** Message-context migration is assigned to Lane D.

Lane B should pass its trusted directory as `anchor_dir` to
`verify_base_release_chain`, with its existing production-pin choice. This
lane did not add an `owned_materialization` keyword.

Regression measurements used archived a1ec2ee source under
`/tmp/receipt-astra-a1ec2ee/src`, explicitly selected through both PYTHONPATH
and pytest's pythonpath override. F1's six new cases failed there and passed
after; the two existing base-success cases also pass. F2's new test measured
the snapshot's filter refusal while the old helper reached OpenSSL; it now
returns the same reader refusal. All nine base-helper tests pass. An
independent review found no blocking defects and independently passed those
nine cases. Five retained F3/F4 tests and five F5/public-reader tests pass.
Logs: `/tmp/receipt-astra-f1-baseline.log`, `/tmp/receipt-astra-f1-fixed.log`,
`/tmp/receipt-astra-f2-baseline.log`, `/tmp/receipt-astra-f2-fixed.log`,
`/tmp/receipt-astra-retained-f3-f4.log`, `/tmp/receipt-astra-f5.log`.

All required suites passed at the reported head with the pinned venv, local
ledger extraction, and the existing authenticated Brier extraction override:
`RECEIPT_BRIER_TREE=/Users/maxghenis/TheAxiomFoundation/receipt/.extraction/brier-4b9e7be`.

- Five-module gate (ledger/release_chain/verify/cli/tsa): **468 passed in
  117.24s**, zero skips. Baseline 461; seven new regression cases.
- Offline non-equivalence gate, excluding the three append-gate modules:
  **1,181 passed, 80 deselected in 220.95s**, zero skips. Baseline 1,174.
- Authenticated ledger/attest/Brier equivalence: **80 passed in 192.16s**,
  zero skips, matching baseline.

Suite logs are `/tmp/receipt-astra-lane.log`, `/tmp/receipt-astra-offline.log`,
and `/tmp/receipt-astra-equivalence.log`. All commands used `set -o pipefail`
and the pinned `/Users/maxghenis/TheAxiomFoundation/receipt/.venv/bin/python`.
Final whitespace, ancestry, file-scope, commit-trailer and untracked-progress
audits pass; the tracked worktree is clean.

The authorized `git push origin feat/0.6-lane-c` failed before any remote
update: the sandbox could not resolve `github.com`. The five commits remain
local; PR #56 was not updated. Push the head below when network access is
available. Push log: `/tmp/receipt-astra-push.log`.

Head OID: 1beab18edb5d2055daf24062644638d14caadce9
Suite totals: 468 passed; 1,181 passed + 80 deselected; 80 passed; zero skips
Findings folded: F1 31f51cdbe4e025d6e951fe579273f12db1a5255b; F2 1872709c5751270c156c0bb26bf8abde8eb5e2cd; F4 answer 790ba6722a982976d0842ac70960a863a6dce578; F5 answer/doc 1beab18edb5d2055daf24062644638d14caadce9
Findings left: F3 6a3613f45931032931f6d9a27a2e705d93156357 — allowed stop for ownership/trusted-anchor boundary; F6 — Lane D scope
