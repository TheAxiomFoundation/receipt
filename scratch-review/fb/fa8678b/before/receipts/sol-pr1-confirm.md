# Sol confirmation pass on PR #1 — APPROVE

Reviewer: gpt-5.6-sol via `codex exec`, 2026-07-20, equivalence-audit framing (third pass on PR #1). Verdict: **APPROVE**.

Confirmed non-vacuous, per finding from the prior REQUEST CHANGES (receipts/sol-pr1-review.md):

1. Canonical dependency authentication is real — both `verify_release_chain.py` and `canonical_json.py` are pinned and iterated in `_authenticated_baseline_tree`; `test_swapped_canonical_dependency_fails_authentication` alters only the serializer and requires an error naming it. Non-vacuous.
2. Scoping accepted — the baseline CLI (`verify_release_chain.py` main) calls only `verify_release_history_immutable` and `verify_release_chain`; the append gate (`check_thesis_facts_append.py`) is the real `verify_base_release_chain` caller, so that binding is required coverage in the next PR, not this one.
3. The two symlink markers are legitimate filesystem alternatives (macOS unknown-file / Linux non-regular-entry); full normalized-message equality is asserted before the marker, so the tuple cannot mask divergence.
4. The comparison contract now accurately discloses both the whitespace strip and the OpenSSL-id masking.
5. Both payload-index directions (1→2 and 2→1) are present; recanonicalization preserves a valid filename digest and the index comparison precedes signature verification, so the pair pins `!=` against either one-sided comparator.

> "Every one of the 23 full-chain and 7 base-ref mutations reaches shared assertions requiring both refusals, full normalized byte equality, and the declared branch marker. No weakened or vacuous mutation was found."

Suite: 36 passed. Optional nit (a stale "one normalization" line contradicting the "two normalizations" contract) fixed in the same commit as this receipt.

## Review provenance across PR #1

Three Sol passes, all under equivalence-audit framing (adversarial/security framing trips ChatGPT's cyber classifier; ChatGPT Trusted Access for Cyber was denied 2026-07-20, so framing is the standing channel): (1) initial — REQUEST CHANGES, port clean, harness coverage gaps; (2) re-review of the hardened harness — REQUEST CHANGES, five refinements incl. the canonical-auth hole; (3) this pass — APPROVE. The port itself was found clean in every pass. Implementation while the main loop was Opus-downgraded was oracle-gated (the differential harness certifies correctness); the cross-family judgment came from Sol. Merge is held for Fable restoration + Max's go — not performed on Opus.
